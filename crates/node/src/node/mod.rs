use crate::alias::{AliasContact, OwnedAlias, RelayProvision};
use crate::forward::decode_authorized_with_policy;
use crate::lease::{
    Capabilities, DynamicGrantRequest, LeaseCreate, LeaseLimits, LeaseRenew, LeaseRevoke,
    OP_CREATE, OP_GRANT_REQUEST, OP_RENEW, OP_REVOKE, OP_ROTATE,
};
use crate::metrics;
use crate::proto::{
    decode_direct_record, decode_payload, encode_contact_update, encode_direct_ack,
    encode_direct_data, encode_direct_presence, encode_first_move, encode_forward_grant,
    encode_frame, ContactUpdate, DirectRecord, NodeInfo, NodePayload, PresenceMode, KIND_BOOTSTRAP,
};
use crate::queues::{GrantRequest, LeaseStore, PushOutcome, StoreConfig, StoreError};
use crate::relay::{FrwdTargetPolicy, RelayTarget, UnauthenticatedRelayPush};
use crate::scheduler::{EnqueueError, ProducerClass, RelayScheduler, SchedulerProfile};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use gcoms_core::{Cell, CellType};
use gcoms_crypto::session::FirstMove;
use gcoms_crypto::{Bundle, IdentityKeypair, LocalSecrets, SealedSession, Session, SessionContext};
use gcoms_transport::server::{
    AcceptedStream, CellHandler, QueueCellHandler, QueueReject, StreamHandler, Tp1Server,
};
use gcoms_transport::tls::TlsIdentity;
use gcoms_transport::{encode_b64url, TokenRegistry, Tp1Client};
use hkdf::Hkdf;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

mod aliases;
mod api;
mod application_inbox;

mod channel_direct;
mod channel_recovery;
mod channels;
mod commands;
mod direct;
#[cfg(feature = "experimental-gc2")]
mod gc2_acks;
#[cfg(feature = "experimental-gc2")]
mod gc2_bootstrap;
#[cfg(feature = "experimental-gc2")]
mod gc2_carrier;
#[cfg(feature = "experimental-gc2")]
mod gc2_direct;
#[cfg(feature = "experimental-gc2")]
mod gc2_forward;
#[cfg(feature = "experimental-gc2")]
mod gc2_gate;
#[cfg(feature = "experimental-gc2")]
mod gc2_receipts;
mod peer_session;
#[cfg(feature = "experimental-gc2")]
mod retained;
use peer_session::PeerSession;
#[cfg(feature = "client-persist")]
mod persist;
#[cfg(feature = "client-persist")]
mod persist_legacy;
mod presence;
mod relay_service;
mod routing;
mod startup_transport;
mod state;
mod ticks;

pub use api::{
    ChannelStatus, ChannelView, ChannelViewRole, Cmd, Ev, IntermediaryStats, NodeDiagnostics,
    NodeHandle, Reachability, RecvEventError,
};
pub use application_inbox::ApplicationDelivery;
pub use routing::{RoutingConfig, RoutingStateStore};
pub use state::NodeState;

pub(crate) use aliases::*;
pub(crate) use channel_direct::*;
pub(crate) use channel_recovery::*;
pub(crate) use channels::*;
pub(crate) use direct::*;
pub(crate) use presence::*;
pub(crate) use relay_service::*;
pub(crate) use state::*;

pub type Alias = OwnedAlias;

/// Which safety posture the node runs with. This is explicit configuration:
/// nothing about it is ever inferred from a bind address, so a production
/// node bound to an unusual interface keeps its cover traffic, its rate
/// matching, and its FRWD target guard.
#[derive(Clone, Debug)]
pub enum NodeProfile {
    /// Real deployment: fixed 3 s slots, rate-matched emission, cover
    /// traffic, complete onion paths, private/reserved FRWD targets refused.
    /// A loopback listener remains an outbound-only production endpoint.
    Production,
    /// Local test harness. Refuses to listen on a non-loopback address so
    /// that a fixture cannot be exposed by mistake.
    Fixture(FixtureProfile),
    /// Explicit GC/2 carrier selection with production transport behaviour.
    /// The normal production selection stays GC/1 until the qualification
    /// gates pass; this variant is the deployment candidate.
    #[cfg(feature = "experimental-gc2")]
    Gc2Carrier(Gc2CarrierProfile),
}

/// Deployment-shaped GC/2 carrier settings. A durable directory is required
/// for a listener that keeps state across restarts; `None` is an explicit
/// outbound-only fixture-style selection.
#[cfg(feature = "experimental-gc2")]
#[derive(Clone, Debug)]
pub struct Gc2CarrierProfile {
    pub directory: Option<std::path::PathBuf>,
    pub entries: usize,
    pub record_len: usize,
    pub period_ms: u16,
    pub unpaced_bulk: bool,
    pub scheduler: SchedulerProfile,
    /// Explicit private introductions for qualification fixtures. Deployment
    /// profiles leave this empty and use the provisioning advertisement.
    pub introductions: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct FixtureProfile {
    /// Experimental peer sessions only. This does not qualify the GC/2 carrier
    /// or privacy profile and is never selected by a production node.
    #[cfg(feature = "experimental-gc2")]
    pub gc2_sessions: bool,
    /// Install the late-bound GC/2 role gate on the listener. It becomes active
    /// only after this node provisions a relay service, so fixtures that do not
    /// act as relays pass every path through unchanged.
    #[cfg(feature = "experimental-gc2")]
    pub gc2_gate: bool,
    /// Optional encrypted GC/2 routing directory; `None` uses an in-memory
    /// directory for tests. The cache keeps its exclusive writer lock for the
    /// node lifetime.
    #[cfg(feature = "experimental-gc2")]
    pub gc2_directory: Option<std::path::PathBuf>,
    /// Background entry count (one to three). Zero disables the carrier owner.
    #[cfg(feature = "experimental-gc2")]
    pub gc2_entries: usize,
    /// Explicit private GC/2 introductions installed as directory seeds at
    /// startup. Fixture/qualification only; deployment uses the authenticated
    /// provisioning advertisement, and an invalid seed fails closed.
    #[cfg(feature = "experimental-gc2")]
    pub gc2_introductions: Vec<Vec<u8>>,
    /// Carrier record bound and emission period for owner entry connections.
    /// Deployment uses the production 4096/1000; qualification fixtures
    /// compress the period so slot scheduling does not dominate latency.
    #[cfg(feature = "experimental-gc2")]
    pub gc2_carrier_record_len: usize,
    #[cfg(feature = "experimental-gc2")]
    pub gc2_carrier_period_ms: u16,
    #[cfg(feature = "experimental-gc2")]
    pub gc2_unpaced_bulk: bool,
    /// Relay lane and maintenance scheduling.
    pub scheduler: SchedulerProfile,
    /// Permit loopback/private FRWD targets (all fixtures need this).
    pub allow_local_targets: bool,
    /// Cadence of relay->subscriber emission on RELAY_SUB streams.
    pub stream_slot_interval: std::time::Duration,
    /// Whether idle stream slots emit cover cells.
    pub stream_emit_cover: bool,
}

/// Parallel protected circuits reserved for bulk records. The entry's shared
/// circuit bound is larger, so interactive, control and subscriptions keep
/// headroom.
#[cfg(feature = "experimental-gc2")]
const GC2_BULK_CIRCUITS: usize = 8;

impl NodeProfile {
    /// Fast, deterministic fixture with cover disabled.
    pub fn fixture() -> Self {
        Self::Fixture(FixtureProfile {
            #[cfg(feature = "experimental-gc2")]
            gc2_sessions: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_gate: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_directory: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_entries: 0,
            #[cfg(feature = "experimental-gc2")]
            gc2_introductions: Vec::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_record_len: 4096,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_period_ms: 1000,
            #[cfg(feature = "experimental-gc2")]
            gc2_unpaced_bulk: false,
            scheduler: SchedulerProfile::fixture(),
            allow_local_targets: true,
            stream_slot_interval: std::time::Duration::from_millis(10),
            stream_emit_cover: false,
        })
    }

    /// Production traffic behaviour at a compressed cadence, for
    /// qualification runs on one host.
    pub fn compressed_production(seed: u64) -> Self {
        Self::Fixture(FixtureProfile {
            #[cfg(feature = "experimental-gc2")]
            gc2_sessions: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_gate: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_directory: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_entries: 0,
            #[cfg(feature = "experimental-gc2")]
            gc2_introductions: Vec::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_record_len: 4096,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_period_ms: 1000,
            #[cfg(feature = "experimental-gc2")]
            gc2_unpaced_bulk: false,
            scheduler: SchedulerProfile::compressed_production(seed),
            allow_local_targets: true,
            stream_slot_interval: std::time::Duration::from_millis(10),
            stream_emit_cover: true,
        })
    }

    /// Fixture transport with the production scheduler and stream cadences.
    /// Used to compare GC/1 and GC/2 at the same production timing; loopback
    /// production-cadence runs are wall-clock bound, so qualification repeats
    /// run in parallel on the cluster.
    pub fn production_cadence_fixture() -> Self {
        Self::Fixture(FixtureProfile {
            #[cfg(feature = "experimental-gc2")]
            gc2_sessions: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_gate: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_directory: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_entries: 0,
            #[cfg(feature = "experimental-gc2")]
            gc2_introductions: Vec::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_record_len: 4096,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_period_ms: 1000,
            #[cfg(feature = "experimental-gc2")]
            gc2_unpaced_bulk: false,
            scheduler: SchedulerProfile::production(),
            allow_local_targets: true,
            stream_slot_interval: std::time::Duration::from_secs(3),
            stream_emit_cover: true,
        })
    }

    pub fn is_production(&self) -> bool {
        match self {
            Self::Production => true,
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2Carrier(_) => true,
            _ => false,
        }
    }

    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_session_fixture() -> Self {
        let Self::Fixture(mut fixture) = Self::fixture() else {
            unreachable!()
        };
        fixture.gc2_sessions = true;
        Self::Fixture(fixture)
    }

    /// Fixture that installs the experimental GC/2 role gate on its listener.
    /// The gate activates only after this node provisions a relay service.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_gate_fixture() -> Self {
        let Self::Fixture(mut fixture) = Self::fixture() else {
            unreachable!()
        };
        fixture.gc2_gate = true;
        Self::Fixture(fixture)
    }

    /// Fixture that runs the experimental GC/2 carrier owner: the role gate,
    /// peer sessions, and one to three background entries over the given
    /// directory (an in-memory directory when `directory` is `None`).
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_carrier_fixture(directory: Option<std::path::PathBuf>, entries: usize) -> Self {
        let Self::Fixture(mut fixture) = Self::fixture() else {
            unreachable!()
        };
        fixture.gc2_sessions = true;
        fixture.gc2_gate = true;
        fixture.gc2_directory = directory;
        fixture.gc2_entries = entries;
        Self::Fixture(fixture)
    }

    /// Deployment-shaped carrier with the production transport schedule.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_carrier_production(directory: Option<std::path::PathBuf>, entries: usize) -> Self {
        Self::Gc2Carrier(Gc2CarrierProfile {
            directory,
            entries,
            record_len: 4096,
            period_ms: 1000,
            unpaced_bulk: true,
            scheduler: SchedulerProfile::production(),
            introductions: Vec::new(),
        })
    }

    /// Deployment-shaped carrier with the compressed production schedule used
    /// by qualification runs on one host.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_carrier_qualification(
        directory: Option<std::path::PathBuf>,
        entries: usize,
        seed: u64,
    ) -> Self {
        Self::Gc2Carrier(Gc2CarrierProfile {
            directory,
            entries,
            record_len: 4096,
            period_ms: 1000,
            unpaced_bulk: false,
            scheduler: SchedulerProfile::compressed_production(seed),
            introductions: Vec::new(),
        })
    }

    /// Carrier *fixture* with the compressed qualification cadence: identical
    /// local transport to `gc2_carrier_fixture`, but maintenance and slot
    /// delays suitable for one-host measurements against a
    /// `compressed_production` baseline.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_carrier_qualification_fixture(
        directory: Option<std::path::PathBuf>,
        entries: usize,
        seed: u64,
    ) -> Self {
        let Self::Fixture(mut fixture) = Self::compressed_production(seed) else {
            unreachable!()
        };
        fixture.gc2_sessions = true;
        fixture.gc2_gate = true;
        fixture.gc2_directory = directory;
        fixture.gc2_entries = entries;
        fixture.gc2_carrier_period_ms = 250;
        Self::Fixture(fixture)
    }

    /// Explicit loopback fixture for the negotiated production file policy.
    #[cfg(feature = "experimental-gc2")]
    pub fn gchat_file_transfer_fixture(entries: usize, seed: u64) -> Self {
        let Self::Fixture(mut fixture) =
            Self::gc2_carrier_qualification_fixture(None, entries, seed)
        else {
            unreachable!()
        };
        fixture.gc2_unpaced_bulk = true;
        Self::Fixture(fixture)
    }

    /// Qualification carrier fixture with explicit private introductions
    /// installed as directory seeds before the owner starts. Used to exercise
    /// the protected entry/middle circuit without a provisioning control plane.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_carrier_qualification_fixture_seeded(
        directory: Option<std::path::PathBuf>,
        entries: usize,
        seed: u64,
        introductions: Vec<Vec<u8>>,
    ) -> Self {
        let Self::Fixture(mut fixture) =
            Self::gc2_carrier_qualification_fixture(directory, entries, seed)
        else {
            unreachable!()
        };
        fixture.gc2_introductions = introductions;
        Self::Fixture(fixture)
    }

    /// Production-cadence qualification carrier fixture: explicit private
    /// introductions with the production scheduler and carrier period, so
    /// GC/2 can be compared with GC/1 at the same production timing.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_carrier_production_cadence_fixture_seeded(
        directory: Option<std::path::PathBuf>,
        entries: usize,
        introductions: Vec<Vec<u8>>,
    ) -> Self {
        let Self::Fixture(mut fixture) = Self::production_cadence_fixture() else {
            unreachable!()
        };
        fixture.gc2_sessions = true;
        fixture.gc2_gate = true;
        fixture.gc2_directory = directory;
        fixture.gc2_entries = entries;
        fixture.gc2_introductions = introductions;
        Self::Fixture(fixture)
    }

    #[cfg(feature = "experimental-gc2")]
    fn gc2_sessions(&self) -> bool {
        match self {
            Self::Fixture(fixture) => fixture.gc2_sessions,
            Self::Gc2Carrier(_) => true,
            Self::Production => false,
        }
    }

    #[cfg(feature = "experimental-gc2")]
    fn gc2_gate(&self) -> bool {
        match self {
            Self::Fixture(fixture) => fixture.gc2_gate,
            Self::Gc2Carrier(_) => true,
            Self::Production => false,
        }
    }

    #[cfg(feature = "experimental-gc2")]
    fn gc2_carrier(&self) -> Option<(Option<&std::path::Path>, usize, usize, u16)> {
        match self {
            Self::Fixture(fixture) if fixture.gc2_entries > 0 => Some((
                fixture.gc2_directory.as_deref(),
                fixture.gc2_entries,
                fixture.gc2_carrier_record_len,
                fixture.gc2_carrier_period_ms,
            )),
            Self::Gc2Carrier(carrier) if carrier.entries > 0 => Some((
                carrier.directory.as_deref(),
                carrier.entries,
                carrier.record_len,
                carrier.period_ms,
            )),
            _ => None,
        }
    }

    #[cfg(feature = "experimental-gc2")]
    fn gc2_wire_profile(&self) -> Result<gcoms_routing::gc2::CandidateProfile, String> {
        if matches!(self, Self::Gc2Carrier(profile) if profile.unpaced_bulk)
            || matches!(self, Self::Fixture(profile) if profile.gc2_unpaced_bulk)
        {
            return Ok(gcoms_routing::gc2::CandidateProfile::file_transfer());
        }
        let (_, _, record_len, period_ms) =
            self.gc2_carrier().ok_or("GChat carrier not selected")?;
        gcoms_routing::gc2::CandidateProfile::new(record_len, period_ms).map_err(|e| e.to_string())
    }

    /// Explicit private introductions installed as directory seeds at startup.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn gc2_introductions(&self) -> &[Vec<u8>] {
        match self {
            Self::Fixture(fixture) => &fixture.gc2_introductions,
            Self::Gc2Carrier(carrier) => &carrier.introductions,
            Self::Production => &[],
        }
    }

    /// True when the carrier profile is the loopback fixture variant; its
    /// in-memory directory must accept loopback introductions.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn gc2_loopback_fixture(&self) -> bool {
        matches!(self, Self::Fixture(fixture) if fixture.gc2_entries > 0)
    }

    pub(crate) fn scheduler_profile(&self) -> SchedulerProfile {
        match self {
            Self::Production => SchedulerProfile::production(),
            Self::Fixture(fixture) => fixture.scheduler.clone(),
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2Carrier(carrier) => carrier.scheduler.clone(),
        }
    }

    pub(crate) fn frwd_target_policy(
        &self,
        configured: Option<FrwdTargetPolicy>,
    ) -> FrwdTargetPolicy {
        match self {
            Self::Production => configured.unwrap_or_else(|| FrwdTargetPolicy::new(false)),
            Self::Fixture(fixture) => {
                configured.unwrap_or_else(|| FrwdTargetPolicy::new(fixture.allow_local_targets))
            }
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2Carrier(_) => configured.unwrap_or_else(|| FrwdTargetPolicy::new(false)),
        }
    }

    /// Connection admission limits for the relay listener. A fixture packs
    /// many nodes onto one host, so its per-source cap is lifted.
    pub(crate) fn server_limits(&self) -> gcoms_transport::ServerLimits {
        match self {
            Self::Production => gcoms_transport::ServerLimits::default(),
            Self::Fixture(_) => gcoms_transport::ServerLimits::shared_host(),
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2Carrier(_) => gcoms_transport::ServerLimits::default(),
        }
    }

    pub(crate) fn stream_emission(&self) -> StreamEmission {
        match self {
            Self::Production => StreamEmission {
                slot_interval: crate::scheduler::SLOT_INTERVAL,
                emission_probability: crate::scheduler::EMISSION_PROBABILITY,
                emit_cover: true,
            },
            Self::Fixture(fixture) => StreamEmission {
                slot_interval: fixture.stream_slot_interval,
                emission_probability: 1.0,
                emit_cover: fixture.stream_emit_cover,
            },
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2Carrier(_) => StreamEmission {
                slot_interval: crate::scheduler::SLOT_INTERVAL,
                emission_probability: crate::scheduler::EMISSION_PROBABILITY,
                emit_cover: true,
            },
        }
    }

    fn check_listen(&self, listen: SocketAddr) -> Result<(), String> {
        let loopback = listen.ip().is_loopback();
        match self {
            Self::Fixture(_) if !loopback && !listen.ip().is_unspecified() => Err(
                "a fixture NodeProfile can only listen on loopback; use NodeProfile::Production to expose a node"
                    .into(),
            ),
            _ => Ok(()),
        }
    }
}

/// Relay->subscriber cadence parameters derived from the profile.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamEmission {
    pub(crate) slot_interval: std::time::Duration,
    pub(crate) emission_probability: f64,
    pub(crate) emit_cover: bool,
}

pub struct NodeConfig {
    pub seed: [u8; 32],
    pub listen: SocketAddr,
    pub control: Option<SocketAddr>,
    pub advertise: Option<SocketAddr>,
    /// Safety posture. Never inferred from `listen`.
    pub profile: NodeProfile,
    /// Full relay that hosts this node's inboxes. When set, the node acts as
    /// an outbound-only forwarder and publishes the leased relay queues.
    pub inbox_relay: Option<NodeInfo>,
    /// Direct-address lifecycle timing. Production callers should use the
    /// default; short values exist for deterministic integration tests.
    pub alias_lifecycle: AliasLifecycleConfig,
}

#[derive(Clone, Copy, Debug)]
pub struct AliasLifecycleConfig {
    pub alias_ttl: std::time::Duration,
    pub alias_drain: std::time::Duration,
    pub poll_interval: std::time::Duration,
    pub revoke_retry: std::time::Duration,
    pub revoke_timeout: std::time::Duration,
}

impl Default for AliasLifecycleConfig {
    fn default() -> Self {
        Self {
            alias_ttl: std::time::Duration::from_secs(24 * 60 * 60),
            alias_drain: std::time::Duration::from_secs(60 * 60),
            poll_interval: std::time::Duration::from_secs(60),
            revoke_retry: std::time::Duration::from_secs(60),
            revoke_timeout: std::time::Duration::from_secs(10 * 60),
        }
    }
}

/// Synchronous durable commit used at direct-session ratchet boundaries.
/// The sink must not call back into the node.
pub type DurableStateSink = Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

fn short_addr_tag(addr: &str) -> String {
    let mut tag = addr.chars().rev().take(12).collect::<String>();
    tag = tag.chars().rev().collect();
    tag
}

fn info_addr(info: &NodeInfo) -> String {
    info.primary()
        .map(|alias| alias.target.address.to_string())
        .unwrap_or_default()
}

pub async fn start(cfg: NodeConfig) -> Result<NodeHandle, String> {
    let tls_identity = TlsIdentity::generate().map_err(|e| e.to_string())?;
    start_with_tls(cfg, tls_identity).await
}

#[cfg(feature = "client-persist")]
pub async fn start_persistent(
    cfg: NodeConfig,
    durable_state_sink: DurableStateSink,
) -> Result<NodeHandle, String> {
    let tls_identity = TlsIdentity::generate().map_err(|e| e.to_string())?;
    start_with_tls_policy_control_and_sink(
        cfg,
        tls_identity,
        None,
        None,
        Some(durable_state_sink),
        None,
        None,
    )
    .await
}

/// Like [`start_persistent`], but with an operator-supplied FRWD target
/// policy (for example one that allows a private CIDR). The profile still
/// decides everything else; the policy only relaxes the FRWD target check
/// (derived from the explicitly selected node profile).
pub async fn start_persistent_with_policy(
    cfg: NodeConfig,
    frwd_target_policy: FrwdTargetPolicy,
    durable_state_sink: DurableStateSink,
) -> Result<NodeHandle, String> {
    let tls_identity = TlsIdentity::generate().map_err(|e| e.to_string())?;
    start_with_tls_policy_control_and_sink(
        cfg,
        tls_identity,
        Some(frwd_target_policy),
        None,
        Some(durable_state_sink),
        None,
        None,
    )
    .await
}

/// Restore and persist a client archive before starting any node ingress or
/// maintenance tasks. This prevents a reconnect from replacing durable state
/// with a partially restored snapshot during boot.
#[cfg(feature = "client-persist")]
pub async fn start_persistent_restored(
    cfg: NodeConfig,
    frwd_target_policy: Option<FrwdTargetPolicy>,
    durable_state_sink: DurableStateSink,
    initial_state: Option<&[u8]>,
) -> Result<NodeHandle, String> {
    let tls_identity = match initial_state {
        Some(bytes) => persist::restore_tls_identity(bytes, &cfg.seed)?,
        None => None,
    };
    let tls_identity = match tls_identity {
        Some(identity) => identity,
        None => TlsIdentity::generate().map_err(|e| e.to_string())?,
    };
    start_with_tls_policy_control_and_sink(
        cfg,
        tls_identity,
        frwd_target_policy,
        None,
        Some(durable_state_sink),
        initial_state,
        None,
    )
    .await
}

pub async fn start_with_tls(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_control_and_sink(cfg, tls_identity, None, None, None, None, None).await
}

/// Backend/test configuration seam. Existing constructors select production
/// routing automatically; explicit fixtures can exercise circuits locally.
pub async fn start_with_routing(
    cfg: NodeConfig,
    routing: RoutingConfig,
) -> Result<NodeHandle, String> {
    let tls = TlsIdentity::generate().map_err(|e| e.to_string())?;
    start_with_tls_policy_control_and_sink(cfg, tls, None, None, None, None, Some(routing)).await
}

#[cfg(feature = "client-persist")]
pub async fn start_persistent_restored_with_routing(
    cfg: NodeConfig,
    routing: RoutingConfig,
    durable_state_sink: DurableStateSink,
    initial_state: Option<&[u8]>,
) -> Result<NodeHandle, String> {
    start_persistent_restored_with_policy_and_routing(
        cfg,
        None,
        routing,
        durable_state_sink,
        initial_state,
    )
    .await
}

/// Explicit backend routing configuration retaining the caller's FRWD target
/// policy and the exact archived TLS identity restoration boundary.
#[cfg(feature = "client-persist")]
pub async fn start_persistent_restored_with_policy_and_routing(
    cfg: NodeConfig,
    frwd_target_policy: Option<FrwdTargetPolicy>,
    routing: RoutingConfig,
    durable_state_sink: DurableStateSink,
    initial_state: Option<&[u8]>,
) -> Result<NodeHandle, String> {
    let tls = match initial_state {
        Some(bytes) => persist::restore_tls_identity(bytes, &cfg.seed)?,
        None => None,
    }
    .map(Ok)
    .unwrap_or_else(|| TlsIdentity::generate().map_err(|e| e.to_string()))?;
    start_with_tls_policy_control_and_sink(
        cfg,
        tls,
        frwd_target_policy,
        None,
        Some(durable_state_sink),
        initial_state,
        Some(routing),
    )
    .await
}

/// Start with an operator-supplied FRWD target policy (for example one
/// that allows a private CIDR). The profile still decides everything else.
pub async fn start_with_tls_and_policy(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: FrwdTargetPolicy,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_and_control(cfg, tls_identity, frwd_target_policy, None).await
}

pub async fn start_with_tls_policy_and_control(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: FrwdTargetPolicy,
    remote_control: Option<crate::control::RemoteControlConfig>,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_control_and_sink(
        cfg,
        tls_identity,
        Some(frwd_target_policy),
        remote_control,
        None,
        None,
        None,
    )
    .await
}

/// Explicit routing configuration for a host with its own TLS/control identity.
pub async fn start_with_tls_policy_control_and_routing(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: FrwdTargetPolicy,
    remote_control: Option<crate::control::RemoteControlConfig>,
    routing: Option<RoutingConfig>,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_control_and_sink(
        cfg,
        tls_identity,
        Some(frwd_target_policy),
        remote_control,
        None,
        None,
        routing,
    )
    .await
}

async fn start_with_tls_policy_control_and_sink(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: Option<FrwdTargetPolicy>,
    remote_control: Option<crate::control::RemoteControlConfig>,
    durable_state_sink: Option<DurableStateSink>,
    initial_state: Option<&[u8]>,
    routing_config: Option<RoutingConfig>,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_control_sink_and_bootstrap(
        cfg,
        tls_identity,
        frwd_target_policy,
        remote_control,
        durable_state_sink,
        initial_state,
        routing_config,
        None,
    )
    .await
}

pub async fn start_with_tls_policy_control_and_bootstrap(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: FrwdTargetPolicy,
    remote_control: Option<crate::control::RemoteControlConfig>,
    bootstrap_directory: Option<std::path::PathBuf>,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_control_routing_and_bootstrap(
        cfg,
        tls_identity,
        frwd_target_policy,
        remote_control,
        None,
        bootstrap_directory,
    )
    .await
}

pub async fn start_with_tls_policy_control_routing_and_bootstrap(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: FrwdTargetPolicy,
    remote_control: Option<crate::control::RemoteControlConfig>,
    routing: Option<RoutingConfig>,
    bootstrap_directory: Option<std::path::PathBuf>,
) -> Result<NodeHandle, String> {
    start_with_tls_policy_control_sink_and_bootstrap(
        cfg,
        tls_identity,
        Some(frwd_target_policy),
        remote_control,
        None,
        None,
        routing,
        bootstrap_directory,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_with_tls_policy_control_sink_and_bootstrap(
    cfg: NodeConfig,
    tls_identity: TlsIdentity,
    frwd_target_policy: Option<FrwdTargetPolicy>,
    remote_control: Option<crate::control::RemoteControlConfig>,
    durable_state_sink: Option<DurableStateSink>,
    initial_state: Option<&[u8]>,
    routing_config: Option<RoutingConfig>,
    bootstrap_directory: Option<std::path::PathBuf>,
) -> Result<NodeHandle, String> {
    if bootstrap_directory.is_some() {
        return Err("managed installer bootstrap is provided by the host integration".into());
    }
    let routing_config = match routing_config {
        Some(config) => Some(config),
        None if cfg.profile.is_production() => Some(RoutingConfig::from_environment()?),
        None => None,
    };
    let connectivity = routing_config.as_ref().and_then(|r| r.connectivity.clone());
    #[cfg(feature = "experimental-gc2")]
    if cfg.profile.gc2_carrier().is_some()
        && routing_config
            .as_ref()
            .is_some_and(|config| config.bootstrap.is_some())
    {
        return Err(
            "GChat carrier requires explicit GCRB2 bootstrap; legacy authority cannot be converted"
                .into(),
        );
    }
    let routing = if let Some(config) = routing_config {
        #[cfg(feature = "client-persist")]
        let directory = match initial_state {
            Some(bytes) => persist::restore_routing_directory(bytes, &cfg.seed)?,
            None => gcoms_routing::Directory::new(),
        };
        #[cfg(not(feature = "client-persist"))]
        let directory = gcoms_routing::Directory::new();
        Some(routing::RoutingRuntime::new(
            config,
            directory,
            !cfg.profile.is_production(),
        )?)
    } else {
        None
    };
    #[cfg(feature = "client-persist")]
    let saved_owner = match initial_state {
        Some(bytes) => persist::restore_owner_aliases(bytes, &cfg.seed, routing.is_some())?,
        None => None,
    };
    // An explicitly auto-selected local port resumes its authenticated saved
    // port. Explicit nonzero configuration must still match; no second listener.
    #[cfg(feature = "client-persist")]
    let cfg = {
        let mut cfg = cfg;
        if let Some(record) = &saved_owner {
            if routing.is_none()
                && cfg.inbox_relay.is_none()
                && cfg.advertise.is_none()
                && cfg.listen.port() == 0
            {
                let target = record.active_target()?;
                if target.address.ip() != cfg.listen.ip()
                    || target.relay_service_id != tls_identity.service_id()
                {
                    return Err(
                        "saved owner listener does not match configured identity/address".into(),
                    );
                }
                cfg.listen = target.address;
            }
        }
        cfg
    };
    #[cfg(feature = "client-persist")]
    let mut owner_restore_clock = match &saved_owner {
        Some(record) => {
            let expected = match &cfg.inbox_relay {
                Some(card) => card
                    .primary()
                    .ok_or("configured relay has no contact")?
                    .target
                    .clone(),
                None if routing.is_some() => record.active_target()?.clone(),
                None => RelayTarget {
                    address: cfg.advertise.unwrap_or(cfg.listen),
                    relay_service_id: tls_identity.service_id(),
                },
            };
            record.validate(&expected)?;
            Some(persist::owner_aliases::RestoreClock::new(
                record.captured_ms,
                now_ms(),
                std::time::Instant::now(),
            )?)
        }
        None => None,
    };
    cfg.profile.check_listen(cfg.listen)?;
    let frwd_target_policy = cfg.profile.frwd_target_policy(frwd_target_policy);
    let scheduler_profile = cfg.profile.scheduler_profile();
    let stream_emission = cfg.profile.stream_emission();
    if cfg.alias_lifecycle.alias_ttl.is_zero()
        || cfg.alias_lifecycle.alias_drain.is_zero()
        || cfg.alias_lifecycle.poll_interval.is_zero()
        || cfg.alias_lifecycle.revoke_retry.is_zero()
        || cfg.alias_lifecycle.revoke_timeout.is_zero()
    {
        return Err("alias lifecycle durations must be nonzero".into());
    }
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let control_listener = match cfg.control {
        Some(address) => Some(
            crate::control::ControlListener::bind(address, remote_control)
                .await
                .map_err(|error| format!("bind control listener {address}: {error}"))?,
        ),
        None => {
            if remote_control.is_some() {
                return Err("remote control TLS configured without a control listener".into());
            }
            None
        }
    };
    let identity = IdentityKeypair::from_seed(cfg.seed);
    let (bundle, secrets) = identity.issue_bundle();
    let secrets = Arc::new(secrets);
    let registry = TokenRegistry::new();
    let service_id = tls_identity.service_id();
    let leases = Arc::new(Mutex::new(
        LeaseStore::new(service_id, StoreConfig::default()).map_err(|e| e.to_string())?,
    ));
    let queue_tokens = Arc::new(Mutex::new(HashMap::<[u8; 32], String>::new()));
    let authorities = Arc::new(Mutex::new(ProvisionAuthorities {
        transit_ready: routing
            .as_ref()
            .filter(|r| r.automatic_connectivity)
            .map(|r| r.published.clone()),
        ..Default::default()
    }));
    #[cfg(feature = "experimental-gc2")]
    let prepared_gc2 = gc2_bootstrap::prepare(&cfg, routing.as_ref())?;
    let client = Arc::new(
        match &routing {
            #[cfg(feature = "experimental-gc2")]
            Some(runtime) if runtime.gc2.get().is_some() => {
                Tp1Client::with_connector(runtime.gc2.get().expect("selected").ready.clone())
            }
            Some(runtime) => Tp1Client::with_connector(runtime.discovery.connector.clone()),
            None => Tp1Client::new(),
        }
        .map_err(|e| e.to_string())?,
    );
    // Transit carries only already authorized relay jobs. It must never invoke
    // the endpoint's onion connector and recursively build another circuit.
    let transit_client = Arc::new(Tp1Client::new().map_err(|e| e.to_string())?);
    let (scheduler, transit_scheduler) = {
        #[cfg(feature = "experimental-gc2")]
        if routing.as_ref().is_some_and(|r| r.gc2.get().is_some()) {
            RelayScheduler::with_gc2_transit(client.clone(), transit_client)
        } else {
            RelayScheduler::with_transit(client.clone(), transit_client, scheduler_profile.clone())
        }
        #[cfg(not(feature = "experimental-gc2"))]
        {
            RelayScheduler::with_transit(client.clone(), transit_client, scheduler_profile.clone())
        }
    };
    let (on_cell, on_queue_cell, on_stream) = relay_service::build_handlers(
        &leases,
        &registry,
        &queue_tokens,
        &authorities,
        &transit_scheduler,
        &frwd_target_policy,
        service_id,
        stream_emission,
    );

    let listener = match &connectivity {
        Some(config) => config.bind(cfg.listen)?,
        None => Tp1Server::bind_listener(cfg.listen).map_err(|e| e.to_string())?,
    };
    let server = Tp1Server::from_listener_with_identity_and_queue(
        listener,
        registry.clone(),
        on_cell,
        on_stream,
        on_queue_cell,
        &tls_identity,
    )
    .map_err(|e| e.to_string())?
    .with_limits(cfg.profile.server_limits());
    #[cfg(feature = "experimental-gc2")]
    let server = if cfg.profile.gc2_gate() {
        // Compose the owned terminal queue service under the same role gate.
        // Its handler only accepts authenticated queue tokens that resolve to a
        // current lease in this node's store.
        let queues = crate::gc2::QueueService::new(leases.clone()).handler();
        let forwards = gc2_forward::handler(
            authorities.clone(),
            transit_scheduler.clone(),
            service_id,
            frwd_target_policy.clone(),
        );
        let terminal: Option<gcoms_transport::server::DuplexHandler> =
            Some(Arc::new(move |path| {
                queues(path).or_else(|| forwards(path))
            }));
        server.with_dispatch_factory(gc2_gate::dispatch_factory(routing.clone(), terminal))
    } else {
        server
    };
    let local_addr = server.local_addr().map_err(|e| e.to_string())?;
    let relay_target = RelayTarget {
        address: cfg.advertise.unwrap_or(local_addr),
        relay_service_id: service_id,
    };
    #[cfg(feature = "experimental-gc2")]
    if let Some(prepared) = &prepared_gc2 {
        prepared
            .directory
            .set_own_services(vec![(relay_target.address, relay_target.relay_service_id)])
            .map_err(|e| e.to_string())?;
    }
    let server = if let Some(runtime) = &routing {
        server.with_duplex(runtime.attach(
            &tls_identity,
            &relay_target,
            leases.clone(),
            registry.clone(),
            authorities.clone(),
        )?)
    } else {
        server
    };
    let mut transport = startup_transport::StartupTransport::spawn(server);
    let cleanup_scheduler = scheduler.clone();
    let cleanup_transit_scheduler = transit_scheduler.clone();
    // Every fallible post-spawn operation belongs to this one result boundary.
    let result = async {
        let client_relay = if routing.is_some() {
            #[cfg(feature = "client-persist")]
            let retained = saved_owner
                .as_ref()
                .and_then(|r| {
                    r.groups
                        .iter()
                        .find(|g| g.role == persist::owner_aliases::Role::Active)
                })
                .map(|g| g.provision.clone());
            #[cfg(not(feature = "client-persist"))]
            let retained = None;
            retained
                .or_else(|| {
                    cfg.inbox_relay
                        .as_ref()
                        .and_then(|card| card.provisioning.clone())
                })
                .unwrap_or_else(routing::empty_provision)
        } else {
            let relay_card = match cfg.inbox_relay.as_ref() {
                Some(card) => card.clone(),
                None => provision_relay(
                    &leases,
                    &registry,
                    &authorities,
                    &relay_target,
                    &identity.public_bytes(),
                    &bundle.encode(),
                    true,
                )?,
            };
            let provision = consume_provision(&scheduler, &relay_card).await?;
            if provision.aliases.len() < 2 {
                return Err("relay provisioning requires normal and control aliases".into());
            }
            provision
        };
        #[cfg(feature = "client-persist")]
        let restored_owner = match (&saved_owner, owner_restore_clock.as_mut()) {
            (Some(record), Some(_)) if routing.is_some() => Some(record.clone()),
            (Some(record), Some(clock)) => Some(
                record
                    .restore_for_constructor(&scheduler, &client_relay, clock)
                    .await?,
            ),
            _ => None,
        };
        #[cfg(feature = "client-persist")]
        let client_relay = {
            let mut relay = client_relay;
            if let Some(record) = &restored_owner {
                relay.aliases = record
                    .groups
                    .iter()
                    .find(|g| g.role == persist::owner_aliases::Role::Active)
                    .ok_or("missing restored active owner aliases")?
                    .provision
                    .aliases
                    .clone();
            }
            relay
        };
        // Always-on lanes (SPEC §7.4): the node's own relay lanes start their
        // slot clocks and cover now, so real traffic never opens a lane.
        for owned in &client_relay.aliases {
            let _ = scheduler.open_lane(
                crate::scheduler::LaneAuth::Push {
                    contact: owned.contact.clone(),
                },
                true,
            );
        }
        if let Some(first) = client_relay.aliases.first() {
            let _ = scheduler.open_lane(
                crate::scheduler::LaneAuth::Frwd {
                    relay: client_relay.clone(),
                    decoy_target: first.contact.target.clone(),
                    policy: frwd_target_policy.clone(),
                },
                true,
            );
        }
        // Always-on lanes (SPEC §7.4): the node's own relay lanes start their
        // slot clocks and cover now, so the wire rate is the same whether or
        // not anyone ever talks to us. Pinned: they live until shutdown.
        for owned in &client_relay.aliases {
            let _ = scheduler.open_lane(
                crate::scheduler::LaneAuth::Push {
                    contact: owned.contact.clone(),
                },
                true,
            );
        }
        if let Some(primary) = client_relay.aliases.first() {
            let _ = scheduler.open_lane(
                crate::scheduler::LaneAuth::Frwd {
                    relay: client_relay.clone(),
                    decoy_target: primary.contact.target.clone(),
                    policy: frwd_target_policy.clone(),
                },
                true,
            );
        }
        let info = NodeInfo {
            identity_pk: identity.public_bytes(),
            bundle: bundle.encode(),
            aliases: client_relay
                .aliases
                .iter()
                .map(|owned| owned.contact.clone())
                .collect(),
            provisioning: None,
        };
        let safety_number = identity.safety_number();

        let state = Arc::new(Mutex::new(NodeState {
            #[cfg(feature = "experimental-gc2")]
            gc2_sessions: cfg.profile.gc2_sessions(),
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_client: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_route: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_bulk_routes: Vec::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_bulk_cursor: 0,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_directory: None,
            #[cfg(feature = "experimental-gc2")]
            retained_direct: std::sync::OnceLock::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_receipts: gc2_receipts::Ledger::default(),
            routing: routing.clone(),
            secrets,
            identity_seed: cfg.seed,
            #[cfg(feature = "client-persist")]
            sealed_tls_identity: persist::seal_tls_identity(&tls_identity, &cfg.seed)?,
            info: info.clone(),
            sessions: HashMap::new(),
            session_states: HashMap::new(),
            peer_routes: HashMap::new(),
            peer_route_generations: HashMap::new(),
            local_contact_generation: 1,
            pending_1to1: HashMap::new(),
            next_direct_sequence: 1,
            durable_applications_enabled: false,
            application_inbox: application_inbox::ApplicationInbox::default(),
            direct_ack_outbox: VecDeque::new(),
            processed_direct: HashMap::new(),
            processed_direct_order: VecDeque::new(),
            direct_presence: HashMap::new(),
            direct_presence_counters: HashMap::new(),
            direct_presence_opt_in: HashSet::new(),
            channel_presence: HashMap::new(),
            channel_presence_counters: HashMap::new(),
            channel_presence_opt_in: HashSet::new(),
            parked: Vec::new(),
            accepted_first_moves: VecDeque::new(),
            channels: HashMap::new(),
            prepared: HashMap::new(),
            chan_parked: Vec::new(),
            channel_fragments: crate::proto::ChannelFragmentBuffer::default(),
            last_channel_send: None,
            pending_channel_direct: HashMap::new(),
            next_prep_id: 1,
            client_relay: client_relay.clone(),
            forward_grants: HashMap::new(),
            active_intermediaries: Vec::new(),
            last_intermediary_rotation: std::time::Instant::now(),
            intermediary_fallbacks: 0,
            staged_contact_aliases: None,
            unannounced_old_contact_aliases: None,
            unannounced_contact_deadlines: None,
            owner_transition_failed: false,
            alias_lifecycle_timing: cfg.alias_lifecycle,
            #[cfg(feature = "client-persist")]
            owner_clock: Mutex::new(persist::owner_aliases::RestoreClock::fresh()?),
            draining_contact_aliases: Vec::new(),
            subscribed_contact_aliases: HashSet::new(),
            subscribed_classes: HashSet::new(),
            #[cfg(feature = "client-persist")]
            owner_alias_origins: HashMap::new(),
            #[cfg(feature = "client-persist")]
            owner_alias_renewals: HashMap::new(),
            contact_aliases_activated: std::time::Instant::now(),
            frwd_target_policy,
            scheduler: scheduler.clone(),
            invite_redeem_inbox: VecDeque::new(),
            pending_invite_redemptions: HashMap::new(),
            durable_state_sink,
        }));

        #[cfg(feature = "client-persist")]
        if let Some(record) = &restored_owner {
            record.apply_retained(
                &mut state.lock().unwrap_or_else(|p| p.into_inner()),
                owner_restore_clock
                    .take()
                    .ok_or("missing owner restore clock")?,
                routing.is_some(),
            )?;
        }
        // The relay server must run to provision local routes, but no application
        // subscription or background state writer starts until restoration is done.
        let initialized: Result<(), String> = async {
            if let Some(archive) = initial_state {
                #[cfg(feature = "client-persist")]
                persist::decode_state_at_startup(&state, &scheduler, archive).await?;
                #[cfg(not(feature = "client-persist"))]
                {
                    let _ = archive;
                    return Err("archive restore requires client-persist".into());
                }
            }
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            routing::refresh_public_info(&mut st);
            if initial_state.is_some() && routing.is_none() {
                // Startup provisions new TLS identity/queue capabilities. Advertise
                // them over every restored authenticated session before applications
                // resume, so peers can keep using their original pinned contact card.
                let updates = queue_contact_updates(&mut st)?;
                persist_current_direct_state(&st)?;
                #[cfg(feature = "client-persist")]
                persist::owner_aliases::validate_current_live(&st)?;
                for delivery in updates {
                    let Some(destination) = delivery.peer.primary() else {
                        continue;
                    };
                    for cell in &delivery.cells {
                        if let Err(error) = scheduler.frwd(
                            ProducerClass::Direct,
                            delivery.relay.clone(),
                            destination.clone(),
                            cell.clone(),
                            st.frwd_target_policy.clone(),
                        ) {
                            metrics::log_event(
                                "restored_contact_announcement_deferred",
                                &[("e", error.to_string())],
                            );
                            break;
                        }
                    }
                }
            }
            if st.durable_state_sink.is_some() {
                persist_current_direct_state(&st)?;
            }
            #[cfg(feature = "client-persist")]
            persist::owner_aliases::validate_current_live(&st)?;
            Ok(())
        }
        .await;
        initialized?;

        #[cfg(feature = "experimental-gc2")]
        if let Some(gc2_bootstrap::Prepared {
            directory,
            owner,
            ready,
        }) = prepared_gc2
        {
            let route = gcoms_transport::Tp1Client::with_connector(ready.clone())
                .map_err(|e| e.to_string())?;
            let route = std::sync::Arc::new(route);
            state.lock().unwrap_or_else(|p| p.into_inner()).gc2_carrier = Some(ready.clone());
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .gc2_carrier_client = Some(client.clone());
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .gc2_carrier_route = Some(route);
            // Bulk stripes: one carrier circuit carries at most one record per
            // profile period, so bulk records round-robin over a small set of
            // protected circuits inside the entry's shared bound. Interactive
            // and control traffic keep the single route above.
            let mut bulk_routes = Vec::with_capacity(GC2_BULK_CIRCUITS);
            for _ in 0..GC2_BULK_CIRCUITS {
                bulk_routes.push(std::sync::Arc::new(
                    gcoms_transport::Tp1Client::with_connector(ready.clone())
                        .map_err(|e| e.to_string())?,
                ));
            }
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .gc2_carrier_bulk_routes = bulk_routes;
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .gc2_carrier_directory = Some(directory);
            tasks.push(tokio::spawn(async move {
                if let Err(error) = owner.run().await {
                    metrics::log_event("gc2_carrier_owner_error", &[("e", error.to_string())]);
                }
            }));
        }

        if let Some(runtime) = &routing {
            runtime.bind_state(&state)?;
        }

        let info = state.lock().unwrap_or_else(|p| p.into_inner()).info.clone();
        let (events_tx, compat_rx) = broadcast::channel::<Ev>(256);
        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(64);
        if routing.is_some() {
            tasks.push(routing::spawn(
                state.clone(),
                scheduler.clone(),
                events_tx.clone(),
            ));
        }

        let workers = vec![
            ticks::spawn_contact_subscription_pump(
                state.clone(),
                scheduler.clone(),
                events_tx.clone(),
                cfg.alias_lifecycle.poll_interval,
            ),
            ticks::spawn_channel_subscription_pump(
                state.clone(),
                scheduler.clone(),
                events_tx.clone(),
            ),
            ticks::spawn_invite_service_loop(state.clone(), scheduler.clone(), events_tx.clone()),
        ];
        // The natural carrier drains its own class queues; the legacy pump
        // stays for sessions that did not migrate.
        #[cfg(feature = "experimental-gc2")]
        let workers = {
            let mut workers = workers;
            if !scheduler.is_gc2()
                && state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .gc2_carrier_client
                    .is_some()
            {
                workers.push(gc2_carrier::spawn_subscriptions(
                    state.clone(),
                    events_tx.clone(),
                ));
            }
            workers
        };
        tasks.push(ticks::spawn_alias_lifecycle_loop(
            state.clone(),
            scheduler.clone(),
            events_tx.clone(),
            cfg.alias_lifecycle,
        ));
        tasks.push(ticks::spawn_channel_alias_renew_loop(
            state.clone(),
            scheduler.clone(),
        ));
        tasks.push(ticks::spawn_contact_renew_loop(
            state.clone(),
            scheduler.clone(),
            events_tx.clone(),
        ));
        let frwd_admitted = authorities
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admitted
            .clone();
        tasks.push(commands::spawn_command_loop(commands::CommandLoopContext {
            state: state.clone(),
            frwd_admitted,
            scheduler: scheduler.clone(),
            events_tx: events_tx.clone(),
            leases: leases.clone(),
            registry: registry.clone(),
            authorities: authorities.clone(),
            relay_target: relay_target.clone(),
            relay_identity_pk: identity.public_bytes(),
            relay_bundle: bundle.encode(),
            cmd_rx,
        }));
        tasks.push(ticks::spawn_direct_maintenance_loop(
            state.clone(),
            scheduler.clone(),
            events_tx.clone(),
            scheduler_profile.clone(),
            cfg.seed,
        ));
        tasks.push(ticks::spawn_channel_maintenance_loop(
            state.clone(),
            scheduler.clone(),
            events_tx.clone(),
            scheduler_profile,
            cfg.seed,
        ));

        if let Some(control_listener) = control_listener {
            let state = state.clone();
            let cmd_tx = cmd_tx.clone();
            let events_tx = events_tx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) =
                    crate::control::serve(state, cmd_tx, events_tx, control_listener).await
                {
                    metrics::log_event("control_error", &[("e", e.to_string())]);
                }
            }));
        }

        tasks.push(relay_service::spawn_lease_sweeper(
            leases.clone(),
            queue_tokens.clone(),
            registry.clone(),
            authorities.clone(),
        ));

        let connectivity_task = match (connectivity, routing.as_ref()) {
            (Some(config), Some(runtime)) => {
                let runtime = runtime.clone();
                let published = runtime.published.clone();
                Some(crate::connectivity::spawn(
                    config,
                    local_addr,
                    cfg.advertise,
                    Arc::new(move |address| runtime.update_endpoint(address)),
                    published,
                ))
            }
            _ => None,
        };
        Ok(NodeHandle {
            state: Arc::downgrade(&state),
            listener_addr: local_addr,
            connectivity: Arc::new(tokio::sync::Mutex::new(connectivity_task)),
            routing,
            info,
            safety_number,
            cmd_tx,
            events_tx,
            compat_rx: Arc::new(tokio::sync::Mutex::new(compat_rx)),
            tasks: Arc::new(tokio::sync::Mutex::new(Some(tasks))),
            workers: Arc::new(tokio::sync::Mutex::new(Some(workers))),
            scheduler,
            transit_scheduler,
            transport: Arc::new(tokio::sync::Mutex::new(Some(transport.take()))),
        })
    }
    .await;
    if result.is_err() {
        transport.stop().await;
        cleanup_scheduler.shutdown();
        cleanup_transit_scheduler.shutdown();
    }
    result
}

fn persist_received_direct_transaction(
    st: &mut NodeState,
    peer: &[u8],
    sealed: &peer_session::Snapshot,
    credit: Option<&[u8]>,
) -> Result<(), String> {
    let previous_outbox_len = st.direct_ack_outbox.len();
    if let Some(credit) = credit {
        if previous_outbox_len >= 1024 {
            return Err("direct credit outbox is full".into());
        }
        let route = st
            .peer_routes
            .get(peer)
            .cloned()
            .ok_or("missing credit route")?;
        st.direct_ack_outbox.push_back(DirectDelivery {
            peer: route,
            relay: st.client_relay.clone(),
            cells: vec![Cell::new(CellType::Msg, 0, 0, credit.to_vec())],
        });
    }
    let previous = st
        .session_states
        .insert(peer.to_vec(), DirectSessionState::Established);
    if let Err(error) = persist_direct_state(st, Some((peer, sealed)), true) {
        st.direct_ack_outbox.truncate(previous_outbox_len);
        match previous {
            Some(state) => {
                st.session_states.insert(peer.to_vec(), state);
            }
            None => {
                st.session_states.remove(peer);
            }
        }
        return Err(error);
    }
    Ok(())
}

fn persist_current_direct_state(st: &NodeState) -> Result<(), String> {
    persist_direct_state(st, None, false)
}

enum DirectPersistenceError {
    #[cfg(feature = "experimental-gc2")]
    Admission(String),
    #[cfg(feature = "client-persist")]
    Storage(String),
}

impl DirectPersistenceError {
    fn into_string(self) -> String {
        match self {
            #[cfg(feature = "experimental-gc2")]
            Self::Admission(error) => error,
            #[cfg(feature = "client-persist")]
            Self::Storage(error) => error,
        }
    }
}

fn persist_direct_state(
    st: &NodeState,
    session_override: Option<(&[u8], &peer_session::Snapshot)>,
    control: bool,
) -> Result<(), String> {
    checkpoint_direct_state(st, session_override, control)
        .map_err(DirectPersistenceError::into_string)
}

fn checkpoint_direct_state(
    st: &NodeState,
    session_override: Option<(&[u8], &peer_session::Snapshot)>,
    control: bool,
) -> Result<(), DirectPersistenceError> {
    #[cfg(feature = "experimental-gc2")]
    let retained = st
        .stage_retained(session_override, control)
        .map_err(DirectPersistenceError::Admission)?;
    #[cfg(not(feature = "experimental-gc2"))]
    let _ = control;
    #[cfg(feature = "client-persist")]
    if let Some(sink) = &st.durable_state_sink {
        let bytes = match session_override {
            Some((peer, sealed)) => persist::encode_state_with_session(st, peer, sealed),
            None => persist::encode_state(st),
        }
        .map_err(DirectPersistenceError::Storage)?;
        sink(bytes).map_err(DirectPersistenceError::Storage)?;
    }
    #[cfg(not(feature = "client-persist"))]
    let _ = (st, session_override);
    #[cfg(feature = "experimental-gc2")]
    if let Some(retained) = retained {
        retained.commit();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// client-persist: export/import of recoverable node state (1:1 sessions,
// channel MLS state + directories). Relay queues, overlays, views, caches,
// tokens and parked frames are NOT exported — RAM-only by design (SPEC R1).
// Exported bytes are key material; callers MUST encrypt them at rest.
// ---------------------------------------------------------------------------

pub use api::ComponentAuthority;
