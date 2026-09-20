/// Host-installed authority policy for admitting an existing component-owned profile.
/// Implementations must authenticate their evidence and bind it to all supplied values.
/// This is a local host extension; network/IPC input cannot install a policy.
pub trait ComponentAuthority: Send + Sync {
    fn verify(
        &self,
        identity: &[u8],
        policy: &gcoms_core::component::RoutingPolicy,
        now: u64,
    ) -> Result<(), String>;
}

// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

/// Result of minting an invite: `(invite_id, invite_secret, expiry_unix)`.
pub type CreatedInvite = ([u8; 16], [u8; 32], u64);

#[cfg(all(test, feature = "experimental-gc2"))]
#[path = "catalog_tests.rs"]
mod catalog_tests;

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn full_command_queue_cannot_prevent_shutdown_from_joining_tasks() {
        let mut node = start(NodeConfig {
            seed: [73; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        })
        .await
        .unwrap();
        // Hold a full command queue with no consumer. The shutdown request
        // itself cannot be enqueued, but its timeout must still join task owners.
        let (blocked, _receiver) = mpsc::channel(1);
        let (done, _result) = tokio::sync::oneshot::channel();
        blocked.send(Cmd::CurrentInfo { done }).await.unwrap();
        let _original_commands = std::mem::replace(&mut node.cmd_tx, blocked);
        let owned = Arc::new(());
        let released = Arc::downgrade(&owned);
        node.tasks
            .lock()
            .await
            .as_mut()
            .unwrap()
            .push(tokio::spawn(async move {
                let _owned = owned;
                std::future::pending::<()>().await;
            }));
        tokio::time::timeout(std::time::Duration::from_secs(6), node.shutdown())
            .await
            .expect("a full command queue must not hang shutdown");
        assert!(
            released.upgrade().is_none(),
            "shutdown must join task cancellation"
        );
    }
}

pub enum Cmd {
    InstallRoutingBootstrap {
        bundle: gcoms_routing::bootstrap::BootstrapBundle,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    InstallInboxRelay {
        relay: Box<NodeInfo>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    CurrentInfo {
        done: tokio::sync::oneshot::Sender<NodeInfo>,
    },
    RenewContacts {
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ListChannels {
        done: tokio::sync::oneshot::Sender<Vec<ChannelView>>,
    },
    ChannelRoster {
        channel: String,
        done:
            tokio::sync::oneshot::Sender<Result<Vec<crate::channel::ChannelMemberSummary>, String>>,
    },
    PublicChannelDescriptor {
        channel: String,
        description: String,
        activity: crate::channel::ActivityBucket,
        automatic_join: Box<crate::channel::AutomaticJoinEndpoint>,
        expires_at_unix: u64,
        done: tokio::sync::oneshot::Sender<Result<crate::channel::PublicChannelDescriptor, String>>,
    },
    SendVolatileApplication {
        peer: Box<NodeInfo>,
        body: zeroize::Zeroizing<Vec<u8>>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },

    Send1to1 {
        durable: bool,
        peer: Box<NodeInfo>,
        text: Vec<u8>,
        via: Box<Option<NodeInfo>>,
        /// Explicit scheduling intent; `None` derives it from the record.
        class: Option<gcoms_core::TrafficClass>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Send1to1Tracked {
        durable: bool,
        peer: Box<NodeInfo>,
        text: Vec<u8>,
        via: Box<Option<NodeInfo>>,
        class: Option<gcoms_core::TrafficClass>,
        done: tokio::sync::oneshot::Sender<Result<[u8; 16], String>>,
    },
    SendDirectPresence {
        peer: Box<NodeInfo>,
        mode: PresenceMode,
        lease_secs: u32,
        via: Box<Option<NodeInfo>>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    SetDirectPresenceOptIn {
        peer: Box<NodeInfo>,
        enabled: bool,
        via: Box<Option<NodeInfo>>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    CreateChannel {
        channel: String,
        display: String,
        capacity: usize,
        visibility: crate::channel::ChannelVisibility,
        done: tokio::sync::oneshot::Sender<Result<crate::channel::ChannelId, String>>,
    },
    PrepareChannelJoin {
        display: String,
        done: tokio::sync::oneshot::Sender<Result<u64, String>>,
    },
    ChannelKeyPackage {
        req_id: u64,
        done: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    AdmitChannel {
        channel: String,
        key_package: Vec<u8>,
        member_name: String,
        done: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    RecoverChannelRoute {
        channel: String,
        expected_id: crate::channel::ChannelId,
        expected_epoch: u64,
        welcome: Vec<u8>,
        peer: Box<NodeInfo>,
        done: tokio::sync::oneshot::Sender<Result<[u8; 16], String>>,
    },
    CreateChannelInvite {
        channel: String,
        ttl_secs: u64,
        done: tokio::sync::oneshot::Sender<Result<CreatedInvite, String>>,
    },
    RedeemChannelInvite {
        channel: String,
        invite_id: [u8; 16],
        invite_secret: [u8; 32],
        key_package: Vec<u8>,
        member_name: String,
        done: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    /// Friend side: redeem an invite over the relay by sending a sealed
    /// InviteRedeem to the owner and awaiting their InviteWelcome.
    RedeemInviteRemote {
        owner: Box<NodeInfo>,
        channel: String,
        member_name: String,
        key_package: Vec<u8>,
        invite_id: [u8; 16],
        invite_secret: [u8; 32],
        timeout_secs: u64,
        done: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    JoinChannel {
        req_id: u64,
        channel: String,
        visibility: crate::channel::ChannelVisibility,
        welcome: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    SendChannelText {
        channel: String,
        text: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    SendChannelTextTracked {
        channel: String,
        text: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<[u8; 16], String>>,
    },
    SendChannelPresence {
        channel: String,
        mode: PresenceMode,
        lease_secs: u32,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    SetChannelPresenceOptIn {
        channel: String,
        enabled: bool,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    SendChannelDirect {
        channel: String,
        recipient: [u8; 32],
        text: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<[u8; 16], String>>,
    },
    RemoveChannelMember {
        channel: String,
        member_id: [u8; 32],
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ReplayLastChannel {
        channel: String,
        count: usize,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ProvisionClientRelay {
        done: tokio::sync::oneshot::Sender<Result<NodeInfo, String>>,
    },
    SignIdentityDigest {
        digest: [u8; 32],
        done: tokio::sync::oneshot::Sender<Vec<u8>>,
    },
    SignPrincipalBindingHash {
        claims_hash: [u8; 32],
        done: tokio::sync::oneshot::Sender<Vec<u8>>,
    },
    Shutdown {
        done: tokio::sync::oneshot::Sender<()>,
    },
    #[cfg(feature = "client-persist")]
    ExportState {
        done: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    #[cfg(feature = "client-persist")]
    ImportState {
        data: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    IntermediaryStats {
        done: tokio::sync::oneshot::Sender<IntermediaryStats>,
    },
    MachineOwnershipRequired {
        done: tokio::sync::oneshot::Sender<bool>,
    },
    CentralOwnershipRequired {
        done: tokio::sync::oneshot::Sender<bool>,
    },
    ConfigureCentralComponentRoutes {
        primary: Vec<[u8; 16]>,
        policy: gcoms_core::component::RoutingPolicy,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ConfigureComponentRoutes {
        binding: Option<std::sync::Arc<dyn ComponentAuthority>>,
        policy: gcoms_core::component::RoutingPolicy,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    EnableDurableApplications {
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    SubmitLocalComponent {
        body: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ApplicationInboxPage {
        after: u64,
        limit: usize,
        done: tokio::sync::oneshot::Sender<Result<Vec<ApplicationDelivery>, String>>,
    },
    ApplicationInboxReceipt {
        sequence: u64,
        digest: [u8; 32],
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    PersistState {
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelView {
    pub id: crate::channel::ChannelId,
    pub channel: String,
    pub visibility: crate::channel::ChannelVisibility,
    pub status: ChannelStatus,
    pub role: ChannelViewRole,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelStatus {
    Active,
    MembershipPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelViewRole {
    Owner,
    Member,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    RecentlyReachable,
    Away,
    Unknown,
}

#[derive(Clone, Debug)]
pub enum Ev {
    IdentityUpdated {
        info: NodeInfo,
        generation: u64,
    },
    SessionOpened {
        peer_pk: Vec<u8>,
        safety_number: String,
    },
    VolatileApplication {
        peer_pk: Vec<u8>,
        msg_id: [u8; 16],
        ts_unix: u64,
        body: Vec<u8>,
    },
    Message {
        peer_pk: Vec<u8>,
        msg_id: [u8; 16],
        ts_unix: u64,
        text: Vec<u8>,
        latency_hint_ms: u64,
    },
    DirectDelivery {
        peer_pk: Vec<u8>,
        msg_id: [u8; 16],
    },
    PresenceChanged {
        peer_pk: Vec<u8>,
        reachability: Reachability,
    },
    ChannelPresenceChanged {
        channel: String,
        member_id: [u8; 32],
        reachability: Reachability,
    },
    ChannelDelivery {
        channel: String,
        msg_id: [u8; 16],
    },
    ChannelMessage {
        channel: String,
        msg_id: [u8; 16],
        ts_unix: u64,
        sender: String,
        channel_epoch: u64,
        sender_index: u32,
        text: Vec<u8>,
        latency_hint_ms: u64,
    },
    ChannelRemoved {
        channel: String,
    },
    ChannelRosterChanged {
        channel: String,
        channel_id: crate::channel::ChannelId,
    },
    ChannelDirectMessage {
        channel: String,
        sender_member_id: [u8; 32],
        recipient_member_id: [u8; 32],
        msg_id: [u8; 16],
        ts_unix: u64,
        text: Vec<u8>,
    },
    ChannelDirectDelivery {
        channel: String,
        recipient_member_id: [u8; 32],
        msg_id: [u8; 16],
    },
    /// The consumer fell behind and `skipped` events were dropped. Emitted
    /// in place of silently continuing so an operator can see message loss.
    Lagged {
        skipped: u64,
    },
}

/// Diagnostics for SPEC §11.1 intermediary selection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntermediaryStats {
    /// Grants held from peers.
    pub pool: usize,
    /// Intermediaries currently pinned as lanes.
    pub active: usize,
    /// Deliveries that used the node's own relay because no grant was eligible.
    pub fallbacks: u64,
    /// Number of FRWD cells this node admitted as an intermediary.
    pub frwd_admitted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvEventError {
    Empty,
    Closed,
}

pub(crate) struct ShutdownTask {
    pub stop: tokio::sync::watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<()>,
}

/// Local aggregate counters only; no contacts, message IDs or payloads.
#[derive(Debug, serde::Serialize)]
pub struct NodeDiagnostics {
    pub transport: TransportStatus,
    /// Shared node allowance; do not sum the independent local peak values.
    pub resources: crate::scheduler::ResourceSnapshot,
    pub client: crate::scheduler::diagnostics::SchedulerSnapshot,
    pub relay: crate::scheduler::diagnostics::SchedulerSnapshot,
    pub client_resources: crate::scheduler::ResourceSnapshot,
    pub relay_resources: crate::scheduler::ResourceSnapshot,
}

/// Local readiness and class counts. No private addresses, tokens or identities.
#[derive(Debug, Default, serde::Serialize)]
pub struct TransportStatus {
    pub protocol: &'static str,
    pub profile_id: Option<u8>,
    pub bootstrap_version: Option<u8>,
    pub ready_entries: usize,
    pub usable_terminal_routes: usize,
    pub interactive_subscriptions: usize,
    pub bulk_subscriptions: usize,
    pub routing_ready: bool,
    pub recovering_inbox: bool,
    pub owned_aliases: usize,
    pub subscribed_owned_aliases: usize,
}

#[derive(Clone)]
pub struct NodeHandle {
    pub(crate) state: std::sync::Weak<Mutex<NodeState>>,
    pub(crate) listener_addr: SocketAddr,
    #[cfg(feature = "relay-host")]
    pub(crate) connectivity: Arc<tokio::sync::Mutex<Option<crate::connectivity::RuntimeTask>>>,
    pub(crate) routing: Option<Arc<super::routing::RoutingRuntime>>,
    pub info: NodeInfo,
    pub safety_number: String,
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
    pub(crate) events_tx: broadcast::Sender<Ev>,
    pub(crate) compat_rx: Arc<tokio::sync::Mutex<broadcast::Receiver<Ev>>>,
    pub(crate) tasks: Arc<tokio::sync::Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>>,
    pub(crate) workers: Arc<tokio::sync::Mutex<Option<Vec<ShutdownTask>>>>,
    pub(crate) scheduler: RelayScheduler,
    pub(crate) transit_scheduler: Option<RelayScheduler>,
    pub(crate) transport: Arc<tokio::sync::Mutex<Option<ShutdownTask>>>,
}

impl NodeHandle {
    /// Enable bounded local counters without changing traffic scheduling.
    /// Startup work may already be admitted before counters are enabled.
    pub fn enable_diagnostics(&self) {
        self.scheduler.enable_diagnostics();
        if let Some(relay) = &self.transit_scheduler {
            relay.enable_diagnostics();
        }
    }

    /// Approximate during concurrent updates; quiesce before reconciling counts.
    pub fn diagnostics(&self) -> NodeDiagnostics {
        NodeDiagnostics {
            transport: self.transport_status(),
            resources: self.scheduler.combined_resource_snapshot(),
            client: self.scheduler.diagnostics_snapshot(),
            relay: self
                .transit_scheduler
                .as_ref()
                .map(|s| s.diagnostics_snapshot())
                .unwrap_or_default(),
            client_resources: self.scheduler.resource_snapshot(),
            relay_resources: self
                .transit_scheduler
                .as_ref()
                .map(|s| s.resource_snapshot())
                .unwrap_or_default(),
        }
    }

    /// The endpoint scheduler selected at startup, independent of readiness.
    pub fn uses_gc2_routing(&self) -> bool {
        self.scheduler.is_gc2()
    }

    /// Whether the selected protocol has retained re-entry introductions.
    /// This is not a routing-readiness check; credentials may need renewal.
    pub fn has_routing_bootstrap(&self) -> bool {
        #[cfg(feature = "experimental-gc2")]
        if self.uses_gc2_routing() {
            return self.gc2_routing_bootstrap().is_ok();
        }
        self.routing_bootstrap().is_ok()
    }

    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_routing_bootstrap(
        &self,
    ) -> Result<gcoms_routing::gc2::directory::BootstrapBundle, String> {
        let current = self
            .routing
            .as_ref()
            .and_then(|runtime| runtime.gc2.get())
            .ok_or("GChat carrier not selected")?;
        let bundle = gcoms_routing::gc2::directory::BootstrapBundle {
            relays: current.directory.reentry_candidates(),
        };
        bundle.validate().map_err(|e| e.to_string())?;
        Ok(bundle)
    }

    pub fn transport_status(&self) -> TransportStatus {
        let mut result = TransportStatus {
            protocol: if self.scheduler.is_gc2() {
                "gchat"
            } else {
                "legacy"
            },
            ..Default::default()
        };
        let Some(state) = self.state.upgrade() else {
            return result;
        };
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        result.recovering_inbox = super::routing::recovering(&st);
        result.owned_aliases = st.client_relay.aliases.len();
        result.subscribed_owned_aliases = st
            .client_relay
            .aliases
            .iter()
            .filter(|a| st.subscribed_contact_aliases.contains(&a.contact.queue_id))
            .count();
        result.interactive_subscriptions = st
            .subscribed_classes
            .iter()
            .filter(|(_, class)| *class == gcoms_core::TrafficClass::Interactive)
            .count();
        result.bulk_subscriptions = st
            .subscribed_classes
            .iter()
            .filter(|(_, class)| *class == gcoms_core::TrafficClass::Bulk)
            .count();
        #[cfg(feature = "experimental-gc2")]
        if let Some(current) = st.routing.as_ref().and_then(|r| r.gc2.get()) {
            result.profile_id = Some(current.profile_id);
            result.bootstrap_version = Some(2);
            result.ready_entries = current.ready.ready_entries();
            let terminals: HashSet<_> = st
                .client_relay
                .aliases
                .iter()
                .map(|a| (a.contact.target.address, a.contact.target.relay_service_id))
                .collect();
            result.usable_terminal_routes = terminals
                .into_iter()
                .filter(|&terminal| current.ready.can_route(terminal))
                .count();
        }
        result.routing_ready = !super::routing::recovering(&st)
            && !st.owner_transition_failed
            && st.client_relay.aliases.len() >= 2
            && st
                .client_relay
                .aliases
                .iter()
                .all(|a| st.subscribed_contact_aliases.contains(&a.contact.queue_id))
            && (!self.scheduler.is_gc2() || result.usable_terminal_routes > 0);
        result
    }

    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_relay_introduction(
        &self,
    ) -> Result<gcoms_routing::gc2::directory::Introduction, String> {
        #[cfg(feature = "relay-host")]
        {
            let runtime = self.routing.as_ref().ok_or("routing not enabled")?;
            let guard = runtime.service.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard
                .as_ref()
                .ok_or("relay service not ready")?
                .gc2_introduction(now_unix()))
        }
        #[cfg(not(feature = "relay-host"))]
        {
            Err("relay hosting is not compiled in".into())
        }
    }

    #[cfg(feature = "experimental-gc2")]
    pub fn install_gc2_routing_bootstrap(
        &self,
        bundle: &gcoms_routing::gc2::directory::BootstrapBundle,
    ) -> Result<(), String> {
        let runtime = self.routing.as_ref().ok_or("routing not enabled")?;
        let current = runtime.gc2.get().ok_or("GChat carrier not selected")?;
        current
            .directory
            .remember(bundle, now_unix())
            .map_err(|e| e.to_string())?;
        #[cfg(feature = "relay-host")]
        if let Some(service) = runtime
            .service
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            service
                .gc2_directory()
                .remember(bundle, now_unix())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The socket actually owned by this runtime, including an OS-assigned port.
    pub fn listener_addr(&self) -> SocketAddr {
        self.listener_addr
    }

    /// True only after another pinned relay authenticated the current candidate.
    pub fn relay_published(&self) -> bool {
        self.routing
            .as_ref()
            .is_some_and(|r| r.published.load(std::sync::atomic::Ordering::Acquire))
    }

    pub async fn install_routing_bootstrap(
        &self,
        bundle: gcoms_routing::bootstrap::BootstrapBundle,
    ) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::InstallRoutingBootstrap { bundle, done })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub fn routing_bootstrap(&self) -> Result<gcoms_routing::bootstrap::BootstrapBundle, String> {
        self.routing
            .as_ref()
            .ok_or("routing bootstrap is unavailable in a direct fixture")?
            .bootstrap()
    }

    /// Attach the selected carrier's bootstrap without downgrading its authority.
    pub fn channel_invite_link(
        &self,
        invite: &crate::channel_invite::ChannelInvite,
    ) -> Result<String, String> {
        #[cfg(feature = "experimental-gc2")]
        if let Some(current) = self.routing.as_ref().and_then(|runtime| runtime.gc2.get()) {
            let bundle = gcoms_routing::gc2::directory::BootstrapBundle {
                relays: current.directory.reentry_candidates(),
            };
            bundle.validate().map_err(|e| e.to_string())?;
            return invite
                .to_link_with_gc2_bootstrap(bundle)
                .ok_or_else(|| "invite is too large to encode".into());
        }
        let link = if self.uses_onion_routing() {
            invite.to_link_with_bootstrap(self.routing_bootstrap()?)
        } else {
            invite.to_link()
        };
        link.ok_or_else(|| "invite is too large to encode".into())
    }

    /// Install only bootstrap material compatible with this runtime's carrier.
    pub async fn install_invite_bootstrap(
        &self,
        envelope: &crate::channel_invite::InviteEnvelope,
    ) -> Result<(), String> {
        #[cfg(feature = "experimental-gc2")]
        if let Some(bundle) = &envelope.gc2_bootstrap {
            if envelope.bootstrap.is_some() {
                return Err("invite contains conflicting bootstrap versions".into());
            }
            return self.install_gc2_routing_bootstrap(bundle);
        }
        if let Some(bundle) = &envelope.bootstrap {
            self.install_routing_bootstrap(bundle.clone()).await?;
        }
        Ok(())
    }

    /// Private local proof material for an explicitly enabled naming worker.
    /// Returns only this listener's introduction after an independent pinned
    /// probe authenticated the current candidate. Never serialize into SDK
    /// responses, public contact cards, logs, or a directory of other peers.
    pub fn local_relay_introduction(
        &self,
    ) -> Result<Option<gcoms_routing::bootstrap::BootstrapBundle>, String> {
        let Some(runtime) = &self.routing else {
            return Ok(None);
        };
        if !runtime.published.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(None);
        }
        let own = runtime
            .own_introduction()
            .ok_or("published listener has no local relay service")?;
        let bundle = gcoms_routing::bootstrap::BootstrapBundle { relays: vec![own] };
        bundle.validate().map_err(|e| e.to_string())?;
        Ok(Some(bundle))
    }

    /// Operator-private seed export; never a person's public contact card.
    pub fn relay_introduction(&self) -> Result<gcoms_routing::Relay, String> {
        let runtime = self
            .routing
            .as_ref()
            .ok_or("relay routing is not enabled")?;
        let relay = runtime
            .own_introduction()
            .ok_or("relay service is not ready")?;
        relay.validate().map_err(|e| e.to_string())?;
        Ok(relay)
    }
    pub fn uses_onion_routing(&self) -> bool {
        self.routing.is_some()
    }

    pub fn configure_catalog_origins(&self, origins: Vec<String>) -> Result<(), String> {
        if origins.len() > 8 || origins.iter().any(|h| !gcoms_routing::wire::valid_host(h)) {
            return Err("invalid catalog origin allowlist".into());
        }
        let runtime = self
            .routing
            .as_ref()
            .ok_or("catalog routing is not enabled")?;
        #[cfg(feature = "relay-host")]
        if let Some(service) = runtime
            .service
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            service
                .configure_catalog_origins(origins.clone())
                .map_err(|e| e.to_string())?;
        }
        *runtime
            .catalog_origins
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = origins;
        Ok(())
    }

    pub async fn catalog_request(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let runtime = self
            .routing
            .as_ref()
            .ok_or("catalog routing is not enabled")?;
        let origins = runtime
            .catalog_origins
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        #[cfg(feature = "experimental-gc2")]
        if self.uses_gc2_routing() {
            let current = runtime
                .gc2
                .get()
                .ok_or("GC/2 catalog routing is not initialized")?;
            let response =
                gcoms_routing::catalog::request_gc2(&current.ready, &origins, method, url, body)
                    .await
                    .map_err(|e| e.to_string())?;
            return Ok((response.status, response.body));
        }
        let response = gcoms_routing::catalog::request(
            &runtime.discovery.connector,
            &origins,
            method,
            url,
            body,
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok((response.status, response.body))
    }

    pub async fn current_info(&self) -> Result<NodeInfo, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::CurrentInfo { done })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())
    }

    /// Await a usable external inbox without delaying profile unlock or IPC.
    /// The caller owns the deadline; retries never extend an invite or attempt.
    pub async fn wait_for_inbox(&self, deadline: tokio::time::Instant) -> Result<(), String> {
        tokio::time::timeout_at(deadline, async {
            loop {
                let info = self.current_info().await?;
                if info.primary().is_some()
                    && self.routing.as_ref().is_none_or(|runtime| {
                        !runtime
                            .recovering_owner
                            .load(std::sync::atomic::Ordering::Acquire)
                    })
                    && (!self.scheduler.is_gc2() || self.transport_status().routing_ready)
                {
                    return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "inbox routing is recovering".to_owned())?
    }

    /// Signs a fixed-domain digest without exporting the GC identity key.
    pub async fn sign_identity_digest(&self, digest: [u8; 32]) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SignIdentityDigest { digest, done })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())
    }

    /// Signs only the GC-identity role of a principal-binding claims hash.
    pub async fn sign_principal_binding_hash(
        &self,
        claims_hash: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SignPrincipalBindingHash { claims_hash, done })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())
    }

    #[doc(hidden)]
    /// Attach trusted bootstrap provisioning after local startup.
    pub async fn install_inbox_relay(&self, relay: NodeInfo) -> Result<(), String> {
        let (done, result) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::InstallInboxRelay {
                relay: Box::new(relay),
                done,
            })
            .await
            .map_err(|_| "node closed")?;
        result.await.map_err(|_| "node closed")?
    }

    pub async fn renew_contacts_now(&self) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::RenewContacts { done })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    pub async fn list_channels(&self) -> Result<Vec<ChannelView>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ListChannels { done })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())
    }

    pub async fn channel_roster(
        &self,
        channel: &str,
    ) -> Result<Vec<crate::channel::ChannelMemberSummary>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ChannelRoster {
                channel: channel.to_string(),
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    pub async fn public_channel_descriptor(
        &self,
        channel: &str,
        description: &str,
        activity: crate::channel::ActivityBucket,
        automatic_join: crate::channel::AutomaticJoinEndpoint,
        expires_at_unix: u64,
    ) -> Result<crate::channel::PublicChannelDescriptor, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::PublicChannelDescriptor {
                channel: channel.to_string(),
                description: description.to_string(),
                activity,
                automatic_join: Box::new(automatic_join),
                expires_at_unix,
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    /// Issues a private, one-use local-control-plane relay provisioning card.
    pub async fn provision_client_relay(&self) -> Result<NodeInfo, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ProvisionClientRelay { done })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    pub async fn send_1to1(
        &self,
        peer: &NodeInfo,
        text: &[u8],
        via: Option<NodeInfo>,
    ) -> Result<(), String> {
        validate_application_payload(text)?;
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::Send1to1 {
                durable: false,
                peer: Box::new(peer.clone()),
                text: text.to_vec(),
                via: Box::new(via),
                class: None,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    pub async fn send_1to1_tracked(
        &self,
        peer: &NodeInfo,
        text: &[u8],
        via: Option<NodeInfo>,
    ) -> Result<[u8; 16], String> {
        validate_application_payload(text)?;
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::Send1to1Tracked {
                durable: false,
                peer: Box::new(peer.clone()),
                text: text.to_vec(),
                via: Box::new(via),
                class: None,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    /// Durable tracked send: returns the exact logical message ID that the
    /// application acknowledgment (`Ev::DirectDelivery`) carries. The record
    /// is persisted before this returns; network delivery is deferred.
    pub async fn send_durable_1to1_tracked(
        &self,
        peer: &NodeInfo,
        body: &[u8],
        via: Option<NodeInfo>,
    ) -> Result<[u8; 16], String> {
        self.send_durable_1to1_tracked_class(peer, body, via, None)
            .await
    }

    pub async fn send_durable_1to1_tracked_class(
        &self,
        peer: &NodeInfo,
        body: &[u8],
        via: Option<NodeInfo>,
        class: Option<gcoms_core::TrafficClass>,
    ) -> Result<[u8; 16], String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::Send1to1Tracked {
                durable: true,
                peer: Box::new(peer.clone()),
                text: body.to_vec(),
                via: Box::new(via),
                class,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub async fn send_direct_presence(
        &self,
        peer: &NodeInfo,
        mode: PresenceMode,
        lease_secs: u32,
        via: Option<NodeInfo>,
    ) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SendDirectPresence {
                peer: Box::new(peer.clone()),
                mode,
                lease_secs,
                via: Box::new(via),
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    pub async fn set_direct_presence_opt_in(
        &self,
        peer: &NodeInfo,
        enabled: bool,
        via: Option<NodeInfo>,
    ) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SetDirectPresenceOptIn {
                peer: Box::new(peer.clone()),
                enabled,
                via: Box::new(via),
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    /// Subscribe to the node event stream. Each subscriber gets its own
    /// receiver; slow subscribers lag (bounded buffer, oldest dropped).
    pub fn subscribe(&self) -> broadcast::Receiver<Ev> {
        self.events_tx.subscribe()
    }

    pub fn try_recv_event(&self) -> Result<Ev, RecvEventError> {
        match self.compat_rx.try_lock().ok().map(|mut r| r.try_recv()) {
            Some(Ok(ev)) => Ok(ev),
            Some(Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped))) => {
                metrics::log_event("event_lag", &[("skipped", skipped.to_string())]);
                Ok(Ev::Lagged { skipped })
            }
            Some(Err(tokio::sync::broadcast::error::TryRecvError::Empty)) => {
                Err(RecvEventError::Empty)
            }
            _ => Err(RecvEventError::Closed),
        }
    }

    /// Single-consumer event pump. A lag is reported as [`Ev::Lagged`]
    /// rather than swallowed.
    pub async fn next_event(&self) -> Option<Ev> {
        match self.compat_rx.lock().await.recv().await {
            Ok(ev) => Some(ev),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                metrics::log_event("event_lag", &[("skipped", skipped.to_string())]);
                Some(Ev::Lagged { skipped })
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }

    pub async fn shutdown(&self) {
        if let Some(runtime) = &self.routing {
            runtime.stop_publication();
        }
        #[cfg(feature = "relay-host")]
        if let Some(connectivity) = self.connectivity.lock().await.take() {
            connectivity.shutdown().await;
        }
        if let Some(transport) = self.transport.lock().await.take() {
            transport.stop.send_replace(true);
            let _ = transport.task.await;
        }
        self.scheduler.shutdown();
        if let Some(relay) = &self.transit_scheduler {
            relay.shutdown();
        }
        // These parents own subscription/invitation tasks. Let them abort and
        // join their children before acknowledging shutdown to the profile owner.
        if let Some(workers) = self.workers.lock().await.take() {
            for worker in &workers {
                worker.stop.send_replace(true);
            }
            for worker in workers {
                let _ = worker.task.await;
            }
        }
        let (done, done_rx) = tokio::sync::oneshot::channel();
        // Saturation can block enqueue as well as completion. Bound the whole
        // exchange before aborting and joining the owned runtime tasks below.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            if self.cmd_tx.send(Cmd::Shutdown { done }).await.is_ok() {
                let _ = done_rx.await;
            }
        })
        .await;
        if let Some(tasks) = self.tasks.lock().await.take() {
            for task in &tasks {
                task.abort();
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    }

    pub async fn create_channel(
        &self,
        channel: &str,
        display: &str,
        capacity: usize,
        visibility: crate::channel::ChannelVisibility,
    ) -> Result<crate::channel::ChannelId, String> {
        if self.uses_onion_routing() {
            self.wait_for_inbox(tokio::time::Instant::now() + std::time::Duration::from_secs(120))
                .await?;
        }
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::CreateChannel {
                channel: channel.to_string(),
                display: display.to_string(),
                capacity,
                visibility,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    pub async fn prepare_channel_join(&self, display: &str) -> Result<u64, String> {
        if self.uses_onion_routing() {
            self.wait_for_inbox(tokio::time::Instant::now() + std::time::Duration::from_secs(120))
                .await?;
        }
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::PrepareChannelJoin {
                display: display.to_string(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    pub async fn channel_key_package(&self, req_id: u64) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ChannelKeyPackage { req_id, done })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    pub async fn admit_channel(
        &self,
        channel: &str,
        key_package: &[u8],
        member_name: &str,
    ) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::AdmitChannel {
                channel: channel.to_string(),
                key_package: key_package.to_vec(),
                member_name: member_name.to_string(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Recover only an existing admission's transport. A hop receipt is not a member ACK.
    pub async fn recover_channel_route(
        &self,
        channel: &str,
        expected_id: crate::channel::ChannelId,
        expected_epoch: u64,
        welcome: &[u8],
        peer: &NodeInfo,
    ) -> Result<[u8; 16], String> {
        let (done, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::RecoverChannelRoute {
                channel: channel.into(),
                expected_id,
                expected_epoch,
                welcome: welcome.to_vec(),
                peer: Box::new(peer.clone()),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        rx.await.map_err(|e| e.to_string())?
    }

    /// Mint a single-use invite for a channel this node owns. Returns
    /// `(invite_id, invite_secret, expiry_unix)`; the caller assembles the
    /// shareable link (adding the rendezvous queue coordinates and this node's
    /// contact bundle).
    pub async fn create_channel_invite(
        &self,
        channel: &str,
        ttl_secs: u64,
    ) -> Result<CreatedInvite, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::CreateChannelInvite {
                channel: channel.to_string(),
                ttl_secs,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Redeem a single-use invite as the channel owner, admitting the member
    /// carried by `key_package` and returning their Welcome. Fails closed with
    /// "invite already used" / "invite expired" / "invite not found".
    pub async fn redeem_channel_invite(
        &self,
        channel: &str,
        invite_id: [u8; 16],
        invite_secret: [u8; 32],
        key_package: &[u8],
        member_name: &str,
    ) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::RedeemChannelInvite {
                channel: channel.to_string(),
                invite_id,
                invite_secret,
                key_package: key_package.to_vec(),
                member_name: member_name.to_string(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Friend side: redeem an invite by contacting the owner over the relay.
    /// Sends a sealed InviteRedeem and waits up to `timeout_secs` for the
    /// owner's InviteWelcome; returns the MLS Welcome to feed `join_channel`.
    #[allow(clippy::too_many_arguments)]
    pub async fn redeem_invite_remote(
        &self,
        owner: NodeInfo,
        channel: &str,
        member_name: &str,
        key_package: &[u8],
        invite_id: [u8; 16],
        invite_secret: [u8; 32],
        timeout_secs: u64,
    ) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::RedeemInviteRemote {
                owner: Box::new(owner),
                channel: channel.to_string(),
                member_name: member_name.to_string(),
                key_package: key_package.to_vec(),
                invite_id,
                invite_secret,
                timeout_secs,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    pub async fn join_channel(
        &self,
        req_id: u64,
        channel: &str,
        visibility: crate::channel::ChannelVisibility,
        welcome: &[u8],
    ) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::JoinChannel {
                req_id,
                channel: channel.to_string(),
                visibility,
                welcome: welcome.to_vec(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Send channel text. Even this untracked API preserves local acceptance
    /// after a successful persistent commit covering the complete, nonempty
    /// remote recipient roster if the first hop fails. Without that durable
    /// outbox, hop failures remain errors. Unlike the tracked variant, this API
    /// does not require persistence or a complete roster before attempting send.
    /// This does not assert recipient delivery; observe `Ev::ChannelDelivery`.
    pub async fn send_channel_text(&self, channel: &str, text: &[u8]) -> Result<(), String> {
        validate_application_payload(text)?;
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SendChannelText {
                channel: channel.to_string(),
                text: text.to_vec(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Return the exact wire ID after durable local acceptance. Requires a
    /// persistent sink and routes for every remote roster member. A first-hop
    /// failure leaves the exact outbox eligible for retry across restart.
    pub async fn send_channel_text_tracked(
        &self,
        channel: &str,
        text: &[u8],
    ) -> Result<[u8; 16], String> {
        validate_application_payload(text)?;
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SendChannelTextTracked {
                channel: channel.into(),
                text: text.to_vec(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub async fn send_channel_presence(
        &self,
        channel: &str,
        mode: PresenceMode,
        lease_secs: u32,
    ) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SendChannelPresence {
                channel: channel.to_string(),
                mode,
                lease_secs,
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    pub async fn set_channel_presence_opt_in(
        &self,
        channel: &str,
        enabled: bool,
    ) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SetChannelPresenceOptIn {
                channel: channel.to_string(),
                enabled,
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    pub async fn send_channel_direct(
        &self,
        channel: &str,
        recipient_member_id: [u8; 32],
        text: &[u8],
    ) -> Result<[u8; 16], String> {
        validate_application_payload(text)?;
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SendChannelDirect {
                channel: channel.to_string(),
                recipient: recipient_member_id,
                text: text.to_vec(),
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }

    pub async fn remove_channel_member(
        &self,
        channel: &str,
        member_id: [u8; 32],
    ) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::RemoveChannelMember {
                channel: channel.to_string(),
                member_id,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Export the node's recoverable state (1:1 sessions, channel state and
    /// directories). Bytes are key material — encrypt before storing.
    /// Relay queues, peer views and tokens are NOT exported (RAM-only by
    /// design, SPEC §4 R1).
    #[cfg(feature = "client-persist")]
    pub async fn export_state(&self) -> Result<Vec<u8>, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ExportState { done })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Import state previously produced by [`NodeHandle::export_state`].
    /// Entries are merged into (overwrite) the live maps; call right after
    /// `start`, before traffic.
    #[cfg(feature = "client-persist")]
    pub async fn import_state(&self, data: &[u8]) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ImportState {
                data: data.to_vec(),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        done_rx.await.map_err(|e| e.to_string())?
    }

    /// Snapshot bounded intermediary queues, available with or without persistence.
    pub async fn intermediary_stats(&self) -> Result<IntermediaryStats, String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::IntermediaryStats { done })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())
    }

    pub async fn send_volatile_application(
        &self,
        peer: &NodeInfo,
        body: &[u8],
    ) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SendVolatileApplication {
                peer: Box::new(peer.clone()),
                body: zeroize::Zeroizing::new(body.to_vec()),
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub async fn send_durable_1to1(
        &self,
        peer: &NodeInfo,
        body: &[u8],
        via: Option<NodeInfo>,
    ) -> Result<(), String> {
        self.send_durable_1to1_class(peer, body, via, None).await
    }

    /// Durable send with an explicit scheduling class. The class only selects
    /// the ratchet reservation and scheduler admission; it changes no wire
    /// bytes. Deferred copies re-derive the class from the record.
    pub async fn send_durable_1to1_class(
        &self,
        peer: &NodeInfo,
        body: &[u8],
        via: Option<NodeInfo>,
        class: Option<gcoms_core::TrafficClass>,
    ) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::Send1to1 {
                durable: true,
                peer: Box::new(peer.clone()),
                text: body.to_vec(),
                via: Box::new(via),
                class,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub async fn configure_component_routes(
        &self,
        policy: gcoms_core::component::RoutingPolicy,
    ) -> Result<(), String> {
        self.configure_component_routes_with_authority(policy, None)
            .await
    }

    /// A host authority can admit a retained component-owned member profile.
    /// Certificate validation is performed against the actual decrypted identity.
    pub async fn configure_component_routes_with_authority(
        &self,
        policy: gcoms_core::component::RoutingPolicy,
        binding: Option<std::sync::Arc<dyn ComponentAuthority>>,
    ) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ConfigureComponentRoutes {
                policy,
                binding,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    /// Hosts must retain machine IPC scope for an already owned profile.
    pub async fn machine_ownership_required(&self) -> Result<bool, String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::MachineOwnershipRequired { done })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())
    }

    /// Read-only retained requirement; hosts must enforce it before serving IPC.
    pub async fn central_ownership_required(&self) -> Result<bool, String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::CentralOwnershipRequired { done })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())
    }

    /// Trusted central host opt-in. Only local component delivery uses this
    /// policy; original network/chat admission and retained state stay unchanged.
    pub async fn configure_central_component_routes(
        &self,
        policy: gcoms_core::component::RoutingPolicy,
        primary: Vec<[u8; 16]>,
    ) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ConfigureCentralComponentRoutes {
                policy,
                primary,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    /// Trusted local host opt-in; ordinary chat profiles leave this disabled.
    pub async fn enable_durable_applications(&self) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::EnableDurableApplications { done })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    /// Trusted component host only. Requires an explicit reciprocal local route
    /// and persistent machine inbox; ordinary network self-contact stays refused.
    pub async fn submit_local_component(&self, body: &[u8]) -> Result<(), String> {
        gcoms_core::component::RoutedApplication::decode(body)?;
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::SubmitLocalComponent {
                body: body.to_vec(),
                done,
            })
            .await
            .map_err(|error| error.to_string())?;
        receive.await.map_err(|error| error.to_string())?
    }

    pub async fn application_inbox(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<ApplicationDelivery>, String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ApplicationInboxPage { after, limit, done })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub async fn commit_application(&self, sequence: u64, digest: [u8; 32]) -> Result<(), String> {
        let (done, receive) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::ApplicationInboxReceipt {
                sequence,
                digest,
                done,
            })
            .await
            .map_err(|e| e.to_string())?;
        receive.await.map_err(|e| e.to_string())?
    }

    pub async fn persist_state(&self) -> Result<(), String> {
        let (done, done_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Cmd::PersistState { done })
            .await
            .map_err(|error| error.to_string())?;
        done_rx.await.map_err(|error| error.to_string())?
    }
}
