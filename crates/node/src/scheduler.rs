use crate::alias::{AliasContact, OwnedAlias, RelayProvision};
use crate::relay::{Frwd, FrwdTargetPolicy, RelayPush, RelayTarget, UnauthenticatedRelayPush};
#[cfg(test)]
use gcoms_core::CellType;
use gcoms_core::{Cell, TrafficClass};
use gcoms_transport::{CellStream, Tp1Client};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{oneshot, watch, Notify};

mod budget;
#[cfg(feature = "experimental-gc2")]
mod gc2;
mod pending;
use pending::PendingRequest;
pub mod diagnostics;
#[cfg(test)]
mod pipeline_admission_tests;
#[cfg(test)]
mod pipeline_cover_tests;
#[cfg(test)]
mod pipeline_tests;
pub(crate) use budget::Reservation as PayloadReservation;
#[cfg(feature = "experimental-gc2")]
pub(crate) use budget::{PayloadUsage, RetainedAccount, RetainedPriority, RetainedUpdate};
pub use budget::{ResourceSnapshot, MAX_BYTES as MAX_QUEUED_BYTES, MAX_JOBS as MAX_QUEUED_JOBS};

pub const SLOT_INTERVAL: Duration = Duration::from_secs(3);
pub const EMISSION_PROBABILITY: f64 = 0.5;
/// Probability that a cover cell is padded to B3 rather than B2, so idle
/// lanes carry 16 KiB frames at the same base rate real traffic does
/// (SPEC §7.5).
pub const COVER_B3_PROB: f64 = 1.0 / 16.0;
/// An unpinned lane with no real job for this long is closed.
pub const LANE_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
/// Upper bound on concurrent lanes. Beyond it `open_lane`/`enqueue` fail
/// with `EnqueueError::Full` so a remote party cannot grow lane count
/// without bound.
pub const MAX_LANES: usize = 64;
const ADMIN_INTERVAL: Duration = Duration::from_millis(250);
const MAINTENANCE_MIN_MS: u64 = 2250;
const MAINTENANCE_MAX_MS: u64 = 3750;
const LANE_CAPACITY: usize = 256;
const CLASS_COUNT: usize = 5;
const LANE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

// Lease and subscription liveness has its own fixed queue and cadence. It
// never takes priority in, or derives timing from, a user data lane.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProducerClass {
    Direct,
    ChannelData,
    ChannelControl,
    Forward,
    Administration,
}

impl ProducerClass {
    fn index(self) -> usize {
        match self {
            Self::Direct => 0,
            Self::ChannelData => 1,
            Self::ChannelControl => 2,
            Self::Forward => 3,
            Self::Administration => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionState {
    Queued,
    HopAccepted,
    Failed,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueError {
    Full,
    Pending,
    Shutdown,
    InvalidCell,
}

#[derive(Clone, Debug)]
pub struct SchedulerProfile {
    slot_interval: Duration,
    emission_probability: f64,
    admin_interval: Duration,
    emit_cover: bool,
    maintenance_min_ms: u64,
    maintenance_max_ms: u64,
    deterministic_seed: Option<u64>,
    connect_retry_base: Duration,
    max_in_flight: usize,
    natural: bool,
}

impl SchedulerProfile {
    pub(crate) fn production() -> Self {
        Self {
            slot_interval: SLOT_INTERVAL,
            emission_probability: EMISSION_PROBABILITY,
            admin_interval: ADMIN_INTERVAL,
            emit_cover: true,
            maintenance_min_ms: MAINTENANCE_MIN_MS,
            maintenance_max_ms: MAINTENANCE_MAX_MS,
            deterministic_seed: None,
            connect_retry_base: Duration::from_millis(500),
            max_in_flight: 1,
            natural: false,
        }
    }

    pub(crate) fn fixture() -> Self {
        Self {
            slot_interval: Duration::from_millis(10),
            emission_probability: 1.0,
            admin_interval: Duration::from_millis(10),
            emit_cover: false,
            maintenance_min_ms: MAINTENANCE_MIN_MS,
            maintenance_max_ms: MAINTENANCE_MAX_MS,
            deterministic_seed: None,
            connect_retry_base: Duration::from_millis(1),
            max_in_flight: 1,
            natural: false,
        }
    }

    /// Production traffic behavior at a compressed cadence for local qualification.
    pub fn compressed_production(seed: u64) -> Self {
        Self {
            slot_interval: Duration::from_millis(10),
            emission_probability: EMISSION_PROBABILITY,
            admin_interval: Duration::from_millis(5),
            emit_cover: true,
            maintenance_min_ms: 25,
            maintenance_max_ms: 40,
            deterministic_seed: Some(seed),
            connect_retry_base: Duration::from_millis(5),
            max_in_flight: 1,
            natural: false,
        }
    }

    pub(crate) fn maintenance_delay(&self, rng: &mut StdRng) -> Duration {
        Duration::from_millis(rng.gen_range(self.maintenance_min_ms..self.maintenance_max_ms))
    }

    /// Bounded pipelining control; retains this profile's existing slot cadence.
    pub fn with_pipelining(mut self) -> Self {
        self.max_in_flight = 4;
        self
    }

    /// Distinct deterministic streams for independent maintenance loops.
    pub(crate) fn maintenance_rng_labeled(&self, node_seed: [u8; 32], label: &[u8]) -> StdRng {
        match self.deterministic_seed {
            Some(seed) => {
                let mut material = Sha256::new();
                material.update(b"gc-maintenance-schedule-v1");
                material.update(seed.to_le_bytes());
                material.update(node_seed);
                material.update(label);
                StdRng::from_seed(material.finalize().into())
            }
            None => StdRng::from_entropy(),
        }
    }
}

impl fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "relay lane queue is full"),
            Self::Pending => write!(f, "the same ciphertext already has an active relay attempt"),
            Self::Shutdown => write!(f, "relay scheduler is shut down"),
            Self::InvalidCell => write!(
                f,
                "relay job requires a canonical MSG within the size limit"
            ),
        }
    }
}

pub struct Receipt {
    state: CompletionState,
    completion: oneshot::Receiver<JobResult>,
}

impl Receipt {
    #[cfg(all(test, feature = "client-persist"))]
    pub(crate) fn test_channel() -> (oneshot::Sender<JobResult>, Self) {
        let (sender, completion) = oneshot::channel();
        (
            sender,
            Self {
                state: CompletionState::Queued,
                completion,
            },
        )
    }

    pub fn state(&self) -> CompletionState {
        self.state
    }

    pub async fn completion(self) -> JobResult {
        self.completion.await.unwrap_or(JobResult::Shutdown)
    }
}

pub enum JobResult {
    HopAccepted(bytes::Bytes),
    Stream(CellStream),
    #[cfg(feature = "experimental-gc2")]
    NaturalStream(gcoms_transport::gc2::NaturalStream),
    Failed(String),
    Shutdown,
}

impl JobResult {
    pub fn state(&self) -> CompletionState {
        match self {
            Self::HopAccepted(_) | Self::Stream(_) => CompletionState::HopAccepted,
            #[cfg(feature = "experimental-gc2")]
            Self::NaturalStream(_) => CompletionState::HopAccepted,
            Self::Failed(_) => CompletionState::Failed,
            Self::Shutdown => CompletionState::Shutdown,
        }
    }

    pub fn accepted(self) -> Result<bytes::Bytes, String> {
        match self {
            Self::HopAccepted(body) => Ok(body),
            Self::Failed(error) => Err(error),
            Self::Shutdown => Err("relay scheduler shut down".into()),
            Self::Stream(_) => Err("unexpected stream completion".into()),
            #[cfg(feature = "experimental-gc2")]
            Self::NaturalStream(_) => Err("unexpected natural stream completion".into()),
        }
    }

    /// Receive semantic MSGs from the explicitly selected wire codec.
    pub fn delivery_stream(self) -> Result<DeliveryStream, String> {
        match self {
            #[cfg(feature = "experimental-gc2")]
            Self::NaturalStream(stream) => Ok(DeliveryStream::Natural(stream)),
            other => other.stream().map(DeliveryStream::Legacy),
        }
    }

    pub fn stream(self) -> Result<CellStream, String> {
        match self {
            Self::Stream(stream) => Ok(stream),
            #[cfg(feature = "experimental-gc2")]
            Self::NaturalStream(_) => Err("GC/2 requires delivery_stream".into()),
            Self::Failed(error) => Err(error),
            Self::Shutdown => Err("relay scheduler shut down".into()),
            Self::HopAccepted(_) => Err("unexpected finite completion".into()),
        }
    }
}

/// The natural wire is validated before conversion to the node's semantic Cell
/// representation. There is no cross-version decoding or transport fallback.
pub enum DeliveryStream {
    Legacy(CellStream),
    #[cfg(feature = "experimental-gc2")]
    Natural(gcoms_transport::gc2::NaturalStream),
}

impl DeliveryStream {
    pub async fn recv(&mut self) -> Option<gcoms_transport::client::Result<Cell>> {
        match self {
            Self::Legacy(stream) => stream.recv().await,
            #[cfg(feature = "experimental-gc2")]
            Self::Natural(stream) => stream.recv().await.map(|result| {
                result.map(|cell| {
                    let mut semantic = Cell::new(cell.kind(), cell.flags(), 0, cell.into_payload());
                    semantic.version = gcoms_core::gc2::VERSION;
                    semantic
                })
            }),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct LaneKey {
    address: SocketAddr,
    service_id: [u8; 32],
    token: String,
    administrative: bool,
    natural_class: Option<TrafficClass>,
}

enum SemanticJob {
    Push {
        contact: AliasContact,
        inner: Cell,
    },
    Frwd {
        relay: RelayProvision,
        destination: AliasContact,
        inner: Cell,
        policy: FrwdTargetPolicy,
    },
    Forward {
        target: RelayTarget,
        push: UnauthenticatedRelayPush,
    },
    #[cfg(feature = "experimental-gc2")]
    ForwardNatural {
        target: RelayTarget,
        push: gcoms_protocol::relay::gc2::UnverifiedPush,
    },
    AdminPost {
        target: RelayTarget,
        token: String,
        cell: Cell,
    },
    Subscribe(Box<OwnedAlias>),
}

/// What a lane may emit when it has no real job: enough to build a fresh,
/// authenticated, zero-length deposit toward the same hop. Captured when
/// the lane opens, never derived from a real request.
#[derive(Clone)]
pub enum LaneAuth {
    /// Direct deposit lane to a relay queue.
    Push { contact: AliasContact },
    /// FRWD lane to an intermediary; cover targets a decoy relay.
    Frwd {
        relay: RelayProvision,
        decoy_target: RelayTarget,
        policy: FrwdTargetPolicy,
    },
}

impl LaneAuth {
    fn key(&self) -> LaneKey {
        match self {
            Self::Push { contact } => LaneKey {
                address: contact.target.address,
                service_id: contact.target.relay_service_id,
                token: gcoms_transport::encode_b64url(&contact.queue_id),
                administrative: false,
                natural_class: None,
            },
            Self::Frwd { relay, .. } => {
                let target = relay
                    .aliases
                    .first()
                    .map(|alias| alias.contact.target.clone())
                    .unwrap_or(RelayTarget {
                        address: "0.0.0.0:0".parse().expect("static"),
                        relay_service_id: [0; 32],
                    });
                LaneKey {
                    address: target.address,
                    service_id: target.relay_service_id,
                    token: relay.frwd_path.clone(),
                    administrative: false,
                    natural_class: None,
                }
            }
        }
    }

    /// A fresh cover request: new nonce, current expiry, valid MAC, random
    /// bucket. Byte-for-byte it is a deposit the relay must authenticate;
    /// its only distinguishing property is `msg_len = 0`, visible to the
    /// relay alone.
    fn cover_request(&self, round: u16, rng: &mut StdRng) -> Result<Request, String> {
        let pad_b3 = rng.gen_bool(COVER_B3_PROB);
        match self {
            Self::Push { contact } => {
                ensure_live_authority(contact.expiry)?;
                let push = RelayPush::cover(
                    contact.queue_id,
                    contact.epoch,
                    random_nonzero_with(rng),
                    now_unix().saturating_add(60).min(contact.expiry),
                );
                let mut cell = push
                    .encode_into_cell(&contact.push_cap, &contact.target.relay_service_id)
                    .map_err(|e| e.to_string())?;
                cell.round_ctr = round;
                Ok(Request::Post {
                    excluded: Vec::new(),
                    token: gcoms_transport::encode_b64url(&contact.queue_id),
                    target: contact.target.clone(),
                    wire: pad_cover(&cell, pad_b3)?,
                })
            }
            Self::Frwd {
                relay,
                decoy_target,
                policy,
            } => {
                let intermediary = relay
                    .aliases
                    .first()
                    .ok_or("client relay provision has no target")?
                    .contact
                    .target
                    .clone();
                let frwd = Frwd {
                    target: decoy_target.clone(),
                    frwd_expiry: now_unix().saturating_add(30),
                    relay_push: None,
                    nonce: random_nonzero_with(rng),
                };
                let mut cell = frwd
                    .encode_into_cell_with_policy(
                        &relay.hop_key,
                        &intermediary.relay_service_id,
                        policy,
                    )
                    .map_err(|e| e.to_string())?;
                cell.round_ctr = round;
                Ok(Request::Post {
                    excluded: vec![(decoy_target.address, decoy_target.relay_service_id)],
                    target: intermediary,
                    token: relay.frwd_path.clone(),
                    wire: pad_cover(&cell, pad_b3)?,
                })
            }
        }
    }
}

/// Encode a (small) cover cell to B2 or, with `COVER_B3_PROB`, to B3.
fn pad_cover(cell: &Cell, pad_b3: bool) -> Result<Vec<u8>, String> {
    let bucket = if pad_b3 {
        gcoms_core::Bucket::B3
    } else {
        gcoms_core::Bucket::B2
    };
    cell.encode(bucket).map_err(|e| e.to_string())
}

struct QueuedJob {
    semantic: SemanticJob,
    done: oneshot::Sender<JobResult>,
    queued_at: Option<std::time::Instant>,
    traffic: TrafficClass,
    producer: [u8; 32],
    _reservation: Option<budget::Reservation>,
}

struct ProducerQueue {
    producer: [u8; 32],
    traffic: TrafficClass,
    jobs: VecDeque<QueuedJob>,
    deficit: usize,
    credit_due: bool,
}

struct FairQueue {
    classes: [VecDeque<ProducerQueue>; CLASS_COUNT],
    len: usize,
    next: usize,
    capacity: usize,
}

impl FairQueue {
    fn new(capacity: usize) -> Self {
        Self {
            classes: std::array::from_fn(|_| VecDeque::new()),
            len: 0,
            next: 0,
            capacity,
        }
    }

    fn push(&mut self, class: ProducerClass, job: QueuedJob) -> bool {
        if self.len >= self.capacity {
            return false;
        }
        let queues = &mut self.classes[class.index()];
        if let Some(queue) = queues
            .iter_mut()
            .find(|queue| queue.producer == job.producer && queue.traffic == job.traffic)
        {
            queue.jobs.push_back(job);
        } else {
            queues.push_back(ProducerQueue {
                producer: job.producer,
                traffic: job.traffic,
                jobs: VecDeque::from([job]),
                deficit: 0,
                credit_due: true,
            });
        }
        self.len += 1;
        true
    }

    #[cfg(test)]
    fn pop(&mut self) -> Option<QueuedJob> {
        self.pop_eligible(true)
    }

    fn pop_eligible(&mut self, bulk_allowed: bool) -> Option<QueuedJob> {
        // Deficit round robin preserves FIFO within each producer/class, and
        // charges bytes rather than letting 16 KiB cells dominate 4 KiB cells.
        // A maximum cell needs four quanta; this loop is bounded by lane capacity.
        for _ in 0..4 {
            for offset in 0..CLASS_COUNT {
                let index = (self.next + offset) % CLASS_COUNT;
                let queues = &mut self.classes[index];
                for _ in 0..queues.len() {
                    let mut queue = queues.pop_front().expect("bounded iteration");
                    if queue.traffic == TrafficClass::Bulk && !bulk_allowed {
                        queues.push_back(queue);
                        continue;
                    }
                    if queue.credit_due {
                        queue.deficit = queue.deficit.saturating_add(4096).min(32768);
                        queue.credit_due = false;
                    }
                    let cost = queue
                        .jobs
                        .front()
                        .expect("nonempty producer")
                        .semantic
                        .service_bytes();
                    if cost > queue.deficit {
                        queue.credit_due = true;
                        queues.push_back(queue);
                        continue;
                    }
                    let job = queue.jobs.pop_front().expect("nonempty producer");
                    queue.deficit -= cost;
                    if let Some(next) = queue.jobs.front() {
                        if next.semantic.service_bytes() <= queue.deficit {
                            // Spend leftover credit without granting another quantum.
                            queues.push_front(queue);
                        } else {
                            queue.credit_due = true;
                            queues.push_back(queue);
                        }
                    }
                    self.len -= 1;
                    self.next = (index + 1) % CLASS_COUNT;
                    return Some(job);
                }
            }
        }
        None
    }

    fn shutdown(&mut self) {
        for queues in &mut self.classes {
            for queue in queues.drain(..) {
                for job in queue.jobs {
                    let _ = job.done.send(JobResult::Shutdown);
                }
            }
        }
        self.len = 0;
    }
}

struct Lane {
    queue: Mutex<FairQueue>,
    /// Authority for cover on this lane. `None` for administrative lanes and
    /// for lanes opened by a forwarded job (an intermediary never emits
    /// cover on behalf of a remote submitter).
    auth: Mutex<Option<LaneAuth>>,
    notify: Notify,
    /// Pinned lanes (own relay, active intermediary set) survive idleness.
    pinned: std::sync::atomic::AtomicBool,
    /// Instant of the last real job, for the idle sweep.
    last_real: Mutex<std::time::Instant>,
    /// Set by `close_lane`; the worker drains and exits.
    closing: std::sync::atomic::AtomicBool,
}

struct Inner {
    client: Arc<Tp1Client>,
    lanes: Mutex<HashMap<LaneKey, Arc<Lane>>>,
    shutdown: watch::Sender<bool>,
    slot_interval: Duration,
    emission_probability: f64,
    admin_interval: Duration,
    emit_cover: bool,
    deterministic_seed: Option<u64>,
    connect_retry_base: Duration,
    diagnostics: diagnostics::Diagnostics,
    budget: budget::Budget,
    max_in_flight: usize,
    natural: bool,
}

#[derive(Clone)]
pub struct RelayScheduler {
    inner: Arc<Inner>,
}

impl RelayScheduler {
    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn retained_account(&self) -> RetainedAccount {
        self.inner.budget.retained_account()
    }

    pub(crate) fn retain_attempt_payload(
        &self,
        bytes: usize,
    ) -> Result<PayloadReservation, EnqueueError> {
        self.inner.budget.reserve(bytes, None)
    }

    pub fn new(client: Arc<Tp1Client>) -> Self {
        Self::with_profile(client, SchedulerProfile::production())
    }

    /// Experimental natural-cell scheduler. Only an existing-entry connector can
    /// construct it; application requests cannot open a new physical entry.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2(connector: Arc<gcoms_routing::gc2::owner::ReadyConnector>) -> Result<Self, String> {
        let client = Arc::new(Tp1Client::with_connector(connector).map_err(|e| e.to_string())?);
        let mut profile = SchedulerProfile::production().with_pipelining();
        profile.natural = true;
        profile.emit_cover = false;
        Ok(Self::with_profile(client, profile))
    }

    pub fn is_gc2(&self) -> bool {
        self.inner.natural
    }

    pub fn subscription_classes(&self) -> &'static [TrafficClass] {
        if self.is_gc2() {
            &[TrafficClass::Interactive, TrafficClass::Bulk]
        } else {
            &[TrafficClass::Interactive]
        }
    }

    pub(crate) fn with_profile(client: Arc<Tp1Client>, profile: SchedulerProfile) -> Self {
        let budget =
            budget::Budget::with_cover_reserve(if profile.emit_cover { MAX_LANES } else { 0 });
        Self::with_budget(client, profile, budget)
    }

    pub(crate) fn with_transit(
        client: Arc<Tp1Client>,
        transit: Arc<Tp1Client>,
        profile: SchedulerProfile,
    ) -> (Self, Self) {
        let (client_budget, transit_budget) =
            budget::Budget::pair(if profile.emit_cover { MAX_LANES } else { 0 });
        (
            Self::with_budget(client, profile.clone(), client_budget),
            Self::with_budget(transit, profile, transit_budget),
        )
    }

    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn with_gc2_transit(
        client: Arc<Tp1Client>,
        transit: Arc<Tp1Client>,
    ) -> (Self, Self) {
        let mut profile = SchedulerProfile::production().with_pipelining();
        profile.natural = true;
        profile.emit_cover = false;
        Self::with_transit(client, transit, profile)
    }

    fn with_budget(
        client: Arc<Tp1Client>,
        profile: SchedulerProfile,
        budget: budget::Budget,
    ) -> Self {
        let (shutdown, _) = watch::channel(false);
        let scheduler = Self {
            inner: Arc::new(Inner {
                client,
                lanes: Mutex::new(HashMap::new()),
                shutdown,
                slot_interval: profile.slot_interval,
                emission_probability: profile.emission_probability,
                admin_interval: profile.admin_interval,
                emit_cover: profile.emit_cover,
                deterministic_seed: profile.deterministic_seed,
                connect_retry_base: profile.connect_retry_base,
                diagnostics: diagnostics::Diagnostics::default(),
                budget,
                max_in_flight: profile.max_in_flight,
                natural: profile.natural,
            }),
        };
        // The idle-lane sweeper needs a runtime; a scheduler built outside
        // one (unit tests, codec fixtures) simply never sweeps.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let sweeper = scheduler.clone();
            let mut shutdown = sweeper.inner.shutdown.subscribe();
            handle.spawn(async move {
                loop {
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(LANE_SWEEP_INTERVAL) => {
                            sweeper.sweep_idle_lanes();
                        }
                    }
                }
            });
        }
        scheduler
    }

    /// The configured slot interval; ticks size their batch deadlines from
    /// it so a compressed test profile and production behave alike.
    pub fn slot_interval(&self) -> Duration {
        self.inner.slot_interval
    }

    /// Enable local aggregate measurements. Call before enqueueing work. No
    /// observations are logged, persisted, or exposed through SDK/control IPC.
    pub fn enable_diagnostics(&self) {
        self.inner.diagnostics.enable();
    }

    pub fn diagnostics_snapshot(&self) -> diagnostics::SchedulerSnapshot {
        self.inner.diagnostics.snapshot()
    }

    pub(crate) fn pipelined(&self) -> bool {
        self.inner.max_in_flight > 1
    }

    pub fn resource_snapshot(&self) -> ResourceSnapshot {
        self.inner.budget.snapshot()
    }

    pub(crate) fn combined_resource_snapshot(&self) -> ResourceSnapshot {
        self.inner.budget.combined_snapshot()
    }

    pub fn push(
        &self,
        class: ProducerClass,
        contact: AliasContact,
        inner: Cell,
    ) -> Result<Receipt, EnqueueError> {
        self.push_with_class(class, contact, inner, TrafficClass::Interactive)
    }

    pub fn push_with_class(
        &self,
        class: ProducerClass,
        contact: AliasContact,
        inner: Cell,
        traffic: TrafficClass,
    ) -> Result<Receipt, EnqueueError> {
        let key = LaneKey {
            address: contact.target.address,
            service_id: contact.target.relay_service_id,
            token: gcoms_transport::encode_b64url(&contact.queue_id),
            administrative: false,
            natural_class: None,
        };
        self.enqueue_with_class(key, class, SemanticJob::Push { contact, inner }, traffic)
    }

    pub fn frwd(
        &self,
        class: ProducerClass,
        relay: RelayProvision,
        destination: AliasContact,
        inner: Cell,
        policy: FrwdTargetPolicy,
    ) -> Result<Receipt, EnqueueError> {
        self.frwd_with_class(
            class,
            relay,
            destination,
            inner,
            policy,
            TrafficClass::Interactive,
        )
    }

    pub fn frwd_with_class(
        &self,
        class: ProducerClass,
        relay: RelayProvision,
        destination: AliasContact,
        inner: Cell,
        policy: FrwdTargetPolicy,
        traffic: TrafficClass,
    ) -> Result<Receipt, EnqueueError> {
        let target = relay
            .aliases
            .first()
            .ok_or(EnqueueError::Shutdown)?
            .contact
            .target
            .clone();
        let key = LaneKey {
            address: target.address,
            service_id: target.relay_service_id,
            token: relay.frwd_path.clone(),
            administrative: false,
            natural_class: None,
        };
        self.enqueue_with_class(
            key,
            class,
            SemanticJob::Frwd {
                relay,
                destination,
                inner,
                policy,
            },
            traffic,
        )
    }

    pub fn forward(&self, frwd: Frwd) -> Result<Receipt, EnqueueError> {
        let Some(push) = frwd.relay_push else {
            // A cover FRWD is admitted upstream and never forwarded.
            return Err(EnqueueError::Shutdown);
        };
        let token = gcoms_transport::encode_b64url(&push.queue_id());
        let key = LaneKey {
            address: frwd.target.address,
            service_id: frwd.target.relay_service_id,
            token,
            administrative: false,
            natural_class: None,
        };
        self.enqueue(
            key,
            ProducerClass::Forward,
            SemanticJob::Forward {
                target: frwd.target,
                push,
            },
        )
    }

    /// Forward authenticated GC/2 work while retaining its exact destination
    /// envelope and class. GC/1 schedulers reject this explicit operation.
    #[cfg(feature = "experimental-gc2")]
    pub fn forward_gc2(
        &self,
        forward: gcoms_protocol::relay::gc2::Forward,
    ) -> Result<Receipt, EnqueueError> {
        if !self.is_gc2() {
            return Err(EnqueueError::Shutdown);
        }
        let push = forward.push.ok_or(EnqueueError::Shutdown)?;
        if push.class() != forward.class {
            return Err(EnqueueError::Shutdown);
        }
        let key = LaneKey {
            address: forward.target.address,
            service_id: forward.target.relay_service_id,
            token: crate::gc2::queue_token(&push.queue_id()),
            administrative: false,
            natural_class: None,
        };
        self.enqueue_with_class(
            key,
            ProducerClass::Forward,
            SemanticJob::ForwardNatural {
                target: forward.target,
                push,
            },
            forward.class,
        )
    }

    pub fn admin_post(
        &self,
        target: RelayTarget,
        token: String,
        cell: Cell,
    ) -> Result<Receipt, EnqueueError> {
        let key = LaneKey {
            address: target.address,
            service_id: target.relay_service_id,
            token: token.clone(),
            administrative: true,
            natural_class: None,
        };
        self.enqueue(
            key,
            ProducerClass::Administration,
            SemanticJob::AdminPost {
                target,
                token,
                cell,
            },
        )
    }

    pub fn subscribe(&self, alias: OwnedAlias) -> Result<Receipt, EnqueueError> {
        self.subscribe_with_class(alias, TrafficClass::Interactive)
    }

    pub fn subscribe_with_class(
        &self,
        alias: OwnedAlias,
        traffic: TrafficClass,
    ) -> Result<Receipt, EnqueueError> {
        if !self.is_gc2() && traffic != TrafficClass::Interactive {
            return Err(EnqueueError::Shutdown);
        }
        let key = LaneKey {
            address: alias.contact.target.address,
            service_id: alias.contact.target.relay_service_id,
            token: gcoms_transport::encode_b64url(&alias.contact.queue_id),
            administrative: true,
            natural_class: None,
        };
        self.enqueue_with_class(
            key,
            ProducerClass::Administration,
            SemanticJob::Subscribe(Box::new(alias)),
            traffic,
        )
    }

    /// Open a lane now, without a job, so its slot clock and cover start
    /// immediately. Idempotent. `pinned` lanes are exempt from the idle
    /// sweep and must be closed explicitly.
    pub fn open_lane(&self, auth: LaneAuth, pinned: bool) -> Result<(), EnqueueError> {
        for traffic in self.subscription_classes() {
            let mut key = auth.key();
            key.natural_class = self.is_gc2().then_some(*traffic);
            let lane = self.lane_for(&key, Some(auth.clone()))?;
            lane.pinned
                .fetch_or(pinned, std::sync::atomic::Ordering::AcqRel);
        }
        Ok(())
    }

    /// Close the lane for `auth`: queued jobs fail with `Shutdown`, the
    /// worker stops, and no further cover is emitted toward that hop.
    pub fn close_lane(&self, auth: &LaneAuth) {
        for traffic in self.subscription_classes() {
            let mut key = auth.key();
            key.natural_class = self.is_gc2().then_some(*traffic);
            let lane = self
                .inner
                .lanes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
            if let Some(lane) = lane {
                lane.closing
                    .store(true, std::sync::atomic::Ordering::Release);
                lane.notify.notify_one();
            }
        }
    }

    pub fn lane_count(&self) -> usize {
        self.inner
            .lanes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    fn lane_for(&self, key: &LaneKey, auth: Option<LaneAuth>) -> Result<Arc<Lane>, EnqueueError> {
        if *self.inner.shutdown.borrow() {
            return Err(EnqueueError::Shutdown);
        }
        let mut lanes = self.inner.lanes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(lane) = lanes.get(key) {
            if let Some(auth) = auth {
                let mut slot = lane.auth.lock().unwrap_or_else(|p| p.into_inner());
                if slot.is_none() {
                    *slot = Some(auth);
                }
            }
            return Ok(lane.clone());
        }
        if lanes.len() >= MAX_LANES {
            return Err(EnqueueError::Full);
        }
        let capacity = if key.administrative {
            32
        } else {
            LANE_CAPACITY
        };
        let lane = Arc::new(Lane {
            queue: Mutex::new(FairQueue::new(capacity)),
            auth: Mutex::new(auth),
            notify: Notify::new(),
            pinned: std::sync::atomic::AtomicBool::new(false),
            last_real: Mutex::new(std::time::Instant::now()),
            closing: std::sync::atomic::AtomicBool::new(false),
        });
        let shutdown = self.inner.shutdown.subscribe();
        lanes.insert(key.clone(), lane.clone());
        spawn_lane(self.inner.clone(), key.clone(), lane.clone(), shutdown);
        Ok(lane)
    }

    fn enqueue(
        &self,
        key: LaneKey,
        class: ProducerClass,
        semantic: SemanticJob,
    ) -> Result<Receipt, EnqueueError> {
        self.enqueue_with_class(key, class, semantic, TrafficClass::Interactive)
    }

    fn enqueue_with_class(
        &self,
        mut key: LaneKey,
        class: ProducerClass,
        semantic: SemanticJob,
        traffic: TrafficClass,
    ) -> Result<Receipt, EnqueueError> {
        // Shape validation needs no authority, nonce or ciphertext preparation.
        // Invalid local work must not create a lane, warm a connection, reserve
        // budget or consume a scheduled opportunity before it can be rejected.
        if let SemanticJob::Push { inner, .. } | SemanticJob::Frwd { inner, .. } = &semantic {
            if RelayPush::validate_message(inner).is_err() {
                self.inner
                    .diagnostics
                    .increment(&self.inner.diagnostics.rejected_invalid);
                return Err(EnqueueError::InvalidCell);
            }
        }
        key.natural_class = self.is_gc2().then_some(traffic);
        let auth = semantic.lane_auth();
        let lane = self.lane_for(&key, auth).inspect_err(|error| {
            let d = &self.inner.diagnostics;
            d.increment(match error {
                EnqueueError::Full => &d.rejected_full,
                EnqueueError::Pending => &d.rejected_pending,
                EnqueueError::Shutdown => &d.rejected_shutdown,
                EnqueueError::InvalidCell => &d.rejected_invalid,
            });
        })?;
        // Keep the final shutdown check and push under the same queue lock so
        // a lane worker cannot finish draining between them.
        let mut queue = lane.queue.lock().unwrap_or_else(|p| p.into_inner());
        if *self.inner.shutdown.borrow() || lane.closing.load(std::sync::atomic::Ordering::Acquire)
        {
            self.inner
                .diagnostics
                .increment(&self.inner.diagnostics.rejected_shutdown);
            return Err(EnqueueError::Shutdown);
        }
        let (done, completion) = oneshot::channel();
        let producer = semantic.producer();
        let attempt = (self.inner.max_in_flight > 1).then(|| {
            let attempt = semantic.attempt(producer);
            if self.is_gc2() {
                let mut hash = Sha256::new();
                hash.update(b"gcoms.scheduler.class-attempt.v2\0");
                hash.update([traffic as u8]);
                hash.update(attempt);
                hash.finalize().into()
            } else {
                attempt
            }
        });
        let reservation = self
            .inner
            .budget
            .reserve(semantic.accounted_bytes(), attempt)
            .inspect_err(|error| {
                let d = &self.inner.diagnostics;
                d.increment(match error {
                    EnqueueError::Full => &d.rejected_full,
                    EnqueueError::Pending => &d.rejected_pending,
                    EnqueueError::Shutdown => &d.rejected_shutdown,
                    EnqueueError::InvalidCell => &d.rejected_invalid,
                });
            })?;
        let queued = queue.push(
            class,
            QueuedJob {
                semantic,
                done,
                queued_at: self.inner.diagnostics.start(),
                traffic,
                producer,
                _reservation: Some(reservation),
            },
        );
        if !queued {
            self.inner
                .diagnostics
                .increment(&self.inner.diagnostics.rejected_full);
            return Err(EnqueueError::Full);
        }
        let d = &self.inner.diagnostics;
        if d.enabled() {
            d.increment(&d.accepted);
            d.queue_high_water
                .fetch_max(queue.len as u64, std::sync::atomic::Ordering::Relaxed);
        }
        drop(queue);
        *lane.last_real.lock().unwrap_or_else(|p| p.into_inner()) = std::time::Instant::now();
        lane.notify.notify_one();
        Ok(Receipt {
            state: CompletionState::Queued,
            completion,
        })
    }

    /// Close unpinned lanes idle for longer than `LANE_IDLE_TTL`.
    fn sweep_idle_lanes(&self) {
        let now = std::time::Instant::now();
        let mut lanes = self.inner.lanes.lock().unwrap_or_else(|p| p.into_inner());
        let expired = lanes
            .iter()
            .filter(|(_, lane)| {
                !lane.pinned.load(std::sync::atomic::Ordering::Acquire)
                    && now.duration_since(*lane.last_real.lock().unwrap_or_else(|p| p.into_inner()))
                        > LANE_IDLE_TTL
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            if let Some(lane) = lanes.remove(&key) {
                lane.closing
                    .store(true, std::sync::atomic::Ordering::Release);
                lane.notify.notify_one();
            }
        }
    }

    pub fn shutdown(&self) {
        let _ = self.inner.shutdown.send_replace(true);
    }
}

impl SemanticJob {
    fn producer(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"gcoms.scheduler.producer.v2\0");
        match self {
            Self::Push { contact, .. } => {
                hash.update(contact.target.relay_service_id);
                hash.update(contact.queue_id);
            }
            Self::Frwd { destination, .. } => {
                hash.update(destination.target.relay_service_id);
                hash.update(destination.queue_id);
            }
            Self::Forward { target, push } => {
                hash.update(target.relay_service_id);
                hash.update(push.queue_id());
            }
            #[cfg(feature = "experimental-gc2")]
            Self::ForwardNatural { target, push } => {
                hash.update(target.relay_service_id);
                hash.update(push.queue_id());
            }
            Self::AdminPost { target, token, .. } => {
                hash.update(target.relay_service_id);
                hash.update(token.as_bytes());
            }
            Self::Subscribe(alias) => {
                hash.update(alias.contact.target.relay_service_id);
                hash.update(alias.contact.queue_id);
            }
        }
        hash.finalize().into()
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Push { inner, .. } | Self::Frwd { inner, .. } => &inner.payload,
            Self::Forward { push, .. } => &push.as_cell().payload,
            #[cfg(feature = "experimental-gc2")]
            Self::ForwardNatural { push, .. } => push.as_cell().payload(),
            Self::AdminPost { cell, .. } => &cell.payload,
            Self::Subscribe(alias) => &alias.capabilities.sub,
        }
    }

    fn attempt(&self, producer: [u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"gcoms.scheduler.attempt.v2\0");
        hash.update(producer);
        hash.update([match self {
            Self::Push { .. } => 0,
            Self::Frwd { .. } => 1,
            Self::Forward { .. } => 2,
            Self::AdminPost { .. } => 3,
            Self::Subscribe(_) => 4,
            #[cfg(feature = "experimental-gc2")]
            Self::ForwardNatural { .. } => 5,
        }]);
        let cell = match self {
            Self::Push { inner, .. } | Self::Frwd { inner, .. } => Some(inner),
            Self::Forward { push, .. } => Some(push.as_cell()),
            Self::AdminPost { cell, .. } => Some(cell),
            Self::Subscribe(_) => None,
            #[cfg(feature = "experimental-gc2")]
            Self::ForwardNatural { .. } => None,
        };
        if let Some(cell) = cell {
            hash.update([cell.version, cell.raw_type, cell.flags]);
            hash.update(cell.round_ctr.to_be_bytes());
        }
        match self {
            Self::Push { contact, .. }
            | Self::Frwd {
                destination: contact,
                ..
            } => {
                hash.update(contact.epoch.to_be_bytes());
                hash.update(contact.push_cap);
            }
            Self::Subscribe(alias) => hash.update(alias.contact.epoch.to_be_bytes()),
            _ => {}
        }
        hash.update(self.payload());
        hash.finalize().into()
    }

    fn service_bytes(&self) -> usize {
        // Account for the largest relay wrapper before wire bucketing.
        gcoms_core::Bucket::smallest_for(self.payload().len().saturating_add(256))
            .unwrap_or(gcoms_core::Bucket::B3)
            .wire()
            .size()
    }

    fn accounted_bytes(&self) -> usize {
        let alias_bytes = |alias: &OwnedAlias| {
            std::mem::size_of::<OwnedAlias>()
                .saturating_add(alias.create_path.capacity())
                .saturating_add(alias.lease_create.payload.capacity())
        };
        let metadata = match self {
            Self::Frwd { relay, .. } => relay.aliases.iter().fold(
                relay.frwd_path.capacity().saturating_add(
                    relay
                        .aliases
                        .capacity()
                        .saturating_sub(relay.aliases.len())
                        .saturating_mul(std::mem::size_of::<OwnedAlias>()),
                ),
                |sum, alias| sum.saturating_add(alias_bytes(alias)),
            ),
            Self::Subscribe(alias) => alias_bytes(alias),
            Self::AdminPost { token, .. } => token.capacity(),
            _ => 0,
        };
        let payload_capacity = match self {
            Self::Push { inner, .. } | Self::Frwd { inner, .. } => inner.payload.capacity(),
            Self::Forward { push, .. } => push.as_cell().payload.capacity(),
            Self::AdminPost { cell, .. } => cell.payload.capacity(),
            Self::Subscribe(_) => 32,
            #[cfg(feature = "experimental-gc2")]
            Self::ForwardNatural { push, .. } => push.as_cell().payload_capacity(),
        };
        // Retain credit for the encoded wire buffer as well as queued payload
        // and copied authority. Credit is held through the response.
        std::mem::size_of::<QueuedJob>()
            .saturating_add(16384)
            .saturating_add(payload_capacity)
            .saturating_add(metadata)
    }

    /// The cover authority implied by a real job on this lane, if any.
    fn lane_auth(&self) -> Option<LaneAuth> {
        match self {
            Self::Push { contact, .. } => Some(LaneAuth::Push {
                contact: contact.clone(),
            }),
            Self::Frwd {
                relay,
                destination,
                policy,
                ..
            } => Some(LaneAuth::Frwd {
                relay: relay.clone(),
                decoy_target: destination.target.clone(),
                policy: policy.clone(),
            }),
            // Forwarded jobs and administrative posts carry no authority we
            // may reuse for cover.
            Self::Forward { .. } | Self::AdminPost { .. } | Self::Subscribe(_) => None,
            #[cfg(feature = "experimental-gc2")]
            Self::ForwardNatural { .. } => None,
        }
    }
}

fn spawn_lane(
    inner: Arc<Inner>,
    key: LaneKey,
    lane: Arc<Lane>,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if *shutdown.borrow() {
            lane.queue
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .shutdown();
            return;
        }
        let mut schedule_rng = match inner.deterministic_seed {
            Some(seed) => {
                let mut material = Sha256::new();
                material.update(b"gc-relay-schedule-v1");
                material.update(seed.to_le_bytes());
                material.update(key.address.to_string().as_bytes());
                material.update(key.service_id);
                material.update(key.token.as_bytes());
                material.update([u8::from(key.administrative)]);
                StdRng::from_seed(material.finalize().into())
            }
            None => StdRng::from_entropy(),
        };
        let mut request_rng = StdRng::from_entropy();
        let mut round = 0u16;
        let interval = if key.administrative {
            inner.admin_interval
        } else {
            inner.slot_interval
        };
        // Connection setup is independent of dispatch and can be canceled by
        // shutdown. A stalled warmup must not pin queued work forever.
        let warming = inner.diagnostics.start();
        let excluded = match lane.auth.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(LaneAuth::Frwd { decoy_target, .. }) => {
                vec![(decoy_target.address, decoy_target.relay_service_id)]
            }
            _ => Vec::new(),
        };
        let warm = tokio::time::timeout(
            Duration::from_secs(60),
            inner.client.warm_excluding_with_class(
                key.address,
                key.service_id,
                &excluded,
                key.natural_class.unwrap_or(TrafficClass::Interactive),
            ),
        );
        tokio::pin!(warm);
        loop {
            if *shutdown.borrow() || lane.closing.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = lane.notify.notified() => {},
                _ = &mut warm => break,
            }
        }
        if let Some(started) = warming {
            inner.diagnostics.warm.observe(started.elapsed());
        }
        let mut clock = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut running = tokio::task::JoinSet::new();
        let mut bulk_running = 0;
        let mut cover_running = false;
        loop {
            if *shutdown.borrow() || lane.closing.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            let ready = inner.natural
                && running.len() < inner.max_in_flight
                && (key.natural_class != Some(TrafficClass::Bulk) || bulk_running < 3)
                && lane.queue.lock().unwrap_or_else(|p| p.into_inner()).len != 0;
            let mut opportunity = false;
            let mut job = None;
            tokio::select! {
                biased;
                _ = shutdown.changed() => continue,
                completed = running.join_next(), if !running.is_empty() => {
                    match completed {
                        Some(Ok((traffic, cover))) => {
                            if traffic == TrafficClass::Bulk { bulk_running -= 1; }
                            if cover { cover_running = false; }
                        },
                        Some(Err(_)) => break,
                        None => {},
                    }
                },
                _ = lane.notify.notified() => {},
                _ = async {}, if ready => {
                    opportunity = true;
                    job = lane.queue.lock().unwrap_or_else(|p| p.into_inner()).pop_eligible(bulk_running < 3);
                },
                _ = clock.tick(), if !inner.natural => {
                    round = round.wrapping_add(1);
                    if !key.administrative { inner.diagnostics.increment(&inner.diagnostics.data_ticks); }
                    if !key.administrative && !schedule_rng.gen_bool(inner.emission_probability) {
                        inner.diagnostics.increment(&inner.diagnostics.data_skipped_ticks);
                    } else if running.len() < inner.max_in_flight {
                        opportunity = true;
                        job = lane.queue.lock().unwrap_or_else(|p| p.into_inner()).pop_eligible(bulk_running < 3);
                    }
                },
            }
            if !opportunity {
                continue;
            }
            let (request, traffic, done, reservation) = if let Some(job) = job {
                if let Some(at) = job.queued_at {
                    inner.diagnostics.queue_wait.observe(at.elapsed());
                }
                inner.diagnostics.increment(&inner.diagnostics.dispatched);
                (
                    prepare_pending(
                        job.semantic,
                        round,
                        job.traffic,
                        inner.natural,
                        random_nonzero_with(&mut request_rng),
                    ),
                    job.traffic,
                    Some(job.done),
                    job._reservation,
                )
            } else if !key.administrative && inner.emit_cover && !cover_running {
                let auth = lane.auth.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let Some(auth) = auth else {
                    continue;
                };
                let Ok(reservation) = inner.budget.reserve_cover() else {
                    continue;
                };
                inner
                    .diagnostics
                    .increment(&inner.diagnostics.cover_attempts);
                (
                    Ok(PendingRequest::cover(
                        auth,
                        round,
                        random_nonzero_with(&mut request_rng),
                    )),
                    TrafficClass::Interactive,
                    None,
                    Some(reservation),
                )
            } else {
                continue;
            };
            if traffic == TrafficClass::Bulk {
                bulk_running += 1;
            }
            let cover = done.is_none();
            cover_running |= cover;
            let inner = inner.clone();
            running.spawn(async move {
                let _reservation = reservation;
                let started = inner.diagnostics.start();
                let result = match request {
                    Ok(request) => {
                        send_request(&inner.client, request, inner.connect_retry_base, traffic)
                            .await
                    }
                    Err(error) => JobResult::Failed(error),
                };
                if let Some(started) = started {
                    inner.diagnostics.service.observe(started.elapsed());
                }
                if done.is_some() && matches!(result, JobResult::Failed(_) | JobResult::Shutdown) {
                    inner.diagnostics.increment(&inner.diagnostics.failed);
                }
                if let Some(done) = done {
                    let _ = done.send(result);
                }
                (traffic, cover)
            });
        }
        lane.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .shutdown();
        running.abort_all();
        while running.join_next().await.is_some() {}
    });
}

/// Transport errors that prove the request never reached the peer (failed
/// or unroutable connect): the cell was not delivered, so the send may be
/// retried safely — no duplicate is possible. Ambiguous failures (timeouts,
/// resets after connect) are deliberately NOT retried here.
fn is_unsent_connect_error(error: &str) -> bool {
    const MARKERS: [&str; 10] = [
        "No route to host",
        "Host is down",
        "Network is unreachable",
        "Connection refused",
        "os error 65",
        "os error 64",
        "os error 51",
        "os error 113",
        "os error 101",
        "os error 61",
    ];
    MARKERS.iter().any(|marker| error.contains(marker))
}

/// A connect-phase failure is usually a transient link hiccup (WiFi power
/// save, ARP refresh, background scan); retry a few times with backoff
/// before giving the job up.
const CONNECT_RETRY_ATTEMPTS: u32 = 4;

fn prepare_pending(
    semantic: SemanticJob,
    round: u16,
    traffic: TrafficClass,
    natural: bool,
    seed: [u8; 32],
) -> Result<PendingRequest, String> {
    #[cfg(feature = "experimental-gc2")]
    if natural {
        return PendingRequest::natural(semantic, traffic, seed);
    }
    let _ = (natural, traffic);
    PendingRequest::semantic(semantic, round, seed)
}

async fn send_request(
    client: &Tp1Client,
    request: PendingRequest,
    retry_base: Duration,
    traffic: TrafficClass,
) -> JobResult {
    #[cfg(feature = "experimental-gc2")]
    if request.natural {
        return gc2::send(client, request, retry_base, traffic).await;
    }
    let PendingRequest {
        target,
        token,
        excluded,
        subscription,
        make,
        ..
    } = request;
    let mut make = Some(make);
    let mut wire: Option<bytes::Bytes> = None;
    let mut attempt = 0;
    loop {
        // Cache outside the transport call too: an internal ambiguous retry can
        // be followed by a connect failure. No retry may regenerate that wire.
        let prepare = || -> gcoms_transport::client::Result<bytes::Bytes> {
            if let Some(wire) = &wire {
                return Ok(wire.clone());
            }
            let bytes = make.take().ok_or("request preparation already consumed")?()?;
            wire = Some(bytes.clone());
            Ok(bytes)
        };
        let result = if subscription {
            client
                .open_stream_prepared(target.address, target.relay_service_id, &token, prepare)
                .await
                .map(JobResult::Stream)
        } else {
            client
                .post_cell_prepared(
                    target.address,
                    target.relay_service_id,
                    &token,
                    &excluded,
                    traffic,
                    prepare,
                )
                .await
                .map(|outcome| match outcome.into_accepted() {
                    Ok(Some(cell)) => match cell.encode_wire() {
                        Ok(wire) => JobResult::HopAccepted(bytes::Bytes::from(wire)),
                        Err(error) => JobResult::Failed(error.to_string()),
                    },
                    Ok(None) => JobResult::HopAccepted(bytes::Bytes::new()),
                    Err(error) => JobResult::Failed(error),
                })
        };
        match result {
            Ok(result) => return result,
            Err(error) => {
                let text = error.to_string();
                if attempt < CONNECT_RETRY_ATTEMPTS && is_unsent_connect_error(&text) {
                    attempt += 1;
                    tokio::time::sleep(retry_base * attempt).await;
                    continue;
                }
                return JobResult::Failed(text);
            }
        }
    }
}

enum Request {
    Post {
        target: RelayTarget,
        token: String,
        wire: Vec<u8>,
        excluded: Vec<(SocketAddr, [u8; 32])>,
    },
    Subscribe {
        alias: Box<OwnedAlias>,
        auth: Vec<u8>,
    },
}

fn ensure_live_authority(expiry: u64) -> Result<(), String> {
    if expiry <= now_unix() {
        return Err("relay authority expired before transport admission".into());
    }
    Ok(())
}

fn prepare(semantic: SemanticJob, round: u16, rng: &mut StdRng) -> Result<Request, String> {
    match semantic {
        #[cfg(feature = "experimental-gc2")]
        SemanticJob::ForwardNatural { .. } => Err("GC/2 data cannot enter GC/1".into()),
        SemanticJob::Push { contact, inner } => {
            ensure_live_authority(contact.expiry)?;
            let push = RelayPush {
                queue_id: contact.queue_id,
                epoch: contact.epoch,
                push_nonce: random_nonzero_with(rng),
                push_expiry: now_unix().saturating_add(60).min(contact.expiry),
                msg: Some(inner),
            };
            let mut cell = push
                .encode_into_cell(&contact.push_cap, &contact.target.relay_service_id)
                .map_err(|e| e.to_string())?;
            cell.round_ctr = round;
            Ok(Request::Post {
                excluded: Vec::new(),
                token: gcoms_transport::encode_b64url(&contact.queue_id),
                target: contact.target,
                wire: cell.encode_wire().map_err(|e| e.to_string())?,
            })
        }
        SemanticJob::Frwd {
            relay,
            destination,
            inner,
            policy,
        } => {
            ensure_live_authority(destination.expiry)?;
            let intermediary = relay
                .aliases
                .first()
                .ok_or("client relay provision has no target")?
                .contact
                .target
                .clone();
            let push = RelayPush {
                queue_id: destination.queue_id,
                epoch: destination.epoch,
                push_nonce: random_nonzero_with(rng),
                push_expiry: now_unix().saturating_add(60).min(destination.expiry),
                msg: Some(inner),
            };
            let mut push_cell = push
                .encode_into_cell(&destination.push_cap, &destination.target.relay_service_id)
                .map_err(|e| e.to_string())?;
            push_cell.round_ctr = round;
            let push = UnauthenticatedRelayPush::parse(push_cell).map_err(|e| e.to_string())?;
            let frwd = Frwd {
                target: destination.target,
                frwd_expiry: now_unix().saturating_add(30),
                relay_push: Some(push),
                nonce: random_nonzero_with(rng),
            };
            let excluded = vec![(frwd.target.address, frwd.target.relay_service_id)];
            let mut cell = frwd
                .encode_into_cell_with_policy(
                    &relay.hop_key,
                    &intermediary.relay_service_id,
                    &policy,
                )
                .map_err(|e| e.to_string())?;
            cell.round_ctr = round;
            Ok(Request::Post {
                excluded,
                target: intermediary,
                token: relay.frwd_path,
                wire: cell.encode_wire().map_err(|e| e.to_string())?,
            })
        }
        SemanticJob::Forward { target, push } => {
            if push.push_expiry() <= now_unix() {
                return Err("forwarded relay push expired while queued".into());
            }
            let token = gcoms_transport::encode_b64url(&push.queue_id());
            let mut cell = push.into_cell();
            cell.round_ctr = round;
            Ok(Request::Post {
                excluded: Vec::new(),
                target,
                token,
                wire: cell.encode_wire().map_err(|e| e.to_string())?,
            })
        }
        SemanticJob::AdminPost {
            target,
            token,
            mut cell,
        } => {
            cell.round_ctr = round;
            Ok(Request::Post {
                excluded: Vec::new(),
                target,
                token,
                wire: cell.encode_wire().map_err(|e| e.to_string())?,
            })
        }
        SemanticJob::Subscribe(alias) => {
            ensure_live_authority(alias.contact.expiry)?;
            let sub = crate::relay::RelaySub {
                queue_id: alias.contact.queue_id,
                epoch: alias.contact.epoch,
                subscription_expiry: now_unix().saturating_add(60).min(alias.contact.expiry),
                nonce: random_nonzero_with(rng),
            };
            let mut cell = sub
                .encode_into_cell(
                    &alias.capabilities.sub,
                    &alias.contact.target.relay_service_id,
                )
                .map_err(|e| e.to_string())?;
            cell.round_ctr = round;
            Ok(Request::Subscribe {
                alias,
                auth: cell.encode_wire().map_err(|e| e.to_string())?,
            })
        }
    }
}

fn random_nonzero_with<const N: usize>(rng: &mut impl RngCore) -> [u8; N] {
    loop {
        let mut value = [0; N];
        rng.fill_bytes(&mut value);
        if value != [0; N] {
            return value;
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn invalid_messages_cannot_open_lanes_spend_budget_or_reach_the_dialer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountDial {
            attempts: AtomicUsize,
            entered: Notify,
        }
        impl gcoms_transport::connector::Connector for CountDial {
            fn connect(
                &self,
                _: SocketAddr,
                _: [u8; 32],
            ) -> gcoms_transport::connector::ConnectFuture<'_> {
                Box::pin(async move {
                    self.attempts.fetch_add(1, Ordering::SeqCst);
                    self.entered.notify_one();
                    std::future::pending().await
                })
            }
        }
        let dial = Arc::new(CountDial {
            attempts: AtomicUsize::new(0),
            entered: Notify::new(),
        });
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::with_connector(dial.clone()).unwrap()),
            SchedulerProfile::fixture(),
        );
        scheduler.enable_diagnostics();
        let contact = AliasContact {
            target: RelayTarget {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [1; 32],
            },
            queue_id: [2; 32],
            epoch: 1,
            push_cap: [3; 32],
            expiry: u64::MAX,
        };
        let relay = RelayProvision {
            aliases: vec![OwnedAlias {
                contact: contact.clone(),
                capabilities: crate::lease::Capabilities {
                    push: [3; 32],
                    sub: [4; 32],
                    admin: [5; 32],
                },
                limits: crate::lease::LeaseLimits {
                    max_queue_cells: 4,
                    max_queue_bytes: 65536,
                },
                create_path: "create".into(),
                lease_create: Cell::new(CellType::RelaySub, 0, 0, Vec::new()),
            }],
            frwd_path: "frwd".into(),
            hop_key: [6; 32],
        };
        let mut wrong_version = Cell::new(CellType::Msg, 0, 0, vec![1]);
        wrong_version.version = 2;
        for cell in [
            Cell::new(CellType::Pex, 0, 0, vec![1; 128]),
            Cell::new(CellType::Msg, 4, 0, vec![1]),
            Cell::new(CellType::Msg, 0, 0, vec![1; 15361]),
            wrong_version,
        ] {
            assert!(matches!(
                scheduler.push(ProducerClass::ChannelData, contact.clone(), cell.clone()),
                Err(EnqueueError::InvalidCell)
            ));
            assert!(matches!(
                scheduler.frwd_with_class(
                    ProducerClass::Direct,
                    relay.clone(),
                    contact.clone(),
                    cell,
                    FrwdTargetPolicy::new(true),
                    TrafficClass::Bulk
                ),
                Err(EnqueueError::InvalidCell)
            ));
        }
        tokio::time::advance(Duration::from_secs(3600)).await;
        tokio::task::yield_now().await;
        assert_eq!(dial.attempts.load(Ordering::SeqCst), 0);
        assert_eq!(scheduler.lane_count(), 0);
        let resources = scheduler.combined_resource_snapshot();
        assert_eq!(
            (
                resources.jobs,
                resources.bytes,
                resources.peak_jobs,
                resources.peak_bytes
            ),
            (0, 0, 0, 0)
        );
        let diagnostics = scheduler.diagnostics_snapshot();
        assert_eq!(diagnostics.rejected_invalid, 8);
        assert_eq!(
            (
                diagnostics.accepted,
                diagnostics.dispatched,
                diagnostics.cover_attempts
            ),
            (0, 0, 0)
        );
        // A subsequent valid message still creates and warms its ordinary lane.
        let valid = scheduler
            .push(
                ProducerClass::Direct,
                contact,
                Cell::new(CellType::Msg, 0, 0, vec![1; 15360]),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), dial.entered.notified())
            .await
            .unwrap();
        assert_eq!(dial.attempts.load(Ordering::SeqCst), 1);
        scheduler.shutdown();
        assert_eq!(valid.completion().await.state(), CompletionState::Shutdown);
    }

    #[tokio::test]
    async fn shutdown_releases_receipts_while_connection_warming_is_pending() {
        struct PendingConnector(tokio::sync::Notify);
        impl gcoms_transport::connector::Connector for PendingConnector {
            fn connect(
                &self,
                _: SocketAddr,
                _: [u8; 32],
            ) -> gcoms_transport::connector::ConnectFuture<'_> {
                Box::pin(async {
                    self.0.notify_one();
                    std::future::pending().await
                })
            }
        }
        let connector = Arc::new(PendingConnector(tokio::sync::Notify::new()));
        let client = Arc::new(Tp1Client::with_connector(connector.clone()).unwrap());
        let scheduler = RelayScheduler::with_profile(client, SchedulerProfile::fixture());
        let mut receipts = Vec::new();
        for marker in 1..=8 {
            receipts.push(scheduler.forward(forwarded(marker)).unwrap());
        }
        tokio::time::timeout(Duration::from_secs(2), connector.0.notified())
            .await
            .unwrap();
        scheduler.shutdown();
        for receipt in receipts {
            let result = tokio::time::timeout(Duration::from_secs(1), receipt.completion())
                .await
                .unwrap();
            assert_eq!(result.state(), CompletionState::Shutdown);
        }
    }

    pub(super) fn forwarded(marker: u8) -> Frwd {
        let target = RelayTarget {
            address: "192.0.2.1:443".parse().unwrap(),
            relay_service_id: [1; 32],
        };
        let push = RelayPush {
            queue_id: [marker; 32],
            epoch: 1,
            push_nonce: [marker; 16],
            push_expiry: u64::MAX,
            msg: Some(Cell::new(CellType::Msg, 0, 0, vec![marker])),
        }
        .encode_into_cell(&[3; 32], &target.relay_service_id)
        .unwrap();
        Frwd {
            target,
            frwd_expiry: u64::MAX,
            relay_push: Some(UnauthenticatedRelayPush::parse(push).unwrap()),
            nonce: [marker; 16],
        }
    }

    #[test]
    fn compressed_profile_preserves_production_behavior_and_is_repeatable() {
        let profile = SchedulerProfile::compressed_production(17);
        assert_eq!(profile.emission_probability, EMISSION_PROBABILITY);
        assert!(profile.emit_cover);

        let mut first = profile.maintenance_rng_labeled([3; 32], b"direct");
        let mut replay = profile.maintenance_rng_labeled([3; 32], b"direct");
        let first_delays = (0..16)
            .map(|_| profile.maintenance_delay(&mut first))
            .collect::<Vec<_>>();
        let replay_delays = (0..16)
            .map(|_| profile.maintenance_delay(&mut replay))
            .collect::<Vec<_>>();
        assert_eq!(first_delays, replay_delays);
        assert!(first_delays.iter().all(|delay| {
            *delay >= Duration::from_millis(25) && *delay < Duration::from_millis(40)
        }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_is_sticky_and_drains_a_lane_before_its_worker_starts() {
        let empty_scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        empty_scheduler.shutdown();
        assert!(matches!(
            empty_scheduler.forward(forwarded(0)),
            Err(EnqueueError::Shutdown)
        ));

        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        let receipt = scheduler.forward(forwarded(1)).unwrap();

        scheduler.shutdown();

        let completion = tokio::time::timeout(Duration::from_secs(1), receipt.completion())
            .await
            .expect("shutdown drains the queued job");
        assert_eq!(completion.state(), CompletionState::Shutdown);
        assert!(matches!(
            scheduler.forward(forwarded(2)),
            Err(EnqueueError::Shutdown)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn diagnostics_account_for_bounded_admission_and_shutdown() {
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        assert!(!scheduler.diagnostics_snapshot().enabled);
        scheduler.enable_diagnostics();
        // No yield until shutdown: this exercises admission without connecting.
        let mut receipts = Vec::new();
        for _ in 0..LANE_CAPACITY {
            receipts.push(scheduler.forward(forwarded(1)).unwrap());
        }
        assert!(matches!(
            scheduler.forward(forwarded(1)),
            Err(EnqueueError::Full)
        ));
        scheduler.shutdown();
        assert!(matches!(
            scheduler.forward(forwarded(1)),
            Err(EnqueueError::Shutdown)
        ));
        for receipt in receipts {
            assert_eq!(
                receipt.completion().await.state(),
                CompletionState::Shutdown
            );
        }
        let snapshot = scheduler.diagnostics_snapshot();
        assert_eq!(snapshot.accepted, LANE_CAPACITY as u64);
        assert_eq!(snapshot.queue_high_water, LANE_CAPACITY as u64);
        assert_eq!(snapshot.rejected_full, 1);
        assert_eq!(snapshot.rejected_shutdown, 1);
        assert_eq!(snapshot.dispatched, 0);
        assert_eq!(snapshot.failed, 0);
        assert_eq!(snapshot.queue_wait.count, 0);
        assert_eq!(snapshot.service.count, 0);
    }

    pub(super) fn queued(marker: u8, class: ProducerClass) -> (ProducerClass, QueuedJob) {
        let (done, _) = oneshot::channel();
        (
            class,
            QueuedJob {
                queued_at: None,
                traffic: TrafficClass::Interactive,
                producer: [0; 32],
                _reservation: None,
                semantic: SemanticJob::Forward {
                    target: RelayTarget {
                        address: "192.0.2.1:443".parse().unwrap(),
                        relay_service_id: [1; 32],
                    },
                    push: UnauthenticatedRelayPush::parse(
                        RelayPush {
                            queue_id: [2; 32],
                            epoch: 1,
                            push_nonce: [marker; 16],
                            push_expiry: u64::MAX,
                            msg: Some(Cell::new(CellType::Msg, 0, 0, vec![marker])),
                        }
                        .encode_into_cell(&[3; 32], &[1; 32])
                        .unwrap(),
                    )
                    .unwrap(),
                },
                done,
            },
        )
    }

    pub(super) fn marker(job: &QueuedJob) -> u8 {
        match &job.semantic {
            SemanticJob::Forward { push, .. } => push.as_cell().payload[42],
            _ => unreachable!(),
        }
    }

    #[test]
    fn fair_queue_is_bounded_reject_new_and_round_robin() {
        let mut queue = FairQueue::new(3);
        for (class, job) in [
            queued(1, ProducerClass::Direct),
            queued(2, ProducerClass::Direct),
            queued(3, ProducerClass::ChannelData),
        ] {
            assert!(queue.push(class, job));
        }
        let (class, rejected) = queued(4, ProducerClass::Forward);
        assert!(!queue.push(class, rejected));
        assert_eq!(marker(&queue.pop().unwrap()), 1);
        assert_eq!(marker(&queue.pop().unwrap()), 3);
        assert_eq!(marker(&queue.pop().unwrap()), 2);
    }

    #[test]
    fn seeded_active_and_idle_slot_schedules_are_equal() {
        let mut active = StdRng::seed_from_u64(7);
        let mut idle = StdRng::seed_from_u64(7);
        let active_slots = (0..256)
            .map(|_| active.gen_bool(EMISSION_PROBABILITY))
            .collect::<Vec<_>>();
        let idle_slots = (0..256)
            .map(|_| idle.gen_bool(EMISSION_PROBABILITY))
            .collect::<Vec<_>>();
        assert_eq!(active_slots, idle_slots);
        assert!(active_slots.iter().any(|emits| *emits));
        assert!(active_slots.iter().any(|emits| !*emits));
    }

    #[test]
    fn one_pop_per_emitting_slot_and_inner_ciphertext_is_unchanged() {
        let inner = Cell::new(CellType::Msg, 0, 77, b"exact ciphertext".to_vec());
        let contact = AliasContact {
            target: RelayTarget {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [8; 32],
            },
            queue_id: [9; 32],
            epoch: 4,
            push_cap: [10; 32],
            expiry: u64::MAX,
        };
        let request = prepare(
            SemanticJob::Push {
                contact: contact.clone(),
                inner: inner.clone(),
            },
            12,
            &mut StdRng::seed_from_u64(1),
        )
        .unwrap();
        let Request::Post { wire, .. } = request else {
            unreachable!()
        };
        let outer = gcoms_core::decode(&wire).unwrap();
        let decoded = RelayPush::decode_from_cell(
            &outer,
            &contact.push_cap,
            &contact.target.relay_service_id,
            now_unix(),
        )
        .unwrap();
        assert_eq!(decoded.msg, Some(inner));
        assert_eq!(outer.round_ctr, 12);
    }

    #[test]
    fn expiry_nonce_and_round_are_created_at_emission() {
        let now = now_unix();
        let contact = AliasContact {
            target: RelayTarget {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [4; 32],
            },
            queue_id: [5; 32],
            epoch: 6,
            push_cap: [7; 32],
            expiry: now + 600,
        };
        let Request::Post { wire, .. } = prepare(
            SemanticJob::Push {
                contact: contact.clone(),
                inner: Cell::new(CellType::Msg, 0, 0, vec![1]),
            },
            99,
            &mut StdRng::seed_from_u64(2),
        )
        .unwrap() else {
            unreachable!()
        };
        let outer = gcoms_core::decode(&wire).unwrap();
        let push = RelayPush::decode_from_cell(
            &outer,
            &contact.push_cap,
            &contact.target.relay_service_id,
            now,
        )
        .unwrap();
        assert!(push.push_expiry >= now + 59);
        assert_ne!(push.push_nonce, [0; 16]);
        assert_eq!(outer.round_ctr, 99);
    }

    #[test]
    fn cover_is_fresh_authenticated_zero_length_and_same_shape() {
        let contact = AliasContact {
            target: RelayTarget {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [14; 32],
            },
            queue_id: [15; 32],
            epoch: 16,
            push_cap: [17; 32],
            expiry: now_unix() + 600,
        };
        let auth = LaneAuth::Push {
            contact: contact.clone(),
        };
        let mut rng = StdRng::seed_from_u64(9);
        let real = prepare(
            SemanticJob::Push {
                contact: contact.clone(),
                inner: Cell::new(CellType::Msg, 0, 44, b"semantic ciphertext".to_vec()),
            },
            1,
            &mut rng,
        )
        .unwrap();
        let first = auth.cover_request(2, &mut rng).unwrap();
        let second = auth.cover_request(3, &mut rng).unwrap();
        let (
            Request::Post {
                target: real_target,
                token: real_token,
                wire: real_wire,
                ..
            },
            Request::Post {
                target: cover_target,
                token: cover_token,
                wire: first_wire,
                ..
            },
            Request::Post {
                wire: second_wire, ..
            },
        ) = (real, first, second)
        else {
            unreachable!()
        };
        // Same hop, same path, same bucket class on the wire.
        assert_eq!(cover_target, real_target);
        assert_eq!(cover_token, real_token);
        assert!(first_wire.len() == 4096 || first_wire.len() == 16384);
        assert_eq!(real_wire.len(), 4096);
        // Fresh nonces: two covers never repeat, and neither repeats the real one.
        let decode = |wire: &[u8]| {
            RelayPush::decode_from_cell(
                &gcoms_core::decode(wire).unwrap(),
                &contact.push_cap,
                &contact.target.relay_service_id,
                now_unix(),
            )
            .unwrap()
        };
        let (real_push, first_push, second_push) = (
            decode(&real_wire),
            decode(&first_wire),
            decode(&second_wire),
        );
        assert!(real_push.msg.is_some());
        assert!(first_push.is_cover() && second_push.is_cover());
        assert_ne!(first_push.push_nonce, second_push.push_nonce);
        assert_ne!(first_push.push_nonce, real_push.push_nonce);
        assert!(first_push.push_expiry > now_unix());
    }

    #[test]
    fn cover_frwd_is_authenticated_and_carries_no_deposit() {
        let target = RelayTarget {
            address: "192.0.2.1:443".parse().unwrap(),
            relay_service_id: [1; 32],
        };
        let relay = RelayProvision {
            aliases: vec![OwnedAlias {
                contact: AliasContact {
                    target: target.clone(),
                    queue_id: [5; 32],
                    epoch: 1,
                    push_cap: [6; 32],
                    expiry: u64::MAX,
                },
                capabilities: crate::lease::Capabilities {
                    push: [6; 32],
                    sub: [7; 32],
                    admin: [8; 32],
                },
                limits: crate::lease::LeaseLimits {
                    max_queue_cells: 4,
                    max_queue_bytes: 1024,
                },
                create_path: "create".into(),
                lease_create: Cell::new(CellType::RelaySub, 0, 0, vec![]),
            }],
            frwd_path: "frwd".into(),
            hop_key: [9; 32],
        };
        let decoy = RelayTarget {
            address: "192.0.2.7:443".parse().unwrap(),
            relay_service_id: [2; 32],
        };
        let auth = LaneAuth::Frwd {
            relay: relay.clone(),
            decoy_target: decoy.clone(),
            policy: FrwdTargetPolicy::new(true),
        };
        let Request::Post { token, wire, .. } = auth
            .cover_request(4, &mut StdRng::seed_from_u64(3))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(token, "frwd");
        let cell = gcoms_core::decode(&wire).unwrap();
        let decoded = Frwd::decode_from_cell_with_policy(
            &cell,
            &relay.hop_key,
            &target.relay_service_id,
            now_unix(),
            &FrwdTargetPolicy::new(true),
        )
        .unwrap();
        assert!(decoded.is_cover());
        assert_eq!(decoded.target, decoy);
        // Tampering with the MAC fails closed.
        let mut tampered = cell.clone();
        *tampered.payload.last_mut().unwrap() ^= 1;
        assert!(Frwd::decode_from_cell_with_policy(
            &tampered,
            &relay.hop_key,
            &target.relay_service_id,
            now_unix(),
            &FrwdTargetPolicy::new(true),
        )
        .is_err());
    }

    #[tokio::test]
    async fn lanes_open_eagerly_close_explicitly_and_are_bounded() {
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        let contact = |byte: u8| AliasContact {
            target: RelayTarget {
                address: format!("192.0.2.{byte}:443").parse().unwrap(),
                relay_service_id: [byte; 32],
            },
            queue_id: [byte; 32],
            epoch: 1,
            push_cap: [byte; 32],
            expiry: u64::MAX,
        };
        for byte in 1..=MAX_LANES as u8 {
            scheduler
                .open_lane(
                    LaneAuth::Push {
                        contact: contact(byte),
                    },
                    false,
                )
                .unwrap();
        }
        assert_eq!(scheduler.lane_count(), MAX_LANES);
        assert_eq!(
            scheduler.open_lane(
                LaneAuth::Push {
                    contact: contact(200)
                },
                false
            ),
            Err(EnqueueError::Full)
        );
        scheduler.close_lane(&LaneAuth::Push {
            contact: contact(1),
        });
        assert_eq!(scheduler.lane_count(), MAX_LANES - 1);
        // Opening the same lane twice is idempotent.
        scheduler
            .open_lane(
                LaneAuth::Push {
                    contact: contact(2),
                },
                true,
            )
            .unwrap();
        assert_eq!(scheduler.lane_count(), MAX_LANES - 1);
        scheduler.shutdown();
    }

    #[test]
    fn production_tp1_data_plane_has_no_client_bypass() {
        let sources: [(&str, &str); 12] = [
            ("node/mod.rs", include_str!("node/mod.rs")),
            ("node/api.rs", include_str!("node/api.rs")),
            ("node/state.rs", include_str!("node/state.rs")),
            ("node/commands.rs", include_str!("node/commands.rs")),
            ("node/direct.rs", include_str!("node/direct.rs")),
            ("node/channels.rs", include_str!("node/channels.rs")),
            (
                "node/channel_direct.rs",
                include_str!("node/channel_direct.rs"),
            ),
            ("node/presence.rs", include_str!("node/presence.rs")),
            ("node/aliases.rs", include_str!("node/aliases.rs")),
            (
                "node/relay_service.rs",
                include_str!("node/relay_service.rs"),
            ),
            ("node/ticks.rs", include_str!("node/ticks.rs")),
            ("forward.rs", include_str!("forward.rs")),
        ];
        let mut client_constructions = 0;
        let mut scheduler_constructed = false;
        for (name, source) in sources {
            for forbidden in [
                ".post_cell_pinned(",
                ".post_cell_pinned_excluding(",
                ".open_stream_body_pinned(",
                ".open_stream_prepared(",
                ".post_cell_prepared(",
                ".post_cell_with_class(",
            ] {
                assert!(!source.contains(forbidden), "{name} bypass: {forbidden}");
            }
            let production = source.split("#[cfg(test)]\nmod ").next().unwrap();
            client_constructions += production.matches("Tp1Client::new(").count();
            scheduler_constructed |= production.contains("RelayScheduler::with_transit(");
        }
        assert_eq!(
            client_constructions, 2,
            "endpoint and authorized transit pools are separate"
        );
        assert!(scheduler_constructed);
    }
}
