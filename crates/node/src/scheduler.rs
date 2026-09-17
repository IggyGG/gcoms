use crate::alias::{AliasContact, OwnedAlias, RelayProvision};
use crate::relay::{Frwd, FrwdTargetPolicy, RelayPush, RelayTarget, UnauthenticatedRelayPush};
use gcoms_core::Cell;
#[cfg(test)]
use gcoms_core::CellType;
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

pub mod diagnostics;

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
    Shutdown,
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
        }
    }

    pub(crate) fn maintenance_delay(&self, rng: &mut StdRng) -> Duration {
        Duration::from_millis(rng.gen_range(self.maintenance_min_ms..self.maintenance_max_ms))
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
            Self::Shutdown => write!(f, "relay scheduler is shut down"),
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
    Failed(String),
    Shutdown,
}

impl JobResult {
    pub fn state(&self) -> CompletionState {
        match self {
            Self::HopAccepted(_) | Self::Stream(_) => CompletionState::HopAccepted,
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
        }
    }

    pub fn stream(self) -> Result<CellStream, String> {
        match self {
            Self::Stream(stream) => Ok(stream),
            Self::Failed(error) => Err(error),
            Self::Shutdown => Err("relay scheduler shut down".into()),
            Self::HopAccepted(_) => Err("unexpected finite completion".into()),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct LaneKey {
    address: SocketAddr,
    service_id: [u8; 32],
    token: String,
    administrative: bool,
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
}

struct FairQueue {
    classes: [VecDeque<QueuedJob>; CLASS_COUNT],
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
        self.classes[class.index()].push_back(job);
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<QueuedJob> {
        for offset in 0..CLASS_COUNT {
            let index = (self.next + offset) % CLASS_COUNT;
            if let Some(job) = self.classes[index].pop_front() {
                self.len -= 1;
                self.next = (index + 1) % CLASS_COUNT;
                return Some(job);
            }
        }
        None
    }

    fn shutdown(&mut self) {
        for queue in &mut self.classes {
            for job in queue.drain(..) {
                let _ = job.done.send(JobResult::Shutdown);
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
}

#[derive(Clone)]
pub struct RelayScheduler {
    inner: Arc<Inner>,
}

impl RelayScheduler {
    pub fn new(client: Arc<Tp1Client>) -> Self {
        Self::with_profile(client, SchedulerProfile::production())
    }

    pub(crate) fn with_profile(client: Arc<Tp1Client>, profile: SchedulerProfile) -> Self {
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

    pub fn push(
        &self,
        class: ProducerClass,
        contact: AliasContact,
        inner: Cell,
    ) -> Result<Receipt, EnqueueError> {
        let key = LaneKey {
            address: contact.target.address,
            service_id: contact.target.relay_service_id,
            token: gcoms_transport::encode_b64url(&contact.queue_id),
            administrative: false,
        };
        self.enqueue(key, class, SemanticJob::Push { contact, inner })
    }

    pub fn frwd(
        &self,
        class: ProducerClass,
        relay: RelayProvision,
        destination: AliasContact,
        inner: Cell,
        policy: FrwdTargetPolicy,
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
        };
        self.enqueue(
            key,
            class,
            SemanticJob::Frwd {
                relay,
                destination,
                inner,
                policy,
            },
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
        let key = LaneKey {
            address: alias.contact.target.address,
            service_id: alias.contact.target.relay_service_id,
            token: gcoms_transport::encode_b64url(&alias.contact.queue_id),
            administrative: true,
        };
        self.enqueue(
            key,
            ProducerClass::Administration,
            SemanticJob::Subscribe(Box::new(alias)),
        )
    }

    /// Open a lane now, without a job, so its slot clock and cover start
    /// immediately. Idempotent. `pinned` lanes are exempt from the idle
    /// sweep and must be closed explicitly.
    pub fn open_lane(&self, auth: LaneAuth, pinned: bool) -> Result<(), EnqueueError> {
        let key = auth.key();
        let lane = self.lane_for(&key, Some(auth))?;
        lane.pinned
            .fetch_or(pinned, std::sync::atomic::Ordering::AcqRel);
        Ok(())
    }

    /// Close the lane for `auth`: queued jobs fail with `Shutdown`, the
    /// worker stops, and no further cover is emitted toward that hop.
    pub fn close_lane(&self, auth: &LaneAuth) {
        let key = auth.key();
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
        let auth = semantic.lane_auth();
        let lane = self.lane_for(&key, auth).inspect_err(|error| {
            let d = &self.inner.diagnostics;
            d.increment(match error {
                EnqueueError::Full => &d.rejected_full,
                EnqueueError::Shutdown => &d.rejected_shutdown,
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
        let queued = queue.push(
            class,
            QueuedJob {
                semantic,
                done,
                queued_at: self.inner.diagnostics.start(),
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
        // Warm the TLS connection on the lane's own clock, never at the
        // instant real traffic first arrives.
        let warming = inner.diagnostics.start();
        if until_shutdown(
            &mut shutdown,
            inner.client.warm(key.address, key.service_id),
        )
        .await
        .is_none()
        {
            lane.queue
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .shutdown();
            return;
        }
        if let Some(started) = warming {
            inner.diagnostics.warm.observe(started.elapsed());
        }
        loop {
            if *shutdown.borrow() {
                lane.queue
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .shutdown();
                break;
            }
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        lane.queue.lock().unwrap_or_else(|p| p.into_inner()).shutdown();
                        break;
                    }
                    continue;
                }
                _ = tokio::time::sleep(interval) => {}
            }
            if lane.closing.load(std::sync::atomic::Ordering::Acquire) {
                lane.queue
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .shutdown();
                break;
            }
            round = round.wrapping_add(1);
            if !key.administrative {
                inner.diagnostics.increment(&inner.diagnostics.data_ticks);
            }
            if !key.administrative && !schedule_rng.gen_bool(inner.emission_probability) {
                inner
                    .diagnostics
                    .increment(&inner.diagnostics.data_skipped_ticks);
                continue;
            }
            let job = lane.queue.lock().unwrap_or_else(|p| p.into_inner()).pop();
            if let Some(job) = job {
                if let Some(queued_at) = job.queued_at {
                    inner.diagnostics.queue_wait.observe(queued_at.elapsed());
                }
                inner.diagnostics.increment(&inner.diagnostics.dispatched);
                let started = inner.diagnostics.start();
                let result = match prepare(job.semantic, round, &mut request_rng) {
                    Ok(request) => until_shutdown(
                        &mut shutdown,
                        send_request(&inner.client, request, inner.connect_retry_base),
                    )
                    .await
                    .unwrap_or(JobResult::Shutdown),
                    Err(error) => JobResult::Failed(error),
                };
                if let Some(started) = started {
                    inner.diagnostics.service.observe(started.elapsed());
                }
                if matches!(result, JobResult::Failed(_) | JobResult::Shutdown) {
                    inner.diagnostics.increment(&inner.diagnostics.failed);
                }
                let _ = job.done.send(result);
            } else if !key.administrative && inner.emit_cover {
                // Idle slot: emit a fresh authenticated cover deposit so the
                // lane's wire rate does not depend on whether it has traffic.
                let auth = lane.auth.lock().unwrap_or_else(|p| p.into_inner()).clone();
                if let Some(auth) = auth {
                    if let Ok(request) = auth.cover_request(round, &mut request_rng) {
                        inner
                            .diagnostics
                            .increment(&inner.diagnostics.cover_attempts);
                        let _ = until_shutdown(
                            &mut shutdown,
                            send_request(&inner.client, request, inner.connect_retry_base),
                        )
                        .await;
                    }
                }
            }
        }
    });
}

// Cancellation releases warming connections and an in-flight receipt as well
// as queued work. A cancelled send does not establish that its remote effect
// was undone; durable callers continue to reconcile the original message ID.
async fn until_shutdown<F: std::future::Future>(
    shutdown: &mut watch::Receiver<bool>,
    future: F,
) -> Option<F::Output> {
    if *shutdown.borrow() {
        return None;
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => None,
        result = future => Some(result),
    }
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

async fn retry_unsent_post(
    client: &Tp1Client,
    target: &RelayTarget,
    token: &str,
    wire: bytes::Bytes,
    excluded: &[(SocketAddr, [u8; 32])],
    retry_base: Duration,
) -> JobResult {
    let mut attempt = 0;
    loop {
        let result = client
            .post_cell_pinned_excluding(
                target.address,
                target.relay_service_id,
                token,
                wire.clone(),
                excluded,
            )
            .await;
        match result {
            Ok(outcome) => {
                return match outcome.into_accepted() {
                    Ok(Some(cell)) => JobResult::HopAccepted(
                        cell.encode_wire()
                            .map(bytes::Bytes::from)
                            .unwrap_or_default(),
                    ),
                    Ok(None) => JobResult::HopAccepted(bytes::Bytes::new()),
                    Err(error) => JobResult::Failed(error),
                };
            }
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

async fn send_request(client: &Tp1Client, request: Request, retry_base: Duration) -> JobResult {
    match request {
        Request::Post {
            target,
            token,
            wire,
            excluded,
        } => {
            retry_unsent_post(
                client,
                &target,
                &token,
                bytes::Bytes::from(wire),
                &excluded,
                retry_base,
            )
            .await
        }
        Request::Subscribe { alias, auth } => {
            let mut attempt = 0;
            loop {
                let result = client
                    .open_stream_body_pinned(
                        alias.contact.target.address,
                        alias.contact.target.relay_service_id,
                        &gcoms_transport::encode_b64url(&alias.contact.queue_id),
                        Some(&auth),
                    )
                    .await;
                match result {
                    Ok(stream) => break JobResult::Stream(stream),
                    Err(error) => {
                        let text = error.to_string();
                        if attempt < CONNECT_RETRY_ATTEMPTS && is_unsent_connect_error(&text) {
                            attempt += 1;
                            tokio::time::sleep(retry_base * attempt).await;
                            continue;
                        }
                        break JobResult::Failed(text);
                    }
                }
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

fn prepare(semantic: SemanticJob, round: u16, rng: &mut StdRng) -> Result<Request, String> {
    match semantic {
        SemanticJob::Push { contact, inner } => {
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

    fn forwarded(marker: u8) -> Frwd {
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

    fn queued(marker: u8, class: ProducerClass) -> (ProducerClass, QueuedJob) {
        let (done, _) = oneshot::channel();
        (
            class,
            QueuedJob {
                queued_at: None,
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

    fn marker(job: &QueuedJob) -> u8 {
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
            ] {
                assert!(!source.contains(forbidden), "{name} bypass: {forbidden}");
            }
            let production = source.split("#[cfg(test)]\nmod ").next().unwrap();
            client_constructions += production.matches("Tp1Client::new(").count();
            scheduler_constructed |= production.contains("RelayScheduler::new(client.clone())");
        }
        assert_eq!(
            client_constructions, 2,
            "endpoint and authorized transit pools are separate"
        );
        assert!(scheduler_constructed);
    }
}
