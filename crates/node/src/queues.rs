use crate::lease::{
    AdmissionGrant, AdmissionKey, Capabilities, DynamicGrantRequest, LeaseCodecError, LeaseCreate,
    LeaseLimits, LeaseRenew, LeaseRevoke, LeaseRotate, Nonce, QueueId, RelayServiceId,
    ValidationPolicy, ADMISSION_GRANT_LEN,
};
use crate::relay::{RelayCodecError, RelaySub, UnauthenticatedRelayPush};
use gcoms_core::{Cell, HEADER_LEN};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;

#[cfg(feature = "experimental-gc2")]
pub mod gc2;
#[cfg(feature = "push-notifications")]
mod notifications;

pub use crate::lease::{DEFAULT_QUEUE_BYTES, DEFAULT_QUEUE_CELLS};
pub const DEFAULT_MAX_GRANTS: usize = 1024;
pub const DEFAULT_MAX_QUEUES: usize = 1024;
pub const DEFAULT_MAX_REPLAY_NONCES: usize = 4096;
/// Distinct live subscription nonces one lease may hold. Subscriptions are
/// long-lived, so they get their own small budget: a `sub_cap` holder cannot
/// exhaust the push replay set and brick deposits (SPEC §10.2).
pub const DEFAULT_MAX_SUBSCRIPTION_NONCES: usize = 64;
/// Aggregate RAM the relay will hold across every queue (SPEC §10.3
/// `RELAY_CAP` as a store bound). Independent of the per-lease limits.
pub const DEFAULT_MAX_TOTAL_QUEUE_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_GRANT_LIFETIME_SECS: u64 = 300;
pub const DEFAULT_MAX_LEASE_LIFETIME_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_DYNAMIC_GRANTS_PER_MINUTE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreConfig {
    pub max_grants: usize,
    pub max_queues: usize,
    pub max_replay_nonces_per_lease: usize,
    pub max_subscription_nonces_per_lease: usize,
    pub max_total_queue_bytes: u64,
    pub relay_limits: LeaseLimits,
    pub grant_lifetime_secs: u64,
    pub max_lease_lifetime_secs: u64,
    pub clock_skew_secs: u64,
    pub dynamic_grants_per_minute: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_grants: DEFAULT_MAX_GRANTS,
            max_queues: DEFAULT_MAX_QUEUES,
            max_replay_nonces_per_lease: DEFAULT_MAX_REPLAY_NONCES,
            max_subscription_nonces_per_lease: DEFAULT_MAX_SUBSCRIPTION_NONCES,
            max_total_queue_bytes: DEFAULT_MAX_TOTAL_QUEUE_BYTES,
            relay_limits: LeaseLimits {
                max_queue_cells: DEFAULT_QUEUE_CELLS,
                max_queue_bytes: DEFAULT_QUEUE_BYTES,
            },
            grant_lifetime_secs: DEFAULT_GRANT_LIFETIME_SECS,
            max_lease_lifetime_secs: DEFAULT_MAX_LEASE_LIFETIME_SECS,
            clock_skew_secs: 0,
            dynamic_grants_per_minute: DEFAULT_DYNAMIC_GRANTS_PER_MINUTE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub limits: LeaseLimits,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionProvision {
    pub grant: AdmissionGrant,
    pub wire: [u8; ADMISSION_GRANT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Enqueued,
    Duplicate,
    /// An authenticated cover deposit (SPEC §7.4): verified and its nonce
    /// recorded, nothing enqueued. The hop receipt is identical to `Enqueued`.
    Cover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    Removed,
    Mismatch,
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseView {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub expiry: u64,
    pub limits: LeaseLimits,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedMessage {
    pub push_nonce: Nonce,
    pub cell: Cell,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidConfig,
    Capacity,
    QueueFull,
    ReplayCapacity,
    Unauthorized,
    GrantConsumed,
    Replay,
    Lease(LeaseCodecError),
    Relay(RelayCodecError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => write!(f, "invalid store configuration"),
            Self::Capacity => write!(f, "store capacity reached"),
            Self::QueueFull => write!(f, "queue capacity reached"),
            Self::ReplayCapacity => write!(f, "replay set capacity reached"),
            Self::Unauthorized => write!(f, "unknown or unauthorized lease operation"),
            Self::GrantConsumed => write!(f, "admission grant was already consumed"),
            Self::Replay => write!(f, "operation nonce was already accepted"),
            Self::Lease(error) => write!(f, "lease authentication failed: {error}"),
            Self::Relay(error) => write!(f, "relay authentication failed: {error}"),
        }
    }
}

impl Error for StoreError {}

impl From<LeaseCodecError> for StoreError {
    fn from(value: LeaseCodecError) -> Self {
        Self::Lease(value)
    }
}

impl From<RelayCodecError> for StoreError {
    fn from(value: RelayCodecError) -> Self {
        Self::Relay(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantStatus {
    Unconsumed,
    Consumed,
}

struct GrantRecord {
    queue_id: QueueId,
    epoch: u64,
    expiry: u64,
    status: GrantStatus,
    temporary_expiry: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayOperation {
    Create,
    Renew,
    Subscribe,
    Push,
    Grant,
}

struct ReplayRecord {
    epoch: u64,
    operation: ReplayOperation,
    nonce: Nonce,
    expiry: u64,
    #[cfg(feature = "experimental-gc2")]
    gc2_push_binding: Option<[u8; 32]>,
}

struct LeaseRecord {
    #[cfg(feature = "push-gateway")]
    ticket_replays: VecDeque<notifications::TicketReplay>,
    #[cfg(feature = "push-gateway")]
    ticket_attempts: VecDeque<u64>,
    #[cfg(feature = "push-notifications")]
    notification: Option<crate::push_notifications::Binding>,
    #[cfg(feature = "push-notifications")]
    last_notification: u64,
    create_digest: [u8; 32],
    queue_id: QueueId,
    epoch: u64,
    expiry: u64,
    limits: LeaseLimits,
    capabilities: Capabilities,
    replay: VecDeque<ReplayRecord>,
    // Earliest live replay expiry. Reads of unrelated queues need not walk
    // this history until a record can actually expire.
    next_replay_expiry: Option<u64>,
    dynamic_grants: VecDeque<u64>,
    temporary_expiry: Option<u64>,
}

impl LeaseRecord {
    fn view(&self) -> LeaseView {
        LeaseView {
            queue_id: self.queue_id,
            epoch: self.epoch,
            expiry: self.expiry,
            limits: self.limits,
        }
    }

    fn purge_replay(&mut self, now_unix: u64) {
        if self
            .next_replay_expiry
            .is_none_or(|expiry| expiry > now_unix)
        {
            return;
        }
        self.replay.retain(|record| record.expiry > now_unix);
        self.next_replay_expiry = self.replay.iter().map(|record| record.expiry).min();
    }

    fn has_replay(&self, epoch: u64, operation: ReplayOperation, nonce: &Nonce) -> bool {
        self.replay.iter().any(|record| {
            record.epoch == epoch && record.operation == operation && record.nonce == *nonce
        })
    }

    fn replay_count(&self, operation: ReplayOperation) -> usize {
        self.replay
            .iter()
            .filter(|record| record.operation == operation)
            .count()
    }

    fn record_replay(
        &mut self,
        epoch: u64,
        operation: ReplayOperation,
        nonce: Nonce,
        expiry: u64,
        max_replay_nonces: usize,
    ) -> Result<(), StoreError> {
        if self.replay_count(operation) >= max_replay_nonces {
            return Err(StoreError::ReplayCapacity);
        }
        self.replay.push_back(ReplayRecord {
            epoch,
            operation,
            nonce,
            expiry,
            #[cfg(feature = "experimental-gc2")]
            gc2_push_binding: None,
        });
        self.next_replay_expiry = Some(
            self.next_replay_expiry
                .map_or(expiry, |old| old.min(expiry)),
        );
        Ok(())
    }
}

impl Drop for LeaseRecord {
    fn drop(&mut self) {
        self.capabilities.push.fill(0);
        self.capabilities.sub.fill(0);
        self.capabilities.admin.fill(0);
    }
}

struct Queue {
    bytes: u64,
    messages: VecDeque<QueuedMessage>,
    #[cfg(feature = "experimental-gc2")]
    classes: gc2::ClassQueues,
}

impl Queue {
    fn len(&self) -> usize {
        let count = self.messages.len();
        #[cfg(feature = "experimental-gc2")]
        let count = count + self.classes.len();
        count
    }
}

/// RAM-only FIFO storage. It contains no stream or task handles. Experimental
/// class queues own change notifications, not background tasks.
pub struct QueueStore {
    max_queues: usize,
    queues: HashMap<QueueId, Queue>,
    /// Bytes held across every queue; bounded by `max_total_queue_bytes`.
    total_bytes: u64,
}

impl QueueStore {
    fn new(max_queues: usize) -> Self {
        Self {
            max_queues,
            queues: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn remove_queue(&mut self, queue_id: &QueueId) -> Option<Queue> {
        let queue = self.queues.remove(queue_id)?;
        self.total_bytes = self.total_bytes.saturating_sub(queue.bytes);
        Some(queue)
    }

    fn create(&mut self, queue_id: QueueId) -> Result<(), StoreError> {
        if self.queues.len() >= self.max_queues || self.queues.contains_key(&queue_id) {
            return Err(StoreError::Capacity);
        }
        self.queues.insert(
            queue_id,
            Queue {
                bytes: 0,
                messages: VecDeque::new(),
                #[cfg(feature = "experimental-gc2")]
                classes: gc2::ClassQueues::new(),
            },
        );
        Ok(())
    }

    fn remove(&mut self, queue_id: &QueueId) {
        self.remove_queue(queue_id);
    }

    pub fn len(&self) -> usize {
        self.queues.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }
}

/// Owns all boot-scoped admission, lease, replay, and queue state.
pub struct LeaseStore {
    #[cfg(feature = "push-gateway")]
    ticket_issuer: Option<crate::push_notifications::TicketIssuer>,
    #[cfg(feature = "push-notifications")]
    notification_sink: Option<tokio::sync::mpsc::Sender<[u8; 32]>>,
    relay_service_id: RelayServiceId,
    admission_key: AdmissionKey,
    config: StoreConfig,
    grants: HashMap<[u8; 16], GrantRecord>,
    leases: HashMap<QueueId, LeaseRecord>,
    queues: QueueStore,
}

impl LeaseStore {
    pub fn new(relay_service_id: RelayServiceId, config: StoreConfig) -> Result<Self, StoreError> {
        if config.max_grants == 0
            || config.max_queues == 0
            || config.max_replay_nonces_per_lease == 0
            || config.max_subscription_nonces_per_lease == 0
            || config.max_total_queue_bytes == 0
            || config.relay_limits.max_queue_cells == 0
            || config.relay_limits.max_queue_bytes == 0
            || config.grant_lifetime_secs == 0
            || config.max_lease_lifetime_secs == 0
            || config.dynamic_grants_per_minute == 0
        {
            return Err(StoreError::InvalidConfig);
        }
        ValidationPolicy::new(0, config.clock_skew_secs, u64::MAX)?;

        let mut admission_key = [0u8; 32];
        while admission_key == [0; 32] {
            OsRng.fill_bytes(&mut admission_key);
        }
        Ok(Self {
            #[cfg(feature = "push-gateway")]
            ticket_issuer: None,
            #[cfg(feature = "push-notifications")]
            notification_sink: None,
            relay_service_id,
            admission_key,
            config,
            grants: HashMap::new(),
            leases: HashMap::new(),
            queues: QueueStore::new(config.max_queues),
        })
    }

    pub fn relay_service_id(&self) -> &RelayServiceId {
        &self.relay_service_id
    }

    pub fn issue_grant(
        &mut self,
        request: GrantRequest,
        now_unix: u64,
    ) -> Result<AdmissionProvision, StoreError> {
        self.issue_grant_with_bound(request, now_unix, None)
    }

    /// A bootstrap grant may create one lease until this fixed deadline. Its
    /// admin capability cannot authorize other queues, even through another
    /// authenticated HTTP path. The bound survives renew/rotate operations.
    pub fn issue_temporary_grant(
        &mut self,
        request: GrantRequest,
        now_unix: u64,
        expires_at: u64,
    ) -> Result<AdmissionProvision, StoreError> {
        if expires_at <= now_unix
            || expires_at > now_unix.saturating_add(self.config.max_lease_lifetime_secs)
        {
            return Err(StoreError::Unauthorized);
        }
        self.issue_grant_with_bound(request, now_unix, Some(expires_at))
    }

    fn issue_grant_with_bound(
        &mut self,
        request: GrantRequest,
        now_unix: u64,
        temporary_expiry: Option<u64>,
    ) -> Result<AdmissionProvision, StoreError> {
        self.cleanup_expired(now_unix);
        if self.grants.len() >= self.config.max_grants
            || request.limits.max_queue_cells > self.config.relay_limits.max_queue_cells
            || request.limits.max_queue_bytes > self.config.relay_limits.max_queue_bytes
            || request.limits.max_queue_cells == 0
            || request.limits.max_queue_bytes == 0
        {
            return Err(StoreError::Capacity);
        }
        let expiry = now_unix
            .checked_add(self.config.grant_lifetime_secs)
            .ok_or(StoreError::InvalidConfig)?;
        let mut grant_id = [0u8; 16];
        let mut grant_cap = [0u8; 32];
        loop {
            OsRng.fill_bytes(&mut grant_id);
            if grant_id != [0; 16] && !self.grants.contains_key(&grant_id) {
                break;
            }
        }
        loop {
            OsRng.fill_bytes(&mut grant_cap);
            if grant_cap != [0; 32] && grant_cap != request.queue_id && grant_cap[..16] != grant_id
            {
                break;
            }
        }
        let grant = AdmissionGrant {
            relay_service_id: self.relay_service_id,
            grant_id,
            grant_cap,
            queue_id: request.queue_id,
            epoch: request.epoch,
            not_before: now_unix,
            expiry,
            max_queue_cells: request.limits.max_queue_cells,
            max_queue_bytes: request.limits.max_queue_bytes,
        };
        grant.validate(self.policy(now_unix, self.config.grant_lifetime_secs)?)?;
        let wire = grant.encode(&self.admission_key)?;
        self.grants.insert(
            grant_id,
            GrantRecord {
                queue_id: request.queue_id,
                epoch: request.epoch,
                expiry,
                status: GrantStatus::Unconsumed,
                temporary_expiry,
            },
        );
        Ok(AdmissionProvision { grant, wire })
    }

    pub fn create_lease(&mut self, wire: &[u8], now_unix: u64) -> Result<LeaseView, StoreError> {
        self.cleanup_expired(now_unix);
        let create = LeaseCreate::decode_and_verify(
            wire,
            &self.admission_key,
            &self.relay_service_id,
            self.policy(now_unix, self.config.grant_lifetime_secs)?,
            self.policy(now_unix, self.config.max_lease_lifetime_secs)?,
            self.config.relay_limits,
        )?;
        // Idempotent replay: a control-plane mint creates the lease up front, so
        // activating the same card again must return the live lease instead of a
        // conflict or a consumed-grant error.
        let create_digest: [u8; 32] = Sha256::digest(wire).into();
        if let Some(existing) = self.leases.get(&create.queue_id) {
            if existing.epoch == create.epoch && existing.create_digest == create_digest {
                return Ok(existing.view());
            }
        }
        let grant_id: [u8; 16] = create.grant[33..49]
            .try_into()
            .map_err(|_| StoreError::Unauthorized)?;
        let grant = self.grants.get(&grant_id).ok_or(StoreError::Unauthorized)?;
        if grant.status == GrantStatus::Consumed {
            return Err(StoreError::GrantConsumed);
        }
        if grant.queue_id != create.queue_id
            || grant.epoch != create.epoch
            || grant.expiry <= now_unix
            || grant
                .temporary_expiry
                .is_some_and(|expiry| create.lease_expiry > expiry)
            || self.leases.contains_key(&create.queue_id)
        {
            return Err(StoreError::Unauthorized);
        }
        self.queues.create(create.queue_id)?;
        let mut replay = VecDeque::new();
        replay.push_back(ReplayRecord {
            epoch: create.epoch,
            operation: ReplayOperation::Create,
            nonce: create.nonce,
            expiry: create.lease_expiry,
            #[cfg(feature = "experimental-gc2")]
            gc2_push_binding: None,
        });
        let lease = LeaseRecord {
            #[cfg(feature = "push-gateway")]
            ticket_replays: VecDeque::new(),
            #[cfg(feature = "push-gateway")]
            ticket_attempts: VecDeque::new(),
            #[cfg(feature = "push-notifications")]
            notification: None,
            #[cfg(feature = "push-notifications")]
            last_notification: 0,
            create_digest,
            queue_id: create.queue_id,
            epoch: create.epoch,
            expiry: create.lease_expiry,
            limits: LeaseLimits {
                max_queue_cells: create.queue_cells,
                max_queue_bytes: create.queue_bytes,
            },
            capabilities: create.capabilities,
            replay,
            next_replay_expiry: Some(create.lease_expiry),
            dynamic_grants: VecDeque::new(),
            temporary_expiry: grant.temporary_expiry,
        };
        let view = lease.view();
        self.leases.insert(create.queue_id, lease);
        self.grants
            .get_mut(&grant_id)
            .expect("grant checked above")
            .status = GrantStatus::Consumed;
        Ok(view)
    }

    pub fn issue_dynamic_grant(
        &mut self,
        wire: &[u8],
        now_unix: u64,
    ) -> Result<AdmissionProvision, StoreError> {
        self.cleanup_expired(now_unix);
        let authority_queue_id = short_queue_id(wire)?;
        let relay_service_id = self.relay_service_id;
        let policy = self.policy(now_unix, self.config.grant_lifetime_secs)?;
        let max_replay = self.config.max_replay_nonces_per_lease;
        let rate_limit = self.config.dynamic_grants_per_minute;
        let request = {
            let authority = self
                .leases
                .get_mut(&authority_queue_id)
                .ok_or(StoreError::Unauthorized)?;
            if authority.temporary_expiry.is_some() {
                return Err(StoreError::Unauthorized);
            }
            authority.purge_replay(now_unix);
            let request = DynamicGrantRequest::decode_and_verify(
                wire,
                &authority.capabilities.admin,
                &relay_service_id,
                &authority.queue_id,
                authority.epoch,
                policy,
            )?;
            if authority.has_replay(authority.epoch, ReplayOperation::Grant, &request.nonce) {
                return Err(StoreError::Replay);
            }
            authority
                .dynamic_grants
                .retain(|issued| issued.saturating_add(60) > now_unix);
            if authority.dynamic_grants.len() >= rate_limit {
                return Err(StoreError::Capacity);
            }
            authority.record_replay(
                authority.epoch,
                ReplayOperation::Grant,
                request.nonce,
                request.expiry,
                max_replay,
            )?;
            authority.dynamic_grants.push_back(now_unix);
            request
        };
        self.issue_grant(
            GrantRequest {
                queue_id: request.queue_id,
                epoch: request.epoch,
                limits: request.limits,
            },
            now_unix,
        )
    }

    pub fn renew(&mut self, wire: &[u8], now_unix: u64) -> Result<LeaseView, StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id = short_queue_id(wire)?;
        let policy = self.policy(now_unix, self.config.max_lease_lifetime_secs)?;
        let max_replay = self.config.max_replay_nonces_per_lease;
        let relay_service_id = self.relay_service_id;
        let lease = self
            .leases
            .get_mut(&queue_id)
            .ok_or(StoreError::Unauthorized)?;
        lease.purge_replay(now_unix);
        let renew = LeaseRenew::decode_and_verify(
            wire,
            &lease.capabilities.admin,
            &relay_service_id,
            lease.expiry,
            policy,
        )?;
        require_binding(lease, renew.queue_id, renew.epoch)?;
        if lease
            .temporary_expiry
            .is_some_and(|expiry| renew.lease_expiry > expiry)
        {
            return Err(StoreError::Unauthorized);
        }
        if lease.has_replay(renew.epoch, ReplayOperation::Renew, &renew.nonce) {
            return Err(StoreError::Replay);
        }
        lease.record_replay(
            renew.epoch,
            ReplayOperation::Renew,
            renew.nonce,
            renew.lease_expiry,
            max_replay,
        )?;
        lease.expiry = renew.lease_expiry;
        Ok(lease.view())
    }

    pub fn rotate(&mut self, wire: &[u8], now_unix: u64) -> Result<LeaseView, StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id = short_queue_id(wire)?;
        let policy = self.policy(now_unix, self.config.max_lease_lifetime_secs)?;
        let relay_service_id = self.relay_service_id;
        let lease = self
            .leases
            .get_mut(&queue_id)
            .ok_or(StoreError::Unauthorized)?;
        lease.purge_replay(now_unix);
        let rotate =
            LeaseRotate::decode_and_verify(wire, &lease.capabilities, &relay_service_id, policy)?;
        require_binding(lease, rotate.queue_id, rotate.old_epoch)?;
        if lease
            .temporary_expiry
            .is_some_and(|expiry| rotate.lease_expiry > expiry)
        {
            return Err(StoreError::Unauthorized);
        }
        lease.capabilities.push.fill(0);
        lease.capabilities.sub.fill(0);
        lease.capabilities.admin.fill(0);
        lease.capabilities = rotate.new_capabilities;
        #[cfg(feature = "push-notifications")]
        {
            lease.notification = None;
            lease.last_notification = 0;
        }
        lease.epoch = rotate.new_epoch;
        lease.expiry = rotate.lease_expiry;
        lease.replay.clear();
        lease.next_replay_expiry = None;
        #[cfg(feature = "experimental-gc2")]
        self.queues
            .queues
            .get(&queue_id)
            .expect("every lease owns a queue")
            .classes
            .wake_all();
        Ok(lease.view())
    }

    pub fn revoke(&mut self, wire: &[u8], now_unix: u64) -> Result<(), StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id = short_queue_id(wire)?;
        let policy = self.policy(now_unix, self.config.max_lease_lifetime_secs)?;
        let relay_service_id = self.relay_service_id;
        let lease = self.leases.get(&queue_id).ok_or(StoreError::Unauthorized)?;
        let revoke = LeaseRevoke::decode_and_verify(
            wire,
            &lease.capabilities.admin,
            &relay_service_id,
            policy,
        )?;
        require_binding(lease, revoke.queue_id, revoke.epoch)?;
        self.leases.remove(&queue_id);
        self.queues.remove(&queue_id);
        Ok(())
    }

    pub fn authenticate_sub(&mut self, cell: &Cell, now_unix: u64) -> Result<RelaySub, StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id: QueueId = cell
            .payload
            .get(2..34)
            .ok_or(StoreError::Unauthorized)?
            .try_into()
            .map_err(|_| StoreError::Unauthorized)?;
        let max_replay = self.config.max_subscription_nonces_per_lease;
        let relay_service_id = self.relay_service_id;
        let lease = self
            .leases
            .get_mut(&queue_id)
            .ok_or(StoreError::Unauthorized)?;
        lease.purge_replay(now_unix);
        let sub =
            RelaySub::decode_from_cell(cell, &lease.capabilities.sub, &relay_service_id, now_unix)?;
        require_binding(lease, sub.queue_id, sub.epoch)?;
        if sub.subscription_expiry > lease.expiry {
            return Err(StoreError::Unauthorized);
        }
        if lease.has_replay(sub.epoch, ReplayOperation::Subscribe, &sub.nonce) {
            return Err(StoreError::Replay);
        }
        lease.record_replay(
            sub.epoch,
            ReplayOperation::Subscribe,
            sub.nonce,
            sub.subscription_expiry,
            max_replay,
        )?;
        Ok(sub)
    }

    pub fn authenticate_push(
        &mut self,
        push: UnauthenticatedRelayPush,
        now_unix: u64,
    ) -> Result<PushOutcome, StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id = push.queue_id();
        let max_replay = self.config.max_replay_nonces_per_lease;
        let relay_service_id = self.relay_service_id;
        let lease = self
            .leases
            .get_mut(&queue_id)
            .ok_or(StoreError::Unauthorized)?;
        lease.purge_replay(now_unix);
        let push = push.authenticate(&lease.capabilities.push, &relay_service_id, now_unix)?;
        require_binding(lease, push.queue_id, push.epoch)?;
        if push.push_expiry > lease.expiry {
            return Err(StoreError::Unauthorized);
        }
        if lease.has_replay(push.epoch, ReplayOperation::Push, &push.push_nonce) {
            // A GC/1 request cannot retry a GC/2 deposit under the same nonce.
            #[cfg(feature = "experimental-gc2")]
            if lease.replay.iter().any(|record| {
                record.epoch == push.epoch
                    && record.operation == ReplayOperation::Push
                    && record.nonce == push.push_nonce
                    && record.gc2_push_binding.is_some()
            }) {
                return Err(StoreError::Replay);
            }
            return Ok(PushOutcome::Duplicate);
        }
        let Some(msg) = push.msg else {
            // Cover deposit: same authentication and replay accounting as a
            // real deposit so the relay's replies and timing are identical,
            // but no queue capacity is consumed.
            lease.record_replay(
                push.epoch,
                ReplayOperation::Push,
                push.push_nonce,
                push.push_expiry,
                max_replay,
            )?;
            return Ok(PushOutcome::Cover);
        };
        let natural_bytes = natural_cell_len_checked(&msg)?;
        let total_after = self
            .queues
            .total_bytes
            .checked_add(natural_bytes)
            .ok_or(StoreError::Capacity)?;
        if total_after > self.config.max_total_queue_bytes {
            return Err(StoreError::Capacity);
        }
        let queue = self
            .queues
            .queues
            .get_mut(&queue_id)
            .expect("every lease owns a queue");
        let next_cells = queue.len().checked_add(1).ok_or(StoreError::QueueFull)?;
        let next_bytes = queue
            .bytes
            .checked_add(natural_bytes)
            .ok_or(StoreError::QueueFull)?;
        if next_cells > usize::from(lease.limits.max_queue_cells)
            || next_bytes > lease.limits.max_queue_bytes
        {
            return Err(StoreError::QueueFull);
        }
        if lease.replay_count(ReplayOperation::Push) >= max_replay {
            return Err(StoreError::ReplayCapacity);
        }
        queue.messages.push_back(QueuedMessage {
            push_nonce: push.push_nonce,
            cell: msg,
        });
        queue.bytes = next_bytes;
        self.queues.total_bytes = total_after;
        lease.record_replay(
            push.epoch,
            ReplayOperation::Push,
            push.push_nonce,
            push.push_expiry,
            max_replay,
        )?;
        Ok(PushOutcome::Enqueued)
    }

    pub fn peek(&mut self, queue_id: &QueueId, now_unix: u64) -> Option<&QueuedMessage> {
        self.cleanup_expired(now_unix);
        self.queues
            .queues
            .get(queue_id)
            .and_then(|queue| queue.messages.front())
    }

    pub fn acknowledge(
        &mut self,
        queue_id: &QueueId,
        push_nonce: &Nonce,
        now_unix: u64,
    ) -> AckOutcome {
        self.cleanup_expired(now_unix);
        let Some(queue) = self.queues.queues.get_mut(queue_id) else {
            return AckOutcome::Empty;
        };
        let Some(head) = queue.messages.front() else {
            return AckOutcome::Empty;
        };
        if head.push_nonce != *push_nonce {
            return AckOutcome::Mismatch;
        }
        let removed = queue.messages.pop_front().expect("head checked above");
        let freed = natural_cell_len(&removed.cell);
        queue.bytes = queue.bytes.saturating_sub(freed);
        self.queues.total_bytes = self.queues.total_bytes.saturating_sub(freed);
        AckOutcome::Removed
    }

    /// Bytes held across every queue on this relay.
    pub fn total_queue_bytes(&self) -> u64 {
        self.queues.total_bytes()
    }

    pub fn lease(&mut self, queue_id: &QueueId, now_unix: u64) -> Option<LeaseView> {
        self.cleanup_expired(now_unix);
        self.leases.get(queue_id).map(LeaseRecord::view)
    }

    pub fn subscription_valid(
        &mut self,
        queue_id: &QueueId,
        epoch: u64,
        subscription_expiry: u64,
        now_unix: u64,
    ) -> bool {
        self.cleanup_expired(now_unix);
        self.leases.get(queue_id).is_some_and(|lease| {
            lease.epoch == epoch
                && subscription_expiry > now_unix
                && subscription_expiry <= lease.expiry
        })
    }

    pub fn queue_len(&mut self, queue_id: &QueueId, now_unix: u64) -> usize {
        self.cleanup_expired(now_unix);
        self.queues.queues.get(queue_id).map_or(0, Queue::len)
    }

    pub fn queue_bytes(&mut self, queue_id: &QueueId, now_unix: u64) -> u64 {
        self.cleanup_expired(now_unix);
        self.queues
            .queues
            .get(queue_id)
            .map_or(0, |queue| queue.bytes)
    }

    pub fn queue_count(&mut self, now_unix: u64) -> usize {
        self.cleanup_expired(now_unix);
        self.queues.len()
    }

    pub fn cleanup_expired(&mut self, now_unix: u64) {
        self.grants.retain(|_, grant| grant.expiry > now_unix);
        let expired: Vec<QueueId> = self
            .leases
            .iter()
            .filter_map(|(queue_id, lease)| (lease.expiry <= now_unix).then_some(*queue_id))
            .collect();
        for queue_id in expired {
            self.leases.remove(&queue_id);
            self.queues.remove(&queue_id);
        }
        for lease in self.leases.values_mut() {
            lease.purge_replay(now_unix);
        }
    }

    fn policy(&self, now_unix: u64, horizon_secs: u64) -> Result<ValidationPolicy, StoreError> {
        let max_expiry_unix = now_unix
            .checked_add(horizon_secs)
            .ok_or(StoreError::InvalidConfig)?;
        Ok(ValidationPolicy::new(
            now_unix,
            self.config.clock_skew_secs,
            max_expiry_unix,
        )?)
    }
}

impl Drop for LeaseStore {
    fn drop(&mut self) {
        self.admission_key.fill(0);
    }
}

fn short_queue_id(wire: &[u8]) -> Result<QueueId, StoreError> {
    wire.get(2..34)
        .ok_or(StoreError::Unauthorized)?
        .try_into()
        .map_err(|_| StoreError::Unauthorized)
}

fn require_binding(lease: &LeaseRecord, queue_id: QueueId, epoch: u64) -> Result<(), StoreError> {
    if lease.queue_id != queue_id || lease.epoch != epoch {
        Err(StoreError::Unauthorized)
    } else {
        Ok(())
    }
}

fn natural_cell_len_checked(msg: &Cell) -> Result<u64, StoreError> {
    if msg.payload.len() > u16::MAX as usize {
        return Err(StoreError::Relay(RelayCodecError::CellTooLarge));
    }
    Ok(natural_cell_len(msg))
}

fn natural_cell_len(cell: &Cell) -> u64 {
    HEADER_LEN as u64 + cell.payload.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{LeaseCreate, LeaseRenew, LeaseRevoke, LeaseRotate};
    use crate::relay::RelayPush;
    use gcoms_core::CellType;

    const NOW: u64 = 1_000_000;
    const RELAY_ID: RelayServiceId = [9; 32];
    const QUEUE_ID: QueueId = [1; 32];
    const EPOCH: u64 = 7;

    fn caps(seed: u8) -> Capabilities {
        Capabilities {
            push: [seed; 32],
            sub: [seed + 1; 32],
            admin: [seed + 2; 32],
        }
    }

    fn config(cells: u16, bytes: u64) -> StoreConfig {
        StoreConfig {
            max_grants: 8,
            max_queues: 4,
            max_replay_nonces_per_lease: 16,
            max_subscription_nonces_per_lease: 16,
            max_total_queue_bytes: 1024 * 1024,
            relay_limits: LeaseLimits {
                max_queue_cells: cells,
                max_queue_bytes: bytes,
            },
            grant_lifetime_secs: 60,
            max_lease_lifetime_secs: 600,
            clock_skew_secs: 0,
            dynamic_grants_per_minute: DEFAULT_DYNAMIC_GRANTS_PER_MINUTE,
        }
    }

    fn store(cells: u16, bytes: u64) -> LeaseStore {
        LeaseStore::new(RELAY_ID, config(cells, bytes)).unwrap()
    }

    fn create_lease(
        store: &mut LeaseStore,
        capabilities: Capabilities,
        cells: u16,
        bytes: u64,
    ) -> AdmissionProvision {
        let provision = store
            .issue_grant(
                GrantRequest {
                    queue_id: QUEUE_ID,
                    epoch: EPOCH,
                    limits: LeaseLimits {
                        max_queue_cells: cells,
                        max_queue_bytes: bytes,
                    },
                },
                NOW,
            )
            .unwrap();
        let create = LeaseCreate {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 300,
            queue_cells: cells,
            queue_bytes: bytes,
            capabilities,
            nonce: [31; 16],
            grant: provision.wire,
        };
        let wire = create.encode(&RELAY_ID).unwrap();
        store.create_lease(&wire, NOW).unwrap();
        provision
    }

    fn msg(payload_len: usize, marker: u8) -> Cell {
        Cell::new(CellType::Msg, 0, marker as u16, vec![marker; payload_len])
    }

    fn push_wire(
        capabilities: &Capabilities,
        epoch: u64,
        nonce: Nonce,
        payload_len: usize,
        marker: u8,
    ) -> UnauthenticatedRelayPush {
        let push = RelayPush {
            queue_id: QUEUE_ID,
            epoch,
            push_nonce: nonce,
            push_expiry: NOW + 100,
            msg: Some(msg(payload_len, marker)),
        };
        UnauthenticatedRelayPush::parse(
            push.encode_into_cell(&capabilities.push, &RELAY_ID)
                .unwrap(),
        )
        .unwrap()
    }

    fn push_wire_with_expiry(
        capabilities: &Capabilities,
        nonce: Nonce,
        expiry: u64,
        marker: u8,
    ) -> UnauthenticatedRelayPush {
        let push = RelayPush {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            push_nonce: nonce,
            push_expiry: expiry,
            msg: Some(msg(10, marker)),
        };
        UnauthenticatedRelayPush::parse(
            push.encode_into_cell(&capabilities.push, &RELAY_ID)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn wrong_cap_is_rejected_before_mutation() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        let wrong = caps(20);
        let result = store.authenticate_push(push_wire(&wrong, EPOCH, [1; 16], 10, 1), NOW);
        assert!(matches!(
            result,
            Err(StoreError::Relay(RelayCodecError::InvalidMac))
        ));
        assert_eq!(store.queue_len(&QUEUE_ID, NOW), 0);
    }

    #[test]
    fn consumed_grant_cannot_create_twice() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        let provision = create_lease(&mut store, capabilities, 4, 1024);
        let replay = LeaseCreate {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 300,
            queue_cells: 4,
            queue_bytes: 1024,
            capabilities,
            nonce: [32; 16],
            grant: provision.wire,
        }
        .encode(&RELAY_ID)
        .unwrap();
        assert_eq!(
            store.create_lease(&replay, NOW),
            Err(StoreError::GrantConsumed)
        );
        assert_eq!(store.queue_count(NOW), 1);
    }

    #[test]
    fn exact_create_retry_preserves_queue_and_cannot_change_authority() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        let provision = create_lease(&mut store, capabilities, 4, 1024);
        let original = LeaseCreate {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 300,
            queue_cells: 4,
            queue_bytes: 1024,
            capabilities,
            nonce: [31; 16],
            grant: provision.wire,
        };
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [55; 16], 10, 1), NOW)
            .unwrap();
        assert!(store
            .create_lease(&original.encode(&RELAY_ID).unwrap(), NOW + 1)
            .is_ok());
        assert_eq!(store.queue_len(&QUEUE_ID, NOW + 1), 1);
        for field in 0..5 {
            let mut changed = original.clone();
            match field {
                0 => changed.capabilities = caps(20),
                1 => changed.queue_cells = 3,
                2 => changed.queue_bytes = 512,
                3 => changed.lease_expiry -= 1,
                _ => changed.nonce = [32; 16],
            }
            assert!(store
                .create_lease(&changed.encode(&RELAY_ID).unwrap(), NOW + 1)
                .is_err());
        }
        assert_eq!(store.queue_len(&QUEUE_ID, NOW + 1), 1);
    }

    #[test]
    fn exact_activation_retry_preserves_queue_and_rejects_changed_capabilities() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        let provision = create_lease(&mut store, capabilities, 4, 1024);
        let mut retry = LeaseCreate {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 300,
            queue_cells: 4,
            queue_bytes: 1024,
            capabilities,
            nonce: [31; 16],
            grant: provision.wire,
        };
        let wire = retry.encode(&RELAY_ID).unwrap();
        let before = store.leases[&QUEUE_ID].view();
        assert_eq!(store.create_lease(&wire, NOW), Ok(before));
        assert_eq!(store.queue_count(NOW), 1);
        assert_eq!(store.leases[&QUEUE_ID].replay.len(), 1);
        retry.capabilities = caps(20);
        assert_eq!(
            store.create_lease(&retry.encode(&RELAY_ID).unwrap(), NOW),
            Err(StoreError::GrantConsumed)
        );
        retry.capabilities = capabilities;
        retry.lease_expiry += 1;
        assert_eq!(
            store.create_lease(&retry.encode(&RELAY_ID).unwrap(), NOW),
            Err(StoreError::GrantConsumed)
        );
        assert_eq!(store.leases[&QUEUE_ID].view(), before);
    }

    #[test]
    fn temporary_grant_cannot_extend_its_bound_or_authorize_another_queue() {
        let mut store = store(4, 1024);
        let capabilities = caps(10);
        let grant = store
            .issue_temporary_grant(
                GrantRequest {
                    queue_id: QUEUE_ID,
                    epoch: EPOCH,
                    limits: LeaseLimits {
                        max_queue_cells: 4,
                        max_queue_bytes: 1024,
                    },
                },
                NOW,
                NOW + 400,
            )
            .unwrap();
        let mut create = LeaseCreate {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 401,
            queue_cells: 4,
            queue_bytes: 1024,
            capabilities,
            nonce: [31; 16],
            grant: grant.wire,
        };
        assert_eq!(
            store.create_lease(&create.encode(&RELAY_ID).unwrap(), NOW),
            Err(StoreError::Unauthorized)
        );
        create.lease_expiry = NOW + 300;
        store
            .create_lease(&create.encode(&RELAY_ID).unwrap(), NOW)
            .unwrap();
        let mut renew = LeaseRenew {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 401,
            nonce: [32; 16],
        };
        assert_eq!(
            store.renew(&renew.encode(&capabilities.admin, &RELAY_ID).unwrap(), NOW),
            Err(StoreError::Unauthorized)
        );
        renew.lease_expiry = NOW + 350;
        store
            .renew(&renew.encode(&capabilities.admin, &RELAY_ID).unwrap(), NOW)
            .unwrap();
        let mut rotate = LeaseRotate {
            queue_id: QUEUE_ID,
            old_epoch: EPOCH,
            new_epoch: EPOCH + 1,
            lease_expiry: NOW + 401,
            new_capabilities: caps(20),
            nonce: [33; 16],
        };
        assert_eq!(
            store.rotate(&rotate.encode(&capabilities.admin, &RELAY_ID).unwrap(), NOW),
            Err(StoreError::Unauthorized)
        );
        rotate.lease_expiry = NOW + 400;
        store
            .rotate(&rotate.encode(&capabilities.admin, &RELAY_ID).unwrap(), NOW)
            .unwrap();
        let request = DynamicGrantRequest {
            authority_queue_id: QUEUE_ID,
            authority_epoch: EPOCH + 1,
            queue_id: [44; 32],
            epoch: 1,
            limits: LeaseLimits {
                max_queue_cells: 4,
                max_queue_bytes: 1024,
            },
            nonce: [34; 16],
            expiry: NOW + 30,
        }
        .encode(&caps(20).admin, &RELAY_ID)
        .unwrap();
        assert!(matches!(
            store.issue_dynamic_grant(&request, NOW),
            Err(StoreError::Unauthorized)
        ));
        assert_eq!(store.queue_count(NOW), 1);
        assert_eq!(store.queue_count(NOW + 400), 0);
    }

    #[test]
    fn subscription_nonce_replay_is_rejected() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        let sub = RelaySub {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            subscription_expiry: NOW + 100,
            nonce: [3; 16],
        }
        .encode_into_cell(&capabilities.sub, &RELAY_ID)
        .unwrap();
        assert!(store.authenticate_sub(&sub, NOW).is_ok());
        assert_eq!(store.authenticate_sub(&sub, NOW), Err(StoreError::Replay));
    }

    #[test]
    fn duplicate_push_has_distinct_outcome_and_no_second_enqueue() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        assert_eq!(
            store
                .authenticate_push(push_wire(&capabilities, EPOCH, [4; 16], 20, 1), NOW)
                .unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            store
                .authenticate_push(push_wire(&capabilities, EPOCH, [4; 16], 20, 1), NOW)
                .unwrap(),
            PushOutcome::Duplicate
        );
        assert_eq!(store.queue_len(&QUEUE_ID, NOW), 1);
    }

    #[test]
    fn push_replay_record_expires_with_push() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        let nonce = [44; 16];
        store
            .authenticate_push(push_wire_with_expiry(&capabilities, nonce, NOW + 1, 1), NOW)
            .unwrap();
        assert_eq!(
            store.acknowledge(&QUEUE_ID, &nonce, NOW),
            AckOutcome::Removed
        );

        assert_eq!(
            store
                .authenticate_push(
                    push_wire_with_expiry(&capabilities, nonce, NOW + 100, 2),
                    NOW + 2,
                )
                .unwrap(),
            PushOutcome::Enqueued
        );
    }

    #[test]
    fn replay_cleanup_tracks_earlier_deadlines_and_exact_boundaries() {
        let capabilities = caps(10);
        let mut bounded = config(8, 1024);
        bounded.max_replay_nonces_per_lease = 2;
        let mut store = LeaseStore::new(RELAY_ID, bounded).unwrap();
        create_lease(&mut store, capabilities, 8, 1024);
        let push =
            |nonce, expiry| push_wire_with_expiry(&capabilities, [nonce; 16], NOW + expiry, nonce);
        store.authenticate_push(push(1, 100), NOW).unwrap();
        // A newly appended record expires before the existing cached deadline.
        store.authenticate_push(push(2, 10), NOW + 1).unwrap();
        assert_eq!(
            store.authenticate_push(push(3, 50), NOW + 9),
            Err(StoreError::ReplayCapacity)
        );
        assert_eq!(
            store.authenticate_push(push(3, 50), NOW + 10),
            Ok(PushOutcome::Enqueued)
        );
        // A clock rollback must not remove still-live replay protection.
        assert_eq!(
            store.authenticate_push(push(1, 100), NOW + 5),
            Ok(PushOutcome::Duplicate)
        );
        assert_eq!(
            store.authenticate_push(push(4, 200), NOW + 49),
            Err(StoreError::ReplayCapacity)
        );
        assert_eq!(
            store.authenticate_push(push(4, 200), NOW + 50),
            Ok(PushOutcome::Enqueued)
        );
        // Expiring replay records never discards the undelivered queue.
        assert_eq!(store.queue_len(&QUEUE_ID, NOW + 50), 4);
        assert_eq!(store.peek(&QUEUE_ID, NOW + 50).unwrap().push_nonce, [1; 16]);
    }

    #[test]
    fn rotated_empty_history_tracks_new_replay_expiry() {
        let old = caps(10);
        let new = caps(20);
        let mut bounded = config(4, 1024);
        bounded.max_replay_nonces_per_lease = 1;
        let mut store = LeaseStore::new(RELAY_ID, bounded).unwrap();
        create_lease(&mut store, old, 4, 1024);
        store
            .authenticate_push(push_wire(&old, EPOCH, [1; 16], 10, 1), NOW)
            .unwrap();
        let rotate = LeaseRotate {
            queue_id: QUEUE_ID,
            old_epoch: EPOCH,
            new_epoch: EPOCH + 1,
            lease_expiry: NOW + 400,
            new_capabilities: new,
            nonce: [12; 16],
        }
        .encode(&old.admin, &RELAY_ID)
        .unwrap();
        store.rotate(&rotate, NOW).unwrap();
        store
            .authenticate_push(push_wire(&new, EPOCH + 1, [2; 16], 10, 2), NOW)
            .unwrap();
        assert_eq!(
            store.authenticate_push(push_wire(&new, EPOCH + 1, [3; 16], 10, 3), NOW + 99),
            Err(StoreError::ReplayCapacity)
        );
        let push = RelayPush {
            queue_id: QUEUE_ID,
            epoch: EPOCH + 1,
            push_nonce: [3; 16],
            push_expiry: NOW + 200,
            msg: Some(msg(10, 3)),
        };
        let wire =
            UnauthenticatedRelayPush::parse(push.encode_into_cell(&new.push, &RELAY_ID).unwrap())
                .unwrap();
        assert_eq!(
            store.authenticate_push(wire, NOW + 100),
            Ok(PushOutcome::Enqueued)
        );
        assert_eq!(store.queue_len(&QUEUE_ID, NOW + 100), 3);
    }

    #[test]
    fn active_subscription_revalidates_lease_epoch_and_expiry() {
        let old_caps = caps(10);
        let new_caps = caps(20);
        let mut store = store(4, 1024);
        create_lease(&mut store, old_caps, 4, 1024);
        assert!(store.subscription_valid(&QUEUE_ID, EPOCH, NOW + 100, NOW));
        assert!(!store.subscription_valid(&QUEUE_ID, EPOCH, NOW + 100, NOW + 100));

        let rotate = LeaseRotate {
            queue_id: QUEUE_ID,
            old_epoch: EPOCH,
            new_epoch: EPOCH + 1,
            lease_expiry: NOW + 400,
            new_capabilities: new_caps,
            nonce: [45; 16],
        }
        .encode(&old_caps.admin, &RELAY_ID)
        .unwrap();
        store.rotate(&rotate, NOW).unwrap();
        assert!(!store.subscription_valid(&QUEUE_ID, EPOCH, NOW + 100, NOW));

        let revoke = LeaseRevoke {
            queue_id: QUEUE_ID,
            epoch: EPOCH + 1,
            operation_expiry: NOW + 30,
            nonce: [46; 16],
        }
        .encode(&new_caps.admin, &RELAY_ID)
        .unwrap();
        store.revoke(&revoke, NOW).unwrap();
        assert!(!store.subscription_valid(&QUEUE_ID, EPOCH + 1, NOW + 100, NOW));
    }

    #[test]
    fn reject_new_preserves_fifo_head() {
        let capabilities = caps(10);
        let mut store = store(1, 1024);
        create_lease(&mut store, capabilities, 1, 1024);
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [5; 16], 20, 1), NOW)
            .unwrap();
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [6; 16], 20, 2), NOW),
            Err(StoreError::QueueFull)
        );
        let head = store.peek(&QUEUE_ID, NOW).unwrap();
        assert_eq!(head.push_nonce, [5; 16]);
        assert_eq!(head.cell.round_ctr, 1);
    }

    #[test]
    fn byte_limit_counts_natural_msg_encoding() {
        let capabilities = caps(10);
        let one_msg_bytes = HEADER_LEN as u64 + 10;
        let mut store = store(4, one_msg_bytes);
        create_lease(&mut store, capabilities, 4, one_msg_bytes);
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [7; 16], 10, 1), NOW)
            .unwrap();
        assert_eq!(store.queue_bytes(&QUEUE_ID, NOW), one_msg_bytes);
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [8; 16], 0, 2), NOW),
            Err(StoreError::QueueFull)
        );
        assert_eq!(store.queue_bytes(&QUEUE_ID, NOW), one_msg_bytes);
    }

    #[test]
    fn stale_epoch_is_rejected() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH + 1, [9; 16], 10, 1), NOW),
            Err(StoreError::Unauthorized)
        );
        assert_eq!(store.queue_len(&QUEUE_ID, NOW), 0);
    }

    #[test]
    fn expiry_cleanup_erases_lease_queue_and_replay() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [10; 16], 10, 1), NOW)
            .unwrap();
        store.cleanup_expired(NOW + 300);
        assert!(store.lease(&QUEUE_ID, NOW + 300).is_none());
        assert_eq!(store.queue_count(NOW + 300), 0);
        assert!(store.peek(&QUEUE_ID, NOW + 300).is_none());
    }

    #[test]
    fn rotate_invalidates_old_caps_and_preserves_queue() {
        let old_caps = caps(10);
        let new_caps = caps(20);
        let mut store = store(4, 1024);
        create_lease(&mut store, old_caps, 4, 1024);
        store
            .authenticate_push(push_wire(&old_caps, EPOCH, [11; 16], 10, 1), NOW)
            .unwrap();
        let rotate = LeaseRotate {
            queue_id: QUEUE_ID,
            old_epoch: EPOCH,
            new_epoch: EPOCH + 1,
            lease_expiry: NOW + 400,
            new_capabilities: new_caps,
            nonce: [12; 16],
        }
        .encode(&old_caps.admin, &RELAY_ID)
        .unwrap();
        assert_eq!(store.rotate(&rotate, NOW).unwrap().epoch, EPOCH + 1);
        assert_eq!(store.queue_len(&QUEUE_ID, NOW), 1);
        assert!(matches!(
            store.authenticate_push(push_wire(&old_caps, EPOCH + 1, [13; 16], 10, 2), NOW),
            Err(StoreError::Relay(RelayCodecError::InvalidMac))
        ));
        assert_eq!(
            store
                .authenticate_push(push_wire(&new_caps, EPOCH + 1, [14; 16], 10, 2), NOW,)
                .unwrap(),
            PushOutcome::Enqueued
        );
    }

    #[test]
    fn renew_extends_and_replay_is_rejected() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        let renew = LeaseRenew {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            lease_expiry: NOW + 400,
            nonce: [15; 16],
        }
        .encode(&capabilities.admin, &RELAY_ID)
        .unwrap();
        assert_eq!(store.renew(&renew, NOW).unwrap().expiry, NOW + 400);
        assert!(store.renew(&renew, NOW).is_err());
    }

    #[test]
    fn revoke_erases_lease_and_queue() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [16; 16], 10, 1), NOW)
            .unwrap();
        let revoke = LeaseRevoke {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            operation_expiry: NOW + 30,
            nonce: [17; 16],
        }
        .encode(&capabilities.admin, &RELAY_ID)
        .unwrap();
        store.revoke(&revoke, NOW).unwrap();
        assert!(store.lease(&QUEUE_ID, NOW).is_none());
        assert_eq!(store.queue_count(NOW), 0);
    }

    #[test]
    fn ack_only_removes_matching_head() {
        let capabilities = caps(10);
        let mut store = store(4, 1024);
        create_lease(&mut store, capabilities, 4, 1024);
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [18; 16], 10, 1), NOW)
            .unwrap();
        store
            .authenticate_push(push_wire(&capabilities, EPOCH, [19; 16], 10, 2), NOW)
            .unwrap();
        assert_eq!(
            store.acknowledge(&QUEUE_ID, &[19; 16], NOW),
            AckOutcome::Mismatch
        );
        assert_eq!(store.queue_len(&QUEUE_ID, NOW), 2);
        assert_eq!(
            store.acknowledge(&QUEUE_ID, &[18; 16], NOW),
            AckOutcome::Removed
        );
        assert_eq!(store.peek(&QUEUE_ID, NOW).unwrap().push_nonce, [19; 16]);
    }

    #[test]
    fn grant_and_replay_sets_reject_new_at_their_bounds() {
        let mut bounded = config(4, 1024);
        bounded.max_grants = 1;
        bounded.max_replay_nonces_per_lease = 2;
        let mut store = LeaseStore::new(RELAY_ID, bounded).unwrap();
        let capabilities = caps(10);
        create_lease(&mut store, capabilities, 4, 1024);

        assert_eq!(
            store.issue_grant(
                GrantRequest {
                    queue_id: [2; 32],
                    epoch: EPOCH,
                    limits: LeaseLimits {
                        max_queue_cells: 4,
                        max_queue_bytes: 1024,
                    },
                },
                NOW,
            ),
            Err(StoreError::Capacity)
        );

        let first = RelaySub {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            subscription_expiry: NOW + 100,
            nonce: [20; 16],
        }
        .encode_into_cell(&capabilities.sub, &RELAY_ID)
        .unwrap();
        let second = RelaySub {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            subscription_expiry: NOW + 100,
            nonce: [21; 16],
        }
        .encode_into_cell(&capabilities.sub, &RELAY_ID)
        .unwrap();
        // Subscriptions draw on their own budget: two subscribe nonces do
        // not consume the push replay set and a push still lands.
        assert!(store.authenticate_sub(&first, NOW).is_ok());
        assert!(store.authenticate_sub(&second, NOW).is_ok());
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [40; 16], 10, 1), NOW),
            Ok(PushOutcome::Enqueued)
        );
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [41; 16], 10, 1), NOW),
            Ok(PushOutcome::Enqueued)
        );
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [42; 16], 10, 1), NOW),
            Err(StoreError::ReplayCapacity)
        );
    }

    #[test]
    fn subscription_nonces_cannot_brick_deposits() {
        let mut bounded = config(8, 1 << 20);
        bounded.max_subscription_nonces_per_lease = 2;
        let mut store = LeaseStore::new(RELAY_ID, bounded).unwrap();
        let capabilities = caps(10);
        create_lease(&mut store, capabilities, 8, 1 << 20);
        for nonce in 20u8..22 {
            let sub = RelaySub {
                queue_id: QUEUE_ID,
                epoch: EPOCH,
                subscription_expiry: NOW + 100,
                nonce: [nonce; 16],
            }
            .encode_into_cell(&capabilities.sub, &RELAY_ID)
            .unwrap();
            assert!(store.authenticate_sub(&sub, NOW).is_ok());
        }
        let third = RelaySub {
            queue_id: QUEUE_ID,
            epoch: EPOCH,
            subscription_expiry: NOW + 100,
            nonce: [22; 16],
        }
        .encode_into_cell(&capabilities.sub, &RELAY_ID)
        .unwrap();
        assert_eq!(
            store.authenticate_sub(&third, NOW),
            Err(StoreError::ReplayCapacity)
        );
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [50; 16], 10, 1), NOW),
            Ok(PushOutcome::Enqueued)
        );
    }

    #[test]
    fn global_queue_bytes_are_bounded_across_leases() {
        let mut bounded = config(64, 1 << 20);
        bounded.max_total_queue_bytes = 3 * 128;
        let mut store = LeaseStore::new(RELAY_ID, bounded).unwrap();
        let capabilities = caps(10);
        create_lease(&mut store, capabilities, 64, 1 << 20);
        let mut accepted = 0;
        for nonce in 60u8..70 {
            match store.authenticate_push(push_wire(&capabilities, EPOCH, [nonce; 16], 100, 1), NOW)
            {
                Ok(PushOutcome::Enqueued) => accepted += 1,
                Err(StoreError::Capacity) => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!((1..10).contains(&accepted), "accepted {accepted}");
        assert!(store.total_queue_bytes() <= 3 * 128);
        // Dequeue frees global capacity.
        let head = store.peek(&QUEUE_ID, NOW).unwrap().push_nonce;
        assert_eq!(
            store.acknowledge(&QUEUE_ID, &head, NOW),
            AckOutcome::Removed
        );
        assert_eq!(
            store.authenticate_push(push_wire(&capabilities, EPOCH, [99; 16], 100, 1), NOW),
            Ok(PushOutcome::Enqueued)
        );
    }

    #[test]
    fn dynamic_grants_require_admin_auth_reject_replay_and_rate_limit() {
        let capabilities = caps(10);
        let mut bounded = config(4, 1024);
        bounded.dynamic_grants_per_minute = 2;
        let mut store = LeaseStore::new(RELAY_ID, bounded).unwrap();
        create_lease(&mut store, capabilities, 4, 1024);
        let request = |queue_byte, nonce_byte| DynamicGrantRequest {
            authority_queue_id: QUEUE_ID,
            authority_epoch: EPOCH,
            queue_id: [queue_byte; 32],
            epoch: u64::from(queue_byte),
            limits: LeaseLimits {
                max_queue_cells: 4,
                max_queue_bytes: 1024,
            },
            nonce: [nonce_byte; 16],
            expiry: NOW + 60,
        };

        let unauthorized = request(40, 1).encode(&caps(50).admin, &RELAY_ID).unwrap();
        assert!(matches!(
            store.issue_dynamic_grant(&unauthorized, NOW),
            Err(StoreError::Lease(LeaseCodecError::InvalidMac))
        ));

        let first = request(40, 1)
            .encode(&capabilities.admin, &RELAY_ID)
            .unwrap();
        assert_eq!(
            store
                .issue_dynamic_grant(&first, NOW)
                .unwrap()
                .grant
                .queue_id,
            [40; 32]
        );
        assert_eq!(
            store.issue_dynamic_grant(&first, NOW),
            Err(StoreError::Replay)
        );
        let second = request(41, 2)
            .encode(&capabilities.admin, &RELAY_ID)
            .unwrap();
        assert!(store.issue_dynamic_grant(&second, NOW).is_ok());
        let limited = request(42, 3)
            .encode(&capabilities.admin, &RELAY_ID)
            .unwrap();
        assert_eq!(
            store.issue_dynamic_grant(&limited, NOW),
            Err(StoreError::Capacity)
        );
    }

    #[test]
    fn dynamic_grant_request_codec_is_fixed_and_domain_authenticated() {
        let capabilities = caps(10);
        let request = DynamicGrantRequest {
            authority_queue_id: QUEUE_ID,
            authority_epoch: EPOCH,
            queue_id: [44; 32],
            epoch: 12,
            limits: LeaseLimits {
                max_queue_cells: 4,
                max_queue_bytes: 1024,
            },
            nonce: [5; 16],
            expiry: NOW + 60,
        };
        let wire = request.encode(&capabilities.admin, &RELAY_ID).unwrap();
        let policy = ValidationPolicy::new(NOW, 0, NOW + 60).unwrap();
        assert_eq!(
            DynamicGrantRequest::decode_and_verify(
                &wire,
                &capabilities.admin,
                &RELAY_ID,
                &QUEUE_ID,
                EPOCH,
                policy,
            )
            .unwrap(),
            request
        );
        assert!(DynamicGrantRequest::decode_and_verify(
            &wire[..wire.len() - 1],
            &capabilities.admin,
            &RELAY_ID,
            &QUEUE_ID,
            EPOCH,
            policy,
        )
        .is_err());
        let mut tampered = wire;
        tampered[74] ^= 1;
        assert!(DynamicGrantRequest::decode_and_verify(
            &tampered,
            &capabilities.admin,
            &RELAY_ID,
            &QUEUE_ID,
            EPOCH,
            policy,
        )
        .is_err());
    }
}
