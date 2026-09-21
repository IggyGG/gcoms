//! Experimental natural-cell queues. Authentication fixes the traffic class for
//! the lifetime of a subscription. Both classes and GC/1 share lease byte, cell
//! and replay limits; this module does not select a carrier or privacy profile.
use super::{
    require_binding, AckOutcome, LeaseRecord, LeaseStore, Nonce, PushOutcome, QueueId,
    ReplayOperation, StoreError,
};
use gcoms_core::{gc2::NaturalCell, TrafficClass};
use gcoms_protocol::relay::gc2::{Subscription, UnverifiedPush};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedMessage {
    pub push_nonce: Nonce,
    pub cell: NaturalCell,
}

struct ClassQueue {
    messages: VecDeque<QueuedMessage>,
    changed: watch::Sender<()>,
}

pub(super) struct ClassQueues {
    queues: [ClassQueue; 2],
    // Distinguishes a recreated queue even if its ID and epoch are reused.
    generation: Arc<()>,
}

impl ClassQueues {
    pub(super) fn new() -> Self {
        Self {
            queues: std::array::from_fn(|_| ClassQueue {
                messages: VecDeque::new(),
                changed: watch::channel(()).0,
            }),
            generation: Arc::new(()),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.queues.iter().map(|queue| queue.messages.len()).sum()
    }

    pub(super) fn wake_all(&self) {
        for queue in &self.queues {
            queue.changed.send_replace(());
        }
    }

    fn class(&self, class: TrafficClass) -> &ClassQueue {
        &self.queues[class as usize]
    }

    fn class_mut(&mut self, class: TrafficClass) -> &mut ClassQueue {
        &mut self.queues[class as usize]
    }
}

/// Created only by authenticated admission. Its private queue incarnation,
/// epoch, expiry and class are rechecked before every peek and acknowledgment.
/// Dropping this value drops only its notification receiver, not queued data.
pub struct AuthenticatedSubscription {
    subscription: Subscription,
    generation: Arc<()>,
    changed: watch::Receiver<()>,
}

impl AuthenticatedSubscription {
    pub fn class(&self) -> TrafficClass {
        self.subscription.class
    }

    pub fn expiry(&self) -> u64 {
        self.subscription.expiry
    }

    /// Waits without polling. Changes between the preceding peek and this call
    /// remain observable. Multiple changes may coalesce; always recheck the queue.
    /// The stream owner must also select on its absolute expiry and shutdown.
    /// Closure means that the queue or its store was removed.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.changed.changed().await
    }
}

impl LeaseRecord {
    fn record_gc2_push(
        &mut self,
        epoch: u64,
        nonce: Nonce,
        expiry: u64,
        binding: [u8; 32],
        max_replay: usize,
    ) -> Result<(), StoreError> {
        self.record_replay(epoch, ReplayOperation::Push, nonce, expiry, max_replay)?;
        self.replay
            .back_mut()
            .expect("record just appended")
            .gc2_push_binding = Some(binding);
        Ok(())
    }
}

impl LeaseStore {
    /// Authenticates exact GC/2 retry bytes, including class. A nonce previously
    /// accepted with different bytes or wire version is a conflict, not success.
    pub fn authenticate_push_gc2(
        &mut self,
        push: UnverifiedPush,
        now_unix: u64,
    ) -> Result<PushOutcome, StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id = push.queue_id();
        let lease = self
            .leases
            .get_mut(&queue_id)
            .ok_or(StoreError::Unauthorized)?;
        let binding: [u8; 32] = Sha256::digest(push.as_cell().encode()).into();
        let push = push.authenticate(&lease.capabilities.push, &self.relay_service_id, now_unix)?;
        require_binding(lease, push.queue_id, push.epoch)?;
        if push.expiry > lease.expiry {
            return Err(StoreError::Unauthorized);
        }
        if let Some(record) = lease.replay.iter().find(|record| {
            record.epoch == push.epoch
                && record.operation == ReplayOperation::Push
                && record.nonce == push.nonce
        }) {
            return if record.gc2_push_binding == Some(binding) {
                Ok(PushOutcome::Duplicate)
            } else {
                Err(StoreError::Replay)
            };
        }
        let max_replay = self.config.max_replay_nonces_per_lease;
        let Some(msg) = push.msg else {
            lease.record_gc2_push(push.epoch, push.nonce, push.expiry, binding, max_replay)?;
            return Ok(PushOutcome::Cover);
        };
        let bytes = msg.encoded_len() as u64;
        let total_after = self
            .queues
            .total_bytes
            .checked_add(bytes)
            .ok_or(StoreError::Capacity)?;
        if total_after > self.config.max_total_queue_bytes {
            return Err(StoreError::Capacity);
        }
        let queue = self
            .queues
            .queues
            .get_mut(&queue_id)
            .expect("every lease owns a queue");
        let next_bytes = queue
            .bytes
            .checked_add(bytes)
            .ok_or(StoreError::QueueFull)?;
        if queue.len() >= usize::from(lease.limits.max_queue_cells)
            || next_bytes > lease.limits.max_queue_bytes
        {
            return Err(StoreError::QueueFull);
        }
        // Reserve replay space before mutating either queue accounting or data.
        lease.record_gc2_push(push.epoch, push.nonce, push.expiry, binding, max_replay)?;
        queue.bytes = next_bytes;
        self.queues.total_bytes = total_after;
        let class = queue.classes.class_mut(push.class);
        class.messages.push_back(QueuedMessage {
            push_nonce: push.nonce,
            cell: msg,
        });
        class.changed.send_replace(());
        #[cfg(feature = "push-notifications")]
        if push.class == TrafficClass::Interactive {
            self.notify_admission(&queue_id, now_unix);
        }
        Ok(PushOutcome::Enqueued)
    }

    /// The subscription capability authenticates the selected class. The live
    /// subscription nonce budget is shared with GC/1 and the other class.
    pub fn authenticate_sub_gc2(
        &mut self,
        cell: &NaturalCell,
        now_unix: u64,
    ) -> Result<AuthenticatedSubscription, StoreError> {
        self.cleanup_expired(now_unix);
        let queue_id: QueueId = cell
            .payload()
            .get(1..33)
            .ok_or(StoreError::Unauthorized)?
            .try_into()
            .map_err(|_| StoreError::Unauthorized)?;
        let lease = self
            .leases
            .get_mut(&queue_id)
            .ok_or(StoreError::Unauthorized)?;
        let subscription = Subscription::decode(
            cell,
            &lease.capabilities.sub,
            &self.relay_service_id,
            now_unix,
        )?;
        require_binding(lease, subscription.queue_id, subscription.epoch)?;
        if subscription.expiry > lease.expiry {
            return Err(StoreError::Unauthorized);
        }
        if lease.has_replay(
            subscription.epoch,
            ReplayOperation::Subscribe,
            &subscription.nonce,
        ) {
            return Err(StoreError::Replay);
        }
        lease.record_replay(
            subscription.epoch,
            ReplayOperation::Subscribe,
            subscription.nonce,
            subscription.expiry,
            self.config.max_subscription_nonces_per_lease,
        )?;
        let classes = &self
            .queues
            .queues
            .get(&queue_id)
            .expect("every lease owns a queue")
            .classes;
        Ok(AuthenticatedSubscription {
            changed: classes.class(subscription.class).changed.subscribe(),
            generation: classes.generation.clone(),
            subscription,
        })
    }

    fn validate_gc2_subscription(
        &self,
        handle: &AuthenticatedSubscription,
        now_unix: u64,
    ) -> Result<(), StoreError> {
        let sub = &handle.subscription;
        let lease = self
            .leases
            .get(&sub.queue_id)
            .ok_or(StoreError::Unauthorized)?;
        require_binding(lease, sub.queue_id, sub.epoch)?;
        if sub.expiry <= now_unix || sub.expiry > lease.expiry {
            return Err(StoreError::Unauthorized);
        }
        let classes = &self
            .queues
            .queues
            .get(&sub.queue_id)
            .expect("every lease owns a queue")
            .classes;
        if !Arc::ptr_eq(&handle.generation, &classes.generation) {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    pub fn peek_gc2(
        &mut self,
        handle: &AuthenticatedSubscription,
        now_unix: u64,
    ) -> Result<Option<&QueuedMessage>, StoreError> {
        self.cleanup_expired(now_unix);
        self.validate_gc2_subscription(handle, now_unix)?;
        let sub = &handle.subscription;
        Ok(self
            .queues
            .queues
            .get(&sub.queue_id)
            .expect("validated queue")
            .classes
            .class(sub.class)
            .messages
            .front())
    }

    /// Dequeues only this class's matching head. This is relay consumption, not
    /// evidence of recipient decryption, persistence or application completion.
    pub fn acknowledge_gc2(
        &mut self,
        handle: &AuthenticatedSubscription,
        push_nonce: &Nonce,
        now_unix: u64,
    ) -> Result<AckOutcome, StoreError> {
        self.cleanup_expired(now_unix);
        self.validate_gc2_subscription(handle, now_unix)?;
        let sub = &handle.subscription;
        let queue = self
            .queues
            .queues
            .get_mut(&sub.queue_id)
            .expect("validated queue");
        let class = queue.classes.class_mut(sub.class);
        let Some(head) = class.messages.front() else {
            return Ok(AckOutcome::Empty);
        };
        if head.push_nonce != *push_nonce {
            return Ok(AckOutcome::Mismatch);
        }
        let removed = class.messages.pop_front().expect("head checked above");
        let freed = removed.cell.encoded_len() as u64;
        queue.bytes -= freed;
        self.queues.total_bytes -= freed;
        class.changed.send_replace(());
        Ok(AckOutcome::Removed)
    }
}
