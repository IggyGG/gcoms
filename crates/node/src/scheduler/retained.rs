//! A durable outbox shares admission with live endpoint and transit requests.
//! Stage growth before a checkpoint; a failed checkpoint releases only that
//! growth. Shrinkage becomes available only after the checkpoint succeeds.
use super::*;
use crate::scheduler::EnqueueError;
use std::sync::{MutexGuard, TryLockError};

// With two production cover allowances these leave at least 2 MiB / 1920
// dispatch slots. Ordinary producers also leave 1 MiB / 512 retained slots for
// receiving, transport credit and application acknowledgements.
const RETAINED_LIMIT: PayloadUsage = PayloadUsage {
    items: 2048,
    bytes: 4 * 1024 * 1024,
};
const APPLICATION_LIMIT: PayloadUsage = PayloadUsage {
    items: 1536,
    bytes: 3 * 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PayloadUsage {
    pub items: usize,
    pub bytes: usize,
}

impl PayloadUsage {
    pub(crate) fn add(&mut self, other: Self) {
        self.items = self.items.saturating_add(other.items);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }

    fn growth(self, old: Self) -> Self {
        Self {
            items: self.items.saturating_sub(old.items),
            bytes: self.bytes.saturating_sub(old.bytes),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RetainedPriority {
    Application,
    Control,
}

pub(crate) struct RetainedAccount {
    owner: Budget,
    usage: Mutex<PayloadUsage>,
}

pub(crate) struct RetainedUpdate<'a> {
    owner: &'a Budget,
    current: MutexGuard<'a, PayloadUsage>,
    next: PayloadUsage,
    growth: PayloadUsage,
    committed: bool,
}

impl Budget {
    pub(crate) fn retained_account(&self) -> RetainedAccount {
        RetainedAccount {
            owner: self.clone(),
            usage: Mutex::new(PayloadUsage::default()),
        }
    }

    fn release_retained(&self, usage: PayloadUsage) {
        let mut state = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        state.retained.items -= usage.items;
        state.retained.bytes -= usage.bytes;
        state.resources.jobs -= usage.items;
        state.resources.bytes -= usage.bytes;
        state.local[self.scope].jobs -= usage.items;
        state.local[self.scope].bytes -= usage.bytes;
    }
}

impl RetainedAccount {
    pub(crate) fn stage(
        &self,
        next: PayloadUsage,
        priority: RetainedPriority,
    ) -> Result<RetainedUpdate<'_>, EnqueueError> {
        // A second candidate cannot commit using a stale account revision.
        let current = match self.usage.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(EnqueueError::Pending),
        };
        let growth = next.growth(*current);
        let mut state = self.owner.shared.lock().unwrap_or_else(|p| p.into_inner());
        let limit = match priority {
            RetainedPriority::Application => APPLICATION_LIMIT,
            RetainedPriority::Control => RETAINED_LIMIT,
        };
        let covers = state.covers.iter().sum::<usize>();
        let cover_limit = state.cover_limits.iter().sum::<usize>();
        let data_jobs = state.resources.jobs - covers;
        let data_bytes = state.resources.bytes - covers * COVER_BYTES;
        if growth.items > limit.items.saturating_sub(state.retained.items)
            || growth.bytes > limit.bytes.saturating_sub(state.retained.bytes)
            || growth.items > (MAX_JOBS - cover_limit).saturating_sub(data_jobs)
            || growth.bytes > (MAX_BYTES - cover_limit * COVER_BYTES).saturating_sub(data_bytes)
        {
            return Err(EnqueueError::Full);
        }
        state.retained.add(growth);
        state.resources.add_many(growth.items, growth.bytes);
        state.local[self.owner.scope].add_many(growth.items, growth.bytes);
        Ok(RetainedUpdate {
            owner: &self.owner,
            current,
            next,
            growth,
            committed: false,
        })
    }
}

impl RetainedUpdate<'_> {
    pub(crate) fn commit(mut self) {
        self.owner.release_retained(self.current.growth(self.next));
        *self.current = self.next;
        self.committed = true;
    }
}

impl Drop for RetainedUpdate<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.owner.release_retained(self.growth);
        }
    }
}

impl Drop for RetainedAccount {
    fn drop(&mut self) {
        let usage = *self.usage.get_mut().unwrap_or_else(|p| p.into_inner());
        self.owner.release_retained(usage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_outbox_competes_with_transit_and_rolls_back_on_cancel() {
        let (endpoint, transit) = Budget::pair(crate::scheduler::MAX_LANES);
        let account = endpoint.retained_account();
        let staged = account
            .stage(APPLICATION_LIMIT, RetainedPriority::Application)
            .unwrap();
        assert!(matches!(
            account.stage(PayloadUsage::default(), RetainedPriority::Control),
            Err(EnqueueError::Pending)
        ));
        let remaining = 3 * 1024 * 1024;
        let running = transit.reserve(remaining, Some([7; 32])).unwrap();
        assert!(matches!(transit.reserve(1, None), Err(EnqueueError::Full)));
        let covers: Vec<_> = (0..crate::scheduler::MAX_LANES)
            .flat_map(|_| {
                [
                    endpoint.reserve_cover().unwrap(),
                    transit.reserve_cover().unwrap(),
                ]
            })
            .collect();
        assert_eq!(endpoint.combined_snapshot().bytes, MAX_BYTES);
        drop(staged);
        assert_eq!(
            endpoint.combined_snapshot().bytes,
            MAX_BYTES - APPLICATION_LIMIT.bytes
        );
        drop((running, covers, account));
        assert_eq!(endpoint.combined_snapshot().bytes, 0);
        assert_eq!(endpoint.combined_snapshot().jobs, 0);
    }

    #[test]
    fn ordinary_outbox_leaves_credit_and_dispatch_headroom() {
        let (endpoint, transit) = Budget::pair(crate::scheduler::MAX_LANES);
        let account = endpoint.retained_account();
        account
            .stage(APPLICATION_LIMIT, RetainedPriority::Application)
            .unwrap()
            .commit();
        assert!(matches!(
            account.stage(RETAINED_LIMIT, RetainedPriority::Application),
            Err(EnqueueError::Full)
        ));
        account
            .stage(RETAINED_LIMIT, RetainedPriority::Control)
            .unwrap()
            .commit();
        let dispatch = transit.reserve(2 * 1024 * 1024, None).unwrap();
        assert!(matches!(transit.reserve(1, None), Err(EnqueueError::Full)));
        let shrinking = account
            .stage(PayloadUsage::default(), RetainedPriority::Control)
            .unwrap();
        assert_eq!(endpoint.snapshot().bytes, RETAINED_LIMIT.bytes);
        drop(shrinking);
        assert_eq!(endpoint.snapshot().bytes, RETAINED_LIMIT.bytes);
        account
            .stage(PayloadUsage::default(), RetainedPriority::Application)
            .unwrap()
            .commit();
        assert_eq!(endpoint.snapshot().bytes, 0);
        assert_eq!(transit.snapshot().bytes, 2 * 1024 * 1024);
        drop((account, dispatch));
        assert_eq!(endpoint.combined_snapshot().bytes, 0);
    }

    #[test]
    fn retained_caps_are_shared_and_account_drop_releases_committed_work() {
        let (endpoint, transit) = Budget::pair(crate::scheduler::MAX_LANES);
        let first = endpoint.retained_account();
        let second = transit.retained_account();
        first
            .stage(RETAINED_LIMIT, RetainedPriority::Control)
            .unwrap()
            .commit();
        assert!(matches!(
            second.stage(
                PayloadUsage { items: 1, bytes: 0 },
                RetainedPriority::Control
            ),
            Err(EnqueueError::Full)
        ));
        drop(first);
        second
            .stage(RETAINED_LIMIT, RetainedPriority::Control)
            .unwrap()
            .commit();
        drop(second);
        assert_eq!(endpoint.combined_snapshot().jobs, 0);
        assert_eq!(endpoint.combined_snapshot().bytes, 0);
    }
}
