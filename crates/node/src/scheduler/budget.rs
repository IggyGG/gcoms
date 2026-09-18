//! Admission covers both queued and running work. A reservation follows a job
//! until completion or cancellation; moving it out of a queue releases nothing.
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub const MAX_JOBS: usize = 4096;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
const COVER_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ResourceSnapshot {
    pub jobs: usize,
    pub bytes: usize,
    pub peak_jobs: usize,
    pub peak_bytes: usize,
}

#[derive(Default)]
struct State {
    resources: ResourceSnapshot,
    attempts: HashSet<(usize, [u8; 32])>,
    local: [ResourceSnapshot; 2],
    cover_limits: [usize; 2],
    covers: [usize; 2],
    #[cfg(feature = "experimental-gc2")]
    retained: PayloadUsage,
}

#[derive(Clone, Default)]
pub(super) struct Budget {
    shared: Arc<Mutex<State>>,
    scope: usize,
}

pub(crate) struct Reservation {
    owner: Budget,
    bytes: usize,
    attempt: Option<[u8; 32]>,
    cover: bool,
}

impl Budget {
    pub(super) fn with_cover_reserve(cover_limit: usize) -> Self {
        assert!(cover_limit <= super::MAX_LANES);
        Self {
            shared: Arc::new(Mutex::new(State {
                cover_limits: [cover_limit, 0],
                ..State::default()
            })),
            scope: 0,
        }
    }

    /// Endpoint and authorized-transit schedulers share the node allowance,
    /// while retaining separate diagnostics and independent attempt identities.
    pub(super) fn pair(cover_limit: usize) -> (Self, Self) {
        assert!(cover_limit <= super::MAX_LANES);
        let shared = Arc::new(Mutex::new(State {
            cover_limits: [cover_limit; 2],
            ..State::default()
        }));
        (
            Self {
                shared: shared.clone(),
                scope: 0,
            },
            Self { shared, scope: 1 },
        )
    }

    pub(super) fn reserve_cover(&self) -> Result<Reservation, super::EnqueueError> {
        self.reserve_inner(COVER_BYTES, None, true)
    }

    pub(super) fn reserve(
        &self,
        bytes: usize,
        attempt: Option<[u8; 32]>,
    ) -> Result<Reservation, super::EnqueueError> {
        self.reserve_inner(bytes, attempt, false)
    }

    fn reserve_inner(
        &self,
        bytes: usize,
        attempt: Option<[u8; 32]>,
        cover: bool,
    ) -> Result<Reservation, super::EnqueueError> {
        let mut state = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if attempt.is_some_and(|id| state.attempts.contains(&(self.scope, id))) {
            return Err(super::EnqueueError::Pending);
        }
        let covers = state.covers.iter().sum::<usize>();
        let cover_limit = state.cover_limits.iter().sum::<usize>();
        if cover {
            if state.covers[self.scope] >= state.cover_limits[self.scope] {
                return Err(super::EnqueueError::Full);
            }
        } else {
            // Payload admission never borrows the cover allowance, even while
            // idle. Returning cover credit therefore cannot change data capacity.
            let data_jobs = state.resources.jobs - covers;
            let data_bytes = state.resources.bytes - covers * COVER_BYTES;
            let data_limit = MAX_BYTES - cover_limit * COVER_BYTES;
            if data_jobs >= MAX_JOBS - cover_limit || bytes > data_limit.saturating_sub(data_bytes)
            {
                return Err(super::EnqueueError::Full);
            }
        }
        if state.resources.jobs >= MAX_JOBS
            || bytes > MAX_BYTES.saturating_sub(state.resources.bytes)
        {
            return Err(super::EnqueueError::Full);
        }
        state.covers[self.scope] += usize::from(cover);
        state.resources.add(bytes);
        state.local[self.scope].add(bytes);
        if let Some(id) = attempt {
            state.attempts.insert((self.scope, id));
        }
        Ok(Reservation {
            owner: self.clone(),
            bytes,
            attempt,
            cover,
        })
    }

    pub(super) fn snapshot(&self) -> ResourceSnapshot {
        self.shared.lock().unwrap_or_else(|p| p.into_inner()).local[self.scope]
    }

    pub(super) fn combined_snapshot(&self) -> ResourceSnapshot {
        self.shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .resources
    }
}

impl ResourceSnapshot {
    fn add(&mut self, bytes: usize) {
        self.add_many(1, bytes);
    }

    fn add_many(&mut self, jobs: usize, bytes: usize) {
        self.jobs += jobs;
        self.bytes += bytes;
        self.peak_jobs = self.peak_jobs.max(self.jobs);
        self.peak_bytes = self.peak_bytes.max(self.bytes);
    }

    fn release(&mut self, bytes: usize) {
        self.jobs -= 1;
        self.bytes -= bytes;
    }
}

#[cfg(feature = "experimental-gc2")]
#[path = "retained.rs"]
mod retained;
#[cfg(feature = "experimental-gc2")]
pub(crate) use retained::{PayloadUsage, RetainedAccount, RetainedPriority, RetainedUpdate};

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.owner.shared.lock().unwrap_or_else(|p| p.into_inner());
        state.covers[self.owner.scope] -= usize::from(self.cover);
        state.resources.release(self.bytes);
        state.local[self.owner.scope].release(self.bytes);
        if let Some(id) = self.attempt {
            state.attempts.remove(&(self.owner.scope, id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_and_transit_share_capacity_without_sharing_attempt_identity() {
        let (endpoint, transit) = Budget::pair(super::super::MAX_LANES);
        let data_limit = MAX_BYTES - 2 * super::super::MAX_LANES * COVER_BYTES;
        let first = endpoint.reserve(data_limit / 2, Some([1; 32])).unwrap();
        let second = transit.reserve(data_limit / 2, Some([1; 32])).unwrap();
        for budget in [&endpoint, &transit] {
            assert!(matches!(
                budget.reserve(1, None),
                Err(super::super::EnqueueError::Full)
            ));
            assert_eq!(budget.snapshot().bytes, data_limit / 2);
        }
        let mut covers = Vec::new();
        for _ in 0..super::super::MAX_LANES {
            covers.push(endpoint.reserve_cover().unwrap());
            covers.push(transit.reserve_cover().unwrap());
        }
        assert_eq!(endpoint.combined_snapshot().bytes, MAX_BYTES);
        assert_eq!(transit.combined_snapshot().bytes, MAX_BYTES);
        assert!(matches!(
            endpoint.reserve_cover(),
            Err(super::super::EnqueueError::Full)
        ));
        drop(first);
        let replacement = transit.reserve(data_limit / 2, None).unwrap();
        assert_eq!(transit.combined_snapshot().bytes, MAX_BYTES);
        drop((second, replacement, covers));
        assert_eq!(endpoint.snapshot().jobs, 0);
        assert_eq!(transit.snapshot().jobs, 0);
        assert_eq!(endpoint.combined_snapshot().bytes, 0);
    }

    #[test]
    fn running_work_holds_memory_and_attempt_identity_until_drop() {
        let budget = Budget::default();
        let running = budget.reserve(MAX_BYTES, Some([1; 32])).unwrap();
        assert!(matches!(
            budget.reserve(1, None),
            Err(super::super::EnqueueError::Full)
        ));
        assert!(matches!(
            budget.reserve(1, Some([1; 32])),
            Err(super::super::EnqueueError::Pending)
        ));
        assert_eq!(budget.snapshot().bytes, MAX_BYTES);
        drop(running);
        let retry = budget.reserve(1, Some([1; 32])).unwrap();
        assert_eq!(budget.snapshot().jobs, 1);
        drop(retry);
        assert_eq!(budget.snapshot().jobs, 0);
        assert_eq!(budget.snapshot().bytes, 0);
        assert_eq!(budget.snapshot().peak_bytes, MAX_BYTES);
    }

    #[test]
    fn job_count_is_bounded_even_for_empty_work() {
        let budget = Budget::default();
        let jobs: Vec<_> = (0..MAX_JOBS)
            .map(|_| budget.reserve(0, None).unwrap())
            .collect();
        assert!(matches!(
            budget.reserve(0, None),
            Err(super::super::EnqueueError::Full)
        ));
        drop(jobs);
        assert_eq!(budget.snapshot().jobs, 0);
    }
    #[test]
    fn saturated_data_cannot_consume_cover_credit() {
        let budget = Budget::with_cover_reserve(super::super::MAX_LANES);
        let data_limit = MAX_BYTES - super::super::MAX_LANES * COVER_BYTES;
        let data = budget.reserve(data_limit, None).unwrap();
        let mut covers = Vec::new();
        for _ in 0..super::super::MAX_LANES {
            covers.push(budget.reserve_cover().unwrap());
        }
        assert_eq!(budget.snapshot().bytes, MAX_BYTES);
        assert!(matches!(
            budget.reserve(1, None),
            Err(super::super::EnqueueError::Full)
        ));
        assert!(matches!(
            budget.reserve_cover(),
            Err(super::super::EnqueueError::Full)
        ));
        drop(covers.pop());
        assert!(matches!(
            budget.reserve(1, None),
            Err(super::super::EnqueueError::Full)
        ));
        covers.push(budget.reserve_cover().unwrap());
        drop(data);
        let next = budget.reserve(data_limit, None).unwrap();
        assert_eq!(budget.snapshot().bytes, MAX_BYTES);
        drop((next, covers));
        assert_eq!(budget.snapshot().jobs, 0);
        assert_eq!(budget.snapshot().bytes, 0);
    }

    #[test]
    fn saturated_job_count_leaves_one_cover_per_lane() {
        let budget = Budget::with_cover_reserve(super::super::MAX_LANES);
        let data: Vec<_> = (0..MAX_JOBS - super::super::MAX_LANES)
            .map(|_| budget.reserve(0, None).unwrap())
            .collect();
        assert!(matches!(
            budget.reserve(0, None),
            Err(super::super::EnqueueError::Full)
        ));
        let covers: Vec<_> = (0..super::super::MAX_LANES)
            .map(|_| budget.reserve_cover().unwrap())
            .collect();
        assert_eq!(budget.snapshot().jobs, MAX_JOBS);
        drop((data, covers));
        assert_eq!(budget.snapshot().jobs, 0);
    }
}
