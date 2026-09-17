//! Admission covers both queued and running work. A reservation follows a job
//! until completion or cancellation; moving it out of a queue releases nothing.
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub const MAX_JOBS: usize = 4096;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;

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
    attempts: HashSet<[u8; 32]>,
}

#[derive(Clone, Default)]
pub(super) struct Budget(Arc<Mutex<State>>);

pub(super) struct Reservation {
    owner: Budget,
    bytes: usize,
    attempt: Option<[u8; 32]>,
}

impl Budget {
    pub(super) fn reserve(
        &self,
        bytes: usize,
        attempt: Option<[u8; 32]>,
    ) -> Result<Reservation, super::EnqueueError> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if attempt.is_some_and(|id| state.attempts.contains(&id)) {
            return Err(super::EnqueueError::Pending);
        }
        if state.resources.jobs >= MAX_JOBS
            || bytes > MAX_BYTES.saturating_sub(state.resources.bytes)
        {
            return Err(super::EnqueueError::Full);
        }
        state.resources.jobs += 1;
        state.resources.bytes += bytes;
        state.resources.peak_jobs = state.resources.peak_jobs.max(state.resources.jobs);
        state.resources.peak_bytes = state.resources.peak_bytes.max(state.resources.bytes);
        if let Some(id) = attempt {
            state.attempts.insert(id);
        }
        Ok(Reservation {
            owner: self.clone(),
            bytes,
            attempt,
        })
    }

    pub(super) fn snapshot(&self) -> ResourceSnapshot {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).resources
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.owner.0.lock().unwrap_or_else(|p| p.into_inner());
        state.resources.jobs -= 1;
        state.resources.bytes -= self.bytes;
        if let Some(id) = self.attempt {
            state.attempts.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
