//! Bounded forwarding admission. Both class budgets are checked atomically;
//! a bulk waiter never occupies an interactive slot while waiting for credit.
use gcoms_core::TrafficClass;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

pub(super) const WAIT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub limit: usize,
    pub bulk_limit: usize,
    pub active: usize,
    pub bulk_active: usize,
    pub waiting: usize,
    pub all_slots_busy: u64,
    pub bulk_slots_busy: u64,
    pub waiters_full: u64,
    pub transit_not_ready: u64,
    pub scheduler_full: u64,
    pub scheduler_pending: u64,
    pub scheduler_shutdown: u64,
    pub last_hop_failed: u64,
}

pub(super) struct Pool {
    state: Mutex<Snapshot>,
    waiters: Semaphore,
    changed: Notify,
    last_log: Mutex<Option<std::time::Instant>>,
}

pub(super) struct Permit {
    pool: Arc<Pool>,
    bulk: bool,
}

impl Pool {
    pub fn new(limit: usize) -> Arc<Self> {
        assert!(limit > 0);
        Arc::new(Self {
            state: Mutex::new(Snapshot {
                limit,
                bulk_limit: limit - 1,
                ..Snapshot::default()
            }),
            waiters: Semaphore::new(limit),
            changed: Notify::new(),
            last_log: Mutex::new(None),
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Snapshot {
            waiting: state.limit - self.waiters.available_permits(),
            ..state.clone()
        }
    }

    fn take(self: &Arc<Self>, bulk: bool) -> Option<Permit> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.active >= state.limit || (bulk && state.bulk_active >= state.bulk_limit) {
            return None;
        }
        state.active += 1;
        state.bulk_active += usize::from(bulk);
        Some(Permit {
            pool: self.clone(),
            bulk,
        })
    }

    pub async fn acquire(self: &Arc<Self>, class: TrafficClass) -> Result<Permit, &'static str> {
        let bulk = class == TrafficClass::Bulk;
        if let Some(permit) = self.take(bulk) {
            return Ok(permit);
        }
        let _waiting = self.waiters.try_acquire().map_err(|_| "waiters_full")?;
        let wait = async {
            loop {
                // Register before testing capacity so a drop cannot be missed.
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if let Some(permit) = self.take(bulk) {
                    return permit;
                }
                changed.await;
            }
        };
        tokio::time::timeout(WAIT, wait).await.map_err(|_| {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if bulk && state.bulk_active >= state.bulk_limit {
                "bulk_slots_busy"
            } else {
                "all_slots_busy"
            }
        })
    }

    pub fn refused(&self, stage: &'static str, reason: &'static str) {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match (stage, reason) {
                (_, "all_slots_busy") => state.all_slots_busy += 1,
                (_, "bulk_slots_busy") => state.bulk_slots_busy += 1,
                (_, "waiters_full") => state.waiters_full += 1,
                (_, "transit_not_ready") => state.transit_not_ready += 1,
                ("scheduler", "full") => state.scheduler_full += 1,
                ("scheduler", "pending") => state.scheduler_pending += 1,
                ("scheduler", "shutdown") => state.scheduler_shutdown += 1,
                ("last_hop", _) => state.last_hop_failed += 1,
                _ => {}
            }
        }
        crate::metrics::log_event(
            "gc2_forward_refused",
            &[("stage", stage.into()), ("reason", reason.into())],
        );
        let mut last = self.last_log.lock().unwrap_or_else(|p| p.into_inner());
        if last.is_none_or(|at| at.elapsed() >= Duration::from_secs(10)) {
            eprintln!("gc2_forward_refused stage={stage} reason={reason}");
            *last = Some(std::time::Instant::now());
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap_or_else(|p| p.into_inner());
        state.active -= 1;
        state.bulk_active -= usize::from(self.bulk);
        drop(state);
        self.pool.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn configured_capacity_reserves_interactive_credit_and_times_out() {
        let pool = Pool::new(128);
        let mut bulk = Vec::new();
        for _ in 0..127 {
            bulk.push(pool.acquire(TrafficClass::Bulk).await.unwrap());
        }
        let interactive = pool.acquire(TrafficClass::Interactive).await.unwrap();
        assert_eq!(pool.snapshot().active, 128);
        assert_eq!(
            pool.acquire(TrafficClass::Bulk).await.err(),
            Some("bulk_slots_busy")
        );
        drop((bulk, interactive));
        assert_eq!(pool.snapshot().active, 0);
        assert_eq!(pool.snapshot().waiting, 0);
    }

    #[tokio::test]
    async fn waiting_bulk_does_not_hold_interactive_credit_and_cancellation_releases_waiter() {
        let pool = Pool::new(2);
        let bulk = pool.acquire(TrafficClass::Bulk).await.unwrap();
        let task_pool = pool.clone();
        let waiter = tokio::spawn(async move { task_pool.acquire(TrafficClass::Bulk).await });
        tokio::task::yield_now().await;
        let interactive = pool.acquire(TrafficClass::Interactive).await.unwrap();
        assert_eq!(pool.snapshot().waiting, 1);
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(pool.snapshot().waiting, 0);
        drop((bulk, interactive));
        assert_eq!(pool.snapshot().active, 0);
    }
}
