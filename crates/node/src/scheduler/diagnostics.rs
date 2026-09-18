//! Opt-in, bounded aggregate observations. No identifiers or per-job traces.
//! Snapshots are approximate during concurrent updates; take a quiescent snapshot
//! for accounting. Enabling these counters does not change the scheduling policy.
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub const LATENCY_BUCKET_UPPER_US: [u64; 8] = [
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    60_000_000,
    600_000_000,
    u64::MAX,
];

#[derive(Debug, Default, Serialize)]
pub struct LatencySnapshot {
    pub count: u64,
    pub total_us: u64,
    pub max_us: u64,
    /// Disjoint buckets, with inclusive upper bounds in LATENCY_BUCKET_UPPER_US.
    pub buckets: [u64; 8],
}

#[derive(Default)]
pub(super) struct Latency {
    count: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
    buckets: [AtomicU64; 8],
}

impl Latency {
    pub(super) fn observe(&self, duration: Duration) {
        let us = duration.as_micros().min(u64::MAX as u128) as u64;
        self.total_us.fetch_add(us, Relaxed);
        self.max_us.fetch_max(us, Relaxed);
        let bucket = LATENCY_BUCKET_UPPER_US
            .iter()
            .position(|upper| us <= *upper)
            .unwrap();
        self.buckets[bucket].fetch_add(1, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    fn snapshot(&self) -> LatencySnapshot {
        LatencySnapshot {
            count: self.count.load(Relaxed),
            total_us: self.total_us.load(Relaxed),
            max_us: self.max_us.load(Relaxed),
            buckets: std::array::from_fn(|i| self.buckets[i].load(Relaxed)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SchedulerSnapshot {
    pub enabled: bool,
    pub accepted: u64,
    pub rejected_full: u64,
    pub rejected_pending: u64,
    pub rejected_shutdown: u64,
    pub rejected_invalid: u64,
    pub dispatched: u64,
    pub failed: u64,
    pub queue_high_water: u64,
    pub data_ticks: u64,
    pub data_skipped_ticks: u64,
    pub cover_attempts: u64,
    pub queue_wait: LatencySnapshot,
    /// Encoding plus the complete transport request/response, including retries.
    pub service: LatencySnapshot,
    /// Connection warming before a newly created lane begins its slot loop.
    pub warm: LatencySnapshot,
}

#[derive(Default)]
pub(super) struct Diagnostics {
    enabled: AtomicBool,
    pub accepted: AtomicU64,
    pub rejected_full: AtomicU64,
    pub rejected_pending: AtomicU64,
    pub rejected_shutdown: AtomicU64,
    pub rejected_invalid: AtomicU64,
    pub dispatched: AtomicU64,
    pub failed: AtomicU64,
    pub queue_high_water: AtomicU64,
    pub data_ticks: AtomicU64,
    pub data_skipped_ticks: AtomicU64,
    pub cover_attempts: AtomicU64,
    pub queue_wait: Latency,
    pub service: Latency,
    pub warm: Latency,
}

impl Diagnostics {
    pub fn enable(&self) {
        self.enabled.store(true, Relaxed);
    }
    pub fn enabled(&self) -> bool {
        self.enabled.load(Relaxed)
    }
    pub fn start(&self) -> Option<Instant> {
        self.enabled().then(Instant::now)
    }
    pub fn increment(&self, counter: &AtomicU64) {
        if self.enabled() {
            counter.fetch_add(1, Relaxed);
        }
    }
    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            enabled: self.enabled(),
            accepted: self.accepted.load(Relaxed),
            rejected_full: self.rejected_full.load(Relaxed),
            rejected_pending: self.rejected_pending.load(Relaxed),
            rejected_shutdown: self.rejected_shutdown.load(Relaxed),
            rejected_invalid: self.rejected_invalid.load(Relaxed),
            dispatched: self.dispatched.load(Relaxed),
            failed: self.failed.load(Relaxed),
            queue_high_water: self.queue_high_water.load(Relaxed),
            data_ticks: self.data_ticks.load(Relaxed),
            data_skipped_ticks: self.data_skipped_ticks.load(Relaxed),
            cover_attempts: self.cover_attempts.load(Relaxed),
            queue_wait: self.queue_wait.snapshot(),
            service: self.service.snapshot(),
            warm: self.warm.snapshot(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_are_opt_in_and_histogram_bounds_are_inclusive() {
        let d = Diagnostics::default();
        d.increment(&d.accepted);
        assert!(d.start().is_none());
        assert_eq!(d.snapshot().accepted, 0);
        d.enable();
        d.increment(&d.accepted);
        for us in [0, 1_000, 1_001, 100_001, 600_000_001] {
            d.queue_wait.observe(Duration::from_micros(us));
        }
        let s = d.snapshot();
        assert_eq!(s.accepted, 1);
        assert_eq!(s.queue_wait.count, 5);
        assert_eq!(s.queue_wait.buckets, [2, 1, 0, 1, 0, 0, 0, 1]);
        assert_eq!(s.queue_wait.total_us, 600_102_003);
        assert_eq!(s.queue_wait.max_us, 600_000_001);
        assert_eq!(s.queue_wait.buckets.iter().sum::<u64>(), s.queue_wait.count);
    }
}
