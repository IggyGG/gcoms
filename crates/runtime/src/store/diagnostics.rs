//! Process-local aggregate storage costs. Never records profile contents or paths.
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Clone, Debug, Default, Serialize)]
pub struct StoreSaveDiagnostics {
    pub attempts: u64,
    pub completed: u64,
    pub failed: u64,
    pub serialized_bytes: u64,
    pub write_attempted_bytes: u64,
    pub committed_bytes: u64,
    pub lock_wait_us: u64,
    pub serialize_us: u64,
    pub encrypt_us: u64,
    pub atomic_write_us: u64,
    pub total_us: u64,
    pub max_save_us: u64,
}

#[derive(Default)]
pub(super) struct SaveCounters {
    attempts: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    serialized_bytes: AtomicU64,
    write_attempted_bytes: AtomicU64,
    committed_bytes: AtomicU64,
    lock_wait_us: AtomicU64,
    serialize_us: AtomicU64,
    encrypt_us: AtomicU64,
    atomic_write_us: AtomicU64,
    total_us: AtomicU64,
    max_save_us: AtomicU64,
}

pub(crate) fn elapsed_us(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

impl SaveCounters {
    pub(super) fn begin(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn finish(&self, sample: &StoreSaveDiagnostics, start: Instant, ok: bool) {
        let total = elapsed_us(start);
        if ok { &self.completed } else { &self.failed }.fetch_add(1, Ordering::Relaxed);
        self.serialized_bytes
            .fetch_add(sample.serialized_bytes, Ordering::Relaxed);
        self.write_attempted_bytes
            .fetch_add(sample.write_attempted_bytes, Ordering::Relaxed);
        if ok {
            self.committed_bytes
                .fetch_add(sample.write_attempted_bytes, Ordering::Relaxed);
        }
        self.lock_wait_us
            .fetch_add(sample.lock_wait_us, Ordering::Relaxed);
        self.serialize_us
            .fetch_add(sample.serialize_us, Ordering::Relaxed);
        self.encrypt_us
            .fetch_add(sample.encrypt_us, Ordering::Relaxed);
        self.atomic_write_us
            .fetch_add(sample.atomic_write_us, Ordering::Relaxed);
        self.total_us.fetch_add(total, Ordering::Relaxed);
        self.max_save_us.fetch_max(total, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> StoreSaveDiagnostics {
        StoreSaveDiagnostics {
            attempts: self.attempts.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            serialized_bytes: self.serialized_bytes.load(Ordering::Relaxed),
            write_attempted_bytes: self.write_attempted_bytes.load(Ordering::Relaxed),
            committed_bytes: self.committed_bytes.load(Ordering::Relaxed),
            lock_wait_us: self.lock_wait_us.load(Ordering::Relaxed),
            serialize_us: self.serialize_us.load(Ordering::Relaxed),
            encrypt_us: self.encrypt_us.load(Ordering::Relaxed),
            atomic_write_us: self.atomic_write_us.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_save_us: self.max_save_us.load(Ordering::Relaxed),
        }
    }
}
