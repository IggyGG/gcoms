//! Bounded, process-local persistence diagnostics. No identities or payloads.
use super::ClientEvent;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Clone, Debug, Default, Serialize)]
pub struct PersistenceCalls {
    pub requested: u64,
    pub completed: u64,
    pub failed: u64,
    pub total_us: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistenceDiagnostics {
    pub profile: crate::store::StoreSaveDiagnostics,
    pub calls: BTreeMap<&'static str, PersistenceCalls>,
    pub events: BTreeMap<&'static str, u64>,
    pub publication_attempts: u64,
}

#[derive(Clone, Copy)]
pub(super) enum SaveCause {
    Explicit,
    Event,
    Periodic,
    Shutdown,
}

const CAUSES: [&str; 4] = ["explicit", "event", "periodic", "shutdown"];
const EVENTS: [&str; 14] = [
    "identity",
    "session",
    "direct_message",
    "direct_delivered",
    "presence",
    "channel_presence",
    "channel_message",
    "channel_delivered",
    "channel_removed",
    "channel_roster",
    "channel_direct_message",
    "channel_direct_delivered",
    "lagged",
    "volatile_application",
];

#[derive(Default)]
struct CallCounters {
    requested: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    total_us: AtomicU64,
}

#[derive(Default)]
pub(super) struct PersistenceCounters {
    calls: [CallCounters; 4],
    events: [AtomicU64; 14],
    publication_attempts: AtomicU64,
}

impl PersistenceCounters {
    pub(super) fn published(&self) {
        self.publication_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn begin(&self, cause: SaveCause) {
        self.calls[cause as usize]
            .requested
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn finish(&self, cause: SaveCause, start: Instant, ok: bool) {
        let calls = &self.calls[cause as usize];
        if ok { &calls.completed } else { &calls.failed }.fetch_add(1, Ordering::Relaxed);
        calls.total_us.fetch_add(
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub(super) fn event(&self, event: &ClientEvent) {
        let index = match event {
            ClientEvent::IdentityUpdated { .. } => 0,
            ClientEvent::SessionOpened { .. } => 1,
            ClientEvent::DirectMessage { .. } => 2,
            ClientEvent::DirectDelivered { .. } => 3,
            ClientEvent::PresenceChanged { .. } => 4,
            ClientEvent::ChannelPresenceChanged { .. } => 5,
            ClientEvent::ChannelMessage { .. } => 6,
            ClientEvent::ChannelDelivered { .. } => 7,
            ClientEvent::ChannelRemoved { .. } => 8,
            ClientEvent::ChannelRosterChanged { .. } => 9,
            ClientEvent::ChannelDirectMessage { .. } => 10,
            ClientEvent::ChannelDirectDelivered { .. } => 11,
            ClientEvent::EventsLagged { .. } => 12,
            ClientEvent::VolatileApplication { .. } => 13,
        };
        self.events[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(
        &self,
        profile: crate::store::StoreSaveDiagnostics,
    ) -> PersistenceDiagnostics {
        PersistenceDiagnostics {
            profile,
            publication_attempts: self.publication_attempts.load(Ordering::Relaxed),
            calls: CAUSES
                .into_iter()
                .zip(self.calls.iter().map(|calls| PersistenceCalls {
                    requested: calls.requested.load(Ordering::Relaxed),
                    completed: calls.completed.load(Ordering::Relaxed),
                    failed: calls.failed.load(Ordering::Relaxed),
                    total_us: calls.total_us.load(Ordering::Relaxed),
                }))
                .collect(),
            events: EVENTS
                .into_iter()
                .zip(
                    self.events
                        .iter()
                        .map(|count| count.load(Ordering::Relaxed)),
                )
                .collect(),
        }
    }
}
