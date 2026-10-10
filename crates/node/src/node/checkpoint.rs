//! Process-local checkpoint revisions. Ciphertext, snapshot timestamps and retry
//! clocks are deliberately not change detectors. NodeState's outer mutex owns
//! every mutation and the complete synchronous persistence transaction.
use std::sync::Mutex;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct CheckpointDiagnostics {
    pub revision: u64,
    pub durable_revision: u64,
    pub forced: u64,
    pub flushes: u64,
    pub skipped: u64,
    pub failed: u64,
    pub writes: u64,
    pub encoded_bytes: u64,
}

pub(super) struct CheckpointState(Mutex<CheckpointDiagnostics>);

impl Default for CheckpointState {
    fn default() -> Self {
        Self(Mutex::new(CheckpointDiagnostics {
            revision: 1,
            ..Default::default()
        }))
    }
}

impl CheckpointState {
    /// Only logical mutations not already covered by a synchronous barrier
    /// need this mark. Retry attempts and derived readiness are not mutations.
    pub(super) fn changed(&self) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.revision = state
            .revision
            .checked_add(1)
            .expect("checkpoint revision exhausted");
    }

    pub(super) fn begin(&self, force: bool) -> Option<u64> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if force {
            state.forced += 1;
            state.revision = state
                .revision
                .checked_add(1)
                .expect("checkpoint revision exhausted");
        } else {
            state.flushes += 1;
            if state.revision == state.durable_revision {
                state.skipped += 1;
                return None;
            }
        }
        Some(state.revision)
    }

    pub(super) fn finish(&self, revision: u64, bytes: Result<Option<usize>, ()>) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match bytes {
            Ok(bytes) => {
                state.durable_revision = revision;
                if let Some(bytes) = bytes {
                    state.writes += 1;
                    state.encoded_bytes = state.encoded_bytes.saturating_add(bytes as u64);
                }
            }
            Err(()) => state.failed += 1,
        }
    }

    pub(super) fn snapshot(&self) -> CheckpointDiagnostics {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[cfg(all(test, feature = "client-persist"))]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn unchanged_routing_rounds_do_not_checkpoint_the_profile() {
        use std::sync::atomic::Ordering;
        let runtime = routing::RoutingRuntime::new(
            RoutingConfig::default(),
            gcoms_routing::Directory::new(),
            true,
        )
        .unwrap();
        runtime.recovering_owner.store(false, Ordering::Release);
        let mut node = persist::tests::state();
        node.routing = Some(runtime.clone());
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        persist_current_direct_state(&node).unwrap();
        let state = Arc::new(Mutex::new(node));
        runtime.bind_state(&state).unwrap();
        let scheduler = state.lock().unwrap().scheduler.clone();
        let (events, _) = broadcast::channel(4);
        let task = routing::spawn(state.clone(), scheduler.clone(), events);
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state.lock().unwrap().durability.snapshot().flushes < 5 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        task.abort();
        let _ = task.await;
        scheduler.shutdown();
        result.expect("five real routing rounds");
        // One explicit save and the initial directory guard checkpoint; the
        // subsequent four unchanged directory/routing rounds add no writes.
        let stats = state.lock().unwrap().durability.snapshot();
        assert_eq!(stats.writes, 2);
        assert_eq!(stats.skipped, stats.flushes);
    }

    #[tokio::test]
    async fn dirty_flush_failure_remains_pending_and_explicit_barriers_never_coalesce() {
        let mut node = persist::tests::state();
        node.channels.insert(
            "dirty".into(),
            persist::tests::established_owner_fixture("dirty"),
        );
        let saved = Arc::new(Mutex::new(Vec::new()));
        let sink = saved.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }));
        persist_current_direct_state(&node).unwrap();
        for _ in 0..20 {
            flush_changed_state(&node).unwrap();
        }
        assert_eq!(node.durability.snapshot().writes, 1);
        assert_eq!(node.durability.snapshot().skipped, 20);

        let state = Arc::new(Mutex::new(node));
        let scheduler = state.lock().unwrap().scheduler.clone();
        create_channel_invite(&state, "dirty", 600).unwrap();
        let mut node = state.lock().unwrap();
        let good_sink = node.durable_state_sink.clone();
        node.durable_state_sink = Some(Arc::new(|_| Err("disk failpoint".into())));
        assert!(flush_changed_state(&node).is_err());
        let failed = node.durability.snapshot();
        assert_ne!(failed.revision, failed.durable_revision);
        assert_eq!(failed.failed, 1);
        node.durable_state_sink = good_sink;
        flush_changed_state(&node).unwrap();
        assert_eq!(node.durability.snapshot().writes, 2);
        flush_changed_state(&node).unwrap();
        assert_eq!(node.durability.snapshot().writes, 2);
        persist_current_direct_state(&node).unwrap();
        assert_eq!(node.durability.snapshot().writes, 3);
        node.owner_transition_failed = true;
        assert!(flush_changed_state(&node).is_err());
        drop(node);

        let mut reopened = persist::tests::state();
        reopened.routing = Some(
            routing::RoutingRuntime::new(
                RoutingConfig::default(),
                gcoms_routing::Directory::new(),
                true,
            )
            .unwrap(),
        );
        let restored = Arc::new(Mutex::new(reopened));
        let restored_scheduler = restored.lock().unwrap().scheduler.clone();
        let bytes = saved.lock().unwrap().clone();
        persist::decode_state_at_startup(&restored, &restored_scheduler, &bytes)
            .await
            .unwrap();
        assert_eq!(restored.lock().unwrap().channels["dirty"].invites.len(), 1);
        scheduler.shutdown();
        restored_scheduler.shutdown();
    }

    #[tokio::test]
    async fn large_clean_profile_ignores_maintenance_and_retry_clocks() {
        let mut node = persist::tests::state();
        let mut channel = persist::tests::established_owner_fixture("large");
        // A retained ciphertext journal in the same size range as the affected
        // encrypted profile; these bytes are synthetic and never leave the lab.
        for byte in 0..64 {
            let wire = vec![byte; 256 * 1024];
            let id = crate::channel::msg_id("large", &wire);
            channel.message_outbox.insert(
                id,
                crate::channel::ChannelMessageOutbox {
                    wire,
                    expected: [(
                        channel.own_route.public.pseudonym,
                        channel.own_route.public.clone(),
                    )]
                    .into_iter()
                    .collect(),
                    acknowledged: HashSet::new(),
                },
            );
        }
        node.channels.insert("large".into(), channel);
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        persist_current_direct_state(&node).unwrap();
        let before = node.durability.snapshot();
        assert!(before.encoded_bytes >= 16 * 1024 * 1024);
        let state = Arc::new(Mutex::new(node));
        let scheduler = state.lock().unwrap().scheduler.clone();
        let (events, _) = broadcast::channel(4);
        let mut maintenance = DirectMaintenance::default();
        for _ in 0..100 {
            maintenance.tick(&state, &scheduler, &events);
            flush_changed_state(&state.lock().unwrap()).unwrap();
        }
        let after = state.lock().unwrap().durability.snapshot();
        assert_eq!(after.writes, before.writes);
        assert_eq!(after.encoded_bytes, before.encoded_bytes);
        scheduler.shutdown();
    }
}
