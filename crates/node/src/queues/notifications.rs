use super::*;
use crate::push_notifications::Binding;

impl LeaseStore {
    pub(crate) fn install_notification_sink(
        &mut self,
        sender: tokio::sync::mpsc::Sender<[u8; 32]>,
    ) -> Result<(), String> {
        if self.notification_sink.is_some() {
            return Err("push gateway is already configured".into());
        }
        self.notification_sink = Some(sender);
        Ok(())
    }
    pub fn bind_notification(&mut self, wire: &[u8], now: u64) -> Result<LeaseView, StoreError> {
        self.cleanup_expired(now);
        let queue: [u8; 32] = wire
            .get(2..34)
            .ok_or(StoreError::Unauthorized)?
            .try_into()
            .map_err(|_| StoreError::Unauthorized)?;
        let lease = self
            .leases
            .get_mut(&queue)
            .ok_or(StoreError::Unauthorized)?;
        let binding = Binding::verify(wire, &lease.capabilities.admin, &self.relay_service_id, now)
            .map_err(|_| StoreError::Unauthorized)?;
        if binding.queue != queue
            || binding.epoch != lease.epoch
            || binding.expires > lease.expiry
            || (binding.reference != [0; 32] && self.notification_sink.is_none())
        {
            return Err(StoreError::Unauthorized);
        }
        if let Some(previous) = &lease.notification {
            // Idempotent replay accepts the same authorized operation, but not
            // another reference at that revision or a delayed earlier binding.
            if binding.revision < previous.revision
                || (binding.revision == previous.revision
                    && (binding.reference != previous.reference
                        || binding.expires != previous.expires))
            {
                return Err(StoreError::Replay);
            }
        }
        lease.notification = Some(binding);
        Ok(lease.view())
    }
    pub(super) fn notify_admission(&mut self, queue: &[u8; 32], now: u64) {
        let Some(sender) = &self.notification_sink else {
            return;
        };
        let Some(lease) = self.leases.get_mut(queue) else {
            return;
        };
        let Some(binding) = &lease.notification else {
            return;
        };
        if binding.expires <= now
            || binding.reference == [0; 32]
            || (lease.last_notification != 0 && now.saturating_sub(lease.last_notification) < 30)
        {
            return;
        }
        if sender.try_send(binding.reference).is_ok() {
            lease.last_notification = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{Capabilities, LeaseCreate, LeaseRevoke, LeaseRotate};
    use gcoms_core::{gc2::NaturalCell, CellType, TrafficClass};
    use gcoms_protocol::relay::gc2::{Push, UnverifiedPush};

    const NOW: u64 = 1_000_000;
    const SERVICE: [u8; 32] = [9; 32];
    const QUEUE: [u8; 32] = [1; 32];
    const CAPS: Capabilities = Capabilities {
        push: [5; 32],
        sub: [6; 32],
        admin: [7; 32],
    };
    fn setup(cells: u16) -> (LeaseStore, tokio::sync::mpsc::Receiver<[u8; 32]>, Binding) {
        let mut store = LeaseStore::new(SERVICE, StoreConfig::default()).unwrap();
        let grant = store
            .issue_grant(
                GrantRequest {
                    queue_id: QUEUE,
                    epoch: 1,
                    limits: LeaseLimits {
                        max_queue_cells: cells,
                        max_queue_bytes: 8192,
                    },
                },
                NOW,
            )
            .unwrap();
        let create = LeaseCreate {
            queue_id: QUEUE,
            epoch: 1,
            lease_expiry: NOW + 300,
            queue_cells: cells,
            queue_bytes: 8192,
            capabilities: CAPS,
            nonce: [31; 16],
            grant: grant.wire,
        };
        store
            .create_lease(&create.encode(&SERVICE).unwrap(), NOW)
            .unwrap();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        store.install_notification_sink(sender).unwrap();
        let binding = Binding {
            queue: QUEUE,
            epoch: 1,
            revision: 1,
            expires: NOW + 200,
            nonce: [32; 16],
            reference: [33; 32],
        };
        (store, receiver, binding)
    }
    fn bind(store: &mut LeaseStore, binding: &Binding) -> Result<LeaseView, StoreError> {
        store.bind_notification(&binding.encode(&CAPS.admin, &SERVICE).unwrap(), NOW)
    }
    fn deposit(
        store: &mut LeaseStore,
        class: TrafficClass,
        nonce: u8,
        cover: bool,
        now: u64,
        key: &[u8; 32],
    ) -> Result<PushOutcome, StoreError> {
        let push = Push {
            class,
            queue_id: QUEUE,
            epoch: 1,
            nonce: [nonce; 16],
            expiry: NOW + 290,
            msg: if cover {
                None
            } else {
                Some(NaturalCell::new(CellType::Msg, 0, vec![nonce; 10]).unwrap())
            },
        };
        store.authenticate_push_gc2(
            UnverifiedPush::parse(push.encode(key, &SERVICE).unwrap()).unwrap(),
            now,
        )
    }
    #[test]
    fn notification_binding_requires_owner_and_monotonic_revision() {
        let (mut store, mut events, mut binding) = setup(8);
        assert!(store
            .bind_notification(&binding.encode(&CAPS.push, &SERVICE).unwrap(), NOW)
            .is_err());
        bind(&mut store, &binding).unwrap();
        binding.nonce = [34; 16]; // A retry may have a new transport nonce.
        bind(&mut store, &binding).unwrap();
        binding.reference = [35; 32];
        assert_eq!(bind(&mut store, &binding), Err(StoreError::Replay));
        binding.revision = 2;
        bind(&mut store, &binding).unwrap();
        binding.revision = 1;
        assert_eq!(bind(&mut store, &binding), Err(StoreError::Replay));
        binding.revision = 3;
        binding.reference = [0; 32];
        bind(&mut store, &binding).unwrap();
        deposit(
            &mut store,
            TrafficClass::Interactive,
            1,
            false,
            NOW,
            &CAPS.push,
        )
        .unwrap();
        assert!(events.try_recv().is_err());
        binding.revision = 4;
        binding.reference = [36; 32];
        binding.expires = NOW + 301;
        assert!(bind(&mut store, &binding).is_err());
    }
    #[test]
    fn notifications_only_follow_new_authenticated_interactive_admission() {
        let (mut store, mut events, binding) = setup(5);
        bind(&mut store, &binding).unwrap();
        let i = TrafficClass::Interactive;
        assert!(deposit(&mut store, i, 1, false, NOW, &[99; 32]).is_err());
        assert_eq!(
            deposit(&mut store, i, 2, true, NOW, &CAPS.push),
            Ok(PushOutcome::Cover)
        );
        deposit(&mut store, TrafficClass::Bulk, 3, false, NOW, &CAPS.push).unwrap();
        assert!(events.try_recv().is_err());
        deposit(&mut store, i, 4, false, NOW, &CAPS.push).unwrap();
        assert_eq!(events.try_recv().unwrap(), binding.reference);
        assert_eq!(
            deposit(&mut store, i, 4, false, NOW + 31, &CAPS.push),
            Ok(PushOutcome::Duplicate)
        );
        assert!(events.try_recv().is_err());
        deposit(&mut store, i, 5, false, NOW + 1, &CAPS.push).unwrap();
        assert!(events.try_recv().is_err()); // Coalesced.
        deposit(&mut store, i, 6, false, NOW + 31, &CAPS.push).unwrap();
        assert_eq!(events.try_recv().unwrap(), binding.reference);
        deposit(&mut store, i, 7, false, NOW + 201, &CAPS.push).unwrap();
        assert!(events.try_recv().is_err()); // Binding expired.
        assert_eq!(
            deposit(&mut store, i, 8, false, NOW + 202, &CAPS.push),
            Err(StoreError::QueueFull)
        );
        assert!(events.try_recv().is_err());
    }
    #[test]
    fn notification_revocation_rotation_and_backpressure_are_bounded() {
        let (mut store, mut events, binding) = setup(8);
        bind(&mut store, &binding).unwrap();
        store.notify_admission(&QUEUE, NOW);
        store.notify_admission(&QUEUE, NOW + 31); // Full channel drops hint, not data.
        assert_eq!(events.try_recv().unwrap(), binding.reference);
        store.notify_admission(&QUEUE, NOW + 32);
        assert_eq!(events.try_recv().unwrap(), binding.reference);
        let rotated = Capabilities {
            push: [45; 32],
            sub: [46; 32],
            admin: [47; 32],
        };
        let rotate = LeaseRotate {
            queue_id: QUEUE,
            old_epoch: 1,
            new_epoch: 2,
            lease_expiry: NOW + 300,
            new_capabilities: rotated,
            nonce: [41; 16],
        };
        store
            .rotate(&rotate.encode(&CAPS.admin, &SERVICE).unwrap(), NOW + 33)
            .unwrap();
        assert!(bind(&mut store, &binding).is_err());
        store.notify_admission(&QUEUE, NOW + 64);
        assert!(events.try_recv().is_err());
        let updated = Binding {
            epoch: 2,
            ..binding
        };
        store
            .bind_notification(&updated.encode(&rotated.admin, &SERVICE).unwrap(), NOW + 64)
            .unwrap();
        let revoke = LeaseRevoke {
            queue_id: QUEUE,
            epoch: 2,
            operation_expiry: NOW + 100,
            nonce: [42; 16],
        };
        store
            .revoke(&revoke.encode(&rotated.admin, &SERVICE).unwrap(), NOW + 65)
            .unwrap();
        store.notify_admission(&QUEUE, NOW + 96);
        assert!(events.try_recv().is_err());
    }
}
