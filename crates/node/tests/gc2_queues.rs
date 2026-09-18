#![cfg(feature = "experimental-gc2")]
use gcoms_core::{gc2::NaturalCell, Cell, CellType, TrafficClass};
use gcoms_node::{
    lease::{Capabilities, LeaseCreate, LeaseLimits, LeaseRevoke, LeaseRotate},
    queues::{
        gc2::AuthenticatedSubscription, AckOutcome, GrantRequest, LeaseStore, PushOutcome,
        StoreConfig, StoreError,
    },
    relay::{
        gc2::{Push, Subscription, UnverifiedPush},
        RelayCodecError, RelayPush, RelaySub, UnauthenticatedRelayPush,
    },
};
use std::time::Duration;

const NOW: u64 = 1_000_000;
const SERVICE: [u8; 32] = [9; 32];
const QUEUE: [u8; 32] = [1; 32];
const CAPS: Capabilities = Capabilities {
    push: [5; 32],
    sub: [6; 32],
    admin: [7; 32],
};
const I: TrafficClass = TrafficClass::Interactive;
const B: TrafficClass = TrafficClass::Bulk;

fn create(store: &mut LeaseStore, limits: LeaseLimits, now: u64) {
    let grant = store
        .issue_grant(
            GrantRequest {
                queue_id: QUEUE,
                epoch: 1,
                limits,
            },
            now,
        )
        .unwrap();
    let create = LeaseCreate {
        queue_id: QUEUE,
        epoch: 1,
        lease_expiry: now + 300,
        queue_cells: limits.max_queue_cells,
        queue_bytes: limits.max_queue_bytes,
        capabilities: CAPS,
        nonce: [31; 16],
        grant: grant.wire,
    };
    store
        .create_lease(&create.encode(&SERVICE).unwrap(), now)
        .unwrap();
}

fn store_with(config: StoreConfig) -> LeaseStore {
    let mut store = LeaseStore::new(SERVICE, config).unwrap();
    create(&mut store, config.relay_limits, NOW);
    store
}
fn store() -> LeaseStore {
    store_with(StoreConfig::default())
}
fn push(class: TrafficClass, nonce: u8) -> Push {
    Push {
        class,
        queue_id: QUEUE,
        epoch: 1,
        nonce: [nonce; 16],
        expiry: NOW + 100,
        msg: Some(NaturalCell::new(CellType::Msg, 0, vec![nonce; 10]).unwrap()),
    }
}
fn deposit(store: &mut LeaseStore, push: &Push) -> Result<PushOutcome, StoreError> {
    store.authenticate_push_gc2(
        UnverifiedPush::parse(push.encode(&CAPS.push, &SERVICE).unwrap()).unwrap(),
        NOW,
    )
}
fn legacy_push(nonce: u8) -> UnauthenticatedRelayPush {
    UnauthenticatedRelayPush::parse(
        RelayPush {
            queue_id: QUEUE,
            epoch: 1,
            push_nonce: [nonce; 16],
            push_expiry: NOW + 100,
            msg: Some(Cell::new(CellType::Msg, 0, 0, vec![nonce; 10])),
        }
        .encode_into_cell(&CAPS.push, &SERVICE)
        .unwrap(),
    )
    .unwrap()
}
fn sub(class: TrafficClass, nonce: u8) -> Subscription {
    Subscription {
        class,
        queue_id: QUEUE,
        epoch: 1,
        expiry: NOW + 100,
        nonce: [nonce; 16],
    }
}
fn subscribe(store: &mut LeaseStore, class: TrafficClass, nonce: u8) -> AuthenticatedSubscription {
    store
        .authenticate_sub_gc2(&sub(class, nonce).encode(&CAPS.sub, &SERVICE).unwrap(), NOW)
        .unwrap()
}
async fn changed(handle: &mut AuthenticatedSubscription) -> bool {
    tokio::time::timeout(Duration::from_secs(1), handle.changed())
        .await
        .is_ok_and(|r| r.is_ok())
}
async fn closed(handle: &mut AuthenticatedSubscription) {
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handle.changed())
            .await
            .unwrap()
            .is_err()
    );
}

#[test]
fn classes_keep_independent_fifo_under_one_cell_and_byte_budget() {
    let mut store = store_with(StoreConfig {
        relay_limits: LeaseLimits {
            max_queue_cells: 3,
            max_queue_bytes: 1024,
        },
        ..StoreConfig::default()
    });
    let interactive = subscribe(&mut store, I, 1);
    let bulk = subscribe(&mut store, B, 2);
    assert_eq!(interactive.class(), I);
    assert_eq!(bulk.class(), B);
    assert_eq!(deposit(&mut store, &push(B, 10)), Ok(PushOutcome::Enqueued));
    assert_eq!(deposit(&mut store, &push(I, 11)), Ok(PushOutcome::Enqueued));
    store.authenticate_push(legacy_push(12), NOW).unwrap();
    assert_eq!(store.queue_len(&QUEUE, NOW), 3);
    assert_eq!(store.total_queue_bytes(), 48);
    assert_eq!(
        deposit(&mut store, &push(B, 13)),
        Err(StoreError::QueueFull)
    );
    assert_eq!(
        store.authenticate_push(legacy_push(14), NOW),
        Err(StoreError::QueueFull)
    );
    assert_eq!(
        store
            .peek_gc2(&interactive, NOW)
            .unwrap()
            .unwrap()
            .push_nonce,
        [11; 16]
    );
    assert_eq!(
        store.peek_gc2(&bulk, NOW).unwrap().unwrap().push_nonce,
        [10; 16]
    );
    assert_eq!(store.peek(&QUEUE, NOW).unwrap().push_nonce, [12; 16]);
    assert_eq!(
        store.acknowledge_gc2(&interactive, &[10; 16], NOW),
        Ok(AckOutcome::Mismatch)
    );
    assert_eq!(
        store.acknowledge_gc2(&bulk, &[10; 16], NOW),
        Ok(AckOutcome::Removed)
    );
    // Rejected capacity does not burn a replay nonce.
    assert_eq!(deposit(&mut store, &push(B, 13)), Ok(PushOutcome::Enqueued));
    assert_eq!(
        store.acknowledge_gc2(&bulk, &[13; 16], NOW),
        Ok(AckOutcome::Removed)
    );
    assert_eq!(
        store.acknowledge_gc2(&interactive, &[11; 16], NOW),
        Ok(AckOutcome::Removed)
    );
    assert_eq!(
        store.acknowledge(&QUEUE, &[12; 16], NOW),
        AckOutcome::Removed
    );
    assert_eq!(store.total_queue_bytes(), 0);
}

#[test]
fn global_and_per_lease_bytes_include_all_versions_and_classes() {
    for global_bound in [false, true] {
        let mut store = store_with(StoreConfig {
            max_total_queue_bytes: if global_bound { 32 } else { 1024 },
            relay_limits: LeaseLimits {
                max_queue_cells: 10,
                max_queue_bytes: if global_bound { 1024 } else { 32 },
            },
            ..StoreConfig::default()
        });
        let i = subscribe(&mut store, I, 1);
        store.authenticate_push(legacy_push(1), NOW).unwrap();
        deposit(&mut store, &push(I, 2)).unwrap();
        let expected = if global_bound {
            StoreError::Capacity
        } else {
            StoreError::QueueFull
        };
        assert_eq!(deposit(&mut store, &push(B, 3)), Err(expected.clone()));
        assert_eq!(store.authenticate_push(legacy_push(3), NOW), Err(expected));
        assert_eq!(store.total_queue_bytes(), 32);
        store.acknowledge_gc2(&i, &[2; 16], NOW).unwrap();
        assert_eq!(deposit(&mut store, &push(B, 3)), Ok(PushOutcome::Enqueued));
        assert_eq!(store.total_queue_bytes(), 32);
    }
}

#[test]
fn idempotent_retry_binds_exact_bytes_class_and_wire_version() {
    let mut store = store();
    let original = push(I, 1);
    deposit(&mut store, &original).unwrap();
    assert_eq!(deposit(&mut store, &original), Ok(PushOutcome::Duplicate));
    let mut changed = original.clone();
    changed.class = B;
    assert_eq!(deposit(&mut store, &changed), Err(StoreError::Replay));
    changed = original.clone();
    changed.expiry += 1;
    assert_eq!(deposit(&mut store, &changed), Err(StoreError::Replay));
    changed = original.clone();
    changed.msg = push(I, 2).msg;
    assert_eq!(deposit(&mut store, &changed), Err(StoreError::Replay));
    changed = original.clone();
    changed.msg = None;
    assert_eq!(deposit(&mut store, &changed), Err(StoreError::Replay));
    assert_eq!(
        store.authenticate_push(legacy_push(1), NOW),
        Err(StoreError::Replay)
    );
    store.authenticate_push(legacy_push(2), NOW).unwrap();
    assert_eq!(deposit(&mut store, &push(B, 2)), Err(StoreError::Replay));
    let wrong_cap = UnverifiedPush::parse(original.encode(&[55; 32], &SERVICE).unwrap()).unwrap();
    assert!(matches!(
        store.authenticate_push_gc2(wrong_cap, NOW),
        Err(StoreError::Relay(RelayCodecError::InvalidMac))
    ));
    assert_eq!(store.queue_len(&QUEUE, NOW), 2);
}

#[test]
fn shared_replay_capacity_does_not_double_for_classes_or_versions() {
    let mut store = store_with(StoreConfig {
        max_replay_nonces_per_lease: 2,
        ..StoreConfig::default()
    });
    let i = subscribe(&mut store, I, 1);
    deposit(&mut store, &push(I, 1)).unwrap();
    store.acknowledge_gc2(&i, &[1; 16], NOW).unwrap();
    let mut cover = push(B, 2);
    cover.msg = None;
    assert_eq!(deposit(&mut store, &cover), Ok(PushOutcome::Cover));
    assert_eq!(deposit(&mut store, &push(I, 1)), Ok(PushOutcome::Duplicate));
    assert_eq!(deposit(&mut store, &cover), Ok(PushOutcome::Duplicate));
    assert_eq!(
        deposit(&mut store, &push(B, 3)),
        Err(StoreError::ReplayCapacity)
    );
    assert_eq!(
        store.authenticate_push(legacy_push(3), NOW),
        Err(StoreError::ReplayCapacity)
    );
    assert_eq!(store.total_queue_bytes(), 0);
    // Capacity is freed only at the authenticated expiry, not at dequeue.
    let mut later = push(B, 3);
    later.expiry = NOW + 200;
    let parsed = UnverifiedPush::parse(later.encode(&CAPS.push, &SERVICE).unwrap()).unwrap();
    assert_eq!(
        store.authenticate_push_gc2(parsed, NOW + 100),
        Ok(PushOutcome::Enqueued)
    );
}

#[test]
fn class_tampering_epoch_and_expiry_fail_before_admission() {
    let mut store = store();
    let cell = push(I, 1).encode(&CAPS.push, &SERVICE).unwrap();
    let mut payload = cell.payload().to_vec();
    payload[0] = B as u8;
    let bad = NaturalCell::new(CellType::RelayPush, 0, payload).unwrap();
    assert!(matches!(
        store.authenticate_push_gc2(UnverifiedPush::parse(bad).unwrap(), NOW),
        Err(StoreError::Relay(RelayCodecError::InvalidMac))
    ));
    let mut stale = push(I, 2);
    stale.epoch = 2;
    assert_eq!(deposit(&mut store, &stale), Err(StoreError::Unauthorized));
    stale = push(I, 2);
    stale.expiry = NOW + 301;
    assert_eq!(deposit(&mut store, &stale), Err(StoreError::Unauthorized));
    let cell = sub(I, 1).encode(&CAPS.sub, &SERVICE).unwrap();
    let mut payload = cell.payload().to_vec();
    payload[0] = B as u8;
    let bad = NaturalCell::new(CellType::RelaySub, 0, payload).unwrap();
    assert!(matches!(
        store.authenticate_sub_gc2(&bad, NOW),
        Err(StoreError::Relay(RelayCodecError::InvalidMac))
    ));
    assert_eq!(store.queue_len(&QUEUE, NOW), 0);
    // Failed authentication does not consume the valid nonce.
    subscribe(&mut store, I, 1);
    assert_eq!(deposit(&mut store, &push(I, 1)), Ok(PushOutcome::Enqueued));
}

#[test]
fn subscription_nonce_budget_is_shared_and_expires_exactly() {
    let mut store = store_with(StoreConfig {
        max_subscription_nonces_per_lease: 2,
        ..StoreConfig::default()
    });
    let i = subscribe(&mut store, I, 1);
    let cell = sub(B, 1).encode(&CAPS.sub, &SERVICE).unwrap();
    assert!(matches!(
        store.authenticate_sub_gc2(&cell, NOW),
        Err(StoreError::Replay)
    ));
    let legacy = RelaySub {
        queue_id: QUEUE,
        epoch: 1,
        subscription_expiry: NOW + 100,
        nonce: [2; 16],
    }
    .encode_into_cell(&CAPS.sub, &SERVICE)
    .unwrap();
    store.authenticate_sub(&legacy, NOW).unwrap();
    let cell = sub(B, 3).encode(&CAPS.sub, &SERVICE).unwrap();
    assert!(matches!(
        store.authenticate_sub_gc2(&cell, NOW + 99),
        Err(StoreError::ReplayCapacity)
    ));
    assert!(matches!(
        store.peek_gc2(&i, NOW + 100),
        Err(StoreError::Unauthorized)
    ));
    let mut s = sub(B, 3);
    s.expiry = NOW + 200;
    assert!(store
        .authenticate_sub_gc2(&s.encode(&CAPS.sub, &SERVICE).unwrap(), NOW + 100)
        .is_ok());
}

#[tokio::test(start_paused = true)]
async fn notifications_catch_peek_wait_race_and_remain_class_filtered() {
    let mut store = store();
    let mut i = subscribe(&mut store, I, 1);
    let mut b = subscribe(&mut store, B, 2);
    assert!(store.peek_gc2(&i, NOW).unwrap().is_none());
    // Deposit after the empty peek and before waiting must not be lost.
    deposit(&mut store, &push(I, 1)).unwrap();
    assert!(changed(&mut i).await);
    assert!(!changed(&mut b).await);
    assert_eq!(deposit(&mut store, &push(I, 1)), Ok(PushOutcome::Duplicate));
    let mut cover = push(I, 2);
    cover.msg = None;
    assert_eq!(deposit(&mut store, &cover), Ok(PushOutcome::Cover));
    assert!(!changed(&mut i).await);
    // A cancelled wait must not consume a later update.
    deposit(&mut store, &push(I, 3)).unwrap();
    assert!(changed(&mut i).await);
    assert_eq!(
        store.acknowledge_gc2(&i, &[1; 16], NOW),
        Ok(AckOutcome::Removed)
    );
    assert!(changed(&mut i).await);
    assert_eq!(
        store.peek_gc2(&i, NOW).unwrap().unwrap().push_nonce,
        [3; 16]
    );
    assert!(!changed(&mut b).await);
}

#[tokio::test(start_paused = true)]
async fn rotation_wakes_waiters_invalidates_old_handles_and_keeps_data() {
    let mut store = store();
    let mut i = subscribe(&mut store, I, 1);
    let mut b = subscribe(&mut store, B, 2);
    deposit(&mut store, &push(I, 1)).unwrap();
    assert!(changed(&mut i).await);
    let new = Capabilities {
        push: [15; 32],
        sub: [16; 32],
        admin: [17; 32],
    };
    let rotate = LeaseRotate {
        queue_id: QUEUE,
        old_epoch: 1,
        new_epoch: 2,
        lease_expiry: NOW + 300,
        new_capabilities: new,
        nonce: [40; 16],
    }
    .encode(&CAPS.admin, &SERVICE)
    .unwrap();
    store.rotate(&rotate, NOW).unwrap();
    assert!(changed(&mut i).await);
    assert!(changed(&mut b).await);
    assert!(matches!(
        store.peek_gc2(&i, NOW),
        Err(StoreError::Unauthorized)
    ));
    assert_eq!(
        store.acknowledge_gc2(&i, &[1; 16], NOW),
        Err(StoreError::Unauthorized)
    );
    let mut s = sub(I, 3);
    s.epoch = 2;
    let fresh = store
        .authenticate_sub_gc2(&s.encode(&new.sub, &SERVICE).unwrap(), NOW)
        .unwrap();
    assert_eq!(
        store.peek_gc2(&fresh, NOW).unwrap().unwrap().push_nonce,
        [1; 16]
    );
    assert_eq!(
        store.acknowledge_gc2(&fresh, &[1; 16], NOW),
        Ok(AckOutcome::Removed)
    );
    assert_eq!(store.total_queue_bytes(), 0);
}

#[tokio::test(start_paused = true)]
async fn revoked_or_recreated_queue_never_revives_an_old_handle() {
    let mut store = store();
    let mut old = subscribe(&mut store, I, 1);
    let revoke = LeaseRevoke {
        queue_id: QUEUE,
        epoch: 1,
        operation_expiry: NOW + 100,
        nonce: [40; 16],
    }
    .encode(&CAPS.admin, &SERVICE)
    .unwrap();
    store.revoke(&revoke, NOW).unwrap();
    closed(&mut old).await;
    create(&mut store, StoreConfig::default().relay_limits, NOW);
    deposit(&mut store, &push(I, 1)).unwrap();
    assert!(matches!(
        store.peek_gc2(&old, NOW),
        Err(StoreError::Unauthorized)
    ));
    assert_eq!(
        store.acknowledge_gc2(&old, &[1; 16], NOW),
        Err(StoreError::Unauthorized)
    );
    let mut fresh = subscribe(&mut store, I, 2);
    assert!(store.peek_gc2(&fresh, NOW).unwrap().is_some());
    store.cleanup_expired(NOW + 300);
    closed(&mut fresh).await;
    assert_eq!(store.total_queue_bytes(), 0);
}

#[tokio::test(start_paused = true)]
async fn dropping_store_closes_subscriptions_without_a_background_task() {
    let mut store = store();
    let mut handle = subscribe(&mut store, I, 1);
    drop(store);
    closed(&mut handle).await;
}
