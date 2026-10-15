async fn blocked_route_control_fixture(seed: u8) -> (NodeState, NodeState, [u8; 16]) {
    let (shared, peer, id) = gc2_recovery_pair(seed, seed + 1).await;
    let mut node = Arc::try_unwrap(shared).ok().unwrap().into_inner().unwrap();
    gc2_fill_control_window(&mut node, &peer.info.identity_pk, 0x94);
    for alias in &mut node.info.aliases {
        alias.expiry = now_unix() + 3600;
    }
    (node, peer, id)
}

fn signed_route_control(node: &NodeState, generation: u64, id: [u8; 16]) -> Vec<u8> {
    let now = now_unix();
    let expires = node
        .info
        .aliases
        .iter()
        .map(|alias| alias.expiry)
        .min()
        .unwrap();
    let update = ContactUpdate::sign(
        generation,
        now,
        expires,
        node.info.clone(),
        &IdentityKeypair::from_seed(node.identity_seed),
    )
    .unwrap();
    assert!(
        update.verify(&node.info.identity_pk, now),
        "fixture route authority must be valid before testing supersession"
    );
    encode_contact_update(id, &update).unwrap()
}

// Reconstruct the old, independently journaled deferred records without using
// the repaired producer; the real archive encoder/decoder must accept them.
fn seed_old_route_control(node: &mut NodeState, peer: &NodeInfo, id: [u8; 16], record: Vec<u8>) {
    let sequence = node.next_direct_sequence;
    node.next_direct_sequence += 1;
    node.pending_1to1.insert(
        id,
        PendingDirect {
            delivery: DirectDelivery {
                peer: peer.clone(),
                relay: node.client_relay.clone(),
                cells: Vec::new(),
            },
            logical_record: Some(record),
            sequence,
            next_attempt: std::time::Instant::now() + std::time::Duration::from_secs(60),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(3600),
            application_event: false,
        },
    );
}

#[tokio::test]
async fn gc2_route_control_coalescing_recovers_a_retained_duplicate_backlog() {
    let (mut node, peer, application) = blocked_route_control_fixture(201).await;
    for generation in 2..=257 {
        let id =
            contact_update_message_id(&node.info.identity_pk, &peer.info.identity_pk, generation);
        let record = signed_route_control(&node, generation, id);
        seed_old_route_control(&mut node, &peer.info, id, record);
    }
    node.local_contact_generation = 257;
    checkpoint_direct_state(&node, None, true)
        .map_err(DirectPersistenceError::into_string)
        .unwrap();
    let bytes = encode_state(&node).unwrap();
    let info = node.info.clone();
    let secrets = node.secrets.clone();
    node.scheduler.shutdown();
    drop(node);
    // A real restart has one newly owned budget, rather than charging two
    // multi-megabyte profile copies to the old scheduler at the same time.
    let mut fresh = gc2_node(201);
    fresh.info = info;
    fresh.secrets = secrets;
    let scheduler = fresh.scheduler.clone();
    let restored = Arc::new(Mutex::new(fresh));
    decode_state_at_startup(&restored, &scheduler, &bytes)
        .await
        .unwrap();
    let mut current = restored.lock().unwrap();
    let pending = &current.pending_1to1[&application];
    let retained_application = (
        pending.logical_record.clone(),
        pending.delivery.cells.clone(),
        pending.sequence,
        pending.expires,
    );
    let old_usage = current.retained_payload(None).unwrap();
    queue_contact_updates(&mut current).unwrap();
    let pending = &current.pending_1to1[&application];
    assert_eq!(
        (
            pending.logical_record.clone(),
            pending.delivery.cells.clone(),
            pending.sequence,
            pending.expires
        ),
        retained_application
    );
    assert!(current.retained_payload(None).unwrap().bytes < old_usage.bytes / 2);
    let archive = decode_v2(&encode_state(&current).unwrap(), &current.identity_seed).unwrap();
    let contacts: Vec<_> = archive
        .pending_direct
        .iter()
        .filter(|p| {
            p.2.as_ref().is_some_and(|r| {
                matches!(
                    decode_direct_record(r),
                    Some(DirectRecord::ContactUpdate { .. })
                )
            })
        })
        .collect();
    assert_eq!(contacts.len(), 1);
    assert_eq!(current.local_contact_generation, 258);
    assert!(archive.pending_direct.iter().any(|p| p.0 == application));
    current.scheduler.shutdown();
    peer.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_route_control_coalescing_restores_exact_memory_and_pauses_on_uncertain_checkpoint() {
    let (mut node, peer, application) = blocked_route_control_fixture(203).await;
    let old = [0x91; 16];
    let newer = [0x92; 16];
    let record = signed_route_control(&node, 2, old);
    queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        old,
        record.clone(),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let sequence = node.next_direct_sequence;
    let original = &node.pending_1to1[&old];
    let metadata = (original.sequence, original.next_attempt, original.expires);
    let usage = node.retained_payload(None).unwrap();
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = written.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        *sink.lock().unwrap() = bytes;
        Err("route coalescing failpoint after storage".into())
    }));
    let record_new = signed_route_control(&node, 3, newer);
    assert!(queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        newer,
        record_new,
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(60)
    )
    .is_err());
    assert!(node.owner_transition_failed);
    assert_eq!(node.next_direct_sequence, sequence);
    assert!(!node.pending_1to1.contains_key(&newer));
    let original = &node.pending_1to1[&old];
    assert_eq!(original.logical_record.as_ref(), Some(&record));
    assert_eq!(
        (original.sequence, original.next_attempt, original.expires),
        metadata
    );
    assert_eq!(node.retained_payload(None).unwrap(), usage);
    let candidate = decode_v2(&written.lock().unwrap(), &node.identity_seed).unwrap();
    assert!(candidate.pending_direct.iter().any(|p| p.0 == newer));
    assert!(!candidate.pending_direct.iter().any(|p| p.0 == old));
    assert!(candidate.pending_direct.iter().any(|p| p.0 == application));
    let bytes = written.lock().unwrap().clone();
    let info = node.info.clone();
    let secrets = node.secrets.clone();
    node.scheduler.shutdown();
    drop(node);
    let mut fresh = gc2_node(203);
    fresh.info = info;
    fresh.secrets = secrets;
    let scheduler = fresh.scheduler.clone();
    let restored = Arc::new(Mutex::new(fresh));
    decode_state_at_startup(&restored, &scheduler, &bytes)
        .await
        .unwrap();
    let mut current = restored.lock().unwrap();
    assert!(!current.owner_transition_failed);
    assert_eq!(current.next_direct_sequence, sequence + 1);
    assert!(current.pending_1to1.contains_key(&newer));
    assert!(!current.pending_1to1.contains_key(&old));
    assert!(current.pending_1to1.contains_key(&application));
    let next = [0x93; 16];
    let record = signed_route_control(&current, 4, next);
    queue_session_control(
        &mut current,
        &peer.info.identity_pk,
        next,
        record,
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(current.next_direct_sequence, sequence + 2);
    assert!(!current.pending_1to1.contains_key(&newer));
    assert!(current.pending_1to1.contains_key(&next));
    assert!(current.pending_1to1.contains_key(&application));
    current.scheduler.shutdown();
    peer.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_route_control_supersession_rejects_tamper_regression_foreign_scope_and_allocated_counters(
) {
    let (mut node, peer, _) = blocked_route_control_fixture(205).await;
    let old = [0xA1; 16];
    let new = [0xA2; 16];
    let record = signed_route_control(&node, 2, old);
    queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        old,
        record,
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let valid = signed_route_control(&node, 3, new);
    assert_eq!(
        route_control::superseded(&node, &peer.info.identity_pk, new, &valid),
        vec![old]
    );
    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(route_control::superseded(&node, &peer.info.identity_pk, new, &tampered).is_empty());
    assert!(
        route_control::superseded(&node, &peer.info.identity_pk, [0xA3; 16], &valid).is_empty()
    );
    assert!(route_control::superseded(&node, &[0xA4; 1952], new, &valid).is_empty());
    let older = signed_route_control(&node, 1, new);
    assert!(route_control::superseded(&node, &peer.info.identity_pk, new, &older).is_empty());
    node.pending_1to1.get_mut(&old).unwrap().application_event = true;
    assert!(route_control::superseded(&node, &peer.info.identity_pk, new, &valid).is_empty());
    node.pending_1to1.get_mut(&old).unwrap().application_event = false;
    node.pending_1to1
        .get_mut(&old)
        .unwrap()
        .delivery
        .cells
        .push(Cell::new(CellType::Msg, 0, 1, vec![7]));
    assert!(route_control::superseded(&node, &peer.info.identity_pk, new, &valid).is_empty());
    node.scheduler.shutdown();
    peer.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_deferred_forward_grant_coalescing_keeps_distinct_authority_and_longer_lifetimes() {
    let (mut node, peer, _) = blocked_route_control_fixture(207).await;
    let old = [0xB1; 16];
    let new = [0xB2; 16];
    let grant = node
        .client_relay
        .forward_grant(now_unix() + 120, node.info.identity_pk.clone())
        .unwrap();
    queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        old,
        encode_forward_grant(old, &grant).unwrap(),
        std::time::Duration::from_secs(120),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let mut longer = grant.clone();
    longer.expires_at += 60;
    let valid = encode_forward_grant(new, &longer).unwrap();
    assert_eq!(
        route_control::superseded(&node, &peer.info.identity_pk, new, &valid),
        vec![old]
    );
    let mut other = longer.clone();
    other.hop_key[0] ^= 1;
    assert!(route_control::superseded(
        &node,
        &peer.info.identity_pk,
        new,
        &encode_forward_grant(new, &other).unwrap()
    )
    .is_empty());
    let mut shorter = grant.clone();
    shorter.expires_at -= 1;
    assert!(route_control::superseded(
        &node,
        &peer.info.identity_pk,
        new,
        &encode_forward_grant(new, &shorter).unwrap()
    )
    .is_empty());
    queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        new,
        valid,
        std::time::Duration::from_secs(180),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    assert!(!node.pending_1to1.contains_key(&old));
    assert!(node.pending_1to1.contains_key(&new));
    node.scheduler.shutdown();
    peer.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_route_control_replacement_at_item_limit_preserves_every_application() {
    let (mut node, peer, _) = blocked_route_control_fixture(209).await;
    let old = [0xC1; 16];
    let newer = [0xC2; 16];
    let record = signed_route_control(&node, 2, old);
    queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        old,
        record,
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    for index in 0u64..1024 {
        if node.pending_1to1.len() == 1024 {
            break;
        }
        let mut id = [0xC3; 16];
        id[..8].copy_from_slice(&index.to_be_bytes());
        let record =
            crate::proto::encode_direct_durable_data(id, now_ms(), b"retained application");
        seed_old_route_control(&mut node, &peer.info, id, record);
        node.pending_1to1.get_mut(&id).unwrap().application_event = true;
    }
    assert_eq!(node.pending_1to1.len(), 1024);
    checkpoint_direct_state(&node, None, true)
        .map_err(DirectPersistenceError::into_string)
        .unwrap();
    let before: HashSet<_> = node.pending_1to1.keys().copied().collect();
    let record = signed_route_control(&node, 3, newer);
    queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        newer,
        record,
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(node.pending_1to1.len(), 1024);
    let after: HashSet<_> = node.pending_1to1.keys().copied().collect();
    assert_eq!(
        before.difference(&after).copied().collect::<Vec<_>>(),
        vec![old]
    );
    assert_eq!(
        after.difference(&before).copied().collect::<Vec<_>>(),
        vec![newer]
    );
    let sequence = node.next_direct_sequence;
    let id = [0xC4; 16];
    let ordinary =
        crate::proto::encode_direct_presence(id, 1, crate::proto::PresenceMode::Away, 60).unwrap();
    assert!(queue_session_control(
        &mut node,
        &peer.info.identity_pk,
        id,
        ordinary,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60)
    )
    .err()
    .unwrap()
    .contains("capacity"));
    assert_eq!(node.next_direct_sequence, sequence);
    assert_eq!(
        node.pending_1to1.keys().copied().collect::<HashSet<_>>(),
        after
    );
    node.scheduler.shutdown();
    peer.scheduler.shutdown();
}
