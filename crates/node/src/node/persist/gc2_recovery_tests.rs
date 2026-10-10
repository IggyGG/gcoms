// Real hybrid-crypto, node archive and inbox transactions, with selected packet
// loss. The independent TLS integration suite exercises the carrier separately.
#[tokio::test]
async fn gc2_recovery_waits_for_owned_inbox_without_rotating_or_writing() {
    let (alice, bob, id) = gc2_recovery_pair(41, 42).await;
    let mut a = alice.lock().unwrap();
    let peer = bob.info.identity_pk.clone();
    let runtime = routing::RoutingRuntime::new(
        RoutingConfig::default(),
        gcoms_routing::Directory::new(),
        true,
    )
    .unwrap();
    runtime
        .recovering_owner
        .store(false, std::sync::atomic::Ordering::Release);
    a.routing = Some(runtime);
    let generation = gc2_generation(&a, &peer);
    let cells = a.pending_1to1[&id].delivery.cells.clone();
    let expiry = a.pending_1to1[&id].expires;
    let before = a.durability.snapshot().writes;
    for _ in 0..100 {
        assert!(!gc2_direct::recover_peer(&mut a, &peer).unwrap());
    }
    assert_eq!(a.durability.snapshot().writes, before);
    assert_eq!(gc2_generation(&a, &peer), generation);
    assert_eq!(a.pending_1to1[&id].delivery.cells, cells);
    assert_eq!(a.pending_1to1[&id].expires, expiry);
    let inbox = a.client_relay.aliases[0].contact.queue_id;
    a.subscribed_contact_aliases.insert(inbox);
    assert!(gc2_direct::recover_peer(&mut a, &peer).unwrap());
    assert_eq!(gc2_generation(&a, &peer), generation + 1);
    assert_eq!(a.durability.snapshot().writes, before + 1);
    assert_eq!(a.pending_1to1[&id].expires, expiry);
    a.scheduler.shutdown();
    bob.scheduler.shutdown();
}

fn gc2_setup_packet(node: &NodeState, peer: &[u8]) -> Vec<u8> {
    let PeerSession::Credited(session) = &node.sessions[peer] else {
        panic!("GC2")
    };
    session
        .window()
        .retries()
        .find(|(_, _, bytes)| bytes.starts_with(b"GCH2"))
        .expect("uncredited first move")
        .2
        .to_vec()
}

fn gc2_generation(node: &NodeState, peer: &[u8]) -> u64 {
    let PeerSession::Credited(session) = &node.sessions[peer] else {
        panic!("GC2")
    };
    session.window().generation()
}

async fn gc2_recovery_pair(a_seed: u8, b_seed: u8) -> (Arc<Mutex<NodeState>>, NodeState, [u8; 16]) {
    let alice = Arc::new(Mutex::new(gc2_node(a_seed)));
    let mut bob = gc2_node(b_seed);
    let scheduler = alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice, &scheduler, &bob.info, b"one logical delivery", None)
        .await
        .unwrap();
    let (id, cells) = {
        let a = alice.lock().unwrap();
        let (id, p) = a.pending_1to1.iter().next().unwrap();
        (*id, p.delivery.cells.clone())
    };
    let (events, _) = broadcast::channel(32);
    for cell in cells {
        gc2_direct::incoming(&mut bob, &cell.payload, &events).unwrap();
    }
    let credits: Vec<_> = bob
        .direct_ack_outbox
        .iter()
        .flat_map(|d| &d.cells)
        .filter(|c| c.payload.starts_with(b"GCA2"))
        .map(|c| c.payload.clone())
        .collect();
    for packet in credits {
        gc2_direct::incoming(&mut alice.lock().unwrap(), &packet, &events).unwrap();
    }
    assert_eq!(bob.application_inbox.entries.len(), 1);
    assert_eq!(bob.gc2_receipts.len(), 1);
    (alice, bob, id)
}

#[tokio::test]
async fn gc2_recovery_consumed_delivery_restart_lost_ack_and_conflicting_reencryption() {
    let (alice, mut bob, id) = gc2_recovery_pair(61, 62).await;
    let ai = alice.lock().unwrap().info.identity_pk.clone();
    let bi = bob.info.identity_pk.clone();
    let delivery = bob.application_inbox.entries[0].clone();
    bob.application_inbox
        .consume(delivery.sequence, delivery.digest())
        .unwrap();
    let restored = gc2_restore(&bob, 62).await;
    let (events, _) = broadcast::channel(32);
    let (deadline, sequence, record, first, saved) = {
        let mut b = restored.lock().unwrap();
        assert_eq!(b.gc2_receipts.len(), 1);
        assert!(b.application_inbox.entries.is_empty());
        let mut a = alice.lock().unwrap();
        let deadline = a.pending_1to1[&id].expires;
        let sequence = a.pending_1to1[&id].sequence;
        let record = a.pending_1to1[&id].logical_record.clone().unwrap();
        assert!(gc2_direct::recover_peer(&mut a, &bi).unwrap());
        assert_eq!(gc2_generation(&a, &bi), 2);
        assert!(a.pending_1to1[&id].delivery.cells.is_empty());
        let first = gc2_setup_packet(&a, &bi);
        let previous_tag = *b.sessions[&ai].tag().unwrap();
        let outbox = b.direct_ack_outbox.clone();
        let saved = Arc::new(Mutex::new(None));
        let saved_sink = saved.clone();
        b.durable_state_sink = Some(Arc::new(move |bytes| {
            *saved_sink.lock().unwrap() = Some(bytes.to_vec());
            Err("recovery receive failpoint after storage".into())
        }));
        assert!(gc2_direct::incoming(&mut b, &first, &events).is_err());
        assert_eq!(b.sessions[&ai].tag(), Some(&previous_tag));
        assert_eq!(
            b.direct_ack_outbox
                .iter()
                .map(|d| &d.cells)
                .collect::<Vec<_>>(),
            outbox.iter().map(|d| &d.cells).collect::<Vec<_>>()
        );
        assert_eq!(b.gc2_receipts.len(), 1);
        assert!(b.owner_transition_failed);
        assert!(gc2_direct::incoming(&mut b, &first, &events).is_err());
        (deadline, sequence, record, first, saved)
    };
    let mut restarted = gc2_node(62);
    restarted.info = bob.info.clone();
    restarted.secrets = bob.secrets.clone();
    let restart_scheduler = restarted.scheduler.clone();
    let restarted = Arc::new(Mutex::new(restarted));
    let checkpoint = saved.lock().unwrap().take().unwrap();
    decode_state_at_startup(&restarted, &restart_scheduler, &checkpoint)
        .await
        .unwrap();
    let mut b = restarted.lock().unwrap();
    let mut a = alice.lock().unwrap();
    assert_eq!(gc2_generation(&b, &ai), 2);
    assert_eq!(b.gc2_receipts.len(), 1);
    gc2_direct::incoming(&mut b, &first, &events).unwrap();
    let credit = b.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    // Lost setup credit: an exact retry reproduces it after acceptance.
    gc2_direct::incoming(&mut b, &first, &events).unwrap();
    assert_eq!(b.direct_ack_outbox.back().unwrap().cells[0].payload, credit);
    gc2_direct::incoming(&mut a, &credit, &events).unwrap();
    materialize_deferred(&mut a).unwrap();
    assert_eq!(a.pending_1to1[&id].expires, deadline);
    assert_eq!(a.pending_1to1[&id].sequence, sequence);
    assert_eq!(
        a.pending_1to1[&id].logical_record.as_deref(),
        Some(record.as_slice())
    );
    let packet = a.pending_1to1[&id].delivery.cells[0].payload.clone();
    gc2_direct::incoming(&mut b, &packet, &events).unwrap();
    assert!(
        b.application_inbox.entries.is_empty(),
        "consumed message must not be delivered twice"
    );
    assert_eq!(b.application_inbox.next_sequence, 2);
    assert_eq!(b.gc2_receipts.len(), 1);

    // The same logical ID with different bytes, but fresh valid ratchet crypto,
    // must fail before changing the inbox, receive counter, receipts or outbox.
    let Some(DirectRecord::Data { sent_ms, .. }) = decode_direct_record(&record) else {
        panic!("Data")
    };
    let conflicting = crate::proto::encode_direct_durable_data(id, sent_ms, b"conflict");
    let key = direct_session_wrapping_key(&a.identity_seed);
    let context = direct_session_context(&a, &bi).unwrap();
    let prepared = a.sessions[&bi]
        .prepare_send(&conflicting, &key, &context)
        .unwrap();
    let packet = prepared.packet(&a.info.identity_pk).unwrap();
    a.sessions
        .get_mut(&bi)
        .unwrap()
        .commit_send(prepared)
        .unwrap();
    let counter = b.sessions[&ai].recv_ctr();
    let acks = b.direct_ack_outbox.len();
    gc2_direct::incoming(&mut b, &packet, &events).unwrap();
    assert_eq!(b.sessions[&ai].recv_ctr(), counter);
    assert_eq!(b.direct_ack_outbox.len(), acks);
    assert!(b.application_inbox.entries.is_empty());

    // The new application ACK is still required. Transport credit for Data
    // alone cannot retire the source's pending logical record.
    let outgoing: Vec<_> = b
        .direct_ack_outbox
        .iter()
        .flat_map(|d| &d.cells)
        .map(|c| c.payload.clone())
        .collect();
    for packet in outgoing.iter().filter(|p| p.starts_with(b"GCA2")) {
        let _ = gc2_direct::incoming(&mut a, packet, &events);
    }
    assert!(a.pending_1to1.contains_key(&id));
    for packet in outgoing.iter().filter(|p| p.starts_with(b"GCM2")) {
        gc2_direct::incoming(&mut a, packet, &events).unwrap();
    }
    assert!(!a.pending_1to1.contains_key(&id));
    let credit = a.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    let receipts = b.gc2_receipts.encode();
    b.durable_state_sink = Some(Arc::new(|_| Err("credit failpoint".into())));
    assert!(gc2_direct::incoming(&mut b, &credit, &events).is_err());
    assert_eq!(b.gc2_receipts.encode(), receipts);
    b.durable_state_sink = Some(Arc::new(|_| Ok(())));
    gc2_direct::incoming(&mut b, &credit, &events).unwrap();
    assert_eq!(b.gc2_receipts.len(), 0);
    a.scheduler.shutdown();
    b.scheduler.shutdown();
    bob.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_recovery_simultaneous_and_ambiguous_acceptance_keep_monotonic_generations() {
    let (alice, mut b, _) = gc2_recovery_pair(63, 64).await;
    let mut a = alice.lock().unwrap();
    let ai = a.info.identity_pk.clone();
    let bi = b.info.identity_pk.clone();
    assert!(gc2_direct::recover_peer(&mut a, &bi).unwrap());
    assert!(gc2_direct::recover_peer(&mut b, &ai).unwrap());
    let first_a = gc2_setup_packet(&a, &bi);
    let first_b = gc2_setup_packet(&b, &ai);
    let (events, _) = broadcast::channel(32);
    let (winner, loser, winning, losing) = if ai < bi {
        (&mut *a, &mut b, first_a, first_b)
    } else {
        (&mut b, &mut *a, first_b, first_a)
    };
    let wi = winner.info.identity_pk.clone();
    let li = loser.info.identity_pk.clone();
    assert!(gc2_direct::incoming(winner, &losing, &events)
        .unwrap_err()
        .contains("wins collision"));
    gc2_direct::incoming(loser, &winning, &events).unwrap();
    assert_eq!(winner.sessions[&li].tag(), loser.sessions[&wi].tag());
    // The accepted replacement's credit is lost. The initiator advances again
    // without knowing which tag the receiver holds; both converge to generation 3.
    assert!(gc2_direct::recover_peer(winner, &li).unwrap());
    let next = gc2_setup_packet(winner, &li);
    gc2_direct::incoming(loser, &next, &events).unwrap();
    assert_eq!(gc2_generation(winner, &li), 3);
    assert_eq!(gc2_generation(loser, &wi), 3);
    assert!(gc2_direct::incoming(loser, &winning, &events).is_err());
    assert!(gc2_direct::incoming(winner, &losing, &events).is_err());
    // Same generation with a different signed tag cannot replace an established peer.
    let alternate = gcoms_protocol::gc2_session::initiate_recovery(
        &IdentityKeypair::from_seed(winner.identity_seed),
        &winner.info.public(),
        &winner.secrets,
        &loser.info.public(),
        3,
        now_unix(),
        &mut rand::thread_rng(),
    )
    .unwrap();
    assert!(gc2_direct::incoming(loser, &alternate.packet, &events).is_err());
    let bytes = encode_state(loser).unwrap();
    let archive = decode_v2(&bytes, &loser.identity_seed).unwrap();
    assert!(archive.gc2_receipts.is_some());
    a.scheduler.shutdown();
    b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_recovery_initial_loss_expired_setup_restart_and_admission_wait() {
    let alice = Arc::new(Mutex::new(gc2_node(65)));
    let mut b = gc2_node(66);
    let bi = b.info.identity_pk.clone();
    let scheduler = alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice, &scheduler, &b.info, b"initial setup lost", None)
        .await
        .unwrap();
    {
        let mut a = alice.lock().unwrap();
        a.session_states.insert(
            bi.clone(),
            DirectSessionState::InitiatedUnconfirmed {
                expires: std::time::Instant::now(),
            },
        );
        cleanup_expired_unconfirmed(&mut a, std::time::Instant::now()).unwrap();
        assert_eq!(gc2_generation(&a, &bi), 1);
    }
    let restored = {
        let bytes = encode_state(&alice.lock().unwrap()).unwrap();
        let restored = Arc::new(Mutex::new(gc2_node(65)));
        let sched = restored.lock().unwrap().scheduler.clone();
        decode_state_at_startup(&restored, &sched, &bytes)
            .await
            .unwrap();
        restored
    };
    let (events, _) = broadcast::channel(32);
    let a = restored.lock().unwrap();
    assert_eq!(gc2_generation(&a, &bi), 1);
    drop(a);
    let mut maintenance = DirectMaintenance::default();
    let restored_scheduler = restored.lock().unwrap().scheduler.clone();
    maintenance.tick(&restored, &restored_scheduler, &events);
    drop(maintenance);
    let mut a = restored.lock().unwrap();
    let recovery = gc2_setup_packet(&a, &bi);
    // Generation one never arrived. Signed recovery still authenticates first
    // contact; it does not require an unauthenticated reset or a downgrade.
    gc2_direct::incoming(&mut b, &recovery, &events).unwrap();
    let credit = b.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    gc2_direct::incoming(&mut a, &credit, &events).unwrap();
    assert_eq!(gc2_generation(&a, &bi), 2);
    let tag = *a.sessions[&bi].tag().unwrap();
    // The credited setup no longer has any retained packet. Saturated shared
    // job admission must prevent advancing to a new retained first move.
    let mut pressure = Vec::new();
    while let Ok(reservation) = a.scheduler.retain_attempt_payload(0) {
        pressure.push(reservation);
    }
    assert!(!pressure.is_empty());
    assert!(!gc2_direct::recover_peer(&mut a, &bi).unwrap());
    assert_eq!(a.sessions[&bi].tag(), Some(&tag));
    assert_eq!(gc2_generation(&a, &bi), 2);
    assert!(!a.owner_transition_failed);
    drop(pressure);
    let pending: Vec<_> = a.pending_1to1.keys().copied().collect();
    a.durable_state_sink = Some(Arc::new(|_| Err("recovery sender failpoint".into())));
    assert!(gc2_direct::recover_peer(&mut a, &bi)
        .unwrap_err()
        .contains("failpoint"));
    assert_eq!(a.sessions[&bi].tag(), Some(&tag));
    assert_eq!(gc2_generation(&a, &bi), 2);
    assert!(a.owner_transition_failed);
    assert!(pending.iter().all(|id| a.pending_1to1.contains_key(id)));
    assert!(gc2_direct::recover_peer(&mut a, &bi).is_err());
    scheduler.shutdown();
    a.scheduler.shutdown();
    b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_recovery_v20_requires_old_ack_credit_and_v21_authenticates_receipts() {
    let (alice, mut b, _) = gc2_recovery_pair(67, 68).await;
    let ai = alice.lock().unwrap().info.identity_pk.clone();
    let delivery = b.application_inbox.entries[0].clone();
    b.application_inbox
        .consume(delivery.sequence, delivery.digest())
        .unwrap();
    let mut bytes = encode_state(&b).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(decode_v2(&bytes, &b.identity_seed).is_err());
    bytes[last] ^= 1;
    // v20 has the exact v21 prefix grammar, without the final sealed receipt
    // field. Construct that actual old grammar, not just a relabeled new file.
    bytes.truncate(bytes.len() - (4 + 28 + b.gc2_receipts.encode().len()));
    bytes[..6].copy_from_slice(MAGIC_V20);
    assert!(decode_v2(&bytes, &b.identity_seed)
        .unwrap()
        .gc2_receipts
        .is_none());
    let fresh = Arc::new(Mutex::new(gc2_node(68)));
    let scheduler = fresh.lock().unwrap().scheduler.clone();
    decode_state_at_startup(&fresh, &scheduler, &bytes)
        .await
        .unwrap();
    {
        let mut restored = fresh.lock().unwrap();
        assert!(!restored.gc2_receipts.recovery_allowed(&ai));
        assert!(gc2_direct::recover_peer(&mut restored, &ai)
            .unwrap_err()
            .contains("historical"));
    }
    let sealed = encode_state(&fresh.lock().unwrap()).unwrap();
    assert_eq!(&sealed[..6], MAGIC_V21);
    assert!(!decode_v2(&sealed, &b.identity_seed)
        .unwrap()
        .gc2_receipts
        .unwrap()
        .recovery_allowed(&ai));
    let (events, _) = broadcast::channel(32);
    let ack = b
        .direct_ack_outbox
        .iter()
        .flat_map(|d| &d.cells)
        .find(|c| c.payload.starts_with(b"GCM2"))
        .unwrap()
        .payload
        .clone();
    let mut a = alice.lock().unwrap();
    gc2_direct::incoming(&mut a, &ack, &events).unwrap();
    let credit = a.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    let mut restored = fresh.lock().unwrap();
    gc2_direct::incoming(&mut restored, &credit, &events).unwrap();
    assert!(restored.gc2_receipts.recovery_allowed(&ai));
    assert!(gc2_direct::recover_peer(&mut restored, &ai).unwrap());
    a.scheduler.shutdown();
    b.scheduler.shutdown();
    scheduler.shutdown();
}

#[tokio::test]
async fn gc2_recovery_expired_data_only_repairs_counter_and_generation_cannot_wrap() {
    let (alice, mut b, _) = gc2_recovery_pair(69, 70).await;
    let mut a = alice.lock().unwrap();
    let ai = a.info.identity_pk.clone();
    let bi = b.info.identity_pk.clone();
    let (events, _) = broadcast::channel(32);
    let expired = crate::proto::encode_direct_durable_data(
        [99; 16],
        now_ms().saturating_sub(601_000),
        b"expired before re-encryption",
    );
    let key = direct_session_wrapping_key(&a.identity_seed);
    let context = direct_session_context(&a, &bi).unwrap();
    let prepared = a.sessions[&bi]
        .prepare_send_until(&expired, now_unix() + 3600, &key, &context)
        .unwrap();
    let packet = prepared.packet(&a.info.identity_pk).unwrap();
    a.sessions
        .get_mut(&bi)
        .unwrap()
        .commit_send(prepared)
        .unwrap();
    let counter = b.sessions[&ai].recv_ctr();
    gc2_direct::incoming(&mut b, &packet, &events).unwrap();
    assert_eq!(b.sessions[&ai].recv_ctr(), counter + 1);
    assert_eq!(b.application_inbox.next_sequence, 2);
    assert_eq!(b.gc2_receipts.len(), 1);
    assert!(b.direct_ack_outbox.back().unwrap().cells[0]
        .payload
        .starts_with(b"GCA2"));
    let max = gcoms_protocol::gc2_session::initiate_recovery(
        &IdentityKeypair::from_seed(a.identity_seed),
        &a.info.public(),
        &a.secrets,
        &b.info.public(),
        u64::MAX,
        now_unix(),
        &mut rand::thread_rng(),
    )
    .unwrap();
    gc2_direct::incoming(&mut b, &max.packet, &events).unwrap();
    let tag = *b.sessions[&ai].tag().unwrap();
    assert_eq!(gc2_generation(&b, &ai), u64::MAX);
    assert!(gc2_direct::recover_peer(&mut b, &ai)
        .unwrap_err()
        .contains("generation exhausted"));
    assert_eq!(b.sessions[&ai].tag(), Some(&tag));
    assert!(!b.owner_transition_failed);
    a.scheduler.shutdown();
    b.scheduler.shutdown();
}

fn gc2_expired_recovery_pair(a_seed: u8, b_seed: u8) -> (NodeState, NodeState) {
    let mut a = gc2_node(a_seed);
    let mut b = gc2_node(b_seed);
    let now = now_unix();
    let then = now - gcoms_crypto::session::SKIP_KEY_TTL.as_secs();
    for node in [&mut a, &mut b] {
        let (bundle, secrets) = IdentityKeypair::from_seed(node.identity_seed)
            .issue_bundle_with_rng(&mut rand::thread_rng(), then)
            .unwrap();
        node.info.bundle = bundle.encode();
        node.secrets = Arc::new(secrets);
    }
    let bi = b.info.identity_pk.clone();
    let candidate = gcoms_protocol::gc2_session::initiate(
        &IdentityKeypair::from_seed(a.identity_seed),
        &a.info.public(),
        &a.secrets,
        &b.info.public(),
        then,
        &mut rand::thread_rng(),
    )
    .unwrap();
    assert!(!candidate.session.window().repair_expired(now - 1));
    assert!(candidate.session.window().repair_expired(now));
    let (events, _) = broadcast::channel(32);
    gc2_direct::incoming(&mut b, &candidate.packet, &events).unwrap();
    a.sessions
        .insert(bi.clone(), PeerSession::Credited(candidate.session));
    a.peer_routes.insert(bi.clone(), b.info.clone());
    a.session_states
        .insert(bi.clone(), DirectSessionState::Established);
    persist_current_direct_state(&a).unwrap();
    (a, b)
}

#[tokio::test]
async fn gc2_recovery_maintenance_replaces_session_at_skipped_key_horizon() {
    let (a, mut b) = gc2_expired_recovery_pair(71, 72);
    let bi = b.info.identity_pk.clone();
    let (events, _) = broadcast::channel(32);
    let scheduler = a.scheduler.clone();
    let writes = a.durability.snapshot().writes;
    let state = Arc::new(Mutex::new(a));
    let mut maintenance = DirectMaintenance::default();
    for _ in 0..100 {
        maintenance.tick(&state, &scheduler, &events);
    }
    {
        let a = state.lock().unwrap();
        assert_eq!(gc2_generation(&a, &bi), 1);
        assert_eq!(a.durability.snapshot().writes, writes);
    }
    let prepared = prepare_durable_1to1(&state, &b.info, b"new durable work", None).unwrap();
    assert!(state.lock().unwrap().pending_1to1[&prepared.message_id]
        .delivery
        .cells
        .is_empty());
    maintenance.tick(&state, &scheduler, &events);
    let first = {
        let a = state.lock().unwrap();
        assert_eq!(gc2_generation(&a, &bi), 2);
        assert!(matches!(
            a.session_states[&bi],
            DirectSessionState::InitiatedUnconfirmed { .. }
        ));
        gc2_setup_packet(&a, &bi)
    };
    gc2_direct::incoming(&mut b, &first, &events).unwrap();
    drop(maintenance);
    scheduler.shutdown();
    b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_fresh_volatile_work_recovers_an_expired_idle_session_once() {
    let (a, mut b) = gc2_expired_recovery_pair(75, 76);
    let bi = b.info.identity_pk.clone();
    let scheduler = a.scheduler.clone();
    let state = Arc::new(Mutex::new(a));
    let body = b"fresh volatile application";
    assert!(prepare_volatile_application(&state, &b.info, body).is_err());
    let (first, writes) = {
        let a = state.lock().unwrap();
        assert_eq!(gc2_generation(&a, &bi), 2);
        assert!(a.pending_1to1.is_empty());
        (gc2_setup_packet(&a, &bi), a.durability.snapshot().writes)
    };
    for _ in 0..32 {
        assert!(prepare_volatile_application(&state, &b.info, body).is_err());
    }
    {
        let a = state.lock().unwrap();
        assert_eq!(gc2_generation(&a, &bi), 2);
        assert_eq!(a.durability.snapshot().writes, writes);
    }
    let (events, _) = broadcast::channel(32);
    gc2_direct::incoming(&mut b, &first, &events).unwrap();
    let credit = b.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    gc2_direct::incoming(&mut state.lock().unwrap(), &credit, &events).unwrap();
    let prepared = prepare_volatile_application(&state, &b.info, body).unwrap();
    let cells = state.lock().unwrap().pending_1to1[&prepared.message_id]
        .delivery
        .cells
        .clone();
    assert!(!cells.is_empty());
    for cell in &cells {
        gc2_direct::incoming(&mut b, &cell.payload, &events).unwrap();
    }
    scheduler.shutdown();
    b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_prepared_receive_keeps_its_logical_receipt_when_flow_deadline_passes() {
    let (alice, mut b, _) = gc2_recovery_pair(73, 74).await;
    let id = [111; 16];
    let deadline = now_unix() + 2;
    let (peer, frame) = {
        let mut a = alice.lock().unwrap();
        let record =
            crate::proto::encode_direct_durable_data(id, now_ms(), b"accepted before expiry");
        let key = direct_session_wrapping_key(&a.identity_seed);
        let context = direct_session_context(&a, &b.info.identity_pk).unwrap();
        let prepared = a.sessions[&b.info.identity_pk]
            .prepare_send_until(&record, deadline, &key, &context)
            .unwrap();
        let frame = gcoms_crypto::Frame::decode(prepared.wire()).unwrap();
        a.sessions
            .get_mut(&b.info.identity_pk)
            .unwrap()
            .commit_send(prepared)
            .unwrap();
        (a.info.identity_pk.clone(), frame)
    };
    let mut key = direct_session_wrapping_key(&b.identity_seed);
    let context = direct_session_context(&b, &peer).unwrap();
    let received = b.sessions[&peer]
        .prepare_receive(&frame, &key, &context)
        .unwrap();
    let accepted = received.plaintext().to_vec();
    assert!(!accepted.is_empty());
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(now_unix() >= deadline);
    assert_eq!(
        received.plaintext(),
        accepted,
        "expiry cannot erase an already prepared receipt"
    );
    let hash: [u8; 32] = Sha256::digest(frame.encode()).into();
    b.application_inbox
        .stage(&peer, id, now_unix(), b"accepted before expiry")
        .unwrap();
    accept_reliable_direct(
        &mut b,
        &peer,
        ((peer.clone(), frame.ctr), hash),
        id,
        received,
        &mut key,
        &context,
    )
    .unwrap();
    assert_eq!(b.gc2_receipts.len(), 2);
    assert_eq!(b.application_inbox.entries.len(), 2);
    let archive = decode_v2(&encode_state(&b).unwrap(), &b.identity_seed).unwrap();
    assert_eq!(archive.gc2_receipts.unwrap().len(), 2);
    alice.lock().unwrap().scheduler.shutdown();
    b.scheduler.shutdown();
}

fn gc2_deliver_fixture(st: &mut NodeState, bytes: &[u8], events: &broadcast::Sender<Ev>) {
    use gcoms_protocol::gc2_session::{Kind, Packet};
    let packet = Packet::decode(bytes).unwrap();
    if packet.kind() == Kind::Frame {
        let (peer, session) = st
            .sessions
            .iter()
            .find(|(_, s)| s.tag() == Some(packet.tag()))
            .unwrap();
        let key = direct_session_wrapping_key(&st.identity_seed);
        let context = direct_session_context(st, peer).unwrap();
        let frame = packet.frame().unwrap();
        session
            .prepare_receive(&frame, &key, &context)
            .unwrap_or_else(|e| {
                panic!(
                    "fixture receive counter={} pq={}: {e}",
                    frame.ctr,
                    frame.pq_ct.is_some()
                )
            });
    }
    gc2_direct::incoming(st, bytes, events).unwrap();
}

fn gc2_drain_fixture_acks(a: &mut NodeState, b: &mut NodeState, events: &broadcast::Sender<Ev>) {
    let mut last_a = None;
    let mut last_b = None;
    for _ in 0..16 {
        // Production maintenance prepares logical ACKs after transport credit
        // frees the send window; this fixture has no background maintenance.
        gc2_acks::materialize(a, &mut last_a).unwrap();
        gc2_acks::materialize(b, &mut last_b).unwrap();
        if a.direct_ack_outbox.is_empty() && b.direct_ack_outbox.is_empty() {
            return;
        }
        for delivery in std::mem::take(&mut a.direct_ack_outbox) {
            for cell in &delivery.cells {
                gc2_deliver_fixture(b, &cell.payload, events);
            }
        }
        for delivery in std::mem::take(&mut b.direct_ack_outbox) {
            for cell in &delivery.cells {
                gc2_deliver_fixture(a, &cell.payload, events);
            }
        }
    }
    panic!("ACK loop did not quiesce");
}

#[tokio::test]
async fn gc2_contact_renewal_keeps_pq_refresh_and_logical_receipts_working() {
    let (alice, mut bob, _) = gc2_recovery_pair(91, 92).await;
    // The pair fixture already delivered setup credits but intentionally kept
    // copies in its ACK outbox for other lost-ACK tests.
    for delivery in &mut bob.direct_ack_outbox {
        delivery
            .cells
            .retain(|cell| !cell.payload.starts_with(b"GCA2"));
    }
    bob.direct_ack_outbox
        .retain(|delivery| !delivery.cells.is_empty());
    let (events, _) = broadcast::channel(32);
    let (scheduler, peer, tag) = {
        let mut a = alice.lock().unwrap();
        gc2_drain_fixture_acks(&mut a, &mut bob, &events);
        (
            a.scheduler.clone(),
            bob.info.clone(),
            *a.sessions[&bob.info.identity_pk].tag().unwrap(),
        )
    };
    let now = now_unix();
    let (aged, secrets) = IdentityKeypair::from_seed(bob.identity_seed)
        .issue_bundle_with_rng(
            &mut rand::thread_rng(),
            now - crate::proto::MAX_BUNDLE_AGE_SECS / 2 - 1,
        )
        .unwrap();
    bob.info.bundle = aged.encode();
    bob.secrets = Arc::new(secrets);
    for alias in &mut bob.info.aliases {
        alias.expiry = now + 3600;
    }
    let updates = queue_contact_updates(&mut bob).unwrap();
    {
        let mut a = alice.lock().unwrap();
        for delivery in updates {
            for cell in &delivery.cells {
                gc2_direct::incoming(&mut a, &cell.payload, &events).unwrap();
            }
        }
        gc2_drain_fixture_acks(&mut a, &mut bob, &events);
        assert_eq!(a.peer_routes[&bob.info.identity_pk].bundle, bob.info.bundle);
    }
    // Consume each durable inbox item as the application would; the peer quota
    // intentionally stops delivery at 32 unconsumed items.
    let first = bob.application_inbox.entries.front().unwrap().clone();
    bob.application_inbox
        .consume(first.sequence, first.digest())
        .unwrap();
    persist_current_direct_state(&bob).unwrap();
    let mut pq_frames = 0;
    // Exceed the actual 32-message PQ-refresh cadence in both directions.
    for n in 0u8..65 {
        send_durable_1to1(&alice, &scheduler, &peer, &[n; 4], None)
            .await
            .unwrap();
        let mut a = alice.lock().unwrap();
        let cells: Vec<_> = a
            .pending_1to1
            .values()
            .flat_map(|p| p.delivery.cells.clone())
            .collect();
        assert!(!cells.is_empty());
        for cell in cells {
            let packet = gcoms_protocol::gc2_session::Packet::decode(&cell.payload).unwrap();
            if packet.frame().is_ok_and(|frame| frame.pq_ct.is_some()) {
                pq_frames += 1;
            }
            gc2_deliver_fixture(&mut bob, &cell.payload, &events);
        }
        gc2_drain_fixture_acks(&mut a, &mut bob, &events);
        assert!(
            a.pending_1to1.is_empty(),
            "recipient logical ACK required at message {n}"
        );
        assert_eq!(a.sessions[&bob.info.identity_pk].tag(), Some(&tag));
        assert_eq!(bob.application_inbox.entries.len(), 1);
        let delivery = bob.application_inbox.entries.back().unwrap().clone();
        assert_eq!(delivery.body, vec![n; 4]);
        assert_eq!(delivery.sequence, n as u64 + 2);
        bob.application_inbox
            .consume(delivery.sequence, delivery.digest())
            .unwrap();
        persist_current_direct_state(&bob).unwrap();
    }
    assert!(
        pq_frames >= 2,
        "must authenticate at least two actual PQ refreshes"
    );
    scheduler.shutdown();
    bob.scheduler.shutdown();
}
