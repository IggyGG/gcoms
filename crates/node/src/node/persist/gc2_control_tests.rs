fn gc2_fill_control_window(node: &mut NodeState, peer: &[u8], marker: u8) -> Vec<Vec<u8>> {
    let key = direct_session_wrapping_key(&node.identity_seed);
    let context = direct_session_context(node, peer).unwrap();
    let mut packets = Vec::new();
    for index in 0..gcoms_protocol::flow::COUNTER_WINDOW {
        let mut id = [marker; 16];
        id[..8].copy_from_slice(&index.to_be_bytes());
        let record = if index == 0 {
            crate::proto::encode_direct_durable_data(id, now_ms(), &[marker; 128])
        } else {
            crate::proto::encode_direct_presence(id, index, crate::proto::PresenceMode::Away, 60)
                .unwrap()
        };
        let prepared = node.sessions[peer]
            .prepare_send(&record, &key, &context)
            .unwrap();
        packets.push(prepared.packet(&node.info.identity_pk).unwrap());
        node.sessions
            .get_mut(peer)
            .unwrap()
            .commit_send(prepared)
            .unwrap();
    }
    packets
}

#[tokio::test]
async fn gc2_full_bidirectional_control_windows_accept_data_and_release_credit() {
    let (alice, mut bob, _) = gc2_recovery_pair(81, 82).await;
    let ai = alice.lock().unwrap().info.identity_pk.clone();
    let bi = bob.info.identity_pk.clone();
    let (events, _) = broadcast::channel(256);
    // Credit the initial application ACK, leaving both transmit windows empty.
    gc2_credit_initial_ack(&alice, &mut bob, &events);
    let outgoing_a = gc2_fill_control_window(&mut alice.lock().unwrap(), &bi, 0x81);
    let outgoing_b = gc2_fill_control_window(&mut bob, &ai, 0x82);
    let before_a = alice.lock().unwrap().sessions[&bi].recv_ctr();
    let before_b = bob.sessions[&ai].recv_ctr();
    // Both directions need an application ACK, with no free ratchet counter.
    // Transport credit must still be committed independently of ACK preparation.
    bob.durable_state_sink = Some(Arc::new(|_| Err("deferred ACK receive failpoint".into())));
    gc2_direct::incoming(&mut bob, &outgoing_a[0], &events).unwrap();
    assert_eq!(bob.sessions[&ai].recv_ctr(), before_b);
    assert_eq!(bob.application_inbox.entries.len(), 1);
    assert!(bob.gc2_receipts.pending_acks(now_unix()).is_empty());
    assert!(bob.direct_ack_outbox.is_empty());
    bob.durable_state_sink = Some(Arc::new(|_| Ok(())));
    gc2_direct::incoming(&mut bob, &outgoing_a[0], &events).unwrap();
    gc2_direct::incoming(&mut alice.lock().unwrap(), &outgoing_b[0], &events).unwrap();
    assert_eq!(bob.sessions[&ai].recv_ctr(), before_b + 1);
    assert_eq!(alice.lock().unwrap().sessions[&bi].recv_ctr(), before_a + 1);
    assert_eq!(bob.application_inbox.entries.len(), 2);
    assert_eq!(alice.lock().unwrap().application_inbox.entries.len(), 1);
    for packet in &outgoing_a[1..] {
        gc2_direct::incoming(&mut bob, packet, &events).unwrap();
    }
    for packet in &outgoing_b[1..] {
        gc2_direct::incoming(&mut alice.lock().unwrap(), packet, &events).unwrap();
    }
    assert_eq!(bob.sessions[&ai].recv_ctr(), before_b + 63);
    assert_eq!(
        alice.lock().unwrap().sessions[&bi].recv_ctr(),
        before_a + 63
    );
    assert_eq!(bob.gc2_receipts.pending_acks(now_unix()).len(), 63);
    assert_eq!(
        alice
            .lock()
            .unwrap()
            .gc2_receipts
            .pending_acks(now_unix())
            .len(),
        63
    );
    let restored = gc2_restore(&bob, 82).await;
    let mut bob = restored.lock().unwrap();
    assert_eq!(bob.gc2_receipts.pending_acks(now_unix()).len(), 63);
    assert_eq!(gc2_acks::materialize(&mut bob, &mut None).unwrap(), 0);
    // Lost credit and a restart do not repeat the already persisted inbox effect.
    gc2_direct::incoming(&mut bob, &outgoing_a[0], &events).unwrap();
    assert_eq!(bob.application_inbox.entries.len(), 2);
    assert_eq!(bob.gc2_receipts.pending_acks(now_unix()).len(), 63);
    let mut alice = alice.lock().unwrap();
    let credit_a = alice.direct_ack_outbox.back().unwrap().cells[0]
        .payload
        .clone();
    let credit_b = bob.direct_ack_outbox.back().unwrap().cells[0]
        .payload
        .clone();
    gc2_direct::incoming(&mut bob, &credit_a, &events).unwrap();
    gc2_direct::incoming(&mut alice, &credit_b, &events).unwrap();
    // Transport credit never retires an application receipt that has no ACK yet.
    assert_eq!(alice.gc2_receipts.len(), 1);
    assert_eq!(bob.gc2_receipts.len(), 1);
    alice.direct_ack_outbox.clear();
    bob.direct_ack_outbox.clear();
    for _ in 0..16 {
        assert!(gc2_acks::materialize(&mut alice, &mut None).unwrap() <= 4);
        assert!(gc2_acks::materialize(&mut bob, &mut None).unwrap() <= 4);
    }
    assert!(alice.gc2_receipts.pending_acks(now_unix()).is_empty());
    assert!(bob.gc2_receipts.pending_acks(now_unix()).is_empty());
    let acks_a: Vec<_> = alice
        .direct_ack_outbox
        .drain(..)
        .flat_map(|mut d| std::mem::take(&mut d.cells))
        .collect();
    let acks_b: Vec<_> = bob
        .direct_ack_outbox
        .drain(..)
        .flat_map(|mut d| std::mem::take(&mut d.cells))
        .collect();
    assert_eq!(acks_a.len(), 63);
    assert_eq!(acks_b.len(), 63);
    for packet in acks_a {
        gc2_direct::incoming(&mut bob, &packet.payload, &events).unwrap();
    }
    for packet in acks_b {
        gc2_direct::incoming(&mut alice, &packet.payload, &events).unwrap();
    }
    let credit_a = alice.direct_ack_outbox.back().unwrap().cells[0]
        .payload
        .clone();
    let credit_b = bob.direct_ack_outbox.back().unwrap().cells[0]
        .payload
        .clone();
    gc2_direct::incoming(&mut bob, &credit_a, &events).unwrap();
    gc2_direct::incoming(&mut alice, &credit_b, &events).unwrap();
    assert_eq!(alice.gc2_receipts.len(), 0);
    assert_eq!(bob.gc2_receipts.len(), 0);
    assert_eq!(alice.application_inbox.entries.len(), 1);
    assert_eq!(bob.application_inbox.entries.len(), 2);
    alice.scheduler.shutdown();
    bob.scheduler.shutdown();
}

fn gc2_credit_initial_ack(
    alice: &Arc<Mutex<NodeState>>,
    bob: &mut NodeState,
    events: &broadcast::Sender<Ev>,
) {
    let ack = bob
        .direct_ack_outbox
        .iter()
        .flat_map(|d| &d.cells)
        .find(|c| c.payload.starts_with(b"GCM2"))
        .unwrap()
        .payload
        .clone();
    gc2_direct::incoming(&mut alice.lock().unwrap(), &ack, events).unwrap();
    let credit = alice
        .lock()
        .unwrap()
        .direct_ack_outbox
        .back()
        .unwrap()
        .cells[0]
        .payload
        .clone();
    gc2_direct::incoming(bob, &credit, events).unwrap();
    alice.lock().unwrap().direct_ack_outbox.clear();
    bob.direct_ack_outbox.clear();
}

#[tokio::test]
async fn gc2_deferred_ack_uncertain_save_pauses_until_restart_without_reusing_counter() {
    let (alice, mut bob, _) = gc2_recovery_pair(83, 84).await;
    let (events, _) = broadcast::channel(256);
    gc2_credit_initial_ack(&alice, &mut bob, &events);
    let ai = alice.lock().unwrap().info.identity_pk.clone();
    let bi = bob.info.identity_pk.clone();
    let from_a = gc2_fill_control_window(&mut alice.lock().unwrap(), &bi, 0x83);
    let from_b = gc2_fill_control_window(&mut bob, &ai, 0x84);
    gc2_direct::incoming(&mut bob, &from_a[0], &events).unwrap();
    gc2_direct::incoming(&mut alice.lock().unwrap(), &from_b[0], &events).unwrap();
    assert_eq!(bob.gc2_receipts.pending_acks(now_unix()).len(), 1);
    let credit = alice
        .lock()
        .unwrap()
        .direct_ack_outbox
        .back()
        .unwrap()
        .cells[0]
        .payload
        .clone();
    gc2_direct::incoming(&mut bob, &credit, &events).unwrap();
    let stored = Arc::new(Mutex::new(None));
    let sink = stored.clone();
    bob.durable_state_sink = Some(Arc::new(move |bytes| {
        *sink.lock().unwrap() = Some(bytes.to_vec());
        Err("deferred ACK failpoint after storage".into())
    }));
    let counter = bob.sessions[&ai].send_ctr();
    let outbox = bob.direct_ack_outbox.len();
    assert!(gc2_acks::materialize(&mut bob, &mut None)
        .unwrap_err()
        .contains("failpoint"));
    assert!(bob.owner_transition_failed);
    assert_eq!(bob.sessions[&ai].send_ctr(), counter);
    assert_eq!(bob.direct_ack_outbox.len(), outbox);
    assert_eq!(bob.gc2_receipts.pending_acks(now_unix()).len(), 1);
    assert_eq!(gc2_acks::materialize(&mut bob, &mut None).unwrap(), 0);
    let bytes = stored.lock().unwrap().take().unwrap();
    let mut fresh = gc2_node(84);
    fresh.info = bob.info.clone();
    fresh.secrets = bob.secrets.clone();
    let scheduler = fresh.scheduler.clone();
    let fresh = Arc::new(Mutex::new(fresh));
    decode_state_at_startup(&fresh, &scheduler, &bytes)
        .await
        .unwrap();
    let mut fresh = fresh.lock().unwrap();
    assert!(!fresh.owner_transition_failed);
    assert_eq!(fresh.sessions[&ai].send_ctr(), counter + 1);
    assert!(fresh.gc2_receipts.pending_acks(now_unix()).is_empty());
    assert_eq!(fresh.direct_ack_outbox.len(), outbox + 1);
    let committed_ack = fresh.direct_ack_outbox.back().unwrap().cells[0]
        .payload
        .clone();
    let PeerSession::Credited(session) = &fresh.sessions[&ai] else {
        panic!("GC2")
    };
    assert!(session
        .window()
        .retries()
        .any(|(_, _, packet)| packet == committed_ack));
    gc2_direct::incoming(&mut fresh, &from_a[0], &events).unwrap();
    assert_eq!(fresh.application_inbox.entries.len(), 2);
    assert_eq!(fresh.sessions[&ai].send_ctr(), counter + 1);
    alice.lock().unwrap().scheduler.shutdown();
    bob.scheduler.shutdown();
    scheduler.shutdown();
}
