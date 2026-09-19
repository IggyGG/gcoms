async fn gc2_queue_media(
    alice: &Arc<Mutex<NodeState>>,
    peer: &NodeInfo,
    body: &[u8],
) -> ([u8; 16], Vec<u8>) {
    let scheduler = alice.lock().unwrap().scheduler.clone();
    // Local preparation and persistence precede the network await. The
    // deliberately unavailable test carrier leaves the original retry in RAM.
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        send_volatile_application(alice, &scheduler, peer, body),
    )
    .await;
    let a = alice.lock().unwrap();
    let (id, pending) = a
        .pending_1to1
        .iter()
        .find(|(_, p)| {
            p.logical_record
                .as_deref()
                .is_some_and(crate::proto::is_volatile_application)
        })
        .expect("volatile record committed before carrier wait");
    assert_eq!(pending.delivery.cells.len(), 1);
    (*id, pending.delivery.cells[0].payload.clone())
}

fn gc2_assert_archive_omits_media(node: &NodeState, bytes: &[u8], body: &[u8], packet: &[u8]) {
    assert!(!bytes.windows(body.len()).any(|part| part == body));
    assert!(!bytes.windows(packet.len()).any(|part| part == packet));
    let archive = decode_v2(bytes, &node.identity_seed).unwrap();
    for (_, delivery, logical, ..) in &archive.pending_direct {
        assert!(!logical
            .as_deref()
            .is_some_and(crate::proto::is_volatile_application));
        assert!(delivery.cells.iter().all(|c| c.payload != packet));
    }
    assert!(archive.processed_direct.is_empty());
    let key = direct_session_wrapping_key(&node.identity_seed);
    for (peer, session, _) in &archive.sessions {
        let ArchivedSession::Credited(sealed) = session else {
            panic!("GC2 archive")
        };
        let context = direct_session_context_for_tag(node, peer, Some(sealed.tag())).unwrap();
        let session = sealed.open(&key, &context).unwrap();
        let private = session.window().encode_private();
        assert!(!private.windows(body.len()).any(|part| part == body));
        assert!(!private.windows(packet.len()).any(|part| part == packet));
        assert!(session
            .window()
            .retries()
            .all(|(_, _, bytes)| bytes != packet));
    }
}

#[tokio::test]
async fn gc2_volatile_sender_restart_discards_media_and_recovers_before_new_counters() {
    let (alice, mut b, durable_id) = gc2_recovery_pair(75, 76).await;
    let body = vec![0x69; 1024];
    let (id, packet) = gc2_queue_media(&alice, &b.info, &body).await;
    let bi = b.info.identity_pk.clone();
    let bytes = {
        let a = alice.lock().unwrap();
        let bytes = encode_state(&a).unwrap();
        gc2_assert_archive_omits_media(&a, &bytes, &body, &packet);
        let PeerSession::Credited(session) = &a.sessions[&bi] else {
            panic!("GC2")
        };
        assert!(session
            .window()
            .retries()
            .any(|(_, _, bytes)| bytes == packet));
        assert!(!session.window().recovery_required(now_unix()));
        bytes
    };
    let mut fresh = gc2_node(75);
    {
        let a = alice.lock().unwrap();
        fresh.info = a.info.clone();
        fresh.secrets = a.secrets.clone();
    }
    let scheduler = fresh.scheduler.clone();
    let fresh = Arc::new(Mutex::new(fresh));
    decode_state_at_startup(&fresh, &scheduler, &bytes)
        .await
        .unwrap();
    {
        let a = fresh.lock().unwrap();
        assert!(!a.pending_1to1.contains_key(&id));
        assert!(a.pending_1to1.contains_key(&durable_id));
        let PeerSession::Credited(session) = &a.sessions[&bi] else {
            panic!("GC2")
        };
        assert!(session.window().has_volatile_counters());
        assert!(session.window().recovery_required(now_unix()));
        assert_eq!(session.window().cached_payload_count(), 0);
        assert_eq!(session.window().cached_payload_bytes(), 0);
        assert!(
            !a.sessions[&bi].can_send(a.pending_1to1[&durable_id].logical_record.as_ref().unwrap())
        );
    }
    let (events, _) = broadcast::channel(32);
    let mut owner = DirectMaintenance::default();
    owner.tick(&fresh, &scheduler, &events);
    let setup = {
        let a = fresh.lock().unwrap();
        assert_eq!(gc2_generation(&a, &bi), 2);
        assert!(!a.pending_1to1.contains_key(&id));
        assert!(a.pending_1to1[&durable_id].delivery.cells.is_empty());
        gc2_setup_packet(&a, &bi)
    };
    gc2_direct::incoming(&mut b, &setup, &events).unwrap();
    let credit = b.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    let mut a = fresh.lock().unwrap();
    gc2_direct::incoming(&mut a, &credit, &events).unwrap();
    materialize_deferred(&mut a).unwrap();
    assert_eq!(a.pending_1to1[&durable_id].delivery.cells.len(), 1);
    assert!(!a.pending_1to1.contains_key(&id));
    gc2_assert_archive_omits_media(&a, &encode_state(&a).unwrap(), &body, &packet);
    drop(owner);
    alice.lock().unwrap().scheduler.shutdown();
    scheduler.shutdown();
    b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_volatile_receive_failure_restart_and_live_recovery_never_repeat_the_event() {
    let (alice, mut b, _) = gc2_recovery_pair(77, 78).await;
    let body = vec![0x6a; 1024];
    let (id, packet) = gc2_queue_media(&alice, &b.info, &body).await;
    let ai = alice.lock().unwrap().info.identity_pk.clone();
    let bi = b.info.identity_pk.clone();
    let (events, mut rx) = broadcast::channel(32);
    let received = b.sessions[&ai].recv_ctr();
    b.durable_state_sink = Some(Arc::new(|_| Err("volatile receive failpoint".into())));
    gc2_direct::incoming(&mut b, &packet, &events).unwrap();
    assert_eq!(b.sessions[&ai].recv_ctr(), received);
    assert_eq!(b.gc2_receipts.len(), 1);
    assert!(rx.try_recv().is_err());
    b.durable_state_sink = Some(Arc::new(|_| Ok(())));
    gc2_direct::incoming(&mut b, &packet, &events).unwrap();
    assert!(
        matches!(rx.try_recv(), Ok(Ev::VolatileApplication { msg_id, body: actual, .. })
        if msg_id == id && actual == body)
    );
    assert_eq!(
        b.application_inbox.entries.len(),
        1,
        "media never enters the durable inbox"
    );
    assert_eq!(b.gc2_receipts.len(), 2);
    gc2_assert_archive_omits_media(&b, &encode_state(&b).unwrap(), &body, &packet);
    let restored = gc2_restore(&b, 78).await;
    let mut b = restored.lock().unwrap();
    gc2_direct::incoming(&mut b, &packet, &events).unwrap();
    assert!(rx.try_recv().is_err());
    let mut a = alice.lock().unwrap();
    assert!(gc2_direct::recover_peer(&mut a, &bi).unwrap());
    let setup = gc2_setup_packet(&a, &bi);
    gc2_direct::incoming(&mut b, &setup, &events).unwrap();
    let credit = b.direct_ack_outbox.back().unwrap().cells[0].payload.clone();
    gc2_direct::incoming(&mut a, &credit, &events).unwrap();
    materialize_deferred(&mut a).unwrap();
    let replacement = a.pending_1to1[&id].delivery.cells[0].payload.clone();
    assert_ne!(replacement, packet);
    gc2_direct::incoming(&mut b, &replacement, &events).unwrap();
    assert_eq!(b.gc2_receipts.len(), 2);
    assert_eq!(b.application_inbox.entries.len(), 1);
    assert!(!std::iter::from_fn(|| rx.try_recv().ok())
        .any(|e| matches!(e, Ev::VolatileApplication { .. })));
    gc2_assert_archive_omits_media(&b, &encode_state(&b).unwrap(), &body, &replacement);
    assert!(
        gc2_direct::incoming(&mut b, &packet, &events).is_err(),
        "retired wire tag cannot replay media"
    );
    a.scheduler.shutdown();
    b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_volatile_failed_send_save_has_no_ram_commit_and_archive_cannot_be_relabelled_v20() {
    let (alice, b, _) = gc2_recovery_pair(79, 80).await;
    let body = vec![0x6b; 1024];
    let stored = Arc::new(Mutex::new(None));
    let counter = {
        let mut a = alice.lock().unwrap();
        let sink = stored.clone();
        a.durable_state_sink = Some(Arc::new(move |bytes| {
            *sink.lock().unwrap() = Some(bytes.to_vec());
            Err("volatile sender failpoint after storage".into())
        }));
        a.sessions[&b.info.identity_pk].send_ctr()
    };
    let scheduler = alice.lock().unwrap().scheduler.clone();
    assert!(
        send_volatile_application(&alice, &scheduler, &b.info, &body)
            .await
            .unwrap_err()
            .contains("failpoint")
    );
    let (bytes, ledger_size) = {
        let a = alice.lock().unwrap();
        assert_eq!(a.sessions[&b.info.identity_pk].send_ctr(), counter);
        assert!(a.pending_1to1.values().all(|p| !p
            .logical_record
            .as_deref()
            .is_some_and(crate::proto::is_volatile_application)));
        let bytes = stored.lock().unwrap().take().unwrap();
        assert!(!bytes.windows(body.len()).any(|part| part == body));
        let archive = decode_v2(&bytes, &a.identity_seed).unwrap();
        let (_, ArchivedSession::Credited(sealed), _) = &archive.sessions[0] else {
            panic!("GC2")
        };
        let key = direct_session_wrapping_key(&a.identity_seed);
        let context =
            direct_session_context_for_tag(&a, &b.info.identity_pk, Some(sealed.tag())).unwrap();
        let session = sealed.open(&key, &context).unwrap();
        assert_eq!(session.window().cached_payload_count(), 0);
        assert!(session.window().recovery_required(now_unix()));
        // Nested v3 has new retention semantics, even when its generation is one.
        // It must not pass through historical v20 recovery migration.
        (bytes, a.gc2_receipts.encode().len())
    };
    let mut old = bytes;
    old.truncate(old.len() - (4 + 28 + ledger_size));
    old[..6].copy_from_slice(MAGIC_V20);
    let fresh = Arc::new(Mutex::new(gc2_node(79)));
    let fresh_scheduler = fresh.lock().unwrap().scheduler.clone();
    assert!(decode_state_at_startup(&fresh, &fresh_scheduler, &old)
        .await
        .unwrap_err()
        .contains("v21"));
    assert!(fresh.lock().unwrap().sessions.is_empty());
    scheduler.shutdown();
    fresh_scheduler.shutdown();
    b.scheduler.shutdown();
}
