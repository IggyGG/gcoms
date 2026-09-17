// Native MLS/ratchet and archive boundaries, with no OS/network mocks.
#[tokio::test]
async fn tracked_channel_send_requires_complete_roster_and_persistence() {
    let (node, _, owner_route) = channel_member_fixture("tracked");
    let state = Arc::new(Mutex::new(node));
    let scheduler = state.lock().unwrap().scheduler.clone();
    assert!(
        send_channel_text_tracked(&state, &scheduler, "tracked", b"body")
            .await
            .unwrap_err()
            .contains("persistent")
    );
    state.lock().unwrap().durable_state_sink = Some(Arc::new(|_| Ok(())));
    assert!(
        send_channel_text_tracked(&state, &scheduler, "tracked", b"body")
            .await
            .unwrap_err()
            .contains("recipient route")
    );
    state
        .lock()
        .unwrap()
        .channels
        .get_mut("tracked")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    // A persistence failure must happen before relay writes and must restore MLS.
    state.lock().unwrap().durable_state_sink = Some(Arc::new(|_| Err("send failpoint".into())));
    assert_eq!(
        send_channel_text_tracked(&state, &scheduler, "tracked", b"body")
            .await
            .unwrap_err(),
        "send failpoint"
    );
    assert!(state.lock().unwrap().channels["tracked"]
        .message_outbox
        .is_empty());
    assert!(state.lock().unwrap().last_channel_send.is_none());
}

#[test]
fn tracked_channel_ack_matches_expected_member_and_commits_before_event() {
    let (mut node, mut owner, owner_route) = channel_member_fixture("tracked-ack");
    let cs = node.channels.get_mut("tracked-ack").unwrap();
    cs.directory.insert("owner".into(), owner_route.clone());
    let wire = cs
        .role
        .send(&crate::channel::encode_text(b"payload", false))
        .unwrap();
    let id = crate::channel::msg_id("tracked-ack", &wire);
    // The ACK is authentic MLS, but its signer is not this send's expected peer.
    let wrong_route = route(44, [0xE1; 32]);
    cs.message_outbox.insert(
        id,
        crate::channel::ChannelMessageOutbox {
            wire,
            expected: HashMap::from([(wrong_route.pseudonym, wrong_route)]),
            acknowledged: HashSet::new(),
        },
    );
    node.durable_state_sink = Some(Arc::new(|_| Ok(())));
    let (events, mut seen) = broadcast::channel(8);
    let wrong = owner
        .send(&crate::channel::encode_text_ack(id, false))
        .unwrap();
    deliver_mls(
        &mut node,
        "tracked-ack",
        &wrong,
        std::time::Instant::now(),
        &events,
    );
    assert!(seen.try_recv().is_err());
    assert!(node.channels["tracked-ack"].message_outbox[&id]
        .acknowledged
        .is_empty());
    node.channels
        .get_mut("tracked-ack")
        .unwrap()
        .message_outbox
        .get_mut(&id)
        .unwrap()
        .expected = HashMap::from([(owner_route.pseudonym, owner_route)]);
    let ack = owner
        .send(&crate::channel::encode_text_ack(id, false))
        .unwrap();
    // Wrong channel never completes this send.
    deliver_mls(&mut node, "other", &ack, std::time::Instant::now(), &events);
    assert!(seen.try_recv().is_err());
    node.durable_state_sink = Some(Arc::new(|_| Err("ack failpoint".into())));
    deliver_mls(
        &mut node,
        "tracked-ack",
        &ack,
        std::time::Instant::now(),
        &events,
    );
    assert!(seen.try_recv().is_err());
    assert!(node.channels["tracked-ack"].message_outbox[&id]
        .acknowledged
        .is_empty());
    let saved = Arc::new(Mutex::new(Vec::new()));
    let capture = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        capture.lock().unwrap().push(bytes);
        Ok(())
    }));
    deliver_mls(
        &mut node,
        "tracked-ack",
        &ack,
        std::time::Instant::now(),
        &events,
    );
    assert!(
        matches!(seen.try_recv(), Ok(Ev::ChannelDelivery {channel, msg_id}) if channel=="tracked-ack" && msg_id==id)
    );
    let archive = decode_v2(saved.lock().unwrap().last().unwrap(), &TEST_SEED).unwrap();
    assert!(archive.channels[0].message_outbox.is_empty());
    deliver_mls(
        &mut node,
        "tracked-ack",
        &ack,
        std::time::Instant::now(),
        &events,
    );
    assert!(
        seen.try_recv().is_err(),
        "replayed ACK is not another completion"
    );
}
