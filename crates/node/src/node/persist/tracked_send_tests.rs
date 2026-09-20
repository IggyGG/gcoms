// Native MLS/ratchet and archive boundaries, with no OS/network mocks.
#[tokio::test]
async fn durable_channel_send_keeps_acceptance_when_the_first_hop_fails() {
    for tracked in [true, false] {
        let (mut node, mut owner, owner_route) = channel_member_fixture("retained-send");
        node.channels
            .get_mut("retained-send")
            .unwrap()
            .directory
            .insert("owner".into(), owner_route.clone());
        let saved = Arc::new(Mutex::new(Vec::new()));
        let capture = saved.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            capture.lock().unwrap().push(bytes);
            Ok(())
        }));
        let scheduler = node.scheduler.clone();
        // Admission fails without sending any bytes. The exact MLS wire is
        // nevertheless already committed for the ordinary outbox retry path.
        scheduler.shutdown();
        let state = Arc::new(Mutex::new(node));
        let prepared =
            prepare_channel_text(&state, "retained-send", b"after reconnect", tracked).unwrap();
        let id = complete_channel_text(&scheduler, prepared)
            .await
            .expect("durable local acceptance survives a failed first hop");
        let snapshots = saved.lock().unwrap();
        assert_eq!(snapshots.len(), 1);
        let archive = decode_v2(&snapshots[0], &TEST_SEED).unwrap();
        drop(snapshots);
        let channel = &archive.channels[0];
        assert_eq!(channel.message_outbox.len(), 1);
        let (saved_id, pending) = &channel.message_outbox[0];
        assert_eq!(*saved_id, id);
        assert_eq!(crate::channel::msg_id("retained-send", &pending.wire), id);
        assert_eq!(pending.expected.len(), 1);
        assert_eq!(pending.expected[&owner_route.pseudonym], owner_route);
        assert!(pending.acknowledged.is_empty());
        let gcoms_mls::ReceiveOutcome::Application { payload, .. } =
            owner.receive_outcome(&pending.wire).unwrap()
        else {
            panic!("retained wire must authenticate as application data");
        };
        assert!(matches!(crate::channel::decode_inner(&payload),
            Some(crate::channel::ChannelInner::Text { body, share_presence: false, .. })
                if body == b"after reconnect"));
        let mut node = state.lock().unwrap();
        assert_eq!(
            node.channels["retained-send"].message_outbox[&id].wire,
            pending.wire
        );
        let (events, mut seen) = broadcast::channel(8);
        let ack = owner
            .send(&crate::channel::encode_text_ack(id, false))
            .unwrap();
        deliver_mls(
            &mut node,
            "retained-send",
            &ack,
            std::time::Instant::now(),
            &events,
        );
        assert!(
            matches!(seen.try_recv(), Ok(Ev::ChannelDelivery { channel, msg_id })
            if channel == "retained-send" && msg_id == id)
        );
        assert!(node.channels["retained-send"].message_outbox.is_empty());
        deliver_mls(
            &mut node,
            "retained-send",
            &ack,
            std::time::Instant::now(),
            &events,
        );
        assert!(
            seen.try_recv().is_err(),
            "replayed ACK cannot repeat delivery"
        );
    }
}

#[tokio::test]
async fn volatile_channel_send_still_reports_a_failed_first_hop() {
    let (mut node, _, owner_route) = channel_member_fixture("volatile-send");
    node.channels
        .get_mut("volatile-send")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let scheduler = node.scheduler.clone();
    scheduler.shutdown();
    let state = Arc::new(Mutex::new(node));
    assert!(
        send_channel_text(&state, &scheduler, "volatile-send", b"no persistent sink")
            .await
            .unwrap_err()
            .contains("channel send failed")
    );
}

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
