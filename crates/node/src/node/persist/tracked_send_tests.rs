// Native MLS/ratchet and archive boundaries, with no OS/network mocks.
#[tokio::test]
async fn pending_channel_wire_is_not_invalidated_by_next_admission() {
    let name = "admission-delivery-barrier";
    let mut owner = gcoms_mls::OwnerSession::create(
        gcoms_crypto::IdentityKeypair::from_seed(channel_seed_from(&TEST_SEED, name)),
        "owner",
        8,
    )
    .unwrap();
    let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let invitation =
        owner.sign_invite_key_package(&package, "member", gcoms_mls::Caps::member(), 3600);
    let admission = owner.admit(&invitation, &package).unwrap();
    let mut member = gcoms_mls::ChannelMember::join(prepared, &admission.welcome).unwrap();
    let owner_route = owned_channel_route(
        31,
        owner.own_pseudonym(),
        channel_direct_secret(&TEST_SEED, &owner.own_pseudonym()),
    );
    let member_route = route(32, member.own_pseudonym());
    let mut channel = ChannelState::new(
        ChannelRole::Owner(owner),
        owner_route,
        17,
        name.into(),
        crate::channel::ChannelVisibility::Private,
    );
    channel
        .directory
        .insert("owner".into(), channel.own_route.public.clone());
    channel
        .directory
        .insert("member".into(), member_route.clone());
    let wire = channel
        .role
        .send(&crate::channel::encode_text(
            b"admitted before next join",
            false,
        ))
        .unwrap();
    let id = crate::channel::msg_id(name, &wire);
    channel.message_outbox.insert(
        id,
        ChannelMessageOutbox {
            wire: wire.clone(),
            expected: HashMap::from([(member_route.pseudonym, member_route)]),
            acknowledged: HashSet::new(),
        },
    );
    let mut node = state();
    node.channels.insert(name.into(), channel);
    let state = Arc::new(Mutex::new(node));
    let scheduler = state.lock().unwrap().scheduler.clone();
    let (invite_id, secret, _) = create_channel_invite(&state, name, 3600).unwrap();
    let next = gcoms_mls::ChannelMember::prepare("next").unwrap();
    let next_package = gcoms_mls::ChannelMember::key_package_bytes(&next).unwrap();
    let next_route = route(33, gcoms_mls::ChannelMember::prepared_pseudonym(&next));
    let encoded = crate::channel::encode_join_package(&next_package, &next_route);
    let epoch = state.lock().unwrap().channels[name].role.epoch();
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        redeem_invite(
            &state, &scheduler, name, &invite_id, &secret, &encoded, "next",
        ),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(ref error)) if error == "channel messages still awaiting acknowledgements"),
        "a new epoch must not overtake an unacknowledged wire: {result:?}"
    );
    {
        let st = state.lock().unwrap();
        let channel = &st.channels[name];
        assert_eq!(channel.role.epoch(), epoch);
        assert!(channel.invites[&invite_id].consumed.is_none());
        assert!(channel.membership_outbox.is_none());
        assert_eq!(channel.message_outbox[&id].wire, wire);
        let restored = decode_v2(&encode_state(&st).unwrap(), &TEST_SEED).unwrap();
        assert_eq!(
            restored.channels[0]
                .message_outbox
                .iter()
                .find(|(key, _)| *key == id)
                .unwrap()
                .1
                .wire,
            wire
        );
    }
    assert!(matches!(
        member.receive_outcome(&wire).unwrap(),
        gcoms_mls::ReceiveOutcome::Application { .. }
    ));
    let ack = member
        .send(&crate::channel::encode_text_ack(id, false))
        .unwrap();
    let (events, _) = broadcast::channel(8);
    let mut st = state.lock().unwrap();
    deliver_mls(&mut st, name, &ack, std::time::Instant::now(), &events);
    let channel = st.channels.get_mut(name).unwrap();
    assert!(
        channel.message_outbox.is_empty(),
        "only the authenticated ACK releases the barrier"
    );
    super::super::channels::stage_recovery_admission_fixture(
        channel,
        name,
        &next_route,
        &next_package,
        "next",
    )
    .unwrap();
    assert_eq!(channel.role.epoch(), epoch + 1);
}

#[tokio::test]
async fn received_channel_text_cannot_schedule_ack_before_failed_checkpoint() {
    let (mut node, mut owner, mut owner_route) = channel_member_fixture("receive-checkpoint");
    node.channel_inbox = channel_inbox::Inbox::new(true);
    owner_route.control.expiry = now_unix() + 3600;
    owner_route.data.expiry = now_unix() + 3600;
    node.channels
        .get_mut("receive-checkpoint")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let scheduler = node.scheduler.clone();
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let jobs = observed.clone();
    node.durable_state_sink = Some(Arc::new(move |_| {
        jobs.store(
            scheduler.resource_snapshot().peak_jobs,
            std::sync::atomic::Ordering::SeqCst,
        );
        Err("injected incoming checkpoint failure".into())
    }));
    let wire = owner
        .send(&crate::channel::encode_text(b"retain before ACK", false))
        .unwrap();
    let (events, mut seen) = broadcast::channel(8);
    assert!(!deliver_mls(
        &mut node,
        "receive-checkpoint",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    assert!(seen.try_recv().is_err());
    assert!(node.channel_inbox.page(0, 1).unwrap().is_empty());
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an uncommitted receive must not submit an ACK to the scheduler"
    );
    assert!(node.channels["receive-checkpoint"]
        .pending_control
        .is_empty());
    node.durable_state_sink = Some(Arc::new(|_| Ok(())));
    assert!(deliver_mls(
        &mut node,
        "receive-checkpoint",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    assert!(matches!(seen.try_recv(), Ok(Ev::ChannelMessage { .. })));
}

#[tokio::test]
async fn channel_delivery_is_sealed_with_ratchet_and_exact_ack_before_publication() {
    let (mut node, mut owner, owner_route) = channel_member_fixture("archive-handoff");
    node.channel_inbox = channel_inbox::Inbox::new(true);
    node.channels
        .get_mut("archive-handoff")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let captures = Arc::new(Mutex::new(Vec::new()));
    let sink = captures.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        sink.lock().unwrap().push(bytes);
        Ok(())
    }));
    let wire = owner
        .send(&crate::channel::encode_text(
            b"durable channel plaintext",
            false,
        ))
        .unwrap();
    let id = crate::channel::msg_id("archive-handoff", &wire);
    let (events, mut seen) = broadcast::channel(8);
    assert!(deliver_mls(
        &mut node,
        "archive-handoff",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    assert!(matches!(seen.try_recv(),Ok(Ev::ChannelMessage {msg_id,..}) if msg_id==id));
    let bytes = captures.lock().unwrap().last().unwrap().clone();
    assert!(!bytes
        .windows(b"durable channel plaintext".len())
        .any(|w| w == b"durable channel plaintext"));
    let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    let delivery = archive.channel_inbox.page(0, 1).unwrap().remove(0);
    assert!(
        matches!(delivery.message.event(),Ev::ChannelMessage {msg_id,text,..} if msg_id==id && text==b"durable channel plaintext")
    );
    assert_eq!(archive.channels[0].commit_acks.len(), 1);
    assert!(decode_v2(&bytes, &[4; 32]).is_err());
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(decode_v2(&corrupt, &TEST_SEED).is_err());
    // Consuming the application receipt must leave MLS and authenticated ACK state intact.
    node.channel_inbox
        .consume(delivery.sequence, delivery.digest())
        .unwrap();
    let after = decode_v2(&encode_state(&node).unwrap(), &TEST_SEED).unwrap();
    assert!(after.channel_inbox.page(0, 1).unwrap().is_empty());
    assert_eq!(after.channels[0].commit_acks.len(), 1);
}

#[tokio::test]
async fn received_channel_commit_cannot_publish_roster_before_failed_checkpoint() {
    let (mut node, mut owner, owner_route) = channel_member_fixture("commit-checkpoint");
    node.channels
        .get_mut("commit-checkpoint")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let prepared = gcoms_mls::ChannelMember::prepare("new-member").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let invite =
        owner.sign_invite_key_package(&package, "new-member", gcoms_mls::Caps::member(), 3600);
    let admission = owner.admit(&invite, &package).unwrap();
    let epoch = node.channels["commit-checkpoint"].role.epoch();
    node.durable_state_sink = Some(Arc::new(|_| {
        Err("injected commit checkpoint failure".into())
    }));
    let (events, mut seen) = broadcast::channel(8);
    deliver_mls(
        &mut node,
        "commit-checkpoint",
        &admission.commit,
        std::time::Instant::now(),
        &events,
    );
    assert!(
        seen.try_recv().is_err(),
        "uncommitted membership must not be published"
    );
    assert_eq!(node.channels["commit-checkpoint"].role.epoch(), epoch);
    assert!(node.channels["commit-checkpoint"]
        .pending_control
        .is_empty());
    node.durable_state_sink = Some(Arc::new(|_| Ok(())));
    deliver_mls(
        &mut node,
        "commit-checkpoint",
        &admission.commit,
        std::time::Instant::now(),
        &events,
    );
    assert!(matches!(
        seen.try_recv(),
        Ok(Ev::ChannelRosterChanged { .. })
    ));
    assert!(node.channels["commit-checkpoint"].role.epoch() > epoch);
}

#[tokio::test]
async fn channel_metadata_successor_retains_authority_for_offline_members() {
    let (mut node, mut owner, owner_route) = channel_member_fixture("offline-handoff");
    let prepared = gcoms_mls::ChannelMember::prepare("offline").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let invite =
        owner.sign_invite_key_package(&package, "offline", gcoms_mls::Caps::member(), 3600);
    let admission = owner.admit(&invite, &package).unwrap();
    let mut offline =
        ChannelRole::Member(gcoms_mls::ChannelMember::join(prepared, &admission.welcome).unwrap());
    let channel = node.channels.get_mut("offline-handoff").unwrap();
    channel.role.receive(&admission.commit).unwrap();
    channel.directory.insert("owner".into(), owner_route);
    channel
        .directory
        .insert("offline".into(), route(33, offline.own_pseudonym()));
    let successor = channel.role.own_pseudonym();
    let original = owner.own_pseudonym();
    let mut owner = ChannelRole::Owner(owner);
    let mut payload = vec![crate::channel::CHAN_METADATA];
    payload.extend(
        crate::channel::metadata::Metadata::prepare(
            &mut owner,
            crate::channel::ChannelChange::Transfer(successor),
        )
        .unwrap(),
    );
    let transfer = owner.send(&payload).unwrap();
    let rejected = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let gate = rejected.clone();
    node.durable_state_sink = Some(Arc::new(move |_| {
        if gate.load(std::sync::atomic::Ordering::SeqCst) {
            Err("handoff save failed".into())
        } else {
            Ok(())
        }
    }));
    let (events, mut seen) = broadcast::channel(8);
    assert!(!deliver_mls(
        &mut node,
        "offline-handoff",
        &transfer,
        std::time::Instant::now(),
        &events
    ));
    assert_eq!(
        node.channels["offline-handoff"].role.owner(),
        Some(original)
    );
    assert!(node.channels["offline-handoff"].message_outbox.is_empty());
    assert!(seen.try_recv().is_err());
    rejected.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(deliver_mls(
        &mut node,
        "offline-handoff",
        &transfer,
        std::time::Instant::now(),
        &events
    ));
    let channel = node.channels.get_mut("offline-handoff").unwrap();
    let announcement = channel.message_outbox.values().next().unwrap();
    assert_eq!(announcement.expected.len(), 2);
    assert!(announcement.expected.contains_key(&offline.own_pseudonym()));
    let gcoms_mls::ReceiveOutcome::Application { payload, .. } =
        offline.receive(&announcement.wire).unwrap()
    else {
        panic!()
    };
    let Some(crate::channel::ChannelInner::Metadata(update)) =
        crate::channel::decode_inner(&payload)
    else {
        panic!()
    };
    assert!(crate::channel::metadata::Metadata::receive(&mut offline, [99; 32], &update).is_err());
    assert_eq!(offline.owner(), Some(original));
    crate::channel::metadata::Metadata::receive(&mut offline, successor, &update).unwrap();
    assert_eq!(offline.owner(), Some(successor));
    let removal = channel.role.stage_remove(original).unwrap();
    channel.role.merge_pending().unwrap();
    offline.receive(&removal.commit).unwrap();
    assert!(!offline
        .roster_members()
        .iter()
        .any(|member| member.pseudonym == original));
    assert_eq!(offline.owner(), Some(successor));
}

#[tokio::test]
async fn voluntary_owner_departure_waits_for_successor_announcement_ack() {
    use crate::node::channels::prepare_channel_control;
    let name = "handoff-ack-before-leave";
    let (mut node, owner, owner_route) = channel_member_fixture(name);
    node.durable_state_sink = Some(Arc::new(|_| Ok(())));
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let successor = node.channels[name].role.own_pseudonym();
    let mut owner = ChannelRole::Owner(owner);
    let original = owner.own_pseudonym();
    let (events, _) = broadcast::channel(16);
    for change in [
        crate::channel::ChannelChange::Transfer(successor),
        crate::channel::ChannelChange::Leave,
    ] {
        let mut payload = vec![crate::channel::CHAN_METADATA];
        payload.extend(crate::channel::metadata::Metadata::prepare(&mut owner, change).unwrap());
        let wire = owner.send(&payload).unwrap();
        assert!(deliver_mls(
            &mut node,
            name,
            &wire,
            std::time::Instant::now(),
            &events,
        ));
    }
    let epoch = node.channels[name].role.epoch();
    let (&id, announcement) = node.channels[name].message_outbox.iter().next().unwrap();
    let wire = announcement.wire.clone();
    assert!(announcement.expected.contains_key(&original));
    let state = Arc::new(Mutex::new(node));
    prepare_channel_control(&state, &events);
    {
        let state = state.lock().unwrap();
        let channel = &state.channels[name];
        assert_eq!(
            channel.role.epoch(),
            epoch,
            "departure invalidated the pending announcement"
        );
        assert_eq!(channel.message_outbox[&id].wire, wire);
        assert!(channel.directory.values().any(|r| r.pseudonym == original));
    }
    let gcoms_mls::ReceiveOutcome::Application { payload, .. } = owner.receive(&wire).unwrap()
    else {
        panic!("expected authenticated ownership announcement")
    };
    let Some(crate::channel::ChannelInner::Metadata(update)) =
        crate::channel::decode_inner(&payload)
    else {
        panic!("expected ownership metadata")
    };
    crate::channel::metadata::Metadata::receive(&mut owner, successor, &update).unwrap();
    let ack = owner
        .send(&crate::channel::encode_text_ack(id, false))
        .unwrap();
    {
        let mut state = state.lock().unwrap();
        deliver_mls(&mut state, name, &ack, std::time::Instant::now(), &events);
        assert!(state.channels[name].message_outbox.is_empty());
    }
    prepare_channel_control(&state, &events);
    let state = state.lock().unwrap();
    let channel = &state.channels[name];
    assert!(channel.role.epoch() > epoch);
    assert_eq!(channel.role.roster_members().len(), 1);
    assert_eq!(channel.role.owner(), Some(successor));
    assert!(!channel.directory.values().any(|r| r.pseudonym == original));
}

#[tokio::test]
async fn channel_removal_is_durable_before_archiving_or_route_close() {
    let (mut node, mut owner, _) = channel_member_fixture("leave-checkpoint");
    let member = node.channels["leave-checkpoint"].role.own_pseudonym();
    let commit = owner.stage_remove(member).unwrap().commit;
    node.channel_presence_opt_in
        .insert("leave-checkpoint".into());
    let rejected = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let gate = rejected.clone();
    node.durable_state_sink = Some(Arc::new(move |_| {
        if gate.load(std::sync::atomic::Ordering::SeqCst) {
            Err("removal save failed".into())
        } else {
            Ok(())
        }
    }));
    let epoch = node.channels["leave-checkpoint"].role.epoch();
    let (events, mut seen) = broadcast::channel(8);
    deliver_mls(
        &mut node,
        "leave-checkpoint",
        &commit,
        std::time::Instant::now(),
        &events,
    );
    assert_eq!(node.channels["leave-checkpoint"].role.epoch(), epoch);
    assert!(node.channel_presence_opt_in.contains("leave-checkpoint"));
    assert!(
        seen.try_recv().is_err(),
        "failed removal must remain retryable, not archived"
    );
    rejected.store(false, std::sync::atomic::Ordering::SeqCst);
    deliver_mls(
        &mut node,
        "leave-checkpoint",
        &commit,
        std::time::Instant::now(),
        &events,
    );
    assert!(!node.channels.contains_key("leave-checkpoint"));
    assert!(!node.channel_presence_opt_in.contains("leave-checkpoint"));
    assert!(matches!(seen.try_recv(), Ok(Ev::ChannelRemoved { .. })));
}

#[tokio::test]
async fn channel_metadata_close_rolls_back_pending_messages_when_save_fails() {
    let (mut node, owner, owner_route) = channel_member_fixture("close-checkpoint");
    node.channels
        .get_mut("close-checkpoint")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gate = failed.clone();
    node.durable_state_sink = Some(Arc::new(move |_| {
        if gate.load(std::sync::atomic::Ordering::SeqCst) {
            Err("close save failed".into())
        } else {
            Ok(())
        }
    }));
    let state = Arc::new(Mutex::new(node));
    prepare_channel_text(&state, "close-checkpoint", b"unconfirmed text", true).unwrap();
    let mut owner = crate::channel::ChannelRole::Owner(owner);
    let mut payload = vec![crate::channel::CHAN_METADATA];
    payload.extend(
        crate::channel::metadata::Metadata::prepare(
            &mut owner,
            crate::channel::ChannelChange::Close,
        )
        .unwrap(),
    );
    let wire = owner.send(&payload).unwrap();
    let (events, mut seen) = broadcast::channel(8);
    let mut node = state.lock().unwrap();
    failed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(!deliver_mls(
        &mut node,
        "close-checkpoint",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    let channel = &node.channels["close-checkpoint"];
    assert!(!crate::channel::metadata::Metadata::read(&channel.role)
        .unwrap()
        .closed());
    assert_eq!(channel.message_outbox.len(), 1);
    assert!(channel.pending_control.is_empty());
    assert!(seen.try_recv().is_err());
    failed.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(deliver_mls(
        &mut node,
        "close-checkpoint",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    assert!(matches!(seen.try_recv(), Ok(Ev::ChannelRemoved { .. })));
    let channel = &node.channels["close-checkpoint"];
    assert!(crate::channel::metadata::Metadata::read(&channel.role)
        .unwrap()
        .closed());
    assert!(channel.message_outbox.is_empty());
    assert_eq!(
        channel.pending_control.len(),
        1,
        "closure ACK is durably retained"
    );
    assert!(
        seen.try_recv().is_err(),
        "discarded sends must never report delivery"
    );
}

#[tokio::test]
async fn channel_metadata_is_durable_before_publication_and_ack() {
    let (mut node, owner, owner_route) = channel_member_fixture("metadata");
    node.channels
        .get_mut("metadata")
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let rejected = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let gate = rejected.clone();
    node.durable_state_sink = Some(Arc::new(move |_| {
        if gate.load(std::sync::atomic::Ordering::SeqCst) {
            Err("metadata save failed".into())
        } else {
            Ok(())
        }
    }));
    let state = Arc::new(Mutex::new(node));
    assert!(prepare_channel_change(
        &state,
        "metadata",
        crate::channel::ChannelChange::Nickname("New nickname".into())
    )
    .is_err());
    {
        let node = state.lock().unwrap();
        let channel = &node.channels["metadata"];
        assert!(channel.role.channel_metadata().unwrap().is_empty());
        assert!(channel.message_outbox.is_empty());
    }
    let mut owner = crate::channel::ChannelRole::Owner(owner);
    let mut payload = vec![crate::channel::CHAN_METADATA];
    payload.extend(
        crate::channel::metadata::Metadata::prepare(
            &mut owner,
            crate::channel::ChannelChange::Topic("Retained topic".into()),
        )
        .unwrap(),
    );
    let wire = owner.send(&payload).unwrap();
    let (events, mut seen) = broadcast::channel(8);
    let mut node = state.lock().unwrap();
    assert!(!deliver_mls(
        &mut node,
        "metadata",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    assert!(seen.try_recv().is_err());
    let channel = &node.channels["metadata"];
    assert!(channel.role.channel_metadata().unwrap().is_empty());
    assert!(channel.pending_control.is_empty());
    assert!(channel.commit_ack_cache.is_empty());
    assert!(channel.unrouted_ack_journal.is_empty());
    rejected.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(deliver_mls(
        &mut node,
        "metadata",
        &wire,
        std::time::Instant::now(),
        &events
    ));
    assert!(matches!(
        seen.try_recv(),
        Ok(Ev::ChannelRosterChanged { .. })
    ));
    let channel = &node.channels["metadata"];
    assert_eq!(
        crate::channel::metadata::Metadata::read(&channel.role)
            .unwrap()
            .topic(),
        "Retained topic"
    );
    let (_, ack) = channel
        .pending_control
        .front()
        .expect("ACK retained only after successful checkpoint");
    assert!(
        matches!(owner.receive(ack).unwrap(), gcoms_mls::ReceiveOutcome::Application { payload, .. } if matches!(crate::channel::decode_inner(&payload), Some(crate::channel::ChannelInner::TextAck { .. })))
    );
}

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
async fn untracked_incomplete_recipient_identity_does_not_claim_durable_acceptance() {
    let (mut node, _, _) = channel_member_fixture("incomplete-send");
    // A directory entry with the right display name but the wrong authenticated
    // identity is not a complete recipient roster, even with a persistent sink.
    node.channels
        .get_mut("incomplete-send")
        .unwrap()
        .directory
        .insert("owner".into(), route(44, [0xE1; 32]));
    let saved = Arc::new(Mutex::new(Vec::new()));
    let capture = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        capture.lock().unwrap().push(bytes);
        Ok(())
    }));
    let scheduler = node.scheduler.clone();
    scheduler.shutdown();
    let state = Arc::new(Mutex::new(node));
    assert!(
        send_channel_text(&state, &scheduler, "incomplete-send", b"incomplete roster")
            .await
            .unwrap_err()
            .contains("channel send failed")
    );
    assert_eq!(saved.lock().unwrap().len(), 1);
    assert!(state.lock().unwrap().channels["incomplete-send"]
        .message_outbox
        .is_empty());
}

#[test]
fn both_channel_send_apis_reject_failed_native_commits_and_retain_only_successful_wire() {
    for tracked in [true, false] {
        let (mut node, mut owner, owner_route) = channel_member_fixture("failed-native");
        node.channels
            .get_mut("failed-native")
            .unwrap()
            .directory
            .insert("owner".into(), owner_route);
        node.durable_state_sink = Some(Arc::new(|_| Err("native commit failed".into())));
        let state = Arc::new(Mutex::new(node));
        let failure =
            prepare_channel_text(&state, "failed-native", b"must not be admitted", tracked);
        assert!(matches!(failure, Err(error) if error == "native commit failed"));
        {
            let node = state.lock().unwrap();
            assert!(node.channels["failed-native"].message_outbox.is_empty());
            assert!(node.last_channel_send.is_none());
        }
        let saved = Arc::new(Mutex::new(Vec::new()));
        let capture = saved.clone();
        state.lock().unwrap().durable_state_sink = Some(Arc::new(move |bytes| {
            capture.lock().unwrap().push(bytes);
            Ok(())
        }));
        // Only the subsequent successful preparation may be retained and
        // authenticate as application data against the original receiver.
        let prepared =
            prepare_channel_text(&state, "failed-native", b"actual admission", tracked).unwrap();
        drop(prepared); // Cancellation before network completion is not delivery.
        let archive = decode_v2(&saved.lock().unwrap()[0], &TEST_SEED).unwrap();
        let (id, pending) = &archive.channels[0].message_outbox[0];
        assert_eq!(crate::channel::msg_id("failed-native", &pending.wire), *id);
        assert!(pending.acknowledged.is_empty());
        let gcoms_mls::ReceiveOutcome::Application { payload, .. } =
            owner.receive_outcome(&pending.wire).unwrap()
        else {
            panic!("only the successfully committed application may be received");
        };
        assert!(matches!(crate::channel::decode_inner(&payload),
            Some(crate::channel::ChannelInner::Text { body, .. }) if body == b"actual admission"));
        assert_eq!(
            state.lock().unwrap().channels["failed-native"].message_outbox[id].wire,
            pending.wire
        );
    }
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

// A joined MLS roster can arrive before its authenticated directory bootstrap.
// Exercise the actual command queue, not a caller that retries rejected sends.
#[tokio::test(start_paused = true)]
async fn tracked_commands_wait_for_authenticated_recipient_routes_without_resubmitting() {
    let name = "pending-recipient-route";
    let (mut node, mut owner, owner_route) = channel_member_fixture(name);
    let saved = Arc::new(Mutex::new(Vec::new()));
    let capture = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        capture.lock().unwrap().push(bytes);
        Ok(())
    }));
    let scheduler = node.scheduler.clone();
    scheduler.shutdown(); // A failed first hop must retain durable acceptance.
    let state = Arc::new(Mutex::new(node));
    let (events_tx, mut events) = broadcast::channel(32);
    let (commands, cmd_rx) = mpsc::channel(8);
    let worker =
        super::super::commands::spawn_command_loop(super::super::commands::CommandLoopContext {
            state: state.clone(),
            frwd_admitted: Default::default(),
            scheduler,
            events_tx: events_tx.clone(),
            #[cfg(feature = "relay-host")]
            relay_host: None,
            cmd_rx,
        });
    let mut results = Vec::new();
    for text in [b"first".as_slice(), b"second".as_slice()] {
        let (done, receive) = tokio::sync::oneshot::channel();
        commands
            .send(Cmd::SendChannelTextTracked {
                channel: name.into(),
                text: text.to_vec(),
                done,
            })
            .await
            .unwrap();
        results.push(receive);
    }
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    for result in &mut results {
        assert!(
            matches!(
                result.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "a joined member must wait for its authenticated recipient route"
        );
    }
    assert!(saved.lock().unwrap().is_empty());
    {
        let st = state.lock().unwrap();
        assert!(st.channels[name].message_outbox.is_empty());
        assert!(st.last_channel_send.is_none());
    }
    // A route with the right display name and wrong authenticated member ID
    // cannot release the pending send.
    let wrong = owner
        .send(&crate::channel::encode_dir("owner", &route(31, [0xee; 32])))
        .unwrap();
    process_chan_cell(
        &mut state.lock().unwrap(),
        name,
        wrong,
        std::time::Instant::now(),
        &events_tx,
    );
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert!(matches!(
        results[0].try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let directory = owner
        .send(&crate::channel::encode_dir("owner", &owner_route))
        .unwrap();
    process_chan_cell(
        &mut state.lock().unwrap(),
        name,
        directory,
        std::time::Instant::now(),
        &events_tx,
    );
    let mut ids = Vec::new();
    for (result, expected) in results
        .into_iter()
        .zip([b"first".as_slice(), b"second".as_slice()])
    {
        let id = tokio::time::timeout(std::time::Duration::from_secs(2), result)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let wire = state.lock().unwrap().channels[name].message_outbox[&id]
            .wire
            .clone();
        assert_eq!(crate::channel::msg_id(name, &wire), id);
        let gcoms_mls::ReceiveOutcome::Application { payload, .. } =
            owner.receive_outcome(&wire).unwrap()
        else {
            panic!("pending send did not produce application data");
        };
        assert!(matches!(crate::channel::decode_inner(&payload),
            Some(crate::channel::ChannelInner::Text { body, .. }) if body == expected));
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(state.lock().unwrap().channels[name].message_outbox.len(), 2);
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Ev::ChannelDelivery { .. }),
            "hop completion is not delivery"
        );
    }
    let restored = decode_v2(saved.lock().unwrap().last().unwrap(), &TEST_SEED).unwrap();
    assert_eq!(restored.channels[0].message_outbox.len(), 2);
    for id in ids {
        let ack = owner
            .send(&crate::channel::encode_text_ack(id, false))
            .unwrap();
        process_chan_cell(
            &mut state.lock().unwrap(),
            name,
            ack,
            std::time::Instant::now(),
            &events_tx,
        );
    }
    assert!(state.lock().unwrap().channels[name]
        .message_outbox
        .is_empty());
    drop(commands);
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn tracked_route_wait_timeout_and_cancellation_never_commit_a_wire() {
    for cancel in [false, true] {
        let name = "pending-route-stop";
        let (mut node, mut owner, owner_route) = channel_member_fixture(name);
        let saves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = saves.clone();
        node.durable_state_sink = Some(Arc::new(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }));
        let state = Arc::new(Mutex::new(node));
        let epoch = state.lock().unwrap().channels[name].role.epoch();
        let start = tokio::time::Instant::now();
        let mut pending = Box::pin(prepare_tracked_channel_text_when_ready(
            &state,
            name,
            b"never committed",
            start + std::time::Duration::from_secs(120),
        ));
        if cancel {
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(1), &mut pending)
                    .await
                    .is_err()
            );
        } else {
            assert!(
                matches!(pending.as_mut().await, Err(error) if error.contains("send deadline"))
            );
            assert_eq!(start.elapsed(), std::time::Duration::from_secs(120));
        }
        drop(pending);
        {
            let st = state.lock().unwrap();
            assert_eq!(st.channels[name].role.epoch(), epoch);
            assert!(st.channels[name].message_outbox.is_empty());
            assert!(st.last_channel_send.is_none());
        }
        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 0);
        state
            .lock()
            .unwrap()
            .channels
            .get_mut(name)
            .unwrap()
            .directory
            .insert("owner".into(), owner_route);
        let _prepared = prepare_tracked_channel_text_when_ready(
            &state,
            name,
            b"only this wire",
            tokio::time::Instant::now() + std::time::Duration::from_secs(120),
        )
        .await
        .unwrap();
        let wire = state
            .lock()
            .unwrap()
            .last_channel_send
            .as_ref()
            .unwrap()
            .1
            .clone();
        let gcoms_mls::ReceiveOutcome::Application { payload, .. } =
            owner.receive_outcome(&wire).unwrap()
        else {
            panic!("only the later admitted wire can be received");
        };
        assert!(matches!(crate::channel::decode_inner(&payload),
            Some(crate::channel::ChannelInner::Text { body, .. }) if body == b"only this wire"));
        assert_eq!(state.lock().unwrap().channels[name].message_outbox.len(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn tracked_route_wait_does_not_retry_a_failed_commit() {
    let name = "pending-route-commit-failure";
    let (mut node, _, owner_route) = channel_member_fixture(name);
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let saves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = saves.clone();
    node.durable_state_sink = Some(Arc::new(move |_| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err("route-ready commit failure".into())
    }));
    let state = Arc::new(Mutex::new(node));
    let epoch = state.lock().unwrap().channels[name].role.epoch();
    let start = tokio::time::Instant::now();
    assert!(
        matches!(prepare_tracked_channel_text_when_ready(&state, name, b"failed", start + std::time::Duration::from_secs(120)).await,
        Err(error) if error == "route-ready commit failure")
    );
    assert_eq!(start.elapsed(), std::time::Duration::ZERO);
    assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 1);
    {
        let st = state.lock().unwrap();
        assert_eq!(st.channels[name].role.epoch(), epoch);
        assert!(st.channels[name].message_outbox.is_empty());
        assert!(st.last_channel_send.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn tracked_route_wait_does_not_commit_after_its_original_deadline() {
    let name = "late-recipient-route";
    let (mut node, _, owner_route) = channel_member_fixture(name);
    node.scheduler.shutdown();
    node.durable_state_sink = Some(Arc::new(|_| panic!("expired send reached persistence")));
    let state = Arc::new(Mutex::new(node));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut pending = Box::pin(prepare_tracked_channel_text_when_ready(
        &state, name, b"late", deadline,
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut pending)
            .await
            .is_err()
    );
    tokio::time::advance(std::time::Duration::from_secs(120)).await;
    state
        .lock()
        .unwrap()
        .channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    assert!(matches!(pending.await, Err(error) if error.contains("send deadline")));
    assert!(state.lock().unwrap().channels[name]
        .message_outbox
        .is_empty());
    assert!(state.lock().unwrap().last_channel_send.is_none());
}
