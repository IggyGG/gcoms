mod channel_pex_tests {
    use super::*;

    fn pair(name: &str) -> (NodeState, Arc<Mutex<NodeState>>) {
        let (mut receiver, owner, _) = channel_member_fixture(name);
        let owned = owned_channel_route(31, owner.own_pseudonym(), [44; 32]);
        let owner_route = owned.public.clone();
        let member_route = receiver.channels[name].own_route.public.clone();
        let mut owner_channel = ChannelState::new(
            ChannelRole::Owner(owner),
            owned,
            17,
            name.into(),
            crate::channel::ChannelVisibility::Private,
        );
        for (display, route) in [("owner", owner_route), ("member", member_route)] {
            owner_channel
                .directory
                .insert(display.into(), route.clone());
            owner_channel.learn(&route);
            let member = receiver.channels.get_mut(name).unwrap();
            member.directory.insert(display.into(), route.clone());
            member.learn(&route);
        }
        let mut sender = state();
        sender.channels.insert(name.into(), owner_channel);
        (sender, Arc::new(Mutex::new(receiver)))
    }

    #[tokio::test]
    async fn targeted_pex_exceeding_mls_forward_limit_does_not_advance_group_ratchet() {
        let name = "pex-no-group-ratchet";
        let (mut sender, receiver) = pair(name);
        // PEX must not alter the durable MLS/archive state or introduce a new
        // persistence operation: it reuses already retained pairwise key inputs.
        sender.durable_state_sink = Some(Arc::new(|_| panic!("PEX has no durable state mutation")));
        let cs = &sender.channels[name];
        let own_ref = crate::channel::PeerRef::from_route(&cs.own_route.public);
        let recipient = cs.directory["member"].pseudonym;
        let mut previous = None;
        for _ in 0..2001 {
            let (target, cell) =
                stage_channel_pex(name, cs, recipient, std::slice::from_ref(&own_ref), &[])
                    .unwrap();
            assert_eq!(target.pseudonym, recipient);
            assert_eq!(cell.cell_type(), Some(CellType::Msg));
            let envelope = crate::proto::ChannelDirectEnvelope::decode(&cell.payload).unwrap();
            assert_ne!(previous, Some((envelope.message_id, envelope.nonce)));
            previous = Some((envelope.message_id, envelope.nonce));
        }
        assert!(sender.channels[name].pending.is_empty());
        assert!(sender.channels[name].message_outbox.is_empty());
        assert!(sender.pending_channel_direct.is_empty());
        // The receiver has seen NONE of those 2001 targeted exchanges. A shared
        // MLS send ratchet would exceed the unchanged maximum distance2000 here.
        let wire = sender
            .channels
            .get_mut(name)
            .unwrap()
            .role
            .send(&crate::channel::encode_text(
                b"ordinary group message survives",
                false,
            ))
            .unwrap();
        let mut receiver = receiver.lock().unwrap();
        let result = receiver.channels.get_mut(name).unwrap().role.receive(&wire);
        assert!(matches!(
            result,
            Ok(gcoms_mls::ReceiveOutcome::Application { .. })
        ));
    }

    #[tokio::test]
    async fn pairwise_pex_authenticates_and_queues_only_original_ciphertext_without_direct_event() {
        let name = "pex-pairwise";
        let (sender, receiver) = pair(name);
        let cs = &sender.channels[name];
        let own_ref = crate::channel::PeerRef::from_route(&cs.own_route.public);
        let recipient = cs.directory["member"].pseudonym;
        {
            let mut st = receiver.lock().unwrap();
            let channel = st.channels.get_mut(name).unwrap();
            channel.note([5; 16], vec![6; 32]);
            channel.seen_direct.push_back([9; 16]);
        }
        let (_, cell) =
            stage_channel_pex(name, cs, recipient, std::slice::from_ref(&own_ref), &[]).unwrap();
        let (events, mut observed) = broadcast::channel(8);
        let mut altered = cell.payload.clone();
        *altered.last_mut().unwrap() ^= 1;
        handle_channel_direct(&receiver, &altered, &events);
        assert!(receiver.lock().unwrap().channels[name]
            .pull_outbox
            .is_empty());
        handle_channel_direct(&receiver, &cell.payload, &events);
        handle_channel_direct(&receiver, &cell.payload, &events);
        let st = receiver.lock().unwrap();
        let channel = &st.channels[name];
        assert_eq!(channel.pull_outbox.len(), 1);
        assert_eq!(
            channel.pull_outbox.front(),
            Some(&(own_ref, [5; 16], vec![6; 32]))
        );
        assert_eq!(channel.seen_direct, VecDeque::from([[9; 16]]));
        assert_eq!(channel.seen_pex.len(), 1);
        assert!(st.pending_channel_direct.is_empty());
        assert!(observed.try_recv().is_err());
    }

    #[tokio::test]
    async fn pairwise_pex_rejects_reflection_unknown_routes_wrong_channel_and_nonmembers() {
        let name = "pex-pairwise-auth";
        let (sender, receiver) = pair(name);
        let cs = &sender.channels[name];
        let own_ref = crate::channel::PeerRef::from_route(&cs.own_route.public);
        let recipient = cs.directory["member"].pseudonym;
        let member_ref = crate::channel::PeerRef::from_route(&cs.directory["member"]);
        let mut substituted = own_ref.clone();
        substituted.contact.queue_id = [99; 32];
        let unknown = crate::channel::PeerRef::from_route(&route(55, [56; 32]));
        receiver
            .lock()
            .unwrap()
            .channels
            .get_mut(name)
            .unwrap()
            .note([5; 16], vec![6; 32]);
        let before = receiver.lock().unwrap().channels[name].id_to_ref.clone();
        let (events, _) = broadcast::channel(8);
        for (channel, target) in [
            (name, member_ref),
            (name, substituted),
            ("other-channel", own_ref.clone()),
        ] {
            let plain = crate::channel::encode_channel_pex(channel, &[target], &[]).unwrap();
            let (_, envelope) =
                seal_channel_direct(name, cs, recipient, fresh_msg_id(), &plain).unwrap();
            handle_channel_direct(&receiver, &envelope.encode().unwrap(), &events);
            let st = receiver.lock().unwrap();
            assert!(st.channels[name].pull_outbox.is_empty());
            assert!(st.channels[name].seen_pex.is_empty());
            assert_eq!(st.channels[name].id_to_ref, before);
        }
        assert!(
            stage_channel_pex(name, cs, [0xff; 32], std::slice::from_ref(&own_ref), &[]).is_err()
        );
        let (_, cell) =
            stage_channel_pex(name, cs, recipient, &[own_ref, unknown.clone()], &[]).unwrap();
        handle_channel_direct(&receiver, &cell.payload, &events);
        let st = receiver.lock().unwrap();
        assert_eq!(st.channels[name].id_to_ref, before);
        assert!(!st.channels[name].overlay.view.contains(unknown.id));
        assert_eq!(st.channels[name].pull_outbox.len(), 1);
    }
}
