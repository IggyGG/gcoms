use super::*;
use crate::channel::{CachedAdmission, ChannelRole, ChannelState, ChannelVisibility};
use crate::node::persist::established_route_secret;
use crate::node::persist::tests::{established_owner_fixture, owned_channel_route, state};

fn current_owned(
    byte: u8,
    role: &ChannelRole,
    seed: &[u8; 32],
    name: &str,
) -> crate::channel::OwnedChannelRoute {
    let mut route = owned_channel_route(
        byte,
        role.own_pseudonym(),
        established_route_secret(seed, name, role),
    );
    let expiry = now_unix() + 3600;
    route.public.data.expiry = expiry;
    route.public.control.expiry = expiry;
    for alias in &mut route.aliases {
        alias.contact.expiry = expiry;
    }
    route
}
fn fixture() -> (NodeState, NodeState, Vec<u8>) {
    let name = "recovery";
    let mut a = state();
    let mut owner = established_owner_fixture(name);
    owner.own_route = current_owned(61, &owner.role, &a.identity_seed, name);
    owner
        .directory
        .insert("owner".into(), owner.own_route.public.clone());
    let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
    let mut own = owned_channel_route(
        62,
        pseudonym,
        channel_direct_secret(&a.identity_seed, &pseudonym),
    );
    own.public.data.expiry = now_unix() + 3600;
    own.public.control.expiry = now_unix() + 3600;
    for alias in &mut own.aliases {
        alias.contact.expiry = own.public.data.expiry;
    }
    stage_recovery_admission_fixture(&mut owner, name, &own.public, &package, "member").unwrap();
    let welcome = owner
        .admission_cache
        .values()
        .next()
        .unwrap()
        .welcome
        .clone();
    let role = ChannelRole::Member(gcoms_mls::ChannelMember::join(prepared, &welcome).unwrap());
    let mut member = ChannelState::new(role, own, 5, name.into(), ChannelVisibility::Private);
    member
        .directory
        .insert("owner".into(), owner.own_route.public.clone());
    member
        .directory
        .insert("member".into(), member.own_route.public.clone());
    owner
        .directory
        .insert("member".into(), member.own_route.public.clone());
    let mut b = state();
    a.channels.insert(name.into(), owner);
    b.channels.insert(name.into(), member);
    (a, b, welcome)
}
fn add_next(a: &mut NodeState) -> Vec<u8> {
    let prepared = gcoms_mls::ChannelMember::prepare("next").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
    let route = owned_channel_route(
        90,
        pseudonym,
        channel_direct_secret(&a.identity_seed, &pseudonym),
    );
    stage_recovery_admission_fixture(
        a.channels.get_mut("recovery").unwrap(),
        "recovery",
        &route.public,
        &package,
        "next",
    )
    .unwrap();
    a.channels["recovery"]
        .membership_outbox
        .as_ref()
        .unwrap()
        .commit
        .clone()
}
fn input(st: &Arc<Mutex<NodeState>>, wire: &[u8], events: &broadcast::Sender<Ev>) {
    for cell in crate::proto::encode_chan_cells("recovery", wire).unwrap() {
        handle_incoming(st, cell, events);
    }
}

#[tokio::test]
async fn delayed_authenticated_receipt_survives_the_channel_control_window() {
    let (mut sender, recipient, _) = fixture();
    let peer = recipient.channels["recovery"].own_route.public.clone();
    let channel = sender.channels.get_mut("recovery").unwrap();
    let wire = channel
        .role
        .send(&crate::channel::encode_text(b"retained command", false))
        .unwrap();
    let id = crate::channel::msg_id("recovery", &wire);
    channel.message_outbox.insert(
        id,
        crate::channel::ChannelMessageOutbox {
            wire: wire.clone(),
            expected: HashMap::from([(peer.pseudonym, peer)]),
            acknowledged: HashSet::new(),
        },
    );
    let sender = Arc::new(Mutex::new(sender));
    let recipient = Arc::new(Mutex::new(recipient));
    let (events, _) = broadcast::channel(32);
    input(&recipient, &wire, &events);
    let receipt = recipient.lock().unwrap().channels["recovery"].commit_ack_cache[&id]
        .1
        .clone();
    // ACKs are private MLS messages sharing this sender's application ratchet.
    // A delayed receipt may be overtaken by the rest of the bounded journal.
    for generation in 1..crate::channel::CHANNEL_ACK_LIMIT {
        let later = recipient
            .lock()
            .unwrap()
            .channels
            .get_mut("recovery")
            .unwrap()
            .role
            .send(&crate::channel::encode_text_ack(
                [generation as u8; 16],
                false,
            ))
            .unwrap();
        input(&sender, &later, &events);
    }
    assert!(sender.lock().unwrap().channels["recovery"]
        .message_outbox
        .contains_key(&id));
    input(&sender, &receipt, &events);
    let mut sender = sender.lock().unwrap();
    let channel = sender.channels.get_mut("recovery").unwrap();
    assert!(
        !channel.message_outbox.contains_key(&id),
        "only the exact authenticated delayed ACK may complete delivery"
    );
    assert!(channel.role.receive_authenticated(&receipt).is_err());
}

fn recovery_fanout_fixture(peers: u8) -> NodeState {
    let mut st = state();
    let name = "recovery";
    let owner = gcoms_mls::OwnerSession::create(
        IdentityKeypair::from_seed(channel_seed(&st, name)),
        "owner",
        64,
    )
    .unwrap();
    let role = ChannelRole::Owner(owner);
    let own = current_owned(61, &role, &st.identity_seed, name);
    let mut cs = ChannelState::new(role, own, 5, name.into(), ChannelVisibility::Private);
    cs.directory
        .insert("owner".into(), cs.own_route.public.clone());
    for i in 0..peers {
        let display = format!("member{i}");
        let prepared = gcoms_mls::ChannelMember::prepare(&display).unwrap();
        let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
        cs.role.stage_admit(&package, &display).unwrap();
        cs.role.merge_pending().unwrap();
        let mut route = owned_channel_route(100 + i, pseudonym, [100 + i; 32]).public;
        route.data.expiry = now_unix() + 3600;
        route.control.expiry = now_unix() + 3600;
        cs.directory.insert(display, route);
    }
    st.channels.insert(name.into(), cs);
    st.durable_state_sink = Some(Arc::new(|_| Ok(())));
    st
}

#[tokio::test]
async fn recovered_route_targets_every_current_peer_beyond_gossip_fanout() {
    let mut st = recovery_fanout_fixture(12);
    let cs = st.channels.get_mut("recovery").unwrap();
    let epoch = cs.role.epoch();
    let roster = cs.role.roster();
    let owned = cs.own_route.public.clone();
    let expected: Vec<_> = cs
        .directory
        .values()
        .filter(|route| route.pseudonym != owned.pseudonym)
        .cloned()
        .collect();
    // Directory history must not grant a removed/nonmember a fresh route.
    cs.directory.insert(
        "obsolete".into(),
        owned_channel_route(200, [200; 32], [201; 32]).public,
    );
    stage_recovered_route_announcements(&mut st, "recovery").unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 12);
    let wire = cs.route_announcement.as_ref().unwrap().wire.clone();
    for recipient in &expected {
        assert_eq!(
            cs.pending_control
                .iter()
                .filter(|(route, pending)| route == recipient && pending == &wire)
                .count(),
            1,
            "every authenticated member needs its own exact durable destination"
        );
    }
    assert!(
        cs.pending.is_empty(),
        "directory delivery cannot rely on gossip"
    );
    assert_eq!(cs.role.epoch(), epoch);
    assert_eq!(cs.role.roster(), roster);
    assert_eq!(cs.own_route.public, owned);
    stage_recovered_route_announcements(&mut st, "recovery").unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 12);
    assert_eq!(cs.route_announcement.as_ref().unwrap().wire, wire);
}

#[tokio::test]
async fn recovered_route_full_outbox_keeps_partial_progress_and_exact_retry() {
    let mut st = recovery_fanout_fixture(12);
    let cs = st.channels.get_mut("recovery").unwrap();
    let epoch = cs.role.epoch();
    let filler_route = cs.directory["member0"].clone();
    for i in 0..crate::channel::CHANNEL_ACK_LIMIT - 3 {
        cs.pending_control
            .push_back((filler_route.clone(), vec![i as u8]));
    }
    assert_eq!(
        stage_recovered_route_announcements(&mut st, "recovery").unwrap_err(),
        "channel control outbox is full"
    );
    let cs = st.channels.get_mut("recovery").unwrap();
    assert_eq!(cs.pending_control.len(), crate::channel::CHANNEL_ACK_LIMIT);
    let wire = cs.route_announcement.as_ref().unwrap().wire.clone();
    let partial: Vec<_> = cs
        .pending_control
        .iter()
        .filter(|(_, w)| w == &wire)
        .cloned()
        .collect();
    assert_eq!(partial.len(), 3);
    // Existing unrelated controls drain; the partial announcement remains.
    cs.pending_control.retain(|(_, w)| w == &wire);
    stage_recovered_route_announcements(&mut st, "recovery").unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 12);
    assert!(partial
        .iter()
        .all(|entry| cs.pending_control.contains(entry)));
    assert!(cs
        .pending_control
        .iter()
        .all(|(_, pending)| pending == &wire));
    assert_eq!(cs.role.epoch(), epoch);
}

#[tokio::test]
async fn recovered_route_progress_survives_drained_prefix_with_blocked_other_controls() {
    let mut st = recovery_fanout_fixture(12);
    let cs = st.channels.get_mut("recovery").unwrap();
    let filler = cs.directory["member0"].clone();
    for i in 0..crate::channel::CHANNEL_ACK_LIMIT - 3 {
        cs.pending_control
            .push_back((filler.clone(), vec![i as u8]));
    }
    let mut staged = std::collections::HashSet::new();
    let mut original_wire = None;
    for round in 0..4 {
        let result = stage_recovered_route_announcements(&mut st, "recovery");
        if round < 3 {
            assert_eq!(result.unwrap_err(), "channel control outbox is full");
        } else {
            result.unwrap();
        }
        let cs = st.channels.get_mut("recovery").unwrap();
        assert_eq!(cs.pending_control.len(), crate::channel::CHANNEL_ACK_LIMIT);
        let announcement = cs.route_announcement.as_ref().unwrap();
        let wire = announcement.wire.clone();
        assert_eq!(original_wire.get_or_insert_with(|| wire.clone()), &wire);
        if round < 3 {
            assert_eq!(announcement.recovery_targets.len(), (round + 1) * 3);
        } else {
            assert!(announcement.recovery_targets.is_empty());
        }
        // Only these announcements receive relay acceptance. The unrelated
        // blocked controls remain and must not starve the remaining peers.
        cs.pending_control.retain(|(target, pending)| {
            if pending == &wire {
                assert!(staged.insert(target.pseudonym), "prefix was staged twice");
                false
            } else {
                true
            }
        });
    }
    assert_eq!(staged.len(), 12);
    let cs = st.channels.get_mut("recovery").unwrap();
    assert_eq!(
        cs.pending_control.len(),
        crate::channel::CHANNEL_ACK_LIMIT - 3
    );
    cs.pending_control.clear();
    // A fresh recovery of the same route must send again after a completed
    // round, reusing the exact encrypted announcement rather than the cursor.
    stage_recovered_route_announcements(&mut st, "recovery").unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 12);
    assert!(cs
        .pending_control
        .iter()
        .all(|(_, w)| Some(w) == original_wire.as_ref()));
    assert!(cs
        .route_announcement
        .as_ref()
        .unwrap()
        .recovery_targets
        .is_empty());
}

#[tokio::test]
async fn recovered_route_partial_progress_cannot_skip_a_changed_owned_route() {
    let mut st = recovery_fanout_fixture(3);
    let cs = st.channels.get_mut("recovery").unwrap();
    let filler = cs.directory["member0"].clone();
    for i in 0..crate::channel::CHANNEL_ACK_LIMIT - 1 {
        cs.pending_control
            .push_back((filler.clone(), vec![i as u8]));
    }
    assert!(stage_recovered_route_announcements(&mut st, "recovery").is_err());
    let seed = st.identity_seed;
    let cs = st.channels.get_mut("recovery").unwrap();
    let old_wire = cs.route_announcement.as_ref().unwrap().wire.clone();
    assert_eq!(
        cs.route_announcement
            .as_ref()
            .unwrap()
            .recovery_targets
            .len(),
        1
    );
    cs.pending_control.clear();
    cs.own_route = current_owned(201, &cs.role, &seed, "recovery");
    stage_recovered_route_announcements(&mut st, "recovery").unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 3);
    let current = cs.route_announcement.as_ref().unwrap();
    assert_ne!(current.wire, old_wire);
    assert_eq!(current.route, cs.own_route.public);
    assert!(cs
        .pending_control
        .iter()
        .all(|(_, wire)| wire == &current.wire));
}

#[tokio::test]
async fn recovered_route_persistence_failure_retains_only_committed_destinations() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut st = recovery_fanout_fixture(3);
    let saves = Arc::new(AtomicUsize::new(0));
    let sink = saves.clone();
    st.durable_state_sink = Some(Arc::new(move |_| {
        if sink.fetch_add(1, Ordering::SeqCst) == 1 {
            Err("second destination save failed".into())
        } else {
            Ok(())
        }
    }));
    assert_eq!(
        stage_recovered_route_announcements(&mut st, "recovery").unwrap_err(),
        "second destination save failed"
    );
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 1);
    let committed = cs.pending_control[0].clone();
    stage_recovered_route_announcements(&mut st, "recovery").unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.pending_control.len(), 3);
    assert!(cs.pending_control.contains(&committed));
    assert!(cs
        .pending_control
        .iter()
        .all(|(_, wire)| wire == &committed.1));
}

#[tokio::test]
async fn recovery_expired_authenticated_carrier_preserves_generation_until_real_member_ack() {
    let (mut a, mut b, welcome) = fixture();
    b.identity_seed = [0xc3; 32];
    let identity = IdentityKeypair::from_seed(b.identity_seed);
    let (bundle, secrets) = identity.issue_bundle();
    b.info.identity_pk = identity.public_bytes();
    b.info.bundle = bundle.encode();
    b.secrets = Arc::new(secrets);
    assert_ne!(a.info.identity_pk, b.info.identity_pk);
    let original_epoch = b.channels["recovery"].role.epoch();
    let commit = add_next(&mut a);
    let current_epoch = a.channels["recovery"].role.epoch();
    assert_eq!(current_epoch, original_epoch + 1);
    // Reopen changes only transport ownership. The original MLS leaves remain.
    for (node, byte, who) in [(&mut a, 81, "owner"), (&mut b, 82, "member")] {
        let seed = node.identity_seed;
        let cs = node.channels.get_mut("recovery").unwrap();
        cs.own_route = current_owned(byte, &cs.role, &seed, "recovery");
        cs.directory.insert(who.into(), cs.own_route.public.clone());
    }
    let mut caller = b.info.public();
    for alias in &mut caller.aliases {
        alias.expiry = now_unix() + 3600;
    }
    let mut remembered = caller.clone();
    for alias in &mut remembered.aliases {
        alias.expiry = now_unix() - 1;
        alias.queue_id[0] ^= 1;
    }
    a.peer_routes
        .insert(caller.identity_pk.clone(), remembered.clone());
    a.peer_route_generations
        .insert(caller.identity_pk.clone(), 17);
    let routes_before = a.peer_routes.clone();
    let generations_before = a.peer_route_generations.clone();
    let cs = &a.channels["recovery"];
    let target = recovery_recipient(cs, cs.id, current_epoch, &welcome).unwrap();
    let carrier = recovery_carrier(&a, &caller, now_unix()).unwrap();
    assert_eq!(carrier, caller);
    assert_eq!(select_peer_route(&a, &caller).unwrap(), remembered);
    let (dir, _) = stage_own_route_announcement(&mut a, "recovery", &target).unwrap();
    assert_eq!(a.peer_routes, routes_before);
    assert_eq!(a.peer_route_generations, generations_before);
    let a = Arc::new(Mutex::new(a));
    let b = Arc::new(Mutex::new(b));
    let (events, _) = broadcast::channel(32);
    // A carrier selection or hop receipt alone has not acknowledged anything.
    assert!(a.lock().unwrap().channels["recovery"]
        .membership_outbox
        .as_ref()
        .unwrap()
        .acknowledged
        .is_empty());
    input(&b, &commit, &events);
    input(&b, &dir, &events);
    assert_eq!(
        b.lock().unwrap().channels["recovery"].role.epoch(),
        current_epoch
    );
    let replies = b.lock().unwrap().channels["recovery"]
        .pending_control
        .iter()
        .map(|(_, wire)| wire.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        a.lock().unwrap().channels["recovery"]
            .membership_outbox
            .as_ref()
            .unwrap()
            .commit,
        commit
    );
    for wire in replies {
        input(&a, &wire, &events);
    }
    let a = a.lock().unwrap();
    assert!(a.channels["recovery"].membership_outbox.is_none());
    assert_eq!(a.peer_routes, routes_before);
    assert_eq!(a.peer_route_generations, generations_before);
    assert_eq!(select_peer_route(&a, &caller).unwrap(), remembered);
}

#[tokio::test]
async fn recovery_carrier_keeps_live_authenticated_precedence_and_refuses_unavailable_routes() {
    let (mut node, _, _) = fixture();
    let now = now_unix();
    let mut caller = node.info.public();
    for alias in &mut caller.aliases {
        alias.expiry = now + 3600;
    }
    let mut remembered = caller.clone();
    remembered.aliases[0].queue_id[0] ^= 1;
    node.peer_routes
        .insert(caller.identity_pk.clone(), remembered.clone());
    node.peer_route_generations
        .insert(caller.identity_pk.clone(), 8);
    let routes = node.peer_routes.clone();
    let generations = node.peer_route_generations.clone();
    assert_eq!(recovery_carrier(&node, &caller, now).unwrap(), remembered);
    caller.aliases[0].expiry = now;
    assert_eq!(recovery_carrier(&node, &caller, now).unwrap(), remembered);
    node.peer_routes
        .get_mut(&caller.identity_pk)
        .unwrap()
        .aliases[0]
        .expiry = now;
    assert!(recovery_carrier(&node, &caller, now).is_err());
    caller.aliases[0].expiry = now + 3600;
    node.peer_routes
        .get_mut(&caller.identity_pk)
        .unwrap()
        .aliases
        .clear();
    assert!(recovery_carrier(&node, &caller, now).is_err());
    node.peer_routes.remove(&caller.identity_pk);
    assert!(recovery_carrier(&node, &caller, now).is_err());
    assert_eq!(node.peer_route_generations, generations);
    node.peer_routes = routes;
    node.peer_route_generations.clear();
    assert_eq!(recovery_carrier(&node, &caller, now).unwrap(), caller);
    assert!(node.peer_route_generations.is_empty());
}

#[tokio::test]
async fn recovery_original_commit_then_dir_accepts_old_and_already_advanced_member() {
    for already_advanced in [false, true] {
        let (mut a, mut b, welcome) = fixture();
        let original_epoch = b.channels["recovery"].role.epoch();
        let commit = add_next(&mut a);
        let current_epoch = a.channels["recovery"].role.epoch();
        assert_eq!(current_epoch, original_epoch + 1);
        let a_seed = a.identity_seed;
        let b_seed = b.identity_seed;
        let ca = a.channels.get_mut("recovery").unwrap();
        ca.own_route = current_owned(71, &ca.role, &a_seed, "recovery");
        ca.directory
            .insert("owner".into(), ca.own_route.public.clone());
        let cb = b.channels.get_mut("recovery").unwrap();
        cb.own_route = current_owned(72, &cb.role, &b_seed, "recovery");
        cb.directory
            .insert("member".into(), cb.own_route.public.clone());
        let fresh_a = ca.own_route.public.clone();
        let fresh_b = cb.own_route.public.clone();
        let recipient = recovery_recipient(ca, ca.id, current_epoch, &welcome).unwrap();
        let (dir, id) = stage_own_route_announcement(&mut a, "recovery", &recipient).unwrap();
        assert_eq!(
            stage_own_route_announcement(&mut a, "recovery", &recipient)
                .unwrap()
                .1,
            id
        );
        let a = Arc::new(Mutex::new(a));
        let b = Arc::new(Mutex::new(b));
        let (events, _) = broadcast::channel(32);
        if already_advanced {
            input(&b, &commit, &events);
        }
        input(&b, &commit, &events);
        input(&b, &dir, &events);
        {
            let b = b.lock().unwrap();
            let cs = &b.channels["recovery"];
            assert_eq!(cs.role.epoch(), current_epoch);
            assert_eq!(cs.directory["owner"], fresh_a);
        }
        // Transport/Dir reception has not forged the owner's membership ACK.
        assert_eq!(
            a.lock().unwrap().channels["recovery"]
                .membership_outbox
                .as_ref()
                .unwrap()
                .commit,
            commit
        );
        let replies = b.lock().unwrap().channels["recovery"]
            .pending_control
            .iter()
            .map(|(_, w)| w.clone())
            .collect::<Vec<_>>();
        for wire in replies {
            input(&a, &wire, &events);
        }
        let a = a.lock().unwrap();
        let cs = &a.channels["recovery"];
        assert_eq!(cs.directory["member"], fresh_b);
        assert!(
            cs.membership_outbox.is_none(),
            "only actual authenticated member ACK converges"
        );
        assert_eq!(cs.role.epoch(), current_epoch);
    }
}

#[tokio::test]
async fn recovery_cached_admission_cannot_authorize_removed_unknown_or_cross_group_leaf() {
    let (mut a, b, welcome) = fixture();
    let cs = a.channels.get_mut("recovery").unwrap();
    let id = cs.id;
    let epoch = cs.role.epoch();
    assert!(recovery_recipient(cs, id, epoch, &welcome).is_ok());
    assert!(recovery_recipient(cs, crate::channel::ChannelId([7; 32]), epoch, &welcome).is_err());
    assert!(recovery_recipient(cs, id, epoch + 1, &welcome).is_err());
    assert!(recovery_recipient(cs, id, epoch, b"unknown").is_err());
    assert!(recovery_recipient(&b.channels["recovery"], id, epoch, &welcome).is_err());
    let leaf = cs.directory["member"].pseudonym;
    let ChannelRole::Owner(owner) = &mut cs.role else {
        panic!("fixture owner")
    };
    owner.remove(leaf).unwrap();
    assert!(recovery_recipient(cs, id, cs.role.epoch(), &welcome).is_err());
    assert!(
        cs.admission_cache.values().any(|a| a.welcome == welcome),
        "historical admission remains"
    );
    cs.admission_cache.insert(
        [0; 32],
        CachedAdmission {
            name: "unknown".into(),
            pseudonym: [0; 32],
            welcome: vec![9],
        },
    );
    assert!(recovery_recipient(cs, id, cs.role.epoch(), &[9]).is_err());
}

#[tokio::test]
async fn recovery_announcement_rolls_back_mls_and_exact_outbox_on_persistence_failure() {
    let (mut a, _, _) = fixture();
    let peer = a.channels["recovery"].directory["member"].clone();
    let epoch = a.channels["recovery"].role.epoch();
    a.durable_state_sink = Some(Arc::new(|_| Err("fixture durable failure".into())));
    let result = stage_own_route_announcement(&mut a, "recovery", &peer);
    assert!(result.unwrap_err().contains("fixture durable failure"));
    let cs = &a.channels["recovery"];
    assert_eq!(cs.role.epoch(), epoch);
    assert!(cs.pending_control.is_empty());
    assert!(cs.route_announcement.is_none());
    a.durable_state_sink = Some(Arc::new(|_| Ok(())));
    let (wire, id) = stage_own_route_announcement(&mut a, "recovery", &peer).unwrap();
    assert_eq!(
        stage_own_route_announcement(&mut a, "recovery", &peer).unwrap(),
        (wire, id)
    );
    assert_eq!(a.channels["recovery"].pending_control.len(), 1);
}

#[tokio::test]
async fn recovery_lost_accepted_carrier_and_reciprocal_reply_reuse_exact_durable_wires() {
    let (mut a, mut b, welcome) = fixture();
    let a_seed = a.identity_seed;
    let b_seed = b.identity_seed;
    for (node, seed, byte, who) in [
        (&mut a, a_seed, 81, "owner"),
        (&mut b, b_seed, 82, "member"),
    ] {
        let cs = node.channels.get_mut("recovery").unwrap();
        cs.own_route = current_owned(byte, &cs.role, &seed, "recovery");
        cs.directory.insert(who.into(), cs.own_route.public.clone());
    }
    let cs = &a.channels["recovery"];
    let target = recovery_recipient(cs, cs.id, cs.role.epoch(), &welcome).unwrap();
    let (first, id) = stage_own_route_announcement(&mut a, "recovery", &target).unwrap();
    let before = b.channels["recovery"].directory["owner"].clone();
    // The modeled hop accepts but drops its application cell. This is not an
    // MLS ACK; no native receiver is invoked and no state can converge.
    let (sender, receipt) = crate::scheduler::Receipt::test_channel();
    assert!(sender
        .send(crate::scheduler::JobResult::HopAccepted(bytes::Bytes::new()))
        .is_ok());
    assert!(receipt.completion().await.accepted().is_ok());
    assert_eq!(b.channels["recovery"].directory["owner"], before);
    let (again, retry_id) = stage_own_route_announcement(&mut a, "recovery", &target).unwrap();
    assert_eq!((again.clone(), retry_id), (first, id));
    let a = Arc::new(Mutex::new(a));
    let b = Arc::new(Mutex::new(b));
    let (events, _) = broadcast::channel(32);
    input(&b, &again, &events);
    let reply = {
        let mut st = b.lock().unwrap();
        let cs = st.channels.get_mut("recovery").unwrap();
        let reply = cs.commit_ack_cache.get(&id).unwrap().1.clone();
        // Model successful push followed by a lost reciprocal Dir. The durable
        // reply association must survive removal from pending control.
        cs.pending_control.clear();
        reply
    };
    input(&b, &again, &events);
    let replayed = {
        let st = b.lock().unwrap();
        let cs = &st.channels["recovery"];
        assert_eq!(cs.pending_control.len(), 1);
        assert_eq!(cs.pending_control[0].1, reply);
        cs.pending_control[0].1.clone()
    };
    input(&a, &replayed, &events);
    assert_eq!(
        a.lock().unwrap().channels["recovery"].directory["member"],
        b.lock().unwrap().channels["recovery"].own_route.public
    );
    assert_eq!(
        b.lock().unwrap().channels["recovery"].directory["owner"],
        a.lock().unwrap().channels["recovery"].own_route.public
    );
}

#[tokio::test]
async fn recovery_received_directory_and_reply_commit_together_or_exact_wire_retries() {
    let (mut a, mut b, welcome) = fixture();
    let seed = a.identity_seed;
    let cs = a.channels.get_mut("recovery").unwrap();
    cs.own_route = current_owned(91, &cs.role, &seed, "recovery");
    cs.directory
        .insert("owner".into(), cs.own_route.public.clone());
    let current = cs.own_route.public.clone();
    let peer = recovery_recipient(cs, cs.id, cs.role.epoch(), &welcome).unwrap();
    let (wire, id) = stage_own_route_announcement(&mut a, "recovery", &peer).unwrap();
    let old = b.channels["recovery"].directory["owner"].clone();
    b.durable_state_sink = Some(Arc::new(|_| Err("received route durable failure".into())));
    let b = Arc::new(Mutex::new(b));
    let (events, _) = broadcast::channel(32);
    input(&b, &wire, &events);
    {
        let mut st = b.lock().unwrap();
        let cs = &st.channels["recovery"];
        assert_eq!(cs.directory["owner"], old);
        assert!(!cs.commit_ack_cache.contains_key(&id));
        assert!(cs.pending_control.is_empty());
        st.durable_state_sink = Some(Arc::new(|_| Ok(())));
    }
    input(&b, &wire, &events);
    let st = b.lock().unwrap();
    let cs = &st.channels["recovery"];
    assert_eq!(cs.directory["owner"], current);
    assert!(cs.commit_ack_cache.contains_key(&id));
    assert_eq!(cs.pending_control.len(), 1);
}

#[tokio::test]
async fn recovery_expired_local_route_keeps_authenticated_owner_dir_and_exact_ack() {
    for expired_index in [0, 1] {
        let (mut a, b, welcome) = fixture();
        let commit = add_next(&mut a);
        let commit_id = crate::channel::msg_id("recovery", &commit);
        let epoch = a.channels["recovery"].role.epoch();
        let seed = a.identity_seed;
        let owner = a.channels.get_mut("recovery").unwrap();
        owner.own_route = current_owned(93, &owner.role, &seed, "recovery");
        owner
            .directory
            .insert("owner".into(), owner.own_route.public.clone());
        let current_owner = owner.own_route.public.clone();
        let recipient = recovery_recipient(owner, owner.id, epoch, &welcome).unwrap();
        let (dir, dir_id) = stage_own_route_announcement(&mut a, "recovery", &recipient).unwrap();
        let a = Arc::new(Mutex::new(a));
        let b = Arc::new(Mutex::new(b));
        let (events, _) = broadcast::channel(32);
        input(&b, &commit, &events);
        let (original_ack, old_owner, expired_own) = {
            let mut st = b.lock().unwrap();
            let cs = st.channels.get_mut("recovery").unwrap();
            let expired = now_unix() - 1;
            cs.own_route.aliases[expired_index].contact.expiry = expired;
            if expired_index == 0 {
                cs.own_route.public.data.expiry = expired;
            } else {
                cs.own_route.public.control.expiry = expired;
            }
            (
                cs.commit_ack_cache[&commit_id].1.clone(),
                cs.directory["owner"].clone(),
                cs.own_route.public.clone(),
            )
        };
        // A genuine persistence failure must still roll back the authenticated
        // receive and route/ACK changes, permitting this exact Dir to retry.
        b.lock().unwrap().durable_state_sink = Some(Arc::new(|_| Err("fixture refusal".into())));
        input(&b, &dir, &events);
        {
            let st = b.lock().unwrap();
            let cs = &st.channels["recovery"];
            assert_eq!(cs.directory["owner"], old_owner);
            assert_eq!(
                cs.commit_ack_cache[&commit_id],
                (old_owner.clone(), original_ack.clone())
            );
        }
        b.lock().unwrap().durable_state_sink = Some(Arc::new(|_| Ok(())));
        input(&b, &dir, &events);
        {
            let st = b.lock().unwrap();
            let cs = &st.channels["recovery"];
            assert_eq!(
                cs.directory["owner"], current_owner,
                "authenticated owner route must not depend on a live local reply route"
            );
            assert_eq!(cs.role.epoch(), epoch);
            assert_eq!(
                cs.own_route.public, expired_own,
                "no local authority or expiry extension"
            );
            assert_eq!(
                cs.commit_ack_cache[&commit_id],
                (current_owner.clone(), original_ack.clone())
            );
            assert!(cs
                .pending_control
                .iter()
                .any(|(route, wire)| route == &current_owner && wire == &original_ack));
            assert!(
                !cs.commit_ack_cache.contains_key(&dir_id),
                "no unavailable reciprocal Dir fabricated"
            );
        }
        input(&a, &original_ack, &events);
        assert!(
            a.lock().unwrap().channels["recovery"]
                .membership_outbox
                .is_none(),
            "only original authenticated ACK converges membership"
        );
    }
}

fn reconnect_fixture() -> (NodeState, NodeState) {
    let (mut a, mut b, _) = fixture();
    a.durable_state_sink = Some(Arc::new(|_| Ok(())));
    b.durable_state_sink = Some(Arc::new(|_| Ok(())));
    let seed = a.identity_seed;
    let cs = a.channels.get_mut("recovery").unwrap();
    cs.own_route = current_owned(93, &cs.role, &seed, "recovery");
    cs.directory
        .insert("owner".into(), cs.own_route.public.clone());
    (a, b)
}

#[tokio::test]
async fn reconnect_export_is_independent_of_already_delivered_directory_wire() {
    let (mut a, mut b) = reconnect_fixture();
    let current = a.channels["recovery"].own_route.public.clone();
    b.channels
        .get_mut("recovery")
        .unwrap()
        .directory
        .insert("owner".into(), current);
    let recipient = a.channels["recovery"].directory["member"].clone();
    let (wire, id) = stage_own_route_announcement(&mut a, "recovery", &recipient).unwrap();
    let (events, _) = broadcast::channel(32);
    process_chan_cell(
        &mut b,
        "recovery",
        wire.clone(),
        std::time::Instant::now(),
        &events,
    );
    assert!(
        !b.channels["recovery"].commit_ack_cache.contains_key(&id),
        "an unchanged directory generates no reciprocal traffic"
    );
    let code = export_channel_reconnect(&mut a, "recovery").unwrap();
    let decoded =
        gcoms_transport::decode_b64url(code.strip_prefix(RECONNECT_PREFIX).unwrap()).unwrap();
    assert_ne!(&decoded[40..], wire);
    assert!(
        !a.channels["recovery"]
            .pending_control
            .iter()
            .any(|(_, pending)| pending == &decoded[40..]),
        "manual reconnect ciphertext must never race automatic delivery"
    );
    import_channel_reconnect(&mut b, "recovery", &code)
        .expect("a previously delivered directory must not consume the manual reconnect code");
    import_channel_reconnect(&mut b, "recovery", &code).expect("exact manual retry is idempotent");
}

#[tokio::test]
async fn reconnect_export_failure_preserves_ratchet_and_does_not_publish_a_cache() {
    let (mut a, mut b) = reconnect_fixture();
    let epoch = a.channels["recovery"].role.epoch();
    let pending = a.channels["recovery"].pending_control.clone();
    a.durable_state_sink = Some(Arc::new(|_| Err("export save failed".into())));
    assert!(export_channel_reconnect(&mut a, "recovery").is_err());
    assert_eq!(a.channels["recovery"].role.epoch(), epoch);
    assert!(a.channels["recovery"].reconnect_announcement.is_none());
    assert_eq!(a.channels["recovery"].pending_control, pending);
    a.durable_state_sink = Some(Arc::new(|_| Ok(())));
    let code = export_channel_reconnect(&mut a, "recovery").unwrap();
    assert_eq!(a.channels["recovery"].pending_control, pending);
    assert_eq!(export_channel_reconnect(&mut a, "recovery").unwrap(), code);
    import_channel_reconnect(&mut b, "recovery", &code).unwrap();
}

#[tokio::test]
async fn reconnect_code_authenticates_self_route_and_rolls_back_failed_save() {
    let (mut a, mut b) = reconnect_fixture();
    let old = b.channels["recovery"].directory["owner"].clone();
    let code = export_channel_reconnect(&mut a, "recovery").unwrap();
    assert_eq!(code, export_channel_reconnect(&mut a, "recovery").unwrap());
    let encoded = code.strip_prefix(RECONNECT_PREFIX).unwrap();
    let bytes = gcoms_transport::decode_b64url(encoded).unwrap();
    for index in [0, 39, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        let bad = format!("{RECONNECT_PREFIX}{}", encode_b64url(&changed));
        assert!(import_channel_reconnect(&mut b, "recovery", &bad).is_err());
        assert_eq!(b.channels["recovery"].directory["owner"], old);
    }
    assert!(import_channel_reconnect(&mut b, "recovery", &"x".repeat(8193)).is_err());
    b.durable_state_sink = Some(Arc::new(|_| Err("reconnect durable failure".into())));
    assert!(import_channel_reconnect(&mut b, "recovery", &code).is_err());
    assert_eq!(b.channels["recovery"].directory["owner"], old);
    b.durable_state_sink = Some(Arc::new(|_| Ok(())));
    import_channel_reconnect(&mut b, "recovery", &code).unwrap();
    assert_eq!(
        b.channels["recovery"].directory["owner"],
        a.channels["recovery"].own_route.public
    );
    let pending = b.channels["recovery"].pending_control.len();
    import_channel_reconnect(&mut b, "recovery", &code).unwrap();
    assert_eq!(b.channels["recovery"].pending_control.len(), pending);
    b.channels
        .get_mut("recovery")
        .unwrap()
        .own_route
        .public
        .data
        .expiry = now_unix() - 1;
    assert!(import_channel_reconnect(&mut b, "recovery", &code).is_err());
}

#[tokio::test]
async fn reconnect_rejects_other_member_route_text_and_expired_authority() {
    for mode in 0..3 {
        let (mut a, mut b) = reconnect_fixture();
        let cs = a.channels.get_mut("recovery").unwrap();
        let mut route = cs.own_route.public.clone();
        if mode == 2 {
            route.data.expiry = now_unix() - 1;
        }
        let payload = match mode {
            0 => crate::channel::encode_dir("member", &route),
            1 => b"not a directory announcement".to_vec(),
            _ => crate::channel::encode_dir("owner", &route),
        };
        let mut bytes = cs.id.0.to_vec();
        bytes.extend_from_slice(&cs.role.epoch().to_be_bytes());
        bytes.extend_from_slice(&cs.role.send(&payload).unwrap());
        let code = format!("{RECONNECT_PREFIX}{}", encode_b64url(&bytes));
        let old = b.channels["recovery"].directory.clone();
        assert!(import_channel_reconnect(&mut b, "recovery", &code).is_err());
        assert_eq!(b.channels["recovery"].directory, old);
    }
}
