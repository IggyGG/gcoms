use super::*;
use crate::channel_invite::policy::{InvitationPolicy, InvitationPreset};
use std::sync::atomic::{AtomicBool, Ordering};

type Fixture = (Arc<Mutex<NodeState>>, Arc<AtomicBool>, Arc<Mutex<Vec<u8>>>);
fn fixture() -> Fixture {
    let mut node = tests::state();
    node.channels.insert(
        "friends".into(),
        tests::established_owner_fixture("friends"),
    );
    let fail = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(Mutex::new(Vec::new()));
    let failure = fail.clone();
    let saved = writes.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        if failure.load(Ordering::SeqCst) {
            return Err("injected enrollment storage failure".into());
        }
        *saved.lock().unwrap() = bytes;
        Ok(())
    }));
    (Arc::new(Mutex::new(node)), fail, writes)
}

#[tokio::test]
async fn reusable_invitation_management_is_durable_and_storage_failure_rolls_back() {
    let (state, fail, saved) = fixture();
    let policy = InvitationPreset::Friends.policy(now_unix()).unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(super::super::invitations::create(&state, "friends", policy).is_err());
    assert!(super::super::invitations::list(&state, "friends")
        .unwrap()
        .is_empty());
    fail.store(false, Ordering::SeqCst);
    let issued = super::super::invitations::create(&state, "friends", policy).unwrap();
    let bytes = saved.lock().unwrap().clone();
    let archived = decode_v2(&bytes, &[0xA5; 32]).unwrap();
    assert_eq!(
        archived.channels[0].invitations.records[0].summary(),
        issued.summary
    );
    assert!(!bytes.windows(32).any(|window| window == issued.secret));
    fail.store(true, Ordering::SeqCst);
    assert!(super::super::invitations::revoke(&state, "friends", issued.summary.id).is_err());
    assert_eq!(
        super::super::invitations::list(&state, "friends").unwrap()[0].revoked_at,
        None
    );
    fail.store(false, Ordering::SeqCst);
    let revoked = super::super::invitations::revoke(&state, "friends", issued.summary.id).unwrap();
    assert!(revoked.revoked_at.is_some());
    assert_eq!(revoked.revision, 2);
    let repeated = super::super::invitations::revoke(&state, "friends", issued.summary.id).unwrap();
    assert_eq!(repeated, revoked);
    let archived = decode_v2(&saved.lock().unwrap(), &[0xA5; 32]).unwrap();
    assert_eq!(
        archived.channels[0].invitations.records[0].summary(),
        revoked
    );
    let mut tampered = saved.lock().unwrap().clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(decode_v2(&tampered, &[0xA5; 32]).is_err());
    assert!(decode_v2(&bytes, &[0xA6; 32]).is_err());
    state.lock().unwrap().scheduler.shutdown();
}

#[tokio::test]
async fn reusable_welcome_and_bootstrap_are_atomic_and_retry_survives_revocation() {
    let (state, fail, saved) = fixture();
    let issued = super::super::invitations::create(
        &state,
        "friends",
        InvitationPolicy {
            expires_at: None,
            max_admissions: Some(2),
        },
    )
    .unwrap();
    let prepared = gcoms_mls::ChannelMember::prepare("newcomer").unwrap();
    let mls = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let route = tests::owned_channel_route(
        83,
        gcoms_mls::ChannelMember::prepared_pseudonym(&prepared),
        channel_direct_secret(
            &[0xA5; 32],
            &gcoms_mls::ChannelMember::prepared_pseudonym(&prepared),
        ),
    );
    let package = crate::channel::encode_join_package(&mls, &route.public);
    let scheduler = state.lock().unwrap().scheduler.clone();
    let epoch = state.lock().unwrap().channels["friends"].role.epoch();
    fail.store(true, Ordering::SeqCst);
    let failed = redeem_invite(
        &state,
        &scheduler,
        "friends",
        &issued.summary.id,
        &issued.secret,
        &package,
        "newcomer",
    )
    .await;
    assert!(failed
        .unwrap_err()
        .contains("injected enrollment storage failure"));
    {
        let st = state.lock().unwrap();
        let cs = &st.channels["friends"];
        assert_eq!(cs.role.epoch(), epoch);
        assert_eq!(cs.invitations.records[0].admissions, 0);
        assert!(cs.message_outbox.is_empty());
        assert!(cs.admission_cache.is_empty());
        assert_eq!(cs.directory.len(), 1);
        assert_eq!(scheduler.resource_snapshot().peak_jobs, 0);
    }
    fail.store(false, Ordering::SeqCst);
    let welcome = redeem_invite(
        &state,
        &scheduler,
        "friends",
        &issued.summary.id,
        &issued.secret,
        &package,
        "newcomer",
    )
    .await
    .unwrap();
    let archive = decode_v2(&saved.lock().unwrap(), &[0xA5; 32]).unwrap();
    assert_eq!(archive.channels[0].role.epoch(), epoch + 1);
    assert_eq!(archive.channels[0].invitations.records[0].admissions, 1);
    assert_eq!(
        archive.channels[0].invitations.records[0].redemptions[0].welcome,
        welcome
    );
    super::super::invitations::revoke(&state, "friends", issued.summary.id).unwrap();
    assert_eq!(
        redeem_invite(
            &state,
            &scheduler,
            "friends",
            &issued.summary.id,
            &issued.secret,
            &package,
            "newcomer"
        )
        .await
        .unwrap(),
        welcome
    );
    let mut joiner = tests::state();
    joiner.durable_state_sink = Some(Arc::new(|_| Ok(())));
    joiner.prepared.insert(
        1,
        PreparedChannelJoin {
            mls: prepared,
            route,
            display: "newcomer".into(),
        },
    );
    let (events, mut received) = broadcast::channel(8);
    join_channel(
        &mut joiner,
        1,
        "friends",
        crate::channel::ChannelVisibility::Private,
        &welcome,
        &events,
    )
    .unwrap();
    assert!(matches!(
        received.try_recv(),
        Ok(Ev::ChannelRosterChanged { .. })
    ));
    assert!(joiner.prepared.is_empty());
    assert_eq!(joiner.channels["friends"].directory.len(), 2);
    let ack = joiner.channels["friends"]
        .pending_control
        .front()
        .unwrap()
        .1
        .clone();
    let mut st = state.lock().unwrap();
    // deliver_mls returns whether this was user-visible text, not whether an
    // ACK was accepted. The persisted outbox and enrollment state prove that.
    deliver_mls(&mut st, "friends", &ack, std::time::Instant::now(), &events);
    assert!(st.channels["friends"].invitations.records[0].redemptions[0].confirmed);
    assert!(st.channels["friends"].message_outbox.is_empty());
    let archive = decode_v2(&saved.lock().unwrap(), &[0xA5; 32]).unwrap();
    assert!(archive.channels[0].invitations.records[0].redemptions[0].confirmed);
    st.scheduler.shutdown();
    joiner.scheduler.shutdown();
}

#[tokio::test]
async fn offline_reusable_members_do_not_block_joins_and_catch_up_in_order() {
    let (state, _, saved) = fixture();
    let scheduler = state.lock().unwrap().scheduler.clone();
    let issued = super::super::invitations::create(
        &state,
        "friends",
        InvitationPolicy {
            expires_at: None,
            max_admissions: Some(3),
        },
    )
    .unwrap();
    let (events, _) = broadcast::channel(32);
    let mut members = Vec::new();
    for (i, name) in ["alice", "bob", "carol"].iter().enumerate() {
        let prepared = gcoms_mls::ChannelMember::prepare(name).unwrap();
        let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
        let route = tests::owned_channel_route(
            90 + i as u8,
            pseudonym,
            channel_direct_secret(&[0xA5; 32], &pseudonym),
        );
        let kp = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let package = crate::channel::encode_join_package(&kp, &route.public);
        let welcome = redeem_invite(
            &state,
            &scheduler,
            "friends",
            &issued.summary.id,
            &issued.secret,
            &package,
            name,
        )
        .await
        .unwrap();
        let mut member = tests::state();
        member.durable_state_sink = Some(Arc::new(|_| Ok(())));
        member.prepared.insert(
            1,
            PreparedChannelJoin {
                mls: prepared,
                route,
                display: name.to_string(),
            },
        );
        join_channel(
            &mut member,
            1,
            "friends",
            crate::channel::ChannelVisibility::Private,
            &welcome,
            &events,
        )
        .unwrap();
        members.push(member);
        // No bootstrap ACKs or membership commits reach any member yet.
    }
    let (commits, old_ack) = {
        let st = state.lock().unwrap();
        let cs = &st.channels["friends"];
        assert_eq!(cs.role.epoch(), 3);
        assert_eq!(cs.invitations.records[0].admissions, 3);
        assert_eq!(cs.membership_records().count(), 2);
        assert!(!cs.membership_barrier());
        let archive = decode_v2(&saved.lock().unwrap(), &[0xA5; 32]).unwrap();
        assert_eq!(archive.channels[0].membership_journal.len(), 1);
        (
            cs.membership_records()
                .map(|r| r.commit.clone())
                .collect::<Vec<_>>(),
            members[0].channels["friends"]
                .pending_control
                .front()
                .unwrap()
                .1
                .clone(),
        )
    };
    // The old epoch bootstrap ACK is accepted at epoch 3, for its actual leaf.
    deliver_mls(
        &mut state.lock().unwrap(),
        "friends",
        &old_ack,
        std::time::Instant::now(),
        &events,
    );
    assert!(
        state.lock().unwrap().channels["friends"]
            .invitations
            .records[0]
            .redemptions[0]
            .confirmed
    );
    // Out-of-order delivery must buffer the future commit, then drain in order.
    process_chan_cell(
        &mut members[0],
        "friends",
        commits[1].clone(),
        std::time::Instant::now(),
        &events,
    );
    assert_eq!(members[0].channels["friends"].role.epoch(), 1);
    process_chan_cell(
        &mut members[0],
        "friends",
        commits[0].clone(),
        std::time::Instant::now(),
        &events,
    );
    assert_eq!(members[0].channels["friends"].role.epoch(), 3);
    let alice = members[0].channels["friends"].role.own_pseudonym();
    let acks = members[0].channels["friends"]
        .pending_control
        .iter()
        .map(|(_, w)| w.clone())
        .collect::<Vec<_>>();
    for ack in acks {
        deliver_mls(
            &mut state.lock().unwrap(),
            "friends",
            &ack,
            std::time::Instant::now(),
            &events,
        );
    }
    let st = state.lock().unwrap();
    assert!(st.channels["friends"]
        .membership_records()
        .all(|r| !r.expected.contains_key(&alice) || r.acknowledged.contains(&alice)));
    assert!(
        st.channels["friends"].membership_pending(),
        "Bob's ACK must not be fabricated"
    );
    st.scheduler.shutdown();
    for member in members {
        member.scheduler.shutdown();
    }
}

#[tokio::test]
async fn authenticated_installation_cannot_consume_a_second_admission() {
    let (state, _, _) = fixture();
    let scheduler = state.lock().unwrap().scheduler.clone();
    let issued = super::super::invitations::create(
        &state,
        "friends",
        InvitationPreset::Friends.policy(now_unix()).unwrap(),
    )
    .unwrap();
    let mut first = Vec::new();
    for (i, name) in ["first", "second"].iter().enumerate() {
        let prepared = gcoms_mls::ChannelMember::prepare(name).unwrap();
        let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
        let route = tests::owned_channel_route(
            120 + i as u8,
            pseudonym,
            channel_direct_secret(&[0xA5; 32], &pseudonym),
        );
        let package = crate::channel::encode_join_package(
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
            &route.public,
        );
        let result = super::super::channels::invitations_admission::redeem_reusable_invite(
            &state,
            &scheduler,
            "friends",
            &issued.summary.id,
            &issued.secret,
            &package,
            name,
            Some([99; 32]),
        );
        if i == 0 {
            let welcome = result.unwrap();
            first = package.clone();
            assert_eq!(
                super::super::channels::invitations_admission::redeem_reusable_invite(
                    &state,
                    &scheduler,
                    "friends",
                    &issued.summary.id,
                    &issued.secret,
                    &package,
                    name,
                    Some([99; 32])
                )
                .unwrap(),
                welcome
            );
        } else {
            assert!(result.unwrap_err().contains("already has an enrollment"));
        }
    }
    assert!(
        super::super::channels::invitations_admission::redeem_reusable_invite(
            &state,
            &scheduler,
            "friends",
            &issued.summary.id,
            &issued.secret,
            &first,
            "first",
            Some([98; 32])
        )
        .unwrap_err()
        .contains("another authenticated")
    );
    assert_eq!(
        state.lock().unwrap().channels["friends"]
            .invitations
            .records[0]
            .admissions,
        1
    );
    scheduler.shutdown();
}

#[tokio::test]
async fn removing_unconfirmed_enrollment_is_atomic_without_synthetic_delivery() {
    let (state, fail, saved) = fixture();
    let scheduler = state.lock().unwrap().scheduler.clone();
    let issued = super::super::invitations::create(
        &state,
        "friends",
        InvitationPreset::Friends.policy(now_unix()).unwrap(),
    )
    .unwrap();
    let prepared = gcoms_mls::ChannelMember::prepare("orphan").unwrap();
    let member = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
    let route =
        tests::owned_channel_route(125, member, channel_direct_secret(&[0xA5; 32], &member));
    let package = crate::channel::encode_join_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        &route.public,
    );
    redeem_invite(
        &state,
        &scheduler,
        "friends",
        &issued.summary.id,
        &issued.secret,
        &package,
        "orphan",
    )
    .await
    .unwrap();
    let epoch = state.lock().unwrap().channels["friends"].role.epoch();
    let (events, mut received) = broadcast::channel(32);
    fail.store(true, Ordering::SeqCst);
    assert!(super::super::channels::prepare_channel_removal(
        &state, "friends", member, &events, false
    )
    .unwrap_err()
    .contains("storage failure"));
    {
        let st = state.lock().unwrap();
        let cs = &st.channels["friends"];
        assert_eq!(cs.role.epoch(), epoch);
        assert_eq!(cs.invitations.records[0].summary().pending, 1);
        assert_eq!(cs.message_outbox.len(), 1);
        assert!(!cs.invitations.records[0].redemptions[0].removed);
    }
    fail.store(false, Ordering::SeqCst);
    super::super::channels::prepare_channel_removal(&state, "friends", member, &events, false)
        .unwrap();
    let archive = decode_v2(&saved.lock().unwrap(), &[0xA5; 32]).unwrap();
    let cs = &archive.channels[0];
    assert_eq!(cs.role.roster_members().len(), 1);
    assert_eq!(cs.invitations.records[0].summary().pending, 0);
    assert!(cs.invitations.records[0].redemptions[0].removed);
    assert!(!cs.invitations.records[0].redemptions[0].confirmed);
    assert!(cs.message_outbox.is_empty());
    assert!(received.try_recv().is_err());
    scheduler.shutdown();
}
