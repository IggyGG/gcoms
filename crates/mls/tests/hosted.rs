#![cfg(feature = "hosted-channels")]

use gcoms_crypto::IdentityKeypair;
use gcoms_mls::{hosted::*, MlsError, ReceiveOutcome};

fn fixture(public: bool, capacity: u32) -> (IdentityKeypair, HostedSession, HostedObserver) {
    let root = IdentityKeypair::from_seed([73; 32]);
    let owner = HostedSession::create(&root, "owner", capacity, public).unwrap();
    let policy = HostedPolicy::decode(
        &owner.policy().encode().unwrap(),
        owner.policy().channel_id(),
    )
    .unwrap();
    let service = HostedObserver::new(
        policy,
        owner.policy().channel_id(),
        &owner.export_group_info().unwrap(),
    )
    .unwrap();
    (root, owner, service)
}

#[test]
fn hosted_capacity_is_bounded_at_sixty_four_for_creation_and_policy_changes() {
    let root = IdentityKeypair::from_seed([74; 32]);
    assert_eq!(MAX_HOSTED_MEMBERS, 64);
    for limit in [0, 1, 65, 100, 500, u32::MAX] {
        assert!(HostedSession::create(&root, "owner", limit, true).is_err());
    }
    let (_, mut owner, mut service) = fixture(true, 2);
    let control = owner
        .create_control(HostedPolicyChange::Capacity(64), "supported maximum")
        .unwrap();
    service = service.stage_control(&control).unwrap();
    owner.apply_control(&control).unwrap();
    let revision = owner.rules().revision();
    for limit in [0, 1, 65, 100, 500, u32::MAX] {
        assert!(owner
            .create_control(HostedPolicyChange::Capacity(limit), "out of range")
            .is_err());
        assert_eq!(owner.rules().capacity(), 64);
        assert_eq!(owner.rules().revision(), revision);
        assert_eq!(service.rules().capacity(), 64);
    }
}

#[test]
fn public_joins_while_all_existing_members_are_offline_then_replay_and_chat() {
    let (_, mut owner, mut service) = fixture(true, 64);
    let (mut alice, first) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .unwrap();
    assert!(alice.send(b"too early").is_err());
    assert!(alice.accept_join(b"different commit").is_err());
    service.accept(&first, 100).unwrap();
    alice.accept_join(&first).unwrap();
    service
        .publish_group_info(&alice.export_group_info().unwrap())
        .unwrap();
    // Neither owner nor Alice processes any new traffic while Bob joins.
    let (mut bob, second) = PreparedHostedJoin::new("bob")
        .unwrap()
        .join(&service, &JoinPermit::public(), 101)
        .unwrap();
    service.accept(&second, 101).unwrap();
    bob.accept_join(&second).unwrap();
    service
        .publish_group_info(&bob.export_group_info().unwrap())
        .unwrap();
    assert_eq!(service.member_count(), 3);
    assert_eq!(owner.epoch(), HOSTED_GENESIS_EPOCH);
    owner.receive(&first, 100).unwrap();
    owner.receive(&second, 101).unwrap();
    alice.receive(&second, 101).unwrap();
    assert_eq!(owner.roster(), bob.roster());
    let wire = bob
        .send(b"encrypted even with public membership commits")
        .unwrap();
    assert!(!wire.windows(9).any(|w| w == b"encrypted"));
    assert!(
        service.accept(&wire, 102).is_err(),
        "public observer cannot decrypt application data"
    );
    assert!(
        matches!(owner.receive(&wire, 102).unwrap(), ReceiveOutcome::Application { payload, .. }
        if payload == b"encrypted even with public membership commits")
    );
    assert!(matches!(
        alice.receive(&wire, 102).unwrap(),
        ReceiveOutcome::Application { .. }
    ));
}

#[test]
fn private_permit_is_leaf_name_channel_epoch_and_expiry_bound() {
    let (root, mut owner, mut service) = fixture(false, 3);
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let permit = owner
        .policy()
        .permit(
            &root,
            HOSTED_GENESIS_EPOCH,
            prepared.member_id(),
            "alice",
            200,
        )
        .unwrap();
    let encoded = permit.encode().unwrap();
    assert!(JoinPermit::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    let wrong_leaf = PreparedHostedJoin::new("alice").unwrap();
    assert!(wrong_leaf.join(&service, &permit, 100).is_err());
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let wrong_name = owner
        .policy()
        .permit(
            &root,
            HOSTED_GENESIS_EPOCH,
            prepared.member_id(),
            "eve",
            200,
        )
        .unwrap();
    assert!(prepared.join(&service, &wrong_name, 100).is_err());
    assert!(PreparedHostedJoin::new("eve")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .is_err());
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let expired = owner
        .policy()
        .permit(
            &root,
            HOSTED_GENESIS_EPOCH,
            prepared.member_id(),
            "alice",
            100,
        )
        .unwrap();
    assert!(matches!(
        prepared.join(&service, &expired, 100),
        Err(MlsError::Expired)
    ));
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let permit = owner
        .policy()
        .permit(
            &root,
            HOSTED_GENESIS_EPOCH,
            prepared.member_id(),
            "alice",
            200,
        )
        .unwrap();
    let (mut alice, commit) = prepared.join(&service, &permit, 100).unwrap();
    assert!(matches!(
        service.accept(&commit, 200),
        Err(MlsError::Expired)
    ));
    assert!(matches!(
        owner.receive(&commit, 200),
        Err(MlsError::Expired)
    ));
    assert_eq!(service.epoch(), HOSTED_GENESIS_EPOCH);
    assert_eq!(owner.epoch(), HOSTED_GENESIS_EPOCH);
    service.accept(&commit, 100).unwrap();
    owner.receive(&commit, 100).unwrap();
    alice.accept_join(&commit).unwrap();
    assert!(service.accept(&commit, 100).is_err());
    assert!(owner.receive(&commit, 100).is_err());
    service
        .publish_group_info(&alice.export_group_info().unwrap())
        .unwrap();
    let prepared = PreparedHostedJoin::new("bob").unwrap();
    let stale = owner
        .policy()
        .permit(
            &root,
            HOSTED_GENESIS_EPOCH,
            prepared.member_id(),
            "bob",
            200,
        )
        .unwrap();
    assert!(prepared.join(&service, &stale, 100).is_err());
}

#[test]
fn sequencer_rejects_concurrent_old_epoch_join_and_wrong_snapshot() {
    let (_, owner, mut service) = fixture(true, 2);
    let genesis = owner.export_group_info().unwrap();
    let (mut alice, first) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .unwrap();
    let (_, second) = PreparedHostedJoin::new("bob")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .unwrap();
    service.accept(&first, 100).unwrap();
    alice.accept_join(&first).unwrap();
    assert!(service.accept(&second, 100).is_err());
    assert!(service.publish_group_info(&genesis).is_err());
    service
        .publish_group_info(&alice.export_group_info().unwrap())
        .unwrap();
    assert!(matches!(
        PreparedHostedJoin::new("bob")
            .unwrap()
            .join(&service, &JoinPermit::public(), 100),
        Err(MlsError::GroupFull)
    ));
    assert!(HostedObserver::new(
        owner.policy().clone(),
        owner.policy().channel_id(),
        &alice.export_group_info().unwrap()
    )
    .is_err());
}

#[test]
fn policy_and_profile_are_pinned_and_bounded() {
    let (root, owner, _) = fixture(false, 64);
    assert!(HostedSession::create(&root, "owner", 501, false).is_err());
    assert!(PreparedHostedJoin::new("bad\nname").is_err());
    assert!(PreparedHostedJoin::new(&"x".repeat(129)).is_err());
    let mut policy = owner.policy().encode().unwrap();
    assert!(HostedPolicy::decode(&policy, [0; 32]).is_err());
    policy[1] = 2;
    assert!(HostedPolicy::decode(&policy, owner.policy().channel_id()).is_err());
    assert!(HostedPolicy::decode(&vec![0; 16385], owner.policy().channel_id()).is_err());
}

#[test]
fn complete_join_bundle_is_validated_without_mutating_current_epoch() {
    let (_, mut owner, service) = fixture(true, 64);
    let (mut alice, commit) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .unwrap();
    assert!(service
        .stage_join(&commit, &owner.export_group_info().unwrap(), 100)
        .is_err());
    assert_eq!(service.epoch(), HOSTED_GENESIS_EPOCH);
    let next = service
        .stage_join(&commit, alice.proposed_group_info().unwrap(), 100)
        .unwrap();
    assert_eq!(
        service.epoch(),
        HOSTED_GENESIS_EPOCH,
        "staging must precede durable installation"
    );
    assert_eq!(next.epoch(), HOSTED_GENESIS_EPOCH + 1);
    alice.accept_join(&commit).unwrap();
    owner.receive(&commit, 100).unwrap();
    let (_, second) = PreparedHostedJoin::new("bob")
        .unwrap()
        .join(&next, &JoinPermit::public(), 101)
        .unwrap();
    owner.receive(&second, 101).unwrap();
    assert_eq!(owner.roster().len(), 3);
}

#[test]
fn duplicate_display_name_is_rejected_by_service_and_member() {
    let (_, mut owner, service) = fixture(true, 64);
    let (impostor, commit) = PreparedHostedJoin::new("owner")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .unwrap();
    assert!(service
        .stage_join(&commit, impostor.proposed_group_info().unwrap(), 100)
        .is_err());
    assert!(owner.receive(&commit, 100).is_err());
    assert_eq!(owner.epoch(), HOSTED_GENESIS_EPOCH);
}

#[test]
fn reusable_code_joins_privately_with_owner_offline_and_retries_same_identity() {
    let root = IdentityKeypair::from_seed([84; 32]);
    let code = HostedAccessCode::generate().unwrap();
    let secret = code.export_secret().unwrap();
    let owner = HostedSession::create_keyed(&root, "owner", 64, &code).unwrap();
    let policy = owner.policy().clone();
    let mut observer = HostedObserver::new(
        policy.clone(),
        policy.channel_id(),
        &owner.export_group_info().unwrap(),
    )
    .unwrap();
    drop(root);
    drop(owner);
    assert!(HostedAccessCode::import_secret(&code.verification_key()).is_err());
    let exported_policy = policy.encode().unwrap();
    assert!(!exported_policy
        .windows(secret.len())
        .any(|w| w == secret.as_slice()));
    let second_code = HostedAccessCode::import_secret(&secret).unwrap();
    let alice = PreparedHostedJoin::new("alice").unwrap();
    let permit = code
        .permit(&policy, observer.epoch(), alice.member_id(), "alice", 200)
        .unwrap();
    let (mut alice, first) = alice.join(&observer, &permit, 100).unwrap();
    let bob = PreparedHostedJoin::new("bob").unwrap();
    let bob_id = bob.member_id();
    let permit = second_code
        .permit(&policy, observer.epoch(), bob_id, "bob", 200)
        .unwrap();
    let (bob, stale) = bob.join(&observer, &permit, 100).unwrap();
    observer = observer
        .stage_join(&first, alice.proposed_group_info().unwrap(), 100)
        .unwrap();
    alice.accept_join(&first).unwrap();
    assert!(observer
        .stage_join(&stale, bob.proposed_group_info().unwrap(), 100)
        .is_err());
    let bob = bob.prepare_join_retry().unwrap();
    assert_eq!(bob.member_id(), bob_id);
    let permit = second_code
        .permit(&policy, observer.epoch(), bob_id, "bob", 200)
        .unwrap();
    let (mut bob, commit) = bob.join(&observer, &permit, 101).unwrap();
    observer = observer
        .stage_join(&commit, bob.proposed_group_info().unwrap(), 101)
        .unwrap();
    bob.accept_join(&commit).unwrap();
    alice.receive(&commit, 101).unwrap();
    let message = bob
        .send_hosted(b"private admission without an online owner")
        .unwrap();
    observer.verify_message(&message).unwrap();
    assert_eq!(
        alice.receive_hosted(&message).unwrap(),
        b"private admission without an online owner"
    );
    assert!(
        alice.prepare_join_retry().is_err(),
        "accepted members cannot reset their epoch"
    );
    let other = HostedAccessCode::generate().unwrap();
    assert!(other
        .permit(&policy, observer.epoch(), bob_id, "bob", 200)
        .is_err());
}

#[cfg(feature = "client-persist")]
#[test]
fn restart_preserves_pending_acceptance_and_encrypts_the_member_state() {
    let (_, mut owner, service) = fixture(true, 64);
    let channel = owner.policy().channel_id();
    let (alice, commit) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(&service, &JoinPermit::public(), 100)
        .unwrap();
    let sealed = alice.persist(&[19; 32]).unwrap();
    drop(alice);
    assert!(HostedSession::restore(&[20; 32], &sealed, channel).is_err());
    assert!(HostedSession::restore(&[19; 32], &sealed, [0; 32]).is_err());
    assert!(gcoms_mls::ChannelMember::restore(&[19; 32], &sealed).is_err());
    let mut alice = HostedSession::restore(&[19; 32], &sealed, channel).unwrap();
    assert!(alice.send(b"not accepted yet").is_err());
    let service = service
        .stage_join(&commit, alice.proposed_group_info().unwrap(), 100)
        .unwrap();
    assert_eq!(service.epoch(), HOSTED_GENESIS_EPOCH + 1);
    alice.accept_join(&commit).unwrap();
    let sealed = alice.persist(&[19; 32]).unwrap();
    drop(alice);
    let mut alice = HostedSession::restore(&[19; 32], &sealed, channel).unwrap();
    owner.receive(&commit, 100).unwrap();
    let message = alice.send(b"after reopening").unwrap();
    assert!(
        matches!(owner.receive(&message, 100).unwrap(), ReceiveOutcome::Application { payload, .. } if payload == b"after reopening")
    );
}

#[test]
#[ignore = "explicit release-mode 64-identity MLS scale gate; not an application/network qualification"]
fn sixty_four_real_members_and_ten_concurrent_senders() {
    let started = std::time::Instant::now();
    let (_, owner, mut service) = fixture(true, 64);
    let mut members = vec![owner];
    let mut max_commit = 0;
    let mut max_info = 0;
    for index in 1..64 {
        let (mut joining, commit) = PreparedHostedJoin::new(&format!("member-{index}"))
            .unwrap()
            .join(&service, &JoinPermit::public(), 100 + index as u64)
            .unwrap();
        let info = joining.proposed_group_info().unwrap();
        max_commit = max_commit.max(commit.len());
        max_info = max_info.max(info.len());
        service = service
            .stage_join(&commit, info, 100 + index as u64)
            .unwrap();
        joining.accept_join(&commit).unwrap();
        // Acceptance precedes all existing member processing/acknowledgment.
        for member in &mut members {
            member.receive(&commit, 100 + index as u64).unwrap();
        }
        members.push(joining);
        if index % 50 == 0 {
            eprintln!(
                "hosted scale: {} real members in {:?}",
                index + 1,
                started.elapsed()
            );
        }
    }
    assert_eq!(service.member_count(), 64);
    for member in &members {
        assert_eq!(member.roster().len(), 64);
    }
    let roster: std::collections::BTreeSet<_> = members[0]
        .roster()
        .into_iter()
        .map(|m| m.pseudonym)
        .collect();
    assert_eq!(roster.len(), 64);
    let admission_seconds = started.elapsed().as_secs_f64();
    let messages = std::thread::scope(|scope| {
        let handles: Vec<_> = members
            .iter_mut()
            .take(10)
            .enumerate()
            .map(|(i, member)| {
                scope.spawn(move || {
                    member
                        .send_hosted(format!("concurrent sender {i}").as_bytes())
                        .unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut delivered = 0;
    for (sender, message) in messages.iter().enumerate() {
        service.verify_message(message).unwrap();
        for (receiver, member) in members.iter_mut().enumerate() {
            if sender == receiver {
                continue;
            }
            assert_eq!(
                member.receive_hosted(message).unwrap(),
                format!("concurrent sender {sender}").as_bytes()
            );
            delivered += 1;
        }
    }
    assert_eq!(delivered, 630);
    assert!(PreparedHostedJoin::new("overflow")
        .unwrap()
        .join(&service, &JoinPermit::public(), 1000)
        .is_err());
    eprintln!("hosted_scale_result members=64 senders=10 authenticated_receives={delivered} admission_seconds={admission_seconds:.3} total_seconds={:.3} max_commit_bytes={max_commit} max_info_bytes={max_info}", started.elapsed().as_secs_f64());
}
