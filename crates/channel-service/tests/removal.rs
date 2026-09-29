use gcoms_channel_service::{ChannelLog, Limits};
use gcoms_crypto::IdentityKeypair;
use gcoms_mls::{hosted::*, MlsError};

const NOW: u64 = 100;
const LIMITS: Limits = Limits {
    bytes: 128 * 1024 * 1024,
    records: 1000,
};

fn log(path: &std::path::Path, owner: &HostedSession) -> ChannelLog {
    ChannelLog::create(
        path,
        owner.policy().clone(),
        owner.policy().channel_id(),
        &owner.export_group_info().unwrap(),
        LIMITS,
    )
    .unwrap()
}
fn join(log: &mut ChannelLog, name: &str, members: &mut [&mut HostedSession]) -> HostedSession {
    let (mut member, commit) = PreparedHostedJoin::new(name)
        .unwrap()
        .join(log.observer(), &JoinPermit::public_for(log.observer()), NOW)
        .unwrap();
    log.append_join(&commit, member.proposed_group_info().unwrap(), NOW)
        .unwrap();
    member.accept_join(&commit).unwrap();
    for other in members {
        other.receive(&commit, NOW).unwrap();
    }
    member
}
fn control(
    log: &mut ChannelLog,
    actor: &mut HostedSession,
    others: &mut [&mut HostedSession],
    change: HostedPolicyChange,
) {
    let control = actor
        .create_control(change, "encrypted departure reason")
        .unwrap();
    log.append_control(&control, NOW).unwrap();
    actor.apply_control(&control).unwrap();
    for other in others {
        other.apply_control(&control).unwrap();
    }
}

#[test]
fn kick_rekeys_without_owner_and_persists_pending_work() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("log");
    let root = IdentityKeypair::from_seed([95; 32]);
    let mut owner = HostedSession::create(&root, "owner", 3, true).unwrap();
    let channel = owner.policy().channel_id();
    let mut log = log(&path, &owner);
    let mut alice = join(&mut log, "alice", &mut [&mut owner]);
    let mut bob = join(&mut log, "bob", &mut [&mut owner, &mut alice]);
    let bob_id = bob.member_id();
    let pre_kick = alice.send_hosted(b"old epoch after kick").unwrap();
    control(
        &mut log,
        &mut owner,
        &mut [&mut alice, &mut bob],
        HostedPolicyChange::Voice(bob_id, 1),
    );
    control(
        &mut log,
        &mut owner,
        &mut [&mut alice, &mut bob],
        HostedPolicyChange::Kick(bob_id),
    );
    assert!(!bob.active());
    assert!(bob.prepare_rekey().is_err());
    assert!(alice.send_hosted(b"must wait for fresh keys").is_err());
    assert!(owner
        .create_control(HostedPolicyChange::Capacity(4), "wait")
        .is_err());
    assert!(log.append_message(&pre_kick, NOW).is_err());
    assert_eq!(log.observer().member_count(), 2);
    let commit = alice.prepare_rekey().unwrap();
    assert!(alice.accept_rekey(b"wrong acceptance").is_err());
    let sealed = alice.persist(&[99; 32]).unwrap();
    drop(alice);
    let mut alice = HostedSession::restore(&[99; 32], &sealed, channel).unwrap();
    drop(log);
    let mut log = ChannelLog::open(&path, channel, LIMITS).unwrap();
    assert_eq!(log.observer().rules().pending_removals(), &[bob_id]);
    let receipt = log
        .append_join(&commit, alice.proposed_group_info().unwrap(), NOW)
        .unwrap();
    alice.accept_rekey(&commit).unwrap();
    assert!(alice.rules().pending_removals().is_empty());
    assert!(!alice.rules().voiced(bob_id));
    assert!(matches!(bob.receive(&commit, NOW), Err(MlsError::Removed)));
    assert!(!bob.active());
    let message = alice
        .send_hosted(b"only remaining members can decrypt")
        .unwrap();
    log.append_message(&message, NOW).unwrap();
    assert!(bob.receive_hosted(&message).is_err());
    // The offline owner recovers in order and can decrypt. Service acceptance
    // never counted as its delivery or substituted for its missing receive.
    owner.receive(&commit, NOW).unwrap();
    assert_eq!(
        owner.receive_hosted(&message).unwrap(),
        b"only remaining members can decrypt"
    );
    drop(log);
    let mut log = ChannelLog::open(&path, channel, LIMITS).unwrap();
    assert!(log.observer().rules().pending_removals().is_empty());
    assert_eq!(
        log.append_join(&commit, &alice.export_group_info().unwrap(), NOW)
            .unwrap(),
        receipt
    );
    let prepared = bob.prepare_rejoin("bob").unwrap();
    assert_eq!(prepared.member_id(), bob_id);
    let (mut bob, commit) = prepared
        .join(log.observer(), &JoinPermit::public_for(log.observer()), NOW)
        .unwrap();
    log.append_join(&commit, bob.proposed_group_info().unwrap(), NOW)
        .unwrap();
    bob.accept_join(&commit).unwrap();
    assert_eq!(bob.rules().role(bob_id), HostedRole::Member);
}

#[test]
fn newcomer_finishes_departure_with_every_existing_member_offline() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let root = IdentityKeypair::from_seed([96; 32]);
    let mut owner = HostedSession::create(&root, "owner", 2, true).unwrap();
    let mut log = log(&dir.path().join("log"), &owner);
    let mut departing = join(&mut log, "departing", &mut [&mut owner]);
    assert!(owner
        .create_control(HostedPolicyChange::Leave, "must transfer")
        .is_err());
    control(
        &mut log,
        &mut departing,
        &mut [&mut owner],
        HostedPolicyChange::Leave,
    );
    // Only public state is used to admit this member at the logical capacity.
    let mut newcomer = join(&mut log, "newcomer", &mut []);
    assert!(newcomer.send_hosted(b"old keys").is_err());
    let commit = newcomer.prepare_rekey().unwrap();
    log.append_join(&commit, newcomer.proposed_group_info().unwrap(), NOW)
        .unwrap();
    newcomer.accept_rekey(&commit).unwrap();
    log.append_message(&newcomer.send_hosted(b"fresh keys").unwrap(), NOW)
        .unwrap();
    assert_eq!(log.observer().member_count(), 2);
}

#[test]
fn same_identity_rejoin_clears_old_role_and_competing_rekey_recovers() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let root = IdentityKeypair::from_seed([97; 32]);
    let mut owner = HostedSession::create(&root, "owner", 3, true).unwrap();
    let mut log = log(&dir.path().join("log"), &owner);
    let mut alice = join(&mut log, "alice", &mut [&mut owner]);
    let mut bob = join(&mut log, "bob", &mut [&mut owner, &mut alice]);
    let bob_id = bob.member_id();
    control(
        &mut log,
        &mut owner,
        &mut [&mut alice, &mut bob],
        HostedPolicyChange::Operator(bob_id, 1),
    );
    control(
        &mut log,
        &mut bob,
        &mut [&mut owner, &mut alice],
        HostedPolicyChange::Leave,
    );
    let refused = alice.prepare_rekey().unwrap();
    let (mut rejoined, rejoin) = bob
        .prepare_rejoin("bob")
        .unwrap()
        .join(log.observer(), &JoinPermit::public_for(log.observer()), NOW)
        .unwrap();
    log.append_join(&rejoin, rejoined.proposed_group_info().unwrap(), NOW)
        .unwrap();
    rejoined.accept_join(&rejoin).unwrap();
    assert!(log
        .append_join(&refused, alice.proposed_group_info().unwrap(), NOW)
        .is_err());
    alice.receive(&rejoin, NOW).unwrap();
    owner.receive(&rejoin, NOW).unwrap();
    assert!(alice.accept_rekey(&refused).is_err());
    assert!(alice.proposed_group_info().is_err());
    assert_eq!(rejoined.rules().role(bob_id), HostedRole::Member);
    assert!(rejoined.rules().pending_removals().is_empty());
    let text = rejoined
        .send_hosted(b"back with the same scoped identity")
        .unwrap();
    log.append_message(&text, NOW).unwrap();
    assert_eq!(
        alice.receive_hosted(&text).unwrap(),
        b"back with the same scoped identity"
    );
    // A stable key cannot shed a ban through departure/rejoin.
    control(
        &mut log,
        &mut owner,
        &mut [&mut alice, &mut rejoined],
        HostedPolicyChange::AccessList(HostedAccessList::Ban, bob_id, 1),
    );
    control(
        &mut log,
        &mut rejoined,
        &mut [&mut owner, &mut alice],
        HostedPolicyChange::Leave,
    );
    assert!(rejoined
        .prepare_rejoin("bob")
        .unwrap()
        .join(log.observer(), &JoinPermit::public_for(log.observer()), NOW)
        .is_err());
}
