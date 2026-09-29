use gcoms_channel_service::{ChannelLog, Limits};
use gcoms_crypto::IdentityKeypair;
use gcoms_mls::hosted::*;

fn apply(
    log: &mut ChannelLog,
    actor: &mut HostedSession,
    recipient: &mut HostedSession,
    change: HostedPolicyChange,
) {
    let control = actor
        .create_control(change, "private moderation reason")
        .unwrap();
    log.append_control(&control, 1000 + actor.rules().revision())
        .unwrap();
    actor.apply_control(&control).unwrap();
    let event = recipient.apply_control(&control).unwrap();
    assert_eq!(event.reason.as_deref(), Some("private moderation reason"));
    assert_eq!(
        recipient.rules().revision(),
        log.observer().rules().revision()
    );
}

#[test]
fn roles_moderation_bans_exceptions_and_transfer_are_ordered_and_durable() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("channel.log");
    let root = IdentityKeypair::from_seed([90; 32]);
    let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
    let channel = owner.policy().channel_id();
    let limits = Limits {
        bytes: 128 * 1024 * 1024,
        records: 1000,
    };
    let mut log = ChannelLog::create(
        &path,
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
        limits,
    )
    .unwrap();
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let alice_id = prepared.member_id();
    let (mut alice, join) = prepared
        .join(log.observer(), &JoinPermit::public(), 100)
        .unwrap();
    log.append_join(&join, alice.proposed_group_info().unwrap(), 100)
        .unwrap();
    alice.accept_join(&join).unwrap();
    owner.receive(&join, 100).unwrap();
    let old_owner = owner.rules().owner();
    let prepared_before_moderation = alice.send_hosted(b"cannot sneak past new policy").unwrap();
    assert!(alice
        .create_control(
            HostedPolicyChange::Mode(HostedMode::Moderated, 1),
            "unauthorized"
        )
        .is_err());
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::Mode(HostedMode::Moderated, 1),
    );
    assert!(alice.send_hosted(b"muted").is_err());
    assert!(log
        .append_message(&prepared_before_moderation, 2000)
        .is_err());
    assert!(owner.receive_hosted(&prepared_before_moderation).is_err());
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::Role(alice_id, HostedRole::Voice),
    );
    let voiced = alice.send_hosted(b"voice can speak").unwrap();
    log.append_message(&voiced, 1000 + owner.rules().revision())
        .unwrap();
    assert_eq!(owner.receive_hosted(&voiced).unwrap(), b"voice can speak");
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::Operator(alice_id, 1),
    );
    assert!(alice.rules().operator(alice_id));
    assert!(alice.rules().voiced(alice_id));
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::Operator(alice_id, 0),
    );
    assert_eq!(
        alice.rules().role(alice_id),
        HostedRole::Voice,
        "removing op must preserve separately granted voice"
    );
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::AccessList(HostedAccessList::Ban, alice_id, 1),
    );
    assert!(alice.send_hosted(b"ban enforced").is_err());
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::AccessList(HostedAccessList::Exemption, alice_id, 1),
    );
    assert!(alice.send_hosted(b"exempt from ban").is_ok());
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::Role(alice_id, HostedRole::Operator),
    );
    apply(
        &mut log,
        &mut alice,
        &mut owner,
        HostedPolicyChange::Mode(HostedMode::InviteOnly, 1),
    );
    apply(
        &mut log,
        &mut alice,
        &mut owner,
        HostedPolicyChange::Discovery(HostedDiscovery::Secret),
    );
    apply(
        &mut log,
        &mut alice,
        &mut owner,
        HostedPolicyChange::Capacity(2),
    );
    assert!(alice
        .create_control(HostedPolicyChange::Transfer(old_owner), "not the owner")
        .is_err());
    assert!(alice
        .create_control(
            HostedPolicyChange::Role(old_owner, HostedRole::Member),
            "demote owner"
        )
        .is_err());
    apply(
        &mut log,
        &mut owner,
        &mut alice,
        HostedPolicyChange::Transfer(alice_id),
    );
    assert_eq!(owner.rules().role(old_owner), HostedRole::Member);
    assert_eq!(alice.rules().role(alice_id), HostedRole::Owner);
    assert!(owner
        .create_control(HostedPolicyChange::Close, "former owner")
        .is_err());
    apply(
        &mut log,
        &mut alice,
        &mut owner,
        HostedPolicyChange::Capacity(3),
    );
    let prepared = PreparedHostedJoin::new("charlie").unwrap();
    assert!(owner
        .policy()
        .permit_for(&root, log.observer(), prepared.member_id(), "charlie", 2000)
        .is_err());
    let permit = alice
        .permit_join(prepared.member_id(), "charlie", 2000)
        .unwrap();
    let now = 1000 + alice.rules().revision();
    let (mut charlie, join) = prepared.join(log.observer(), &permit, now).unwrap();
    log.append_join(&join, charlie.proposed_group_info().unwrap(), now)
        .unwrap();
    charlie.accept_join(&join).unwrap();
    owner.receive(&join, now).unwrap();
    alice.receive(&join, now).unwrap();
    let revision = alice.rules().revision();
    drop(log);
    let mut log = ChannelLog::open(&path, channel, limits).unwrap();
    assert_eq!(log.observer().rules().revision(), revision);
    assert_eq!(log.observer().rules().owner(), alice_id);
    assert_eq!(log.observer().rules().discovery(), HostedDiscovery::Secret);
    assert_eq!(log.observer().rules().capacity(), 3);
    assert!(log.observer().rules().mode(HostedMode::InviteOnly));
    apply(&mut log, &mut alice, &mut owner, HostedPolicyChange::Close);
    assert!(alice.send_hosted(b"closed").is_err());
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(25).any(|w| w == b"private moderation reason"));
}

#[test]
fn access_code_rotation_and_invite_exceptions_apply_to_current_revision() {
    let root = IdentityKeypair::from_seed([93; 32]);
    let old_code = HostedAccessCode::generate().unwrap();
    let mut owner = HostedSession::create_keyed(&root, "owner", 500, &old_code).unwrap();
    let mut public = HostedObserver::new(
        owner.policy().clone(),
        owner.policy().channel_id(),
        &owner.export_group_info().unwrap(),
    )
    .unwrap();
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let identity = prepared.member_id();
    let permit = old_code
        .permit_for(&public, identity, "alice", 1000)
        .unwrap();
    let (joining, commit) = prepared.join(&public, &permit, 100).unwrap();
    let new_code = HostedAccessCode::generate().unwrap();
    let change = owner
        .create_control(
            HostedPolicyChange::AccessCode(Some(new_code.verification_key())),
            "rotate",
        )
        .unwrap();
    public = public.stage_control(&change).unwrap();
    owner.apply_control(&change).unwrap();
    assert!(public
        .stage_join(&commit, joining.proposed_group_info().unwrap(), 101)
        .is_err());
    assert!(old_code
        .permit_for(&public, identity, "alice", 1000)
        .is_err());
    let prepared = joining.prepare_join_retry().unwrap();
    assert_eq!(prepared.member_id(), identity);
    let permit = new_code
        .permit_for(&public, identity, "alice", 1000)
        .unwrap();
    let (mut alice, commit) = prepared.join(&public, &permit, 102).unwrap();
    public = public
        .stage_join(&commit, alice.proposed_group_info().unwrap(), 102)
        .unwrap();
    alice.accept_join(&commit).unwrap();
    owner.receive(&commit, 102).unwrap();
    let bob = PreparedHostedJoin::new("bob").unwrap();
    let change = owner
        .create_control(
            HostedPolicyChange::AccessList(HostedAccessList::InviteException, bob.member_id(), 1),
            "invited identity",
        )
        .unwrap();
    public = public.stage_control(&change).unwrap();
    owner.apply_control(&change).unwrap();
    alice.apply_control(&change).unwrap();
    let (mut bob, commit) = bob
        .join(&public, &JoinPermit::public_for(&public), 103)
        .unwrap();
    public = public
        .stage_join(&commit, bob.proposed_group_info().unwrap(), 103)
        .unwrap();
    bob.accept_join(&commit).unwrap();
    owner.receive(&commit, 103).unwrap();
    alice.receive(&commit, 103).unwrap();
    assert_eq!(public.member_count(), 3);
    assert_eq!(bob.rules().revision(), public.rules().revision());
}

#[test]
fn a_prepared_join_cannot_bypass_a_new_ban_but_exemption_restores_admission() {
    let root = IdentityKeypair::from_seed([92; 32]);
    let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
    let mut public = HostedObserver::new(
        owner.policy().clone(),
        owner.policy().channel_id(),
        &owner.export_group_info().unwrap(),
    )
    .unwrap();
    let prepared = PreparedHostedJoin::new("target").unwrap();
    let target = prepared.member_id();
    let (joining, commit) = prepared.join(&public, &JoinPermit::public(), 100).unwrap();
    let ban = owner
        .create_control(
            HostedPolicyChange::AccessList(HostedAccessList::Ban, target, 1),
            "ban",
        )
        .unwrap();
    public = public.stage_control(&ban).unwrap();
    owner.apply_control(&ban).unwrap();
    assert!(public
        .stage_join(&commit, joining.proposed_group_info().unwrap(), 101)
        .is_err());
    assert!(owner.receive(&commit, 101).is_err());
    let exemption = owner
        .create_control(
            HostedPolicyChange::AccessList(HostedAccessList::Exemption, target, 1),
            "exempt",
        )
        .unwrap();
    public = public.stage_control(&exemption).unwrap();
    owner.apply_control(&exemption).unwrap();
    assert!(
        public
            .stage_join(&commit, joining.proposed_group_info().unwrap(), 102)
            .is_err(),
        "an old policy snapshot still requires a retry"
    );
    let retry = joining.prepare_join_retry().unwrap();
    assert_eq!(retry.member_id(), target);
    let (mut joining, commit) = retry
        .join(&public, &JoinPermit::public_for(&public), 102)
        .unwrap();
    public = public
        .stage_join(&commit, joining.proposed_group_info().unwrap(), 102)
        .unwrap();
    joining.accept_join(&commit).unwrap();
    owner.receive(&commit, 102).unwrap();
    assert_eq!(joining.rules().revision(), public.rules().revision());
    assert_eq!(public.member_count(), 2);
}

#[test]
fn single_use_invitation_survives_offline_creator_and_is_consumed_atomically() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("log");
    let limits = Limits {
        bytes: 64 * 1024 * 1024,
        records: 1000,
    };
    let root = IdentityKeypair::from_seed([104; 32]);
    let mut owner = HostedSession::create(&root, "owner", 500, false).unwrap();
    let channel = owner.policy().channel_id();
    let mut log = ChannelLog::create(
        &path,
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
        limits,
    )
    .unwrap();
    let invitation = HostedAccessCode::generate().unwrap();
    let verifier = invitation.verification_key();
    let grant = owner
        .create_control(HostedPolicyChange::Invitation(verifier, 1000), "single use")
        .unwrap();
    log.append_control(&grant, 100).unwrap();
    owner.apply_control(&grant).unwrap();
    drop(log);
    let mut log = ChannelLog::open(&path, channel, limits).unwrap();
    let alice = PreparedHostedJoin::new("alice").unwrap();
    let bob = PreparedHostedJoin::new("bob").unwrap();
    let alice_permit = invitation
        .invitation_permit(log.observer(), alice.member_id(), "alice", 500)
        .unwrap();
    let bob_permit = invitation
        .invitation_permit(log.observer(), bob.member_id(), "bob", 500)
        .unwrap();
    let (mut alice, a) = alice.join(log.observer(), &alice_permit, 101).unwrap();
    let (bob, b) = bob.join(log.observer(), &bob_permit, 101).unwrap();
    let info = alice.proposed_group_info().unwrap().to_vec();
    let receipt = log.append_join(&a, &info, 101).unwrap();
    alice.accept_join(&a).unwrap();
    assert_eq!(alice.rules().invitation_expiry(verifier), None);
    assert!(log
        .append_join(&b, bob.proposed_group_info().unwrap(), 102)
        .is_err());
    let bob = bob.prepare_join_retry().unwrap();
    assert!(invitation
        .invitation_permit(log.observer(), bob.member_id(), "bob", 500)
        .is_err());
    assert_eq!(log.observer().rules().invitation_expiry(verifier), None);
    owner.receive(&a, 101).unwrap();
    assert_eq!(owner.rules().invitation_expiry(verifier), None);
    drop(log);
    let mut log = ChannelLog::open(&path, channel, limits).unwrap();
    assert_eq!(log.observer().rules().invitation_expiry(verifier), None);
    assert_eq!(log.append_join(&a, &info, 102).unwrap(), receipt);
    let proof = invitation.read_proof(channel, [7; 32], 150).unwrap();
    assert!(log
        .observer()
        .verify_read(&proof, HostedReadScope::Snapshot, [7; 32], 102)
        .is_err());
    let secret = invitation.export_secret().unwrap();
    assert!(!std::fs::read(path)
        .unwrap()
        .windows(secret.len())
        .any(|part| part == secret.as_slice()));
}
