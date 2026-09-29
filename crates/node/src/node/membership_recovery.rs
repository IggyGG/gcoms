//! Explicit owner revocation, never an ACK or a timeout-based membership change.
use super::channels::completed_member_removal_key;
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryMember {
    pub member_id: [u8; 32],
    pub display_name: String,
    pub is_self: bool,
    pub missing_commit: bool,
    pub pending_messages: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipRecoveryStatus {
    pub channel_id: [u8; 32],
    pub epoch: u64,
    pub pending_commit: Option<[u8; 16]>,
    pub revision: [u8; 32],
    pub members: Vec<RecoveryMember>,
    pub retained_messages: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipRecoveryRequest {
    pub channel_id: [u8; 32],
    pub epoch: u64,
    pub pending_commit: Option<[u8; 16]>,
    pub revision: [u8; 32],
    pub remove_members: Vec<[u8; 32]>,
}

pub(crate) fn status(st: &NodeState, channel: &str) -> Result<MembershipRecoveryStatus, String> {
    let cs = st.channels.get(channel).ok_or("no channel")?;
    if !cs.role.is_owner() {
        return Err("channel recovery requires its owner".into());
    }
    let mut members: Vec<_> = cs
        .role
        .roster_members()
        .into_iter()
        .map(|m| RecoveryMember {
            member_id: m.pseudonym,
            display_name: m.display_name,
            is_self: m.pseudonym == cs.role.own_pseudonym(),
            missing_commit: cs.membership_outbox.as_ref().is_some_and(|p| {
                p.expected.contains_key(&m.pseudonym) && !p.acknowledged.contains(&m.pseudonym)
            }),
            pending_messages: cs
                .message_outbox
                .values()
                .filter(|p| {
                    p.expected.contains_key(&m.pseudonym) && !p.acknowledged.contains(&m.pseudonym)
                })
                .count() as u32,
        })
        .collect();
    members.sort_by_key(|m| m.member_id);
    let mut hash = Sha256::new();
    hash.update(b"GComs/member-recovery/v1\0");
    hash.update(cs.id.0);
    hash.update(cs.role.epoch().to_be_bytes());
    if let Some(p) = &cs.membership_outbox {
        hash.update([1]);
        hash.update(p.commit_id);
    } else {
        hash.update([0]);
    }
    for m in &members {
        hash.update(m.member_id);
        hash.update([u8::from(m.missing_commit)]);
    }
    let mut messages: Vec<_> = cs.message_outbox.iter().collect();
    messages.sort_by_key(|(id, _)| **id);
    for (id, pending) in messages {
        hash.update(id);
        let mut recipients: Vec<_> = pending.expected.keys().collect();
        recipients.sort();
        hash.update((recipients.len() as u64).to_be_bytes());
        for peer in recipients {
            hash.update(peer);
            hash.update([u8::from(pending.acknowledged.contains(peer))]);
        }
    }
    Ok(MembershipRecoveryStatus {
        channel_id: cs.id.0,
        epoch: cs.role.epoch(),
        pending_commit: cs.membership_outbox.as_ref().map(|p| p.commit_id),
        revision: hash.finalize().into(),
        members,
        retained_messages: cs.message_outbox.len() as u32,
    })
}

pub(crate) fn recover(
    st: &mut NodeState,
    channel: &str,
    request: &MembershipRecoveryRequest,
    events: &broadcast::Sender<Ev>,
) -> Result<MembershipRecoveryStatus, String> {
    if !cfg!(feature = "client-persist")
        || st.durable_state_sink.is_none()
        || st.owner_transition_failed
    {
        return Err("channel recovery requires healthy persistent state".into());
    }
    let before = status(st, channel)?;
    let removed: HashSet<_> = request.remove_members.iter().copied().collect();
    if removed.is_empty()
        || removed.len() != request.remove_members.len()
        || removed.len() > 256
        || before.channel_id != request.channel_id
    {
        return Err("invalid channel recovery selection".into());
    }
    let cs = &st.channels[channel];
    if removed.contains(&cs.role.own_pseudonym()) {
        return Err("cannot remove the channel owner".into());
    }
    // Exact repeated removal is inert even after the RPC reply was lost.
    if before.epoch > request.epoch
        && removed.iter().all(|id| {
            cs.completed_removals
                .contains(&completed_member_removal_key(id))
                && !before.members.iter().any(|m| m.member_id == *id)
        })
    {
        return Ok(before);
    }
    if before.epoch != request.epoch
        || before.pending_commit != request.pending_commit
        || before.revision != request.revision
    {
        return Err("channel changed; review recovery again".into());
    }
    if removed
        .iter()
        .any(|id| !before.members.iter().any(|m| m.member_id == *id))
    {
        return Err("selected member is not current".into());
    }
    if cs.membership_outbox.as_ref().is_some_and(|pending| {
        pending
            .expected
            .keys()
            .any(|id| !pending.acknowledged.contains(id) && !removed.contains(id))
    }) {
        return Err("select every member still awaiting the previous membership change".into());
    }
    if before
        .members
        .iter()
        .any(|m| !removed.contains(&m.member_id) && m.pending_messages != 0)
    {
        return Err("remaining members still have unconfirmed messages".into());
    }
    let _finalizer = cs
        .admission_finalizer
        .clone()
        .try_lock_owned()
        .map_err(|_| "membership operation is still running")?;
    let key = channel_archive_key(&st.identity_seed);
    let seed = channel_seed(st, channel);
    let checkpoint = cs.role.checkpoint(&key).map_err(|e| e.to_string())?;
    let mut candidate = cs
        .role
        .restore_checkpoint(&key, &checkpoint, || IdentityKeypair::from_seed(seed))
        .map_err(|e| e.to_string())?;
    let staged = candidate
        .stage_remove_members(&request.remove_members)
        .map_err(|e| e.to_string())?;
    candidate.merge_pending().map_err(|e| e.to_string())?;
    let survivors: HashSet<_> = before
        .members
        .iter()
        .filter(|m| !m.is_self && !removed.contains(&m.member_id))
        .map(|m| m.member_id)
        .collect();
    let expected: HashMap<_, _> = cs
        .directory
        .values()
        .filter(|r| survivors.contains(&r.pseudonym))
        .map(|r| (r.pseudonym, r.clone()))
        .collect();
    if expected.len() != survivors.len() {
        return Err("remaining member directory is incomplete".into());
    }
    let cs = st.channels.get_mut(channel).expect("held state");
    let old_role = std::mem::replace(&mut cs.role, candidate);
    let old_membership = cs.membership_outbox.take();
    let old_directory = cs.directory.clone();
    let old_removals = cs.completed_removals.clone();
    if !expected.is_empty() {
        cs.membership_outbox = Some(crate::channel::MembershipOutbox {
            commit_id: crate::channel::msg_id(channel, &staged.commit),
            epoch: cs.role.epoch(),
            commit: staged.commit.clone(),
            expected,
            acknowledged: HashSet::new(),
        });
    }
    cs.directory
        .retain(|_, route| !removed.contains(&route.pseudonym));
    for id in &removed {
        cs.completed_removals
            .insert(completed_member_removal_key(id));
    }
    // Admission records stay sealed for diagnostics; replay gates below reject
    // revoked leaves before looking up a cached Welcome or consuming an invite.
    if let Err(error) = persist_current_direct_state(st) {
        let cs = st.channels.get_mut(channel).expect("held state");
        cs.role = old_role;
        cs.membership_outbox = old_membership;
        cs.directory = old_directory;
        cs.completed_removals = old_removals;
        return Err(error);
    }
    let cs = st.channels.get_mut(channel).expect("held state");
    cs.id_to_ref
        .retain(|_, peer| !removed.contains(&peer.pseudonym));
    if cs.membership_outbox.is_none() {
        cs.membership_done.notify_waiters();
    }
    let channel_id = cs.id;
    for id in removed {
        withdraw_channel_presence(st, channel, id, events);
        st.channel_presence_counters
            .remove(&(channel.to_owned(), id));
    }
    let _ = events.send(Ev::ChannelRosterChanged {
        channel: channel.to_owned(),
        channel_id,
    });
    status(st, channel)
}

#[cfg(all(test, feature = "client-persist"))]
mod tests {
    use super::*;
    use crate::node::persist::tests::{established_owner_fixture, owned_channel_route, state};
    const CHANNEL: &str = "membership-recovery";

    fn fixture() -> (NodeState, Vec<gcoms_mls::ChannelMember>, Vec<Vec<u8>>) {
        let mut st = state();
        st.durable_state_sink = Some(Arc::new(|_| Ok(())));
        let mut cs = established_owner_fixture(CHANNEL);
        let mut members = Vec::new();
        let mut packages = Vec::new();
        for (byte, name) in [(83, "first"), (84, "second")] {
            let prepared = gcoms_mls::ChannelMember::prepare(name).unwrap();
            let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
            let route = owned_channel_route(
                byte,
                gcoms_mls::ChannelMember::prepared_pseudonym(&prepared),
                [byte; 32],
            );
            super::super::channels::stage_recovery_admission_fixture(
                &mut cs,
                CHANNEL,
                &route.public,
                &package,
                name,
            )
            .unwrap();
            let key: [u8; 32] = Sha256::digest(&package).into();
            members.push(
                gcoms_mls::ChannelMember::join(prepared, &cs.admission_cache[&key].welcome)
                    .unwrap(),
            );
            cs.directory.insert(name.into(), route.public.clone());
            packages.push(crate::channel::encode_join_package(&package, &route.public));
        }
        assert_eq!(members[0].epoch(), 1);
        assert_eq!(cs.role.epoch(), 2);
        let wire = cs
            .role
            .send(&crate::channel::encode_text(b"unconfirmed", false))
            .unwrap();
        let id = crate::channel::msg_id(CHANNEL, &wire);
        cs.message_outbox.insert(
            id,
            crate::channel::ChannelMessageOutbox {
                wire,
                expected: cs
                    .directory
                    .values()
                    .filter(|r| r.pseudonym != cs.role.own_pseudonym())
                    .map(|r| (r.pseudonym, r.clone()))
                    .collect(),
                acknowledged: HashSet::new(),
            },
        );
        st.channels.insert(CHANNEL.into(), cs);
        (st, members, packages)
    }

    fn request(st: &NodeState) -> MembershipRecoveryRequest {
        let s = status(st, CHANNEL).unwrap();
        MembershipRecoveryRequest {
            channel_id: s.channel_id,
            epoch: s.epoch,
            pending_commit: s.pending_commit,
            revision: s.revision,
            remove_members: s
                .members
                .iter()
                .filter(|m| !m.is_self)
                .map(|m| m.member_id)
                .collect(),
        }
    }

    #[tokio::test]
    async fn owner_recovery_revokes_stalled_members_without_ack_or_wire_loss() {
        let (mut st, mut members, packages) = fixture();
        let req = request(&st);
        let original_id = st.channels[CHANNEL].id;
        let pending: Vec<_> = st.channels[CHANNEL]
            .message_outbox
            .iter()
            .map(|(id, p)| (*id, p.wire.clone()))
            .collect();
        let (events, mut receiver) = broadcast::channel(32);
        let after = recover(&mut st, CHANNEL, &req, &events).unwrap();
        assert_eq!(after.epoch, 3);
        assert_eq!(after.members.len(), 1);
        assert!(after.pending_commit.is_none());
        assert_eq!(st.channels[CHANNEL].id, original_id);
        for (id, wire) in &pending {
            let p = &st.channels[CHANNEL].message_outbox[id];
            assert_eq!(&p.wire, wire);
            assert!(p.acknowledged.is_empty());
        }
        while let Ok(event) = receiver.try_recv() {
            assert!(!matches!(event, Ev::ChannelDelivery { .. }));
        }
        let wire = st
            .channels
            .get_mut(CHANNEL)
            .unwrap()
            .role
            .send(b"owner-only")
            .unwrap();
        for member in &mut members {
            assert!(member.receive_outcome(&wire).is_err());
        }
        assert_eq!(recover(&mut st, CHANNEL, &req, &events).unwrap().epoch, 3);
        // A revoked leaf cannot replay its old cached admission.
        for package in packages {
            let (route, kp) = crate::channel::decode_join_package(&package).unwrap();
            assert!(super::super::channels::stage_recovery_admission_fixture(
                st.channels.get_mut(CHANNEL).unwrap(),
                CHANNEL,
                &route,
                kp,
                "first"
            )
            .unwrap_err()
            .contains("removed"));
        }
        // A genuinely fresh key with a reused nickname remains admissible.
        let fresh = gcoms_mls::ChannelMember::prepare("first").unwrap();
        let kp = gcoms_mls::ChannelMember::key_package_bytes(&fresh).unwrap();
        let route = owned_channel_route(
            85,
            gcoms_mls::ChannelMember::prepared_pseudonym(&fresh),
            [85; 32],
        );
        super::super::channels::stage_recovery_admission_fixture(
            st.channels.get_mut(CHANNEL).unwrap(),
            CHANNEL,
            &route.public,
            &kp,
            "first",
        )
        .unwrap();
        assert_eq!(st.channels[CHANNEL].role.epoch(), 4);
        st.scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_recovery_rejects_stale_partial_and_owner_selections() {
        let (mut st, _, _) = fixture();
        let original = request(&st);
        let (events, _) = broadcast::channel(8);
        let mut stale = original.clone();
        stale.revision[0] ^= 1;
        assert!(recover(&mut st, CHANNEL, &stale, &events)
            .unwrap_err()
            .contains("changed"));
        let missing = status(&st, CHANNEL)
            .unwrap()
            .members
            .into_iter()
            .find(|m| m.missing_commit)
            .unwrap()
            .member_id;
        let mut partial = original.clone();
        partial.remove_members.retain(|id| *id != missing);
        assert!(recover(&mut st, CHANNEL, &partial, &events)
            .unwrap_err()
            .contains("every member"));
        let mut owner = original.clone();
        owner
            .remove_members
            .push(st.channels[CHANNEL].role.own_pseudonym());
        assert!(recover(&mut st, CHANNEL, &owner, &events)
            .unwrap_err()
            .contains("owner"));
        let mut partial = original.clone();
        partial.remove_members = vec![missing];
        assert!(recover(&mut st, CHANNEL, &partial, &events)
            .unwrap_err()
            .contains("unconfirmed"));
        assert_eq!(request(&st), original);
        st.scheduler.shutdown();
    }

    #[tokio::test]
    async fn delegated_owner_uses_the_same_batch_removal_adapter() {
        let (mut st, mut members, _) = fixture();
        let cs = st.channels.get_mut(CHANNEL).unwrap();
        members[0]
            .receive_outcome(&cs.membership_outbox.as_ref().unwrap().commit)
            .unwrap();
        let first = members[0].own_pseudonym();
        let delegation = cs.role.propose_owner(first).unwrap();
        members[0].install_owner(&delegation).unwrap();
        let removed = vec![cs.role.own_pseudonym(), members[1].own_pseudonym()];
        let mut role = crate::channel::ChannelRole::Member(members.remove(0));
        assert!(role.is_owner());
        role.stage_remove_members(&removed).unwrap();
        role.merge_pending().unwrap();
        assert_eq!(role.roster_members().len(), 1);
        assert_eq!(role.own_pseudonym(), first);
        st.scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_recovery_keeps_survivor_commit_ack_and_rejects_spent_invite_replay() {
        let (mut st, mut members, packages) = fixture();
        let first = crate::channel::decode_join_package(&packages[0])
            .unwrap()
            .0
            .pseudonym;
        let second = crate::channel::decode_join_package(&packages[1])
            .unwrap()
            .0
            .pseudonym;
        {
            let cs = st.channels.get_mut(CHANNEL).unwrap();
            let pending = cs.membership_outbox.as_mut().unwrap();
            members[0].receive_outcome(&pending.commit).unwrap();
            pending.acknowledged.insert(first);
            for message in cs.message_outbox.values_mut() {
                message.acknowledged.insert(first);
            }
        }
        let mut req = request(&st);
        req.remove_members = vec![second];
        let (events, _) = broadcast::channel(8);
        let after = recover(&mut st, CHANNEL, &req, &events).unwrap();
        assert_eq!(after.members.len(), 2);
        assert!(after.pending_commit.is_some());
        let cs = st.channels.get_mut(CHANNEL).unwrap();
        let pending = cs.membership_outbox.as_ref().unwrap();
        assert_eq!(
            pending.expected.keys().copied().collect::<Vec<_>>(),
            vec![first]
        );
        assert!(pending.acknowledged.is_empty());
        members[0].receive_outcome(&pending.commit).unwrap();
        let wire = cs.role.send(b"survivor only").unwrap();
        assert!(members[0].receive_outcome(&wire).is_ok());
        assert!(members[1].receive_outcome(&wire).is_err());
        let scheduler = st.scheduler.clone();
        let state = Arc::new(Mutex::new(st));
        let (id, secret, _) =
            super::super::channels::create_channel_invite(&state, CHANNEL, 60).unwrap();
        state
            .lock()
            .unwrap()
            .channels
            .get_mut(CHANNEL)
            .unwrap()
            .invites
            .get_mut(&id)
            .unwrap()
            .consumed = Some(second);
        assert!(super::super::channels::redeem_invite(
            &state,
            &scheduler,
            CHANNEL,
            &id,
            &secret,
            &packages[1],
            "second"
        )
        .await
        .unwrap_err()
        .contains("removed"));
        scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_recovery_reopen_retains_wire_revocation_and_idempotency() {
        let (mut st, _, _) = fixture();
        let request = request(&st);
        let (events, _) = broadcast::channel(8);
        let before: Vec<_> = st.channels[CHANNEL]
            .message_outbox
            .iter()
            .map(|(id, p)| (*id, p.wire.clone(), p.expected.len()))
            .collect();
        recover(&mut st, CHANNEL, &request, &events).unwrap();
        let encoded = persist::encode_state(&st).unwrap();
        let mut fresh = state();
        fresh.routing = Some(
            routing::RoutingRuntime::new(
                RoutingConfig::default(),
                gcoms_routing::Directory::new(),
                true,
            )
            .unwrap(),
        );
        fresh.durable_state_sink = Some(Arc::new(|_| Ok(())));
        let fresh = Arc::new(Mutex::new(fresh));
        let scheduler = fresh.lock().unwrap().scheduler.clone();
        persist::decode_state_at_startup(&fresh, &scheduler, &encoded)
            .await
            .unwrap();
        {
            let mut restored = fresh.lock().unwrap();
            assert_eq!(
                recover(&mut restored, CHANNEL, &request, &events)
                    .unwrap()
                    .epoch,
                3
            );
            assert_eq!(status(&restored, CHANNEL).unwrap().members.len(), 1);
            for (id, wire, count) in before {
                let p = &restored.channels[CHANNEL].message_outbox[&id];
                assert_eq!(p.wire, wire);
                assert_eq!(p.expected.len(), count);
                assert!(p.acknowledged.is_empty());
            }
        }
        scheduler.shutdown();
        st.scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_recovery_full_removal_history_fails_without_mutation() {
        let (mut st, _, _) = fixture();
        for value in 0u32..1024 {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&value.to_be_bytes());
            st.channels
                .get_mut(CHANNEL)
                .unwrap()
                .completed_removals
                .insert(completed_member_removal_key(&id));
        }
        let request = request(&st);
        let (events, mut receiver) = broadcast::channel(8);
        assert!(recover(&mut st, CHANNEL, &request, &events)
            .unwrap_err()
            .contains("history is full"));
        assert_eq!(status(&st, CHANNEL).unwrap().epoch, 2);
        assert_eq!(st.channels[CHANNEL].completed_removals.len(), 1024);
        assert!(receiver.try_recv().is_err());
        st.scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_recovery_failed_save_rolls_back_every_membership_field() {
        let (mut st, _, _) = fixture();
        let original = request(&st);
        let old = st.channels[CHANNEL]
            .membership_outbox
            .as_ref()
            .unwrap()
            .commit
            .clone();
        st.durable_state_sink = Some(Arc::new(|_| Err("recovery sink failure".into())));
        let (events, mut receiver) = broadcast::channel(8);
        assert!(recover(&mut st, CHANNEL, &original, &events)
            .unwrap_err()
            .contains("recovery sink failure"));
        assert_eq!(request(&st), original);
        assert_eq!(
            st.channels[CHANNEL]
                .membership_outbox
                .as_ref()
                .unwrap()
                .commit,
            old
        );
        assert!(st.channels[CHANNEL].completed_removals.is_empty());
        assert!(receiver.try_recv().is_err());
        st.scheduler.shutdown();
    }
}
