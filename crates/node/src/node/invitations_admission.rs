use super::*;
use crate::channel_invite::{policy::Redemption, welcome};

/// The old compatibility path retains its convergence gate. The reusable path
/// checkpoints its entire result before any hop can observe the new epoch.
#[allow(clippy::too_many_arguments)]
pub(in crate::node) fn redeem_reusable_invite(
    state: &Arc<Mutex<NodeState>>,
    _scheduler: &RelayScheduler,
    channel: &str,
    id: &[u8; 16],
    secret: &[u8; 32],
    package: &[u8],
    name: &str,
    principal: Option<[u8; 32]>,
) -> Result<Vec<u8>, String> {
    if name.is_empty() || name.len() > 1024 || channel.len() > u16::MAX as usize {
        return Err("invalid enrollment name".into());
    }
    let (route, mls) =
        crate::channel::decode_join_package(package).ok_or("bad channel join package")?;
    if gcoms_mls::pseudonym_of_key_package(mls) != Some(route.pseudonym) {
        return Err("channel route does not match MLS leaf".into());
    }
    let request: [u8; 32] = Sha256::digest(mls).into();
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    invitations::require_durable(&st)?;
    let key = channel_archive_key(&st.identity_seed);
    let seed = channel_seed(&st, channel);
    let cs = st.channels.get_mut(channel).ok_or("no channel")?;
    if !cs.role.is_owner() || crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
        return Err("channel owner is unavailable".into());
    }
    if cs
        .completed_removals
        .contains(&completed_member_removal_key(&route.pseudonym))
    {
        return Err("member was removed; use a fresh invitation and join identity".into());
    }
    if let Some(result) = cs.invitations.authorize(
        id,
        secret,
        &cs.role.own_pseudonym(),
        &request,
        &route.pseudonym,
        name,
        now_unix(),
    )? {
        if principal.is_some() && result.principal != principal {
            return Err("enrollment belongs to another authenticated installation".into());
        }
        let result = result.welcome.clone();
        let current = cs
            .directory
            .get(name)
            .ok_or("retained member route is missing")?;
        if current != &route {
            if principal.is_none()
                || route.data.expiry <= current.data.expiry
                || route.control.expiry <= current.control.expiry
            {
                return Err("enrollment return route must be a newer authenticated route".into());
            }
            let change = cs
                .install_authenticated_route(name, &route)
                .ok_or("invalid enrollment return route")?;
            if let Err(error) = persist_current_direct_state(&st) {
                st.channels
                    .get_mut(channel)
                    .expect("locked channel")
                    .rollback_authenticated_route(change);
                return Err(error);
            }
            st.channels
                .get_mut(channel)
                .expect("locked channel")
                .learn(&route);
        }
        return Ok(result);
    }
    // One authenticated installation cannot consume this invitation repeatedly
    // by generating a different MLS package (or bypass a removal that way).
    // Re-admission after removal requires a different, explicitly issued invite.
    if let Some(principal) = principal {
        let roster = cs.role.roster_members();
        if cs.invitations.records.iter().any(|record| {
            record.redemptions.iter().any(|r| {
                r.principal == Some(principal)
                    && (record.id == *id
                        || roster.iter().any(|member| member.pseudonym == r.member))
            })
        }) {
            return Err("this installation already has an enrollment; resume it, or request a new invitation after removal".into());
        }
    }
    if cs.own_route.aliases.len() != 2 || !route.is_valid() {
        return Err("channel routing is recovering".into());
    }
    if cs.message_outbox.len() >= 64
        || cs.pending_control.len() + cs.directory.len() > crate::channel::CHANNEL_ACK_LIMIT
    {
        return Err("channel bootstrap queue is full".into());
    }
    let checkpoint = zeroize::Zeroizing::new(cs.role.checkpoint(&key).map_err(|e| e.to_string())?);
    let prior = (
        cs.invitations.clone(),
        cs.admission_cache.clone(),
        cs.admission_cache_order.clone(),
        cs.membership_outbox.clone(),
        cs.membership_journal.clone(),
        cs.catchup_members.clone(),
        cs.directory.clone(),
        cs.message_outbox.clone(),
        cs.pending_control.clone(),
    );
    let staged = (|| {
        let (admitted, _guard) = match stage_admission_locked(cs, channel, &route, mls, name)? {
            StagedAdmission::Fresh(admitted, guard) => (admitted, guard),
            StagedAdmission::Replay(_) => {
                return Err("enrollment belongs to another invitation".into())
            }
        };
        cs.catchup_members.insert(route.pseudonym);
        cs.directory.insert(name.to_owned(), route.clone());
        let directory = cs
            .directory
            .iter()
            .map(|(name, route)| (name.clone(), route.clone()))
            .collect::<Vec<_>>();
        let mut records = Vec::new();
        for entries in directory.chunks(crate::channel::CHANNEL_DIR_BATCH_LIMIT) {
            let payload = crate::channel::encode_dir_batch(entries)
                .ok_or("channel directory batch too large")?;
            records.push(cs.role.send(&payload).map_err(|e| e.to_string())?);
        }
        let mut metadata = vec![crate::channel::CHAN_METADATA];
        metadata.extend(crate::channel::metadata::Metadata::snapshot(&cs.role)?);
        let wire = cs.role.send(&metadata).map_err(|e| e.to_string())?;
        let bootstrap_id = crate::channel::msg_id(channel, &wire);
        cs.message_outbox.insert(
            bootstrap_id,
            crate::channel::ChannelMessageOutbox {
                wire: wire.clone(),
                expected: HashMap::from([(route.pseudonym, route.clone())]),
                acknowledged: HashSet::new(),
            },
        );
        records.push(wire);
        let result = welcome::encode(&admitted.welcome, &records)?;
        let announce = cs
            .role
            .send(&crate::channel::encode_dir(name, &route))
            .map_err(|e| e.to_string())?;
        for (_, target) in directory.iter().filter(|(_, target)| {
            target.pseudonym != route.pseudonym && target.pseudonym != cs.role.own_pseudonym()
        }) {
            cs.pending_control
                .push_back((target.clone(), announce.clone()));
        }
        cs.invitations.commit(
            id,
            Redemption {
                request,
                member: route.pseudonym,
                principal,
                name: name.to_owned(),
                epoch: cs.role.epoch(),
                welcome: result.clone(),
                confirmed: false,
                removed: false,
                bootstrap_id,
            },
        )?;
        Ok(result)
    })();
    let committed = staged.and_then(|result| persist_current_direct_state(&st).map(|_| result));
    if committed.is_err() {
        let cs = st.channels.get_mut(channel).expect("locked channel");
        (
            cs.invitations,
            cs.admission_cache,
            cs.admission_cache_order,
            cs.membership_outbox,
            cs.membership_journal,
            cs.catchup_members,
            cs.directory,
            cs.message_outbox,
            cs.pending_control,
        ) = prior;
        match cs
            .role
            .restore_checkpoint(&key, &checkpoint, || IdentityKeypair::from_seed(seed))
        {
            Ok(role) => cs.role = role,
            Err(error) => {
                st.pause_failed_owner_transition();
                return Err(format!("enrollment rollback failed: {error}"));
            }
        }
    }
    committed
}

#[cfg(not(feature = "client-persist"))]
pub(super) fn join_durable(
    _st: &mut NodeState,
    _req_id: u64,
    _channel: &str,
    _visibility: crate::channel::ChannelVisibility,
    _welcome: &[u8],
    _bootstrap: &[&[u8]],
    _events: &broadcast::Sender<Ev>,
) -> Result<(), String> {
    Err("reusable enrollment requires client persistence".into())
}

#[cfg(feature = "client-persist")]
pub(super) fn join_durable(
    st: &mut NodeState,
    req_id: u64,
    channel: &str,
    visibility: crate::channel::ChannelVisibility,
    welcome: &[u8],
    bootstrap: &[&[u8]],
    events: &broadcast::Sender<Ev>,
) -> Result<(), String> {
    invitations::require_durable(st)?;
    let key = channel_archive_key(&st.identity_seed);
    let prepared = st.prepared.get(&req_id).ok_or("unknown req")?;
    // Work on a restored copy until the full joined state and its receipt have
    // reached durable storage. Any parsing, authentication or storage failure
    // leaves the original preparation available to retry the exact result.
    let saved = zeroize::Zeroizing::new(prepared.mls.persist(&key).map_err(|e| e.to_string())?);
    let copy = gcoms_mls::PreparedJoin::restore(&key, &saved).map_err(|e| e.to_string())?;
    let member = gcoms_mls::ChannelMember::join(copy, welcome).map_err(|e| e.to_string())?;
    if member.own_pseudonym() != prepared.route.public.pseudonym {
        return Err("channel route does not match MLS leaf".into());
    }
    let mut cs = crate::channel::ChannelState::new(
        crate::channel::ChannelRole::Member(member),
        prepared.route.clone(),
        rand::thread_rng().next_u64(),
        channel.to_owned(),
        visibility,
    );
    cs.directory
        .insert(prepared.display.clone(), cs.own_route.public.clone());
    let mut metadata_received = false;
    for wire in bootstrap {
        let gcoms_mls::ReceiveOutcome::Application {
            sender, payload, ..
        } = cs.role.receive(wire).map_err(|e| e.to_string())?
        else {
            return Err("invalid enrollment bootstrap message".into());
        };
        if !cs.role.is_owner_name(&sender.display_name) {
            return Err("enrollment bootstrap is not from the owner".into());
        }
        let id = crate::channel::msg_id(channel, wire);
        match crate::channel::decode_inner(&payload) {
            Some(crate::channel::ChannelInner::DirBatch(entries)) if !metadata_received => {
                for (name, route) in entries {
                    if cs.role.pseudonym_for_name(&name) != Some(route.pseudonym) {
                        return Err("enrollment directory does not match membership".into());
                    }
                    if route.pseudonym != cs.role.own_pseudonym() {
                        cs.directory.insert(name, route);
                    }
                }
            }
            Some(crate::channel::ChannelInner::Metadata(bytes)) if !metadata_received => {
                crate::channel::metadata::Metadata::receive(
                    &mut cs.role,
                    sender.pseudonym,
                    &bytes,
                )?;
                stage_authenticated_channel_ack(
                    &mut cs,
                    id,
                    sender.pseudonym,
                    crate::channel::encode_text_ack(id, false),
                )?;
                metadata_received = true;
            }
            _ => return Err("invalid enrollment bootstrap ordering".into()),
        }
        cs.overlay.first_sighting(id);
    }
    if !metadata_received || cs.directory.len() != cs.role.roster_members().len() {
        return Err("incomplete enrollment bootstrap".into());
    }
    let routes = cs.directory.values().cloned().collect::<Vec<_>>();
    for route in routes {
        cs.learn(&route);
    }
    let channel_id = cs.id;
    if st
        .enrollments
        .iter()
        .find(|op| op.prepared_id == Some(req_id))
        .and_then(|op| op.expected_channel_id)
        .is_some_and(|expected| expected != channel_id.0)
    {
        return Err("joined channel does not match the invitation pin".into());
    }
    let enrollment = st
        .enrollments
        .iter()
        .position(|op| op.prepared_id == Some(req_id));
    let prior_enrollment = enrollment.map(|index| (index, st.enrollments[index].clone()));
    if let Some(index) = enrollment {
        st.enrollments[index].joined();
    }
    let prepared = st.prepared.remove(&req_id).expect("retained preparation");
    st.channels.insert(channel.to_owned(), cs);
    if let Err(error) = persist_current_direct_state(st) {
        st.channels.remove(channel);
        st.prepared.insert(req_id, prepared);
        if let Some((index, op)) = prior_enrollment {
            st.enrollments[index] = op;
        }
        return Err(error);
    }
    let _ = events.send(Ev::ChannelRosterChanged {
        channel: channel.to_owned(),
        channel_id,
    });
    Ok(())
}

pub(super) enum VerifiedRequest {
    Admission { package: Vec<u8>, reusable: bool },
    Challenge(Vec<u8>),
}

/// Prove the requester actually drains the authenticated return route before
/// allowing a new membership change. The short-lived MAC is stateless and bound
/// to this node, peer, invitation, exact package, name and current return card.
/// It cannot be used for a different identity or route. Existing v1 invitations
/// continue their historical flow; reusable ones require this exchange.
pub(super) fn verify_request(
    state: &Arc<Mutex<NodeState>>,
    request: &InviteRedeemRequest,
) -> Result<VerifiedRequest, String> {
    use crate::channel_invite::proof;
    use hmac::{Hmac, Mac};
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    let channel = st.channels.get(&request.channel).ok_or("no channel")?;
    if !channel
        .invitations
        .records
        .iter()
        .any(|r| r.id == request.invite_id)
    {
        return Ok(VerifiedRequest::Admission {
            package: request.key_package.clone(),
            reusable: false,
        });
    }
    let (package, supplied) = proof::decode_request(&request.key_package)
        .ok_or("reusable invitation requires authenticated return-path verification")?;
    let (route, mls) =
        crate::channel::decode_join_package(package).ok_or("bad channel join package")?;
    if gcoms_mls::pseudonym_of_key_package(mls) != Some(route.pseudonym) {
        return Err("channel route does not match MLS leaf".into());
    }
    let replay = channel.invitations.authorize(
        &request.invite_id,
        &request.invite_secret,
        &channel.role.own_pseudonym(),
        &Sha256::digest(mls).into(),
        &route.pseudonym,
        &request.member_name,
        now_unix(),
    )?;
    if replay.is_some_and(|r| r.principal != Some(Sha256::digest(&request.sender_pk).into())) {
        return Err("enrollment belongs to another authenticated installation".into());
    }
    let peer = st
        .peer_routes
        .get(&request.sender_pk)
        .ok_or("enrollment return route is unavailable")?;
    let now = now_unix();
    let expires = supplied.map_or_else(|| now.saturating_add(120), |proof| proof.expires);
    if expires <= now || expires > now.saturating_add(120) {
        return Err("enrollment return proof expired; verify the current route again".into());
    }
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&st.identity_seed).expect("HMAC accepts 32 bytes");
    mac.update(b"gcoms/enrollment-return-proof/v1\0");
    mac.update(&channel.id.0);
    mac.update(&request.invite_id);
    mac.update(&Sha256::digest(&request.sender_pk));
    mac.update(&Sha256::digest(request.member_name.as_bytes()));
    mac.update(&Sha256::digest(package));
    mac.update(&Sha256::digest(peer.public().encode()));
    mac.update(&expires.to_be_bytes());
    if let Some(proof) = supplied {
        mac.verify_slice(&proof.tag)
            .map_err(|_| "enrollment return proof does not match the current route")?;
        Ok(VerifiedRequest::Admission {
            package: package.to_vec(),
            reusable: true,
        })
    } else {
        let tag: [u8; 32] = mac.finalize().into_bytes().into();
        Ok(VerifiedRequest::Challenge(proof::challenge(proof::Proof {
            expires,
            tag,
        })))
    }
}
