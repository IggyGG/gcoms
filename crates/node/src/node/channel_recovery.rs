//! Recover established channel transport through an explicitly bound base peer.
//! The carrier is unchanged MSG/FRWD; only existing MLS commits and self-Dir travel.
use super::*;

/// Stage one self announcement per current epoch/owned route. This transient
/// cache contains no global peer identity. Exact wires also live in the existing
/// durable control outbox; a retry never invents an ACK or advances membership.
pub(crate) fn stage_own_route_announcement(
    st: &mut NodeState,
    channel: &str,
    recipient: &crate::channel::ChannelRoute,
) -> Result<(Vec<u8>, [u8; 16]), String> {
    stage_route_announcement(st, channel, recipient, None)
}

/// Associate the exact encrypted Dir response with its authenticated request in
/// the existing durable reply cache. It is still a Dir, never a membership ACK.
pub(crate) fn stage_own_route_reply(
    st: &mut NodeState,
    channel: &str,
    recipient: &crate::channel::ChannelRoute,
    original_id: [u8; 16],
) -> Result<(Vec<u8>, [u8; 16]), String> {
    stage_route_announcement(st, channel, recipient, Some(original_id))
}

fn stage_route_announcement(
    st: &mut NodeState,
    channel: &str,
    recipient: &crate::channel::ChannelRoute,
    original_id: Option<[u8; 16]>,
) -> Result<(Vec<u8>, [u8; 16]), String> {
    let key = channel_archive_key(&st.identity_seed);
    let seed = channel_seed(st, channel);
    let cs = st.channels.get_mut(channel).ok_or("no channel")?;
    let own = cs.own_route.public.clone();
    if !own.is_valid() || own.data.expiry <= now_unix() || own.control.expiry <= now_unix() {
        return Err("current owned channel route is unavailable".into());
    }
    if recipient.pseudonym == own.pseudonym
        || !cs
            .role
            .roster_members()
            .iter()
            .any(|m| m.pseudonym == recipient.pseudonym)
        || !cs.directory.values().any(|r| r == recipient)
    {
        return Err("channel route recipient is not current".into());
    }
    let epoch = cs.role.epoch();
    let cached = cs
        .route_announcement
        .as_ref()
        .filter(|a| a.epoch == epoch && a.route == own);
    let pending = cached.is_some_and(|cached| {
        cs.pending_control
            .iter()
            .any(|(r, w)| r == recipient && w == &cached.wire)
    });
    let reply_cached = original_id.is_none_or(|id| {
        cs.commit_ack_cache
            .get(&id)
            .is_some_and(|(r, w)| r == recipient && cached.is_some_and(|cached| w == &cached.wire))
    });
    if pending && reply_cached && original_id.is_none() {
        let wire = cached.expect("pending cache").wire.clone();
        return Ok((wire.clone(), crate::channel::msg_id(channel, &wire)));
    }
    if !pending && cs.pending_control.len() >= crate::channel::CHANNEL_ACK_LIMIT {
        return Err("channel control outbox is full".into());
    }
    let previous_replies =
        original_id.map(|_| (cs.commit_ack_cache.clone(), cs.commit_ack_order.clone()));
    let checkpoint = cs.role.checkpoint(&key).map_err(|e| e.to_string())?;
    let previous = cs.route_announcement.clone();
    let wire = match cached {
        Some(cached) => cached.wire.clone(),
        None => {
            let own_name = cs
                .role
                .roster()
                .into_iter()
                .find_map(|(_, name)| {
                    (cs.role.pseudonym_for_name(&name) == Some(own.pseudonym)).then_some(name)
                })
                .ok_or("own channel roster entry missing")?;
            cs.role
                .send(&crate::channel::encode_dir(&own_name, &own))
                .map_err(|e| e.to_string())?
        }
    };
    let id = crate::channel::msg_id(channel, &wire);
    cs.route_announcement = Some(crate::channel::RouteAnnouncement {
        epoch,
        route: own,
        wire: wire.clone(),
    });
    if !pending {
        cs.pending_control
            .push_back((recipient.clone(), wire.clone()));
    }
    if let Some(original_id) = original_id {
        cs.cache_ack(original_id, recipient.clone(), wire.clone());
    }
    if let Err(error) = persist_current_direct_state(st) {
        let cs = st.channels.get_mut(channel).expect("retained under lock");
        if !pending {
            cs.pending_control.pop_back();
        }
        if let Some((cache, order)) = previous_replies {
            cs.commit_ack_cache = cache;
            cs.commit_ack_order = order;
        }
        cs.route_announcement = previous;
        cs.role = cs
            .role
            .restore_checkpoint(&key, &checkpoint, || IdentityKeypair::from_seed(seed))
            .map_err(|e| e.to_string())?;
        return Err(error);
    }
    let cs = st.channels.get_mut(channel).expect("retained under lock");
    cs.overlay.first_sighting(id);
    cs.note(id, wire.clone());
    Ok((wire, id))
}

pub(crate) fn recovery_recipient(
    cs: &crate::channel::ChannelState,
    expected_id: crate::channel::ChannelId,
    expected_epoch: u64,
    welcome: &[u8],
) -> Result<crate::channel::ChannelRoute, String> {
    if !matches!(cs.role, crate::channel::ChannelRole::Owner(_))
        || cs.id != expected_id
        || cs.role.epoch() != expected_epoch
    {
        return Err("channel recovery owner/id/epoch is not current".into());
    }
    let mut admissions = cs.admission_cache.values().filter(|a| a.welcome == welcome);
    let admission = admissions
        .next()
        .ok_or("exact retained admission missing")?;
    if admissions.next().is_some()
        || !cs
            .role
            .roster_members()
            .iter()
            .any(|m| m.pseudonym == admission.pseudonym)
    {
        return Err("retained admission leaf is not current".into());
    }
    cs.directory
        .values()
        .find(|r| r.pseudonym == admission.pseudonym)
        .cloned()
        .ok_or_else(|| "retained admission route is missing".into())
}

fn recovery_carrier(st: &NodeState, caller: &NodeInfo, now: u64) -> Result<NodeInfo, String> {
    let peer = select_peer_route(st, caller)?;
    let primary = peer
        .primary()
        .ok_or("current base contact is expired or missing")?;
    if primary.expiry > now {
        return Ok(peer);
    }
    if caller.primary().is_none_or(|alias| alias.expiry <= now) {
        return Err("current base contact is expired or missing".into());
    }
    // Only carry the retained MLS commit and authenticated directory through
    // the caller's live base contact. This does not authenticate that contact
    // as a newer pairwise route or modify its remembered generation.
    Ok(caller.public())
}

pub(crate) async fn recover_channel_route(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    expected_id: crate::channel::ChannelId,
    expected_epoch: u64,
    welcome: &[u8],
    peer: &NodeInfo,
) -> Result<[u8; 16], String> {
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    let (delivery, policy, id, own_route) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if !cfg!(feature = "client-persist") || st.durable_state_sink.is_none() {
            return Err("channel route recovery requires persistent state".into());
        }
        let cs = st.channels.get(channel).ok_or("no channel")?;
        let recipient = recovery_recipient(cs, expected_id, expected_epoch, welcome)?;
        let commit = cs
            .membership_outbox
            .as_ref()
            .filter(|m| {
                m.epoch == expected_epoch
                    && m.expected.contains_key(&recipient.pseudonym)
                    && !m.acknowledged.contains(&recipient.pseudonym)
            })
            .map(|m| m.commit.clone());
        let peer = recovery_carrier(&st, peer, now_unix())?;
        let (wire, id) = stage_own_route_announcement(&mut st, channel, &recipient)?;
        let mut cells = Vec::new();
        if let Some(commit) = commit {
            cells.extend(crate::proto::encode_chan_cells(channel, &commit)?);
        }
        cells.extend(crate::proto::encode_chan_cells(channel, &wire)?);
        let relay = choose_intermediary(&mut st, &peer);
        (
            DirectDelivery { peer, relay, cells },
            st.frwd_target_policy.clone(),
            id,
            st.channels[channel].own_route.public.clone(),
        )
    };
    tokio::time::timeout_at(end, async {
        for cell in &delivery.cells {
            {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                let cs = st.channels.get(channel).ok_or("no channel")?;
                recovery_recipient(cs, expected_id, expected_epoch, welcome)?;
                if cs.own_route.public != own_route {
                    return Err("owned route changed during recovery".to_string());
                }
            }
            scheduler
                .frwd(
                    ProducerClass::Direct,
                    delivery.relay.clone(),
                    delivery.peer.primary().ok_or("base alias missing")?.clone(),
                    cell.clone(),
                    policy.clone(),
                )
                .map_err(|e| e.to_string())?
                .completion()
                .await
                .accepted()?;
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|_| "channel route carrier exceeded original deadline".to_string())??;
    // Recheck the exact owner/group/epoch/leaf after the wait. A successful hop
    // never becomes proof of membership convergence or an application result.
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    recovery_recipient(
        st.channels.get(channel).ok_or("no channel")?,
        expected_id,
        expected_epoch,
        welcome,
    )?;
    if st.channels[channel].own_route.public != own_route {
        return Err("owned route changed during recovery".into());
    }
    Ok(id)
}

#[cfg(all(test, feature = "client-persist"))]
#[path = "channel_recovery_unit_tests.rs"]
mod tests;
