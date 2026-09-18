// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

pub(crate) const PASSIVE_REACHABILITY_SECS: u64 = 60;

pub(crate) fn observe_direct_reachability(
    st: &mut NodeState,
    peer_pk: &[u8],
    reachability: Reachability,
    lease_secs: u64,
    events: &broadcast::Sender<Ev>,
) {
    let changed = st
        .direct_presence
        .get(peer_pk)
        .is_none_or(|observation| observation.reachability != reachability);
    st.direct_presence.insert(
        peer_pk.to_vec(),
        DirectPresenceObservation {
            reachability,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(lease_secs),
        },
    );
    if changed {
        let _ = events.send(Ev::PresenceChanged {
            peer_pk: peer_pk.to_vec(),
            reachability,
        });
    }
}

pub(crate) fn withdraw_direct_presence(
    st: &mut NodeState,
    peer_pk: &[u8],
    events: &broadcast::Sender<Ev>,
) {
    if st.direct_presence.remove(peer_pk).is_some() {
        let _ = events.send(Ev::PresenceChanged {
            peer_pk: peer_pk.to_vec(),
            reachability: Reachability::Unknown,
        });
    }
}

pub(crate) fn apply_direct_presence(
    st: &mut NodeState,
    peer_pk: &[u8],
    counter: u64,
    mode: PresenceMode,
    lease_secs: u32,
    events: &broadcast::Sender<Ev>,
) -> bool {
    let previous = st
        .direct_presence_counters
        .get(peer_pk)
        .copied()
        .unwrap_or(0);
    if counter <= previous {
        return false;
    }
    st.direct_presence_counters
        .insert(peer_pk.to_vec(), counter);
    if !st.direct_presence_opt_in.contains(peer_pk) {
        withdraw_direct_presence(st, peer_pk, events);
        return true;
    }
    match mode {
        PresenceMode::RecentlyReachable => observe_direct_reachability(
            st,
            peer_pk,
            Reachability::RecentlyReachable,
            u64::from(lease_secs),
            events,
        ),
        PresenceMode::Away => observe_direct_reachability(
            st,
            peer_pk,
            Reachability::Away,
            u64::from(lease_secs),
            events,
        ),
        PresenceMode::Invisible => withdraw_direct_presence(st, peer_pk, events),
    }
    true
}

pub(crate) fn expire_direct_presence(
    st: &mut NodeState,
    now: std::time::Instant,
    events: &broadcast::Sender<Ev>,
) {
    let expired = st
        .direct_presence
        .iter()
        .filter_map(|(peer, observation)| (observation.expires <= now).then_some(peer.clone()))
        .collect::<Vec<_>>();
    for peer in expired {
        st.direct_presence.remove(&peer);
        let _ = events.send(Ev::PresenceChanged {
            peer_pk: peer,
            reachability: Reachability::Unknown,
        });
    }
}

pub(crate) fn apply_channel_presence(
    st: &mut NodeState,
    channel: &str,
    member_id: [u8; 32],
    counter: u64,
    mode: PresenceMode,
    lease_secs: u32,
    events: &broadcast::Sender<Ev>,
) -> bool {
    let key = (channel.to_string(), member_id);
    let previous = st.channel_presence_counters.get(&key).copied().unwrap_or(0);
    if counter <= previous {
        return false;
    }
    st.channel_presence_counters.insert(key.clone(), counter);
    if !st.channel_presence_opt_in.contains(channel) {
        withdraw_channel_presence(st, channel, member_id, events);
        return true;
    }
    let reachability = match mode {
        PresenceMode::RecentlyReachable => Some(Reachability::RecentlyReachable),
        PresenceMode::Away => Some(Reachability::Away),
        PresenceMode::Invisible => None,
    };
    match reachability {
        Some(reachability) => observe_channel_reachability(
            st,
            channel,
            member_id,
            reachability,
            u64::from(lease_secs),
            events,
        ),
        None => withdraw_channel_presence(st, channel, member_id, events),
    }
    true
}

pub(crate) fn withdraw_channel_presence(
    st: &mut NodeState,
    channel: &str,
    member_id: [u8; 32],
    events: &broadcast::Sender<Ev>,
) {
    if st
        .channel_presence
        .remove(&(channel.to_string(), member_id))
        .is_some()
    {
        let _ = events.send(Ev::ChannelPresenceChanged {
            channel: channel.to_string(),
            member_id,
            reachability: Reachability::Unknown,
        });
    }
}

pub(crate) fn observe_channel_reachability(
    st: &mut NodeState,
    channel: &str,
    member_id: [u8; 32],
    reachability: Reachability,
    lease_secs: u64,
    events: &broadcast::Sender<Ev>,
) {
    let key = (channel.to_string(), member_id);
    let changed = st
        .channel_presence
        .get(&key)
        .is_none_or(|observation| observation.reachability != reachability);
    st.channel_presence.insert(
        key,
        DirectPresenceObservation {
            reachability,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(lease_secs),
        },
    );
    if changed {
        let _ = events.send(Ev::ChannelPresenceChanged {
            channel: channel.to_string(),
            member_id,
            reachability,
        });
    }
}

pub(crate) fn expire_channel_presence(
    st: &mut NodeState,
    now: std::time::Instant,
    events: &broadcast::Sender<Ev>,
) {
    let expired = st
        .channel_presence
        .iter()
        .filter_map(|(key, observation)| (observation.expires <= now).then_some(key.clone()))
        .collect::<Vec<_>>();
    for (channel, member_id) in expired {
        st.channel_presence.remove(&(channel.clone(), member_id));
        let _ = events.send(Ev::ChannelPresenceChanged {
            channel,
            member_id,
            reachability: Reachability::Unknown,
        });
    }
}

pub(crate) fn clear_channel_presence(
    st: &mut NodeState,
    channel: &str,
    events: &broadcast::Sender<Ev>,
) {
    let members = st
        .channel_presence
        .keys()
        .filter_map(|(name, member_id)| (name == channel).then_some(*member_id))
        .collect::<Vec<_>>();
    for member_id in members {
        st.channel_presence
            .remove(&(channel.to_string(), member_id));
        let _ = events.send(Ev::ChannelPresenceChanged {
            channel: channel.to_string(),
            member_id,
            reachability: Reachability::Unknown,
        });
    }
}

pub(crate) struct PreparedChannelPresence {
    wire: Vec<u8>,
    channel: String,
    targets: Vec<crate::channel::PeerRef>,
}

pub(crate) fn prepare_channel_presence(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    mode: PresenceMode,
    lease_secs: u32,
) -> Result<PreparedChannelPresence, String> {
    let (wire, targets) = {
        let mut st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if mode != PresenceMode::Invisible && !st.channel_presence_opt_in.contains(channel) {
            return Err("channel presence is not opted in for this channel".into());
        }
        let counter = st.next_direct_sequence;
        let next_sequence = counter
            .checked_add(1)
            .ok_or("presence sequence exhausted")?;
        let payload = crate::channel::encode_presence(counter, mode, lease_secs)
            .ok_or("invalid channel presence lease")?;
        let archive_key = channel_archive_key(&st.identity_seed);
        let owner_seed = channel_seed(&st, channel);
        let (wire, targets, checkpoint) = {
            let cs = st.channels.get_mut(channel).ok_or("no channel")?;
            if cs.membership_outbox.is_some() {
                return Err("channel membership is still converging".into());
            }
            let checkpoint = cs
                .role
                .checkpoint(&archive_key)
                .map_err(|error| error.to_string())?;
            let wire = cs.role.send(&payload).map_err(|error| error.to_string())?;
            let own_pseudonym = cs.role.own_pseudonym();
            let mut targets = cs
                .overlay
                .origin_targets()
                .iter()
                .filter_map(|id| cs.resolve(id))
                .collect::<Vec<_>>();
            let mut roster = cs.directory.values().cloned().collect::<Vec<_>>();
            use rand::seq::SliceRandom;
            roster.shuffle(&mut rand::thread_rng());
            for route in roster.into_iter().take(64) {
                if route.pseudonym != own_pseudonym
                    && !targets
                        .iter()
                        .any(|target| target.pseudonym == route.pseudonym)
                {
                    targets.push(crate::channel::PeerRef::from_route(&route));
                }
            }
            (wire, targets, checkpoint)
        };
        st.next_direct_sequence = next_sequence;
        if let Err(error) = persist_current_direct_state(&st) {
            st.next_direct_sequence = counter;
            let restored = st
                .channels
                .get(channel)
                .ok_or("channel disappeared during presence rollback")?
                .role
                .restore_checkpoint(&archive_key, &checkpoint, || {
                    gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                })
                .map_err(|restore| format!("{error}; channel rollback failed: {restore}"))?;
            st.channels
                .get_mut(channel)
                .expect("channel checked above")
                .role = restored;
            return Err(error);
        }
        (wire, targets)
    };
    Ok(PreparedChannelPresence {
        wire,
        channel: channel.to_string(),
        targets,
    })
}

pub(crate) async fn complete_channel_presence(
    scheduler: &RelayScheduler,
    prepared: PreparedChannelPresence,
) -> Result<(), String> {
    let PreparedChannelPresence {
        wire,
        channel,
        targets,
    } = prepared;
    let cell = Cell::new(
        CellType::Msg,
        0,
        0,
        crate::proto::encode_chan(&channel, &wire),
    );
    let mut failures = 0;
    for target in &targets {
        if push_to_ref(scheduler, target, &cell).await.is_err() {
            failures += 1;
        }
    }
    metrics::log_event(
        "channel_presence_sent",
        &[
            ("channel", channel.clone()),
            ("targets", targets.len().to_string()),
        ],
    );
    if failures == 0 {
        Ok(())
    } else {
        Err(format!(
            "channel presence send failed for {failures} target(s)"
        ))
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) async fn send_channel_presence(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    mode: PresenceMode,
    lease_secs: u32,
) -> Result<(), String> {
    let prepared = prepare_channel_presence(state, channel, mode, lease_secs)?;
    complete_channel_presence(scheduler, prepared).await
}

pub(crate) fn prepare_direct_presence(
    state: &Arc<Mutex<NodeState>>,
    peer: &NodeInfo,
    mode: PresenceMode,
    lease_secs: u32,
    via: Option<NodeInfo>,
) -> Result<PreparedDirect, String> {
    if mode != PresenceMode::Invisible
        && !state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .direct_presence_opt_in
            .contains(&peer.identity_pk)
    {
        return Err("direct presence is not opted in for this peer".into());
    }
    prepare_direct_record(
        state,
        peer,
        via,
        // Report only the authenticated matching ACK after receive persistence.
        // This is transport reachability, not an application execution receipt.
        true,
        None,
        move |message_id, sequence| {
            encode_direct_presence(message_id, sequence, mode, lease_secs)
                .ok_or_else(|| "invalid direct presence lease".to_string())
        },
    )
}
