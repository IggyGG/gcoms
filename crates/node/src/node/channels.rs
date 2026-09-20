// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

pub(crate) async fn push_to_ref(
    scheduler: &RelayScheduler,
    r: &crate::channel::PeerRef,
    cell: &Cell,
) -> Result<(), String> {
    scheduler
        .push(ProducerClass::ChannelData, r.contact.clone(), cell.clone())
        .map_err(|e| e.to_string())?
        .completion()
        .await
        .accepted()
        .map(|_| ())
}

#[path = "channel_maintenance.rs"]
mod maintenance;
pub(crate) use maintenance::ChannelMaintenance;

// One finite retry round for focused tests. Production owns the same receipt
// set across recurring ticks in spawn_channel_maintenance_loop.
#[cfg(all(test, feature = "client-persist"))]
pub(crate) async fn channel_tick(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    _events: &broadcast::Sender<Ev>,
) {
    let mut maintenance = ChannelMaintenance::default();
    maintenance.tick(state, scheduler);
    while !maintenance.is_empty() {
        maintenance.complete_next(state).await;
    }
}

/// Control recovery keeps its independent maintenance clock. Data admission
/// and held hop receipts never own the clock that retransmits ACKs and commits.
pub(crate) async fn channel_control_tick(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
) {
    let leaving = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.owner_transition_failed {
            return;
        }
        st.channels
            .iter()
            .filter(|(_, cs)| cs.role.is_owner() && cs.membership_outbox.is_none())
            .filter_map(|(name, cs)| {
                crate::channel::metadata::Metadata::read(&cs.role)
                    .ok()?
                    .pending_leave(&cs.role)
                    .map(|member| (name.clone(), member))
            })
            .collect::<Vec<_>>()
    };
    for (name, member) in leaving {
        if let Ok(Some(_)) = prepare_channel_removal(state, &name, member, events) {
            if let Some(cs) = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .channels
                .get(&name)
            {
                let _ = events.send(Ev::ChannelRosterChanged {
                    channel: name,
                    channel_id: cs.id,
                });
            }
        }
    }
    let control_actions = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.owner_transition_failed {
            return;
        }
        expire_channel_presence(&mut st, std::time::Instant::now(), events);
        let mut control_actions = Vec::new();
        for (chan, cs) in st.channels.iter_mut() {
            if cs.own_route.aliases.len() != 2 {
                continue;
            }
            let authenticated_routes = cs.directory.values().cloned().collect::<Vec<_>>();
            for route in authenticated_routes {
                for mut wire in cs.promote_unrouted_acks(&route) {
                    wire.fill(0);
                }
            }
            control_actions.extend(
                cs.pending_control
                    .iter()
                    .cloned()
                    .map(|(peer, wire)| (chan.clone(), peer, wire)),
            );
            if let Some(outbox) = &cs.membership_outbox {
                control_actions.extend(
                    outbox
                        .expected
                        .iter()
                        .filter(|(identity, _)| !outbox.acknowledged.contains(*identity))
                        .map(|(_, peer)| (chan.clone(), peer.clone(), outbox.commit.clone())),
                );
            }
        }
        control_actions
    };

    futures_join_all(control_actions.into_iter().map(|(chan, peer, wire)| {
        let state = state.clone();
        let scheduler = scheduler.clone();
        async move {
            let cells = crate::proto::encode_chan_cells(&chan, &wire).unwrap_or_default();
            let mut sent = !cells.is_empty();
            let receipts = cells
                .iter()
                .map(|cell| {
                    scheduler.push(
                        ProducerClass::ChannelControl,
                        peer.control.clone(),
                        cell.clone(),
                    )
                })
                .collect::<Vec<_>>();
            // Every peer's jobs are queued before waiting for another peer. A
            // failed/slow lane must not serialise all membership ACK retransmits.
            sent &= tokio::time::timeout(std::time::Duration::from_secs(120), async {
                let outcomes = futures_join_all(receipts.into_iter().map(|receipt| async move {
                    match receipt {
                        Ok(receipt) => receipt.completion().await.accepted().is_ok(),
                        Err(_) => false,
                    }
                }))
                .await;
                outcomes.into_iter().all(|accepted| accepted)
            })
            .await
            .unwrap_or(false);
            if sent {
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(cs) = st.channels.get_mut(&chan) {
                    let mut index = 0;
                    while index < cs.pending_control.len() {
                        let remove = cs.pending_control[index].0 == peer
                            && cs.pending_control[index].1 == wire;
                        if remove {
                            if let Some((_, mut pending_wire)) = cs.pending_control.remove(index) {
                                pending_wire.fill(0);
                            }
                        } else {
                            index += 1;
                        }
                    }
                }
            }
        }
    }))
    .await;
}

/// Pairwise channel encryption keeps targeted maintenance off the shared MLS
/// sender ratchet. The established roster/directory and AEAD envelope are reused.
pub(crate) fn stage_channel_pex(
    chan: &str,
    cs: &crate::channel::ChannelState,
    recipient: [u8; 32],
    refs: &[crate::channel::PeerRef],
    have: &[[u8; 16]],
) -> Result<(crate::channel::PeerRef, Cell), String> {
    if !cs
        .role
        .roster_members()
        .iter()
        .any(|member| member.pseudonym == recipient)
    {
        return Err("PEX recipient is not a current channel member".into());
    }
    let mut plaintext = crate::channel::encode_channel_pex(chan, refs, have)
        .ok_or_else(|| "invalid channel PEX bounds".to_string())?;
    let sealed = seal_channel_direct(chan, cs, recipient, fresh_msg_id(), &plaintext);
    plaintext.fill(0);
    let (route, envelope) = sealed?;
    let cell = Cell::new(
        CellType::Msg,
        0,
        0,
        envelope.encode().ok_or("channel PEX envelope too large")?,
    );
    cell.encode_wire().map_err(|error| error.to_string())?;
    Ok((crate::channel::PeerRef::from_route(&route), cell))
}

fn pex_sender_is_authenticated(
    cs: &crate::channel::ChannelState,
    sender: [u8; 32],
    refs: &[crate::channel::PeerRef],
) -> bool {
    refs.first().is_some_and(|target| {
        target.pseudonym == sender
            && cs.directory.values().any(|route| {
                route.pseudonym == sender && crate::channel::PeerRef::from_route(route) == *target
            })
    })
}

pub(crate) fn apply_authenticated_pex(
    cs: &mut crate::channel::ChannelState,
    sender: [u8; 32],
    refs: &[crate::channel::PeerRef],
    have: &[[u8; 16]],
) -> bool {
    let Some(target) = refs.first() else {
        return false;
    };
    if !pex_sender_is_authenticated(cs, sender, refs) {
        return false;
    }
    for r in refs {
        cs.learn_ref(r);
    }
    let peer_have: std::collections::HashSet<[u8; 16]> = have.iter().copied().collect();
    let mut to_send: Vec<([u8; 16], Vec<u8>)> = cs
        .have_list()
        .into_iter()
        .filter(|id| !peer_have.contains(id))
        .filter_map(|id| cs.cell_cache.get(&id).map(|wire| (id, wire.clone())))
        .collect();
    to_send.reverse();
    to_send.truncate(2);
    // Responses stay on the existing channel tick; never reflect immediately.
    for (id, wire) in to_send {
        cs.queue_pull(target.clone(), id, wire);
    }
    true
}

pub(crate) fn handle_chan_cell(
    state: &Arc<Mutex<NodeState>>,
    chan: String,
    mut wire: Vec<u8>,
    events: &broadcast::Sender<Ev>,
) {
    let received = std::time::Instant::now();
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    if !st.channels.contains_key(&chan) {
        if st.chan_parked.len() < 64 {
            st.chan_parked.push((chan, wire));
            metrics::log_event("chan_parked", &[]);
        } else {
            wire.fill(0);
        }
        return;
    }
    process_chan_cell(&mut st, &chan, wire, received, events);
}

pub(crate) fn process_chan_cell(
    st: &mut NodeState,
    chan: &str,
    mut wire: Vec<u8>,
    received: std::time::Instant,
    events: &broadcast::Sender<Ev>,
) {
    let _received = received;
    let id = crate::channel::msg_id(chan, &wire);
    metrics::log_event(
        "chan_cell_arrive",
        &[
            ("node", short_addr_tag(&info_addr(&st.info))),
            ("msg", encode_b64url(&id)),
        ],
    );
    let Some(cs) = st.channels.get_mut(chan) else {
        wire.fill(0);
        return;
    };
    let msg_epoch = crate::channel::mls_epoch_of(&wire);
    let my_epoch = cs.role.epoch();
    if msg_epoch.is_some_and(|epoch| {
        epoch
            .checked_sub(my_epoch)
            .is_some_and(|distance| distance > crate::channel::FUTURE_EPOCH_DISTANCE_LIMIT)
    }) {
        wire.fill(0);
        metrics::log_event(
            "chan_future_epoch_rejected",
            &[("channel", chan.to_string())],
        );
        return;
    }
    if !cs.overlay.first_sighting(id) {
        if let Some((peer, mut ack_wire)) = cs.commit_ack_cache.get(&id).cloned() {
            if cs.pending_control.len() < crate::channel::CHANNEL_ACK_LIMIT
                && !cs
                    .pending_control
                    .iter()
                    .any(|(pending_peer, pending_wire)| {
                        pending_peer.pseudonym == peer.pseudonym && pending_wire == &ack_wire
                    })
            {
                cs.pending_control.push_back((peer, ack_wire));
            } else {
                ack_wire.fill(0);
            }
        }
        metrics::log_event(
            "chan_msg_dup",
            &[
                ("channel", chan.to_string()),
                ("node", short_addr_tag(&info_addr(&st.info))),
            ],
        );
        wire.fill(0);
        return;
    }
    if let Some(me) = msg_epoch {
        if me > my_epoch {
            let parked = cs.park_future_message(my_epoch, me, wire);
            metrics::log_event(
                if parked.is_ok() {
                    "chan_future_epoch_parked"
                } else {
                    "chan_future_epoch_rejected"
                },
                &[
                    ("channel", chan.to_string()),
                    ("have", me.to_string()),
                    ("at", my_epoch.to_string()),
                    ("node", short_addr_tag(&info_addr(&st.info))),
                ],
            );
            return;
        }
    }
    let was_text = deliver_mls(st, chan, &wire, _received, events);
    if was_text {
        if let Some(cs) = st.channels.get_mut(chan) {
            cs.note(id, wire.clone());
            cs.enqueue_forward(id, wire);
        }
    } else {
        wire.fill(0);
    }
    drain_future_epochs(st, chan, events);
}

pub(crate) fn drain_future_epochs(st: &mut NodeState, chan: &str, events: &broadcast::Sender<Ev>) {
    loop {
        let my_epoch = match st.channels.get(chan) {
            Some(cs) => cs.role.epoch(),
            None => return,
        };
        let wires = match st.channels.get_mut(chan) {
            Some(cs) => cs.take_ready_out_of_order(my_epoch),
            None => return,
        };
        let Some(wires) = wires else { return };
        for mut wire in wires {
            let received = std::time::Instant::now();
            if deliver_mls(st, chan, &wire, received, events) {
                let id = crate::channel::msg_id(chan, &wire);
                if let Some(cs) = st.channels.get_mut(chan) {
                    cs.note(id, wire.clone());
                    cs.enqueue_forward(id, wire);
                }
            } else {
                wire.fill(0);
            }
        }
    }
}

pub(crate) fn deliver_mls(
    st: &mut NodeState,
    chan: &str,
    wire: &[u8],
    _received: std::time::Instant,
    events: &broadcast::Sender<Ev>,
) -> bool {
    let node_tag = short_addr_tag(&info_addr(&st.info));
    let scheduler = st.scheduler.clone();
    let id = crate::channel::msg_id(chan, wire);
    let mut was_text = false;
    let archive_key = channel_archive_key(&st.identity_seed);
    let Some(cs) = st.channels.get_mut(chan) else {
        return false;
    };
    let role_checkpoint = match cs.role.checkpoint(&archive_key) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            metrics::log_event("chan_checkpoint_error", &[("e", error.to_string())]);
            return false;
        }
    };
    let recv_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cs.role.receive(wire)))
            .unwrap_or_else(|_| Err(gcoms_mls::MlsError::OpenMls("panic in receive".into())));
    match recv_result {
        Err(gcoms_mls::MlsError::Removed) => {
            let owner_seed = channel_seed(st, chan);
            let opted_in = st.channel_presence_opt_in.remove(chan);
            let counters = st
                .channel_presence_counters
                .iter()
                .filter(|((channel, _), _)| channel == chan)
                .map(|(k, v)| (k.clone(), *v))
                .collect::<Vec<_>>();
            let removed = st.channels.remove(chan).expect("received channel exists");
            st.channel_presence_counters
                .retain(|(channel, _), _| channel != chan);
            if let Err(error) = persist_current_direct_state(st) {
                st.channels.insert(chan.into(), removed);
                if opted_in {
                    st.channel_presence_opt_in.insert(chan.into());
                }
                st.channel_presence_counters.extend(counters);
                if let Some(cs) = st.channels.get_mut(chan) {
                    cs.overlay.forget_sighting(id);
                    match cs
                        .role
                        .restore_checkpoint(&archive_key, &role_checkpoint, || {
                            gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                        }) {
                        Ok(role) => cs.role = role,
                        Err(_) => st.pause_failed_owner_transition(),
                    }
                }
                metrics::log_event("channel_removal_persist_error", &[("e", error)]);
                return false;
            }
            close_route_lanes(&st.scheduler, &removed.own_route);
            clear_channel_presence(st, chan, events);
            metrics::log_event("channel_self_removed", &[("channel", chan.to_string())]);
            let _ = events.send(Ev::ChannelRemoved {
                channel: chan.to_string(),
            });
        }
        Err(e) => {
            if e == gcoms_mls::MlsError::Unauthorized {
                // An authorized new-owner commit can overtake its delegation.
                // Retain the receive ratchet so its exact retry can succeed
                // after the authenticated ownership record arrives.
                if let Some(cs) = st.channels.get_mut(chan) {
                    cs.overlay.forget_sighting(id);
                }
                restore_directory_receive(st, chan, &role_checkpoint);
            }
            metrics::log_event(
                "chan_error",
                &[
                    ("channel", chan.to_string()),
                    ("e", e.to_string()),
                    ("node", node_tag.clone()),
                ],
            );
        }
        Ok(gcoms_mls::ReceiveOutcome::Application {
            sender_index: sender_idx,
            payload: plain,
        }) => {
            let sender = st
                .channels
                .get(chan)
                .map(|cs| cs.role.roster())
                .and_then(|r| {
                    r.into_iter()
                        .find(|(idx, _)| *idx == sender_idx)
                        .map(|(_, name)| name)
                })
                .unwrap_or_default();
            let inner = crate::channel::decode_inner(&plain);
            match inner {
                Some(crate::channel::ChannelInner::Metadata(update)) => {
                    if !commit_channel_metadata(st, chan, id, &sender, &update, &role_checkpoint) {
                        return false;
                    }
                    was_text = true;
                    if let Some(cs) = st.channels.get(chan) {
                        if crate::channel::metadata::Metadata::read(&cs.role)
                            .is_ok_and(|m| m.closed())
                        {
                            let _ = events.send(Ev::ChannelRemoved {
                                channel: chan.into(),
                            });
                        } else {
                            let _ = events.send(Ev::ChannelRosterChanged {
                                channel: chan.into(),
                                channel_id: cs.id,
                            });
                        }
                    }
                }
                Some(crate::channel::ChannelInner::Text {
                    ts_ms,
                    share_presence,
                    body,
                }) => {
                    if st.channels.get(chan).is_some_and(|cs| {
                        crate::channel::metadata::Metadata::read(&cs.role).is_ok_and(|m| m.closed())
                    }) {
                        return false;
                    }
                    if gcoms_core::is_volatile_application_payload(&body) {
                        return false;
                    }
                    let latency = now_ms().saturating_sub(ts_ms);
                    let channel_epoch = st
                        .channels
                        .get(chan)
                        .map(|cs| cs.role.epoch())
                        .unwrap_or_default();
                    let sender_pseudonym = st
                        .channels
                        .get(chan)
                        .and_then(|channel| channel.role.pseudonym_for_name(&sender));
                    if let Some(sender_pseudonym) = sender_pseudonym {
                        if let Some(cs) = st.channels.get_mut(chan) {
                            queue_authenticated_channel_ack(
                                cs,
                                &scheduler,
                                chan,
                                id,
                                sender_pseudonym,
                                crate::channel::encode_text_ack(
                                    id,
                                    st.channel_presence_opt_in.contains(chan),
                                ),
                            );
                        }
                    }
                    if let Err(error) = persist_current_direct_state(st) {
                        metrics::log_event("channel_message_persist_error", &[("e", error)]);
                        return false;
                    }
                    let display_sender = sender_pseudonym
                        .and_then(|member| {
                            st.channels
                                .get(chan)
                                .and_then(|cs| {
                                    crate::channel::metadata::Metadata::read(&cs.role).ok()
                                })
                                .and_then(|metadata| metadata.nickname(member).map(str::to_owned))
                        })
                        .unwrap_or_else(|| sender.clone());
                    let sent_ok = events.send(Ev::ChannelMessage {
                        channel: chan.to_string(),
                        msg_id: id,
                        ts_unix: now_unix(),
                        sender: display_sender,
                        channel_epoch,
                        sender_index: sender_idx,
                        text: body,
                        latency_hint_ms: latency,
                    });
                    if let Some(sender_pseudonym) = sender_pseudonym.filter(|member_id| {
                        share_presence
                            && st.channel_presence_opt_in.contains(chan)
                            && st
                                .channel_presence
                                .contains_key(&(chan.to_string(), *member_id))
                    }) {
                        observe_channel_reachability(
                            st,
                            chan,
                            sender_pseudonym,
                            Reachability::RecentlyReachable,
                            PASSIVE_REACHABILITY_SECS,
                            events,
                        );
                    }
                    metrics::log_event(
                        "chan_text_delivered",
                        &[
                            ("node", node_tag.clone()),
                            ("msg", encode_b64url(&id)),
                            ("emit_ok", sent_ok.is_ok().to_string()),
                        ],
                    );
                    was_text = true;
                }
                Some(crate::channel::ChannelInner::Dir(name, route)) => {
                    let route = *route;
                    let authorized = st.channels.get(chan).is_some_and(|cs| {
                        let roster = cs.role.roster();
                        roster.iter().any(|(_, roster_name)| roster_name == &name)
                            && (cs.role.is_owner_name(&sender) || sender == name)
                            && cs.role.pseudonym_for_name(&name) == Some(route.pseudonym)
                            && cs
                                .directory
                                .get(&name)
                                .is_none_or(|known| known.pseudonym == route.pseudonym)
                    });
                    if !authorized {
                        restore_directory_receive(st, chan, &role_checkpoint);
                        metrics::log_event(
                            "chan_dir_rejected",
                            &[("channel", chan.to_string()), ("name", name)],
                        );
                        return false;
                    }
                    let changed_self = sender == name
                        && st.channels.get(chan).is_some_and(|cs| {
                            cs.directory.get(&name).is_none_or(|old| old != &route)
                        });
                    let response_route = route.clone();
                    if !commit_authenticated_directory(
                        st,
                        chan,
                        id,
                        &[(name.clone(), route)],
                        &role_checkpoint,
                        changed_self.then_some(&response_route),
                    ) {
                        return false;
                    }
                    metrics::log_event(
                        "chan_dir_learned",
                        &[("channel", chan.to_string()), ("name", name)],
                    );
                }
                Some(crate::channel::ChannelInner::DirBatch(entries)) => {
                    // Validate the entire owner-authenticated batch before
                    // installing any entry or publishing an ACK route.
                    let authorized = st.channels.get(chan).is_some_and(|cs| {
                        cs.role.is_owner_name(&sender)
                            && entries.iter().all(|(name, route)| {
                                cs.role.pseudonym_for_name(name) == Some(route.pseudonym)
                                    && cs
                                        .directory
                                        .get(name)
                                        .is_none_or(|known| known.pseudonym == route.pseudonym)
                            })
                    });
                    if !authorized {
                        restore_directory_receive(st, chan, &role_checkpoint);
                        return false;
                    }
                    if !commit_authenticated_directory(
                        st,
                        chan,
                        id,
                        &entries,
                        &role_checkpoint,
                        None,
                    ) {
                        return false;
                    }
                }
                Some(crate::channel::ChannelInner::DirectIntro {
                    name,
                    pseudonym,
                    direct_public,
                }) => {
                    let authorized = direct_public != [0; 32]
                        && st.channels.get(chan).is_some_and(|channel| {
                            channel.role.pseudonym_for_name(&name) == Some(pseudonym)
                                && (channel.role.is_owner_name(&sender) || sender == name)
                                && channel
                                    .directory
                                    .get(&name)
                                    .is_some_and(|route| route.pseudonym == pseudonym)
                        });
                    if authorized {
                        if let Some(route) = st
                            .channels
                            .get_mut(chan)
                            .and_then(|channel| channel.directory.get_mut(&name))
                        {
                            route.direct_public = direct_public;
                        }
                    }
                }
                Some(crate::channel::ChannelInner::CommitAck {
                    commit_id,
                    epoch,
                    share_presence,
                }) => {
                    let mut acknowledged_sender = None;
                    if let Some(cs) = st.channels.get_mut(chan) {
                        if let Some(outbox) = cs.membership_outbox.as_mut() {
                            if outbox.commit_id == commit_id && outbox.epoch == epoch {
                                if let Some(pseudonym) = cs.role.pseudonym_for_name(&sender) {
                                    if outbox.expected.contains_key(&pseudonym) {
                                        outbox.acknowledged.insert(pseudonym);
                                        acknowledged_sender = Some(pseudonym);
                                    }
                                }
                                if outbox.acknowledged.len() == outbox.expected.len() {
                                    cs.membership_outbox = None;
                                    cs.membership_done.notify_waiters();
                                }
                            }
                        }
                    }
                    if let Some(member_id) = acknowledged_sender.filter(|member_id| {
                        share_presence
                            && st.channel_presence_opt_in.contains(chan)
                            && st
                                .channel_presence
                                .contains_key(&(chan.to_string(), *member_id))
                    }) {
                        if let Err(error) = persist_current_direct_state(st) {
                            metrics::log_event("channel_ack_persist_error", &[("e", error)]);
                            return false;
                        }
                        observe_channel_reachability(
                            st,
                            chan,
                            member_id,
                            Reachability::RecentlyReachable,
                            PASSIVE_REACHABILITY_SECS,
                            events,
                        );
                    }
                }
                Some(crate::channel::ChannelInner::TextAck {
                    message_id,
                    share_presence,
                }) => {
                    let mut completed = false;
                    let mut acknowledged_sender = None;
                    let previous = st
                        .channels
                        .get(chan)
                        .and_then(|cs| cs.message_outbox.get(&message_id))
                        .cloned();
                    if let Some(cs) = st.channels.get_mut(chan) {
                        let authenticated = cs.role.pseudonym_for_name(&sender);
                        if let Some(outbox) = cs.message_outbox.get_mut(&message_id) {
                            if let Some(pseudonym) = authenticated {
                                if outbox.expected.contains_key(&pseudonym) {
                                    outbox.acknowledged.insert(pseudonym);
                                    acknowledged_sender = Some(pseudonym);
                                }
                            }
                            completed = !outbox.expected.is_empty()
                                && outbox
                                    .expected
                                    .keys()
                                    .all(|peer| outbox.acknowledged.contains(peer));
                        }
                        if completed {
                            cs.message_outbox.remove(&message_id);
                        }
                    }
                    // Authenticated ACK consumption and outbox completion are
                    // one durable boundary, regardless of presence opt-in.
                    if let Err(error) = persist_current_direct_state(st) {
                        let owner_seed = channel_seed(st, chan);
                        if let Some(cs) = st.channels.get_mut(chan) {
                            if let Some(previous) = previous {
                                cs.message_outbox.insert(message_id, previous);
                            }
                            if let Ok(role) =
                                cs.role
                                    .restore_checkpoint(&archive_key, &role_checkpoint, || {
                                        gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                                    })
                            {
                                cs.role = role;
                            }
                        }
                        metrics::log_event("channel_ack_persist_error", &[("e", error)]);
                        return false;
                    }
                    if completed {
                        if let Some(cs) = st.channels.get_mut(chan) {
                            cs.forget_forward(&message_id);
                        }
                    }
                    if let Some(member_id) = acknowledged_sender.filter(|member_id| {
                        share_presence
                            && st.channel_presence_opt_in.contains(chan)
                            && st
                                .channel_presence
                                .contains_key(&(chan.to_string(), *member_id))
                    }) {
                        observe_channel_reachability(
                            st,
                            chan,
                            member_id,
                            Reachability::RecentlyReachable,
                            PASSIVE_REACHABILITY_SECS,
                            events,
                        );
                    }
                    if completed {
                        let _ = events.send(Ev::ChannelDelivery {
                            channel: chan.to_string(),
                            msg_id: message_id,
                        });
                    }
                }
                Some(crate::channel::ChannelInner::PresenceLease {
                    counter,
                    mode,
                    lease_secs,
                }) => {
                    let Some(member_id) = st
                        .channels
                        .get(chan)
                        .and_then(|channel| channel.role.pseudonym_for_name(&sender))
                    else {
                        return false;
                    };
                    if let Err(error) = persist_current_direct_state(st) {
                        let owner_seed = channel_seed(st, chan);
                        let restored = st.channels.get(chan).and_then(|channel| {
                            channel
                                .role
                                .restore_checkpoint(&archive_key, &role_checkpoint, || {
                                    gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                                })
                                .ok()
                        });
                        if let Some(restored) = restored {
                            st.channels.get_mut(chan).expect("channel exists").role = restored;
                        }
                        metrics::log_event("channel_presence_persist_error", &[("e", error)]);
                        return false;
                    }
                    if !apply_channel_presence(
                        st, chan, member_id, counter, mode, lease_secs, events,
                    ) {
                        metrics::log_event(
                            "channel_presence_replay_rejected",
                            &[("channel", chan.to_string())],
                        );
                    }
                    was_text = true;
                }
                None => {}
            }
        }
        Ok(gcoms_mls::ReceiveOutcome::CommitMerged {
            sender_index: sender_idx,
        }) => {
            if let Some(cs) = st.channels.get_mut(chan) {
                // The authenticated commit is the membership authority. Remove
                // obsolete public routing before an ACK or any later state save;
                // a re-added name must learn its new route from a fresh MLS Dir.
                cs.directory.retain(|name, route| {
                    cs.role.pseudonym_for_name(name) == Some(route.pseudonym)
                });
                let _ = events.send(Ev::ChannelRosterChanged {
                    channel: chan.to_string(),
                    channel_id: cs.id,
                });
                let sender_pseudonym = cs
                    .role
                    .roster()
                    .into_iter()
                    .find(|(idx, _)| *idx == sender_idx)
                    .and_then(|(_, name)| cs.role.pseudonym_for_name(&name));
                if let Some(sender_pseudonym) = sender_pseudonym {
                    let epoch = cs.role.epoch();
                    queue_authenticated_channel_ack(
                        cs,
                        &scheduler,
                        chan,
                        id,
                        sender_pseudonym,
                        crate::channel::encode_commit_ack(
                            id,
                            epoch,
                            st.channel_presence_opt_in.contains(chan),
                        ),
                    );
                }
            }
            metrics::log_event(
                "chan_commit_merged",
                &[("channel", chan.to_string()), ("node", node_tag)],
            );
        }
        Ok(gcoms_mls::ReceiveOutcome::Other) => {}
    }
    was_text
}

fn restore_directory_receive(st: &mut NodeState, chan: &str, checkpoint: &[u8]) {
    let archive_key = channel_archive_key(&st.identity_seed);
    let owner_seed = channel_seed(st, chan);
    if let Some(cs) = st.channels.get_mut(chan) {
        match cs.role.restore_checkpoint(&archive_key, checkpoint, || {
            gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
        }) {
            Ok(role) => cs.role = role,
            Err(error) => {
                metrics::log_event(
                    "channel_directory_rollback_error",
                    &[("e", error.to_string())],
                );
                st.pause_failed_owner_transition();
            }
        }
    }
}

/// Metadata, MLS ratchets and the exact ACK enter one durable checkpoint.
/// No ACK is submitted to the scheduler until this transaction succeeds.
fn commit_channel_metadata(
    st: &mut NodeState,
    chan: &str,
    id: [u8; 16],
    sender: &str,
    update: &[u8],
    checkpoint: &[u8],
) -> bool {
    let Some(cs) = st.channels.get_mut(chan) else {
        return false;
    };
    let Some(actor) = cs.role.pseudonym_for_name(sender) else {
        return false;
    };
    let route = cs
        .directory
        .values()
        .find(|r| r.pseudonym == actor)
        .cloned();
    let key = crate::channel::UnroutedAckKey {
        original_id: id,
        sender_pseudonym: actor,
    };
    if (route.is_some() && cs.pending_control.len() >= crate::channel::CHANNEL_ACK_LIMIT)
        || (route.is_none() && !cs.can_journal_unrouted_ack(&key))
    {
        restore_directory_receive(st, chan, checkpoint);
        return false;
    }
    let previous = (
        cs.pending_control.clone(),
        cs.commit_ack_cache.clone(),
        cs.commit_ack_order.clone(),
        cs.unrouted_ack_journal.clone(),
        cs.unrouted_ack_order.clone(),
    );
    let mut discarded_outbox = None;
    let mut ownership_announcement = None;
    let staged = (|| {
        let was_owner = cs.role.is_owner();
        crate::channel::metadata::Metadata::receive(&mut cs.role, actor, update)?;
        if !was_owner && cs.role.is_owner() {
            if cs.message_outbox.len() >= 64 {
                return Err("too many unacknowledged channel messages".into());
            }
            let own = cs.role.own_pseudonym();
            let mut expected = HashMap::new();
            for member in cs.role.roster_members() {
                if member.pseudonym == own {
                    continue;
                }
                let target = cs
                    .directory
                    .values()
                    .find(|route| route.pseudonym == member.pseudonym)
                    .ok_or("Channel routing must be complete before accepting ownership")?;
                expected.insert(member.pseudonym, target.clone());
            }
            let mut payload = vec![crate::channel::CHAN_METADATA];
            payload.extend(crate::channel::metadata::Metadata::ownership_snapshot(
                &cs.role,
            )?);
            let wire = cs.role.send(&payload).map_err(|e| e.to_string())?;
            let announcement_id = crate::channel::msg_id(chan, &wire);
            cs.message_outbox.insert(
                announcement_id,
                crate::channel::ChannelMessageOutbox {
                    wire,
                    expected,
                    acknowledged: HashSet::new(),
                },
            );
            ownership_announcement = Some(announcement_id);
        }
        if crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
            discarded_outbox = Some(std::mem::take(&mut cs.message_outbox));
        }
        let wire = cs
            .role
            .send(&crate::channel::encode_text_ack(id, false))
            .map_err(|e| e.to_string())?;
        if let Some(route) = route {
            cs.pending_control.push_back((route.clone(), wire.clone()));
            cs.cache_ack(id, route, wire);
        } else {
            cs.journal_unrouted_ack(key, wire);
        }
        Ok::<(), String>(())
    })();
    let committed = staged.and_then(|_| persist_current_direct_state(st));
    if let Err(error) = committed {
        if let Some(cs) = st.channels.get_mut(chan) {
            (
                cs.pending_control,
                cs.commit_ack_cache,
                cs.commit_ack_order,
                cs.unrouted_ack_journal,
                cs.unrouted_ack_order,
            ) = previous;
            if let Some(outbox) = discarded_outbox {
                cs.message_outbox = outbox;
            }
            if let Some(id) = ownership_announcement {
                cs.message_outbox.remove(&id);
            }
            cs.overlay.forget_sighting(id);
        }
        restore_directory_receive(st, chan, checkpoint);
        metrics::log_event("channel_metadata_rejected", &[("e", error)]);
        return false;
    }
    if let Some(cs) = st
        .channels
        .get_mut(chan)
        .filter(|cs| crate::channel::metadata::Metadata::read(&cs.role).is_ok_and(|m| m.closed()))
    {
        cs.discard_forward_queue();
    }
    true
}

/// Commit authenticated route descriptors together with the MLS receive state.
/// No queued wire, recipient set or ACK is recreated when a member changes relay.
fn commit_authenticated_directory(
    st: &mut NodeState,
    chan: &str,
    id: [u8; 16],
    entries: &[(String, crate::channel::ChannelRoute)],
    role_checkpoint: &[u8],
    reply_route: Option<&crate::channel::ChannelRoute>,
) -> bool {
    let mut changes = Vec::new();
    if let Some(cs) = st.channels.get_mut(chan) {
        for (name, route) in entries {
            if let Some(change) = cs.install_authenticated_route(name, route) {
                changes.push(change);
            }
        }
    }
    // An expired local route cannot authorize a reciprocal Dir. It must not
    // prevent accepting the authenticated remote route or retargeting an
    // existing ACK to it. Preserve local authority unchanged in this case.
    let now = now_unix();
    let reply_route = reply_route.filter(|_| {
        st.channels.get(chan).is_some_and(|cs| {
            cs.own_route.public.data.expiry > now && cs.own_route.public.control.expiry > now
        })
    });
    // Commit the receive state, route replacement and any available reciprocal
    // Dir atomically. Other reply or persistence failures still roll back the
    // receive, allowing the exact incoming wire to retry.
    let committed = match reply_route {
        Some(route) => stage_own_route_reply(st, chan, route, id).map(|(wire, _)| Some(wire)),
        None => persist_current_direct_state(st).map(|_| None),
    };
    let reply = match committed {
        Ok(reply) => reply,
        Err(error) => {
            if let Some(cs) = st.channels.get_mut(chan) {
                for change in changes.into_iter().rev() {
                    cs.rollback_authenticated_route(change);
                }
                // Permit this exact authenticated wire to retry after the failed
                // durable commit, without dropping unrelated replay protection.
                cs.overlay.forget_sighting(id);
            }
            restore_directory_receive(st, chan, role_checkpoint);
            metrics::log_event("channel_directory_persist_error", &[("e", error)]);
            return false;
        }
    };
    let scheduler = st.scheduler.clone();
    if let (Some(route), Some(wire)) = (reply_route, reply) {
        enqueue_channel_control(&scheduler, chan, route, &wire);
    }
    if let Some(cs) = st.channels.get_mut(chan) {
        for (name, _) in entries {
            // A stale entry may have been ignored. Only use the installed
            // authenticated route when activating peers and resolving ACKs.
            let Some(route) = cs.directory.get(name).cloned() else {
                continue;
            };
            cs.learn(&route);
            for mut wire in cs.promote_unrouted_acks(&route) {
                enqueue_channel_control(&scheduler, chan, &route, &wire);
                wire.fill(0);
            }
        }
    }
    true
}

pub(crate) fn queue_authenticated_channel_ack(
    channel: &mut crate::channel::ChannelState,
    scheduler: &RelayScheduler,
    channel_name: &str,
    original_id: [u8; 16],
    sender_pseudonym: [u8; 32],
    ack: Vec<u8>,
) {
    if sender_pseudonym == channel.role.own_pseudonym()
        || channel.commit_ack_cache.contains_key(&original_id)
    {
        return;
    }
    let key = crate::channel::UnroutedAckKey {
        original_id,
        sender_pseudonym,
    };
    let route = channel
        .directory
        .values()
        .find(|route| route.pseudonym == sender_pseudonym)
        .cloned();
    if route.is_some() && channel.pending_control.len() >= crate::channel::CHANNEL_ACK_LIMIT {
        return;
    }
    if route.is_none() && !channel.can_journal_unrouted_ack(&key) {
        return;
    }
    let Ok(mut wire) = channel.role.send(&ack) else {
        return;
    };
    if let Some(route) = route {
        channel
            .pending_control
            .push_back((route.clone(), wire.clone()));
        channel.cache_ack(original_id, route.clone(), wire.clone());
        enqueue_channel_control(scheduler, channel_name, &route, &wire);
        wire.fill(0);
    } else {
        channel.journal_unrouted_ack(key, wire);
    }
}

pub(crate) fn enqueue_channel_control(
    scheduler: &RelayScheduler,
    channel: &str,
    peer: &crate::channel::ChannelRoute,
    wire: &[u8],
) -> bool {
    let cell = Cell::new(
        CellType::Msg,
        0,
        0,
        crate::proto::encode_chan(channel, wire),
    );
    scheduler
        .push(ProducerClass::ChannelControl, peer.control.clone(), cell)
        .is_ok()
}

pub(crate) async fn create_channel(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    display: &str,
    capacity: usize,
    visibility: crate::channel::ChannelVisibility,
) -> Result<crate::channel::ChannelId, String> {
    if channel.len() > u16::MAX as usize || display.len() > u16::MAX as usize {
        return Err("channel or display name too long".into());
    }
    let (identity_seed, relay) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.channels.contains_key(channel) {
            return Err("channel exists".into());
        }
        if st.channels.len() >= gcoms_mls::CHANNEL_MAX {
            return Err("channel limit reached".into());
        }
        (channel_seed(&st, channel), st.client_relay.clone())
    };
    let identity = gcoms_crypto::IdentityKeypair::from_seed(identity_seed);
    let owner =
        gcoms_mls::OwnerSession::create(identity, display, capacity).map_err(|e| e.to_string())?;
    let pseudonym = owner.own_pseudonym();
    let direct_secret = channel_direct_secret(&identity_seed, &pseudonym);
    let own_route = provision_channel_route(scheduler, &relay, pseudonym, direct_secret).await?;
    open_route_lanes(scheduler, &own_route);
    // Seed the overlay eviction RNG from OS entropy, not from the public
    // queue id: a predictable, restart-stable seed would let an observer
    // anticipate which view entries we evict (T12). Fresh randomness per
    // create makes eviction unlinkable across restarts.
    let seed = rand::thread_rng().next_u64();
    let mut cs = crate::channel::ChannelState::new(
        crate::channel::ChannelRole::Owner(owner),
        own_route,
        seed,
        channel.to_string(),
        visibility,
    );
    let id = cs.id;
    let public = cs.own_route.public.clone();
    cs.directory.insert(display.to_string(), public.clone());
    cs.learn(&public);
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    if st.channels.contains_key(channel) {
        return Err("channel exists".into());
    }
    st.channels.insert(channel.to_string(), cs);
    metrics::log_event("channel_created", &[("channel", channel.to_string())]);
    Ok(id)
}

/// Wrapping key for sealed MLS archives of every channel on this node. The
/// group id inside the archive (bound as AAD) keeps channels apart.
pub(crate) fn channel_archive_key(identity_seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(identity_seed), b"channel-archive");
    let mut key = [0u8; 32];
    hk.expand(b"gc1/channel-archive/v1", &mut key)
        .expect("32 bytes fit hkdf-sha256");
    key
}

/// Start the always-on lanes toward a channel route's own data/control
/// queues. Unpinned: if the channel goes quiet for `LANE_IDLE_TTL` the lane
/// closes and reopens on the next real job.
pub(crate) fn open_route_lanes(
    scheduler: &RelayScheduler,
    route: &crate::channel::OwnedChannelRoute,
) {
    for owned in &route.aliases {
        let _ = scheduler.open_lane(
            crate::scheduler::LaneAuth::Push {
                contact: owned.contact.clone(),
            },
            false,
        );
    }
}

pub(crate) fn close_route_lanes(
    scheduler: &RelayScheduler,
    route: &crate::channel::OwnedChannelRoute,
) {
    for owned in &route.aliases {
        scheduler.close_lane(&crate::scheduler::LaneAuth::Push {
            contact: owned.contact.clone(),
        });
    }
}

pub(crate) fn channel_seed(st: &NodeState, channel: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&st.identity_seed), channel.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"gc1/channel-seed", &mut seed)
        .expect("32 bytes fit hkdf-sha256");
    seed
}

pub(crate) fn channel_direct_secret(node_seed: &[u8; 32], pseudonym: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(node_seed), pseudonym);
    let mut secret = [0u8; 32];
    hk.expand(b"gc1/channel-direct/x25519/v1", &mut secret)
        .expect("32 bytes fit hkdf-sha256");
    secret
}

pub(crate) async fn prepare_channel_join(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    display: &str,
) -> Result<u64, String> {
    if display.len() > u16::MAX as usize {
        return Err("display name too long".into());
    }
    if state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .prepared
        .len()
        >= 64
    {
        return Err("too many prepared channel joins".into());
    }
    let prepared = gcoms_mls::ChannelMember::prepare(display).map_err(|e| e.to_string())?;
    let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
    let (relay, identity_seed) = {
        let state = state.lock().unwrap_or_else(|p| p.into_inner());
        (state.client_relay.clone(), state.identity_seed)
    };
    let direct_secret = channel_direct_secret(&identity_seed, &pseudonym);
    let route = provision_channel_route(scheduler, &relay, pseudonym, direct_secret).await?;
    open_route_lanes(scheduler, &route);
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    let id = st.next_prep_id;
    st.next_prep_id = st.next_prep_id.checked_add(1).ok_or("join id exhausted")?;
    st.prepared.insert(
        id,
        PreparedChannelJoin {
            mls: prepared,
            route,
            display: display.to_string(),
        },
    );
    Ok(id)
}

pub(crate) fn join_channel(
    st: &mut NodeState,
    req_id: u64,
    channel: &str,
    visibility: crate::channel::ChannelVisibility,
    welcome: &[u8],
    events: &broadcast::Sender<Ev>,
) -> Result<(), String> {
    if channel.len() > u16::MAX as usize {
        return Err("channel name too long".into());
    }
    if st.channels.contains_key(channel) {
        return Err("channel exists".into());
    }
    if st.channels.len() >= gcoms_mls::CHANNEL_MAX {
        return Err("channel limit reached".into());
    }
    let prepared = st.prepared.remove(&req_id).ok_or("unknown req")?;
    let member =
        gcoms_mls::ChannelMember::join(prepared.mls, welcome).map_err(|e| e.to_string())?;
    if member.own_pseudonym() != prepared.route.public.pseudonym {
        return Err("channel route does not match MLS leaf".into());
    }
    // Seed the overlay eviction RNG from OS entropy, not from the public
    // queue id: a predictable, restart-stable seed would let an observer
    // anticipate which view entries we evict (T12). Fresh randomness per
    // create makes eviction unlinkable across restarts.
    let seed = rand::thread_rng().next_u64();
    let mut channel_state = crate::channel::ChannelState::new(
        crate::channel::ChannelRole::Member(member),
        prepared.route,
        seed,
        channel.to_string(),
        visibility,
    );
    let own_route = channel_state.own_route.public.clone();
    channel_state
        .directory
        .insert(prepared.display, own_route.clone());
    channel_state.learn(&own_route);
    st.channels.insert(channel.to_string(), channel_state);
    let channel_id = st.channels[channel].id;
    let _ = events.send(Ev::ChannelRosterChanged {
        channel: channel.to_string(),
        channel_id,
    });
    metrics::log_event("channel_joined", &[("channel", channel.to_string())]);
    let (parked, remaining): (Vec<_>, Vec<_>) = std::mem::take(&mut st.chan_parked)
        .into_iter()
        .partition(|(parked_channel, _)| parked_channel == channel);
    st.chan_parked = remaining;
    for (chan, wire) in parked {
        let received = std::time::Instant::now();
        process_chan_cell(st, &chan, wire, received, events);
    }
    Ok(())
}

pub(crate) async fn push_ctrl_to_route(
    scheduler: &RelayScheduler,
    route: &crate::channel::ChannelRoute,
    cell: &Cell,
) -> Result<(), String> {
    push_to_contact(scheduler, &route.control, cell).await
}

pub(crate) async fn push_to_contact(
    scheduler: &RelayScheduler,
    contact: &AliasContact,
    cell: &Cell,
) -> Result<(), String> {
    scheduler
        .push(ProducerClass::ChannelControl, contact.clone(), cell.clone())
        .map_err(|e| e.to_string())?
        .completion()
        .await
        .accepted()
        .map(|_| ())
}

pub(crate) async fn broadcast_chan(
    st: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    mls_wire: &[u8],
    exclude: Option<&str>,
) -> Result<(), String> {
    let targets = {
        let st = st.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get(channel) else {
            return Err("no channel".into());
        };
        let targets: Vec<crate::channel::ChannelRoute> = cs
            .directory
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != exclude)
            .map(|(_, info)| info.clone())
            .collect();
        targets
    };
    broadcast_chan_to_targets(scheduler, channel, mls_wire, &targets).await
}

pub(crate) async fn broadcast_chan_to_targets(
    scheduler: &RelayScheduler,
    channel: &str,
    mls_wire: &[u8],
    targets: &[crate::channel::ChannelRoute],
) -> Result<(), String> {
    let cells = crate::proto::encode_chan_cells(channel, mls_wire)?;
    let mut failures = 0;
    for t in targets {
        for cell in &cells {
            if push_ctrl_to_route(scheduler, t, cell).await.is_err() {
                failures += 1;
                break;
            }
        }
    }
    metrics::log_event(
        "chan_broadcast",
        &[
            ("channel", channel.to_string()),
            ("targets", targets.len().to_string()),
            ("failures", failures.to_string()),
        ],
    );
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("channel broadcast failed for {failures} target(s)"))
    }
}

pub(crate) fn enqueue_broadcast_chan(
    st: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    class: ProducerClass,
    channel: &str,
    mls_wire: &[u8],
    exclude: Option<&str>,
) -> Result<(), String> {
    let targets = {
        let st = st.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get(channel) else {
            return Err("no channel".into());
        };
        let own = cs.role.own_pseudonym();
        cs.directory
            .iter()
            .filter(|(name, route)| Some(name.as_str()) != exclude && route.pseudonym != own)
            .map(|(_, route)| route.clone())
            .collect::<Vec<_>>()
    };
    let cells = crate::proto::encode_chan_cells(channel, mls_wire)?;
    for target in targets {
        for cell in &cells {
            scheduler
                .push(class, target.control.clone(), cell.clone())
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub(crate) fn retain_channel_wire(state: &Arc<Mutex<NodeState>>, channel: &str, wire: &[u8]) {
    let id = crate::channel::msg_id(channel, wire);
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cs) = st.channels.get_mut(channel) {
        if !cs.pending.iter().any(|entry| entry.id == id) {
            cs.note(id, wire.to_vec());
            cs.enqueue_forward(id, wire.to_vec());
        }
    }
}

/// Membership convergence timeout. This blocks only the command that
/// changed membership (per-channel serialisation), never the node.
pub(crate) const MEMBERSHIP_CONVERGENCE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(90);

pub(crate) async fn wait_for_membership_acks(state: &Arc<Mutex<NodeState>>, channel: &str) -> bool {
    let deadline = tokio::time::Instant::now() + MEMBERSHIP_CONVERGENCE_TIMEOUT;
    let notify = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        match st.channels.get(channel) {
            Some(cs) => cs.membership_done.clone(),
            None => return true,
        }
    };
    wait_for_membership_condition(&notify, deadline, || {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.channels
            .get(channel)
            .is_none_or(|cs| cs.membership_outbox.is_none())
    })
    .await
}

async fn wait_for_membership_condition(
    notify: &tokio::sync::Notify,
    deadline: tokio::time::Instant,
    complete: impl Fn() -> bool,
) -> bool {
    loop {
        // Register before reading the condition. notify_waiters does not retain
        // a permit for a future created after the final ACK clears the outbox.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if complete() {
            return true;
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            // An ACK can race the deadline; recheck the authoritative state.
            return complete();
        }
    }
}

/// Outcome of staging one admission under the channel lock.
enum StagedAdmission {
    /// This exact key package was already admitted; replay its Welcome.
    Replay(Vec<u8>),
    /// A fresh MLS add was staged and merged; broadcast the commit.
    Fresh(gcoms_mls::Admission),
}

/// The single lock-held admission decision shared by manual admit and invite
/// redemption: dedup, role/name/capacity checks, MLS stage+merge, and recording
/// the `membership_outbox` + `admission_cache`. Runs entirely inside the
/// caller's `NodeState` lock (no `.await`), so it composes with any additional
/// same-lock guard the caller applies first (e.g. the single-use invite flip).
///
/// `cs` must be the owner's channel state. `member_route`/`mls_key_package` come
/// from a validated join package; `member_name` is the requested display name.
fn stage_admission_locked(
    cs: &mut crate::channel::ChannelState,
    channel: &str,
    member_route: &crate::channel::ChannelRoute,
    mls_key_package: &[u8],
    member_name: &str,
) -> Result<StagedAdmission, String> {
    if crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
        return Err("This channel is closed".into());
    }
    let request_id: [u8; 32] = Sha256::digest(mls_key_package).into();
    if let Some(cached) = cs.admission_cache.get(&request_id) {
        if cached.name == member_name && cached.pseudonym == member_route.pseudonym {
            return Ok(StagedAdmission::Replay(cached.welcome.clone()));
        }
        return Err("key package was already used by a different admission".into());
    }
    if cs.membership_outbox.is_some() {
        return Err("membership change still awaiting acknowledgements".into());
    }
    let expected = cs
        .directory
        .values()
        .filter(|route| route.pseudonym != cs.role.own_pseudonym())
        .map(|route| (route.pseudonym, route.clone()))
        .collect::<HashMap<_, _>>();
    if !cs.role.is_owner() {
        return Err("not owner".into());
    }
    if cs.directory.contains_key(member_name) {
        return Err("name taken".into());
    }
    let staged = cs
        .role
        .stage_admit(mls_key_package, member_name)
        .map_err(|e| e.to_string())?;
    cs.role.merge_pending().map_err(|e| e.to_string())?;
    let epoch = cs.role.epoch();
    if !expected.is_empty() {
        cs.membership_outbox = Some(crate::channel::MembershipOutbox {
            commit_id: crate::channel::msg_id(channel, &staged.commit),
            epoch,
            commit: staged.commit.clone(),
            expected,
            acknowledged: std::collections::HashSet::new(),
        });
    }
    cs.admission_cache.insert(
        request_id,
        crate::channel::CachedAdmission {
            name: member_name.to_string(),
            pseudonym: member_route.pseudonym,
            welcome: staged.welcome.clone(),
        },
    );
    cs.admission_cache_order.push_back(request_id);
    while cs.admission_cache_order.len() > 64 {
        if let Some(oldest) = cs.admission_cache_order.pop_front() {
            cs.admission_cache.remove(&oldest);
        }
    }
    Ok(StagedAdmission::Fresh(gcoms_mls::Admission {
        commit: staged.commit,
        welcome: staged.welcome,
    }))
}

#[cfg(all(test, feature = "client-persist"))]
pub(crate) fn stage_recovery_admission_fixture(
    cs: &mut crate::channel::ChannelState,
    channel: &str,
    route: &crate::channel::ChannelRoute,
    package: &[u8],
    name: &str,
) -> Result<(), String> {
    stage_admission_locked(cs, channel, route, package, name).map(|_| ())
}

pub(crate) async fn admit_channel(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    key_package: &[u8],
    member_name: &str,
) -> Result<Vec<u8>, String> {
    if channel.len() > u16::MAX as usize || member_name.len() > u16::MAX as usize {
        return Err("channel or member name too long".into());
    }
    let (member_route, mls_key_package) =
        crate::channel::decode_join_package(key_package).ok_or("bad channel join package")?;
    if gcoms_mls::pseudonym_of_key_package(mls_key_package) != Some(member_route.pseudonym) {
        return Err("channel route does not match MLS leaf".into());
    }
    let admission = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get_mut(channel) else {
            return Err("no channel".into());
        };
        if cs.own_route.aliases.len() != 2 {
            return Err("channel routing is recovering".into());
        }
        match stage_admission_locked(cs, channel, &member_route, mls_key_package, member_name)? {
            StagedAdmission::Replay(welcome) => return Ok(welcome),
            StagedAdmission::Fresh(admission) => admission,
        }
    };
    finalize_admission(
        state,
        scheduler,
        channel,
        &member_route,
        member_name,
        admission,
    )
    .await
}

/// Broadcast a staged admission commit, wait for convergence, publish the new
/// directory entry, and bootstrap the newcomer. Shared by manual admit and
/// invite redemption. Returns the newcomer's Welcome.
async fn finalize_admission(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    member_route: &crate::channel::ChannelRoute,
    member_name: &str,
    admission: gcoms_mls::Admission,
) -> Result<Vec<u8>, String> {
    retain_channel_wire(state, channel, &admission.commit);
    enqueue_broadcast_chan(
        state,
        scheduler,
        ProducerClass::ChannelControl,
        channel,
        &admission.commit,
        None,
    )?;
    let converged = wait_for_membership_acks(state, channel).await;
    if !converged {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(outbox) = st
            .channels
            .get(channel)
            .and_then(|cs| cs.membership_outbox.as_ref())
        {
            metrics::log_event(
                "channel_membership_pending",
                &[
                    ("expected", outbox.expected.len().to_string()),
                    ("acknowledged", outbox.acknowledged.len().to_string()),
                ],
            );
        }
    }
    metrics::log_event(
        "channel_membership_converged",
        &[
            ("channel", channel.to_string()),
            ("ok", converged.to_string()),
        ],
    );
    let (full_dir, new_entry) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get_mut(channel) else {
            return Err("no channel".into());
        };
        cs.directory
            .insert(member_name.to_string(), member_route.clone());
        cs.learn(member_route);
        let entry = cs.directory.get(member_name).cloned().unwrap();
        (cs.directory.clone().into_iter().collect::<Vec<_>>(), entry)
    };
    let new_wire = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get_mut(channel) else {
            return Err("no channel".into());
        };
        cs.role
            .send(&crate::channel::encode_dir(member_name, &new_entry))
            .map_err(|e| e.to_string())?
    };
    retain_channel_wire(state, channel, &new_wire);
    enqueue_broadcast_chan(
        state,
        scheduler,
        ProducerClass::ChannelControl,
        channel,
        &new_wire,
        Some(member_name),
    )?;
    let bootstrap = full_dir
        .into_iter()
        .filter(|(name, _)| name != member_name)
        .collect::<Vec<_>>();
    for entries in bootstrap.chunks(crate::channel::CHANNEL_DIR_BATCH_LIMIT) {
        let wire = {
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            let Some(cs) = st.channels.get_mut(channel) else {
                return Err("no channel".into());
            };
            let payload = crate::channel::encode_dir_batch(entries)
                .ok_or("channel directory batch is too large")?;
            cs.role.send(&payload).map_err(|e| e.to_string())?
        };
        retain_channel_wire(state, channel, &wire);
        let cell = Cell::new(
            CellType::Msg,
            0,
            0,
            crate::proto::encode_chan(channel, &wire),
        );
        scheduler
            .push(
                ProducerClass::ChannelControl,
                member_route.control.clone(),
                cell,
            )
            .map_err(|error| error.to_string())?;
    }
    queue_channel_metadata_snapshot(state, channel, member_route)?;
    metrics::log_event(
        "channel_admitted",
        &[
            ("channel", channel.to_string()),
            ("member", member_name.to_string()),
        ],
    );
    Ok(admission.welcome.clone())
}

fn queue_channel_metadata_snapshot(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    recipient: &crate::channel::ChannelRoute,
) -> Result<(), String> {
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    let key = channel_archive_key(&st.identity_seed);
    let seed = channel_seed(&st, channel);
    let cs = st.channels.get_mut(channel).ok_or("no channel")?;
    if cs
        .role
        .channel_metadata()
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Ok(());
    }
    if cs.message_outbox.len() >= 64 {
        return Err("too many unacknowledged channel messages".into());
    }
    let checkpoint = cs.role.checkpoint(&key).map_err(|e| e.to_string())?;
    let mut payload = vec![crate::channel::CHAN_METADATA];
    payload.extend(crate::channel::metadata::Metadata::snapshot(&cs.role)?);
    let wire = match cs.role.send(&payload) {
        Ok(wire) => wire,
        Err(error) => {
            cs.role = cs
                .role
                .restore_checkpoint(&key, &checkpoint, || {
                    gcoms_crypto::IdentityKeypair::from_seed(seed)
                })
                .map_err(|e| e.to_string())?;
            return Err(error.to_string());
        }
    };
    let id = crate::channel::msg_id(channel, &wire);
    cs.message_outbox.insert(
        id,
        crate::channel::ChannelMessageOutbox {
            wire,
            expected: HashMap::from([(recipient.pseudonym, recipient.clone())]),
            acknowledged: HashSet::new(),
        },
    );
    if let Err(error) = persist_current_direct_state(&st) {
        let cs = st
            .channels
            .get_mut(channel)
            .expect("channel retained under lock");
        cs.message_outbox.remove(&id);
        cs.role = cs
            .role
            .restore_checkpoint(&key, &checkpoint, || {
                gcoms_crypto::IdentityKeypair::from_seed(seed)
            })
            .map_err(|e| e.to_string())?;
        return Err(error);
    }
    Ok(())
}

/// Default lifetime of a channel invite, used when the caller passes `0`.
/// Kept at or below the rendezvous queue lease so the queue never expires before
/// the invite does.
pub(crate) const DEFAULT_INVITE_TTL_SECS: u64 = 60 * 60;
pub(crate) const MAX_INVITE_TTL_SECS: u64 = 24 * 60 * 60;
/// Bound on live invites per channel (eviction prefers expired/consumed).
const MAX_INVITES_PER_CHANNEL: usize = 64;

/// Mint a single-use invite for a channel this node owns. Returns
/// `(invite_id, invite_secret, expiry)`; the caller builds the shareable link
/// (which carries the owner's public contact card so a friend can redeem it
/// over the relay). The secret is high-entropy, so the link needs no PAKE.
/// `ttl_secs` of `0` uses `DEFAULT_INVITE_TTL_SECS`.
pub(crate) fn create_channel_invite(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    ttl_secs: u64,
) -> Result<([u8; 16], [u8; 32], u64), String> {
    let ttl = if ttl_secs == 0 {
        DEFAULT_INVITE_TTL_SECS
    } else {
        ttl_secs.min(MAX_INVITE_TTL_SECS)
    };
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    let Some(cs) = st.channels.get_mut(channel) else {
        return Err("no channel".into());
    };
    if crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
        return Err("This channel is closed".into());
    }
    if !cs.role.is_owner() {
        return Err("not owner".into());
    }
    let mut id = [0u8; 16];
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    rand::thread_rng().fill_bytes(&mut secret);
    let expiry = now_unix().saturating_add(ttl);
    cs.invites.insert(
        id,
        crate::channel::InviteRecord {
            secret,
            expiry,
            consumed: None,
        },
    );
    cs.invite_order.push_back(id);
    evict_invites(cs);
    metrics::log_event(
        "channel_invite_created",
        &[("channel", channel.to_string())],
    );
    Ok((id, secret, expiry))
}

/// Keep the per-channel invite ledger bounded. Prefer discarding spent or
/// expired records before a live unconsumed one, so minting many invites cannot
/// silently invalidate an invite a friend is mid-redeeming.
fn evict_invites(cs: &mut crate::channel::ChannelState) {
    if cs.invite_order.len() <= MAX_INVITES_PER_CHANNEL {
        return;
    }
    let now = now_unix();
    // First pass: drop dead (consumed or expired) records, oldest first.
    let mut i = 0;
    while cs.invite_order.len() > MAX_INVITES_PER_CHANNEL && i < cs.invite_order.len() {
        let id = cs.invite_order[i];
        let dead = cs
            .invites
            .get(&id)
            .map(|record| record.consumed.is_some() || now >= record.expiry)
            .unwrap_or(true);
        if dead {
            cs.invite_order.remove(i);
            cs.invites.remove(&id);
        } else {
            i += 1;
        }
    }
    // If still over (all live), fall back to oldest-first.
    while cs.invite_order.len() > MAX_INVITES_PER_CHANNEL {
        if let Some(oldest) = cs.invite_order.pop_front() {
            cs.invites.remove(&oldest);
        }
    }
}

/// Redeem a single-use invite: verify id+secret, flip the invite to consumed
/// under the same lock that stages the MLS add (so two redemptions of one link
/// cannot both succeed), then admit the member and return their Welcome.
///
/// `key_package` is the redeemer's encoded join package (route + MLS key
/// package), exactly as `admit_channel` expects.
pub(crate) async fn redeem_invite(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    invite_id: &[u8; 16],
    invite_secret: &[u8; 32],
    key_package: &[u8],
    member_name: &str,
) -> Result<Vec<u8>, String> {
    use subtle::ConstantTimeEq;
    if channel.len() > u16::MAX as usize || member_name.len() > u16::MAX as usize {
        return Err("channel or member name too long".into());
    }
    let (member_route, mls_key_package) =
        crate::channel::decode_join_package(key_package).ok_or("bad channel join package")?;
    if gcoms_mls::pseudonym_of_key_package(mls_key_package) != Some(member_route.pseudonym) {
        return Err("channel route does not match MLS leaf".into());
    }
    let admission = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get_mut(channel) else {
            return Err("no channel".into());
        };
        // Look up and validate the invite, then flip it to consumed BEFORE
        // staging the add. All of this is one lock with no .await, so a racing
        // redemption either sees `consumed` already set or blocks until we
        // finish — exactly one winner.
        let Some(record) = cs.invites.get(invite_id) else {
            return Err("invite not found".into());
        };
        // Constant-time secret compare, and the same "invite not found" string
        // as an unknown id, so a wrong secret is not distinguishable from a
        // wrong id by the error. (The id lookup above still short-circuits, so
        // this is not fully timing-uniform — unexploitable with 128-bit ids.)
        if !bool::from(record.secret.ct_eq(invite_secret)) {
            return Err("invite not found".into());
        }
        if now_unix() >= record.expiry {
            return Err("invite expired".into());
        }
        // Single-use: once consumed, only the SAME redeemer may proceed (an
        // idempotent retry that replays the cached Welcome via the admission
        // cache). Any other pseudonym is refused — the invite is spent.
        if let Some(consumed_by) = record.consumed {
            if consumed_by != member_route.pseudonym {
                return Err("invite already used".into());
            }
        }
        // Stage the MLS add. It marks the invite consumed only if it actually
        // succeeds, so a transient failure (e.g. an in-flight membership
        // change) does not burn the invite. `stage_admission_locked` also
        // enforces capacity (MLS GroupFull -> "channel is full") and name-taken,
        // and replays idempotently for a repeated key package.
        match stage_admission_locked(cs, channel, &member_route, mls_key_package, member_name) {
            Ok(StagedAdmission::Replay(welcome)) => {
                if let Some(record) = cs.invites.get_mut(invite_id) {
                    record.consumed.get_or_insert(member_route.pseudonym);
                }
                return Ok(welcome);
            }
            Ok(StagedAdmission::Fresh(admission)) => {
                if let Some(record) = cs.invites.get_mut(invite_id) {
                    record.consumed = Some(member_route.pseudonym);
                }
                admission
            }
            Err(e) => return Err(e),
        }
    };
    metrics::log_event(
        "channel_invite_redeemed",
        &[("channel", channel.to_string())],
    );
    finalize_admission(
        state,
        scheduler,
        channel,
        &member_route,
        member_name,
        admission,
    )
    .await
}

/// Friend side: send a sealed `InviteRedeem` to the owner and wait for the
/// `InviteWelcome` reply (or a timeout). Registers a waiter under the sent
/// message id BEFORE sending, so a fast reply cannot race the registration.
/// Returns the MLS Welcome on success.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn redeem_invite_remote(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    owner: &NodeInfo,
    channel: &str,
    member_name: &str,
    key_package: &[u8],
    invite_id: [u8; 16],
    invite_secret: [u8; 32],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    // We must register the waiter under the message id the record will carry.
    // send_direct_record generates the transport id, but the InviteWelcome the
    // owner returns echoes the id WE put in the InviteRedeem body, so mint that
    // id here and key the waiter on it.
    let body_id = crate::node::state::fresh_msg_id();
    {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.pending_invite_redemptions.len() >= 64 {
            return Err("too many invite redemptions in flight".into());
        }
        st.pending_invite_redemptions.insert(body_id, tx);
    }
    let channel_owned = channel.to_string();
    let member_owned = member_name.to_string();
    let key_package_owned = key_package.to_vec();
    let send = send_direct_record(
        state,
        scheduler,
        owner,
        None,
        false,
        move |_generated_id, _seq| {
            crate::proto::encode_invite_redeem(
                body_id,
                &channel_owned,
                &member_owned,
                &invite_id,
                &invite_secret,
                &key_package_owned,
            )
            .ok_or_else(|| "invite redeem record too large".to_string())
        },
    )
    .await;
    if let Err(error) = send {
        state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending_invite_redemptions
            .remove(&body_id);
        return Err(error);
    }
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("invite redemption cancelled".into()),
        Err(_) => {
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending_invite_redemptions
                .remove(&body_id);
            Err("timed out waiting for the owner (they may be offline)".into())
        }
    }
}

/// How long to keep retrying a redemption blocked only by an in-flight
/// membership change on the same channel, before giving up and telling the
/// friend. Below the friend-side wait, so a retry can still land in time.
const INVITE_REDEEM_RETRY_SECS: u64 = 45;

/// Run one queued redemption and reply to the friend with the Welcome or error.
pub(crate) async fn service_one_invite(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
    request: crate::node::state::InviteRedeemRequest,
) {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(INVITE_REDEEM_RETRY_SECS);
    let result = loop {
        let outcome = redeem_invite(
            state,
            scheduler,
            &request.channel,
            &request.invite_id,
            &request.invite_secret,
            &request.key_package,
            &request.member_name,
        )
        .await;
        // A concurrent membership change on this channel is transient: the
        // invite is not burned, so wait briefly and retry rather than shipping
        // the internal "still awaiting acknowledgements" string to the friend.
        match &outcome {
            Err(e)
                if e == "membership change still awaiting acknowledgements"
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                continue;
            }
            _ => break outcome,
        }
    };
    // Remote redemption bypasses Cmd::RedeemChannelInvite. Publish its roster
    // change too, before attempting the reply (which can fail after admission).
    if result.is_ok() {
        if let Some(channel_id) = state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .channels
            .get(&request.channel)
            .map(|channel| channel.id)
        {
            let _ = events.send(Ev::ChannelRosterChanged {
                channel: request.channel.clone(),
                channel_id,
            });
        }
    }
    // Resolve the friend's NodeInfo (populated when their FirstMove was
    // accepted) so we can reply on the same authenticated session.
    let peer = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.peer_routes.get(&request.sender_pk).cloned()
    };
    let Some(peer) = peer else {
        metrics::log_event("invite_reply_no_route", &[]);
        return;
    };
    // The record echoes the id the friend registered its waiter under.
    let waited_id = request.message_id;
    if let Err(error) = send_direct_record(
        state,
        scheduler,
        &peer,
        None,
        false,
        move |_generated_id, _seq| {
            crate::proto::encode_invite_welcome(waited_id, &result)
                .ok_or_else(|| "invite welcome too large".to_string())
        },
    )
    .await
    {
        metrics::log_event("invite_reply_send_failed", &[("e", error)]);
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) async fn send_channel_text(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    text: &[u8],
) -> Result<(), String> {
    let prepared = prepare_channel_text(state, channel, text, false)?;
    complete_channel_text(scheduler, prepared).await.map(|_| ())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) async fn send_channel_text_tracked(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    text: &[u8],
) -> Result<[u8; 16], String> {
    let prepared = prepare_channel_text(state, channel, text, true)?;
    complete_channel_text(scheduler, prepared).await
}

pub(crate) struct PreparedChannelText {
    wire: Vec<u8>,
    id: [u8; 16],
    channel: String,
    targets: Vec<crate::channel::PeerRef>,
    durable_outbox: bool,
}

pub(crate) fn prepare_channel_text(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    text: &[u8],
    tracked: bool,
) -> Result<PreparedChannelText, String> {
    prepare_channel_payload(state, channel, text, tracked, None)
}

pub(crate) fn prepare_channel_change(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    change: crate::channel::ChannelChange,
) -> Result<PreparedChannelText, String> {
    change.validate()?;
    prepare_channel_payload(state, channel, &[], false, Some(change))
}

fn prepare_channel_payload(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    text: &[u8],
    tracked: bool,
    change: Option<crate::channel::ChannelChange>,
) -> Result<PreparedChannelText, String> {
    let closing = matches!(change, Some(crate::channel::ChannelChange::Close));
    if change.is_none() {
        validate_application_payload(text)?;
    }
    let (wire, id, targets, durable_outbox) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let persistent = cfg!(feature = "client-persist") && st.durable_state_sink.is_some();
        if tracked && !persistent {
            return Err("tracked send requires persistent client state".into());
        }
        let share_presence = st.channel_presence_opt_in.contains(channel);
        let archive_key = channel_archive_key(&st.identity_seed);
        let owner_seed = channel_seed(&st, channel);
        let cs = st.channels.get_mut(channel).ok_or("no channel")?;
        if crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
            return Err("This channel is closed".into());
        }
        if crate::channel::metadata::Metadata::read(&cs.role)?.leaving(cs.role.own_pseudonym())
            && !matches!(change, Some(crate::channel::ChannelChange::Leave))
        {
            return Err("This channel has a pending leave request".into());
        }
        if matches!(change, Some(crate::channel::ChannelChange::Transfer(_))) {
            if cs.visibility != crate::channel::ChannelVisibility::Private {
                return Err("Ownership transfer currently requires a private channel".into());
            }
            if !cs.message_outbox.is_empty() {
                return Err(
                    "Wait for pending channel messages before transferring ownership".into(),
                );
            }
        }
        if cs.own_route.aliases.len() != 2 {
            return Err("channel routing is recovering".into());
        }
        if cs.membership_outbox.is_some() {
            return Err("channel membership is still converging".into());
        }
        if cs.message_outbox.len() >= 64 && !closing {
            return Err("too many unacknowledged channel messages".into());
        }
        let own_pseudonym = cs.role.own_pseudonym();
        let mut expected = HashMap::new();
        let mut complete_roster = true;
        // Track the authenticated roster at this exact send. A missing route
        // must not silently reduce the set whose ACKs mean delivery.
        for (_, name) in cs.role.roster() {
            let pseudonym = cs
                .role
                .pseudonym_for_name(&name)
                .ok_or("channel member has no identity")?;
            if pseudonym == own_pseudonym {
                continue;
            }
            match cs
                .directory
                .get(&name)
                .filter(|route| route.pseudonym == pseudonym)
            {
                Some(route) => {
                    expected.insert(pseudonym, route.clone());
                }
                None if tracked || change.is_some() => {
                    return Err("channel recipient route is not ready".into())
                }
                None => complete_roster = false,
            }
        }
        if tracked && expected.is_empty() {
            return Err("tracked channel send requires a remote member".into());
        }
        let durable_outbox = persistent && complete_roster && !expected.is_empty();
        let checkpoint = cs
            .role
            .checkpoint(&archive_key)
            .map_err(|e| e.to_string())?;
        let result = (|| {
            let payload = if let Some(change) = change {
                let mut payload = vec![crate::channel::CHAN_METADATA];
                payload.extend(crate::channel::metadata::Metadata::prepare(
                    &mut cs.role,
                    change,
                )?);
                payload
            } else {
                crate::channel::encode_text(text, share_presence)
            };
            cs.role.send(&payload).map_err(|e| e.to_string())
        })();
        let wire = match result {
            Ok(wire) => wire,
            Err(error) => {
                cs.role = cs
                    .role
                    .restore_checkpoint(&archive_key, &checkpoint, || {
                        gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                    })
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        let id = crate::channel::msg_id(channel, &wire);
        let discarded_outbox = closing.then(|| std::mem::take(&mut cs.message_outbox));
        if !expected.is_empty() {
            cs.message_outbox.insert(
                id,
                crate::channel::ChannelMessageOutbox {
                    wire: wire.clone(),
                    expected,
                    acknowledged: HashSet::new(),
                },
            );
        }
        // Publish the MLS send state and exact wire/outbox together before
        // any network enqueue or caller-visible message ID.
        if let Err(error) = persist_current_direct_state(&st) {
            let cs = st
                .channels
                .get_mut(channel)
                .expect("channel retained under lock");
            cs.message_outbox.remove(&id);
            if let Some(outbox) = discarded_outbox {
                cs.message_outbox = outbox;
            }
            cs.role = cs
                .role
                .restore_checkpoint(&archive_key, &checkpoint, || {
                    gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                })
                .map_err(|e| e.to_string())?;
            return Err(error);
        }
        let cs = st
            .channels
            .get_mut(channel)
            .expect("channel retained under lock");
        if closing {
            cs.discard_forward_queue();
        }
        cs.overlay.first_sighting(id);
        cs.note(id, wire.clone());
        let mut targets = cs
            .overlay
            .origin_targets()
            .iter()
            .filter_map(|pid| cs.resolve(pid))
            .collect::<Vec<_>>();
        let mut roster = cs.directory.values().cloned().collect::<Vec<_>>();
        use rand::seq::SliceRandom;
        roster.shuffle(&mut rand::thread_rng());
        for route in roster.into_iter().take(64) {
            if route.pseudonym != own_pseudonym
                && !targets.iter().any(|t| t.pseudonym == route.pseudonym)
            {
                targets.push(crate::channel::PeerRef::from_route(&route));
            }
        }
        cs.enqueue_forward(id, wire.clone());
        st.last_channel_send = Some((channel.to_string(), wire.clone()));
        (wire, id, targets, durable_outbox)
    };
    Ok(PreparedChannelText {
        wire,
        id,
        channel: channel.to_string(),
        targets,
        durable_outbox,
    })
}

pub(crate) async fn complete_channel_text(
    scheduler: &RelayScheduler,
    prepared: PreparedChannelText,
) -> Result<[u8; 16], String> {
    let PreparedChannelText {
        wire,
        id,
        channel,
        targets,
        durable_outbox,
    } = prepared;
    let cell = Cell::new(
        CellType::Msg,
        0,
        0,
        crate::proto::encode_chan(&channel, &wire),
    );
    let mut sent = 0;
    let mut failures = 0;
    for target in &targets {
        if push_to_ref(scheduler, target, &cell).await.is_ok() {
            sent += 1;
        } else {
            failures += 1;
        }
    }
    metrics::log_event(
        "chan_text_sent",
        &[
            ("channel", channel.clone()),
            ("targets", sent.to_string()),
            ("failed_targets", failures.to_string()),
            ("durable_outbox", durable_outbox.to_string()),
            ("msg", encode_b64url(&id)),
        ],
    );
    // Preparation committed the exact MLS wire and complete recipient set.
    // The ordinary channel tick retries this outbox across route loss and
    // restart; a failed first hop cannot undo its local acceptance. Only an
    // authenticated ACK can remove a recipient or emit ChannelDelivery.
    if failures == 0 || durable_outbox {
        Ok(id)
    } else {
        Err(format!("channel send failed for {failures} target(s)"))
    }
}

pub(crate) async fn replay_last_channel(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    count: usize,
) -> Result<(), String> {
    if count == 0 || count > 100 {
        return Err("count must be between 1 and 100".into());
    }
    let (wire, targets) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let (last_channel, wire) = st.last_channel_send.as_ref().ok_or("no channel send")?;
        if last_channel != channel {
            return Err("last send is for another channel".into());
        }
        let cs = st.channels.get(channel).ok_or("no channel")?;
        let targets = cs
            .directory
            .values()
            .filter(|route| route.pseudonym != cs.role.own_pseudonym())
            .map(crate::channel::PeerRef::from_route)
            .collect::<Vec<_>>();
        (wire.clone(), targets)
    };
    if targets.is_empty() {
        return Err("no replay targets".into());
    }
    let cell = Cell::new(
        CellType::Msg,
        0,
        0,
        crate::proto::encode_chan(channel, &wire),
    );
    for _ in 0..count {
        for target in &targets {
            push_to_ref(scheduler, target, &cell).await?;
        }
    }
    metrics::log_event(
        "chan_replay_injected",
        &[
            ("channel", channel.to_string()),
            ("count", count.to_string()),
        ],
    );
    Ok(())
}

pub(crate) const MEMBER_REMOVAL_PREFIX: &str = "member-id:";
#[cfg(feature = "client-persist")]
pub(crate) const LEGACY_REMOVAL_PREFIX: &str = "legacy-name:";

pub(crate) fn completed_member_removal_key(member_id: &[u8; 32]) -> String {
    format!(
        "{MEMBER_REMOVAL_PREFIX}{}",
        gcoms_transport::encode_b64url(member_id)
    )
}

#[cfg(feature = "client-persist")]
pub(crate) fn completed_legacy_removal_key(member_name: &str) -> String {
    format!(
        "{LEGACY_REMOVAL_PREFIX}{}",
        gcoms_transport::encode_b64url(member_name.as_bytes())
    )
}

#[cfg(feature = "client-persist")]
pub(crate) fn valid_completed_removal_key(key: &str) -> bool {
    if let Some(encoded) = key.strip_prefix(MEMBER_REMOVAL_PREFIX) {
        return gcoms_transport::decode_b64url(encoded)
            .and_then(|value| <[u8; 32]>::try_from(value).ok())
            .is_some_and(|member_id| completed_member_removal_key(&member_id) == key);
    }
    if let Some(encoded) = key.strip_prefix(LEGACY_REMOVAL_PREFIX) {
        return gcoms_transport::decode_b64url(encoded)
            .and_then(|value| String::from_utf8(value).ok())
            .is_some_and(|member_name| {
                !member_name.is_empty() && completed_legacy_removal_key(&member_name) == key
            });
    }
    false
}

type PreparedChannelRemoval = (Vec<u8>, Option<crate::channel::ChannelRoute>);
fn prepare_channel_removal(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    member_id: [u8; 32],
    events: &broadcast::Sender<Ev>,
) -> Result<Option<PreparedChannelRemoval>, String> {
    let removal_key = completed_member_removal_key(&member_id);
    let (commit, removed_target) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let archive_key = channel_archive_key(&st.identity_seed);
        let owner_seed = channel_seed(&st, channel);
        let (commit, checkpoint, removed_directory, pending_control_len, removed_target) = {
            let Some(cs) = st.channels.get_mut(channel) else {
                return Err("no channel".into());
            };
            if cs.completed_removals.contains(&removal_key) {
                return Ok(None);
            }
            if cs.membership_outbox.is_some() {
                return Err("membership change still awaiting acknowledgements".into());
            }
            let expected = cs
                .directory
                .values()
                .filter(|route| {
                    route.pseudonym != member_id && route.pseudonym != cs.role.own_pseudonym()
                })
                .map(|route| (route.pseudonym, route.clone()))
                .collect::<HashMap<_, _>>();
            let checkpoint = cs
                .role
                .checkpoint(&archive_key)
                .map_err(|error| error.to_string())?;
            let removed_directory = cs
                .directory
                .iter()
                .filter(|(_, route)| route.pseudonym == member_id)
                .map(|(name, route)| (name.clone(), route.clone()))
                .collect::<Vec<_>>();
            let removed_target = removed_directory.first().map(|(_, route)| route.clone());
            if removed_target.is_some()
                && cs.pending_control.len() >= crate::channel::CHANNEL_ACK_LIMIT
            {
                return Err("channel control journal is full".into());
            }
            let pending_control_len = cs.pending_control.len();
            if !cs.role.is_owner() {
                return Err("not owner".into());
            }
            let staged = cs.role.stage_remove(member_id).map_err(|e| e.to_string())?;
            cs.role.merge_pending().map_err(|e| e.to_string())?;
            if !expected.is_empty() {
                cs.membership_outbox = Some(crate::channel::MembershipOutbox {
                    commit_id: crate::channel::msg_id(channel, &staged.commit),
                    epoch: cs.role.epoch(),
                    commit: staged.commit.clone(),
                    expected,
                    acknowledged: std::collections::HashSet::new(),
                });
            }
            cs.completed_removals.insert(removal_key.clone());
            if let Some(route) = &removed_target {
                cs.pending_control
                    .push_back((route.clone(), staged.commit.clone()));
            }
            cs.directory.retain(|_, route| route.pseudonym != member_id);
            (
                staged.commit,
                checkpoint,
                removed_directory,
                pending_control_len,
                removed_target,
            )
        };
        if let Err(error) = persist_current_direct_state(&st) {
            let cs = st
                .channels
                .get_mut(channel)
                .ok_or("channel disappeared during removal rollback")?;
            cs.role = cs
                .role
                .restore_checkpoint(&archive_key, &checkpoint, || {
                    gcoms_crypto::IdentityKeypair::from_seed(owner_seed)
                })
                .map_err(|restore| format!("{error}; channel rollback failed: {restore}"))?;
            cs.membership_outbox = None;
            cs.membership_done.notify_waiters();
            cs.completed_removals.remove(&removal_key);
            cs.directory.extend(removed_directory);
            while cs.pending_control.len() > pending_control_len {
                if let Some((_, mut wire)) = cs.pending_control.pop_back() {
                    wire.fill(0);
                }
            }
            return Err(error);
        }
        (commit, removed_target)
    };
    {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        withdraw_channel_presence(&mut st, channel, member_id, events);
        st.channel_presence_counters
            .remove(&(channel.to_string(), member_id));
    };
    retain_channel_wire(state, channel, &commit);
    Ok(Some((commit, removed_target)))
}

pub(crate) async fn remove_channel_member(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    member_id: [u8; 32],
    events: &broadcast::Sender<Ev>,
) -> Result<(), String> {
    let Some((commit, removed_target)) =
        prepare_channel_removal(state, channel, member_id, events)?
    else {
        return Ok(());
    };
    if let Some(removed_target) = removed_target {
        let _ = broadcast_chan_to_targets(
            scheduler,
            channel,
            &commit,
            std::slice::from_ref(&removed_target),
        )
        .await;
    }
    let _ = broadcast_chan(state, scheduler, channel, &commit, None).await;
    let converged = wait_for_membership_acks(state, channel).await;
    metrics::log_event(
        "channel_membership_converged",
        &[
            ("channel", channel.to_string()),
            ("ok", converged.to_string()),
        ],
    );
    metrics::log_event(
        "channel_removed_member",
        &[
            ("channel", channel.to_string()),
            ("member_id", gcoms_transport::encode_b64url(&member_id)),
        ],
    );
    Ok(())
}

#[cfg(test)]
mod membership_wait_tests {
    use super::wait_for_membership_condition;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use tokio::sync::Notify;
    use tokio::time::{Duration, Instant};

    #[tokio::test]
    async fn final_ack_between_condition_read_and_await_is_not_lost() {
        let notify = Notify::new();
        let reads = AtomicUsize::new(0);
        let mut wait = Box::pin(wait_for_membership_condition(
            &notify,
            Instant::now() + Duration::from_secs(90),
            || {
                if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    // The condition read observed pending, then the ACK arrived
                    // before the caller could await its notification.
                    notify.notify_waiters();
                    false
                } else {
                    true
                }
            },
        ));
        assert_eq!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(true)
        );
    }

    #[tokio::test]
    async fn incomplete_membership_still_times_out() {
        assert!(!wait_for_membership_condition(&Notify::new(), Instant::now(), || false).await);
    }
}
