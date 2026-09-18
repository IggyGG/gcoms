//! Explicit GC/2 peer setup and non-ratcheted transport-credit dispatch.
use super::*;
use gcoms_protocol::gc2_session::{self, Kind, Packet};

pub(super) fn incoming(
    st: &mut NodeState,
    bytes: &[u8],
    events: &broadcast::Sender<Ev>,
) -> Result<(), String> {
    if !st.gc2_sessions {
        return Err("GC/2 peer sessions are not selected".into());
    }
    if st.owner_transition_failed {
        return Err("owner lifecycle persistence outcome is unconfirmed".into());
    }
    let packet = Packet::decode(bytes).map_err(|e| e.to_string())?;
    let peer = st
        .sessions
        .iter()
        .find(|(_, s)| s.tag() == Some(packet.tag()))
        .map(|(p, _)| p.clone());
    if packet.kind() == Kind::FirstMove && peer.is_none() {
        return accept(st, &packet, events);
    }
    let peer = peer.ok_or("unknown GC/2 session tag")?;
    let wrapping = zeroize::Zeroizing::new(direct_session_wrapping_key(&st.identity_seed));
    let context = direct_session_context(st, &peer)?;
    match packet.kind() {
        Kind::Frame => process_frame(st, peer, packet.frame().map_err(|e| e.to_string())?, events),
        Kind::FirstMove => {
            let prepared = st.sessions[&peer]
                .prepare_first_move_retry(&packet, &wrapping, &context)
                .map_err(|e| e.to_string())?;
            persist_received_direct_transaction(
                st,
                &peer,
                prepared.sealed_state(),
                prepared.credit(),
            )?;
            st.sessions
                .get_mut(&peer)
                .expect("selected session")
                .commit_receive(prepared)
                .map_err(|e| e.to_string())?;
        }
        Kind::Credit => {
            let PeerSession::Credited(session) = &st.sessions[&peer] else {
                return Err("GC/2 session required".into());
            };
            let Some(prepared) = session.prepare_credit(bytes).map_err(|e| e.to_string())? else {
                return Ok(());
            };
            let sealed = peer_session::seal(
                packet.tag(),
                &session
                    .seal_ratchet(&wrapping, &context)
                    .map_err(|e| e.to_string())?,
                &prepared.private_flow(),
                crate::scheduler::PayloadUsage {
                    items: prepared.cached_payload_count(),
                    bytes: prepared.cached_payload_bytes(),
                },
                &wrapping,
            )
            .map_err(|e| e.to_string())?;
            let receipt_undo = st
                .gc2_receipts
                .stage_credit(&peer, prepared.window(), now_unix());
            if let Err(error) = persist_received_direct_transaction(st, &peer, &sealed, None) {
                st.gc2_receipts.rollback(receipt_undo);
                return Err(error);
            }
            let PeerSession::Credited(session) =
                st.sessions.get_mut(&peer).expect("selected session")
            else {
                unreachable!()
            };
            session.commit_credit(prepared).map_err(|e| e.to_string())?;
            // Credit never implies application acceptance and produces no ACK.
        }
    }
    Ok(())
}

fn accept(
    st: &mut NodeState,
    packet: &Packet<'_>,
    events: &broadcast::Sender<Ev>,
) -> Result<(), String> {
    let hash: [u8; 32] = Sha256::digest(packet.bytes()).into();
    if st.accepted_first_moves.contains(&hash) {
        return Err("retired GC/2 first move".into());
    }
    if st.direct_ack_outbox.len() >= 1024 {
        return Err("GC/2 session capacity reached".into());
    }
    let accepted = gc2_session::accept(packet, &st.info.public(), &st.secrets, now_unix())
        .map_err(|e| e.to_string())?;
    let peer = accepted.peer;
    if peer.primary().is_none() {
        return Err("GC/2 peer has no public receive route".into());
    }
    let pk = peer.identity_pk.clone();
    if !st.sessions.contains_key(&pk) && st.sessions.len() >= 8192 {
        return Err("GC/2 session capacity reached".into());
    }
    if let Some(current) = st.sessions.get(&pk) {
        let PeerSession::Credited(current) = current else {
            return Err("explicit GC/1 to GC/2 migration required".into());
        };
        if !st.gc2_receipts.recovery_allowed(&pk) {
            return Err("historical GC/2 acknowledgments must be credited before recovery".into());
        }
        let incoming_generation = accepted.session.window().generation();
        let current_generation = current.window().generation();
        if incoming_generation < current_generation {
            return Err("retired GC/2 recovery generation".into());
        }
        if incoming_generation == current_generation {
            match st
                .session_states
                .get(&pk)
                .copied()
                .unwrap_or(DirectSessionState::Established)
            {
                DirectSessionState::Established => {
                    return Err("authenticated GC/2 recovery required".into())
                }
                DirectSessionState::InitiatedUnconfirmed { .. } if st.info.identity_pk < pk => {
                    return Err("local GC/2 initiation wins collision".into())
                }
                _ => (),
            }
        } else if !accepted.recovery {
            return Err("authenticated GC/2 recovery required".into());
        }
    }
    // A peer may never have received generation one. A fresh signed recovery
    // authenticates first contact just as normal setup does. Once a generation
    // is retained, the checks above forbid rollback, including after restart.
    // Requeue live logical records after a simultaneous initiation without
    // consuming counters yet. Their IDs, sequence and original deadlines stay.
    if st
        .pending_1to1
        .values()
        .any(|p| p.delivery.peer.identity_pk == pk && p.logical_record.is_none())
    {
        return Err("unrecoverable GC/2 pending record".into());
    }
    let mut previous_pending = Vec::new();
    for (id, pending) in &mut st.pending_1to1 {
        if pending.delivery.peer.identity_pk == pk {
            previous_pending.push((*id, pending.delivery.clone()));
            pending.delivery.cells.clear();
            pending.delivery.peer = peer.clone();
        }
    }
    let old_route = st.peer_routes.insert(pk.clone(), peer.clone());
    let old_session = st
        .sessions
        .insert(pk.clone(), PeerSession::Credited(accepted.session));
    let old_state = st
        .session_states
        .insert(pk.clone(), DirectSessionState::Established);
    let old_outbox = retire_outbox(st, &pk);
    st.direct_ack_outbox.push_back(DirectDelivery {
        peer,
        relay: st.client_relay.clone(),
        cells: vec![Cell::new(CellType::Msg, 0, 0, accepted.credit.to_vec())],
    });
    st.accepted_first_moves.push_back(hash);
    if let Err(error) = checkpoint_direct_state(st, None, true) {
        st.direct_ack_outbox.pop_back();
        restore_outbox(st, old_outbox);
        st.accepted_first_moves.pop_back();
        st.sessions.remove(&pk);
        if let Some(session) = old_session {
            st.sessions.insert(pk.clone(), session);
        }
        st.session_states.remove(&pk);
        if let Some(state) = old_state {
            st.session_states.insert(pk.clone(), state);
        }
        st.peer_routes.remove(&pk);
        if let Some(route) = old_route {
            st.peer_routes.insert(pk.clone(), route);
        }
        for (id, delivery) in previous_pending {
            st.pending_1to1
                .get_mut(&id)
                .expect("saved pending")
                .delivery = delivery;
        }
        #[cfg(feature = "client-persist")]
        if matches!(error, DirectPersistenceError::Storage(_)) {
            st.owner_transition_failed = true;
        }
        return Err(error.into_string());
    }
    while st.accepted_first_moves.len() > 512 {
        st.accepted_first_moves.pop_front();
    }
    let _ = events.send(Ev::SessionOpened {
        safety_number: gcoms_crypto::safety_number_of(&pk),
        peer_pk: pk,
    });
    Ok(())
}

fn retire_outbox(st: &mut NodeState, peer: &[u8]) -> Vec<(usize, DirectDelivery)> {
    let mut removed = Vec::new();
    let mut index = 0;
    let mut original = 0;
    while index < st.direct_ack_outbox.len() {
        if st.direct_ack_outbox[index].peer.identity_pk == peer {
            removed.push((original, st.direct_ack_outbox.remove(index).unwrap()));
        } else {
            index += 1;
        }
        original += 1;
    }
    removed
}

fn restore_outbox(st: &mut NodeState, removed: Vec<(usize, DirectDelivery)>) {
    for (index, delivery) in removed {
        st.direct_ack_outbox.insert(index, delivery);
    }
}

/// The maintenance owner calls this on its existing cadence. Admission waits
/// without changing generation; an uncertain durable write pauses publication.
pub(super) fn recover_peer(st: &mut NodeState, peer: &[u8]) -> Result<bool, String> {
    if st.owner_transition_failed {
        return Err("owner lifecycle persistence outcome is unconfirmed".into());
    }
    let Some(PeerSession::Credited(current)) = st.sessions.get(peer) else {
        return Err("GC/2 recovery requires an existing peer session".into());
    };
    if !st.gc2_receipts.recovery_allowed(peer) {
        return Err("historical GC/2 acknowledgments must be credited before recovery".into());
    }
    let generation = current
        .window()
        .generation()
        .checked_add(1)
        .ok_or("GC/2 recovery generation exhausted")?;
    let route = select_peer_route(
        st,
        st.peer_routes.get(peer).ok_or("missing recovery route")?,
    )?;
    if st
        .pending_1to1
        .values()
        .any(|p| p.delivery.peer.identity_pk == peer && p.logical_record.is_none())
    {
        return Err("unrecoverable GC/2 pending record".into());
    }
    let candidate = gc2_session::initiate_recovery(
        &IdentityKeypair::from_seed(st.identity_seed),
        &st.info.public(),
        &st.secrets,
        &route.public(),
        generation,
        now_unix(),
        &mut rand::thread_rng(),
    )
    .map_err(|e| e.to_string())?;
    if st
        .sessions
        .values()
        .any(|s| s.tag() == Some(candidate.session.window().session()))
    {
        return Err("GC/2 recovery tag collision".into());
    }
    let mut previous = Vec::new();
    for (id, pending) in &mut st.pending_1to1 {
        if pending.delivery.peer.identity_pk == peer {
            previous.push((*id, pending.delivery.clone()));
            pending.delivery.cells.clear();
            pending.delivery.peer = route.clone();
        }
    }
    let old_outbox = retire_outbox(st, peer);
    let old_session = st
        .sessions
        .insert(peer.to_vec(), PeerSession::Credited(candidate.session))
        .expect("known recovery peer");
    let old_state = st.session_states.insert(
        peer.to_vec(),
        DirectSessionState::InitiatedUnconfirmed {
            expires: std::time::Instant::now() + std::time::Duration::from_secs(600),
        },
    );
    // The exact first move is already retained by the new counter window and
    // leaves only through the maintenance repair queue after this checkpoint.
    if let Err(error) = checkpoint_direct_state(st, None, true) {
        st.sessions.insert(peer.to_vec(), old_session);
        st.session_states.remove(peer);
        if let Some(old) = old_state {
            st.session_states.insert(peer.to_vec(), old);
        }
        restore_outbox(st, old_outbox);
        for (id, delivery) in previous {
            st.pending_1to1.get_mut(&id).unwrap().delivery = delivery;
        }
        return match error {
            DirectPersistenceError::Admission(_) => Ok(false),
            #[cfg(feature = "client-persist")]
            DirectPersistenceError::Storage(error) => {
                st.owner_transition_failed = true;
                Err(error)
            }
        };
    }
    Ok(true)
}

/// Both durable application bodies and ephemeral events need stable logical
/// receipt metadata when a lost ACK is followed by session recovery. Expired
/// records still repair their counter without creating another application effect.
pub(super) fn logical_receive(
    st: &mut NodeState,
    peer: &[u8],
    received: peer_session::PreparedReceive,
    message_id: [u8; 16],
    sent_ms: u64,
) -> Option<(peer_session::PreparedReceive, bool)> {
    if st.sessions[peer].tag().is_none() {
        return Some((received, false));
    }
    let horizon = gc2_receipts::horizon(sent_ms);
    if horizon <= st.gc2_receipts.now(now_unix()) {
        if persist_received_direct_transaction(st, peer, received.sealed_state(), received.credit())
            .is_ok()
        {
            let _ = st.sessions.get_mut(peer).unwrap().commit_receive(received);
        }
        return None;
    }
    match st.gc2_receipts.check(
        peer,
        message_id,
        Sha256::digest(received.plaintext()).into(),
        horizon,
        now_unix(),
    ) {
        Ok(duplicate) => Some((received, duplicate)),
        Err(error) => {
            metrics::log_event("gc2_logical_record_rejected", &[("e", error)]);
            None
        }
    }
}
