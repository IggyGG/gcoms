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
            persist_received_direct_transaction(st, &peer, &sealed, None)?;
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
    if st.sessions.len() >= 8192 || st.direct_ack_outbox.len() >= 1024 {
        return Err("GC/2 session capacity reached".into());
    }
    let accepted = gc2_session::accept(packet, &st.info.public(), &st.secrets, now_unix())
        .map_err(|e| e.to_string())?;
    let peer = accepted.peer;
    if peer.primary().is_none() {
        return Err("GC/2 peer has no public receive route".into());
    }
    let pk = peer.identity_pk.clone();
    if st.sessions.contains_key(&pk) {
        if st.sessions[&pk].tag().is_none() {
            return Err("explicit GC/1 to GC/2 migration required".into());
        }
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
    }
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
    st.direct_ack_outbox.push_back(DirectDelivery {
        peer,
        relay: st.client_relay.clone(),
        cells: vec![Cell::new(CellType::Msg, 0, 0, accepted.credit.to_vec())],
    });
    st.accepted_first_moves.push_back(hash);
    if let Err(error) = persist_direct_state(st, None, true) {
        st.direct_ack_outbox.pop_back();
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
        return Err(error);
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
