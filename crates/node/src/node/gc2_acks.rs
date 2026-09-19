//! Bounded preparation of application ACKs after receive credit was committed.
use super::*;

pub(super) fn materialize(
    st: &mut NodeState,
    last_peer: &mut Option<[u8; 32]>,
) -> Result<usize, String> {
    let mut pending = st.gc2_receipts.pending_acks(now_unix());
    if pending.is_empty() || st.owner_transition_failed {
        return Ok(0);
    }
    // Rotate peers independently of their clocks or arrival rate. Within each
    // peer prepare older obligations first, with four preparations per tick.
    pending.sort_by_key(|(key, _, expires)| {
        (
            last_peer.is_some_and(|last| key.0 <= last),
            key.0,
            *expires,
            key.1,
        )
    });
    let peers: HashMap<_, _> = st
        .sessions
        .iter()
        .filter(|(_, session)| session.tag().is_some())
        .map(|(peer, _)| (gc2_receipts::peer_key(peer), peer.clone()))
        .collect();
    let mut per_peer = HashMap::<[u8; 32], usize>::new();
    let mut prepared_count = 0;
    for (key, share_presence, _) in pending {
        if prepared_count == 16 || st.direct_ack_outbox.len() >= 1024 {
            break;
        }
        if per_peer.get(&key.0).copied().unwrap_or(0) >= 4 {
            continue;
        }
        let Some(peer) = peers.get(&key.0) else {
            continue;
        };
        let Some(route) = st.peer_routes.get(peer).cloned() else {
            continue;
        };
        if !matches!(
            st.session_states.get(peer),
            Some(DirectSessionState::Established)
        ) {
            continue;
        }
        let record = encode_direct_ack(
            key.1,
            share_presence && st.direct_presence_opt_in.contains(peer),
        );
        let session = &st.sessions[peer];
        if !session.can_send(&record) {
            continue;
        }
        let wrapping = zeroize::Zeroizing::new(direct_session_wrapping_key(&st.identity_seed));
        let context = direct_session_context(st, peer)?;
        let prepared = session
            .prepare_send(&record, &wrapping, &context)
            .map_err(|e| e.to_string())?;
        let counter = gcoms_crypto::Frame::decode(prepared.wire())
            .ok_or("invalid prepared ACK")?
            .ctr;
        let packet = prepared.packet(&st.info.identity_pk)?;
        let undo =
            st.gc2_receipts
                .stage_prepared_ack(key, (*session.tag().unwrap(), counter), now_unix());
        st.direct_ack_outbox.push_back(DirectDelivery {
            peer: route,
            relay: st.client_relay.clone(),
            cells: vec![peer_session::cell(packet, 3)],
        });
        if let Err(error) = checkpoint_direct_state(st, Some((peer, prepared.sealed_state())), true)
        {
            st.direct_ack_outbox.pop_back();
            st.gc2_receipts.rollback(undo);
            return match error {
                DirectPersistenceError::Admission(_) => Ok(prepared_count),
                #[cfg(feature = "client-persist")]
                DirectPersistenceError::Storage(error) => {
                    st.owner_transition_failed = true;
                    Err(error)
                }
            };
        }
        if let Err(error) = st.sessions.get_mut(peer).unwrap().commit_send(prepared) {
            st.owner_transition_failed = true;
            return Err(error.to_string());
        }
        prepared_count += 1;
        *last_peer = Some(key.0);
        *per_peer.entry(key.0).or_default() += 1;
    }
    Ok(prepared_count)
}
