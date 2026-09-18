// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

#[cfg(all(test, feature = "client-persist"))]
#[path = "direct_maintenance_tests.rs"]
mod maintenance_tests;

/// Grants an intermediary of the active set may use toward `peer`
/// (SPEC §11.1): exclude the receiver's own relays, grants issued by the
/// receiver, and this node's own relay.
pub(crate) fn eligible_intermediaries(
    st: &NodeState,
    peer: &NodeInfo,
    now: u64,
) -> Vec<crate::alias::ForwardGrant> {
    let receiver_relays: HashSet<[u8; 32]> = peer
        .aliases
        .iter()
        .map(|alias| alias.target.relay_service_id)
        .collect();
    let own_relay = st
        .client_relay
        .aliases
        .first()
        .map(|alias| alias.contact.target.relay_service_id);
    st.active_intermediaries
        .iter()
        .filter_map(|service_id| st.forward_grants.get(service_id))
        .filter(|grant| grant.expires_at > now)
        .filter(|grant| !receiver_relays.contains(&grant.target.relay_service_id))
        .filter(|grant| Some(grant.target.relay_service_id) != own_relay)
        .filter(|grant| grant.issued_by != peer.identity_pk)
        .cloned()
        .collect()
}

/// Pick the first hop for one delivery: a uniformly random eligible
/// intermediary, else the node's own relay (counted as a fallback).
pub(crate) fn choose_intermediary(st: &mut NodeState, peer: &NodeInfo) -> RelayProvision {
    let eligible = eligible_intermediaries(st, peer, now_unix());
    if eligible.is_empty() {
        st.intermediary_fallbacks = st.intermediary_fallbacks.saturating_add(1);
        return st.client_relay.clone();
    }
    use rand::seq::SliceRandom;
    let grant = eligible
        .choose(&mut rand::rngs::StdRng::from_entropy())
        .expect("non-empty");
    RelayProvision {
        aliases: vec![OwnedAlias {
            contact: AliasContact {
                target: grant.target.clone(),
                queue_id: [0; 32],
                epoch: 0,
                push_cap: [0; 32],
                expiry: grant.expires_at,
            },
            capabilities: crate::lease::Capabilities {
                push: [0; 32],
                sub: [0; 32],
                admin: [0; 32],
            },
            limits: crate::lease::LeaseLimits {
                max_queue_cells: 0,
                max_queue_bytes: 0,
            },
            create_path: String::new(),
            lease_create: Cell::new(CellType::RelaySub, 0, 0, Vec::new()),
        }],
        frwd_path: grant.frwd_path.clone(),
        hop_key: grant.hop_key,
    }
}

pub(crate) async fn deliver_direct(
    scheduler: &RelayScheduler,
    delivery: &DirectDelivery,
    policy: &FrwdTargetPolicy,
) -> Result<(), String> {
    let destination = delivery.peer.primary().ok_or("peer has no public alias")?;
    for msg in &delivery.cells {
        scheduler
            .frwd(
                ProducerClass::Direct,
                delivery.relay.clone(),
                destination.clone(),
                msg.clone(),
                policy.clone(),
            )
            .map_err(|e| e.to_string())?
            .completion()
            .await
            .accepted()?;
    }
    Ok(())
}

/// Re-select the first hop for every queued delivery at the moment it is
/// sent, so retries rotate across intermediaries and a grant learned after
/// enqueue is used. Resolve an authenticated contact update at the same time;
/// queued ciphertext must follow the peer to its renewed receive queues.
pub(crate) fn reroute_deliveries(st: &mut NodeState, deliveries: &mut [DirectDelivery]) {
    for delivery in deliveries.iter_mut() {
        if let Ok(peer) = select_peer_route(st, &delivery.peer) {
            delivery.peer = peer;
        }
        let peer = delivery.peer.clone();
        delivery.relay = choose_intermediary(st, &peer);
    }
}

const MAX_DIRECT_ACK_ATTEMPTS: usize = 16;
const MAX_DIRECT_RETRY_ATTEMPTS: usize = 48;

/// Identify committed ciphertext independently of mutable relay/contact routes.
/// A rekey can replace ciphertext under the same logical message ID; that is a
/// distinct attempt. Lengths and every cell header make the digest unambiguous.
fn direct_attempt_key(delivery: &DirectDelivery) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"gcoms.direct-maintenance.v1\0");
    hash.update((delivery.peer.identity_pk.len() as u64).to_be_bytes());
    hash.update(&delivery.peer.identity_pk);
    hash.update((delivery.cells.len() as u64).to_be_bytes());
    for cell in &delivery.cells {
        hash.update([cell.version, cell.raw_type, cell.flags]);
        hash.update(cell.round_ctr.to_be_bytes());
        hash.update((cell.payload.len() as u64).to_be_bytes());
        hash.update(&cell.payload);
    }
    hash.finalize().into()
}

struct DirectAttempt {
    key: [u8; 32],
    ack: bool,
    delivery: DirectDelivery,
    accepted: bool,
}

/// Own all maintenance receipts without holding up later ticks. ACKs remain in
/// the archived outbox until hop acceptance; dropping this owner cannot lose an
/// in-flight ACK. Retries retain their original pending entry and deadline.
#[derive(Default)]
pub(crate) struct DirectMaintenance {
    active: HashMap<[u8; 32], bool>,
    completions: futures_util::stream::FuturesUnordered<
        futures_util::future::BoxFuture<'static, DirectAttempt>,
    >,
}

impl DirectMaintenance {
    pub(crate) fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    fn start(
        &mut self,
        st: &mut NodeState,
        scheduler: &RelayScheduler,
        mut delivery: DirectDelivery,
        ack: bool,
    ) {
        let key = direct_attempt_key(&delivery);
        self.active.insert(key, ack);
        reroute_deliveries(st, std::slice::from_mut(&mut delivery));
        let scheduler = scheduler.clone();
        let policy = st.frwd_target_policy.clone();
        self.completions.push(Box::pin(async move {
            let accepted = deliver_direct(&scheduler, &delivery, &policy).await.is_ok();
            DirectAttempt {
                key,
                ack,
                delivery,
                accepted,
            }
        }));
    }

    pub(crate) fn tick(
        &mut self,
        state: &Arc<Mutex<NodeState>>,
        scheduler: &RelayScheduler,
        events: &broadcast::Sender<Ev>,
    ) {
        let now = std::time::Instant::now();
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.owner_transition_failed {
            return;
        }
        if let Err(error) = materialize_deferred(&mut st) {
            metrics::log_event("deferred_application_prepare_error", &[("e", error)]);
        }
        if st.owner_transition_failed {
            return;
        }
        if let Err(error) = cleanup_expired_unconfirmed(&mut st, now) {
            metrics::log_event("session_cleanup_persist_error", &[("e", error)]);
        }
        st.pending_1to1.retain(|_, pending| pending.expires > now);
        expire_direct_presence(&mut st, now, events);
        rotate_active_intermediaries(&mut st);

        let ack_count = self.active.values().filter(|&&ack| ack).count();
        let mut selected = HashSet::new();
        let acks: Vec<_> = st
            .direct_ack_outbox
            .iter()
            .filter(|ack| {
                let key = direct_attempt_key(ack);
                !self.active.contains_key(&key) && selected.insert(key)
            })
            .take(MAX_DIRECT_ACK_ATTEMPTS - ack_count)
            .cloned()
            .collect();
        for ack in acks {
            self.start(&mut st, scheduler, ack, true);
        }

        // Oldest due work first, so the finite window cannot keep selecting an
        // arbitrary HashMap prefix. Only admitted attempts move their deadline.
        let mut due: Vec<_> = st
            .pending_1to1
            .iter()
            .filter(|(_, pending)| {
                pending.next_attempt <= now && !pending.delivery.cells.is_empty()
            })
            .map(|(id, pending)| (pending.next_attempt, pending.sequence, *id))
            .collect();
        due.sort_unstable();
        let retry_count = self.active.values().filter(|&&ack| !ack).count();
        let mut available = MAX_DIRECT_RETRY_ATTEMPTS - retry_count;
        for (_, _, id) in due {
            if available == 0 {
                break;
            }
            let pending = st
                .pending_1to1
                .get_mut(&id)
                .expect("selected pending entry");
            if self
                .active
                .contains_key(&direct_attempt_key(&pending.delivery))
            {
                continue;
            }
            pending.next_attempt = now + jittered(std::time::Duration::from_secs(60));
            let delivery = pending.delivery.clone();
            self.start(&mut st, scheduler, delivery, false);
            available -= 1;
        }
    }

    pub(crate) async fn complete_next(&mut self, state: &Arc<Mutex<NodeState>>) {
        use futures_util::StreamExt;
        if let Some(attempt) = self.completions.next().await {
            self.active.remove(&attempt.key);
            if !attempt.ack {
                return;
            }
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            let matches = |ack: &DirectDelivery| {
                ack.peer.identity_pk == attempt.delivery.peer.identity_pk
                    && ack.cells == attempt.delivery.cells
            };
            if let Some(index) = st.direct_ack_outbox.iter().position(&matches) {
                let retained = st.direct_ack_outbox.remove(index).expect("matched ACK");
                st.direct_ack_outbox.retain(|ack| !matches(ack));
                let current_destination = select_peer_route(&st, &retained.peer).ok();
                let accepted_current_route = attempt.accepted
                    && current_destination.as_ref().and_then(NodeInfo::primary)
                        == attempt.delivery.peer.primary();
                if !accepted_current_route {
                    // Retry on a later tick, behind other waiting ACKs. Keep the
                    // retained contact, which may have renewed during this wait.
                    st.direct_ack_outbox.push_back(retained);
                }
            }
        }
    }
}

pub(crate) fn cleanup_expired_unconfirmed(
    st: &mut NodeState,
    now: std::time::Instant,
) -> Result<(), String> {
    let expired = st
        .session_states
        .iter()
        .filter_map(|(peer, state)| match state {
            DirectSessionState::InitiatedUnconfirmed { expires } if *expires <= now => {
                Some(peer.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if expired.is_empty() {
        return Ok(());
    }
    let mut sessions = Vec::with_capacity(expired.len());
    let mut pending = Vec::new();
    for peer in &expired {
        if let Some(session) = st.sessions.remove(peer) {
            let state = st
                .session_states
                .get(peer)
                .copied()
                .expect("expired session state exists");
            sessions.push((peer.clone(), session, state));
        }
        st.session_states.remove(peer);
        let message_ids = st
            .pending_1to1
            .iter()
            .filter_map(|(message_id, pending)| {
                (pending.delivery.peer.identity_pk == *peer).then_some(*message_id)
            })
            .collect::<Vec<_>>();
        for message_id in message_ids {
            if let Some(record) = st.pending_1to1.remove(&message_id) {
                pending.push((message_id, record));
            }
        }
    }
    if let Err(error) = persist_current_direct_state(st) {
        for (peer, session, state) in sessions {
            st.sessions.insert(peer.clone(), session);
            st.session_states.insert(peer, state);
        }
        for (message_id, record) in pending {
            st.pending_1to1.insert(message_id, record);
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn handle_incoming(
    state: &Arc<Mutex<NodeState>>,
    mut cell: Cell,
    events: &broadcast::Sender<Ev>,
) {
    if state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .owner_transition_failed
    {
        cell.payload.fill(0);
        return;
    }
    if cell.cell_type() != Some(CellType::Msg) {
        return;
    }
    if cell.payload.first() == Some(&crate::proto::KIND_CHAN_FRAGMENT) {
        let Some(payload) = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .channel_fragments
            .push(&cell.payload)
        else {
            return;
        };
        cell = Cell::new(CellType::Msg, 0, 0, payload);
    }
    if let Some((chan, wire)) = crate::proto::decode_chan(&cell) {
        handle_chan_cell(state, chan, wire, events);
        return;
    }
    if cell.payload.first() == Some(&crate::proto::KIND_CHANNEL_DIRECT) {
        handle_channel_direct(state, &cell.payload, events);
        return;
    }
    match decode_payload(&cell) {
        Some(NodePayload::FirstMove(fm)) => {
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            match accept_first_move(&mut st, &fm) {
                Ok(accepted) => {
                    let peer_pk = accepted.peer_pk;
                    metrics::log_event("session_opened", &[]);
                    let _ = events.send(Ev::SessionOpened {
                        safety_number: gcoms_crypto::safety_number_of(&peer_pk),
                        peer_pk: peer_pk.clone(),
                    });
                    for delivery in accepted.rewritten {
                        if let Some(destination) = delivery.peer.primary().cloned() {
                            for cell in &delivery.cells {
                                let _ = st.scheduler.frwd(
                                    ProducerClass::Direct,
                                    delivery.relay.clone(),
                                    destination.clone(),
                                    cell.clone(),
                                    st.frwd_target_policy.clone(),
                                );
                            }
                        }
                    }
                    let parked: Vec<(Vec<u8>, gcoms_crypto::session::Frame)> = st
                        .parked
                        .iter()
                        .filter(|(pk, _)| *pk == peer_pk)
                        .cloned()
                        .collect();
                    st.parked.retain(|(pk, _)| *pk != peer_pk);
                    for (sender_pk, frame) in parked {
                        process_frame(&mut st, sender_pk, frame, events);
                    }
                }
                Err(e) => {
                    metrics::log_event("accept_error", &[("e", e.to_string())]);
                }
            }
        }
        Some(NodePayload::Frame(sender_pk, frame)) => {
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            if !st.sessions.contains_key(&sender_pk) {
                if st.parked.len() < 64 {
                    st.parked.push((sender_pk, frame));
                    metrics::log_event("frame_parked", &[]);
                }
                return;
            }
            process_frame(&mut st, sender_pk, frame, events);
        }
        _ => {}
    }
}

pub(crate) fn accept_reliable_direct(
    st: &mut NodeState,
    sender_pk: &[u8],
    processed_frame: ((Vec<u8>, u64), [u8; 32]),
    message_id: [u8; 16],
    received: gcoms_crypto::session::PreparedReceive,
    wrapping_key: &mut [u8; 32],
    context: &SessionContext,
) -> Result<DirectDelivery, String> {
    let (frame_key, frame_hash) = processed_frame;
    let peer = st
        .peer_routes
        .get(sender_pk)
        .cloned()
        .ok_or_else(|| "authenticated peer route is missing".to_string())?;
    let staged = Session::open_state(received.sealed_state(), wrapping_key, context)
        .map_err(|error| error.to_string())?;
    let ack = staged
        .prepare_send(
            &encode_direct_ack(message_id, st.direct_presence_opt_in.contains(sender_pk)),
            wrapping_key,
            context,
        )
        .map_err(|error| error.to_string())?;
    let ack_frame = gcoms_crypto::Frame::decode(ack.wire()).ok_or("prepared invalid ACK frame")?;
    if st.direct_ack_outbox.len() >= 1024 {
        return Err("direct ACK outbox is full".into());
    }
    let delivery = DirectDelivery {
        peer,
        relay: st.client_relay.clone(),
        cells: vec![Cell::new(
            CellType::Msg,
            0,
            0,
            encode_frame(&st.info.identity_pk, &ack_frame),
        )],
    };
    st.direct_ack_outbox.push_back(delivery.clone());
    st.processed_direct.insert(
        frame_key.clone(),
        ProcessedDirect {
            frame_hash,
            delivery: delivery.clone(),
        },
    );
    st.processed_direct_order.push_back(frame_key.clone());
    if let Err(error) = persist_received_direct_transaction(st, sender_pk, ack.sealed_state()) {
        st.direct_ack_outbox.pop_back();
        st.processed_direct.remove(&frame_key);
        st.processed_direct_order.pop_back();
        return Err(error);
    }
    st.sessions
        .get_mut(sender_pk)
        .expect("session prepared above")
        .commit_receive(received)
        .and_then(|()| {
            st.sessions
                .get_mut(sender_pk)
                .expect("session committed above")
                .commit_send(ack)
        })
        .map_err(|error| error.to_string())?;
    wrapping_key.fill(0);
    while st.processed_direct_order.len() > 8192 {
        if let Some(oldest) = st.processed_direct_order.pop_front() {
            st.processed_direct.remove(&oldest);
        }
    }
    // The ACK leaves on the next jittered direct tick from the outbox, never
    // synchronously from the receive path: an inbound cell must not produce
    // an immediately correlated outbound one.
    Ok(delivery)
}

pub(crate) fn process_frame(
    st: &mut NodeState,
    sender_pk: Vec<u8>,
    frame: gcoms_crypto::session::Frame,
    events: &broadcast::Sender<Ev>,
) {
    let frame_key = (sender_pk.clone(), frame.ctr);
    let frame_hash: [u8; 32] = Sha256::digest(frame.encode()).into();
    let Some(session) = st.sessions.get(&sender_pk) else {
        return;
    };
    let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
    let context = match direct_session_context(st, &sender_pk) {
        Ok(context) => context,
        Err(error) => {
            metrics::log_event("frame_error", &[("e", error)]);
            return;
        }
    };
    let received = session.prepare_receive(&frame, &wrapping_key, &context);
    match received {
        Ok(received) => match decode_direct_record(received.plaintext()) {
            Some(DirectRecord::VolatileApplication {
                message_id, body, ..
            }) => {
                if body.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT
                    || st
                        .application_inbox
                        .routing_policy
                        .as_ref()
                        .is_some_and(|policy| !policy.permits(&sender_pk, &body))
                {
                    return;
                }
                // Persist only the ratchet and ordinary receipt ACK, never the
                // incoming application body or its ciphertext frame.
                if accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                )
                .is_err()
                {
                    return;
                }
                let _ = events.send(Ev::VolatileApplication {
                    peer_pk: sender_pk.clone(),
                    msg_id: message_id,
                    ts_unix: now_unix(),
                    body,
                });
            }
            Some(DirectRecord::Data {
                durable,
                message_id,
                sent_ms,
                share_presence,
                body,
            }) => {
                if gcoms_core::is_volatile_application_payload(&body) {
                    metrics::log_event("volatile_contact_on_persistent_transport", &[]);
                    return;
                }
                let latency = now_ms().saturating_sub(sent_ms);
                let inbox_checkpoint = (
                    st.application_inbox.next_sequence,
                    st.application_inbox.entries.len(),
                );
                if durable {
                    if !cfg!(feature = "client-persist")
                        || st.durable_state_sink.is_none()
                        || !st.durable_applications_enabled
                    {
                        metrics::log_event("durable_application_unavailable", &[]);
                        return;
                    }
                    if let Err(error) =
                        st.application_inbox
                            .stage(&sender_pk, message_id, now_unix(), &body)
                    {
                        metrics::log_event("durable_application_rejected", &[("e", error)]);
                        return;
                    }
                }
                if let Err(error) = accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                ) {
                    st.application_inbox.entries.truncate(inbox_checkpoint.1);
                    st.application_inbox.next_sequence = inbox_checkpoint.0;
                    metrics::log_event("frame_persist_error", &[("e", error)]);
                    return;
                }
                if durable {
                    // Delivered through the persistent cursor API. Volatile
                    // event subscribers cannot accidentally consume this data.
                    return;
                }
                if share_presence
                    && st.direct_presence_opt_in.contains(&sender_pk)
                    && st.direct_presence.contains_key(&sender_pk)
                {
                    observe_direct_reachability(
                        st,
                        &sender_pk,
                        Reachability::RecentlyReachable,
                        PASSIVE_REACHABILITY_SECS,
                        events,
                    );
                }
                metrics::log_event("message_delivered", &[("ms", latency.to_string())]);
                let _ = events.send(Ev::Message {
                    peer_pk: sender_pk.clone(),
                    msg_id: message_id,
                    ts_unix: now_unix(),
                    text: body,
                    latency_hint_ms: latency,
                });
            }
            Some(DirectRecord::ContactUpdate { message_id, update }) => {
                let current_generation = st
                    .peer_route_generations
                    .get(&sender_pk)
                    .copied()
                    .unwrap_or(0);
                if update.generation <= current_generation || !update.verify(&sender_pk, now_unix())
                {
                    if persist_received_direct_transaction(st, &sender_pk, received.sealed_state())
                        .is_ok()
                    {
                        let _ = st
                            .sessions
                            .get_mut(&sender_pk)
                            .expect("session prepared above")
                            .commit_receive(received);
                    }
                    metrics::log_event("contact_update_rejected", &[]);
                    return;
                }
                let old_route = st
                    .peer_routes
                    .insert(sender_pk.clone(), update.info.clone());
                let old_generation = st
                    .peer_route_generations
                    .insert(sender_pk.clone(), update.generation);
                if let (Some(bundle), Some(session)) = (
                    Bundle::decode(&update.info.bundle),
                    st.sessions.get_mut(&sender_pk),
                ) {
                    let _ = session.provide_peer_kem(bundle.kem_pub);
                }
                if let Err(error) = accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                ) {
                    match old_route {
                        Some(route) => {
                            st.peer_routes.insert(sender_pk.clone(), route);
                        }
                        None => {
                            st.peer_routes.remove(&sender_pk);
                        }
                    }
                    match old_generation {
                        Some(generation) => {
                            st.peer_route_generations
                                .insert(sender_pk.clone(), generation);
                        }
                        None => {
                            st.peer_route_generations.remove(&sender_pk);
                        }
                    }
                    metrics::log_event("contact_update_persist_error", &[("e", error)]);
                    return;
                }
                // The route transaction is committed. Wake existing work now
                // instead of leaving it on the old queue until the retry timer.
                for pending in st.pending_1to1.values_mut() {
                    if pending.delivery.peer.identity_pk == sender_pk {
                        pending.next_attempt = std::time::Instant::now();
                    }
                }
                metrics::log_event(
                    "contact_update_accepted",
                    &[("generation", update.generation.to_string())],
                );
            }
            Some(DirectRecord::ForwardGrant { message_id, grant }) => {
                if let Err(error) = accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                ) {
                    metrics::log_event("grant_persist_error", &[("e", error)]);
                    return;
                }
                // Only a grant issued by the authenticated sender is trusted,
                // and never one pointing at a private/reserved target.
                if grant.issued_by == sender_pk
                    && grant.expires_at > now_unix()
                    && st.frwd_target_policy.permits(&grant.target)
                {
                    install_forward_grant(st, grant);
                } else {
                    metrics::log_event("grant_rejected", &[]);
                }
            }
            Some(DirectRecord::PresenceLease {
                message_id,
                counter,
                mode,
                lease_secs,
            }) => {
                if let Err(error) = accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                ) {
                    metrics::log_event("presence_persist_error", &[("e", error)]);
                    return;
                }
                if !apply_direct_presence(st, &sender_pk, counter, mode, lease_secs, events) {
                    metrics::log_event("presence_replay_rejected", &[]);
                }
            }
            Some(DirectRecord::Ack {
                message_id,
                share_presence,
            }) => {
                let matches_peer = st
                    .pending_1to1
                    .get(&message_id)
                    .is_some_and(|pending| pending.delivery.peer.identity_pk == sender_pk);
                let pending = matches_peer
                    .then(|| st.pending_1to1.remove(&message_id))
                    .flatten();
                let application_event = pending
                    .as_ref()
                    .is_some_and(|pending| pending.application_event);
                if let Err(error) =
                    persist_received_direct_transaction(st, &sender_pk, received.sealed_state())
                {
                    if let Some(pending) = pending {
                        st.pending_1to1.insert(message_id, pending);
                    }
                    metrics::log_event("frame_persist_error", &[("e", error)]);
                    return;
                }
                if st
                    .sessions
                    .get_mut(&sender_pk)
                    .expect("session prepared above")
                    .commit_receive(received)
                    .is_err()
                {
                    return;
                }
                wrapping_key.fill(0);
                if matches_peer
                    && share_presence
                    && st.direct_presence_opt_in.contains(&sender_pk)
                    && st.direct_presence.contains_key(&sender_pk)
                {
                    observe_direct_reachability(
                        st,
                        &sender_pk,
                        Reachability::RecentlyReachable,
                        PASSIVE_REACHABILITY_SECS,
                        events,
                    );
                }
                if application_event {
                    let _ = events.send(Ev::DirectDelivery {
                        peer_pk: sender_pk,
                        msg_id: message_id,
                    });
                }
            }
            Some(DirectRecord::InviteRedeem {
                message_id,
                channel,
                member_name,
                invite_id,
                invite_secret,
                key_package,
            }) => {
                // Owner side. Consume the frame like any reliable direct record
                // (dedup + session ratchet), then queue the request for async
                // handling by the invite service (the MLS admit + broadcast + reply
                // cannot run here under the state lock). A duplicate request
                // that already produced a Welcome is answered idempotently by
                // the redeem path, so we always queue.
                if let Err(error) = accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                ) {
                    metrics::log_event("invite_redeem_persist_error", &[("e", error)]);
                    return;
                }
                if st.invite_redeem_inbox.len() < 256 {
                    st.invite_redeem_inbox
                        .push_back(crate::node::state::InviteRedeemRequest {
                            sender_pk: sender_pk.clone(),
                            message_id,
                            channel,
                            member_name,
                            invite_id,
                            invite_secret,
                            key_package,
                        });
                    metrics::log_event("invite_redeem_queued", &[]);
                } else {
                    metrics::log_event("invite_redeem_dropped_full", &[]);
                }
            }
            Some(DirectRecord::InviteWelcome { message_id, result }) => {
                // Friend side. Consume the frame, then wake the waiting
                // `join_with_invite` caller with the owner's result.
                if let Err(error) = accept_reliable_direct(
                    st,
                    &sender_pk,
                    (frame_key, frame_hash),
                    message_id,
                    received,
                    &mut wrapping_key,
                    &context,
                ) {
                    metrics::log_event("invite_welcome_persist_error", &[("e", error)]);
                    return;
                }
                if let Some(waiter) = st.pending_invite_redemptions.remove(&message_id) {
                    let _ = waiter.send(result);
                    metrics::log_event("invite_welcome_delivered", &[]);
                } else {
                    metrics::log_event("invite_welcome_unmatched", &[]);
                }
            }
            None => {
                if persist_received_direct_transaction(st, &sender_pk, received.sealed_state())
                    .is_ok()
                {
                    let _ = st
                        .sessions
                        .get_mut(&sender_pk)
                        .expect("session prepared above")
                        .commit_receive(received);
                }
                metrics::log_event("frame_error", &[("e", "bad direct record".to_string())]);
            }
        },
        Err(gcoms_crypto::CryptoError::Replay) => {
            if let Some(processed) = st.processed_direct.get(&frame_key) {
                if processed.frame_hash == frame_hash && st.direct_ack_outbox.len() < 1024 {
                    st.direct_ack_outbox.push_back(processed.delivery.clone());
                }
            }
        }
        Err(e) => {
            metrics::log_event("frame_error", &[("e", e.to_string())]);
        }
    }
}

pub(crate) struct AcceptedFirstMove {
    pub(crate) peer_pk: Vec<u8>,
    pub(crate) rewritten: Vec<DirectDelivery>,
}

pub(crate) fn remember_first_move(st: &mut NodeState, first_move_id: [u8; 32]) {
    st.accepted_first_moves.push_back(first_move_id);
    while st.accepted_first_moves.len() > 512 {
        st.accepted_first_moves.pop_front();
    }
}

pub(crate) fn accept_first_move(
    st: &mut NodeState,
    fm: &FirstMove,
) -> Result<AcceptedFirstMove, String> {
    let first_move_id: [u8; 32] = Sha256::digest(fm.encode()).into();
    if st.accepted_first_moves.contains(&first_move_id) {
        return Err(gcoms_crypto::CryptoError::Replay.to_string());
    }
    let (payload0, mut session) = st.secrets.accept(fm).map_err(|error| error.to_string())?;
    let Some((bootstrap, signature)) = gcoms_crypto::split_authenticated_payload(&payload0) else {
        return Err(gcoms_crypto::CryptoError::BadEncoding.to_string());
    };
    if bootstrap.first() != Some(&KIND_BOOTSTRAP) {
        return Err(gcoms_crypto::CryptoError::BadEncoding.to_string());
    }
    let Some(peer) = NodeInfo::decode(bootstrap) else {
        return Err(gcoms_crypto::CryptoError::BadEncoding.to_string());
    };
    // The claimed identity must prove possession before any route, session,
    // or application state is touched: an unsigned or mis-signed first move
    // is indistinguishable from forgery and is never remembered or emitted.
    let Some(own_bundle) = Bundle::decode(&st.info.bundle) else {
        return Err("own bundle is undecodable".into());
    };
    // Bidirectional PQ refresh (SPEC §8.3): the responder learns the
    // initiator's current ML-KEM key from the authenticated bootstrap so it
    // can refresh toward the initiator too.
    if let Some(peer_bundle) = Bundle::decode(&peer.bundle) {
        if peer_bundle.is_fresh(now_unix()) {
            let _ = session.provide_peer_kem(peer_bundle.kem_pub);
        }
    }
    if !gcoms_crypto::verify_first_move_auth(
        fm,
        &peer.identity_pk,
        &st.info.identity_pk,
        &own_bundle,
        bootstrap,
        signature,
    ) {
        return Err(gcoms_crypto::CryptoError::BadSignature.to_string());
    }
    if peer.identity_pk == st.info.identity_pk {
        remember_first_move(st, first_move_id);
        return Err(gcoms_crypto::CryptoError::Replay.to_string());
    }
    if st.sessions.contains_key(&peer.identity_pk) {
        match st
            .session_states
            .get(&peer.identity_pk)
            .copied()
            .unwrap_or(DirectSessionState::Established)
        {
            DirectSessionState::Established => {
                remember_first_move(st, first_move_id);
                return Err(gcoms_crypto::CryptoError::Replay.to_string());
            }
            DirectSessionState::InitiatedUnconfirmed { .. }
                if st.info.identity_pk < peer.identity_pk =>
            {
                remember_first_move(st, first_move_id);
                return Err(gcoms_crypto::CryptoError::Replay.to_string());
            }
            DirectSessionState::InitiatedUnconfirmed { .. } => {}
        }
    }

    let mut pending_ids = st
        .pending_1to1
        .iter()
        .filter_map(|(message_id, pending)| {
            (pending.delivery.peer.identity_pk == peer.identity_pk)
                .then_some((*message_id, pending.sequence))
        })
        .collect::<Vec<_>>();
    pending_ids.sort_by_key(|(_, sequence)| *sequence);
    let mut session = session;
    let mut replacements = Vec::with_capacity(pending_ids.len());
    let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
    let context = direct_session_context(st, &peer.identity_pk)?;
    for (message_id, _) in &pending_ids {
        let pending = st
            .pending_1to1
            .get(message_id)
            .expect("pending direct selected above");
        let record = pending
            .logical_record
            .as_deref()
            .ok_or("unconfirmed direct record is not recoverable")?;
        let prepared = session
            .prepare_send(record, &wrapping_key, &context)
            .map_err(|error| error.to_string())?;
        let frame = gcoms_crypto::Frame::decode(prepared.wire()).ok_or("prepared invalid frame")?;
        let replacement = PendingDirect {
            delivery: DirectDelivery {
                peer: peer.clone(),
                relay: pending.delivery.relay.clone(),
                cells: vec![Cell::new(
                    CellType::Msg,
                    0,
                    3,
                    encode_frame(&st.info.identity_pk, &frame),
                )],
            },
            logical_record: Some(record.to_vec()),
            sequence: pending.sequence,
            next_attempt: pending.next_attempt,
            expires: pending.expires,
            application_event: pending.application_event,
        };
        session
            .commit_send(prepared)
            .map_err(|error| error.to_string())?;
        replacements.push((*message_id, replacement));
    }
    wrapping_key.fill(0);

    let old_route = st
        .peer_routes
        .insert(peer.identity_pk.clone(), peer.clone());
    let old_session = st.sessions.insert(peer.identity_pk.clone(), session);
    let old_session_state = st
        .session_states
        .insert(peer.identity_pk.clone(), DirectSessionState::Established);
    let mut old_pending = Vec::with_capacity(replacements.len());
    for (message_id, replacement) in replacements {
        if let Some(old) = st.pending_1to1.insert(message_id, replacement) {
            old_pending.push((message_id, old));
        }
    }
    if let Err(error) = persist_current_direct_state(st) {
        st.sessions.remove(&peer.identity_pk);
        st.session_states.remove(&peer.identity_pk);
        if let Some(session) = old_session {
            st.sessions.insert(peer.identity_pk.clone(), session);
        }
        if let Some(state) = old_session_state {
            st.session_states.insert(peer.identity_pk.clone(), state);
        }
        for (message_id, pending) in old_pending {
            st.pending_1to1.insert(message_id, pending);
        }
        if let Some(route) = old_route {
            st.peer_routes.insert(peer.identity_pk.clone(), route);
        } else {
            st.peer_routes.remove(&peer.identity_pk);
        }
        return Err(error);
    }
    remember_first_move(st, first_move_id);
    let mut rewritten: Vec<DirectDelivery> = pending_ids
        .into_iter()
        .filter_map(|(message_id, _)| {
            st.pending_1to1
                .get(&message_id)
                .map(|pending| pending.delivery.clone())
        })
        .collect();
    // Offer ourselves as an intermediary to the peer (SPEC §12: every node
    // relays). The record leaves on the next direct tick like any other.
    match queue_forward_grant(st, &peer.identity_pk) {
        Ok(Some(delivery)) => rewritten.push(delivery),
        Ok(None) => {}
        Err(error) => metrics::log_event("grant_offer_error", &[("e", error)]),
    }
    Ok(AcceptedFirstMove {
        peer_pk: peer.identity_pk,
        rewritten,
    })
}

/// Install a grant into the pool and, if the active set has room, open a
/// pinned lane toward it right away.
pub(crate) fn install_forward_grant(st: &mut NodeState, mut grant: crate::alias::ForwardGrant) {
    let service_id = grant.target.relay_service_id;
    if st.forward_grants.len() >= MAX_FORWARD_GRANTS && !st.forward_grants.contains_key(&service_id)
    {
        grant.zeroize();
        metrics::log_event("grant_pool_full", &[]);
        return;
    }
    if let Some(mut old) = st.forward_grants.insert(service_id, grant.clone()) {
        old.zeroize();
    }
    if st.active_intermediaries.len() < LANE_SET && !st.active_intermediaries.contains(&service_id)
    {
        open_intermediary_lane(st, &grant);
        st.active_intermediaries.push(service_id);
    }
    metrics::log_event(
        "grant_installed",
        &[("pool", st.forward_grants.len().to_string())],
    );
}

fn open_intermediary_lane(st: &NodeState, grant: &crate::alias::ForwardGrant) {
    let relay = RelayProvision {
        aliases: vec![OwnedAlias {
            contact: AliasContact {
                target: grant.target.clone(),
                queue_id: [0; 32],
                epoch: 0,
                push_cap: [0; 32],
                expiry: grant.expires_at,
            },
            capabilities: crate::lease::Capabilities {
                push: [0; 32],
                sub: [0; 32],
                admin: [0; 32],
            },
            limits: crate::lease::LeaseLimits {
                max_queue_cells: 0,
                max_queue_bytes: 0,
            },
            create_path: String::new(),
            lease_create: Cell::new(CellType::RelaySub, 0, 0, Vec::new()),
        }],
        frwd_path: grant.frwd_path.clone(),
        hop_key: grant.hop_key,
    };
    let decoy_target = st
        .client_relay
        .aliases
        .first()
        .map(|alias| alias.contact.target.clone())
        .unwrap_or_else(|| grant.target.clone());
    let _ = st.scheduler.open_lane(
        crate::scheduler::LaneAuth::Frwd {
            relay,
            decoy_target,
            policy: st.frwd_target_policy.clone(),
        },
        true,
    );
}

/// Rotate one member of the active intermediary set every `LANE_ROTATE`
/// (jittered), so the set of concurrent TLS peers changes slowly rather
/// than tracking message arrivals.
pub(crate) fn rotate_active_intermediaries(st: &mut NodeState) {
    let now = now_unix();
    st.forward_grants.retain(|_, grant| grant.expires_at > now);
    st.active_intermediaries
        .retain(|service_id| st.forward_grants.contains_key(service_id));
    // Fill empty slots first.
    let mut candidates: Vec<[u8; 32]> = st
        .forward_grants
        .keys()
        .filter(|id| !st.active_intermediaries.contains(id))
        .copied()
        .collect();
    if candidates.is_empty() {
        return;
    }
    use rand::seq::SliceRandom;
    use rand::Rng;
    let mut rng = rand::rngs::StdRng::from_entropy();
    candidates.shuffle(&mut rng);
    while st.active_intermediaries.len() < LANE_SET {
        let Some(next) = candidates.pop() else { break };
        if let Some(grant) = st.forward_grants.get(&next).cloned() {
            open_intermediary_lane(st, &grant);
            st.active_intermediaries.push(next);
        }
    }
    if st.last_intermediary_rotation.elapsed() < jittered(LANE_ROTATE) {
        return;
    }
    st.last_intermediary_rotation = std::time::Instant::now();
    if let (Some(next), true) = (candidates.pop(), st.active_intermediaries.len() >= LANE_SET) {
        let victim_index = rng.gen_range(0..st.active_intermediaries.len());
        let victim = st.active_intermediaries.swap_remove(victim_index);
        if let Some(grant) = st.forward_grants.get(&victim).cloned() {
            close_intermediary_lane(st, &grant);
        }
        if let Some(grant) = st.forward_grants.get(&next).cloned() {
            open_intermediary_lane(st, &grant);
            st.active_intermediaries.push(next);
        }
    }
}

fn close_intermediary_lane(st: &NodeState, grant: &crate::alias::ForwardGrant) {
    let relay = RelayProvision {
        aliases: vec![OwnedAlias {
            contact: AliasContact {
                target: grant.target.clone(),
                queue_id: [0; 32],
                epoch: 0,
                push_cap: [0; 32],
                expiry: grant.expires_at,
            },
            capabilities: crate::lease::Capabilities {
                push: [0; 32],
                sub: [0; 32],
                admin: [0; 32],
            },
            limits: crate::lease::LeaseLimits {
                max_queue_cells: 0,
                max_queue_bytes: 0,
            },
            create_path: String::new(),
            lease_create: Cell::new(CellType::RelaySub, 0, 0, Vec::new()),
        }],
        frwd_path: grant.frwd_path.clone(),
        hop_key: grant.hop_key,
    };
    st.scheduler.close_lane(&crate::scheduler::LaneAuth::Frwd {
        relay,
        decoy_target: grant.target.clone(),
        policy: st.frwd_target_policy.clone(),
    });
}

/// Encrypt a `ForwardGrant` record for `peer` into the pending journal so it
/// is delivered (and retried) like any other direct record. Returns the
/// delivery if one was queued.
pub(crate) fn queue_forward_grant(
    st: &mut NodeState,
    peer: &[u8],
) -> Result<Option<DirectDelivery>, String> {
    if st.pending_1to1.len() >= 1024 {
        return Ok(None);
    }
    let Some(route) = st.peer_routes.get(peer).cloned() else {
        return Ok(None);
    };
    let expires_at = now_unix().saturating_add(FORWARD_GRANT_LIFETIME_SECS);
    let Some(grant) = st
        .client_relay
        .forward_grant(expires_at, st.info.identity_pk.clone())
    else {
        return Ok(None);
    };
    let message_id = forward_grant_message_id(&st.info.identity_pk, peer, expires_at);
    if st.pending_1to1.contains_key(&message_id) {
        return Ok(None);
    }
    let record = encode_forward_grant(message_id, &grant).ok_or("grant exceeds record limit")?;
    let sequence = st.next_direct_sequence;
    st.next_direct_sequence = sequence
        .checked_add(1)
        .ok_or("direct message sequence exhausted")?;
    let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
    let context = direct_session_context(st, peer)?;
    let prepared = st
        .sessions
        .get(peer)
        .ok_or("no session for grant")?
        .prepare_send(&record, &wrapping_key, &context)
        .map_err(|error| error.to_string())?;
    wrapping_key.fill(0);
    let frame = gcoms_crypto::Frame::decode(prepared.wire()).ok_or("prepared invalid frame")?;
    let delivery = DirectDelivery {
        peer: route,
        relay: st.client_relay.clone(),
        cells: vec![Cell::new(
            CellType::Msg,
            0,
            3,
            encode_frame(&st.info.identity_pk, &frame),
        )],
    };
    let now = std::time::Instant::now();
    st.pending_1to1.insert(
        message_id,
        PendingDirect {
            delivery: delivery.clone(),
            logical_record: Some(record),
            sequence,
            next_attempt: now + jittered(std::time::Duration::from_secs(60)),
            expires: now + std::time::Duration::from_secs(FORWARD_GRANT_LIFETIME_SECS),
            application_event: false,
        },
    );
    if let Err(error) = persist_direct_transaction(st, peer, prepared.sealed_state()) {
        st.pending_1to1.remove(&message_id);
        st.next_direct_sequence = sequence;
        return Err(error);
    }
    st.sessions
        .get_mut(peer)
        .expect("session prepared above")
        .commit_send(prepared)
        .map_err(|error| error.to_string())?;
    Ok(Some(delivery))
}

fn forward_grant_message_id(identity: &[u8], peer: &[u8], expires_at: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"gc1/forward-grant/message-id/v1\0");
    digest.update(identity);
    digest.update(peer);
    digest.update(expires_at.to_be_bytes());
    digest.finalize()[..16].try_into().expect("SHA-256 prefix")
}

pub(crate) async fn send_1to1(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    peer: &NodeInfo,
    text: &[u8],
    via: Option<NodeInfo>,
) -> Result<(), String> {
    send_1to1_id(state, scheduler, peer, text, via)
        .await
        .map(|_| ())
}

pub(crate) async fn send_1to1_tracked(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    peer: &NodeInfo,
    text: &[u8],
    via: Option<NodeInfo>,
) -> Result<[u8; 16], String> {
    if !cfg!(feature = "client-persist")
        || state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .durable_state_sink
            .is_none()
    {
        return Err("tracked send requires persistent client state".into());
    }
    send_1to1_id(state, scheduler, peer, text, via).await
}

pub(crate) async fn send_1to1_id(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    peer: &NodeInfo,
    text: &[u8],
    via: Option<NodeInfo>,
) -> Result<[u8; 16], String> {
    validate_application_payload(text)?;
    let share_presence = state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .direct_presence_opt_in
        .contains(&peer.identity_pk);
    send_direct_record(state, scheduler, peer, via, true, |message_id, _| {
        Ok(encode_direct_data(
            message_id,
            now_ms(),
            share_presence,
            text,
        ))
    })
    .await
}

pub(crate) async fn send_volatile_application(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    peer: &NodeInfo,
    body: &[u8],
) -> Result<(), String> {
    validate_application_size(body)?;
    send_direct_record(state, scheduler, peer, None, false, |message_id, _| {
        Ok(crate::proto::encode_volatile_application(
            message_id,
            now_ms(),
            body,
        ))
    })
    .await
    .map(|_| ())
}

pub(crate) async fn send_durable_1to1(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    peer: &NodeInfo,
    body: &[u8],
    via: Option<NodeInfo>,
) -> Result<(), String> {
    validate_application_payload(body)?;
    if body.is_empty()
        || !cfg!(feature = "client-persist")
        || state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .durable_state_sink
            .is_none()
    {
        return Err(
            "durable application delivery requires persistent client state and a nonempty body"
                .into(),
        );
    }
    if !state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .durable_applications_enabled
    {
        return Err("durable applications are not enabled for this profile".into());
    }
    send_direct_record(state, scheduler, peer, via, true, |message_id, _| {
        Ok(crate::proto::encode_direct_durable_data(
            message_id,
            now_ms(),
            body,
        ))
    })
    .await
    .map(|_| ())
}

pub(crate) async fn send_direct_record<F>(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    peer: &NodeInfo,
    via: Option<NodeInfo>,
    application_event: bool,
    encode_record: F,
) -> Result<[u8; 16], String>
where
    F: FnOnce([u8; 16], u64) -> Result<Vec<u8>, String>,
{
    peer.primary().ok_or("peer has no public alias")?;
    let peer = select_peer_route(
        &state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        peer,
    )?;
    let relay = match via {
        // An explicit card forces the first hop (tests, catalog bootstrap).
        Some(card) => card
            .provisioning
            .ok_or("via card has no private relay provisioning fields")?,
        // Otherwise pick a random eligible intermediary for this message
        // (SPEC §11.1); falls back to our own relay when none is eligible.
        None => {
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            choose_intermediary(&mut st, &peer)
        }
    };
    let message_id = fresh_msg_id();
    let (delivery, policy, durable) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.pending_1to1.len() >= 1024 {
            return Err("too many unacknowledged direct messages".into());
        }
        let sequence = st.next_direct_sequence;
        let next_direct_sequence = sequence
            .checked_add(1)
            .ok_or("direct message sequence exhausted")?;
        let mut direct = zeroize::Zeroizing::new(encode_record(message_id, sequence)?);
        // Validate the worst sending epoch, not just the frame produced today:
        // a durable record may need re-encryption after simultaneous initiation.
        let overhead = gcoms_crypto::session::MAX_FRAME_OVERHEAD
            .saturating_add(3)
            .saturating_add(st.info.identity_pk.len());
        if direct.len().saturating_add(overhead) > gcoms_core::MAX_MESSAGE {
            return Err(format!(
                "direct record exceeds {} byte PQ-safe limit",
                gcoms_core::MAX_MESSAGE.saturating_sub(overhead)
            ));
        }
        let durable = crate::proto::is_durable_direct_data(&direct);
        if crate::proto::is_volatile_application(&direct)
            && (!st.sessions.contains_key(&peer.identity_pk)
                || !matches!(
                    st.session_states.get(&peer.identity_pk),
                    Some(DirectSessionState::Established)
                ))
        {
            return Err(
                "volatile application requires an established authenticated session".into(),
            );
        }
        if crate::proto::is_volatile_application(&direct) {
            let queued: Vec<_> = st
                .pending_1to1
                .values()
                .filter(|pending| {
                    pending
                        .logical_record
                        .as_deref()
                        .is_some_and(crate::proto::is_volatile_application)
                })
                .collect();
            if queued.len() >= 64
                || queued
                    .iter()
                    .filter(|pending| pending.delivery.peer.identity_pk == peer.identity_pk)
                    .count()
                    >= 8
            {
                return Err("volatile outbox quota exceeded".into());
            }
        }
        if durable {
            let queued = st
                .pending_1to1
                .values()
                .filter(|pending| {
                    pending
                        .logical_record
                        .as_deref()
                        .is_some_and(crate::proto::is_durable_direct_data)
                })
                .collect::<Vec<_>>();
            let component = direct_component_source(&direct);
            let quota = st.application_inbox.routing_policy.as_ref().map_or(
                application_inbox::APPLICATION_INBOX_PEER_LIMIT,
                |policy| {
                    policy.quota(
                        application_inbox::APPLICATION_INBOX_LIMIT,
                        application_inbox::APPLICATION_INBOX_PEER_LIMIT,
                    )
                },
            );
            if queued.len() >= application_inbox::APPLICATION_INBOX_LIMIT
                || queued
                    .iter()
                    .filter(|pending| {
                        let source = pending
                            .logical_record
                            .as_deref()
                            .and_then(direct_component_source);
                        if st.application_inbox.routing_policy.is_some() && component.is_some() {
                            source == component
                        } else {
                            pending.delivery.peer.identity_pk == peer.identity_pk
                                && source == component
                                && pending
                                    .logical_record
                                    .as_deref()
                                    .and_then(direct_component_destination)
                                    == direct_component_destination(&direct)
                        }
                    })
                    .count()
                    >= quota
            {
                return Err("durable application transport outbox is full".into());
            }
        }

        let awaiting_confirmation = st.scheduler.pipelined()
            && matches!(
                st.session_states.get(&peer.identity_pk),
                Some(DirectSessionState::InitiatedUnconfirmed { .. })
            );
        let routing_recovering = st.routing.is_some() && st.info.primary().is_none();
        if routing_recovering || awaiting_confirmation {
            if !durable {
                return Err(if awaiting_confirmation {
                    "direct session confirmation is pending"
                } else {
                    "inbox routing is recovering"
                }
                .into());
            }
            let now = std::time::Instant::now();
            st.next_direct_sequence = next_direct_sequence;
            st.pending_1to1.insert(
                message_id,
                PendingDirect {
                    delivery: DirectDelivery {
                        peer: peer.clone(),
                        relay,
                        cells: Vec::new(),
                    },
                    logical_record: Some(std::mem::take(&mut *direct)),
                    sequence,
                    next_attempt: now,
                    expires: now + std::time::Duration::from_secs(600),
                    application_event,
                },
            );
            if let Err(error) = persist_current_direct_state(&st) {
                st.pending_1to1.remove(&message_id);
                st.next_direct_sequence = sequence;
                return Err(error);
            }
            // No ratchet slot or network operation has occurred. The exact
            // logical record, ID and original deadline are now durable locally.
            return Ok(message_id);
        }

        let old_route = st
            .peer_routes
            .insert(peer.identity_pk.clone(), peer.clone());
        for pending in st.pending_1to1.values_mut() {
            if pending.delivery.peer.identity_pk == peer.identity_pk {
                pending.delivery.peer = peer.clone();
            }
        }
        for ack in &mut st.direct_ack_outbox {
            if ack.peer.identity_pk == peer.identity_pk {
                ack.peer = peer.clone();
            }
        }
        for processed in st.processed_direct.values_mut() {
            if processed.delivery.peer.identity_pk == peer.identity_pk {
                processed.delivery.peer = peer.clone();
            }
        }
        let mut first_move = None;
        let new_session = !st.sessions.contains_key(&peer.identity_pk);
        let now = std::time::Instant::now();
        let expires = now + std::time::Duration::from_secs(600);
        let old_session_state = st.session_states.get(&peer.identity_pk).copied();
        if new_session {
            let bundle = Bundle::decode(&peer.bundle).ok_or("bad peer bundle")?;
            if !bundle.is_fresh(now_unix()) {
                return Err("peer bundle is outside its rotation window".into());
            }
            let own_info = st.info.encode();
            let identity = IdentityKeypair::from_seed(st.identity_seed);
            let (fm, mut session) = gcoms_crypto::initiate_authenticated(
                &identity,
                &peer.identity_pk,
                &bundle,
                &own_info,
            )
            .map_err(|e| e.to_string())?;
            session.provide_local_kem(st.secrets.kem_decapsulation_key());
            st.sessions.insert(peer.identity_pk.clone(), session);
            st.session_states.insert(
                peer.identity_pk.clone(),
                DirectSessionState::InitiatedUnconfirmed { expires },
            );
            first_move = Some(fm);
        } else if !st.scheduler.pipelined()
            && matches!(
                old_session_state,
                Some(DirectSessionState::InitiatedUnconfirmed { .. })
            )
        {
            st.session_states.insert(
                peer.identity_pk.clone(),
                DirectSessionState::InitiatedUnconfirmed { expires },
            );
        }
        let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
        let context = direct_session_context(&st, &peer.identity_pk)?;
        let prepared = st.sessions[&peer.identity_pk]
            .prepare_send(&direct, &wrapping_key, &context)
            .map_err(|error| error.to_string())?;
        wrapping_key.fill(0);
        let frame = gcoms_crypto::Frame::decode(prepared.wire()).ok_or("prepared invalid frame")?;
        let mut cells = Vec::with_capacity(if first_move.is_some() { 2 } else { 1 });
        if let Some(first_move) = &first_move {
            cells.push(Cell::new(
                CellType::Msg,
                0,
                1,
                encode_first_move(first_move),
            ));
        }
        cells.push(Cell::new(
            CellType::Msg,
            0,
            if first_move.is_some() { 2 } else { 3 },
            encode_frame(&st.info.identity_pk, &frame),
        ));
        let delivery = DirectDelivery {
            peer: peer.clone(),
            relay,
            cells,
        };
        st.next_direct_sequence = next_direct_sequence;
        st.pending_1to1.insert(
            message_id,
            PendingDirect {
                delivery: delivery.clone(),
                logical_record: Some(std::mem::take(&mut *direct)),
                sequence,
                next_attempt: now + std::time::Duration::from_secs(60),
                expires,
                application_event,
            },
        );
        if let Err(error) =
            persist_direct_transaction(&st, &peer.identity_pk, prepared.sealed_state())
        {
            st.pending_1to1.remove(&message_id);
            st.next_direct_sequence = sequence;
            if new_session {
                st.sessions.remove(&peer.identity_pk);
                st.session_states.remove(&peer.identity_pk);
            } else if let Some(state) = old_session_state {
                st.session_states.insert(peer.identity_pk.clone(), state);
            }
            if let Some(route) = old_route {
                st.peer_routes.insert(peer.identity_pk.clone(), route);
            } else {
                st.peer_routes.remove(&peer.identity_pk);
            }
            return Err(error);
        }
        st.sessions
            .get_mut(&peer.identity_pk)
            .expect("session prepared above")
            .commit_send(prepared)
            .map_err(|error| error.to_string())?;
        st.peer_route_generations
            .entry(peer.identity_pk.clone())
            .or_insert(0);
        (delivery, st.frwd_target_policy.clone(), durable)
    };
    if delivery.cells.len() == 2 {
        metrics::log_event("first_move_sent", &[]);
    } else {
        metrics::log_event("frame_sent", &[]);
    }
    if durable {
        // The API confirms durable local acceptance. Network receipt waits here
        // would block every later request on the application's IPC connection.
        // Queued frames remain in the persisted retry outbox until a peer ACK
        // (or the existing transport expiry), including scheduler backpressure.
        let destination = delivery.peer.primary().ok_or("peer has no public alias")?;
        for cell in &delivery.cells {
            if let Err(error) = scheduler.frwd(
                ProducerClass::Direct,
                delivery.relay.clone(),
                destination.clone(),
                cell.clone(),
                policy.clone(),
            ) {
                metrics::log_event(
                    "durable_application_enqueue_deferred",
                    &[("e", error.to_string())],
                );
                break;
            }
        }
    } else {
        deliver_direct(scheduler, &delivery, &policy).await?;
    }
    Ok(message_id)
}

pub(super) fn materialize_deferred(st: &mut NodeState) -> Result<(), String> {
    if st.info.primary().is_none()
        || st.client_relay.aliases.is_empty()
        || super::routing::recovering(st)
    {
        return Ok(());
    }
    let now = std::time::Instant::now();
    let mut ids: Vec<_> = st
        .pending_1to1
        .iter()
        .filter(|(_, p)| p.delivery.cells.is_empty() && p.expires > now)
        .map(|(id, p)| (*id, p.sequence))
        .collect();
    ids.sort_by_key(|(_, sequence)| *sequence);
    for (id, _) in ids {
        let pending = &st.pending_1to1[&id];
        let peer = select_peer_route(st, &pending.delivery.peer)?;
        if st.scheduler.pipelined()
            && matches!(
                st.session_states.get(&peer.identity_pk),
                Some(DirectSessionState::InitiatedUnconfirmed { .. })
            )
        {
            // The first reliable record owns session setup. Later logical
            // records retain their IDs/deadlines without consuming ratchet slots.
            continue;
        }
        let expires = pending.expires;
        let body = zeroize::Zeroizing::new(
            pending
                .logical_record
                .clone()
                .ok_or("missing deferred application record")?,
        );
        let new_session = !st.sessions.contains_key(&peer.identity_pk);
        let mut first_move = None;
        let mut staged_session = None;
        if new_session {
            let bundle = Bundle::decode(&peer.bundle).ok_or("invalid deferred peer bundle")?;
            if !bundle.is_fresh(now_unix()) {
                continue;
            }
            let identity = IdentityKeypair::from_seed(st.identity_seed);
            let (fm, mut session) = gcoms_crypto::initiate_authenticated(
                &identity,
                &peer.identity_pk,
                &bundle,
                &st.info.encode(),
            )
            .map_err(|e| e.to_string())?;
            session.provide_local_kem(st.secrets.kem_decapsulation_key());
            staged_session = Some(session);
            first_move = Some(fm);
        }
        let wrapping = zeroize::Zeroizing::new(direct_session_wrapping_key(&st.identity_seed));
        let context = direct_session_context(st, &peer.identity_pk)?;
        let prepared = staged_session
            .as_ref()
            .or_else(|| st.sessions.get(&peer.identity_pk))
            .expect("new or existing session")
            .prepare_send(&body, &wrapping, &context)
            .map_err(|e| e.to_string())?;
        let frame = gcoms_crypto::Frame::decode(prepared.wire())
            .ok_or("invalid prepared application frame")?;
        let mut cells = Vec::new();
        if let Some(fm) = first_move {
            cells.push(Cell::new(CellType::Msg, 0, 1, encode_first_move(&fm)));
        }
        cells.push(Cell::new(
            CellType::Msg,
            0,
            if cells.is_empty() { 3 } else { 2 },
            encode_frame(&st.info.identity_pk, &frame),
        ));
        for cell in &cells {
            cell.encode_wire().map_err(|e| e.to_string())?;
        }
        // Preparation may fail before a candidate can be saved. Keep a fresh
        // session local until then so the next attempt still sends FirstMove.
        if let Some(session) = staged_session {
            st.sessions.insert(peer.identity_pk.clone(), session);
            st.session_states.insert(
                peer.identity_pk.clone(),
                DirectSessionState::InitiatedUnconfirmed { expires },
            );
        }
        let relay = choose_intermediary(st, &peer);
        let pending = st
            .pending_1to1
            .get_mut(&id)
            .expect("selected pending application");
        pending.delivery = DirectDelivery {
            peer: peer.clone(),
            relay,
            cells,
        };
        pending.next_attempt = now;
        if let Err(error) =
            persist_direct_transaction(st, &peer.identity_pk, prepared.sealed_state())
        {
            // A sink can fail after writing. Preserve the candidate and stop
            // publication until restart resolves its durable ratchet outcome.
            st.pause_failed_owner_transition();
            return Err(error);
        }
        if let Err(error) = st
            .sessions
            .get_mut(&peer.identity_pk)
            .expect("prepared session")
            .commit_send(prepared)
        {
            st.pause_failed_owner_transition();
            return Err(error.to_string());
        }
        st.peer_routes
            .insert(peer.identity_pk.clone(), peer.clone());
        st.peer_route_generations
            .entry(peer.identity_pk)
            .or_insert(0);
    }
    Ok(())
}

pub(crate) fn select_peer_route(st: &NodeState, caller: &NodeInfo) -> Result<NodeInfo, String> {
    if st
        .peer_route_generations
        .get(&caller.identity_pk)
        .copied()
        .unwrap_or(0)
        > 0
    {
        st.peer_routes
            .get(&caller.identity_pk)
            .cloned()
            .ok_or_else(|| "authenticated peer route is missing".into())
    } else {
        Ok(caller.public())
    }
}

pub(crate) fn direct_session_wrapping_key(identity_seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(
        Some(b"gc1/node/direct-session-wrapping-key/v1"),
        identity_seed,
    );
    let mut key = [0; 32];
    hk.expand(b"gc-node/client-persist", &mut key)
        .expect("32-byte HKDF output");
    key
}

pub(crate) fn direct_session_context(
    st: &NodeState,
    peer: &[u8],
) -> Result<SessionContext, String> {
    let machine: [u8; 32] = Sha256::digest(&st.info.identity_pk).into();
    let peer: [u8; 32] = Sha256::digest(peer).into();
    SessionContext::new(machine, b"gc-node/direct-session/v1", peer, b"direct")
        .map_err(|error| error.to_string())
}

fn direct_component_source(record: &[u8]) -> Option<gcoms_core::component::ComponentId> {
    match crate::proto::decode_direct_record(record)? {
        crate::proto::DirectRecord::Data { body, .. } => {
            gcoms_core::component::RoutedApplication::decode(&body)
                .ok()
                .map(|r| r.source)
        }
        _ => None,
    }
}

fn direct_component_destination(record: &[u8]) -> Option<gcoms_core::component::ComponentId> {
    match crate::proto::decode_direct_record(record)? {
        crate::proto::DirectRecord::Data { body, .. } => {
            gcoms_core::component::RoutedApplication::decode(&body)
                .ok()
                .map(|r| r.destination)
        }
        _ => None,
    }
}
