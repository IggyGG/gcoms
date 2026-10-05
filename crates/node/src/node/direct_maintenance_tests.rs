use super::*;
use bytes::Bytes;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn delivery(st: &NodeState, tag: u8) -> DirectDelivery {
    let mut peer = st.info.clone();
    for alias in &mut peer.aliases {
        alias.expiry = now_unix() + 3600;
    }
    DirectDelivery {
        peer,
        relay: st.client_relay.clone(),
        cells: vec![Cell::new(CellType::Msg, 0, 0, vec![tag; 32])],
    }
}

fn pending(delivery: DirectDelivery, sequence: u64, now: Instant) -> PendingDirect {
    PendingDirect {
        delivery,
        logical_record: None,
        sequence,
        next_attempt: now,
        expires: now + Duration::from_secs(600),
        application_event: false,
    }
}

#[tokio::test]
async fn local_route_failure_retries_exact_work_without_shortening_unknown_outcomes() {
    for failure in [
        Some("no ready independent GC/2 route"),
        Some("tp1 request timed out"),
        Some("GC/2 terminal deposit refused: Internal"),
        None,
    ] {
        let mut node = persist::tests::state();
        let scheduler = node.scheduler.clone();
        let now = Instant::now();
        let work = delivery(&node, 1);
        let key = direct_attempt_key(&work);
        let mut retained = pending(work.clone(), 1, now);
        retained.next_attempt = now + Duration::from_secs(60);
        let deadline = retained.expires;
        node.pending_1to1.insert([1; 16], retained);
        let mut rewritten = pending(work.clone(), 2, now);
        rewritten.delivery.cells[0].payload[0] ^= 1;
        rewritten.next_attempt = now + Duration::from_secs(60);
        node.pending_1to1.insert([2; 16], rewritten);
        let state = Arc::new(Mutex::new(node));
        let mut owner = DirectMaintenance::default();
        owner.active.insert(key, false);
        #[cfg(feature = "experimental-gc2")]
        owner.repair_due.insert(key, now + Duration::from_secs(60));
        let result = failure.map_or(Ok(()), |error| Err(error.into()));
        owner.completions.push(Box::pin(async move {
            DirectAttempt {
                key,
                ack: false,
                destination: work.peer.primary().cloned(),
                accepted: result.is_ok(),
                route_unavailable: local_route_unavailable(&result),
            }
        }));
        owner.complete_next(&state).await;
        assert!(owner.active.is_empty());
        let st = state.lock().unwrap();
        let retained = &st.pending_1to1[&[1; 16]];
        assert_eq!(retained.expires, deadline);
        assert_eq!(retained.delivery.cells[0].payload, vec![1; 32]);
        assert_eq!(
            st.pending_1to1[&[2; 16]].next_attempt,
            now + Duration::from_secs(60)
        );
        if failure == Some("no ready independent GC/2 route") {
            assert!(retained.next_attempt >= now + Duration::from_secs(4));
            assert!(retained.next_attempt < now + Duration::from_secs(7));
            #[cfg(feature = "experimental-gc2")]
            assert_eq!(owner.repair_due[&key], retained.next_attempt);
        } else {
            assert_eq!(retained.next_attempt, now + Duration::from_secs(60));
            #[cfg(feature = "experimental-gc2")]
            assert_eq!(owner.repair_due[&key], retained.next_attempt);
        }
        drop(st);
        scheduler.shutdown();
    }
}

fn component_record(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut application = b"GCAPP1".to_vec();
    application.extend_from_slice(&(kind.len() as u16).to_be_bytes());
    application.extend_from_slice(kind.as_bytes());
    application.extend_from_slice(body);
    let routed = gcoms_core::component::RoutedApplication {
        source: [7; 16],
        destination: [8; 16],
        application,
    };
    crate::proto::encode_direct_durable_data([9; 16], 1, &routed.encode().unwrap())
}

#[test]
fn file_records_are_bulk_while_chat_control_and_acknowledgements_stay_interactive() {
    assert_eq!(
        direct_traffic_class(&component_record(
            gcoms_core::FILE_RECORD_CONTENT_TYPE,
            b"chunk"
        )),
        gcoms_core::TrafficClass::Bulk
    );
    assert_eq!(
        direct_traffic_class(&component_record("application/vnd.ghost.chat.v1", b"hi")),
        gcoms_core::TrafficClass::Interactive
    );
    assert_eq!(
        direct_traffic_class(&crate::proto::encode_direct_ack([4; 16], false)),
        gcoms_core::TrafficClass::Interactive
    );
    assert_eq!(
        direct_traffic_class(&crate::proto::encode_volatile_application(
            [5; 16], 1, b"media"
        )),
        gcoms_core::TrafficClass::Interactive
    );
    for (kind, expected) in [
        (
            gcoms_core::CONTACT_PIECE_CONTENT_TYPE,
            gcoms_core::TrafficClass::Bulk,
        ),
        (
            "application/vnd.gcoms.file-control.v2",
            gcoms_core::TrafficClass::Interactive,
        ),
    ] {
        let mut plain = b"GCAPP1".to_vec();
        plain.extend((kind.len() as u16).to_be_bytes());
        plain.extend(kind.as_bytes());
        plain.extend(b"record");
        let wire = crate::proto::encode_direct_durable_data([8; 16], 1, &plain);
        assert_eq!(direct_traffic_class(&wire), expected);
    }
    for (kind, expected) in [
        (
            gcoms_core::CONTACT_PIECE_CONTENT_TYPE,
            gcoms_core::TrafficClass::Bulk,
        ),
        (
            "application/vnd.gcoms.file-control.v2",
            gcoms_core::TrafficClass::Interactive,
        ),
        (
            gcoms_core::VOLATILE_FILE_CONTENT_TYPE,
            gcoms_core::TrafficClass::Bulk,
        ),
        (
            gcoms_core::VOLATILE_FILE_ACK_CONTENT_TYPE,
            gcoms_core::TrafficClass::Interactive,
        ),
        (
            gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE,
            gcoms_core::TrafficClass::Interactive,
        ),
        (
            gcoms_core::bootstrap::CONTENT_TYPE,
            gcoms_core::TrafficClass::Interactive,
        ),
    ] {
        let record = component_record(kind, b"record");
        let Some(crate::proto::DirectRecord::Data { body, .. }) =
            crate::proto::decode_direct_record(&record)
        else {
            panic!("fixture")
        };
        let volatile = crate::proto::encode_volatile_application([6; 16], 1, &body);
        assert_eq!(direct_traffic_class(&volatile), expected, "{kind}");
    }
}

#[test]
fn legacy_sessions_preserve_one_lane_even_when_gc2_is_enabled() {
    let mut node = persist::tests::state();
    let peer = node.info.clone();
    let (_, session) = peer_session::initiate(&node, &peer).unwrap();
    node.sessions.insert(peer.identity_pk.clone(), session);
    #[cfg(feature = "experimental-gc2")]
    {
        node.gc2_sessions = true;
    }
    for traffic in [
        gcoms_core::TrafficClass::Interactive,
        gcoms_core::TrafficClass::Bulk,
    ] {
        assert_eq!(
            direct_transport_class(&node, &peer.identity_pk, traffic),
            gcoms_core::TrafficClass::Interactive
        );
    }
}

#[cfg(feature = "client-persist")]
#[test]
fn legacy_durable_backlog_waits_for_a_ciphertext_window_receipt() {
    let mut node = persist::tests::state();
    let identity = gcoms_crypto::IdentityKeypair::from_seed([2; 32]);
    let (bundle, _) = identity.issue_bundle();
    let mut peer = node.info.clone();
    peer.identity_pk = identity.public_bytes();
    peer.bundle = bundle.encode();
    for alias in &mut peer.aliases {
        alias.expiry = now_unix() + 3600;
    }
    let (_, session) = peer_session::initiate(&node, &peer).unwrap();
    assert!(session.tag().is_none());
    node.sessions.insert(peer.identity_pk.clone(), session);
    node.session_states
        .insert(peer.identity_pk.clone(), DirectSessionState::Established);
    let saved = Arc::new(Mutex::new(Vec::new()));
    let sink = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        *sink.lock().unwrap() = bytes;
        Ok(())
    }));
    let state = Arc::new(Mutex::new(node));
    let prepare = |body: &'static [u8]| {
        prepare_direct_record(&state, &peer, None, false, None, |id, sequence| {
            Ok(crate::proto::encode_direct_durable_data(id, sequence, body))
        })
        .unwrap()
    };
    let first: Vec<_> = (0..LEGACY_APPLICATION_WINDOW)
        .map(|_| prepare(b"first"))
        .collect();
    assert!(first.iter().all(|p| !p.delivery.cells.is_empty()));
    let second = prepare(b"second");
    let third = prepare(b"third");
    assert!(second.delivery.cells.is_empty());
    assert!(third.delivery.cells.is_empty());
    let mut node = state.lock().unwrap();
    let counter = node.sessions[&peer.identity_pk].send_ctr();
    let original_deadline = node.pending_1to1[&second.message_id].expires;
    materialize_deferred(&mut node).unwrap();
    assert_eq!(node.sessions[&peer.identity_pk].send_ctr(), counter);
    assert!(node.pending_1to1[&second.message_id]
        .delivery
        .cells
        .is_empty());
    assert_eq!(
        node.pending_1to1[&second.message_id].expires,
        original_deadline
    );
    assert!(
        !saved.lock().unwrap().is_empty(),
        "deferred records must be durable"
    );

    // Receipt authentication is exercised by the receive-path tests. Removing
    // that acknowledged entry releases exactly one retained logical record.
    node.pending_1to1.remove(&first[0].message_id);
    materialize_deferred(&mut node).unwrap();
    assert!(!node.pending_1to1[&second.message_id]
        .delivery
        .cells
        .is_empty());
    assert!(node.pending_1to1[&third.message_id]
        .delivery
        .cells
        .is_empty());
    assert_eq!(node.sessions[&peer.identity_pk].send_ctr(), counter + 1);
    assert_eq!(
        node.pending_1to1[&second.message_id].expires,
        original_deadline
    );
}

#[cfg(feature = "experimental-gc2")]
#[test]
fn credited_sessions_keep_bulk_and_interactive_initial_and_retry_classes() {
    let mut node = persist::tests::state();
    node.gc2_sessions = true;
    let identity = gcoms_crypto::IdentityKeypair::from_seed([2; 32]);
    let (bundle, _) = identity.issue_bundle();
    let mut peer = node.info.clone();
    peer.identity_pk = identity.public_bytes();
    peer.bundle = bundle.encode();
    let (_, session) = peer_session::initiate(&node, &peer).unwrap();
    assert!(session.tag().is_some());
    node.sessions.insert(peer.identity_pk.clone(), session);
    node.pending_1to1.insert(
        [42; 16],
        PendingDirect {
            delivery: DirectDelivery {
                peer: peer.clone(),
                relay: node.client_relay.clone(),
                cells: vec![Cell::new(CellType::Msg, 0, 0, vec![1; 32])],
            },
            logical_record: Some(crate::proto::encode_direct_durable_data(
                [42; 16], 1, b"data",
            )),
            sequence: 1,
            next_attempt: Instant::now(),
            expires: Instant::now() + Duration::from_secs(600),
            application_event: false,
        },
    );
    assert!(!legacy_application_window_full(&node, &peer.identity_pk));
    for traffic in [
        gcoms_core::TrafficClass::Interactive,
        gcoms_core::TrafficClass::Bulk,
    ] {
        assert_eq!(
            direct_transport_class(&node, &peer.identity_pk, traffic),
            traffic
        );
    }
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn gc2_owned_retry_copies_are_charged_before_poll_and_released_on_cancel() {
    let mut node = persist::tests::state();
    node.gc2_sessions = true;
    // Exercise the natural carrier branch as well as its retained GC/2 state.
    node.gc2_carrier_client = Some(Arc::new(Tp1Client::new().unwrap()));
    let scheduler = node.scheduler.clone();
    let mut ack = delivery(&node, 1);
    ack.cells[0].payload = vec![0; gcoms_protocol::flow::CREDIT_BYTES];
    ack.cells[0].payload[..4].copy_from_slice(b"GCA2");
    node.direct_ack_outbox.push_back(ack);
    persist_current_direct_state(&node).unwrap();
    let retained = scheduler.resource_snapshot().bytes;
    assert_eq!(retained, gcoms_protocol::flow::CREDIT_BYTES);
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);
    let mut owner = DirectMaintenance::default();
    owner.tick(&state, &scheduler, &events);
    assert_eq!(owner.active.len(), 1);
    assert_eq!(scheduler.resource_snapshot().bytes, retained * 2);
    drop(owner);
    assert_eq!(scheduler.resource_snapshot().bytes, retained);
    assert_eq!(state.lock().unwrap().direct_ack_outbox.len(), 1);
    drop(state);
    assert_eq!(scheduler.resource_snapshot().bytes, 0);
    scheduler.shutdown();
}

#[tokio::test]
async fn bounds_fair_retries_and_ack_archive_survive_owner_cancellation() {
    let mut node = persist::tests::state();
    let scheduler = node.scheduler.clone();
    let now = Instant::now();
    for id in 0..80 {
        node.pending_1to1.insert(
            [id; 16],
            pending(delivery(&node, id), u64::from(id) + 1, now),
        );
    }
    node.next_direct_sequence = 81;
    for id in 160..180 {
        let ack = delivery(&node, id);
        // Duplicate receives may enqueue the same cached ACK more than once.
        node.direct_ack_outbox.extend([ack.clone(), ack]);
    }
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);
    let mut owner = DirectMaintenance::default();
    owner.tick(&state, &scheduler, &events);
    assert_eq!(owner.active.values().filter(|&&ack| ack).count(), 16);
    assert_eq!(owner.active.values().filter(|&&ack| !ack).count(), 48);
    {
        let mut st = state.lock().unwrap();
        for id in 0..80 {
            let pending = st.pending_1to1.get_mut(&[id; 16]).unwrap();
            assert_eq!(pending.next_attempt > now, id < 48);
            assert_eq!(pending.expires, now + Duration::from_secs(600));
            // A receipt can last longer than a retry interval.
            pending.next_attempt = now;
        }
    }
    owner.tick(&state, &scheduler, &events);
    assert_eq!(
        owner.active.len(),
        64,
        "repeated ticks cannot accumulate attempts"
    );
    let archive = persist::encode_state(&state.lock().unwrap()).unwrap();
    drop(owner);
    assert_eq!(state.lock().unwrap().direct_ack_outbox.len(), 40);
    let restored = Arc::new(Mutex::new(persist::tests::state()));
    persist::decode_state_at_startup(&restored, &scheduler, &archive)
        .await
        .unwrap();
    let st = restored.lock().unwrap();
    assert_eq!(
        st.direct_ack_outbox.len(),
        40,
        "in-flight ACKs remain archived"
    );
    assert_eq!(st.direct_ack_outbox[0].cells[0].payload, vec![160; 32]);
    assert_eq!(st.pending_1to1.len(), 80);
    st.scheduler.shutdown();
    scheduler.shutdown();
}

#[tokio::test]
async fn rerouting_deduplicates_but_rekeyed_ciphertext_gets_a_distinct_attempt() {
    let mut node = persist::tests::state();
    let scheduler = node.scheduler.clone();
    let now = Instant::now();
    node.pending_1to1
        .insert([1; 16], pending(delivery(&node, 1), 1, now));
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);
    let mut owner = DirectMaintenance::default();
    owner.tick(&state, &scheduler, &events);
    {
        let mut st = state.lock().unwrap();
        let pending = st.pending_1to1.get_mut(&[1; 16]).unwrap();
        pending.delivery.peer.aliases[0].queue_id = [222; 32];
        pending.delivery.relay.frwd_path = "renewed-private-path".into();
        pending.next_attempt = now;
    }
    owner.tick(&state, &scheduler, &events);
    assert_eq!(owner.active.len(), 1);
    {
        let mut st = state.lock().unwrap();
        st.pending_1to1.get_mut(&[1; 16]).unwrap().delivery.cells[0].payload[0] ^= 1;
    }
    owner.tick(&state, &scheduler, &events);
    assert_eq!(
        owner.active.len(),
        2,
        "same logical ID can carry rewritten ciphertext"
    );
    scheduler.shutdown();
}

#[tokio::test]
async fn rejected_ack_rotates_behind_waiters_and_preserves_renewed_route() {
    let mut node = persist::tests::state();
    let scheduler = node.scheduler.clone();
    let first = delivery(&node, 1);
    node.direct_ack_outbox.push_back(first.clone());
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);
    let mut owner = DirectMaintenance::default();
    owner.tick(&state, &scheduler, &events);
    {
        let mut st = state.lock().unwrap();
        st.direct_ack_outbox[0].peer.aliases[0].queue_id = [222; 32];
        let second = delivery(&st, 2);
        st.direct_ack_outbox.extend([second, first]);
    }
    scheduler.shutdown();
    owner.complete_next(&state).await;
    assert!(owner.is_empty());
    let st = state.lock().unwrap();
    assert_eq!(st.direct_ack_outbox.len(), 2, "exact duplicates coalesce");
    assert_eq!(st.direct_ack_outbox[0].cells[0].payload, vec![2; 32]);
    assert_eq!(st.direct_ack_outbox[1].peer.aliases[0].queue_id, [222; 32]);
}

struct HopFixture {
    target: RelayTarget,
    requests: mpsc::Receiver<(Cell, Option<h2::SendStream<Bytes>>)>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HopFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn hop_fixture(hop_key: [u8; 32], contact: AliasContact, stalled: bool) -> HopFixture {
    let identity = TlsIdentity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let service_id = target.relay_service_id;
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let (tx, requests) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let mut jobs = tokio::task::JoinSet::new();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        loop {
            tokio::select! {
                result = jobs.join_next(), if !jobs.is_empty() => { result.unwrap().unwrap(); }
                request = connection.accept() => {
                    let Some(Ok((request, mut reply))) = request else { break; };
                    let tx = tx.clone();
                    let contact = contact.clone();
                    let attempts = attempts.clone();
                    jobs.spawn(async move {
                        let mut body = request.into_body();
                        let mut wire = Vec::new();
                        while let Some(Ok(bytes)) = body.data().await {
                            body.flow_control().release_capacity(bytes.len()).unwrap();
                            wire.extend_from_slice(&bytes);
                        }
                        let cell = gcoms_core::decode(&wire).unwrap();
                        let frwd = crate::forward::decode_authorized(&cell, &hop_key, &service_id, now_unix(), true).unwrap();
                        let mut send = reply.send_response(http::Response::new(()), false).unwrap();
                        let outcome = if let Some(push) = frwd.relay_push {
                            let message = push.authenticate(&contact.push_cap, &contact.target.relay_service_id, now_unix()).unwrap().msg.unwrap();
                            if stalled {
                                tx.send((message, Some(send))).await.unwrap();
                                return;
                            }
                            tx.send((message, None)).await.unwrap();
                            if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                                gcoms_transport::HopReply::Overloaded
                            } else {
                                gcoms_transport::HopReply::Accepted
                            }
                        } else { gcoms_transport::HopReply::Accepted };
                        send.send_data(Bytes::from(outcome.cell().encode_wire().unwrap()), true).unwrap();
                    });
                }
            }
        }
    });
    HopFixture {
        target,
        requests,
        task,
    }
}

#[tokio::test]
async fn stalled_retry_does_not_block_new_ack_retry_or_presence_expiry() {
    let profile = SchedulerProfile::compressed_production(69);
    let scheduler =
        RelayScheduler::with_profile(Arc::new(Tp1Client::new().unwrap()), profile.clone());
    let mut node = persist::tests::state();
    node.scheduler = scheduler.clone();
    node.frwd_target_policy = FrwdTargetPolicy::new(true);
    let first = delivery(&node, 1);
    let second = delivery(&node, 2);
    let contact = first.peer.primary().unwrap().clone();
    let mut slow = hop_fixture(node.client_relay.hop_key, contact.clone(), true).await;
    let mut healthy = hop_fixture(node.client_relay.hop_key, contact, false).await;
    node.client_relay.aliases[0].contact.target = slow.target.clone();
    node.pending_1to1
        .insert([1; 16], pending(first.clone(), 1, Instant::now()));
    let state = Arc::new(Mutex::new(node));
    let (events, mut event_rx) = broadcast::channel(8);
    let task = super::super::ticks::spawn_direct_maintenance_loop(
        state.clone(),
        scheduler.clone(),
        events,
        profile,
        [69; 32],
    );
    let (wire, held_response) = tokio::time::timeout(Duration::from_secs(5), slow.requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire, first.cells[0]);
    let held_response = held_response.unwrap();
    {
        let mut st = state.lock().unwrap();
        st.client_relay.aliases[0].contact.target = healthy.target.clone();
        st.pending_1to1.get_mut(&[1; 16]).unwrap().next_attempt = Instant::now();
        st.direct_ack_outbox
            .extend([second.clone(), second.clone()]);
        st.direct_presence.insert(
            vec![9; 32],
            DirectPresenceObservation {
                reachability: Reachability::RecentlyReachable,
                expires: Instant::now(),
            },
        );
    }
    // A rejected hop receipt must get a fresh maintenance opportunity while the
    // other lane is still waiting. Both attempts reuse the exact cached MSG.
    for _ in 0..2 {
        let (wire, response) =
            tokio::time::timeout(Duration::from_secs(5), healthy.requests.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(wire, second.cells[0]);
        assert!(response.is_none());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.lock().unwrap().direct_ack_outbox.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        event_rx.try_recv(),
        Ok(Ev::PresenceChanged {
            reachability: Reachability::Unknown,
            ..
        })
    ));
    assert!(state.lock().unwrap().direct_presence.is_empty());
    assert_eq!(
        state.lock().unwrap().pending_1to1.len(),
        1,
        "hop receipt is not recipient delivery"
    );
    assert!(
        slow.requests.try_recv().is_err(),
        "held ciphertext is not duplicated"
    );
    assert!(
        healthy.requests.try_recv().is_err(),
        "rerouting does not duplicate the held retry"
    );
    assert!(scheduler.resource_snapshot().jobs > 0);
    task.abort();
    let _ = task.await;
    assert_eq!(
        Arc::strong_count(&state),
        1,
        "canceled work retains no profile references"
    );
    scheduler.shutdown();
    drop(held_response);
}

#[tokio::test]
async fn late_acceptance_on_old_receive_queue_cannot_clear_renewed_ack() {
    let profile = SchedulerProfile::compressed_production(71);
    let scheduler =
        RelayScheduler::with_profile(Arc::new(Tp1Client::new().unwrap()), profile.clone());
    let mut node = persist::tests::state();
    node.scheduler = scheduler.clone();
    node.frwd_target_policy = FrwdTargetPolicy::new(true);
    let ack = delivery(&node, 3);
    let mut renewed = ack.peer.clone();
    renewed.aliases[0].queue_id = [223; 32];
    renewed.aliases[0].push_cap = [224; 32];
    let mut slow = hop_fixture(
        node.client_relay.hop_key,
        ack.peer.primary().unwrap().clone(),
        true,
    )
    .await;
    let mut healthy = hop_fixture(
        node.client_relay.hop_key,
        renewed.primary().unwrap().clone(),
        false,
    )
    .await;
    node.client_relay.aliases[0].contact.target = slow.target.clone();
    node.direct_ack_outbox.push_back(ack.clone());
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);
    let task = super::super::ticks::spawn_direct_maintenance_loop(
        state.clone(),
        scheduler.clone(),
        events,
        profile,
        [71; 32],
    );
    let (wire, held_response) = tokio::time::timeout(Duration::from_secs(5), slow.requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire, ack.cells[0]);
    {
        let mut st = state.lock().unwrap();
        st.client_relay.aliases[0].contact.target = healthy.target.clone();
        st.peer_route_generations
            .insert(renewed.identity_pk.clone(), 1);
        st.peer_routes.insert(renewed.identity_pk.clone(), renewed);
    }
    held_response
        .unwrap()
        .send_data(
            Bytes::from(
                gcoms_transport::HopReply::Accepted
                    .cell()
                    .encode_wire()
                    .unwrap(),
            ),
            true,
        )
        .unwrap();
    // The old queue accepted this ciphertext, but it still needs delivery to
    // the authenticated replacement. The new queue verifies its new push cap.
    for _ in 0..2 {
        let (wire, _) = tokio::time::timeout(Duration::from_secs(5), healthy.requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(wire, ack.cells[0]);
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.lock().unwrap().direct_ack_outbox.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;
    scheduler.shutdown();
}
