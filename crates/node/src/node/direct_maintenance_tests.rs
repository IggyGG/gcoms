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

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn gc2_owned_retry_copies_are_charged_before_poll_and_released_on_cancel() {
    let mut node = persist::tests::state();
    node.gc2_sessions = true;
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
