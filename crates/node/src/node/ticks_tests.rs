use super::*;
use bytes::Bytes;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "experimental-gc2")]
#[path = "ticks_route_tests.rs"]
mod protected_routes;

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn unavailable_entries_preserve_inbox_and_channel_authority() {
    use std::sync::atomic::Ordering;
    let directory = Arc::new(gcoms_routing::gc2::directory::Directory::for_loopback_fixture());
    let (_entry_owner, ready) = gcoms_routing::gc2::owner::EntryOwner::new(
        directory,
        gcoms_routing::gc2::CandidateProfile::file_transfer(),
        2,
    )
    .unwrap();
    let scheduler = RelayScheduler::gc2(ready.clone()).unwrap();
    let runtime = super::super::routing::RoutingRuntime::new(
        RoutingConfig::default(),
        gcoms_routing::Directory::new(),
        true,
    )
    .unwrap();
    runtime.recovering_owner.store(false, Ordering::Release);
    runtime.channel_ready.lock().unwrap().insert("files".into());
    let mut node = persist::tests::state();
    node.scheduler = scheduler.clone();
    node.gc2_carrier = Some(ready);
    node.routing = Some(runtime.clone());
    node.channels.insert(
        "files".into(),
        persist::tests::established_owner_fixture("files"),
    );
    let inbox = node.client_relay.clone();
    let channel = node.channels["files"].own_route.aliases.clone();
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);
    let contact = spawn_contact_subscription_pump(
        state.clone(),
        scheduler.clone(),
        events.clone(),
        Duration::from_millis(10),
    );
    let channels = spawn_channel_subscription_pump(state.clone(), scheduler.clone(), events);
    // Poll both ordinary pumps across several maintenance opportunities with
    // retained authority but no usable entry, as at the hourly carrier rollover.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    for pump in [contact, channels] {
        pump.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), pump.task)
            .await
            .unwrap()
            .unwrap();
    }
    scheduler.shutdown();
    assert!(
        !runtime.recovering_owner.load(Ordering::Acquire),
        "a missing entry must not invalidate retained inbox authority"
    );
    assert!(
        runtime.channel_ready.lock().unwrap().contains("files"),
        "a missing entry must not invalidate retained channel authority"
    );
    let st = state.lock().unwrap();
    assert_eq!(st.client_relay, inbox);
    assert_eq!(st.channels["files"].own_route.aliases, channel);
    assert!(st.subscribed_classes.is_empty());
}

#[tokio::test]
async fn channel_control_retries_while_data_response_is_stalled() {
    let identity = TlsIdentity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let mut channel = persist::tests::established_owner_fixture("ops");
    let mut peer = channel.own_route.public.clone();
    peer.pseudonym = [42; 32];
    peer.data.target = target.clone();
    peer.control.target = target;
    peer.data.expiry = now_unix() + 3600;
    peer.control.expiry = peer.data.expiry;
    channel.directory.insert("peer".into(), peer.clone());
    channel.learn(&peer);
    let wire = b"retained opaque MLS data".to_vec();
    let id = crate::channel::msg_id("ops", &wire);
    channel.queue_pull(crate::channel::PeerRef::from_route(&peer), id, wire);

    let profile = SchedulerProfile::compressed_production(42);
    let scheduler =
        RelayScheduler::with_profile(Arc::new(Tp1Client::new().unwrap()), profile.clone());
    let mut node = persist::tests::state();
    node.scheduler = scheduler.clone();
    node.channels.insert("ops".into(), channel);
    let state = Arc::new(Mutex::new(node));
    let (events, _) = broadcast::channel(4);

    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let data_contact = peer.data.clone();
    let control_contact = peer.control.clone();
    let (data_tx, mut data_rx) = mpsc::channel(4);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        while let Some(Ok((request, mut reply))) = connection.accept().await {
            let data_contact = data_contact.clone();
            let control_contact = control_contact.clone();
            let data_tx = data_tx.clone();
            let control_tx = control_tx.clone();
            let attempts = attempts.clone();
            tokio::spawn(async move {
                let is_data =
                    request.uri().path() == format!("/{}", encode_b64url(&data_contact.queue_id));
                let contact = if is_data {
                    data_contact
                } else {
                    control_contact
                };
                let mut body = request.into_body();
                let mut encoded = Vec::new();
                while let Some(Ok(bytes)) = body.data().await {
                    body.flow_control().release_capacity(bytes.len()).unwrap();
                    encoded.extend_from_slice(&bytes);
                }
                let cell = gcoms_core::decode(&encoded).unwrap();
                let push = crate::relay::RelayPush::decode_from_cell(
                    &cell,
                    &contact.push_cap,
                    &contact.target.relay_service_id,
                    now_unix(),
                )
                .unwrap();
                let mut send = reply.send_response(http::Response::new(()), false).unwrap();
                // Ignore scheduled covers; only real work drives the fixture.
                let outcome = if push.msg.is_none() {
                    gcoms_transport::HopReply::Accepted
                } else if is_data {
                    data_tx.send(send).await.unwrap();
                    return;
                } else {
                    let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    control_tx.send(attempt).await.unwrap();
                    if attempt == 0 {
                        gcoms_transport::HopReply::Overloaded
                    } else {
                        gcoms_transport::HopReply::Accepted
                    }
                };
                send.send_data(Bytes::from(outcome.cell().encode_wire().unwrap()), true)
                    .unwrap();
            });
        }
    });
    let maintenance =
        spawn_channel_maintenance_loop(state.clone(), scheduler.clone(), events, profile, [42; 32]);
    let held_data = tokio::time::timeout(Duration::from_secs(5), data_rx.recv())
        .await
        .unwrap()
        .unwrap();
    // The first data cycle is already waiting for a response body. Queue a
    // newly generated ACK now: it needs a later, independent control cycle.
    state
        .lock()
        .unwrap()
        .channels
        .get_mut("ops")
        .unwrap()
        .pending_control
        .push_back((peer, b"retained opaque MLS ACK".to_vec()));
    for expected in 0..2 {
        let attempt = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attempt, expected);
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.lock().unwrap().channels["ops"]
                .pending_control
                .is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        scheduler.resource_snapshot().jobs > 0,
        "data is still in flight"
    );
    maintenance.abort();
    let _ = maintenance.await;
    scheduler.shutdown();
    drop(held_data);
    server.abort();
}

// Differential local scheduling probe: authenticated hop receipts are not MLS
// delivery ACKs. Outboxes stay pending in both layouts until a real member ACK.
#[tokio::test]
async fn retained_channel_data_same_channel_peers_progress_independently() {
    retained_channel_data_progress(false, false).await;
}

#[tokio::test]
async fn retained_channel_data_other_channel_progresses_while_peer_is_stalled() {
    retained_channel_data_progress(true, false).await;
}

#[tokio::test]
async fn retained_channel_data_later_channel_progresses_during_backlogged_stalled_channel() {
    retained_channel_data_progress(true, true).await;
}

async fn retained_channel_data_progress(separate_channels: bool, later: bool) {
    let origin = std::time::Instant::now();
    let identity = TlsIdentity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let profile = SchedulerProfile::compressed_production(42);
    let scheduler =
        RelayScheduler::with_profile(Arc::new(Tp1Client::new().unwrap()), profile.clone());
    let mut node = persist::tests::state();
    node.scheduler = scheduler.clone();
    node.channels.insert(
        "alpha".into(),
        persist::tests::established_owner_fixture("alpha"),
    );
    if separate_channels {
        node.channels.insert(
            "beta".into(),
            persist::tests::established_owner_fixture("beta"),
        );
    }
    // Select the actual first iteration slot, without changing production map
    // ordering or relying on a randomly chosen channel name to stall first.
    let names: Vec<_> = node.channels.keys().cloned().collect();
    let first = names[0].clone();
    let second = names[usize::from(separate_channels)].clone();
    let mut held = node.channels[&first].own_route.public.clone();
    held.pseudonym = [81; 32];
    held.data.target = target.clone();
    held.data.queue_id = [81; 32];
    held.data.push_cap = [83; 32];
    held.data.expiry = now_unix() + 300;
    let mut healthy = held.clone();
    healthy.pseudonym = [82; 32];
    healthy.data.queue_id = [82; 32];
    healthy.data.push_cap = [84; 32];
    let mut retained = Vec::new();
    for (name, peer, wire) in [
        (
            first.clone(),
            held.clone(),
            b"held opaque channel wire".to_vec(),
        ),
        (
            second.clone(),
            healthy.clone(),
            b"healthy opaque channel wire".to_vec(),
        ),
    ] {
        let id = crate::channel::msg_id(&name, &wire);
        node.channels.get_mut(&name).unwrap().message_outbox.insert(
            id,
            crate::channel::ChannelMessageOutbox {
                wire: wire.clone(),
                expected: [(peer.pseudonym, peer)].into_iter().collect(),
                acknowledged: HashSet::new(),
            },
        );
        retained.push((name, id, wire));
    }
    let deferred = if later {
        let pending = node
            .channels
            .get_mut(&second)
            .unwrap()
            .message_outbox
            .remove(&retained[1].1)
            .unwrap();
        for n in 0..32u8 {
            let wire = vec![n; 1024];
            let id = crate::channel::msg_id(&first, &wire);
            node.channels
                .get_mut(&first)
                .unwrap()
                .message_outbox
                .insert(
                    id,
                    crate::channel::ChannelMessageOutbox {
                        wire,
                        expected: [(held.pseudonym, held.clone())].into_iter().collect(),
                        acknowledged: HashSet::new(),
                    },
                );
        }
        Some(pending)
    } else {
        None
    };
    let state = Arc::new(Mutex::new(node));
    let (events, mut seen) = broadcast::channel(8);
    let (held_tx, mut held_rx) = mpsc::channel(4);
    let (healthy_tx, mut healthy_rx) = mpsc::channel(4);
    let (hold_observed, hold_started) = tokio::sync::watch::channel(false);
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let held = held.clone();
            let healthy = healthy.clone();
            let held_tx = held_tx.clone();
            let healthy_tx = healthy_tx.clone();
            let hold_started = hold_started.clone();
            connections.spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                let mut requests = tokio::task::JoinSet::new();
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    let held = held.clone();
                    let healthy = healthy.clone();
                    let held_tx = held_tx.clone();
                    let healthy_tx = healthy_tx.clone();
                    let mut hold_started = hold_started.clone();
                    requests.spawn(async move {
                        let is_held = request.uri().path()
                            == format!("/{}", encode_b64url(&held.data.queue_id));
                        let contact = if is_held { held.data } else { healthy.data };
                        assert_eq!(
                            request.uri().path(),
                            format!("/{}", encode_b64url(&contact.queue_id))
                        );
                        let mut body = request.into_body();
                        let mut bytes = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                            bytes.extend_from_slice(&chunk);
                        }
                        let cell = gcoms_core::decode(&bytes).unwrap();
                        let push = crate::relay::RelayPush::decode_from_cell(
                            &cell,
                            &contact.push_cap,
                            &contact.target.relay_service_id,
                            now_unix(),
                        )
                        .unwrap();
                        let mut response =
                            reply.send_response(http::Response::new(()), false).unwrap();
                        if let Some(cell) = push.msg {
                            let payload = crate::proto::decode_chan(&cell).unwrap();
                            if is_held {
                                held_tx.send((payload, response)).await.unwrap();
                                return;
                            }
                            let arrived_at = origin.elapsed();
                            while !*hold_started.borrow_and_update() {
                                hold_started.changed().await.unwrap();
                            }
                            healthy_tx
                                .send((payload, arrived_at, origin.elapsed()))
                                .await
                                .unwrap();
                        }
                        response
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
                    });
                }
            });
        }
    });
    let tick_state = state.clone();
    let tick_scheduler = scheduler.clone();
    let tick = if later {
        spawn_channel_maintenance_loop(tick_state, tick_scheduler, events, profile, [42; 32])
    } else {
        tokio::spawn(async move { channel_tick(&tick_state, &tick_scheduler, &events).await })
    };
    let ((held_name, held_wire), mut held_response) =
        tokio::time::timeout(Duration::from_secs(5), held_rx.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(held_name, first);
    if !later {
        assert_eq!(held_wire, retained[0].2);
    }
    if let Some(pending) = deferred {
        state
            .lock()
            .unwrap()
            .channels
            .get_mut(&second)
            .unwrap()
            .message_outbox
            .insert(retained[1].1, pending);
    }
    let held_at = origin.elapsed();
    hold_observed.send(true).unwrap();
    let during_hold = scheduler.resource_snapshot();
    let healthy_before_release = tokio::time::timeout(Duration::from_secs(2), healthy_rx.recv())
        .await
        .ok()
        .flatten();
    let release_at = origin.elapsed();
    held_response
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
    let progressed_before_release = healthy_before_release.is_some();
    let ((healthy_name, healthy_wire), healthy_request_at, healthy_at) =
        match healthy_before_release {
            Some(arrival) => arrival,
            None => tokio::time::timeout(Duration::from_secs(5), healthy_rx.recv())
                .await
                .unwrap()
                .unwrap(),
        };
    assert_eq!(healthy_name, second);
    assert_eq!(healthy_wire, retained[1].2);
    if later {
        tick.abort();
        assert!(tick.await.unwrap_err().is_cancelled());
    } else {
        tokio::time::timeout(Duration::from_secs(5), tick)
            .await
            .unwrap()
            .unwrap();
    }
    let completed_at = origin.elapsed();
    {
        let node = state.lock().unwrap();
        for (name, id, wire) in &retained {
            let pending = &node.channels[name].message_outbox[id];
            assert_eq!(&pending.wire, wire);
            assert!(pending.acknowledged.is_empty());
        }
    }
    while let Ok(event) = seen.try_recv() {
        assert!(
            !matches!(event, Ev::ChannelDelivery { .. }),
            "hop acceptance is not member delivery"
        );
    }
    scheduler.shutdown();
    tokio::time::timeout(Duration::from_secs(2), async {
        while scheduler.resource_snapshot().jobs != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let final_budget = scheduler.resource_snapshot();
    assert_eq!(final_budget.bytes, 0);
    assert!(final_budget.peak_jobs <= crate::scheduler::MAX_QUEUED_JOBS);
    assert!(final_budget.peak_bytes <= crate::scheduler::MAX_QUEUED_BYTES);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "channel_retry_progress_probe",
            "separate_channels": separate_channels,
            "later_healthy_work_with_32_stalled_wires": later,
            "first_channel": first,
            "second_channel": second,
            "held_hop_ms": held_at.as_millis(),
            "release_ms": release_at.as_millis(),
            "healthy_request_ms": healthy_request_at.as_millis(),
            "healthy_hop_ms": healthy_at.as_millis(),
            "completion_ms": completed_at.as_millis(),
            "healthy_before_release": progressed_before_release,
            "during_hold": during_hold,
            "after_cleanup": final_budget,
            "pending_outboxes": retained.len(),
            "cleanup_complete": true
        })
    );
    assert!(
        progressed_before_release,
        "responsive channel retry must progress while another channel's hop receipt is held"
    );
}
