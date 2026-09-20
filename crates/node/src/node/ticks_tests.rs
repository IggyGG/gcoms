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
