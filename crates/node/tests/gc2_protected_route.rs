#![cfg(all(feature = "experimental-gc2", feature = "client-persist"))]
//! Live protected-route fixture: two real relay services (entry and middle)
//! and two carrier nodes whose directories are seeded with both introductions.
//! The durable application must cross the protected circuit; the relay
//! dispatch counters prove the circuit was dialed.
use gcoms_node::{
    node::{start_persistent_restored, Ev, NodeConfig, NodeProfile},
    NodeHandle,
};
use gcoms_routing::{route::now_unix, Directory, RelayService, ServicePolicy};
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

type Archive = Arc<Mutex<Vec<u8>>>;

struct Relays {
    entry: Arc<RelayService>,
    middle: Arc<RelayService>,
    entry_connections: Arc<AtomicUsize>,
    middle_connections: Arc<AtomicUsize>,
    _entry_server: tokio::task::JoinHandle<()>,
    _middle_server: tokio::task::JoinHandle<()>,
}

async fn start_relay(
    ip: &str,
    delay: Duration,
) -> (
    Arc<RelayService>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        format!("{ip}:0").parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap();
    let service = RelayService::new(
        server.local_addr().unwrap(),
        identity.service_id(),
        [8; 32],
        Arc::new(Directory::new()),
        ServicePolicy {
            carrier: gcoms_routing::carrier::CarrierConfig::fixture(),
            target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
            ..Default::default()
        },
    )
    .unwrap();
    let factory = service.gc2_handler_factory();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    let server = server.with_dispatch_factory(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        factory()
    }));
    let handle = tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = server.run_until(std::future::pending::<()>()).await;
    });
    (service, connections, handle)
}

async fn start_relays() -> Relays {
    start_relays_after(Duration::ZERO).await
}

async fn start_relays_after(delay: Duration) -> Relays {
    let (entry, entry_connections, entry_server) = start_relay("127.0.0.86", delay).await;
    let (middle, middle_connections, middle_server) = start_relay("127.0.0.87", delay).await;
    Relays {
        entry,
        middle,
        entry_connections,
        middle_connections,
        _entry_server: entry_server,
        _middle_server: middle_server,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_entry_readiness_retries_without_the_minute_timer() {
    let relays = start_relays_after(Duration::from_secs(3)).await;
    let introductions = seeds(&relays);
    let profile = gcoms_routing::gc2::CandidateProfile::new(4096, 250)
        .unwrap()
        .with_mode(gcoms_routing::gc2::CoverMode::Interactive);
    let a = endpoint(
        101,
        NodeProfile::gc2_carrier_qualification_fixture_seeded(None, 1, 101, introductions.clone())
            .with_gc2_traffic_profile(profile)
            .unwrap(),
    )
    .await;
    let b = endpoint(
        102,
        NodeProfile::gc2_carrier_qualification_fixture_seeded(None, 1, 102, introductions)
            .with_gc2_traffic_profile(profile)
            .unwrap(),
    )
    .await;
    a.enable_durable_applications().await.unwrap();
    b.enable_durable_applications().await.unwrap();
    let info = b.current_info().await.unwrap();
    let id = a
        .send_durable_1to1_tracked(&info, b"queued before entry readiness", None)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(25), async {
        let delivered = receive(&b, 1).await;
        assert_eq!(delivered[0].message_id, id);
        assert_eq!(delivered[0].body, b"queued before entry readiness");
        loop {
            if matches!(a.next_event().await, Some(Ev::DirectDelivery {msg_id, ..}) if msg_id == id)
            {
                break;
            }
        }
    })
    .await
    .expect("entry readiness must retry before the 60-second timer");
    a.shutdown().await;
    b.shutdown().await;
}

fn seeds(relays: &Relays) -> Vec<Vec<u8>> {
    let now = now_unix();
    vec![
        relays
            .entry
            .gc2_introduction(now)
            .encode()
            .unwrap()
            .to_vec(),
        relays
            .middle
            .gc2_introduction(now)
            .encode()
            .unwrap()
            .to_vec(),
    ]
}

async fn endpoint(seed: u8, profile: NodeProfile) -> NodeHandle {
    let archive: Archive = Arc::new(Mutex::new(Vec::new()));
    let sink = archive.clone();
    start_persistent_restored(
        NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile,
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes.to_vec();
            Ok(())
        }),
        None,
    )
    .await
    .unwrap()
}

async fn receive(node: &NodeHandle, expected: usize) -> Vec<gcoms_node::node::ApplicationDelivery> {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let messages = node.application_inbox(0, 32).await.unwrap();
            if messages.len() == expected {
                return messages;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("protected-route application delivery timeout")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_route_carries_durable_applications_through_the_circuit() {
    let relays = start_relays().await;
    let introductions = seeds(&relays);
    let a = endpoint(
        81,
        NodeProfile::gc2_carrier_qualification_fixture_seeded(None, 1, 81, introductions.clone()),
    )
    .await;
    a.enable_durable_applications().await.unwrap();
    let b = endpoint(
        82,
        NodeProfile::gc2_carrier_qualification_fixture_seeded(None, 1, 82, introductions),
    )
    .await;
    b.enable_durable_applications().await.unwrap();

    let info = b.current_info().await.unwrap();
    a.send_durable_1to1(&info, b"protected route delivery", None)
        .await
        .unwrap();
    let delivered = receive(&b, 1).await;
    assert_eq!(delivered[0].body, b"protected route delivery");
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if matches!(a.next_event().await, Some(Ev::DirectDelivery { msg_id, .. })
                if msg_id == delivered[0].message_id)
            {
                return;
            }
        }
    })
    .await
    .expect("protected-route application receipt timeout");

    assert!(
        relays.entry_connections.load(Ordering::SeqCst) > 0,
        "the entry relay was never dialed"
    );
    assert!(
        relays.middle_connections.load(Ordering::SeqCst) > 0,
        "the middle relay was never dialed"
    );

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_entries_defer_durable_delivery_without_direct_fallback() {
    let a = endpoint(
        91,
        NodeProfile::gc2_carrier_qualification_fixture(None, 1, 91),
    )
    .await;
    let b = endpoint(
        92,
        NodeProfile::gc2_carrier_qualification_fixture(None, 1, 92),
    )
    .await;
    a.enable_durable_applications().await.unwrap();
    b.enable_durable_applications().await.unwrap();
    let info = b.current_info().await.unwrap();
    a.send_durable_1to1(&info, b"must wait for a protected entry", None)
        .await
        .unwrap();
    // Both terminal listeners are reachable, but neither directory has an
    // entry. The old readiness fallback could deliver over direct TLS here.
    let unexpected = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !b.application_inbox(0, 32).await.unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
    assert!(
        unexpected.is_err(),
        "message escaped the protected route while entries were unavailable"
    );
}
