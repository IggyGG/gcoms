#![cfg(feature = "experimental-gc2")]
use bytes::Bytes;
use gcoms_core::{gc2::NaturalCell, CellType, TrafficClass};
use gcoms_routing::{
    gc2::{
        directory::{BootstrapBundle, Directory as Gc2Directory, Introduction},
        discovery,
    },
    route::now_unix,
    Directory, RelayService, ServicePolicy,
};
use gcoms_transport::{
    gc2::{NaturalOutcome, NaturalRoute},
    server::Tp1Server,
    tls::{self, TlsIdentity},
    TokenRegistry, Tp1Client,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};

// Role isolation belongs to a physical connection. Tp1Client deliberately
// retires its pool entry after 404, so retain TLS/H2 for cross-role probes.
async fn retained_connection(
    seed: &Introduction,
) -> (h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let (sender, connection) = timeout(Duration::from_secs(60), async {
        let socket = tokio::net::TcpStream::connect(seed.addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(
            tls::client_config_pinned(seed.service_id).unwrap(),
        ))
        .connect(tls::server_name_ip(seed.addr.ip()), socket)
        .await
        .unwrap();
        h2::client::handshake(tls).await.unwrap()
    })
    .await
    .expect("retained connection must finish within the client request bound");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

async fn retained_post(
    sender: &h2::client::SendRequest<Bytes>,
    seed: &Introduction,
    token: &str,
    wire: Bytes,
) -> (http::StatusCode, Bytes) {
    timeout(Duration::from_secs(60), async {
        let mut sender = sender.clone().ready().await.unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{}/{token}", seed.addr))
            .body(())
            .unwrap();
        let (response, mut send) = sender.send_request(request, false).unwrap();
        send.send_data(wire, true).unwrap();
        let response = response.await.unwrap();
        let status = response.status();
        let body = gcoms_transport::server::read_body(&mut response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, body)
    })
    .await
    .expect("retained request must finish within the client request bound")
}

async fn retained_refresh(sender: &h2::client::SendRequest<Bytes>, seed: &Introduction) {
    let (status, body) = retained_post(
        sender,
        seed,
        &gcoms_transport::encode_b64url(&seed.reentry_cap),
        Bytes::from(pex().encode()),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let cell = NaturalCell::decode(&body).unwrap();
    assert_eq!(cell.kind(), CellType::Pex);
    assert_eq!(cell.flags(), 0);
    let bundle = BootstrapBundle::decode(cell.payload()).unwrap();
    let own = bundle
        .relays
        .iter()
        .find(|relay| relay.service_id == seed.service_id)
        .unwrap();
    assert_eq!(own.reentry_cap, seed.reentry_cap);
    own.entry(now_unix()).unwrap();
}

struct Fixture {
    service: Arc<RelayService>,
    connections: Arc<AtomicUsize>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        Self::at("127.0.0.91:0").await
    }
    async fn at(address: &str) -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let registry = TokenRegistry::new();
        registry.insert_post("fixture-registered");
        let server = Tp1Server::bind_with_identity(
            address.parse().unwrap(),
            registry,
            Arc::new(|_, cell| Ok(Some(cell))),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap();
        let service = RelayService::new(
            server.local_addr().unwrap(),
            identity.service_id(),
            [71; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let observed = connections.clone();
        let factory = service.gc2_handler_factory();
        let server = server.with_dispatch_factory(Arc::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            factory()
        }));
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .run_until(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            service,
            connections,
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(()).unwrap();
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.service.active_circuits(), 0);
    }
}

#[tokio::test]
async fn service_renews_only_authorized_referrals_despite_stalled_peers() {
    let publisher = Fixture::new().await;
    let peer = Fixture::at("127.0.0.92:0").await;
    let undisclosed = Fixture::at("127.0.0.93:0").await;
    let now = now_unix();
    peer.service
        .gc2_directory()
        .remember(
            &BootstrapBundle {
                relays: vec![undisclosed.service.gc2_introduction(now)],
            },
            now,
        )
        .unwrap();
    let old = peer.service.gc2_introduction(now - 7200);
    assert!(old.entry(now).is_err());
    let mut seeds = Vec::new();
    let mut stalled = Vec::new();
    for n in [94u8, 95] {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.{n}:0"))
            .await
            .unwrap();
        let mut seed = old.clone();
        seed.addr = listener.local_addr().unwrap();
        seed.service_id = [n; 32];
        seeds.push(seed);
        stalled.push(listener);
    }
    seeds.push(old.clone());
    publisher
        .service
        .gc2_directory()
        .remember(&BootstrapBundle { relays: seeds }, now)
        .unwrap();
    let before = publisher.service.gc2_introduction(now);
    let client = Tp1Client::new().unwrap();
    let initial = discovery::refresh(&client, &before, &[]).await.unwrap();
    assert_eq!(
        initial.relays.len(),
        1,
        "expired referrals cannot be advertised"
    );
    let service = publisher.service.clone();
    let task = tokio::spawn(async move { service.run_gc2_referral_refresh().await });
    timeout(Duration::from_secs(5), async {
        loop {
            let reply = discovery::refresh(&client, &before, &[]).await.unwrap();
            if let Some(fresh) = reply.relays.iter().find(|r| r.service_id == old.service_id) {
                assert_eq!(fresh.reentry_cap, old.reentry_cap);
                assert_ne!(fresh.entry_cap, old.entry_cap);
                fresh.entry(now_unix()).unwrap();
                assert_eq!(
                    reply.relays.len(),
                    2,
                    "peer referrals must not expand disclosure"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        publisher.service.gc2_directory().reentry_candidates().len(),
        3
    );
    assert!(
        old.entry(now_unix()).is_err(),
        "renewal cannot extend old authority"
    );
    drop(stalled);
    drop(client);
    publisher.stop().await;
    peer.stop().await;
    undisclosed.stop().await;
}

#[tokio::test]
async fn private_or_unpublished_service_cannot_dial_public_referrals() {
    use std::sync::atomic::AtomicBool;
    let peer = Fixture::at("127.0.0.92:0").await;
    let peer_ip = peer.service.address().ip();
    for own_address_allowed in [false, true] {
        let ready = Arc::new(AtomicBool::new(false));
        let service = RelayService::new(
            "127.0.0.91:443".parse().unwrap(),
            [88; 32],
            [89; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                target_allowed: Arc::new(move |addr| {
                    addr.ip() == peer_ip || (own_address_allowed && addr.ip().is_loopback())
                }),
                transit_ready: own_address_allowed.then(|| ready.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        service
            .gc2_directory()
            .remember(
                &BootstrapBundle {
                    relays: vec![peer.service.gc2_introduction(now_unix() - 7200)],
                },
                now_unix(),
            )
            .unwrap();
        let running = service.clone();
        let task = tokio::spawn(async move { running.run_gc2_referral_refresh().await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            peer.connections.load(Ordering::SeqCst),
            0,
            "a private endpoint or unproved relay cannot dial referrals"
        );
        if own_address_allowed {
            ready.store(true, Ordering::Release);
            timeout(Duration::from_secs(3), async {
                while service
                    .gc2_directory()
                    .eligible(&[], now_unix())
                    .unwrap()
                    .is_empty()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(peer.connections.load(Ordering::SeqCst), 1);
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    peer.stop().await;
}

async fn request(
    client: &Tp1Client,
    seed: &Introduction,
    cap: &[u8; 32],
    cell: NaturalCell,
) -> gcoms_routing::Result<NaturalOutcome> {
    let token = gcoms_transport::encode_b64url(cap);
    client
        .post_natural_prepared(
            NaturalRoute {
                addr: seed.addr,
                service_id: seed.service_id,
                token: &token,
                excluded: &[],
                class: TrafficClass::Interactive,
            },
            || Ok(cell),
        )
        .await
}
fn pex() -> NaturalCell {
    NaturalCell::new(CellType::Pex, 0, b"GCD2".to_vec()).unwrap()
}

#[tokio::test]
async fn expired_private_seed_renews_bounded_referrals_on_one_pinned_connection() {
    let fixture = Fixture::new().await;
    let now = now_unix();
    let seed = fixture.service.gc2_introduction(now - 7200);
    assert!(seed.entry(now).is_err());
    for index in 1..=12 {
        let referral = Introduction {
            addr: format!("127.0.1.{index}:443").parse().unwrap(),
            service_id: [index; 32],
            reentry_cap: [101; 32],
            entry_cap: [102; 32],
            transit_cap: [103; 32],
            expires_at: now + 1000,
        };
        fixture
            .service
            .gc2_directory()
            .remember(
                &BootstrapBundle {
                    relays: vec![referral],
                },
                now,
            )
            .unwrap();
    }
    let client = Tp1Client::new().unwrap();
    let directory = Gc2Directory::for_loopback_fixture();
    directory
        .remember(
            &BootstrapBundle {
                relays: vec![seed.clone()],
            },
            now,
        )
        .unwrap();
    assert!(directory.eligible(&[], now).unwrap().is_empty());
    for _ in 0..3 {
        let bundle = timeout(
            Duration::from_secs(3),
            discovery::refresh(&client, &seed, &[]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(bundle.relays.len(), 8);
        let own = &bundle.relays[0];
        assert_eq!(own.service_id, seed.service_id);
        assert_eq!(own.reentry_cap, seed.reentry_cap);
        assert_ne!(own.entry_cap, seed.entry_cap);
        assert_ne!(own.transit_cap, seed.transit_cap);
        own.entry(now_unix()).unwrap();
        directory.remember(&bundle, now_unix()).unwrap();
    }
    assert!(!directory.eligible(&[], now_unix()).unwrap().is_empty());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert_eq!(client.pooled_connections().await, 1);
    fixture.stop().await;
}

#[tokio::test]
async fn roles_cannot_mix_and_gc1_authority_cannot_authenticate_v2_discovery() {
    let fixture = Fixture::new().await;
    let seed = fixture.service.gc2_introduction(now_unix());
    let old = fixture.service.introduction(now_unix());
    let factory = fixture.service.gc2_handler_factory();
    let roles = [seed.entry_cap, seed.transit_cap, seed.reentry_cap];
    for (index, first) in roles.iter().enumerate() {
        let handler = factory();
        // Invalid authority never commits the physical connection's role.
        for cap in [old.reentry_cap, old.circuit_cap, [0; 32]] {
            assert!(matches!(
                handler(&gcoms_transport::encode_b64url(&cap), false),
                gcoms_transport::server::Dispatch::Rejected
            ));
        }
        assert!(matches!(
            handler(&gcoms_transport::encode_b64url(first), false),
            gcoms_transport::server::Dispatch::Accepted(_)
        ));
        for (next, cap) in roles.iter().enumerate() {
            assert_eq!(
                matches!(
                    handler(&gcoms_transport::encode_b64url(cap), false),
                    gcoms_transport::server::Dispatch::Accepted(_)
                ),
                index == next && index != 1
            );
        }
        assert!(matches!(
            handler("fixture-registered", true),
            gcoms_transport::server::Dispatch::Rejected
        ));
    }
    let terminal = factory();
    assert!(matches!(
        terminal("fixture-registered", true),
        gcoms_transport::server::Dispatch::Pass
    ));
    for cap in &roles {
        assert!(matches!(
            terminal(&gcoms_transport::encode_b64url(cap), false),
            gcoms_transport::server::Dispatch::Rejected
        ));
    }
    let (client, driver) = retained_connection(&seed).await;
    retained_refresh(&client, &seed).await;
    for cap in [
        seed.entry_cap,
        seed.transit_cap,
        old.reentry_cap,
        old.circuit_cap,
    ] {
        assert_eq!(
            retained_post(
                &client,
                &seed,
                &gcoms_transport::encode_b64url(&cap),
                Bytes::from(pex().encode()),
            )
            .await
            .0,
            http::StatusCode::NOT_FOUND
        );
    }
    retained_refresh(&client, &seed).await;
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    drop(client);
    fixture.stop().await;
    timeout(Duration::from_secs(3), driver)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn registered_endpoint_cannot_bypass_control_role_or_then_switch_to_control() {
    use gcoms_core::Cell;
    let fixture = Fixture::new().await;
    let seed = fixture.service.gc2_introduction(now_unix());
    let bytes = bytes::Bytes::from(
        Cell::new(CellType::Msg, 0, 0, vec![7; 128])
            .encode_wire()
            .unwrap(),
    );
    let (control, control_driver) = retained_connection(&seed).await;
    retained_refresh(&control, &seed).await;
    assert_eq!(
        retained_post(&control, &seed, "fixture-registered", bytes.clone())
            .await
            .0,
        http::StatusCode::NOT_FOUND
    );
    retained_refresh(&control, &seed).await;
    let (terminal, terminal_driver) = retained_connection(&seed).await;
    let (status, body) = retained_post(&terminal, &seed, "fixture-registered", bytes.clone()).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, bytes);
    assert_eq!(
        retained_post(
            &terminal,
            &seed,
            &gcoms_transport::encode_b64url(&seed.reentry_cap),
            Bytes::from(pex().encode()),
        )
        .await
        .0,
        http::StatusCode::NOT_FOUND
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    drop(control);
    drop(terminal);
    fixture.stop().await;
    for driver in [control_driver, terminal_driver] {
        timeout(Duration::from_secs(3), driver)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn malformed_private_requests_and_wrong_pin_fail_without_fallback() {
    let fixture = Fixture::new().await;
    let seed = fixture.service.gc2_introduction(now_unix());
    let client = Tp1Client::new().unwrap();
    for cell in [
        NaturalCell::new(CellType::Pex, 0, b"GCD1".to_vec()).unwrap(),
        NaturalCell::new(CellType::Msg, 0, b"GCD2".to_vec()).unwrap(),
        NaturalCell::new(CellType::Pex, 0, vec![0; 100]).unwrap(),
    ] {
        assert!(timeout(
            Duration::from_secs(3),
            request(&client, &seed, &seed.reentry_cap, cell)
        )
        .await
        .unwrap()
        .is_err());
    }
    let mut reserved = pex().encode();
    reserved[1] = 1;
    let token = gcoms_transport::encode_b64url(&seed.reentry_cap);
    assert!(timeout(
        Duration::from_secs(3),
        client.post_cell_pinned(
            seed.addr,
            seed.service_id,
            &token,
            bytes::Bytes::from(reserved),
        )
    )
    .await
    .unwrap()
    .is_err());
    let mut wrong = seed.clone();
    wrong.service_id = [0xee; 32];
    assert!(timeout(
        Duration::from_secs(3),
        discovery::refresh(&client, &wrong, &[])
    )
    .await
    .unwrap()
    .is_err());
    // Failure has neither extended old authority nor damaged valid renewal.
    discovery::refresh(&client, &seed, &[]).await.unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn private_refresh_budget_is_bounded_and_does_not_consume_circuit_capacity() {
    let fixture = Fixture::new().await;
    let seed = fixture.service.gc2_introduction(now_unix());
    let client = Tp1Client::new().unwrap();
    for _ in 0..64 {
        discovery::refresh(&client, &seed, &[]).await.unwrap();
    }
    assert_eq!(
        request(&client, &seed, &seed.reentry_cap, pex())
            .await
            .unwrap(),
        NaturalOutcome::Overloaded
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.active_circuits(), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn authenticated_reply_cannot_silently_replace_stable_authority_or_revive_expiry() {
    use bytes::Bytes;
    use gcoms_transport::server::AcceptedDuplex;
    let identity = TlsIdentity::generate().unwrap();
    let reply = Arc::new(std::sync::Mutex::new(None::<NaturalCell>));
    let outgoing = reply.clone();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.92:0".parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap()
    .with_duplex(Arc::new(move |_| {
        let cell = outgoing.lock().unwrap().as_ref().unwrap().clone();
        let accepted: AcceptedDuplex = Box::new(move |mut body, mut respond| {
            Box::pin(async move {
                gcoms_transport::server::read_body(&mut body, 10)
                    .await
                    .unwrap();
                let mut send = respond
                    .send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    )
                    .unwrap();
                send.send_data(Bytes::from(cell.encode()), true).unwrap();
            })
        });
        Some(accepted)
    }));
    let seed = Introduction {
        addr: server.local_addr().unwrap(),
        service_id: identity.service_id(),
        reentry_cap: [20; 32],
        entry_cap: [21; 32],
        transit_cap: [22; 32],
        expires_at: now_unix() + 1000,
    };
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let client = Tp1Client::new().unwrap();
    for change in 0..4 {
        let mut own = seed.clone();
        match change {
            0 => own.reentry_cap = [23; 32],
            1 => own.expires_at = now_unix(),
            2 => own.service_id = [24; 32],
            _ => own.expires_at = now_unix() + 86401,
        }
        let bytes = BootstrapBundle { relays: vec![own] }.encode().unwrap();
        *reply.lock().unwrap() = Some(NaturalCell::new(CellType::Pex, 0, bytes.to_vec()).unwrap());
        assert!(discovery::refresh(&client, &seed, &[]).await.is_err());
    }
    stop.send(()).unwrap();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
