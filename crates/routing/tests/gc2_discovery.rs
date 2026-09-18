#![cfg(feature = "experimental-gc2")]
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
    tls::TlsIdentity,
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

struct Fixture {
    service: Arc<RelayService>,
    connections: Arc<AtomicUsize>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let registry = TokenRegistry::new();
        registry.insert_post("fixture-registered");
        let server = Tp1Server::bind_with_identity(
            "127.0.0.91:0".parse().unwrap(),
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
    let client = Tp1Client::new().unwrap();
    discovery::refresh(&client, &seed, &[]).await.unwrap();
    for cap in [
        seed.entry_cap,
        seed.transit_cap,
        old.reentry_cap,
        old.circuit_cap,
    ] {
        assert_eq!(
            request(&client, &seed, &cap, pex()).await.unwrap(),
            NaturalOutcome::Decoy(404)
        );
    }
    discovery::refresh(&client, &seed, &[]).await.unwrap();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn registered_endpoint_cannot_bypass_control_role_or_then_switch_to_control() {
    use gcoms_core::Cell;
    use gcoms_transport::HopOutcome;
    let fixture = Fixture::new().await;
    let seed = fixture.service.gc2_introduction(now_unix());
    let bytes = bytes::Bytes::from(
        Cell::new(CellType::Msg, 0, 0, vec![7; 128])
            .encode_wire()
            .unwrap(),
    );
    let control = Tp1Client::new().unwrap();
    discovery::refresh(&control, &seed, &[]).await.unwrap();
    assert_eq!(
        control
            .post_cell_pinned(
                seed.addr,
                seed.service_id,
                "fixture-registered",
                bytes.clone()
            )
            .await
            .unwrap(),
        HopOutcome::Decoy(404)
    );
    discovery::refresh(&control, &seed, &[]).await.unwrap();
    let terminal = Tp1Client::new().unwrap();
    assert!(matches!(
        terminal
            .post_cell_pinned(seed.addr, seed.service_id, "fixture-registered", bytes)
            .await
            .unwrap(),
        HopOutcome::Accepted(Some(_))
    ));
    assert!(discovery::refresh(&terminal, &seed, &[]).await.is_err());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    fixture.stop().await;
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
