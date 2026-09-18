#![cfg(feature = "experimental-gc2")]
use bytes::Bytes;
use gcoms_core::{Cell, CellType, TrafficClass};
use gcoms_routing::{
    gc2::{
        connector::PreparedConnector,
        entry::{self, EntryCarrier, EntryDescriptor},
        transit::TransitDescriptor,
        CandidateProfile, RecordCodec, RecordKind,
    },
    route::now_unix,
    wire::Target,
    Directory, RelayService, ServicePolicy,
};
use gcoms_transport::{
    connector::{BoxStream, ConnectFuture, Connector},
    duplex::H2Stream,
    server::Tp1Server,
    tls::{self, TlsIdentity},
    TokenRegistry, Tp1Client,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsConnector;

struct Fixture {
    service: Arc<RelayService>,
    terminal_addr: SocketAddr,
    terminal_pin: [u8; 32],
    connections: Arc<AtomicUsize>,
    stop: Vec<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
    carriers: Vec<tokio::task::AbortHandle>,
}

impl Fixture {
    async fn new() -> Self {
        let entry_identity = TlsIdentity::generate().unwrap();
        let local_registry = TokenRegistry::new();
        local_registry.insert_post("fixture-local");
        let entry_server = Tp1Server::bind_with_identity(
            "127.0.0.81:0".parse().unwrap(),
            local_registry,
            Arc::new(|_, cell| Ok(Some(cell))),
            Arc::new(|_| None),
            &entry_identity,
        )
        .await
        .unwrap();
        let service = RelayService::new(
            entry_server.local_addr().unwrap(),
            entry_identity.service_id(),
            [7; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        let factory = service.gc2_handler_factory();
        let connections = Arc::new(AtomicUsize::new(0));
        let observed = connections.clone();
        let entry_server = entry_server.with_dispatch_factory(Arc::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            factory()
        }));
        let terminal_identity = TlsIdentity::generate().unwrap();
        let registry = TokenRegistry::new();
        registry.insert_post("fixture-echo");
        let terminal = Tp1Server::bind_with_identity(
            "127.0.0.82:0".parse().unwrap(),
            registry,
            Arc::new(|_, cell| Ok(Some(cell))),
            Arc::new(|_| None),
            &terminal_identity,
        )
        .await
        .unwrap();
        let terminal_addr = terminal.local_addr().unwrap();
        let mut tasks = JoinSet::new();
        let mut stop = Vec::new();
        for server in [entry_server, terminal] {
            let (tx, rx) = oneshot::channel();
            stop.push(tx);
            tasks.spawn(async move {
                server
                    .run_until(async {
                        let _ = rx.await;
                    })
                    .await
                    .unwrap();
            });
        }
        Self {
            service,
            terminal_addr,
            terminal_pin: terminal_identity.service_id(),
            connections,
            stop,
            tasks,
            carriers: Vec::new(),
        }
    }

    async fn carrier(&mut self) -> EntryCarrier {
        let descriptor = self.service.gc2_entry_descriptor(now_unix());
        let socket = tokio::net::TcpStream::connect(descriptor.addr)
            .await
            .unwrap();
        socket.set_nodelay(true).unwrap();
        let (tx, rx) = oneshot::channel();
        let handle = self.tasks.spawn(async move {
            let _ = entry::run(
                Box::new(socket),
                descriptor,
                CandidateProfile::new(4096, 250).unwrap(),
                tx,
            )
            .await;
        });
        self.carriers.push(handle);
        timeout(Duration::from_secs(5), rx).await.unwrap().unwrap()
    }

    fn target(&self) -> Target {
        Target::Relay {
            addr: self.terminal_addr,
            service_id: self.terminal_pin,
        }
    }

    async fn middle(&mut self) -> Arc<RelayService> {
        let identity = TlsIdentity::generate().unwrap();
        let server = Tp1Server::bind_with_identity(
            "127.0.0.84:0".parse().unwrap(),
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
                target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        let server = server.with_dispatch_factory(service.gc2_handler_factory());
        let (tx, rx) = oneshot::channel();
        self.stop.push(tx);
        self.tasks.spawn(async move {
            server
                .run_until(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        service
    }

    async fn stop(mut self) {
        for stop in self.stop.drain(..) {
            stop.send(()).unwrap();
        }
        timeout(Duration::from_secs(3), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .unwrap();
        assert_eq!(self.service.active_circuits(), 0);
    }
}

struct FullConnector(EntryCarrier, TrafficClass, TransitDescriptor);
impl Connector for FullConnector {
    fn connect(&self, addr: SocketAddr, service_id: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async move {
            self.0
                .connect_via(self.1, &self.2, &Target::Relay { addr, service_id }, &[])
                .await
        })
    }

    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        Box::pin(async move {
            self.0
                .connect_via(
                    self.1,
                    &self.2,
                    &Target::Relay { addr, service_id },
                    excluded,
                )
                .await
        })
    }
}

#[tokio::test]
async fn complete_gc2_circuits_authenticate_all_three_hops_on_one_entry() {
    let mut fixture = Fixture::new().await;
    let middle = fixture.middle().await;
    let carrier = fixture.carrier().await;
    let descriptor = middle.gc2_transit_descriptor(now_unix());
    let mut clients = Vec::new();
    for class in [TrafficClass::Bulk, TrafficClass::Interactive] {
        let client = Tp1Client::with_connector(Arc::new(FullConnector(
            carrier.clone(),
            class,
            descriptor.clone(),
        )))
        .unwrap();
        let cell = Cell::new(CellType::Msg, 0, 0, vec![21; 12000]);
        let outcome = timeout(
            Duration::from_secs(15),
            client.post_cell_pinned(
                fixture.terminal_addr,
                fixture.terminal_pin,
                "fixture-echo",
                Bytes::from(cell.encode_wire().unwrap()),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let gcoms_transport::HopOutcome::Accepted(Some(echo)) = outcome else {
            panic!("expected three-hop echo");
        };
        assert_eq!(echo.payload, cell.payload);
        clients.push(client);
    }
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert_eq!(carrier.active_circuits(), 2);
    assert_eq!(middle.active_circuits(), 2);
    assert!(clients[0]
        .get_pinned(fixture.terminal_addr, [0xc7; 32], "/")
        .await
        .is_err());
    // Cancel just the root carrier while both relay listeners remain running.
    fixture.carriers[0].abort();
    timeout(Duration::from_secs(3), async {
        while fixture.service.active_circuits() != 0
            || middle.active_circuits() != 0
            || carrier.active_circuits() != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn one_terminal_client_reuses_separate_class_circuits_on_one_entry() {
    let mut fixture = Fixture::new().await;
    let middle = fixture.middle().await;
    let carrier = fixture.carrier().await;
    let descriptor = middle.gc2_transit_descriptor(now_unix());
    let client = Tp1Client::with_connector(Arc::new(PreparedConnector::new(
        carrier.clone(),
        descriptor.clone(),
    )))
    .unwrap();
    for class in [
        TrafficClass::Bulk,
        TrafficClass::Interactive,
        TrafficClass::Bulk,
        TrafficClass::Interactive,
    ] {
        let cell = Cell::new(CellType::Msg, 0, 0, vec![class as u8; 128]);
        let outcome = timeout(
            Duration::from_secs(15),
            client.post_cell_with_class(
                fixture.terminal_addr,
                fixture.terminal_pin,
                "fixture-echo",
                Bytes::from(cell.encode_wire().unwrap()),
                &[],
                class,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let gcoms_transport::HopOutcome::Accepted(Some(echo)) = outcome else {
            panic!("class-routed echo required");
        };
        assert_eq!(echo.payload, cell.payload);
    }
    assert_eq!(client.pooled_connections().await, 2);
    assert_eq!(carrier.active_circuits(), 2);
    assert_eq!(middle.active_circuits(), 2);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    let forbidden = [(descriptor.addr, descriptor.service_id)];
    assert!(client
        .warm_excluding_with_class(
            fixture.terminal_addr,
            fixture.terminal_pin,
            &forbidden,
            TrafficClass::Bulk
        )
        .await
        .is_err());
    assert_eq!(
        carrier.active_circuits(),
        2,
        "existing unconstrained pools cannot bypass exclusions"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn middle_pin_capability_and_complete_route_exclusions_fail_closed() {
    let mut fixture = Fixture::new().await;
    let middle = fixture.middle().await;
    let carrier = fixture.carrier().await;
    let descriptor = middle.gc2_transit_descriptor(now_unix());
    let mut wrong_pin = descriptor.clone();
    wrong_pin.service_id = [0x44; 32];
    let mut wrong_role = descriptor.clone();
    wrong_role.transit_cap = middle.gc2_entry_descriptor(now_unix()).entry_cap;
    let mut old_cap = descriptor.clone();
    old_cap.transit_cap = middle.introduction(now_unix()).circuit_cap;
    for invalid in [wrong_pin, wrong_role, old_cap] {
        assert!(timeout(
            Duration::from_secs(3),
            carrier.connect_via(TrafficClass::Bulk, &invalid, &fixture.target(), &[])
        )
        .await
        .unwrap()
        .is_err());
    }
    for excluded in [
        (descriptor.addr, [1; 32]),
        ("127.0.0.98:443".parse().unwrap(), descriptor.service_id),
        (fixture.service.address(), [2; 32]),
        (
            "127.0.0.99:443".parse().unwrap(),
            fixture.service.gc2_entry_descriptor(now_unix()).service_id,
        ),
    ] {
        assert!(carrier
            .connect_via(
                TrafficClass::Interactive,
                &descriptor,
                &fixture.target(),
                &[excluded]
            )
            .await
            .is_err());
    }
    for target in [
        Target::Relay {
            addr: descriptor.addr,
            service_id: [3; 32],
        },
        Target::Relay {
            addr: fixture.terminal_addr,
            service_id: descriptor.service_id,
        },
    ] {
        assert!(carrier
            .connect_via(TrafficClass::Bulk, &descriptor, &target, &[])
            .await
            .is_err());
    }
    timeout(Duration::from_secs(3), async {
        while fixture.service.active_circuits() != 0 || middle.active_circuits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    fixture.stop().await;
}

struct EntryConnector(EntryCarrier, TrafficClass);
impl Connector for EntryConnector {
    fn connect(&self, addr: SocketAddr, service_id: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async move {
            Ok(Box::new(
                self.0
                    .open(self.1, &Target::Relay { addr, service_id })
                    .await?,
            ) as BoxStream)
        })
    }
}

#[tokio::test]
async fn one_pinned_entry_carries_both_classes_and_preserves_terminal_authentication() {
    let mut fixture = Fixture::new().await;
    let carrier = fixture.carrier().await;
    let bulk = Tp1Client::with_connector(Arc::new(EntryConnector(
        carrier.clone(),
        TrafficClass::Bulk,
    )))
    .unwrap();
    let interactive = Tp1Client::with_connector(Arc::new(EntryConnector(
        carrier.clone(),
        TrafficClass::Interactive,
    )))
    .unwrap();
    let payload = Cell::new(CellType::Msg, 0, 0, vec![17; 12000]);
    for client in [&bulk, &interactive] {
        let response = timeout(
            Duration::from_secs(15),
            client.post_cell_pinned(
                fixture.terminal_addr,
                fixture.terminal_pin,
                "fixture-echo",
                Bytes::from(payload.encode_wire().unwrap()),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let gcoms_transport::HopOutcome::Accepted(Some(response)) = response else {
            panic!("expected echoed cell");
        };
        assert_eq!(response.payload, payload.payload);
    }
    assert!(bulk
        .get_pinned(fixture.terminal_addr, [0xaa; 32], "/")
        .await
        .is_err());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert!(carrier
        .open(
            TrafficClass::Interactive,
            &Target::Relay {
                addr: fixture.service.address(),
                service_id: fixture.terminal_pin,
            }
        )
        .await
        .is_err());
    fixture.stop().await;
    assert!(carrier
        .open(
            TrafficClass::Bulk,
            &Target::Relay {
                addr: "127.0.0.82:443".parse().unwrap(),
                service_id: [9; 32],
            }
        )
        .await
        .is_err());
}

#[tokio::test]
async fn shared_physical_connection_enforces_limits_and_shutdown_releases_targets() {
    let mut fixture = Fixture::new().await;
    let carrier = fixture.carrier().await;
    let mut held = Vec::new();
    for _ in 0..15 {
        held.push(
            carrier
                .open(TrafficClass::Bulk, &fixture.target())
                .await
                .unwrap(),
        );
    }
    assert!(carrier
        .open(TrafficClass::Bulk, &fixture.target())
        .await
        .is_err());
    held.push(
        carrier
            .open(TrafficClass::Interactive, &fixture.target())
            .await
            .unwrap(),
    );
    assert_eq!(carrier.active_circuits(), 16);
    assert_eq!(fixture.service.active_circuits(), 16);
    assert!(carrier
        .open(TrafficClass::Interactive, &fixture.target())
        .await
        .is_err());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    drop(held.remove(0));
    timeout(Duration::from_secs(2), async {
        while fixture.service.active_circuits() != 15 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    held.push(
        carrier
            .open(TrafficClass::Bulk, &fixture.target())
            .await
            .unwrap(),
    );
    fixture.stop().await;
    drop(held);
    assert_eq!(carrier.active_circuits(), 0);
}

#[tokio::test]
async fn blocked_bulk_on_the_same_physical_connection_preserves_interactive_progress() {
    let mut fixture = Fixture::new().await;
    let carrier = fixture.carrier().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.83:0").await.unwrap();
    let mut bulk = carrier
        .open(
            TrafficClass::Bulk,
            &Target::Relay {
                addr: listener.local_addr().unwrap(),
                service_id: [0xb3; 32],
            },
        )
        .await
        .unwrap();
    let (_stopped_reader, _) = listener.accept().await.unwrap();
    // A deliberately non-reading byte sink exhausts the actual TCP and HTTP2
    // windows. Fixed scratch storage avoids turning the test into a queue.
    let chunk = vec![3; 64 * 1024];
    assert!(timeout(Duration::from_millis(100), async {
        for _ in 0..2048 {
            bulk.write_all(&chunk).await.unwrap();
        }
    })
    .await
    .is_err());
    let interactive =
        Tp1Client::with_connector(Arc::new(EntryConnector(carrier, TrafficClass::Interactive)))
            .unwrap();
    let cell = Cell::new(CellType::Msg, 0, 0, vec![5; 128]);
    let response = timeout(
        Duration::from_secs(8),
        interactive.post_cell_pinned(
            fixture.terminal_addr,
            fixture.terminal_pin,
            "fixture-echo",
            Bytes::from(cell.encode_wire().unwrap()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let gcoms_transport::HopOutcome::Accepted(Some(echo)) = response else {
        panic!("expected interactive reply");
    };
    assert_eq!(echo.payload, cell.payload);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn wrong_entry_pin_and_gc1_capability_fail_without_version_fallback() {
    let fixture = Fixture::new().await;
    let correct = fixture.service.gc2_entry_descriptor(now_unix());
    let mut bad_pin = correct.clone();
    bad_pin.service_id = [0xee; 32];
    let mut old_cap = correct.clone();
    old_cap.entry_cap = fixture.service.introduction(now_unix()).circuit_cap;
    for descriptor in [bad_pin, old_cap] {
        let socket = tokio::net::TcpStream::connect(descriptor.addr)
            .await
            .unwrap();
        let (tx, rx) = oneshot::channel();
        assert!(timeout(
            Duration::from_secs(3),
            entry::run(
                Box::new(socket),
                descriptor,
                CandidateProfile::new(4096, 250).unwrap(),
                tx
            )
        )
        .await
        .unwrap()
        .is_err());
        assert!(rx.await.is_err());
    }
    assert_eq!(fixture.service.active_circuits(), 0);
    fixture.stop().await;
}

async fn raw_open(
    sender: &mut h2::client::SendRequest<Bytes>,
    descriptor: &EntryDescriptor,
    codec: RecordCodec,
) -> Result<H2Stream, Box<dyn std::error::Error + Send + Sync>> {
    std::future::poll_fn(|cx| sender.poll_ready(cx)).await?;
    let (reply, send) = sender.send_request(
        http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/{}",
                descriptor.addr,
                gcoms_transport::encode_b64url(&descriptor.entry_cap)
            ))
            .body(())?,
        false,
    )?;
    let reply = reply.await?;
    let mut wire = H2Stream::new(reply.into_body(), send);
    let opened = codec.encode(RecordKind::Open, &[])?;
    wire.write_all(&opened).await?;
    let mut ack = vec![0; opened.len()];
    wire.read_exact(&mut ack).await?;
    assert_eq!(opened, ack);
    Ok(wire)
}

#[tokio::test]
async fn profile_and_class_binding_are_immutable_on_one_connection() {
    let mut fixture = Fixture::new().await;
    let descriptor = fixture.service.gc2_entry_descriptor(now_unix());
    let socket = tokio::net::TcpStream::connect(descriptor.addr)
        .await
        .unwrap();
    let tls = TlsConnector::from(Arc::new(
        tls::client_config_pinned(descriptor.service_id).unwrap(),
    ))
    .connect(tls::server_name_ip(descriptor.addr.ip()), socket)
    .await
    .unwrap();
    let (mut sender, driver) = h2::client::handshake(tls).await.unwrap();
    fixture.tasks.spawn(async move {
        let _ = driver.await;
    });
    let profile = CandidateProfile::new(4096, 250).unwrap();
    let interactive = RecordCodec::new(TrafficClass::Interactive, profile);
    let held = raw_open(&mut sender, &descriptor, interactive)
        .await
        .unwrap();
    for bad in [
        interactive,
        RecordCodec::new(
            TrafficClass::Bulk,
            CandidateProfile::new(1024, 1500).unwrap(),
        ),
    ] {
        assert!(timeout(
            Duration::from_secs(2),
            raw_open(&mut sender, &descriptor, bad)
        )
        .await
        .unwrap()
        .is_err());
    }
    let bulk = raw_open(
        &mut sender,
        &descriptor,
        RecordCodec::new(TrafficClass::Bulk, profile),
    )
    .await
    .unwrap();
    let transit = fixture.service.gc2_transit_descriptor(now_unix());
    let (reply, mut denied) = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/{}",
                    transit.addr,
                    gcoms_transport::encode_b64url(&transit.transit_cap)
                ))
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    assert_eq!(
        reply.await.unwrap().status(),
        404,
        "an entry connection cannot add an unshaped transit path"
    );
    denied.send_reset(h2::Reason::CANCEL);
    // Even a valid registered application endpoint is denied before it can
    // echo unshaped payload outside the two established carrier channels.
    let (response, mut body) = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri(format!("https://{}/fixture-local", descriptor.addr))
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    body.send_data(
        Bytes::from(
            Cell::new(CellType::Msg, 0, 0, vec![7; 128])
                .encode_wire()
                .unwrap(),
        ),
        true,
    )
    .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        404
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    drop((held, bulk, sender));
    fixture.stop().await;
}

#[tokio::test]
async fn malformed_middle_open_is_rejected_before_any_target_dial() {
    let mut fixture = Fixture::new().await;
    let middle = fixture.middle().await;
    let descriptor = middle.gc2_transit_descriptor(now_unix());
    let observed = tokio::net::TcpListener::bind("127.0.0.85:0").await.unwrap();
    let target = Target::Relay {
        addr: observed.local_addr().unwrap(),
        service_id: [4; 32],
    }
    .encode();
    let mut valid = b"GCX2".to_vec();
    valid.push(TrafficClass::Bulk as u8);
    valid.extend_from_slice(&(target.len() as u16).to_be_bytes());
    valid.extend_from_slice(&target);
    let mut cases = vec![valid[..3].to_vec(), valid[..valid.len() - 1].to_vec()];
    for (index, value) in [(3, b'1'), (4, 9), (5, 255), (7, 255)] {
        let mut malformed = valid.clone();
        malformed[index] = value;
        cases.push(malformed);
    }
    for malformed in cases {
        let socket = tokio::net::TcpStream::connect(descriptor.addr)
            .await
            .unwrap();
        let tls = TlsConnector::from(Arc::new(
            tls::client_config_pinned(descriptor.service_id).unwrap(),
        ))
        .connect(tls::server_name_ip(descriptor.addr.ip()), socket)
        .await
        .unwrap();
        let (mut sender, driver) = h2::client::handshake(tls).await.unwrap();
        fixture.tasks.spawn(async move {
            let _ = driver.await;
        });
        let (reply, send) = sender
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri(format!(
                        "https://{}/{}",
                        descriptor.addr,
                        gcoms_transport::encode_b64url(&descriptor.transit_cap)
                    ))
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let reply = reply.await.unwrap();
        assert_eq!(reply.status(), 200);
        let mut wire = H2Stream::new(reply.into_body(), send);
        wire.write_all(&malformed).await.unwrap();
        wire.shutdown().await.unwrap();
        let mut ack = [0; 6];
        assert!(timeout(Duration::from_secs(2), wire.read_exact(&mut ack))
            .await
            .unwrap()
            .is_err());
    }
    assert!(timeout(Duration::from_millis(30), observed.accept())
        .await
        .is_err());
    assert_eq!(middle.active_circuits(), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn background_owner_preconnects_without_messages_and_never_dials_from_send() {
    use gcoms_routing::gc2::{
        directory::{BootstrapBundle, Directory as Gc2Directory},
        owner::EntryOwner,
    };
    let mut fixture = Fixture::new().await;
    let middle = fixture.middle().await;
    let directory = Arc::new(Gc2Directory::for_loopback_fixture());
    let first = fixture.service.gc2_introduction(now_unix() - 7200);
    let second = middle.gc2_introduction(now_unix() - 7200);
    directory
        .remember(
            &BootstrapBundle {
                relays: vec![first.clone(), second.clone()],
            },
            now_unix(),
        )
        .unwrap();
    directory
        .set_guards(vec![first.service_id, second.service_id])
        .unwrap();
    assert!(directory.eligible(&[], now_unix()).unwrap().is_empty());
    let (owner, ready) = EntryOwner::new(
        directory.clone(),
        CandidateProfile::new(4096, 250).unwrap(),
        1,
    )
    .unwrap();
    let owner = fixture.tasks.spawn(async move {
        let _ = owner.run().await;
    });
    timeout(Duration::from_secs(8), async {
        while ready.ready_entries() != 1 || directory.eligible(&[], now_unix()).unwrap().len() != 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // One protected entry and one periodic private control connection to this
    // guard exist before any application request. Neither depends on messages.
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    let client = Tp1Client::with_connector(ready.clone()).unwrap();
    for class in [TrafficClass::Bulk, TrafficClass::Interactive] {
        let cell = Cell::new(CellType::Msg, 0, 0, vec![5; 128]);
        let response = timeout(
            Duration::from_secs(15),
            client.post_cell_with_class(
                fixture.terminal_addr,
                fixture.terminal_pin,
                "fixture-echo",
                Bytes::from(cell.encode_wire().unwrap()),
                &[],
                class,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let gcoms_transport::HopOutcome::Accepted(Some(echo)) = response else {
            panic!("expected terminal reply");
        };
        assert_eq!(echo.payload, cell.payload);
        assert_eq!(ready.ready_entries(), 1);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    }
    assert!(ready
        .connect_excluding(
            fixture.terminal_addr,
            fixture.terminal_pin,
            &[(first.addr, first.service_id)]
        )
        .await
        .is_err());
    assert!(ready
        .connect_excluding(
            fixture.terminal_addr,
            fixture.terminal_pin,
            &[(second.addr, second.service_id)]
        )
        .await
        .is_err());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    owner.abort();
    timeout(Duration::from_secs(3), async {
        while ready.ready_entries() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(ready
        .connect(fixture.terminal_addr, fixture.terminal_pin)
        .await
        .is_err());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    fixture.stop().await;
}
