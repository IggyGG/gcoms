use bytes::Bytes;
use gcoms_core::{Cell, CellType};
use gcoms_routing::{
    carrier::CarrierConfig, route::now_unix, Directory, OnionConnector, Relay, RelayService,
    ServicePolicy,
};
use gcoms_transport::{
    connector::{BoxStream, ConnectFuture, Connector, DirectConnector},
    server::Tp1Server,
    tls::TlsIdentity,
    HopOutcome, TokenRegistry, Tp1Client,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Listener {
    addr: SocketAddr,
    pin: [u8; 32],
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn listener(ip: &str, stream: bool) -> (Tp1Server, TlsIdentity, TokenRegistry) {
    let identity = TlsIdentity::generate().unwrap();
    let registry = TokenRegistry::new();
    registry.insert_post("fixture-post-capability");
    registry.insert_stream("fixture-stream-capability");
    let server = Tp1Server::bind_with_identity(
        format!("{ip}:0").parse().unwrap(),
        registry.clone(),
        Arc::new(|_, cell| Ok(Some(cell))),
        Arc::new(move |_| {
            stream.then(|| {
                Box::new(|sink: gcoms_transport::server::StreamSink| {
                    tokio::spawn(async move {
                        for n in 0..3 {
                            if !sink
                                .send(Cell::new(CellType::Msg, 0, n, vec![n as u8; 12000]))
                                .await
                            {
                                break;
                            }
                        }
                    });
                }) as gcoms_transport::server::AcceptedStream
            })
        }),
        &identity,
    )
    .await
    .unwrap();
    (server, identity, registry)
}

fn run(server: Tp1Server) -> Listener {
    let addr = server.local_addr().unwrap();
    let pin = server.service_id();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        server
            .run_until(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    Listener {
        addr,
        pin,
        stop: Some(stop),
        task,
    }
}

struct Observe(Arc<Mutex<Vec<SocketAddr>>>);
impl Connector for Observe {
    fn connect(&self, addr: SocketAddr, pin: [u8; 32]) -> ConnectFuture<'_> {
        self.0.lock().unwrap().push(addr);
        Box::pin(async move { DirectConnector.connect(addr, pin).await })
    }
}

struct Network {
    relays: Vec<Listener>,
    services: Vec<Arc<RelayService>>,
    terminal: Listener,
    directory: Arc<Directory>,
    dials: Arc<Mutex<Vec<SocketAddr>>>,
    extensions: Arc<Mutex<Vec<(SocketAddr, SocketAddr)>>>,
}

impl Network {
    async fn new(relay_count: u8) -> Self {
        let directory = Arc::new(Directory::new());
        let extensions = Arc::new(Mutex::new(Vec::new()));
        let dials = Arc::new(Mutex::new(Vec::new()));
        let mut relays = Vec::new();
        let mut services = Vec::new();
        for n in 2..2 + relay_count {
            let (server, identity, _) = listener(&format!("127.0.0.{n}"), false).await;
            let addr = server.local_addr().unwrap();
            let observer = extensions.clone();
            let policy = ServicePolicy {
                carrier: CarrierConfig::fixture(),
                target_allowed: Arc::new(move |target| {
                    observer.lock().unwrap().push((addr, target));
                    target.ip().is_loopback()
                }),
                ..ServicePolicy::default()
            };
            let service = RelayService::new(
                addr,
                identity.service_id(),
                [n; 32],
                Arc::new(Directory::new()),
                policy,
            )
            .unwrap();
            directory
                .install(service.introduction(now_unix()), now_unix())
                .unwrap();
            relays.push(run(server.with_duplex(service.handler())));
            services.push(service);
        }
        let (server, _, _) = listener("127.0.0.99", true).await;
        Self {
            relays,
            services,
            terminal: run(server),
            directory,
            dials,
            extensions,
        }
    }

    fn connector(&self) -> OnionConnector {
        OnionConnector::new(self.directory.clone())
            .with_carrier_config(CarrierConfig::fixture())
            .unwrap()
            .with_entry_connector(Arc::new(Observe(self.dials.clone())))
    }

    fn client(&self) -> Tp1Client {
        Tp1Client::with_connector(Arc::new(self.connector())).unwrap()
    }

    async fn echo(
        &self,
        client: &Tp1Client,
        size: usize,
    ) -> gcoms_transport::client::Result<HopOutcome> {
        let cell = Cell::new(CellType::Msg, 0, 7, vec![0x52; size])
            .encode_wire()
            .unwrap();
        client
            .post_cell_pinned(
                self.terminal.addr,
                self.terminal.pin,
                "fixture-post-capability",
                Bytes::from(cell),
            )
            .await
    }
}

#[tokio::test]
async fn nested_pins_cells_subscription_and_adjacent_targets() {
    let net = Network::new(2).await;
    let client = net.client();
    for size in [1, 3000, 12000, 15104] {
        let response = tokio::time::timeout(Duration::from_secs(10), net.echo(&client, size))
            .await
            .unwrap()
            .unwrap();
        let HopOutcome::Accepted(Some(cell)) = response else {
            panic!("expected endpoint echo")
        };
        assert_eq!(cell.payload, vec![0x52; size]);
    }
    let mut stream = client
        .open_stream_body_pinned(
            net.terminal.addr,
            net.terminal.pin,
            "fixture-stream-capability",
            Some(
                &Cell::new(CellType::RelaySub, 0, 0, vec![0])
                    .encode_wire()
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    for n in 0..3 {
        let cell = tokio::time::timeout(Duration::from_secs(10), stream.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(cell.payload, vec![n; 12000]);
    }
    let dials = net.dials.lock().unwrap().clone();
    assert_eq!(dials.len(), 1, "endpoint pool reuses its circuit");
    assert_ne!(dials[0], net.terminal.addr);
    let extensions = net.extensions.lock().unwrap().clone();
    assert_eq!(extensions.len(), 2);
    assert_eq!(extensions[0].0, dials[0]);
    assert_eq!(extensions[0].1, extensions[1].0);
    assert_eq!(extensions[1].1, net.terminal.addr);
    assert_ne!(
        extensions[0].1, net.terminal.addr,
        "entry learns only middle"
    );
}

#[tokio::test]
async fn missing_path_and_excluded_destinations_never_dial() {
    let net = Network::new(1).await;
    assert!(net.echo(&net.client(), 1).await.is_err());
    assert!(net.dials.lock().unwrap().is_empty());
    let net = Network::new(2).await;
    let result = net
        .connector()
        .connect_excluding(
            net.terminal.addr,
            net.terminal.pin,
            &[(net.relays[0].addr, net.relays[0].pin)],
        )
        .await;
    assert!(result.is_err());
    assert!(net.dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn each_independent_tls_pin_rejects_substitution() {
    for layer in 0..3 {
        let net = Network::new(2).await;
        let [entry, middle] = net
            .directory
            .path(&[(net.terminal.addr, net.terminal.pin)], now_unix())
            .unwrap();
        if layer < 2 {
            let selected = if layer == 0 { entry } else { middle };
            // Build a retained private view with an incorrect service pin while
            // preserving the already selected guard ordering for this layer.
            let mut archive = net.directory.encode_private().unwrap();
            let old_pin = selected.service_id;
            let new_pin = [0xaa + layer as u8; 32];
            for offset in 0..archive.len().saturating_sub(31) {
                if archive[offset..offset + 32] == old_pin {
                    archive[offset..offset + 32].copy_from_slice(&new_pin);
                }
            }
            let directory = Arc::new(Directory::restore_private(&archive).unwrap());
            let connector = OnionConnector::new(directory)
                .with_carrier_config(CarrierConfig::fixture())
                .unwrap();
            let client = Tp1Client::with_connector(Arc::new(connector)).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(10), net.echo(&client, 10))
                    .await
                    .unwrap()
                    .is_err()
            );
        } else {
            let result = net
                .client()
                .get_pinned(net.terminal.addr, [0xee; 32], "/")
                .await;
            assert!(result.is_err());
        }
    }
}

#[tokio::test]
async fn dropping_stream_releases_nested_service_permits_and_shutdown_drains() {
    let mut net = Network::new(2).await;
    let stream: BoxStream = net
        .connector()
        .connect(net.terminal.addr, net.terminal.pin)
        .await
        .unwrap();
    assert_eq!(
        net.services
            .iter()
            .map(|s| s.active_circuits())
            .sum::<usize>(),
        2
    );
    drop(stream);
    tokio::time::timeout(Duration::from_secs(3), async {
        while net.services.iter().any(|s| s.active_circuits() != 0) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let stream = net
        .connector()
        .connect(net.terminal.addr, net.terminal.pin)
        .await
        .unwrap();
    for listener in &mut net.relays {
        let _ = listener.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(3), &mut listener.task)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(net.services.iter().all(|s| s.active_circuits() == 0));
    drop(stream);
}

#[test]
fn private_view_retains_stale_reentry_but_refuses_stale_routes_and_ip_aliases() {
    let directory = Directory::new();
    for i in 1..=70u8 {
        directory
            .install(
                Relay {
                    addr: format!("192.0.2.{i}:443").parse().unwrap(),
                    service_id: [i; 32],
                    reentry_cap: [1; 32],
                    circuit_cap: [2; 32],
                    expires_at: 200,
                },
                100,
            )
            .unwrap();
    }
    assert_eq!(directory.introductions().len(), 64);
    let path = directory.path(&[], 100).unwrap();
    let restored = Directory::restore_private(&directory.encode_private().unwrap()).unwrap();
    assert_eq!(
        restored.path(&[], 100).unwrap()[0].service_id,
        path[0].service_id
    );
    assert!(restored.path(&[], 201).is_err());
    assert_eq!(
        restored.introductions().len(),
        64,
        "stale seeds remain available for re-entry"
    );
    let same_ip = Directory::new();
    for i in 1..=2 {
        same_ip
            .install(
                Relay {
                    addr: format!("192.0.2.1:{}", 440 + i).parse().unwrap(),
                    service_id: [i as u8; 32],
                    reentry_cap: [1; 32],
                    circuit_cap: [2; 32],
                    expires_at: 200,
                },
                100,
            )
            .unwrap();
    }
    assert!(same_ip.path(&[], 100).is_err());
}

#[tokio::test]
async fn authenticated_users_share_an_entry_under_production_source_limits() {
    let net = Network::new(2).await;
    let mut clients = Vec::new();
    for _ in 0..12 {
        let client = net.client();
        net.echo(&client, 64).await.unwrap();
        clients.push(client);
    }
    assert_eq!(
        net.services
            .iter()
            .map(|s| s.active_circuits())
            .sum::<usize>(),
        24
    );
    let dials = net.dials.lock().unwrap();
    assert_eq!(dials.len(), 12);
    assert!(dials.iter().all(|a| a == &dials[0]));
}

#[tokio::test]
async fn retained_reentry_refreshes_expired_circuit_credentials() {
    let net = Network::new(2).await;
    let seed = net.services[0].introduction(now_unix().saturating_sub(7200));
    assert!(seed.expires_at <= now_unix());
    let stream = DirectConnector
        .connect(seed.addr, seed.service_id)
        .await
        .unwrap();
    let refreshed = gcoms_routing::carrier::refresh(stream, &seed)
        .await
        .unwrap();
    assert!(refreshed[0].expires_at > now_unix());
    assert_eq!(refreshed[0].reentry_cap, seed.reentry_cap);
    assert_ne!(refreshed[0].circuit_cap, seed.circuit_cap);
    let mut bad = seed.clone();
    bad.reentry_cap[0] ^= 1;
    let stream = DirectConnector
        .connect(seed.addr, seed.service_id)
        .await
        .unwrap();
    assert!(gcoms_routing::carrier::refresh(stream, &bad).await.is_err());
}

#[tokio::test]
async fn failed_original_guards_recover_using_retained_volunteers() {
    recover_failed_guards(false).await;
}

#[tokio::test]
async fn slow_guard_failures_do_not_repeat_after_the_directory_cooldown_expires() {
    recover_failed_guards(true).await;
}

struct SlowGuardFailure {
    guards: Vec<[u8; 32]>,
    attempts: Arc<Mutex<Vec<[u8; 32]>>>,
}
impl Connector for SlowGuardFailure {
    fn connect(&self, addr: SocketAddr, pin: [u8; 32]) -> ConnectFuture<'_> {
        self.attempts.lock().unwrap().push(pin);
        Box::pin(async move {
            if self.guards.contains(&pin) {
                // Three failed attempts together exceed the first two-second
                // cooldown, as ordinary refused connections can on Windows.
                tokio::time::sleep(Duration::from_millis(1100)).await;
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into())
            } else {
                DirectConnector.connect(addr, pin).await
            }
        })
    }
}

async fn recover_failed_guards(slow: bool) {
    let mut net = Network::new(5).await;
    let [_, _] = net
        .directory
        .path(&[(net.terminal.addr, net.terminal.pin)], now_unix())
        .unwrap();
    let archive = net.directory.encode_private().unwrap();
    let guards: Vec<[u8; 32]> = archive[7 + 5 * gcoms_routing::directory::RELAY_BYTES..]
        .as_chunks::<32>()
        .0
        .to_vec();
    assert_eq!(guards.len(), 3);
    for relay in &mut net.relays {
        if guards.contains(&relay.pin) {
            let _ = relay.stop.take().unwrap().send(());
            (&mut relay.task).await.unwrap();
        }
    }
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let mut connector =
        OnionConnector::new(Arc::new(Directory::restore_private(&archive).unwrap()))
            .with_carrier_config(CarrierConfig::fixture())
            .unwrap();
    if slow {
        connector = connector.with_entry_connector(Arc::new(SlowGuardFailure {
            guards,
            attempts: attempts.clone(),
        }));
    }
    let client = Tp1Client::with_connector(Arc::new(connector)).unwrap();
    tokio::time::timeout(Duration::from_secs(10), net.echo(&client, 15104))
        .await
        .unwrap()
        .unwrap();
    if slow {
        let attempts = attempts.lock().unwrap();
        assert_eq!(attempts.len(), 4);
        assert_eq!(
            attempts
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4
        );
    }
}

#[tokio::test]
async fn terminal_constraints_cannot_reuse_an_unconstrained_pool_connection() {
    let net = Network::new(3).await;
    let client = net.client();
    net.echo(&client, 10).await.unwrap();
    let first_entry = net.dials.lock().unwrap()[0];
    let excluded = net.relays.iter().find(|r| r.addr == first_entry).unwrap();
    let wire = Cell::new(CellType::Msg, 0, 8, vec![8; 100])
        .encode_wire()
        .unwrap();
    for _ in 0..2 {
        client
            .post_cell_pinned_excluding(
                net.terminal.addr,
                net.terminal.pin,
                "fixture-post-capability",
                Bytes::from(wire.clone()),
                &[(excluded.addr, excluded.pin)],
            )
            .await
            .unwrap();
    }
    let dials = net.dials.lock().unwrap();
    assert_eq!(
        dials.len(),
        2,
        "constrained pool is separate and then reused"
    );
    assert_ne!(dials[1], excluded.addr);
    let extensions = net.extensions.lock().unwrap();
    assert_eq!(extensions.len(), 4);
    assert!(extensions[2..]
        .iter()
        .all(|(source, target)| *source != excluded.addr && *target != excluded.addr));
}

#[tokio::test]
async fn private_provision_retry_and_public_probe_use_complete_circuits() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let net = Network::new(3).await;
    let (server, identity, _) = listener("127.0.0.50", false).await;
    let admitted = Arc::new(Directory::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let service = RelayService::new(
        server.local_addr().unwrap(),
        identity.service_id(),
        [50; 32],
        admitted.clone(),
        ServicePolicy {
            carrier: CarrierConfig::fixture(),
            target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
            provision: Some(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(vec![0x93; 20_000])
            })),
            ..ServicePolicy::default()
        },
    )
    .unwrap();
    let _listener = run(server.with_duplex(service.handler()));
    let relay = service.introduction(now_unix());
    for _ in 0..2 {
        let stream = net
            .connector()
            .connect(relay.addr, relay.service_id)
            .await
            .unwrap();
        let reply = gcoms_routing::carrier::provision(stream, &relay, [12; 32])
            .await
            .unwrap();
        assert_eq!(reply.as_slice(), vec![0x93; 20_000]);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "lost-response retry reuses one inbox grant"
    );
    assert!(admitted.introductions().is_empty());
    let volunteer = net.services[0].introduction(now_unix());
    let stream = net
        .connector()
        .connect(relay.addr, relay.service_id)
        .await
        .unwrap();
    gcoms_routing::carrier::advertise(stream, &relay, &volunteer)
        .await
        .unwrap();
    assert_eq!(admitted.introductions()[0].service_id, volunteer.service_id);
    let mut impostor = net.services[1].introduction(now_unix());
    impostor.service_id[0] ^= 1;
    let stream = net
        .connector()
        .connect(relay.addr, relay.service_id)
        .await
        .unwrap();
    assert!(gcoms_routing::carrier::advertise(stream, &relay, &impostor)
        .await
        .is_err());
    assert_eq!(
        admitted.introductions().len(),
        1,
        "wrong-pin probe never enters referrals"
    );
    assert_eq!(net.dials.lock().unwrap().len(), 4);
    assert!(net
        .dials
        .lock()
        .unwrap()
        .iter()
        .all(|addr| *addr != relay.addr));
}
