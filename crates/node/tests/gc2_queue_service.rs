#![cfg(feature = "experimental-gc2")]
use bytes::Bytes;
use gcoms_core::{gc2::NaturalCell, CellType, TrafficClass};
use gcoms_node::{
    gc2::{queue_token, QueueService},
    lease::{Capabilities, LeaseCreate, LeaseRevoke},
    queues::{GrantRequest, LeaseStore, StoreConfig},
    relay::gc2::{Push, Subscription},
};
use gcoms_routing::{
    gc2::{connector::PreparedConnector, entry, CandidateProfile},
    route::now_unix,
    Directory, RelayService, ServicePolicy,
};
use gcoms_transport::{
    gc2::{NaturalOutcome, NaturalRoute, NaturalStream},
    server::Tp1Server,
    tls::{self, TlsIdentity},
    TokenRegistry, Tp1Client,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::oneshot,
    task::{AbortHandle, JoinSet},
    time::{timeout, Instant},
};

const QUEUE: [u8; 32] = [1; 32];
const CAPS: Capabilities = Capabilities {
    push: [5; 32],
    sub: [6; 32],
    admin: [7; 32],
};
const I: TrafficClass = TrafficClass::Interactive;
const B: TrafficClass = TrafficClass::Bulk;

struct Fixture {
    address: SocketAddr,
    pin: [u8; 32],
    store: Arc<Mutex<LeaseStore>>,
    service: QueueService,
    stops: Vec<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
    carriers: Vec<AbortHandle>,
    entry_connections: Arc<AtomicUsize>,
}
impl Fixture {
    async fn new() -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let pin = identity.service_id();
        let config = StoreConfig::default();
        let mut store = LeaseStore::new(pin, config).unwrap();
        let now = now_unix();
        let grant = store
            .issue_grant(
                GrantRequest {
                    queue_id: QUEUE,
                    epoch: 1,
                    limits: config.relay_limits,
                },
                now,
            )
            .unwrap();
        let create = LeaseCreate {
            queue_id: QUEUE,
            epoch: 1,
            lease_expiry: now + 300,
            queue_cells: config.relay_limits.max_queue_cells,
            queue_bytes: config.relay_limits.max_queue_bytes,
            capabilities: CAPS,
            nonce: [31; 16],
            grant: grant.wire,
        };
        store
            .create_lease(&create.encode(&pin).unwrap(), now)
            .unwrap();
        let store = Arc::new(Mutex::new(store));
        let service = QueueService::new(store.clone());
        let server = Tp1Server::bind_with_identity(
            "127.0.0.85:0".parse().unwrap(),
            TokenRegistry::new(),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap()
        .with_duplex(service.handler());
        let address = server.local_addr().unwrap();
        let mut fixture = Self {
            address,
            pin,
            store,
            service,
            stops: Vec::new(),
            tasks: JoinSet::new(),
            carriers: Vec::new(),
            entry_connections: Arc::new(AtomicUsize::new(0)),
        };
        fixture.add(server);
        fixture
    }
    fn add(&mut self, server: Tp1Server) {
        let (tx, rx) = oneshot::channel();
        self.stops.push(tx);
        self.tasks.spawn(async move {
            server
                .run_until(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
    }
    fn route<'a>(&self, token: &'a str, class: TrafficClass) -> NaturalRoute<'a> {
        NaturalRoute {
            addr: self.address,
            service_id: self.pin,
            token,
            excluded: &[],
            class,
        }
    }
    fn push(&self, class: TrafficClass, nonce: u8, len: usize) -> Push {
        Push {
            class,
            queue_id: QUEUE,
            epoch: 1,
            nonce: [nonce; 16],
            expiry: now_unix() + 100,
            msg: Some(NaturalCell::new(CellType::Msg, 0, vec![nonce; len]).unwrap()),
        }
    }
    async fn deposit(&self, client: &Tp1Client, push: &Push) -> NaturalOutcome {
        client
            .post_natural_prepared(self.route(&queue_token(&QUEUE), push.class), || {
                Ok(push.encode(&CAPS.push, &self.pin)?)
            })
            .await
            .unwrap()
    }
    async fn subscribe(&self, client: &Tp1Client, class: TrafficClass, nonce: u8) -> NaturalStream {
        let sub = Subscription {
            class,
            queue_id: QUEUE,
            epoch: 1,
            expiry: now_unix() + 100,
            nonce: [nonce; 16],
        };
        client
            .open_natural_prepared(
                self.route(&queue_token(&QUEUE), class),
                Instant::now() + Duration::from_secs(60),
                || Ok(sub.encode(&CAPS.sub, &self.pin)?),
            )
            .await
            .unwrap()
    }
    async fn relay(&mut self, ip: &str, observe: bool) -> Arc<RelayService> {
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
                target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        let factory = service.gc2_handler_factory();
        let connections = self.entry_connections.clone();
        self.add(server.with_duplex_factory(Arc::new(move || {
            if observe {
                connections.fetch_add(1, Ordering::SeqCst);
            }
            factory()
        })));
        service
    }
    async fn protected_client(&mut self) -> Tp1Client {
        let relay = self.relay("127.0.0.86", true).await;
        let middle = self.relay("127.0.0.87", false).await;
        let descriptor = relay.gc2_entry_descriptor(now_unix());
        let socket = tokio::net::TcpStream::connect(descriptor.addr)
            .await
            .unwrap();
        socket.set_nodelay(true).unwrap();
        let (tx, rx) = oneshot::channel();
        self.carriers.push(self.tasks.spawn(async move {
            let _ = entry::run(
                Box::new(socket),
                descriptor,
                CandidateProfile::new(4096, 250).unwrap(),
                tx,
            )
            .await;
        }));
        let entry = timeout(Duration::from_secs(10), rx).await.unwrap().unwrap();
        Tp1Client::with_connector(Arc::new(PreparedConnector::new(
            entry,
            middle.gc2_transit_descriptor(now_unix()),
        )))
        .unwrap()
    }
    async fn inactive(&self) {
        timeout(Duration::from_secs(3), async {
            while self.service.active_subscriptions() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
    async fn finish(mut self) {
        for driver in self.carriers.drain(..) {
            driver.abort();
        }
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        while let Some(result) = self.tasks.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled(), "{error}");
            }
        }
        assert_eq!(self.service.active_subscriptions(), 0);
    }
}

#[tokio::test]
async fn authenticated_natural_delivery_uses_one_entry_for_both_classes() {
    let mut fixture = Fixture::new().await;
    let client = fixture.protected_client().await;
    let mut interactive = fixture.subscribe(&client, I, 1).await;
    let mut bulk = fixture.subscribe(&client, B, 2).await;
    let push = fixture.push(B, 10, 11 * 1024);
    assert_eq!(
        fixture.deposit(&client, &push).await,
        NaturalOutcome::Accepted(None)
    );
    assert_eq!(
        timeout(Duration::from_secs(10), bulk.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        push.msg.clone().unwrap()
    );
    let chat = fixture.push(I, 11, 128);
    assert_eq!(
        fixture.deposit(&client, &chat).await,
        NaturalOutcome::Accepted(None)
    );
    assert_eq!(
        timeout(Duration::from_secs(10), interactive.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        chat.msg.clone().unwrap()
    );
    assert_eq!(
        fixture.deposit(&client, &push).await,
        NaturalOutcome::Accepted(None)
    );
    let mut conflict = push.clone();
    conflict.class = I;
    assert_eq!(
        fixture.deposit(&client, &conflict).await,
        NaturalOutcome::Conflict
    );
    // Quiet natural subscriptions carry no inner cover and retries do not
    // enqueue again; the independent outer entry schedule remains active.
    assert!(timeout(Duration::from_millis(100), bulk.recv())
        .await
        .is_err());
    assert_eq!(fixture.entry_connections.load(Ordering::SeqCst), 1);
    assert_eq!(client.pooled_connections().await, 2);
    assert_eq!(fixture.store.lock().unwrap().total_queue_bytes(), 0);
    drop(interactive);
    drop(bulk);
    fixture.inactive().await;
    fixture.finish().await;
}

#[tokio::test]
async fn shutdown_owns_idle_subscriptions_and_releases_store_references() {
    let fixture = Fixture::new().await;
    let client = Tp1Client::new().unwrap();
    let mut stream = fixture.subscribe(&client, I, 1).await;
    assert_eq!(fixture.service.active_subscriptions(), 1);
    let store = fixture.store.clone();
    fixture.finish().await;
    assert_eq!(Arc::strong_count(&store), 1);
    let _ = timeout(Duration::from_secs(3), stream.recv())
        .await
        .unwrap();
}

#[tokio::test]
async fn authentication_and_path_binding_fail_without_queue_mutation() {
    let fixture = Fixture::new().await;
    let client = Tp1Client::new().unwrap();
    let push = fixture.push(I, 1, 128);
    let result = client
        .post_natural_prepared(fixture.route(&queue_token(&QUEUE), I), || {
            Ok(push.encode(&[99; 32], &fixture.pin)?)
        })
        .await
        .unwrap();
    assert_eq!(result, NaturalOutcome::Decoy(404));
    let mut wrong_queue = push.clone();
    wrong_queue.queue_id = [2; 32];
    let result = client
        .post_natural_prepared(fixture.route(&queue_token(&QUEUE), I), || {
            Ok(wrong_queue.encode(&CAPS.push, &fixture.pin)?)
        })
        .await
        .unwrap();
    assert_eq!(result, NaturalOutcome::Decoy(404));
    assert_eq!(
        fixture.store.lock().unwrap().queue_len(&QUEUE, now_unix()),
        0
    );
    assert_eq!(
        fixture.deposit(&client, &push).await,
        NaturalOutcome::Accepted(None)
    );
    let wrong_sub = Subscription {
        class: I,
        queue_id: QUEUE,
        epoch: 1,
        expiry: now_unix() + 100,
        nonce: [1; 16],
    };
    assert!(client
        .open_natural_prepared(
            fixture.route(&queue_token(&QUEUE), I),
            Instant::now() + Duration::from_secs(3),
            || Ok(wrong_sub.encode(&[99; 32], &fixture.pin)?)
        )
        .await
        .is_err());
    assert_eq!(fixture.service.active_subscriptions(), 0);
    fixture.finish().await;
}

#[tokio::test]
async fn idle_subscription_stops_at_its_authenticated_expiry() {
    let fixture = Fixture::new().await;
    let client = Tp1Client::new().unwrap();
    let sub = Subscription {
        class: I,
        queue_id: QUEUE,
        epoch: 1,
        expiry: now_unix() + 2,
        nonce: [1; 16],
    };
    let mut stream = client
        .open_natural_prepared(
            fixture.route(&queue_token(&QUEUE), I),
            Instant::now() + Duration::from_secs(10),
            || Ok(sub.encode(&CAPS.sub, &fixture.pin)?),
        )
        .await
        .unwrap();
    assert!(timeout(Duration::from_secs(3), stream.recv())
        .await
        .unwrap()
        .is_none());
    assert_eq!(fixture.service.active_subscriptions(), 0);
    fixture.finish().await;
}

#[tokio::test]
async fn revoked_subscription_cancels_a_writer_blocked_on_receive_credit() {
    let fixture = Fixture::new().await;
    let client = Tp1Client::new().unwrap();
    fixture.deposit(&client, &fixture.push(B, 10, 1024)).await;
    let socket = tokio::net::TcpStream::connect(fixture.address)
        .await
        .unwrap();
    socket.set_nodelay(true).unwrap();
    let tls =
        tokio_rustls::TlsConnector::from(Arc::new(tls::client_config_pinned(fixture.pin).unwrap()))
            .connect(tls::server_name_ip(fixture.address.ip()), socket)
            .await
            .unwrap();
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(16);
    let (mut sender, connection) = builder.handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    let sub = Subscription {
        class: B,
        queue_id: QUEUE,
        epoch: 1,
        expiry: now_unix() + 100,
        nonce: [1; 16],
    };
    let request = http::Request::builder()
        .method("POST")
        .uri(format!(
            "https://{}/{}",
            fixture.address,
            queue_token(&QUEUE)
        ))
        .body(())
        .unwrap();
    let (response, mut body) = sender.send_request(request, false).unwrap();
    body.send_data(
        Bytes::from(sub.encode(&CAPS.sub, &fixture.pin).unwrap().encode()),
        true,
    )
    .unwrap();
    let mut response = response.await.unwrap().into_body();
    // Read without releasing credit until the 16-byte window is consumed:
    // eight acceptance bytes, then only a prefix of the 1,030-byte message.
    let mut received = 0;
    while received < 16 {
        received += timeout(Duration::from_secs(3), response.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .len();
    }
    assert_eq!(received, 16);
    assert_eq!(
        fixture.store.lock().unwrap().queue_len(&QUEUE, now_unix()),
        1
    );
    let revoke = LeaseRevoke {
        queue_id: QUEUE,
        epoch: 1,
        operation_expiry: now_unix() + 60,
        nonce: [40; 16],
    }
    .encode(&CAPS.admin, &fixture.pin)
    .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .revoke(&revoke, now_unix())
        .unwrap();
    fixture.inactive().await;
    assert_eq!(fixture.store.lock().unwrap().total_queue_bytes(), 0);
    drop(response);
    drop(body);
    drop(sender);
    driver.abort();
    let result = driver.await;
    assert!(result.is_ok() || result.unwrap_err().is_cancelled());
    fixture.finish().await;
}
