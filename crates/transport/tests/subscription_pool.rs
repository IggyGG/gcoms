#![cfg(feature = "experimental-gc2")]
use bytes::Bytes;
use gcoms_core::{gc2::NaturalCell, CellType, TrafficClass};
use gcoms_transport::{
    client::MAX_ACTIVE_CONNECTIONS,
    connector::{ConnectFuture, Connector, DirectConnector},
    gc2::{status_cell, NaturalOutcome, NaturalRoute, NaturalStream},
    tls::TlsIdentity,
    HopReply, Tp1Client,
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::mpsc, task::JoinSet, time::timeout};
use tokio_rustls::TlsAcceptor;

struct Fixture {
    address: SocketAddr,
    pin: [u8; 32],
    bodies: mpsc::UnboundedReceiver<(usize, h2::SendStream<Bytes>)>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(stream_limit: u32) -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let pin = identity.service_id();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
        let (bodies_tx, bodies) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut number = 0;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        let acceptor = acceptor.clone();
                        let bodies_tx = bodies_tx.clone();
                        let index = number;
                        number += 1;
                        connections.spawn(async move {
                            let Ok(tls) = acceptor.accept(tcp).await else { return };
                            let mut connection = h2::server::Builder::new()
                                .max_concurrent_streams(stream_limit)
                                .handshake(tls).await.unwrap();
                            let mut requests = JoinSet::new();
                            while let Some(Ok((request, mut respond))) = connection.accept().await {
                                let bodies_tx = bodies_tx.clone();
                                requests.spawn(async move {
                                    let held = request.uri().path() == "/held";
                                    let mut body = request.into_body();
                                    gcoms_transport::server::read_body(&mut body, 16384).await.unwrap();
                                    let mut send = respond.send_response(http::Response::new(()), false).unwrap();
                                    send.send_data(Bytes::from(status_cell(HopReply::Accepted).encode()), !held).unwrap();
                                    if held { let _ = bodies_tx.send((index, send)); }
                                });
                            }
                            while let Some(result) = requests.join_next().await { result.unwrap(); }
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            address,
            pin,
            bodies,
            server,
        }
    }

    fn route(&self, token: &'static str) -> NaturalRoute<'static> {
        NaturalRoute {
            addr: self.address,
            service_id: self.pin,
            token,
            excluded: &[],
            class: TrafficClass::Bulk,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn request(class: TrafficClass) -> gcoms_transport::client::Result<NaturalCell> {
    Ok(NaturalCell::new(CellType::RelaySub, 0, vec![class as u8, 1]).unwrap())
}

async fn open(client: &Tp1Client, route: NaturalRoute<'_>) -> NaturalStream {
    timeout(
        Duration::from_secs(3),
        client.open_natural_prepared(
            route,
            tokio::time::Instant::now() + Duration::from_secs(30),
            || request(route.class),
        ),
    )
    .await
    .expect("subscription admission is bounded")
    .unwrap()
}

async fn control(client: &Tp1Client, route: NaturalRoute<'_>) {
    let reply = timeout(
        Duration::from_secs(3),
        client.post_natural_prepared(route, || request(route.class)),
    )
    .await
    .expect("finite control retains credit")
    .unwrap();
    assert_eq!(reply, NaturalOutcome::Accepted(None));
}

#[tokio::test]
async fn zero_stream_peer_refuses_without_dialing_overflow_or_preparing_a_body() {
    let fixture = Fixture::new(0).await;
    let client = Tp1Client::new().unwrap();
    let reply = timeout(
        Duration::from_secs(3),
        client.open_natural_prepared(
            fixture.route("held"),
            tokio::time::Instant::now() + Duration::from_secs(30),
            || panic!("a suspended peer must not prepare authenticated bytes"),
        ),
    )
    .await
    .unwrap()
    .err()
    .expect("zero peer capacity is explicit");
    assert!(reply
        .to_string()
        .contains("suspended HTTP/2 stream admission"));
    assert_eq!(client.pooled_connections().await, 1);
}

#[tokio::test]
async fn single_stream_peer_retains_control_at_hard_connection_bound_and_reuses_cancelled_credit() {
    let mut fixture = Fixture::new(1).await;
    let client = Tp1Client::new().unwrap();
    let mut held = Vec::new();
    let mut bodies = Vec::new();
    for _ in 1..MAX_ACTIVE_CONNECTIONS {
        held.push(open(&client, fixture.route("held")).await);
        bodies.push(fixture.bodies.recv().await.unwrap());
    }
    assert_eq!(client.pooled_connections().await, MAX_ACTIVE_CONNECTIONS);
    control(&client, fixture.route("control")).await;
    let prepared = std::sync::atomic::AtomicBool::new(false);
    let error = timeout(
        Duration::from_secs(3),
        client.open_natural_prepared(
            fixture.route("held"),
            tokio::time::Instant::now() + Duration::from_secs(30),
            || {
                prepared.store(true, std::sync::atomic::Ordering::Relaxed);
                request(TrafficClass::Bulk)
            },
        ),
    )
    .await
    .unwrap()
    .err()
    .expect("physical connection bound enforced");
    assert!(error.to_string().contains("capacity exhausted"));
    assert!(!prepared.load(std::sync::atomic::Ordering::Relaxed));
    control(&client, fixture.route("control")).await;

    // Dropping one receiver cancels its H2 stream and returns only that shard's
    // admission. Existing peers and the hard bound must remain intact.
    drop(held.remove(0));
    let original_connection = bodies.remove(0).0;
    held.push(open(&client, fixture.route("held")).await);
    let replacement = fixture.bodies.recv().await.unwrap();
    assert_eq!(replacement.0, original_connection);
    bodies.push(replacement);
    assert_eq!(client.pooled_connections().await, MAX_ACTIVE_CONNECTIONS);
    let expected = NaturalCell::new(CellType::Msg, 0, vec![7]).unwrap();
    for (_, mut body) in bodies {
        body.send_data(Bytes::from(expected.encode()), true)
            .unwrap();
    }
    for stream in &mut held {
        assert_eq!(
            timeout(Duration::from_secs(3), stream.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            expected
        );
    }
}

type Dial = (
    SocketAddr,
    [u8; 32],
    Vec<(SocketAddr, [u8; 32])>,
    TrafficClass,
);
struct ObservedConnector(Arc<Mutex<Vec<Dial>>>);
impl Connector for ObservedConnector {
    fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
        panic!("no unclassified fallback")
    }
    fn binds_traffic_class(&self) -> bool {
        true
    }
    fn connect_with_class_excluding<'a>(
        &'a self,
        address: SocketAddr,
        pin: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
        class: TrafficClass,
    ) -> ConnectFuture<'a> {
        self.0
            .lock()
            .unwrap()
            .push((address, pin, excluded.to_vec(), class));
        DirectConnector.connect(address, pin)
    }
}

#[tokio::test]
async fn concurrent_subscription_shards_preserve_pins_exclusions_classes_and_stream_limits() {
    let mut fixture = Fixture::new(8).await;
    let dials = Arc::new(Mutex::new(Vec::new()));
    let client =
        Arc::new(Tp1Client::with_connector(Arc::new(ObservedConnector(dials.clone()))).unwrap());
    let mut held = Vec::new();
    let mut bodies = Vec::new();
    for (class, excluded) in [
        (TrafficClass::Interactive, vec![]),
        (TrafficClass::Bulk, vec![]),
        (
            TrafficClass::Bulk,
            vec![("192.0.2.1:443".parse().unwrap(), [1; 32])],
        ),
    ] {
        let mut calls = JoinSet::new();
        for _ in 0..12 {
            let client = client.clone();
            let excluded = excluded.clone();
            let address = fixture.address;
            let pin = fixture.pin;
            calls.spawn(async move {
                open(
                    &client,
                    NaturalRoute {
                        addr: address,
                        service_id: pin,
                        token: "held",
                        excluded: &excluded,
                        class,
                    },
                )
                .await
            });
        }
        while let Some(result) = calls.join_next().await {
            held.push(result.unwrap());
        }
        let mut counts = BTreeMap::new();
        for _ in 0..12 {
            let body = fixture.bodies.recv().await.unwrap();
            *counts.entry(body.0).or_insert(0) += 1;
            bodies.push(body);
        }
        assert_eq!(counts.values().copied().collect::<Vec<_>>(), [4, 8]);
        control(
            &client,
            NaturalRoute {
                excluded: &excluded,
                class,
                ..fixture.route("control")
            },
        )
        .await;
    }
    let calls = dials.lock().unwrap().clone();
    assert_eq!(
        calls.len(),
        6,
        "concurrent reservations converge on two shards per route"
    );
    for (index, (address, pin, exclusions, class)) in calls.iter().enumerate() {
        assert_eq!((*address, *pin), (fixture.address, fixture.pin));
        assert_eq!(
            *class,
            if index < 2 {
                TrafficClass::Interactive
            } else {
                TrafficClass::Bulk
            }
        );
        assert_eq!(exclusions.len(), usize::from(index >= 4));
    }
    let wrong = NaturalRoute {
        service_id: [0; 32],
        ..fixture.route("held")
    };
    assert!(timeout(
        Duration::from_secs(3),
        client.open_natural_prepared(
            wrong,
            tokio::time::Instant::now() + Duration::from_secs(30),
            || request(wrong.class)
        )
    )
    .await
    .unwrap()
    .is_err());
    assert_eq!(client.pooled_connections().await, 6);
    let expected = NaturalCell::new(CellType::Msg, 0, vec![9]).unwrap();
    for (_, mut body) in bodies {
        body.send_data(Bytes::from(expected.encode()), true)
            .unwrap();
    }
    for stream in &mut held {
        assert_eq!(
            timeout(Duration::from_secs(3), stream.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            expected
        );
    }
}
