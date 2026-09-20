//! Real wall-clock carrier turnover. Only this fixture shortens the credential
//! epoch; production discovery scheduling, TLS, entry/transit handlers and
//! natural subscription framing run unchanged. This is not a fleet latency test.
use super::*;
use crate::gc2::{directory::BootstrapBundle, mux::TargetConnector, transit};
use bytes::Bytes;
use gcoms_core::{gc2::NaturalCell, CellType};
use gcoms_protocol::relay::gc2::Subscription;
use gcoms_transport::{
    connector::BoxStream,
    gc2::{status_cell, NaturalRoute, NaturalStream},
    server::{Dispatch, Tp1Server},
    tls::TlsIdentity,
    HopReply, TokenRegistry,
};
use std::{
    collections::HashSet,
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    task::JoinSet,
};

const WAIT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct Dials {
    live: AtomicUsize,
    peak: AtomicUsize,
    total: AtomicUsize,
}
struct CountedSocket {
    io: TcpStream,
    counts: Arc<Dials>,
}
impl Drop for CountedSocket {
    fn drop(&mut self) {
        self.counts.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl AsyncRead for CountedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for CountedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
impl Connector for DialsConnector {
    fn connect(&self, addr: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async move {
            let io = TcpStream::connect(addr).await?;
            let live = self.0.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.0.peak.fetch_max(live, Ordering::SeqCst);
            self.0.total.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountedSocket {
                io,
                counts: self.0.clone(),
            }) as BoxStream)
        })
    }
}
struct DialsConnector(Arc<Dials>);

#[derive(Clone)]
struct Trace {
    start: Instant,
    events: Arc<Mutex<Vec<String>>>,
}
impl Trace {
    fn record(&self, event: impl std::fmt::Display) {
        let line = format!(
            "{:.3}s wall={} {event}",
            self.start.elapsed().as_secs_f64(),
            now_unix()
        );
        eprintln!("{line}");
        self.events.lock().unwrap().push(line);
    }
}

async fn bind(ip: &str, identity: &TlsIdentity) -> Tp1Server {
    Tp1Server::bind_with_identity(
        format!("{ip}:0").parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        identity,
    )
    .await
    .unwrap()
}

// The relay authenticates only the current fixture epoch. A refresh before the
// shared wall-clock boundary cannot obtain future credentials.
async fn relay(
    tasks: &mut JoinSet<()>,
    index: usize,
    expiry: u64,
    first_refreshed: Arc<AtomicUsize>,
    release_middle: watch::Receiver<bool>,
    trace: Trace,
) -> [Introduction; 2] {
    let identity = TlsIdentity::generate().unwrap();
    let server = bind(
        if index == 0 {
            "127.0.0.105"
        } else {
            "127.0.0.106"
        },
        &identity,
    )
    .await;
    let old = Introduction {
        addr: server.local_addr().unwrap(),
        service_id: identity.service_id(),
        reentry_cap: rand::random(),
        entry_cap: rand::random(),
        transit_cap: rand::random(),
        expires_at: expiry,
    };
    let mut new = old.clone();
    new.entry_cap = rand::random();
    new.transit_cap = rand::random();
    new.expires_at = expiry + 180;
    let introductions = [old, new];
    let fixture = introductions.clone();
    let connect: TargetConnector = Arc::new(|target, _| {
        Box::pin(async move {
            let Target::Relay { addr, .. } = target else {
                return Err("fixture requires relay target".into());
            };
            if !addr.ip().is_loopback() {
                return Err("fixture target outside loopback".into());
            }
            Ok(Box::new(TcpStream::connect(addr).await?) as BoxStream)
        })
    });
    let factory = Arc::new(move || {
        let context = Arc::new(entry::ConnectionContext::default());
        let role = Mutex::new(None);
        let fixture = fixture.clone();
        let connect = connect.clone();
        let first_refreshed = first_refreshed.clone();
        let release_middle = release_middle.clone();
        let trace = trace.clone();
        Arc::new(move |path: &str, _: bool| {
            let generation = usize::from(now_unix() >= expiry);
            let intro = fixture[generation].clone();
            let cap = gcoms_transport::decode_b64url(path).unwrap_or_default();
            let requested = if cap == intro.entry_cap {
                0
            } else if cap == intro.transit_cap {
                1
            } else if cap == intro.reentry_cap {
                2
            } else {
                return Dispatch::Rejected;
            };
            let mut selected = role.lock().unwrap();
            if selected.is_some_and(|prior| prior != requested || prior == 1) {
                return Dispatch::Rejected;
            }
            *selected = Some(requested);
            drop(selected);
            if requested == 0 {
                trace.record(format!(
                    "entry_accept relay={index} generation={generation} original_expiry={}",
                    intro.expires_at
                ));
                return Dispatch::Accepted(context.accept(intro.expires_at, connect.clone()));
            }
            if requested == 1 {
                trace.record(format!(
                    "transit_accept relay={index} generation={generation}"
                ));
                return Dispatch::Accepted(transit::accept(intro.expires_at, connect.clone()));
            }
            let first_refreshed = first_refreshed.clone();
            let mut release_middle = release_middle.clone();
            let trace = trace.clone();
            Dispatch::Accepted(Box::new(move |mut body, mut response| {
                Box::pin(async move {
                    let request = gcoms_transport::server::read_body(&mut body, 32)
                        .await
                        .unwrap();
                    let request = NaturalCell::decode(&request).unwrap();
                    assert_eq!(request.kind(), CellType::Pex);
                    assert_eq!(request.payload(), discovery::REQUEST);
                    trace.record(format!(
                        "refresh_request relay={index} generation={generation}"
                    ));
                    if generation == 1 {
                        let first = first_refreshed
                            .compare_exchange(usize::MAX, index, Ordering::SeqCst, Ordering::SeqCst)
                            .unwrap_or_else(|value| value);
                        if first != usize::MAX && first != index {
                            trace.record(format!(
                                "refresh_held_for_independent_middle relay={index}"
                            ));
                            while !*release_middle.borrow_and_update() {
                                if release_middle.changed().await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    let bytes = BootstrapBundle {
                        relays: vec![intro],
                    }
                    .encode()
                    .unwrap();
                    let cell = NaturalCell::new(CellType::Pex, 0, bytes.to_vec()).unwrap();
                    let mut send = response
                        .send_response(http::Response::builder().body(()).unwrap(), false)
                        .unwrap();
                    send.send_data(Bytes::from(cell.encode()), true).unwrap();
                    trace.record(format!(
                        "refresh_response relay={index} generation={generation}"
                    ));
                })
            }))
        }) as gcoms_transport::server::DispatchHandler
    });
    tasks.spawn(async move { server.with_dispatch_factory(factory).run().await.unwrap() });
    introductions
}

fn message(class: TrafficClass, nonce: [u8; 16]) -> NaturalCell {
    let mut bytes = vec![
        class as u8;
        if class == TrafficClass::Bulk {
            8192
        } else {
            128
        }
    ];
    bytes[..16].copy_from_slice(&nonce);
    NaturalCell::new(CellType::Msg, 0, bytes).unwrap()
}

struct Terminal {
    addr: SocketAddr,
    pin: [u8; 32],
    cap: [u8; 32],
    expiry: u64,
    subscriptions: Arc<Mutex<Vec<Subscription>>>,
}
impl Terminal {
    async fn new(tasks: &mut JoinSet<()>, expiry: u64, trace: Trace) -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let server = bind("127.0.0.107", &identity).await;
        let addr = server.local_addr().unwrap();
        let pin = identity.service_id();
        let cap = rand::random();
        let subscriptions = Arc::new(Mutex::new(Vec::<Subscription>::new()));
        let observed = subscriptions.clone();
        let handler = Arc::new(move |path: &str| {
            if path != "retained-queue" {
                return None;
            }
            let observed = observed.clone();
            let trace = trace.clone();
            let accepted: gcoms_transport::server::AcceptedDuplex = Box::new(
                move |mut body, mut response: h2::server::SendResponse<Bytes>| {
                    Box::pin(async move {
                        let bytes = gcoms_transport::server::read_body(
                            &mut body,
                            gcoms_core::gc2::MAX_CELL,
                        )
                        .await
                        .unwrap();
                        let cell = NaturalCell::decode(&bytes).unwrap();
                        let subscription =
                            Subscription::decode(&cell, &cap, &pin, now_unix()).unwrap();
                        assert_eq!(subscription.queue_id, [0x51; 32]);
                        assert_eq!(subscription.epoch, 7);
                        assert_eq!(subscription.expiry, expiry);
                        {
                            let mut seen = observed.lock().unwrap();
                            assert!(
                                seen.iter().all(|old| old.nonce != subscription.nonce),
                                "fresh authenticated nonce required"
                            );
                            seen.push(subscription.clone());
                        }
                        trace.record(format!(
                            "subscription_accepted class={:?} authority_epoch=7",
                            subscription.class
                        ));
                        let mut send = response
                            .send_response(http::Response::builder().body(()).unwrap(), false)
                            .unwrap();
                        let mut wire = status_cell(HopReply::Accepted).encode();
                        wire.extend_from_slice(
                            &message(subscription.class, subscription.nonce).encode(),
                        );
                        send.send_data(Bytes::from(wire), false).unwrap();
                        // Keep the stream live beyond the carrier's original authority.
                        std::future::pending::<()>().await;
                        drop((body, send));
                    })
                },
            );
            Some(accepted)
        });
        tasks.spawn(async move { server.with_duplex(handler).run().await.unwrap() });
        Self {
            addr,
            pin,
            cap,
            expiry,
            subscriptions,
        }
    }

    async fn delivered(&self, client: &Tp1Client, class: TrafficClass) -> NaturalStream {
        let subscription = Subscription {
            class,
            queue_id: [0x51; 32],
            epoch: 7,
            expiry: self.expiry,
            nonce: rand::random(),
        };
        let mut stream = timeout(
            WAIT,
            client.open_natural_prepared(
                NaturalRoute {
                    addr: self.addr,
                    service_id: self.pin,
                    token: "retained-queue",
                    excluded: &[],
                    class,
                },
                Instant::now() + Duration::from_secs(120),
                || Ok(subscription.encode(&self.cap, &self.pin)?),
            ),
        )
        .await
        .expect("protected subscription setup bound")
        .unwrap();
        let actual = timeout(WAIT, stream.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            actual,
            message(class, subscription.nonce),
            "exact terminal payload independently received"
        );
        stream
    }
}

async fn until(mut condition: impl FnMut() -> bool, reason: &str) {
    timeout(WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{reason}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_expiry_reacquires_carrier_and_both_retained_subscriptions() {
    let mut tasks = JoinSet::new();
    let trace = Trace {
        start: Instant::now(),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let expiry = now_unix() + 24;
    let first_refreshed = Arc::new(AtomicUsize::new(usize::MAX));
    let (release, held) = watch::channel(false);
    let a = relay(
        &mut tasks,
        0,
        expiry,
        first_refreshed.clone(),
        held.clone(),
        trace.clone(),
    )
    .await;
    let b = relay(&mut tasks, 1, expiry, first_refreshed, held, trace.clone()).await;
    let terminal = Terminal::new(&mut tasks, expiry + 180, trace.clone()).await;
    let directory = Arc::new(Directory::for_loopback_fixture());
    directory
        .remember(
            &BootstrapBundle {
                relays: vec![a[0].clone(), b[0].clone()],
            },
            now_unix(),
        )
        .unwrap();
    directory
        .set_guards(vec![a[0].service_id, b[0].service_id])
        .unwrap();
    let retained_guards = directory.guards();
    let (mut owner, ready) =
        EntryOwner::new(directory.clone(), CandidateProfile::file_transfer(), 1).unwrap();
    let counts = Arc::new(Dials::default());
    // Count only entry sockets; the owner's independent private-control client
    // retains its ordinary connector and is not confused with protected entries.
    owner.dial = Arc::new(DialsConnector(counts.clone()));
    tasks.spawn(async move { owner.run().await.unwrap() });
    until(
        || ready.can_route((terminal.addr, terminal.pin)),
        "initial independent route",
    )
    .await;
    let original = ready.state.entries.read().unwrap()[0].clone();
    assert_eq!(original.introduction.expires_at, expiry);
    let client = Tp1Client::with_connector(ready.clone()).unwrap();
    let (mut interactive, mut bulk) = tokio::join!(
        terminal.delivered(&client, TrafficClass::Interactive),
        terminal.delivered(&client, TrafficClass::Bulk),
    );
    assert!(
        now_unix() < expiry,
        "both subscriptions must deliver before real expiry"
    );
    trace.record("both classes delivered before expiry");
    tokio::time::sleep(
        crate::gc2::remaining_authority_at(expiry, SystemTime::now()) + Duration::from_millis(10),
    )
    .await;
    assert!(now_unix() >= expiry, "real SystemTime credential expiry");
    let (interactive_end, bulk_end) = tokio::join!(
        timeout(WAIT, interactive.recv()),
        timeout(WAIT, bulk.recv()),
    );
    assert!(interactive_end
        .unwrap()
        .is_none_or(|result| result.is_err()));
    assert!(bulk_end.unwrap().is_none_or(|result| result.is_err()));
    trace.record("original subscriptions terminated at authenticated carrier expiry");
    // A refreshed directory must not extend the old authenticated carrier.
    assert!(original
        .carrier
        .open(
            TrafficClass::Interactive,
            &Target::Relay {
                addr: terminal.addr,
                service_id: terminal.pin
            }
        )
        .await
        .is_err());
    assert!(original.introduction.entry(now_unix()).is_err());
    until(
        || directory.eligible(&[], now_unix()).unwrap().len() == 1 && ready.ready_entries() == 1,
        "one refreshed introduction and a newly authenticated entry",
    )
    .await;
    assert!(
        !ready.can_route((terminal.addr, terminal.pin)),
        "fresh own entry alone is insufficient"
    );
    assert!(ready.connect(terminal.addr, terminal.pin).await.is_err());
    trace.record("fresh entry acquired; independent middle still unavailable");
    assert!(counts.total.load(Ordering::SeqCst) >= 2);
    let reacquired = ready.state.entries.read().unwrap()[0].clone();
    assert_eq!(reacquired.introduction.expires_at, expiry + 180);
    until(
        || {
            trace
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.contains("refresh_held_for_independent_middle"))
        },
        "second relay refresh reaches the controlled response barrier",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!ready.can_route((terminal.addr, terminal.pin)));
    assert_eq!(directory.eligible(&[], now_unix()).unwrap().len(), 1);
    release.send(true).unwrap();
    until(
        || {
            directory.eligible(&[], now_unix()).unwrap().len() == 2
                && ready.can_route((terminal.addr, terminal.pin))
        },
        "fresh independently authenticated middle",
    )
    .await;
    trace.record("fresh entry and independent middle available");
    let (interactive, bulk) = tokio::join!(
        terminal.delivered(&client, TrafficClass::Interactive),
        terminal.delivered(&client, TrafficClass::Bulk),
    );
    trace.record("both classes delivered after carrier reacquisition");
    let received = terminal.subscriptions.lock().unwrap().clone();
    assert_eq!(received.len(), 4);
    for class in [TrafficClass::Interactive, TrafficClass::Bulk] {
        assert_eq!(received.iter().filter(|sub| sub.class == class).count(), 2);
    }
    assert_eq!(
        received
            .iter()
            .map(|sub| sub.nonce)
            .collect::<HashSet<_>>()
            .len(),
        4
    );
    assert_eq!(directory.guards(), retained_guards);
    assert_eq!(
        counts.peak.load(Ordering::SeqCst),
        1,
        "bounded owned entries including in-flight sockets"
    );
    assert_eq!(ready.ready_entries(), 1);
    drop((interactive, bulk, client, original, reacquired));
    tasks.shutdown().await;
    assert_eq!(counts.live.load(Ordering::SeqCst), 0);
    assert_eq!(ready.ready_entries(), 0);
}
