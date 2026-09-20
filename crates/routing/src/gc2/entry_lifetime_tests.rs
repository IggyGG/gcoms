//! Isolate the unchanged 1800-second monotonic carrier cap from credential
//! expiry. Tokio time is paused; SystemTime authority remains fresh. These are
//! transport component tests, not elapsed-time or application turnover receipts.
use super::*;
use gcoms_transport::tls::TlsIdentity;
use tokio::{io::DuplexStream, task::JoinSet};
use tokio_rustls::TlsAcceptor;

const WAIT: Duration = Duration::from_secs(20);

type Peers = Arc<Mutex<Vec<(TrafficClass, DuplexStream)>>>;
type Starts = Arc<Mutex<Vec<Instant>>>;

fn target() -> Target {
    Target::Relay {
        addr: "192.0.2.2:443".parse().unwrap(),
        service_id: [2; 32],
    }
}

fn fixture() -> (TlsIdentity, EntryDescriptor, Peers, mux::TargetConnector) {
    let identity = TlsIdentity::generate().unwrap();
    let descriptor = EntryDescriptor {
        addr: "192.0.2.1:443".parse().unwrap(),
        service_id: identity.service_id(),
        entry_cap: [9; 32],
        expires_at: now_unix() + 7200,
    };
    let peers: Peers = Arc::default();
    let retained = peers.clone();
    let connect: mux::TargetConnector = Arc::new(move |requested, class| {
        assert_eq!(requested, target());
        let (local, peer) = tokio::io::duplex(8192);
        retained.lock().unwrap().push((class, peer));
        Box::pin(async move { Ok(Box::new(local) as BoxStream) })
    });
    (identity, descriptor, peers, connect)
}

// Disabling only this fixture peer's outer timeout isolates run()'s cap. All
// TLS, class framing, multiplexing and target admission stay real. Conversely,
// capped=true exercises the production ConnectionContext::accept timeout.
async fn serve(
    io: DuplexStream,
    identity: TlsIdentity,
    descriptor: EntryDescriptor,
    context: Arc<ConnectionContext>,
    connect: mux::TargetConnector,
    starts: Starts,
    capped: bool,
) {
    let tls = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()))
        .accept(io)
        .await
        .unwrap();
    let mut connection = h2::server::handshake(tls).await.unwrap();
    let mut channels = JoinSet::new();
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(Ok((request, mut respond))) = request else { break };
                assert_eq!(request.method(), "POST");
                assert_eq!(request.uri().path(), format!("/{}", gcoms_transport::encode_b64url(&descriptor.entry_cap)));
                descriptor.validate().unwrap();
                let context = context.clone();
                let connect = connect.clone();
                let starts = starts.clone();
                let expires_at = descriptor.expires_at;
                channels.spawn(async move {
                    starts.lock().unwrap().push(Instant::now());
                    if capped {
                        context.accept(expires_at, connect)(request.into_body(), respond).await;
                    } else {
                        let headers = http::Response::builder()
                            .header("content-type", "application/octet-stream")
                            .body(()).unwrap();
                        let send = respond.send_response(headers, false).unwrap();
                        let _ = context.serve(H2Stream::new(request.into_body(), send), connect).await;
                    }
                });
            },
            Some(result) = channels.join_next(), if !channels.is_empty() => result.unwrap(),
        }
    }
    channels.abort_all();
    while let Some(result) = channels.join_next().await {
        assert!(result.is_ok() || result.unwrap_err().is_cancelled());
    }
}

async fn settle() {
    // Drive ready futures without automatically jumping to their next timer.
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

fn trace(origin: Instant, descriptor: &EntryDescriptor, event: &str) {
    eprintln!(
        "event={event} simulated_seconds={:.3} wall={} authority_expiry={} carrier_cap_seconds={}",
        origin.elapsed().as_secs_f64(),
        now_unix(),
        descriptor.expires_at,
        MAX_LIFETIME.as_secs()
    );
}

async fn advance_to(when: Instant) {
    assert!(Instant::now() <= when, "fixture ran past its checkpoint");
    tokio::time::advance(when - Instant::now()).await;
    settle().await;
}

async fn exchange(stream: &mut mux::CircuitStream, peer: &mut DuplexStream, bytes: &[u8]) {
    timeout(WAIT, async {
        stream.write_all(bytes).await.unwrap();
        let mut received = vec![0; bytes.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
        peer.write_all(bytes).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
    })
    .await
    .unwrap();
}

fn take_peer(peers: &Peers, class: TrafficClass) -> DuplexStream {
    let mut peers = peers.lock().unwrap();
    let index = peers.iter().position(|(found, _)| *found == class).unwrap();
    peers.remove(index).1
}

async fn ended(stream: &mut mux::CircuitStream, peer: &mut DuplexStream) {
    timeout(WAIT, async {
        let mut byte = [0];
        assert!(!matches!(stream.read(&mut byte).await, Ok(n) if n > 0));
        assert!(!matches!(peer.read(&mut byte).await, Ok(n) if n > 0));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn client_cap_ends_both_classes_while_authority_is_fresh() {
    assert_eq!(MAX_LIFETIME, Duration::from_secs(1800));
    let (identity, descriptor, peers, connect) = fixture();
    let authority = descriptor.clone();
    let context = Arc::new(ConnectionContext::default());
    let starts = Starts::default();
    let (client_io, server_io) = tokio::io::duplex(CHANNEL_BUFFER * 2);
    let server = tokio::spawn(serve(
        server_io,
        identity,
        descriptor.clone(),
        context.clone(),
        connect,
        starts.clone(),
        false,
    ));
    let origin = Instant::now();
    let (ready, receive) = oneshot::channel();
    let client = tokio::spawn(run(
        Box::new(client_io),
        descriptor,
        CandidateProfile::file_transfer(),
        ready,
    ));
    let carrier = timeout(WAIT, receive).await.unwrap().unwrap();
    let client_budget = carrier.budget.clone();
    trace(origin, &authority, "client_ready");
    let mut chat = carrier
        .open(TrafficClass::Interactive, &target())
        .await
        .unwrap();
    let mut bulk = carrier.open(TrafficClass::Bulk, &target()).await.unwrap();
    let mut chat_peer = take_peer(&peers, TrafficClass::Interactive);
    let mut bulk_peer = take_peer(&peers, TrafficClass::Bulk);
    exchange(&mut chat, &mut chat_peer, b"chat before cap").await;
    exchange(&mut bulk, &mut bulk_peer, b"bulk before cap").await;
    assert_eq!(carrier.active_circuits(), 2);
    assert_eq!(context.budget.active(), 2);
    assert_eq!(starts.lock().unwrap().len(), 2);

    advance_to(origin + MAX_LIFETIME - Duration::from_secs(10)).await;
    exchange(&mut chat, &mut chat_peer, b"late chat").await;
    exchange(&mut bulk, &mut bulk_peer, b"late bulk").await;
    advance_to(origin + MAX_LIFETIME - Duration::from_millis(1)).await;
    trace(origin, &authority, "client_before_cap");
    assert!(!client.is_finished(), "carrier ended before its cap");
    authority.validate().unwrap();
    assert!(authority.expires_at - now_unix() > MAX_LIFETIME.as_secs());
    advance_to(origin + MAX_LIFETIME).await;
    let failure = timeout(Duration::from_millis(1), client)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.to_string(), "GC/2 entry lifetime ended");
    trace(origin, &authority, "client_cap_ended");
    authority.validate().unwrap();
    ended(&mut chat, &mut chat_peer).await;
    ended(&mut bulk, &mut bulk_peer).await;
    assert!(carrier
        .open(TrafficClass::Interactive, &target())
        .await
        .is_err());
    assert!(carrier.open(TrafficClass::Bulk, &target()).await.is_err());
    drop((chat, bulk, carrier));
    assert_eq!(client_budget.active(), 0);
    timeout(WAIT, server).await.unwrap().unwrap();
    assert_eq!(context.budget.active(), 0);
    assert!(peers.lock().unwrap().is_empty());
}

// No outer timer on this deliberately uncooperative test peer. This prevents
// the production client's earlier cap from masking a missing server deadline.
async fn uncapped_client(
    io: DuplexStream,
    descriptor: &EntryDescriptor,
    tasks: &mut JoinSet<()>,
) -> (mux::MuxClient, mux::MuxClient, Arc<mux::CircuitBudget>) {
    let tls = TlsConnector::from(Arc::new(
        tls::client_config_pinned(descriptor.service_id).unwrap(),
    ))
    .connect(tls::server_name_ip(descriptor.addr.ip()), io)
    .await
    .unwrap();
    let (sender, driver) = h2::client::handshake(tls).await.unwrap();
    tasks.spawn(async move {
        let _ = driver.await;
    });
    let profile = CandidateProfile::file_transfer();
    let budget = Arc::new(mux::CircuitBudget::default());
    let mut clients = Vec::new();
    for class in [TrafficClass::Interactive, TrafficClass::Bulk] {
        let codec = RecordCodec::new(class, profile);
        let wire = open_channel(sender.clone(), descriptor, codec)
            .await
            .unwrap();
        let (local, pumped) = tokio::io::duplex(CHANNEL_BUFFER);
        tasks.spawn(async move {
            let _ = channel::pump(wire, pumped, codec, Instant::now() + profile.period()).await;
        });
        let (client, driver) = mux::MuxClient::handshake(local, class, budget.clone())
            .await
            .unwrap();
        tasks.spawn(async move {
            let _ = driver.await;
        });
        clients.push(client);
    }
    let bulk = clients.pop().unwrap();
    (clients.pop().unwrap(), bulk, budget)
}

#[tokio::test(start_paused = true)]
async fn server_cap_reclaims_both_classes_while_authority_is_fresh() {
    assert_eq!(MAX_LIFETIME, Duration::from_secs(1800));
    let (identity, descriptor, peers, connect) = fixture();
    let context = Arc::new(ConnectionContext::default());
    let starts = Starts::default();
    let (client_io, server_io) = tokio::io::duplex(CHANNEL_BUFFER * 2);
    let server = tokio::spawn(serve(
        server_io,
        identity,
        descriptor.clone(),
        context.clone(),
        connect,
        starts.clone(),
        true,
    ));
    let mut tasks = JoinSet::new();
    let origin = Instant::now();
    let (chat_client, bulk_client, budget) =
        timeout(WAIT, uncapped_client(client_io, &descriptor, &mut tasks))
            .await
            .unwrap();
    trace(origin, &descriptor, "server_peer_ready");
    let mut chat = chat_client.open(&target()).await.unwrap();
    let mut bulk = bulk_client.open(&target()).await.unwrap();
    let mut chat_peer = take_peer(&peers, TrafficClass::Interactive);
    let mut bulk_peer = take_peer(&peers, TrafficClass::Bulk);
    exchange(&mut chat, &mut chat_peer, b"chat before server cap").await;
    exchange(&mut bulk, &mut bulk_peer, b"bulk before server cap").await;
    let accepted = starts.lock().unwrap().clone();
    assert_eq!(accepted.len(), 2);
    assert_eq!(context.pending.available_permits(), 0);
    assert_eq!(context.budget.active(), 2);
    let first = *accepted.iter().min().unwrap() + MAX_LIFETIME;
    let last = *accepted.iter().max().unwrap() + MAX_LIFETIME;
    advance_to(first - Duration::from_secs(10)).await;
    exchange(&mut chat, &mut chat_peer, b"late chat").await;
    exchange(&mut bulk, &mut bulk_peer, b"late bulk").await;
    advance_to(first - Duration::from_millis(1)).await;
    trace(origin, &descriptor, "server_before_first_cap");
    assert_eq!(context.pending.available_permits(), 0);
    assert_eq!(
        context.budget.active(),
        2,
        "server ended circuits before its cap"
    );
    descriptor.validate().unwrap();
    assert!(descriptor.expires_at - now_unix() > MAX_LIFETIME.as_secs());
    advance_to(last).await;
    trace(origin, &descriptor, "server_at_last_cap");
    assert_eq!(
        context.pending.available_permits(),
        2,
        "server retained expired class handlers"
    );
    assert_eq!(
        context.budget.active(),
        0,
        "server retained target work past its cap"
    );
    descriptor.validate().unwrap();
    ended(&mut chat, &mut chat_peer).await;
    ended(&mut bulk, &mut bulk_peer).await;
    assert!(chat_client.open(&target()).await.is_err());
    assert!(bulk_client.open(&target()).await.is_err());
    drop((chat, bulk, chat_client, bulk_client));
    assert_eq!(budget.active(), 0);
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        assert!(result.is_ok() || result.unwrap_err().is_cancelled());
    }
    timeout(WAIT, server).await.unwrap().unwrap();
    assert!(peers.lock().unwrap().is_empty());
}
