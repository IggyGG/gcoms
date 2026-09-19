//! Application-level goodput and latency harness for the GC/2 carrier
//! comparison. Loopback only; disposable in-memory archives; real durable
//! applications, persistence and application receipts.
//!
//! Usage:
//!   app_performance --profile gc1|gc2 --seed N [--chat-count N]
//!                   [--chat-bytes 128] [--chat-interval-ms 250]
//!                   [--bulk-bytes N] [--bulk-chunk 11264] [--inflight 16]
//!                   [--timeout 60] [--json out.json]
//!
//! Chat runs as an independent stream at `--chat-interval-ms`; bulk keeps a
//! bounded in-flight window. One invocation measures one trial and prints one
//! JSON record. `scripts/app-utilization.py` runs the balanced matrix and
//! applies the acceptance gates; this binary never decides qualification.
#![cfg(all(feature = "experimental-gc2", feature = "client-persist"))]

use futures_util::{stream::FuturesUnordered, StreamExt};
use gcoms_node::node::{start_persistent_restored, Ev, NodeConfig, NodeProfile};
use gcoms_node::proto::NodeInfo;
use gcoms_node::NodeHandle;
use gcoms_routing::{route::now_unix, Directory, RelayService, ServicePolicy};
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Args {
    profile: String,
    protected: bool,
    entries: usize,
    cadence: String,
    drain_ms: u64,
    idle_ms: u64,
    skip_single: bool,
    listen_a: u16,
    listen_b: u16,
    seed: u64,
    chat_count: usize,
    chat_bytes: usize,
    chat_interval_ms: u64,
    bulk_bytes: usize,
    bulk_chunk: usize,
    inflight: usize,
    timeout: Duration,
    json: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        profile: "gc1".into(),
        protected: false,
        entries: 2,
        cadence: "compressed".into(),
        drain_ms: 5000,
        idle_ms: 0,
        skip_single: false,
        listen_a: 0,
        listen_b: 0,
        seed: 1,
        chat_count: 0,
        chat_bytes: 128,
        chat_interval_ms: 250,
        bulk_bytes: 0,
        bulk_chunk: 11 * 1024,
        inflight: 16,
        timeout: Duration::from_secs(90),
        json: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--profile" => args.profile = value()?,
            "--protected" => args.protected = true,
            "--entries" => args.entries = value()?.parse::<usize>().map_err(|e| e.to_string())?,
            "--drain-ms" => args.drain_ms = value()?.parse::<u64>().map_err(|e| e.to_string())?,
            "--idle-ms" => args.idle_ms = value()?.parse::<u64>().map_err(|e| e.to_string())?,
            "--skip-single" => args.skip_single = true,
            "--listen-a" => args.listen_a = value()?.parse::<u16>().map_err(|e| e.to_string())?,
            "--listen-b" => args.listen_b = value()?.parse::<u16>().map_err(|e| e.to_string())?,
            "--cadence" => {
                let cadence = value()?;
                if !matches!(cadence.as_str(), "compressed" | "production") {
                    return Err("--cadence must be compressed or production".into());
                }
                args.cadence = cadence;
            }
            "--seed" => args.seed = value()?.parse::<u64>().map_err(|e| e.to_string())?,
            "--chat-count" => {
                args.chat_count = value()?.parse::<usize>().map_err(|e| e.to_string())?
            }
            "--chat-bytes" => {
                args.chat_bytes = value()?.parse::<usize>().map_err(|e| e.to_string())?
            }
            "--chat-interval-ms" => {
                args.chat_interval_ms = value()?.parse::<u64>().map_err(|e| e.to_string())?
            }
            "--bulk-bytes" => {
                args.bulk_bytes = value()?.parse::<usize>().map_err(|e| e.to_string())?
            }
            "--bulk-chunk" => {
                args.bulk_chunk = value()?.parse::<usize>().map_err(|e| e.to_string())?
            }
            "--inflight" => args.inflight = value()?.parse::<usize>().map_err(|e| e.to_string())?,
            "--timeout" => {
                args.timeout =
                    Duration::from_secs(value()?.parse::<u64>().map_err(|e| e.to_string())?)
            }
            "--json" => args.json = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if !matches!(args.profile.as_str(), "gc1" | "gc2") {
        return Err("--profile must be gc1 or gc2".into());
    }
    if args.chat_count == 0 && args.bulk_bytes == 0 && args.idle_ms == 0 {
        return Err("nothing to measure: set --chat-count, --bulk-bytes or --idle-ms".into());
    }
    if args.bulk_chunk < 1024 || args.bulk_chunk > 15 * 1024 {
        return Err("--bulk-chunk must be between 1024 and 15360".into());
    }
    if args.inflight == 0 || args.inflight > 48 {
        return Err("--inflight must be between 1 and 48".into());
    }
    if args.chat_bytes == 0 || args.chat_bytes > 12 * 1024 {
        return Err("--chat-bytes must be between 1 and 12 KiB".into());
    }
    Ok(args)
}

fn profile(
    name: &str,
    seed: u64,
    introductions: &[Vec<u8>],
    entries: usize,
    cadence: &str,
) -> NodeProfile {
    // Both variants are loopback fixtures: a production-shaped profile has no
    // published inbox without the control plane, so the local carrier fixture
    // exercises the real session/scheduling path. Operated-network runs use the
    // production profile once a relay card is provisioned. With `--protected`
    // the fixture is seeded with live entry/middle introductions so the carrier
    // owner dials real circuits instead of the direct terminal.
    let production = cadence == "production";
    match name {
        "gc2" if !introductions.is_empty() && production => {
            NodeProfile::gc2_carrier_production_cadence_fixture_seeded(
                None,
                entries,
                introductions.to_vec(),
            )
        }
        "gc2" if !introductions.is_empty() => {
            NodeProfile::gc2_carrier_qualification_fixture_seeded(
                None,
                entries,
                seed,
                introductions.to_vec(),
            )
        }
        "gc2" => NodeProfile::gc2_carrier_qualification_fixture(None, entries, seed),
        _ if production => NodeProfile::production_cadence_fixture(),
        _ => NodeProfile::compressed_production(seed),
    }
}

/// One loopback relay service with a GC/2 dispatch factory; the returned
/// counter advances on every dialed circuit.
async fn start_relay(
    ip: &str,
) -> (
    Arc<RelayService>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let identity = TlsIdentity::generate().expect("relay identity");
    let server = Tp1Server::bind_with_identity(
        format!("{ip}:0").parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .expect("relay listener");
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
    .expect("relay service");
    let factory = service.gc2_handler_factory();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    let server = server.with_dispatch_factory(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        factory()
    }));
    let handle = tokio::spawn(async move {
        let _ = server.run_until(std::future::pending::<()>()).await;
    });
    (service, connections, handle)
}

/// Entry and middle relays plus the encoded introductions for both directories.
async fn protected_relays() -> (
    Vec<Vec<u8>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let (entry, entry_connections, entry_task) = start_relay("127.0.0.86").await;
    let (middle, middle_connections, middle_task) = start_relay("127.0.0.87").await;
    let now = now_unix();
    let introductions = vec![
        entry.gc2_introduction(now).encode().unwrap().to_vec(),
        middle.gc2_introduction(now).encode().unwrap().to_vec(),
    ];
    (
        introductions,
        entry_connections,
        middle_connections,
        vec![entry_task, middle_task],
    )
}

async fn endpoint(seed: u8, profile: NodeProfile, listen: std::net::SocketAddr) -> NodeHandle {
    let archive = Arc::new(Mutex::new(Vec::new()));
    let sink_archive = archive.clone();
    let node = start_persistent_restored(
        NodeConfig {
            seed: [seed; 32],
            listen,
            control: None,
            advertise: None,
            inbox_relay: None,
            profile,
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(move |bytes| {
            *sink_archive.lock().unwrap() = bytes;
            Ok(())
        }),
        None,
    )
    .await
    .expect("loopback endpoint starts");
    node.enable_durable_applications()
        .await
        .expect("durable applications enabled");
    node.enable_diagnostics();
    node
}

/// Routes each application acknowledgment to its waiter exactly once. A
/// completion without a waiter is retained until the sender registers one.
#[derive(Default)]
struct AckHub {
    inner: Mutex<AckHubState>,
}

#[derive(Default)]
struct AckHubState {
    completed: std::collections::HashMap<[u8; 16], Instant>,
    waiters: std::collections::HashMap<[u8; 16], tokio::sync::oneshot::Sender<Instant>>,
}

impl AckHub {
    fn complete(&self, id: [u8; 16]) {
        let mut state = self.inner.lock().unwrap();
        if let Some(waiter) = state.waiters.remove(&id) {
            let _ = waiter.send(Instant::now());
        } else {
            state.completed.insert(id, Instant::now());
        }
    }

    async fn wait(&self, id: [u8; 16]) -> Option<Instant> {
        let receiver = {
            let mut state = self.inner.lock().unwrap();
            if let Some(at) = state.completed.remove(&id) {
                return Some(at);
            }
            let (sender, receiver) = tokio::sync::oneshot::channel();
            state.waiters.insert(id, sender);
            receiver
        };
        receiver.await.ok()
    }
}

fn file_record_body(chunk: &[u8]) -> Vec<u8> {
    let mut application = b"GCAPP1".to_vec();
    application
        .extend_from_slice(&(gcoms_core::FILE_RECORD_CONTENT_TYPE.len() as u16).to_be_bytes());
    application.extend_from_slice(gcoms_core::FILE_RECORD_CONTENT_TYPE.as_bytes());
    application.extend_from_slice(chunk);
    gcoms_core::component::RoutedApplication {
        source: [0x21; 16],
        destination: [0x22; 16],
        application,
    }
    .encode()
    .expect("bounded file record")
}

fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index]
}

#[allow(clippy::too_many_arguments)]
async fn chat_stream(
    sender: &NodeHandle,
    peer: &NodeInfo,
    body: &[u8],
    count: usize,
    interval: Duration,
    hub: &Arc<AckHub>,
    timeout: Duration,
) -> (Vec<f64>, usize, usize) {
    let mut latencies = Vec::with_capacity(count);
    let mut sent = 0usize;
    let mut failures = 0usize;
    for index in 0..count {
        if index > 0 && !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
        let start = Instant::now();
        let id = match sender.send_durable_1to1_tracked(peer, body, None).await {
            Ok(id) => id,
            Err(_) => {
                failures += 1;
                continue;
            }
        };
        sent += 1;
        match tokio::time::timeout(timeout, hub.wait(id)).await {
            Ok(Some(_)) => latencies.push(start.elapsed().as_secs_f64()),
            _ => failures += 1,
        }
    }
    (latencies, sent, failures)
}

#[allow(clippy::too_many_arguments)]
async fn bulk_stream(
    sender: &NodeHandle,
    peer: &NodeInfo,
    body: &[u8],
    total: usize,
    chunk: usize,
    inflight: usize,
    hub: &Arc<AckHub>,
    timeout: Duration,
) -> (usize, usize, usize) {
    let mut acked_bytes = 0usize;
    let mut acked = 0usize;
    let mut failures = 0usize;
    let mut sent = 0usize;
    let mut flight = FuturesUnordered::new();
    loop {
        while flight.len() < inflight && sent < total {
            match sender.send_durable_1to1_tracked(peer, body, None).await {
                Ok(id) => {
                    sent += 1;
                    let hub = hub.clone();
                    flight.push(async move {
                        tokio::time::timeout(timeout, hub.wait(id))
                            .await
                            .ok()
                            .flatten()
                            .is_some()
                    });
                }
                Err(_) => {
                    failures += 1;
                    sent += 1;
                }
            }
        }
        if flight.is_empty() {
            break;
        }
        match flight.next().await {
            Some(true) => {
                acked += 1;
                acked_bytes += chunk;
            }
            Some(false) => failures += 1,
            None => break,
        }
    }
    (acked_bytes, acked, failures)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), String> {
    let args = parse_args()?;
    let (introductions, entry_connections, middle_connections, _relay_tasks) = if args.protected {
        let (introductions, entry, middle, tasks) = protected_relays().await;
        (introductions, Some(entry), Some(middle), tasks)
    } else {
        (Vec::new(), None, None, Vec::new())
    };
    let listen_a: std::net::SocketAddr = format!("127.0.0.1:{}", args.listen_a).parse().unwrap();
    let listen_b: std::net::SocketAddr = format!("127.0.0.1:{}", args.listen_b).parse().unwrap();
    let recipient = endpoint(
        0x51,
        profile(
            &args.profile,
            args.seed,
            &introductions,
            args.entries,
            &args.cadence,
        ),
        listen_a,
    )
    .await;
    let sender = endpoint(
        0x52,
        profile(
            &args.profile,
            args.seed,
            &introductions,
            args.entries,
            &args.cadence,
        ),
        listen_b,
    )
    .await;
    let recipient_addr = recipient.listener_addr();
    let sender_addr = sender.listener_addr();
    let peer = recipient.current_info().await?;

    // Consume durable inbox entries like a real application: commit the
    // authenticated receipt promptly so the bounded inbox cannot stall the
    // sender and the measurement reflects sustained application delivery.
    let draining = Arc::new(AtomicBool::new(true));
    let drained = Arc::new(AtomicUsize::new(0));
    let drain_task = tokio::spawn({
        let recipient = recipient.clone();
        let draining = draining.clone();
        let drained = drained.clone();
        async move {
            let mut after = 0u64;
            while draining.load(Ordering::Relaxed) {
                match recipient.application_inbox(after, 32).await {
                    Ok(entries) if !entries.is_empty() => {
                        for entry in entries {
                            if recipient
                                .commit_application(entry.sequence, entry.digest())
                                .await
                                .is_ok()
                            {
                                after = entry.sequence;
                                drained.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
    });

    // One pump owns the event stream and routes acknowledgments to waiters.
    let hub = Arc::new(AckHub::default());
    let pumping = Arc::new(AtomicBool::new(true));
    let pump_task = tokio::spawn({
        let sender = sender.clone();
        let hub = hub.clone();
        let pumping = pumping.clone();
        async move {
            while pumping.load(Ordering::Relaxed) {
                match sender.next_event().await {
                    Some(Ev::DirectDelivery { msg_id, .. }) => hub.complete(msg_id),
                    Some(_) => {}
                    None => tokio::time::sleep(Duration::from_millis(2)).await,
                }
            }
        }
    });

    if args.idle_ms > 0 && args.chat_count == 0 && args.bulk_bytes == 0 {
        tokio::time::sleep(Duration::from_millis(args.idle_ms)).await;
    }
    let chat_body = vec![0x41; args.chat_bytes];
    let bulk_body = file_record_body(&vec![0x42; args.bulk_chunk]);
    let chat_interval = Duration::from_millis(args.chat_interval_ms);
    let bulk_total = args.bulk_bytes.div_ceil(args.bulk_chunk);
    let bulk_start = Instant::now();
    let chat = chat_stream(
        &sender,
        &peer,
        &chat_body,
        args.chat_count,
        chat_interval,
        &hub,
        args.timeout,
    );
    let bulk = bulk_stream(
        &sender,
        &peer,
        &bulk_body,
        bulk_total,
        args.bulk_chunk,
        args.inflight,
        &hub,
        args.timeout,
    );
    let (chat, bulk) = tokio::join!(chat, bulk);
    let elapsed = bulk_start.elapsed().as_secs_f64();

    // Workload results are final once both streams join.
    let (mut chat_latencies, chat_sent, chat_failures) = chat;
    let (bulk_acked_bytes, bulk_chunks, bulk_failures) = bulk;
    let failures = chat_failures + bulk_failures;
    chat_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let chat_p50_ms = percentile(&chat_latencies, 0.5) * 1000.0;
    let chat_p95_ms = percentile(&chat_latencies, 0.95) * 1000.0;
    let chat_max_ms = chat_latencies.last().copied().unwrap_or_default() * 1000.0;
    let goodput_kib_s = if elapsed > 0.0 {
        bulk_acked_bytes as f64 / elapsed / 1024.0
    } else {
        0.0
    };
    let diagnostics = sender.diagnostics();

    // Drain the workload before measuring the idle shaping delay, then send a
    // single message on the established session. The gate bounds the *one-way*
    // intentional shaping delay, so stop the drain task and time arrival at the
    // peer's durable inbox (send -> persisted) before waiting for the ACK.
    if args.drain_ms > 0 {
        tokio::time::sleep(Duration::from_millis(args.drain_ms)).await;
    }
    draining.store(false, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (single_delay_ms, single_one_way_ms) = if args.skip_single {
        (-1.0, -1.0)
    } else {
        let single_start = Instant::now();
        let id = sender
            .send_durable_1to1_tracked(&peer, &chat_body, None)
            .await?;
        let (one_way, arrival) = {
            let deadline = Instant::now() + args.timeout;
            let mut arrived = -1.0f64;
            let mut arrival = None;
            while Instant::now() < deadline {
                if let Ok(entries) = recipient.application_inbox(0, 32).await {
                    if let Some(entry) = entries.iter().find(|entry| entry.message_id == id) {
                        arrived = single_start.elapsed().as_secs_f64() * 1000.0;
                        arrival = Some((entry.sequence, entry.digest()));
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            (arrived, arrival)
        };
        let round_trip = match tokio::time::timeout(args.timeout, hub.wait(id)).await {
            Ok(Some(_)) => single_start.elapsed().as_secs_f64() * 1000.0,
            _ => -1.0,
        };
        // The drain task is paused for the one-way measurement; commit its
        // receipt here so run accounting stays exact.
        if let Some((sequence, digest)) = arrival {
            if recipient.commit_application(sequence, digest).await.is_ok() {
                drained.fetch_add(1, Ordering::Relaxed);
            }
        }
        (round_trip, one_way)
    };

    // Wait for the receiver to commit every durable receipt before stopping.
    let expected_receipts = chat_sent + bulk_chunks + usize::from(!args.skip_single);
    for _ in 0..300 {
        if drained.load(Ordering::Relaxed) >= expected_receipts {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Both helper tasks may be parked on an idle stream; abort rather than
    // waiting for an event that will never come.
    pumping.store(false, Ordering::Relaxed);
    pump_task.abort();
    drain_task.abort();
    let delivered = drained.load(Ordering::Relaxed);

    let record = format!(
        "{{\"profile\":\"{}\",\"protected\":{},\"entry_connections\":{},\"middle_connections\":{},\"seed\":{},\"listen_a\":\"{}\",\"listen_b\":\"{}\",\"chat_count\":{},\"chat_sent\":{},\"chat_p50_ms\":{:.3},\"chat_p95_ms\":{:.3},\"chat_max_ms\":{:.3},\"single_delay_ms\":{:.3},\"single_one_way_ms\":{:.3},\"bulk_chunk\":{},\"bulk_chunks\":{},\"bulk_acked_bytes\":{},\"bulk_goodput_kib_s\":{:.3},\"failures\":{},\"recipient_drained\":{},\"sender_jobs\":{},\"sender_bytes\":{}}}\n",
        args.profile,
        args.protected,
        entry_connections
            .as_ref()
            .map(|count| count.load(Ordering::SeqCst))
            .unwrap_or(0),
        middle_connections
            .as_ref()
            .map(|count| count.load(Ordering::SeqCst))
            .unwrap_or(0),
        args.seed,
        recipient_addr,
        sender_addr,
        args.chat_count,
        chat_sent,
        chat_p50_ms,
        chat_p95_ms,
        chat_max_ms,
        single_delay_ms,
        single_one_way_ms,
        args.bulk_chunk,
        bulk_chunks,
        bulk_acked_bytes,
        goodput_kib_s,
        failures,
        delivered,
        diagnostics.resources.jobs,
        diagnostics.resources.bytes,
    );
    if let Some(path) = &args.json {
        std::fs::write(path, record.as_bytes()).map_err(|e| e.to_string())?;
    }
    print!("{record}");
    sender.shutdown().await;
    recipient.shutdown().await;
    Ok(())
}
