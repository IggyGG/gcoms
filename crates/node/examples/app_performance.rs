//! Application-level goodput and latency harness for the GC/2 carrier
//! comparison. Loopback only; disposable, atomically persisted node archives.
//! This is a protocol fixture, not an installed GChat qualification.
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
use gcoms_routing::gc2::{CandidateProfile, CoverMode};
use gcoms_routing::{route::now_unix, Directory, RelayService, ServicePolicy};
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
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
    measurement_ms: u64,
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
    traffic_profile: Option<CandidateProfile>,
    warmup_ms: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        profile: "gc1".into(),
        protected: false,
        entries: 2,
        cadence: "compressed".into(),
        drain_ms: 5000,
        idle_ms: 0,
        measurement_ms: 0,
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
        traffic_profile: None,
        warmup_ms: 0,
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
            "--measurement-ms" => {
                args.measurement_ms = value()?.parse::<u64>().map_err(|e| e.to_string())?
            }
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
            "--warmup-ms" => args.warmup_ms = value()?.parse::<u64>().map_err(|e| e.to_string())?,
            "--traffic-profile" => {
                let selection = value()?;
                let parts: Vec<_> = selection.split('/').collect();
                if parts.len() != 3 {
                    return Err(
                        "traffic profile must be full|interactive|jitter/record-bytes/period-ms"
                            .into(),
                    );
                }
                let mode = match parts[0] {
                    "full" => CoverMode::Full,
                    "interactive" => CoverMode::Interactive,
                    "jitter" => CoverMode::InteractiveJitter,
                    _ => return Err("unknown traffic profile mode".into()),
                };
                args.traffic_profile = Some(
                    CandidateProfile::new(
                        parts[1].parse().map_err(|_| "invalid record bytes")?,
                        parts[2].parse().map_err(|_| "invalid period")?,
                    )
                    .map_err(|e| e.to_string())?
                    .with_mode(mode),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if !matches!(args.profile.as_str(), "gc1" | "gc2" | "gchat-files") {
        return Err("--profile must be gc1, gc2 or gchat-files".into());
    }
    if args.profile == "gchat-files" && (!args.protected || args.cadence != "production") {
        return Err("gchat-files requires --protected --cadence production".into());
    }
    if args.chat_count == 0 && args.bulk_bytes == 0 && args.idle_ms == 0 && args.measurement_ms == 0
    {
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
    if args.chat_count > 10000 || args.bulk_bytes > 128 * 1024 * 1024 || args.timeout.is_zero() {
        return Err(
            "bounded fixture requires <=10000 chats, <=128 MiB bulk and a positive timeout".into(),
        );
    }
    if args.protected
        && (!matches!(args.profile.as_str(), "gc2" | "gchat-files")
            || !(1..=3).contains(&args.entries))
    {
        return Err("protected fixture requires GC/2 with 1..3 entries".into());
    }
    if args.profile == "gchat-files"
        && args
            .traffic_profile
            .is_some_and(|p| p != CandidateProfile::file_transfer())
    {
        return Err("gchat-files requires its fixed authenticated traffic profile".into());
    }
    if args.traffic_profile.is_some() && !args.protected {
        return Err("traffic profile comparison requires protected GC/2 circuits".into());
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
        "gchat-files" => {
            let NodeProfile::Fixture(mut fixture) =
                NodeProfile::gc2_carrier_production_cadence_fixture_seeded(
                    None,
                    entries,
                    introductions.to_vec(),
                )
            else {
                unreachable!()
            };
            fixture.gc2_cover_mode = gcoms_routing::gc2::CoverMode::Interactive;
            NodeProfile::Fixture(fixture)
        }
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
        "gc2" if production => {
            NodeProfile::gc2_carrier_production_cadence_fixture_seeded(None, 0, Vec::new())
        }
        "gc2" => NodeProfile::gc2_carrier_qualification_fixture(None, 0, seed),
        _ if production => NodeProfile::production_cadence_fixture(),
        _ => NodeProfile::compressed_production(seed),
    }
}

/// One loopback relay service with a GC/2 dispatch factory; the returned
/// counter advances on every dialed circuit.
async fn start_relay(
    ip: &str,
    production: bool,
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
            carrier: if production {
                gcoms_routing::carrier::CarrierConfig::default()
            } else {
                gcoms_routing::carrier::CarrierConfig::fixture()
            },
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
async fn protected_relays(
    production: bool,
) -> (
    Vec<Vec<u8>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Vec<tokio::task::JoinHandle<()>>,
    std::net::SocketAddr,
    std::net::SocketAddr,
) {
    let (entry, entry_connections, entry_task) = start_relay("127.0.0.86", production).await;
    let (middle, middle_connections, middle_task) = start_relay("127.0.0.87", production).await;
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
        entry.address(),
        middle.address(),
    )
}

async fn endpoint(
    seed: u8,
    profile: NodeProfile,
    listen: std::net::SocketAddr,
    archive: PathBuf,
) -> NodeHandle {
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
            let parent = archive.parent().ok_or("archive has no directory")?;
            let mut temporary =
                tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
            gcoms_private_fs::make_private(temporary.path(), false)?;
            temporary
                .write_all(&bytes)
                .and_then(|_| temporary.as_file().sync_all())
                .map_err(|e| e.to_string())?;
            temporary.persist(&archive).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| e.to_string())?;
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

/// Expected contents are keyed by the actual protocol message ID. Arrival may
/// race registration; the drain retries unknown IDs until registration finishes.
#[derive(Default)]
struct DeliveryLedger {
    expected: BTreeMap<[u8; 16], [u8; 32]>,
    received: BTreeMap<[u8; 16], [u8; 32]>,
    errors: Vec<String>,
}

impl DeliveryLedger {
    fn register(&mut self, id: [u8; 16], body: &[u8]) {
        if self
            .expected
            .insert(id, Sha256::digest(body).into())
            .is_some()
        {
            self.errors.push("duplicate sender message ID".into());
        }
    }

    fn verify(&mut self, id: [u8; 16], body: &[u8]) -> bool {
        let Some(expected) = self.expected.get(&id) else {
            return false;
        };
        let actual: [u8; 32] = Sha256::digest(body).into();
        if *expected != actual || self.received.contains_key(&id) {
            self.errors
                .push("recipient contents or uniqueness mismatch".into());
            return false;
        }
        true
    }

    fn exact(&self, requested: usize) -> bool {
        self.errors.is_empty() && self.expected.len() == requested && self.received == self.expected
    }
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
    inflight: usize,
    hub: &Arc<AckHub>,
    ledger: &Arc<Mutex<DeliveryLedger>>,
    timeout: Duration,
) -> (Vec<f64>, usize, usize, Vec<f64>) {
    let mut latencies = Vec::with_capacity(count);
    let admissions = Mutex::new(Vec::with_capacity(count));
    let sent = AtomicUsize::new(0);
    let mut failures = 0usize;
    let epoch = tokio::time::Instant::now();
    let permits = tokio::sync::Semaphore::new(inflight);
    let mut offered = FuturesUnordered::new();
    for index in 0..count {
        let permits = &permits;
        let sent = &sent;
        let admissions = &admissions;
        offered.push(async move {
            let scheduled = epoch + interval * index as u32;
            tokio::time::sleep_until(scheduled).await;
            let admitted = async {
                let _permit = permits.acquire().await.map_err(|e| e.to_string())?;
                let id = sender.send_durable_1to1_tracked(peer, body, None).await?;
                ledger.lock().unwrap().register(id, body);
                sent.fetch_add(1, Ordering::Relaxed);
                admissions
                    .lock()
                    .unwrap()
                    .push(scheduled.elapsed().as_secs_f64());
                let delivered = hub.wait(id).await;
                Ok::<_, String>(delivered.map(|at| {
                    at.saturating_duration_since(scheduled.into_std())
                        .as_secs_f64()
                }))
            };
            tokio::time::timeout_at(scheduled + timeout, admitted).await
        });
    }
    while let Some(result) = offered.next().await {
        match result {
            Ok(Ok(Some(latency))) => latencies.push(latency),
            _ => failures += 1,
        }
    }
    drop(offered);
    (
        latencies,
        sent.load(Ordering::Relaxed),
        failures,
        admissions.into_inner().unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
async fn bulk_stream(
    sender: &NodeHandle,
    peer: &NodeInfo,
    total_bytes: usize,
    chunk: usize,
    inflight: usize,
    hub: &Arc<AckHub>,
    ledger: &Arc<Mutex<DeliveryLedger>>,
    timeout: Duration,
) -> (usize, usize, usize, f64) {
    let start = Instant::now();
    let mut acked_bytes = 0usize;
    let mut acked = 0usize;
    let mut failures = 0usize;
    let mut offset = 0usize;
    let mut flight = FuturesUnordered::new();
    loop {
        while flight.len() < inflight && offset < total_bytes {
            let bytes = chunk.min(total_bytes - offset);
            // Distinct contents by offset; the final record is never rounded up.
            let data: Vec<u8> = (offset..offset + bytes)
                .map(|n| (n.wrapping_mul(73) ^ (n >> 8)) as u8)
                .collect();
            let body = file_record_body(&data);
            offset += bytes;
            match sender.send_durable_1to1_tracked(peer, &body, None).await {
                Ok(id) => {
                    ledger.lock().unwrap().register(id, &body);
                    let hub = hub.clone();
                    flight.push(async move {
                        tokio::time::timeout(timeout, hub.wait(id))
                            .await
                            .ok()
                            .flatten()
                            .map(|_| bytes)
                    });
                }
                Err(_) => failures += 1,
            }
        }
        if flight.is_empty() {
            break;
        }
        match flight.next().await {
            Some(Some(bytes)) => {
                acked += 1;
                acked_bytes += bytes;
            }
            Some(None) => failures += 1,
            None => break,
        }
    }
    (acked_bytes, acked, failures, start.elapsed().as_secs_f64())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), String> {
    let args = parse_args()?;
    if let Some(path) = &args.json {
        let metrics = path.with_extension("metrics.jsonl");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&metrics)
            .map_err(|e| e.to_string())?;
        gcoms_node::metrics::init(&metrics).map_err(|e| e.to_string())?;
    }
    let archive_directory = tempfile::Builder::new()
        .prefix("gc2-app-evidence-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let ledger = Arc::new(Mutex::new(DeliveryLedger::default()));
    let (
        introductions,
        entry_connections,
        middle_connections,
        _relay_tasks,
        entry_addr,
        middle_addr,
    ) = if args.protected {
        let (introductions, entry, middle, tasks, entry_addr, middle_addr) =
            protected_relays(args.cadence == "production").await;
        (
            introductions,
            Some(entry),
            Some(middle),
            tasks,
            Some(entry_addr),
            Some(middle_addr),
        )
    } else {
        (Vec::new(), None, None, Vec::new(), None, None)
    };
    let selected_profile = || -> Result<NodeProfile, String> {
        let selected = profile(
            &args.profile,
            args.seed,
            &introductions,
            args.entries,
            &args.cadence,
        );
        match args.traffic_profile {
            Some(candidate) => selected.with_gc2_traffic_profile(candidate),
            None => Ok(selected),
        }
    };
    let listen_a: std::net::SocketAddr = format!("127.0.0.1:{}", args.listen_a).parse().unwrap();
    let listen_b: std::net::SocketAddr = format!("127.0.0.1:{}", args.listen_b).parse().unwrap();
    let recipient = endpoint(
        0x51,
        selected_profile()?,
        listen_a,
        archive_directory.path().join("recipient.bin"),
    )
    .await;
    let sender = endpoint(
        0x52,
        selected_profile()?,
        listen_b,
        archive_directory.path().join("sender.bin"),
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
        let ledger = ledger.clone();
        async move {
            let mut after = 0u64;
            while draining.load(Ordering::Relaxed) {
                match recipient.application_inbox(after, 32).await {
                    Ok(entries) if !entries.is_empty() => {
                        for entry in entries {
                            if !ledger.lock().unwrap().verify(entry.message_id, &entry.body) {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                break;
                            }
                            if recipient
                                .commit_application(entry.sequence, entry.digest())
                                .await
                                .is_ok()
                            {
                                ledger
                                    .lock()
                                    .unwrap()
                                    .received
                                    .insert(entry.message_id, Sha256::digest(&entry.body).into());
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

    let chat_body = vec![0x41; args.chat_bytes];
    let chat_interval = Duration::from_millis(args.chat_interval_ms);
    let bulk_total = args.bulk_bytes.div_ceil(args.bulk_chunk);
    if args.warmup_ms > 0 {
        tokio::time::sleep(Duration::from_millis(args.warmup_ms)).await;
    }
    let measurement_clock = Instant::now();
    let measure_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs_f64();
    println!("MEASUREMENT_START {measure_start:.6}");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let chat = chat_stream(
        &sender,
        &peer,
        &chat_body,
        args.chat_count,
        chat_interval,
        args.inflight,
        &hub,
        &ledger,
        args.timeout,
    );
    let bulk = bulk_stream(
        &sender,
        &peer,
        args.bulk_bytes,
        args.bulk_chunk,
        args.inflight,
        &hub,
        &ledger,
        args.timeout,
    );
    let (chat, bulk) = tokio::join!(chat, bulk);
    let measurement_overrun = args.measurement_ms > 0
        && measurement_clock.elapsed() > Duration::from_millis(args.measurement_ms);
    // Keep complete delivery/failure evidence even when the fixed interval was
    // exceeded. Such a run must fail instead of being relabeled as a shorter run.
    let measurement_end = if args.measurement_ms > 0 {
        tokio::time::sleep(
            Duration::from_millis(args.measurement_ms).saturating_sub(measurement_clock.elapsed()),
        )
        .await;
        let end = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs_f64();
        println!("MEASUREMENT_END {end:.6}");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        Some(end)
    } else {
        None
    };

    // Workload results are final once both streams join.
    let (mut chat_latencies, chat_sent, chat_failures, mut admission_latencies) = chat;
    let chat_acked = chat_latencies.len();
    let (bulk_acked_bytes, bulk_chunks, bulk_failures, bulk_elapsed) = bulk;
    let failures = chat_failures + bulk_failures;
    chat_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let chat_p50_ms = percentile(&chat_latencies, 0.5) * 1000.0;
    let chat_p95_ms = percentile(&chat_latencies, 0.95) * 1000.0;
    let chat_max_ms = chat_latencies.last().copied().unwrap_or_default() * 1000.0;
    admission_latencies.sort_by(f64::total_cmp);
    let goodput_kib_s = if bulk_elapsed > 0.0 {
        bulk_acked_bytes as f64 / bulk_elapsed / 1024.0
    } else {
        0.0
    };
    let diagnostics = sender.diagnostics();

    // An explicit idle phase runs after the workload so captures can compare
    // ongoing activity with idle periods that follow it on warm circuits. The
    // marker lets a capture drop everything before the idle window.
    if args.idle_ms > 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        println!("IDLE_START {}.{:06}", now.as_secs(), now.subsec_micros());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        tokio::time::sleep(Duration::from_millis(args.idle_ms)).await;
    }
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
        ledger.lock().unwrap().register(id, &chat_body);
        let (one_way, arrival) = {
            let deadline = Instant::now() + args.timeout;
            let mut arrived = -1.0f64;
            let mut arrival = None;
            while Instant::now() < deadline {
                if let Ok(entries) = recipient.application_inbox(0, 32).await {
                    if let Some(entry) = entries.iter().find(|entry| entry.message_id == id) {
                        if !ledger.lock().unwrap().verify(id, &entry.body) {
                            return Err("single-message contents mismatch".into());
                        }
                        arrived = single_start.elapsed().as_secs_f64() * 1000.0;
                        arrival = Some((entry.sequence, entry.digest()));
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            (arrived, arrival)
        };
        if let Some((sequence, digest)) = arrival {
            if recipient.commit_application(sequence, digest).await.is_ok() {
                ledger
                    .lock()
                    .unwrap()
                    .received
                    .insert(id, Sha256::digest(&chat_body).into());
                drained.fetch_add(1, Ordering::Relaxed);
            }
        }
        let round_trip = match tokio::time::timeout(args.timeout, hub.wait(id)).await {
            Ok(Some(_)) => single_start.elapsed().as_secs_f64() * 1000.0,
            _ => -1.0,
        };
        (round_trip, one_way)
    };

    // Wait for the receiver to commit every durable receipt before stopping.
    let expected_receipts = args.chat_count + bulk_total + usize::from(!args.skip_single);
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

    let (record, exact_delivery) = {
        let evidence = ledger.lock().unwrap();
        let exact_delivery = evidence.exact(expected_receipts);
        let record = serde_json::json!({
            "schema": 2, "fixture": "loopback_protocol", "persistence": "atomic_fsync_node_archive",
            "profile": args.profile, "protected": args.protected, "cadence": args.cadence,
            "traffic_profile_id": args.traffic_profile
                .or_else(|| (args.profile == "gchat-files").then(CandidateProfile::file_transfer))
                .map(|p| p.id()),
            "entry_connections": entry_connections.as_ref().map(|v| v.load(Ordering::SeqCst)).unwrap_or(0),
            "middle_connections": middle_connections.as_ref().map(|v| v.load(Ordering::SeqCst)).unwrap_or(0),
            "seed": args.seed, "listen_a": recipient_addr.to_string(), "listen_b": sender_addr.to_string(),
            "entry_addr": entry_addr.map(|a| a.to_string()).unwrap_or_default(),
            "middle_addr": middle_addr.map(|a| a.to_string()).unwrap_or_default(),
            "chat_count": args.chat_count, "chat_acked": chat_acked,
            "chat_sent": chat_sent,
            "chat_p50_ms": chat_p50_ms, "chat_p95_ms": chat_p95_ms, "chat_max_ms": chat_max_ms,
            "admission_p95_ms": percentile(&admission_latencies, 0.95) * 1000.0,
            "single_delay_ms": single_delay_ms, "single_one_way_ms": single_one_way_ms,
            "bulk_bytes": args.bulk_bytes, "bulk_chunk": args.bulk_chunk, "bulk_chunks": bulk_chunks,
            "bulk_acked_bytes": bulk_acked_bytes, "bulk_goodput_kib_s": goodput_kib_s,
            "bulk_elapsed_seconds": bulk_elapsed, "failures": failures, "recipient_drained": delivered,
            "requested_receipts": expected_receipts, "exact_delivery": exact_delivery,
            "delivery_errors": evidence.errors,
            "measurement_start_epoch": measure_start,
            "measurement_end_epoch": measurement_end,
            "measurement_requested_ms": args.measurement_ms,
            "measurement_overrun": measurement_overrun,
            "sender_jobs": diagnostics.resources.jobs, "sender_bytes": diagnostics.resources.bytes,
        });
        (record, exact_delivery)
    };
    let record = serde_json::to_string(&record).map_err(|e| e.to_string())? + "\n";
    if let Some(path) = &args.json {
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        output
            .write_all(record.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    print!("{record}");
    sender.shutdown().await;
    recipient.shutdown().await;
    if measurement_overrun
        || !exact_delivery
        || failures != 0
        || bulk_acked_bytes != args.bulk_bytes
    {
        return Err("incomplete or incorrect durable delivery; retain the failed run".into());
    }
    Ok(())
}
