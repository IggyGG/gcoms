//! Isolated transport measurements, never an application delivery/ anonymity gate.
//! All listeners and destinations are hard-coded loopback fixtures. Captures
//! contain byte counts and relative times only, never ciphertext or identifiers.
use bytes::Bytes;
use gcoms_core::{Cell, CellType};
use gcoms_node::{
    alias::AliasContact,
    relay::{RelayPush, RelayTarget},
    scheduler::{LaneAuth, ProducerClass, RelayScheduler},
};
use gcoms_routing::{
    carrier::CarrierConfig, route::now_unix, Directory, OnionConnector, RelayService, ServicePolicy,
};
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, HopOutcome, TokenRegistry, Tp1Client};
use serde::Serialize;
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;
const PUSH_CAP: [u8; 32] = [19; 32];
const QUEUE_ID: [u8; 32] = [23; 32];
const MAX_SAMPLES: usize = 65_536;

#[path = "relay_performance/utilization.rs"]
mod utilization;

#[cfg(target_os = "linux")]
fn resources() -> (u64, u64) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // getrusage writes one rusage value; failure is reported as unavailable (0).
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return (0, 0);
    }
    let usage = unsafe { usage.assume_init() };
    let cpu = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as u64 * 1_000_000
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as u64;
    (cpu, usage.ru_maxrss as u64)
}

#[cfg(not(target_os = "linux"))]
fn resources() -> (u64, u64) {
    (0, 0)
}

#[derive(Clone, Serialize)]
struct Sample {
    us: u64,
    direction: u8,
    bytes: usize,
}

#[derive(Default)]
struct Trace {
    start: Option<Instant>,
    samples: Vec<Sample>,
    bytes: [u64; 2],
    dropped: u64,
    connections: u64,
}

impl Trace {
    fn record(&mut self, direction: usize, bytes: usize) {
        let Some(start) = self.start else {
            return;
        };
        self.bytes[direction] += bytes as u64;
        if self.samples.len() == MAX_SAMPLES {
            self.dropped += 1;
            return;
        }
        self.samples.push(Sample {
            us: start.elapsed().as_micros() as u64,
            direction: direction as u8,
            bytes,
        });
    }
}

struct Fixture {
    tasks: Vec<JoinHandle<()>>,
    traces: Vec<Arc<Mutex<Trace>>>,
    services: Vec<Arc<RelayService>>,
    directory: Arc<Directory>,
    terminal: SocketAddr,
    terminal_pin: [u8; 32],
    slot_ms: u64,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn copy_observed<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
    trace: Arc<Mutex<Trace>>,
    direction: usize,
    delay_ms: u64,
) -> std::io::Result<()> {
    let mut buffer = [0; 32 * 1024];
    loop {
        let count = read.read(&mut buffer).await?;
        if count == 0 {
            write.shutdown().await?;
            return Ok(());
        }
        trace.lock().unwrap().record(direction, count);
        if delay_ms != 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        write.write_all(&buffer[..count]).await?;
    }
}

async fn proxy(
    ip: &str,
    backend: SocketAddr,
    delay_ms: u64,
) -> Result<(SocketAddr, Arc<Mutex<Trace>>, JoinHandle<()>)> {
    assert!(backend.ip().is_loopback());
    let listener = TcpListener::bind(format!("{ip}:0")).await?;
    let address = listener.local_addr()?;
    let trace = Arc::new(Mutex::new(Trace::default()));
    let captured = trace.clone();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((front, _)) = accepted else { break; };
                    captured.lock().unwrap().connections += 1;
                    let trace = captured.clone();
                    connections.spawn(async move {
                        let back = TcpStream::connect(backend).await?;
                        front.set_nodelay(true)?;
                        back.set_nodelay(true)?;
                        let (fr, fw) = front.into_split();
                        let (br, bw) = back.into_split();
                        tokio::try_join!(copy_observed(fr, bw, trace.clone(), 0, delay_ms), copy_observed(br, fw, trace, 1, delay_ms))?;
                        Ok::<_, std::io::Error>(())
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    Ok((address, trace, task))
}

impl Fixture {
    async fn new(slot_ms: u64, delay_ms: u64) -> Result<Self> {
        let directory = Arc::new(Directory::new());
        let mut result = Self {
            tasks: vec![],
            traces: vec![],
            services: vec![],
            directory,
            terminal: "127.0.0.99:0".parse()?,
            terminal_pin: [0; 32],
            slot_ms,
        };
        for index in 0..3u8 {
            let ip = format!("127.0.0.{}", index + 2);
            let identity = TlsIdentity::generate()?;
            let pin = identity.service_id();
            let registry = TokenRegistry::new();
            registry.insert_post("performance-fixture");
            registry.insert_post(&gcoms_transport::encode_b64url(&QUEUE_ID));
            let server = Tp1Server::bind_with_identity(
                format!("{ip}:0").parse()?,
                registry,
                Arc::new(move |_, cell| {
                    if cell.raw_type == CellType::RelayPush as u8 {
                        let pushed =
                            RelayPush::decode_from_cell(&cell, &PUSH_CAP, &pin, now_unix())
                                .map_err(|_| gcoms_transport::server::QueueReject::Unauthorized)?;
                        Ok(pushed.msg)
                    } else {
                        Ok(Some(cell))
                    }
                }),
                Arc::new(|_| None),
                &identity,
            )
            .await?;
            let (address, trace, proxy_task) = proxy(&ip, server.local_addr()?, delay_ms).await?;
            result.tasks.push(proxy_task);
            result.traces.push(trace);
            let server = if index < 2 {
                let service = RelayService::new(
                    address,
                    pin,
                    [index + 30; 32],
                    Arc::new(Directory::new()),
                    ServicePolicy {
                        carrier: CarrierConfig {
                            slot: Duration::from_millis(slot_ms),
                            ..CarrierConfig::default()
                        },
                        target_allowed: Arc::new(|address| address.ip().is_loopback()),
                        ..ServicePolicy::default()
                    },
                )?;
                result
                    .directory
                    .install(service.introduction(now_unix()), now_unix())?;
                let server = server.with_duplex(service.handler());
                result.services.push(service);
                server
            } else {
                result.terminal = address;
                result.terminal_pin = pin;
                server
            };
            result.tasks.push(tokio::spawn(async move {
                let _ = server.run_until(std::future::pending::<()>()).await;
            }));
        }
        Ok(result)
    }

    fn client(&self, onion: bool) -> Result<Tp1Client> {
        if onion {
            let connector =
                OnionConnector::new(self.directory.clone()).with_carrier_config(CarrierConfig {
                    slot: Duration::from_millis(self.slot_ms),
                    ..CarrierConfig::default()
                })?;
            Tp1Client::with_connector(Arc::new(connector))
        } else {
            Tp1Client::new()
        }
    }

    fn contact(&self) -> AliasContact {
        AliasContact {
            target: RelayTarget {
                address: self.terminal,
                relay_service_id: self.terminal_pin,
            },
            queue_id: QUEUE_ID,
            epoch: 1,
            push_cap: PUSH_CAP,
            expiry: now_unix() + 600,
        }
    }
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    onion: bool,
    scheduled: bool,
    slot_ms: u64,
    window: usize,
    idle: bool,
    mixed: bool,
    delay_ms: u64,
}

struct StopScheduler(RelayScheduler);

impl Drop for StopScheduler {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

async fn trial(case: Case, repeat: usize, quick: bool) -> Result<serde_json::Value> {
    let fixture = Fixture::new(case.slot_ms, case.delay_ms).await?;
    let client = Arc::new(fixture.client(case.onion)?);
    let warming = Instant::now();
    client.warm(fixture.terminal, fixture.terminal_pin).await?;
    let warm_us = warming.elapsed().as_micros() as u64;
    let scheduler = RelayScheduler::new(client.clone());
    // Also stop workers when a trial errors or its timeout cancels this future.
    let _stop_scheduler = StopScheduler(scheduler.clone());
    scheduler.enable_diagnostics();
    if case.scheduled {
        scheduler
            .open_lane(
                LaneAuth::Push {
                    contact: fixture.contact(),
                },
                true,
            )
            .map_err(|e| e.to_string())?;
    }
    // Warmup is recorded separately, excluded from the steady-state samples.
    let start = Instant::now();
    let (cpu_start, _) = resources();
    for trace in &fixture.traces {
        trace.lock().unwrap().start = Some(start);
    }
    let count = if case.idle {
        0
    } else if quick {
        2
    } else {
        8
    };
    let mut pending = JoinSet::new();
    let mut next = 0;
    let mut latencies = Vec::new();
    let mut useful_bytes = 0;
    while next < count || !pending.is_empty() {
        while next < count && pending.len() < case.window {
            let size = if case.mixed && next % 2 == 0 {
                128
            } else {
                12_000
            };
            let payload = vec![next as u8; size];
            let cell = Cell::new(CellType::Msg, 0, next as u16, payload.clone());
            let queued = Instant::now();
            let contact = fixture.contact();
            let client = client.clone();
            let receipt = if case.scheduled {
                Some(
                    scheduler
                        .push(ProducerClass::Direct, contact.clone(), cell.clone())
                        .map_err(|e| e.to_string())?,
                )
            } else {
                None
            };
            pending.spawn(async move {
                let reply = if let Some(receipt) = receipt {
                    let wire = receipt.completion().await.accepted()?;
                    gcoms_core::decode(&wire)?
                } else {
                    let outcome = client
                        .post_cell_pinned(
                            contact.target.address,
                            contact.target.relay_service_id,
                            "performance-fixture",
                            Bytes::from(cell.encode_wire()?),
                        )
                        .await?;
                    let HopOutcome::Accepted(Some(reply)) = outcome else {
                        return Err("fixture did not echo".into());
                    };
                    reply
                };
                if reply.payload != payload {
                    return Err("synthetic payload mismatch".into());
                }
                Ok::<_, Error>((queued.elapsed().as_micros() as u64, size))
            });
            next += 1;
        }
        if let Some(result) = pending.join_next().await {
            let (us, size) = result??;
            latencies.push(json!({"us": us, "payload_bytes": size}));
            useful_bytes += size;
        }
    }
    let transfer_us = start.elapsed().as_micros() as u64;
    let minimum = Duration::from_secs(if quick {
        2
    } else if case.idle && case.scheduled {
        30
    } else {
        8
    });
    if let Some(remaining) = minimum.checked_sub(start.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    let measurement_us = start.elapsed().as_micros() as u64;
    let (cpu_end, peak_rss_kib) = resources();
    // Freeze each observer while the streams are still open, excluding teardown.
    let observers = fixture.traces.iter().enumerate().map(|(index, trace)| {
        let mut trace = trace.lock().unwrap();
        trace.start = None;
        json!({"fixture_link": index, "bytes": trace.bytes, "samples": trace.samples, "dropped": trace.dropped})
    }).collect::<Vec<_>>();
    let diagnostics = scheduler.diagnostics_snapshot();
    scheduler.shutdown();
    Ok(json!({
        "case": case.name, "repeat": repeat, "onion": case.onion,
        "application_schedule": if case.scheduled { "production" } else { "transport_only" },
        "carrier_slot_ms": case.slot_ms, "window": case.window,
        "per_copy_delay_ms": case.delay_ms, "warm_us": warm_us,
        "useful_bytes": useful_bytes, "transfer_us": transfer_us,
        "measurement_us": measurement_us, "completions": latencies,
        "process_cpu_us": cpu_end.saturating_sub(cpu_start),
        "process_peak_rss_kib": peak_rss_kib,
        "scheduler": diagnostics, "observers": observers,
    }))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let mut output = None::<PathBuf>;
    let mut quick = false;
    let mut utilization = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--quick" => quick = true,
            "--utilization" => utilization = true,
            "--output" => output = Some(args.next().ok_or("--output needs a path")?.into()),
            _ => {
                return Err(
                    "usage: relay_performance [--quick] [--utilization] --output NEW_FILE.json"
                        .into(),
                )
            }
        }
    }
    let output = output.ok_or("--output is required")?;
    if utilization {
        return utilization::run(&output, quick).await;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output)?;
    let base = Case {
        name: "",
        onion: true,
        scheduled: false,
        slot_ms: 100,
        window: 1,
        idle: false,
        mixed: false,
        delay_ms: 0,
    };
    let cases = [
        Case {
            name: "idle_carrier_100ms",
            idle: true,
            ..base
        },
        Case {
            name: "idle_production_scheduler_carrier_100ms",
            idle: true,
            scheduled: true,
            ..base
        },
        Case {
            name: "direct_window_1",
            onion: false,
            ..base
        },
        Case {
            name: "carrier_100ms_window_1",
            ..base
        },
        Case {
            name: "carrier_100ms_window_4",
            window: 4,
            ..base
        },
        Case {
            name: "carrier_20ms_window_4",
            slot_ms: 20,
            window: 4,
            ..base
        },
        Case {
            name: "mixed_carrier_100ms",
            window: 4,
            mixed: true,
            ..base
        },
        Case {
            name: "delayed_carrier_100ms",
            window: 4,
            delay_ms: 20,
            ..base
        },
        Case {
            name: "production_scheduler_carrier_100ms",
            scheduled: true,
            window: 4,
            ..base
        },
    ];
    let mut trials = vec![];
    let mut failed = false;
    for repeat in 0..if quick { 1 } else { 3 } {
        for case in cases {
            eprintln!("measuring {} repeat {}", case.name, repeat);
            let result =
                tokio::time::timeout(Duration::from_secs(180), trial(case, repeat, quick)).await;
            match result {
                Ok(Ok(value)) => trials.push(value),
                error => {
                    failed = true;
                    // Errors are deliberately categorized without transport addresses.
                    trials.push(json!({"case": case.name, "repeat": repeat, "error": if error.is_err() { "timeout" } else { "fixture_failed" }}));
                }
            }
        }
    }
    let report = json!({
        "schema": 1, "kind": "loopback_transport_study", "quick": quick,
        "sample_unit": "tcp_read_chunk_not_packet", "payload": "generated_non_executable_bytes",
        "privacy_verdict": "not_qualified", "trials": trials,
    });
    serde_json::to_writer_pretty(&mut file, &report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    if failed {
        return Err("one or more trials failed; evidence retained".into());
    }
    Ok(())
}
