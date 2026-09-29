//! One pinned TLS connection with two permanent GCT2 class channels. The owner
//! polls `run` continuously for its connected period; sending a chat message must
//! never create this connection or restart its schedule.
use super::{channel, mux, CandidateProfile, RecordCodec, RecordKind, HEADER_LEN};
use crate::{route::now_unix, wire::Target, Result};
use bytes::Bytes;
use futures_util::{stream::FuturesUnordered, StreamExt};
use gcoms_core::TrafficClass;
use gcoms_transport::{connector::BoxStream, duplex::H2Stream, server::AcceptedDuplex, tls};
use std::{
    future::poll_fn,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, Semaphore},
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::TlsConnector;
use zeroize::Zeroize;

const CHANNEL_BUFFER: usize = 32 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_LIFETIME: Duration = Duration::from_secs(1800);

/// Opt-in local lifecycle evidence. No addresses, service IDs, capabilities,
/// application bytes or error strings are emitted. This observes the existing
/// deadline; it never changes authority, scheduling or reconnect behavior.
struct Lifecycle {
    id: u64,
    role: &'static str,
    started: Instant,
    expires_at: u64,
    deadline_ms: u128,
    enabled: bool,
    ended: bool,
}

impl Lifecycle {
    fn new(role: &'static str, expires_at: u64, deadline: Instant) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let enabled = std::env::var_os("GCOMS_GC2_LIFECYCLE").is_some_and(|v| v == "1");
        let started = Instant::now();
        let value = Self {
            id: if enabled {
                NEXT.fetch_add(1, Ordering::Relaxed)
            } else {
                0
            },
            role,
            started,
            expires_at,
            deadline_ms: deadline.saturating_duration_since(started).as_millis(),
            enabled,
            ended: false,
        };
        value.emit("started");
        value
    }

    fn emit(&self, phase: &'static str) {
        if !self.enabled {
            return;
        }
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        eprintln!(
            "gc2_entry_lifecycle {{\"id\":{},\"role\":\"{}\",\"phase\":\"{}\",\"unix_ms\":{},\"elapsed_ms\":{},\"authority_expires_at\":{},\"deadline_after_start_ms\":{},\"max_lifetime_ms\":{}}}",
            self.id, self.role, phase, wall_ms, self.started.elapsed().as_millis(),
            self.expires_at, self.deadline_ms, MAX_LIFETIME.as_millis(),
        );
    }

    fn finish(&mut self, phase: &'static str) {
        self.emit(phase);
        self.ended = true;
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        if !self.ended {
            self.emit("dropped");
        }
    }
}

#[cfg(test)]
#[path = "entry_lifetime_tests.rs"]
pub(crate) mod lifetime_tests;

/// Explicit GC/2 entry authority. It is deliberately a distinct type from a
/// GC/1 relay introduction; there is no implicit compatibility conversion.
#[derive(Clone)]
pub struct EntryDescriptor {
    pub addr: SocketAddr,
    pub service_id: [u8; 32],
    pub entry_cap: [u8; 32],
    pub expires_at: u64,
}

impl Drop for EntryDescriptor {
    fn drop(&mut self) {
        self.entry_cap.zeroize();
    }
}

impl EntryDescriptor {
    pub fn validate(&self) -> Result<()> {
        crate::wire::decode_address(&crate::wire::encode_address(self.addr))?;
        if self.service_id == [0; 32] || self.entry_cap == [0; 32] || self.expires_at <= now_unix()
        {
            return Err("invalid or expired GC/2 entry authority".into());
        }
        Ok(())
    }
}

/// Ready class multiplexors on exactly one physical connection. Cloning these
/// handles creates no connections. The run future owns every driver and stream.
#[derive(Clone)]
pub struct EntryCarrier {
    interactive: mux::MuxClient,
    bulk: mux::MuxClient,
    descriptor: EntryDescriptor,
    budget: Arc<mux::CircuitBudget>,
    nested: mpsc::Sender<NestedDriver>,
}

type NestedDriver = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

impl EntryCarrier {
    pub fn active_circuits(&self) -> usize {
        self.budget.active()
    }

    /// Construct the entry and three independently pinned middle extensions.
    /// The caller authenticates the fifth (terminal) relay inside the result.
    /// No new entry connection or profile change is triggered.
    pub async fn connect_via(
        &self,
        class: TrafficClass,
        middles: &super::path::MiddlePath,
        target: &Target,
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<BoxStream> {
        let entry = (self.descriptor.addr, self.descriptor.service_id);
        super::path::validate(entry, middles, target, excluded)?;
        let first = &middles[0];
        let mut stream: BoxStream = Box::new(
            self.open(
                class,
                &Target::Relay {
                    addr: first.addr,
                    service_id: first.service_id,
                },
            )
            .await?,
        );
        for (index, middle) in middles.iter().enumerate() {
            let next = middles.get(index + 1).map(|relay| Target::Relay {
                addr: relay.addr,
                service_id: relay.service_id,
            });
            let (extended, driver) =
                super::transit::open(stream, class, middle, next.as_ref().unwrap_or(target))
                    .await
                    .map_err(|error| format!("GC/2 middle {}: {error}", index + 1))?;
            self.nested
                .send(driver)
                .await
                .map_err(|_| "GC/2 entry owner stopped")?;
            stream = extended;
        }
        Ok(stream)
    }

    /// Extend to an adjacent relay. The complete route must be selected with all
    /// endpoint/terminal exclusions before this call; this repeats the entry
    /// exclusion instead of treating a shared connection as an exemption.
    pub async fn open(&self, class: TrafficClass, target: &Target) -> Result<mux::CircuitStream> {
        self.descriptor.validate()?;
        if let Target::Relay { addr, service_id } = target {
            if addr.ip() == self.descriptor.addr.ip() || service_id == &self.descriptor.service_id {
                return Err("GC/2 entry and adjacent relay must be independent".into());
            }
        }
        match class {
            TrafficClass::Interactive => self.interactive.open(target).await,
            TrafficClass::Bulk => self.bulk.open(target).await,
        }
    }
}

/// Run an explicitly selected entry on an already dialed socket. Both channels
/// and inner multiplexors start before publishing readiness, including bulk
/// when idle. Dropping this future synchronously drops the complete driver tree.
/// The owner controls authenticated re-entry and reconnect independently of chat.
pub async fn run(
    socket: BoxStream,
    descriptor: EntryDescriptor,
    profile: CandidateProfile,
    ready: oneshot::Sender<EntryCarrier>,
) -> Result<()> {
    descriptor.validate()?;
    let deadline = super::authority_deadline(descriptor.expires_at, MAX_LIFETIME)
        .ok_or("GC/2 entry authority expired")?;
    let mut lifecycle = Lifecycle::new("client", descriptor.expires_at, deadline);
    let result = timeout_at(deadline, async {
        let tls = timeout(HANDSHAKE_TIMEOUT, async {
            let tls = TlsConnector::from(Arc::new(tls::client_config_pinned(descriptor.service_id)?))
                .connect(tls::server_name_ip(descriptor.addr.ip()), socket).await?;
            if tls.get_ref().1.alpn_protocol() != Some(tls::ALPN_H2) {
                return Err("GC/2 entry did not negotiate HTTP2".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(tls)
        }).await.map_err(|_| "GC/2 entry TLS timeout")??;
        let (sender, driver) = h2::client::Builder::new()
            // A stopped bulk consumer can occupy only one 32 KiB window; the
            // connection retains another full window for interactive records.
            .initial_window_size(CHANNEL_BUFFER as u32)
            .initial_connection_window_size((CHANNEL_BUFFER * 2) as u32)
            .max_frame_size(16 * 1024)
            .max_send_buffer_size(CHANNEL_BUFFER)
            .max_header_list_size(1024)
            .header_table_size(0)
            .initial_max_send_streams(2)
            .max_concurrent_reset_streams(2)
            .max_pending_accept_reset_streams(2)
            .max_local_error_reset_streams(Some(2))
            .enable_push(false)
            .handshake(tls).await?;
        tokio::select! {
            result = driver => { result?; Err("GC/2 entry connection ended".into()) },
            result = async {
                let chat_codec = RecordCodec::new(TrafficClass::Interactive, profile);
                let bulk_codec = RecordCodec::new(TrafficClass::Bulk, profile);
                let (chat_wire, bulk_wire) = timeout(HANDSHAKE_TIMEOUT, async {
                    tokio::try_join!(
                        open_channel(sender.clone(), &descriptor, chat_codec),
                        open_channel(sender, &descriptor, bulk_codec),
                    )
                }).await.map_err(|_| "GC/2 channel handshake timed out")??;
                let (chat_io, chat_pump_io) = tokio::io::duplex(CHANNEL_BUFFER);
                let (bulk_io, bulk_pump_io) = tokio::io::duplex(CHANNEL_BUFFER);
                let first_slot = Instant::now() + profile.period();
                let budget = Arc::new(mux::CircuitBudget::default());
                tokio::select! {
                    result = channel::pump(chat_wire, chat_pump_io, chat_codec, first_slot) => {
                        result?; Err("GC/2 interactive channel ended".into())
                    },
                    result = channel::pump(bulk_wire, bulk_pump_io, bulk_codec, first_slot) => {
                        result?; Err("GC/2 bulk channel ended".into())
                    },
                    result = async {
                        let ((interactive, chat_driver), (bulk, bulk_driver)) = tokio::try_join!(
                            mux::MuxClient::handshake(chat_io, TrafficClass::Interactive, budget.clone()),
                            mux::MuxClient::handshake(bulk_io, TrafficClass::Bulk, budget.clone()),
                        )?;
                        let (nested, nested_rx) = mpsc::channel(mux::MAX_CIRCUITS);
                        let carrier = EntryCarrier { interactive, bulk, descriptor, budget, nested };
                        ready.send(carrier).map_err(|_| "GC/2 entry readiness owner dropped")?;
                        lifecycle.emit("class_muxes_ready");
                        tokio::select! {
                            result = chat_driver => { result?; Err("GC/2 interactive mux ended".into()) },
                            result = bulk_driver => { result?; Err("GC/2 bulk mux ended".into()) },
                            result = own_nested(nested_rx) => result,
                        }
                    } => result,
                }
            } => result,
        }
    }).await;
    lifecycle.finish(match &result {
        Err(_) => "deadline_elapsed",
        Ok(Err(_)) => "transport_ended",
        Ok(Ok(_)) => "completed",
    });
    result.map_err(|_| "GC/2 entry lifetime ended")?
}

async fn own_nested(mut receiver: mpsc::Receiver<NestedDriver>) -> Result<()> {
    let mut active = FuturesUnordered::new();
    let mut closed = false;
    loop {
        tokio::select! {
            driver = receiver.recv(), if !closed && active.len() < mux::MAX_CIRCUITS * super::path::MIDDLE_HOPS => {
                match driver { Some(driver) => active.push(driver), None => closed = true }
            },
            Some(()) = active.next(), if !active.is_empty() => (),
            // Dropping application handles must not change the connected cover
            // period. Only the root owner/lifetime ends the carrier.
            _ = std::future::pending::<()>() => unreachable!(),
        }
    }
}

async fn open_channel(
    mut sender: h2::client::SendRequest<Bytes>,
    descriptor: &EntryDescriptor,
    codec: RecordCodec,
) -> Result<H2Stream> {
    poll_fn(|cx| sender.poll_ready(cx)).await?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!(
            "https://{}/{}",
            descriptor.addr,
            gcoms_transport::encode_b64url(&descriptor.entry_cap)
        ))
        .header("content-type", "application/octet-stream")
        .body(())?;
    let (response, send) = sender.send_request(request, false)?;
    let mut pending = mux::PendingSend(Some(send));
    // The private service sends headers before reading Open. Any mismatch below
    // resets the stream through H2Stream's drop guard, without a GC/1 retry.
    let response = response.await?;
    if response.status() != 200 {
        return Err("GC/2 entry capability refused".into());
    }
    let mut stream = H2Stream::new(response.into_body(), pending.0.take().unwrap());
    let opened = codec.encode(RecordKind::Open, &[])?;
    stream.write_all(&opened).await?;
    let mut reply = vec![0; opened.len()];
    stream.read_exact(&mut reply).await?;
    if codec.decode(&reply)?.kind() != RecordKind::Open {
        return Err("GC/2 open acknowledgment required".into());
    }
    Ok(stream)
}

pub(crate) fn hold_capacity(
    io: BoxStream,
    permits: Vec<tokio::sync::OwnedSemaphorePermit>,
) -> BoxStream {
    Box::new(HeldStream {
        io,
        _permits: permits,
    })
}

struct HeldStream {
    io: BoxStream,
    _permits: Vec<tokio::sync::OwnedSemaphorePermit>,
}

impl tokio::io::AsyncRead for HeldStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HeldStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub(crate) struct ConnectionContext {
    pending: Arc<Semaphore>,
    selected: Mutex<(Option<CandidateProfile>, [bool; 2])>,
    budget: Arc<mux::CircuitBudget>,
}

impl Default for ConnectionContext {
    fn default() -> Self {
        Self {
            pending: Arc::new(Semaphore::new(2)),
            selected: Mutex::new((None, [false; 2])),
            budget: Arc::new(mux::CircuitBudget::default()),
        }
    }
}

impl ConnectionContext {
    pub(crate) fn accept(
        self: &Arc<Self>,
        expires_at: u64,
        connect: mux::TargetConnector,
    ) -> AcceptedDuplex {
        let context = self.clone();
        let permit = self.pending.clone().try_acquire_owned();
        Box::new(move |body, mut respond| {
            Box::pin(async move {
                let Some(deadline) = super::authority_deadline(expires_at, MAX_LIFETIME) else {
                    return;
                };
                let Ok(_permit) = permit else {
                    let _ = respond.send_response(
                        http::Response::builder().status(503).body(()).unwrap(),
                        true,
                    );
                    return;
                };
                let headers = http::Response::builder()
                    .header("content-type", "application/octet-stream")
                    .body(())
                    .unwrap();
                let Ok(send) = respond.send_response(headers, false) else {
                    return;
                };
                let wire = H2Stream::new(body, send);
                let mut lifecycle = Lifecycle::new("server_channel", expires_at, deadline);
                let result = timeout_at(deadline, context.serve(wire, connect)).await;
                lifecycle.finish(match result {
                    Err(_) => "deadline_elapsed",
                    Ok(Err(_)) => "transport_ended",
                    Ok(Ok(_)) => "completed",
                });
            })
        })
    }

    async fn serve(&self, mut wire: H2Stream, connect: mux::TargetConnector) -> Result<()> {
        let codec = timeout(HANDSHAKE_TIMEOUT, async {
            let mut header = [0; HEADER_LEN];
            wire.read_exact(&mut header).await?;
            let codec = RecordCodec::from_open_header(&header)?;
            let mut record = header.to_vec();
            record.resize(codec.wire_len(&header)?, 0);
            wire.read_exact(&mut record[HEADER_LEN..]).await?;
            codec.decode(&record)?;
            {
                let mut selected = self.selected.lock().unwrap_or_else(|p| p.into_inner());
                if selected.0.is_some_and(|profile| profile != codec.profile())
                    || selected.1[codec.class() as usize]
                {
                    return Err("GC/2 duplicate class or mismatched connection profile".into());
                }
                selected.0 = Some(codec.profile());
                selected.1[codec.class() as usize] = true;
            }
            wire.write_all(&record).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(codec)
        })
        .await
        .map_err(|_| "GC/2 channel open timed out")??;
        let (local, pumped) = tokio::io::duplex(CHANNEL_BUFFER);
        tokio::select! {
            result = channel::pump(wire, pumped, codec, Instant::now() + codec.profile().period()) => { result?; Ok(()) },
            result = mux::serve(local, codec.class(), self.budget.clone(), connect) => result,
        }
    }
}
