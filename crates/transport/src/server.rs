use crate::hop::HopReply;
use crate::token::{TokenKind, TokenRegistry};
use crate::{decoy, tls};
use bytes::Bytes;
use gcoms_core::{decode, Bucket, Cell, CellType};
use http::{Method, Response, StatusCode};
use std::collections::HashMap;
use std::error::Error;
use std::future::poll_fn;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_rustls::TlsAcceptor;

pub type CellHandler =
    Arc<dyn Fn(&str, Cell) -> Result<Option<Cell>, QueueReject> + Send + Sync + 'static>;
pub type QueueCellHandler =
    Arc<dyn Fn(&str, Cell) -> Result<Option<Cell>, QueueReject> + Send + Sync + 'static>;
pub type AcceptedStream = Box<dyn FnOnce(StreamSink) + Send + 'static>;
pub type StreamHandler = Arc<dyn Fn(&[u8]) -> Option<AcceptedStream> + Send + Sync + 'static>;
/// The service authenticates the private path before returning a handler. The
/// server owns the returned future, including cancellation at transport shutdown.
pub type AcceptedDuplex = Box<
    dyn FnOnce(
            h2::RecvStream,
            h2::server::SendResponse<Bytes>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send,
>;
pub type DuplexHandler = Arc<dyn Fn(&str) -> Option<AcceptedDuplex> + Send + Sync>;
/// Creates isolated service state once per established TLS/HTTP2 connection.
/// All duplex paths on that connection share the returned handler. Creation is
/// not private-service authorization: each path must still be authenticated.
/// Keep this state lightweight; per-stream allocations follow path admission.
pub type DuplexHandlerFactory = Arc<dyn Fn() -> DuplexHandler + Send + Sync>;

/// Connection-wide dispatch runs before registered endpoints and legacy duplex
/// services. Rejection is final and does not authenticate an unknown source.
pub enum Dispatch {
    /// Continue ordinary registry/duplex routing.
    Pass,
    /// Uniform decoy response, without invoking any later endpoint handler.
    Rejected,
    /// The private path is authenticated; own this service future as usual.
    Accepted(AcceptedDuplex),
}
/// The boolean indicates a currently registered private path, not body-level
/// queue authorization. A passed request still runs its normal envelope checks.
pub type DispatchHandler = Arc<dyn Fn(&str, bool) -> Dispatch + Send + Sync>;
pub type DispatchHandlerFactory = Arc<dyn Fn() -> DispatchHandler + Send + Sync>;

#[derive(Clone)]
struct Handlers {
    registry: Arc<TokenRegistry>,
    on_cell: CellHandler,
    on_queue_cell: Option<QueueCellHandler>,
    on_stream: StreamHandler,
    on_duplex: Option<DuplexHandler>,
    on_dispatch: Option<DispatchHandler>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueReject {
    Unauthorized,
    Conflict,
    Overloaded,
}

const MAX_BODY: usize = Bucket::B3.size();
/// Cells queued toward one subscriber before the relay applies backpressure.
const STREAM_QUEUE: usize = 32;
/// Total accepted connections. Each also counts against its source address.
pub const MAX_CONNECTIONS: usize = 1024;
/// Unauthenticated connections one source IP may hold at once. Authenticated
/// streams remain subject to the global and per-connection resource bounds.
pub const MAX_CONNECTIONS_PER_IP: usize = 8;
/// Requests in flight on one connection. Lanes keep a handful of streams.
pub const MAX_INFLIGHT_PER_CONNECTION: usize = 16;
const MAX_STREAMS_PER_CONNECTION: u32 = MAX_INFLIGHT_PER_CONNECTION as u32;
const MAX_SEND_BUFFER: usize = Bucket::B3.size() * 2;
/// Every DATA frame is one whole wire cell: never split a 16 KiB cell.
const H2_MAX_FRAME_SIZE: u32 = Bucket::B3.size() as u32;
const H2_INITIAL_STREAM_WINDOW: u32 = 256 * 1024;
const H2_INITIAL_CONNECTION_WINDOW: u32 = 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Connection admission limits. The source limit applies until possession of
/// a private service capability is demonstrated; the total limit always applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
        }
    }
}

impl ServerLimits {
    /// Total bound only; for test fixtures where every peer shares one IP.
    pub fn shared_host() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_connections_per_ip: MAX_CONNECTIONS,
        }
    }
}

/// Per-source accounting. Slots are released when the connection task ends.
#[derive(Default)]
struct SourceTable {
    per_ip: HashMap<IpAddr, usize>,
    total: usize,
}

struct SourceSlot {
    table: Arc<Mutex<SourceTable>>,
    ip: IpAddr,
    authenticated: AtomicBool,
}

impl SourceTable {
    fn try_admit(
        table: &Arc<Mutex<SourceTable>>,
        limits: ServerLimits,
        ip: IpAddr,
    ) -> Option<SourceSlot> {
        let mut guard = table.lock().unwrap_or_else(|p| p.into_inner());
        let per_ip = guard.per_ip.get(&ip).copied().unwrap_or(0);
        if guard.total >= limits.max_connections || per_ip >= limits.max_connections_per_ip {
            return None;
        }
        guard.total += 1;
        *guard.per_ip.entry(ip).or_insert(0) += 1;
        Some(SourceSlot {
            table: table.clone(),
            ip,
            authenticated: AtomicBool::new(false),
        })
    }
}

impl SourceSlot {
    fn authenticate(&self) {
        let mut guard = self.table.lock().unwrap_or_else(|p| p.into_inner());
        if !self.authenticated.swap(true, Ordering::AcqRel) {
            release_source(&mut guard, self.ip);
        }
    }
}

fn release_source(table: &mut SourceTable, ip: IpAddr) {
    if let Some(count) = table.per_ip.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            table.per_ip.remove(&ip);
        }
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut guard = self.table.lock().unwrap_or_else(|p| p.into_inner());
        guard.total = guard.total.saturating_sub(1);
        if !self.authenticated.load(Ordering::Acquire) {
            release_source(&mut guard, self.ip);
        }
    }
}

#[derive(Clone)]
pub struct StreamSink {
    tx: mpsc::Sender<QueuedCell>,
}

struct QueuedCell {
    cell: Cell,
    ack: oneshot::Sender<bool>,
}

impl StreamSink {
    pub async fn send(&self, cell: Cell) -> bool {
        let (ack, delivered) = oneshot::channel();
        if self.tx.send(QueuedCell { cell, ack }).await.is_err() {
            return false;
        }
        delivered.await.unwrap_or(false)
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

pub struct Tp1Server {
    listener: TcpListener,
    service_id: [u8; 32],
    registry: Arc<TokenRegistry>,
    on_cell: CellHandler,
    on_queue_cell: Option<QueueCellHandler>,
    on_stream: StreamHandler,
    duplex_factory: Option<DuplexHandlerFactory>,
    dispatch_factory: Option<DispatchHandlerFactory>,
    tls: TlsAcceptor,
    limits: ServerLimits,
}

impl Tp1Server {
    pub async fn bind_with_identity(
        addr: SocketAddr,
        registry: TokenRegistry,
        on_cell: CellHandler,
        on_stream: StreamHandler,
        identity: &tls::TlsIdentity,
    ) -> io::Result<Self> {
        Self::bind_inner(addr, registry, on_cell, on_stream, None, identity).await
    }

    pub async fn bind_with_identity_and_queue(
        addr: SocketAddr,
        registry: TokenRegistry,
        on_cell: CellHandler,
        on_stream: StreamHandler,
        on_queue_cell: QueueCellHandler,
        identity: &tls::TlsIdentity,
    ) -> io::Result<Self> {
        Self::bind_inner(
            addr,
            registry,
            on_cell,
            on_stream,
            Some(on_queue_cell),
            identity,
        )
        .await
    }

    async fn bind_inner(
        addr: SocketAddr,
        registry: TokenRegistry,
        on_cell: CellHandler,
        on_stream: StreamHandler,
        on_queue_cell: Option<QueueCellHandler>,
        identity: &tls::TlsIdentity,
    ) -> io::Result<Self> {
        let listener = Self::bind_listener(addr)?;
        Self::from_listener_inner(
            listener,
            registry,
            on_cell,
            on_stream,
            on_queue_cell,
            identity,
        )
    }

    /// Bind once and retain the selected socket through transport construction.
    pub fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        // Windows SO_REUSEADDR permits multiple live owners of the same port.
        #[cfg(unix)]
        socket.set_reuseaddr(true)?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                setsockopt, WSAGetLastError, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            };
            let exclusive = 1i32;
            // SAFETY: the socket is live and unbound; the option points to an
            // initialized integer of the exact size required by Winsock.
            if unsafe {
                setsockopt(
                    socket.as_raw_socket() as _,
                    SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE,
                    (&exclusive as *const i32).cast(),
                    std::mem::size_of::<i32>() as i32,
                )
            } == SOCKET_ERROR
            {
                return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
            }
        }
        socket.bind(addr)?;
        socket.listen(1024)
    }

    /// Consume a listener already owned by the caller, without closing/rebinding.
    pub fn from_listener_with_identity_and_queue(
        listener: TcpListener,
        registry: TokenRegistry,
        on_cell: CellHandler,
        on_stream: StreamHandler,
        on_queue_cell: QueueCellHandler,
        identity: &tls::TlsIdentity,
    ) -> io::Result<Self> {
        Self::from_listener_inner(
            listener,
            registry,
            on_cell,
            on_stream,
            Some(on_queue_cell),
            identity,
        )
    }

    fn from_listener_inner(
        listener: TcpListener,
        registry: TokenRegistry,
        on_cell: CellHandler,
        on_stream: StreamHandler,
        on_queue_cell: Option<QueueCellHandler>,
        identity: &tls::TlsIdentity,
    ) -> io::Result<Self> {
        let cfg = identity.server_config().map_err(std::io::Error::other)?;
        Ok(Tp1Server {
            listener,
            service_id: identity.service_id(),
            registry: Arc::new(registry),
            on_cell,
            on_queue_cell,
            on_stream,
            duplex_factory: None,
            dispatch_factory: None,
            tls: TlsAcceptor::from(Arc::new(cfg)),
            limits: ServerLimits::default(),
        })
    }

    /// Override admission limits before `run`.
    pub fn with_limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Add private authenticated streaming services without changing existing
    /// queue/post handlers or requiring request END_STREAM before the response.
    pub fn with_duplex(self, handler: DuplexHandler) -> Self {
        self.with_duplex_factory(Arc::new(move || handler.clone()))
    }

    /// Share bounded service state across all authenticated duplex paths on one
    /// physical connection, without sharing it with another connection.
    /// Transport shutdown drains requests before releasing this state.
    pub fn with_duplex_factory(mut self, factory: DuplexHandlerFactory) -> Self {
        self.duplex_factory = Some(factory);
        self
    }

    /// Bind connection policy before any POST endpoint can run. Unlike a
    /// duplex fallback, this gate also sees registered queue/post/stream paths.
    /// Returning `Rejected` cannot fall through to another service.
    pub fn with_dispatch_factory(mut self, factory: DispatchHandlerFactory) -> Self {
        self.dispatch_factory = Some(factory);
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn service_id(&self) -> [u8; 32] {
        self.service_id
    }

    pub async fn run(self) -> io::Result<()> {
        self.run_until(std::future::pending()).await
    }

    /// Stop accepting and drain owned connections and requests before returning.
    pub async fn run_until(
        self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> io::Result<()> {
        tokio::pin!(shutdown);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let mut connections = tokio::task::JoinSet::new();
        let sources = Arc::new(Mutex::new(SourceTable::default()));
        let limits = self.limits;
        let result = loop {
            // Accept unconditionally so the kernel backlog never fills while
            // the table is full; an over-limit source is closed at once
            // without a TLS handshake, which is what a saturated ordinary
            // HTTPS server does too.
            let accepted = tokio::select! {
                _ = &mut shutdown => break Ok(()),
                result = self.listener.accept() => result,
                _ = connections.join_next(), if !connections.is_empty() => continue,
            };
            let (stream, peer) = match accepted {
                Ok(value) => value,
                Err(error) => break Err(error),
            };
            let Some(slot) = SourceTable::try_admit(&sources, limits, peer.ip()) else {
                drop(stream);
                continue;
            };
            let handlers = Handlers {
                registry: self.registry.clone(),
                on_cell: self.on_cell.clone(),
                on_queue_cell: self.on_queue_cell.clone(),
                on_stream: self.on_stream.clone(),
                on_duplex: None,
                on_dispatch: None,
            };
            let tls = self.tls.clone();
            let stopped = stopped.clone();
            let factory = self.duplex_factory.clone();
            let dispatch_factory = self.dispatch_factory.clone();
            connections.spawn(async move {
                let _ = handle_connection(
                    stream,
                    tls,
                    handlers,
                    Arc::new(slot),
                    stopped,
                    factory,
                    dispatch_factory,
                )
                .await;
            });
        };
        drop(self.listener);
        stop.send_replace(true);
        while connections.join_next().await.is_some() {}
        result
    }
}

async fn server_stopped(receiver: &mut tokio::sync::watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    tls: TlsAcceptor,
    mut handlers: Handlers,
    slot: Arc<SourceSlot>,
    mut stopped: tokio::sync::watch::Receiver<bool>,
    factory: Option<DuplexHandlerFactory>,
    dispatch_factory: Option<DispatchHandlerFactory>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let request_slots = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONNECTION));
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_STREAMS_PER_CONNECTION)
        .max_frame_size(H2_MAX_FRAME_SIZE)
        .initial_window_size(H2_INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW)
        .max_send_buffer_size(MAX_SEND_BUFFER);
    let handshake = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, async {
        let tls_stream = tls.accept(stream).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(builder.handshake(tls_stream).await?)
    });
    let mut conn = tokio::select! {
        _ = server_stopped(&mut stopped) => return Ok(()),
        result = handshake => result,
    }
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection handshake timed out"))??;
    // Initializing service state cannot block the accept loop, and malformed
    // TLS/HTTP2 probes never allocate it.
    handlers.on_duplex = factory.map(|factory| factory());
    handlers.on_dispatch = dispatch_factory.map(|factory| factory());
    let mut requests = tokio::task::JoinSet::new();
    let result = async {
    loop {
        while requests.try_join_next().is_some() {}
        let idle = requests.is_empty();
        let request = tokio::select! {
            _ = server_stopped(&mut stopped) => break,
            result = async {
                if idle {
                    tokio::time::timeout(IDLE_TIMEOUT, conn.accept()).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout"))
                } else {
                    Ok(conn.accept().await)
                }
            } => result?,
            Some(_) = requests.join_next(), if !idle => continue,
        };
        let Some(request) = request else {
            break;
        };
        let (request, respond) = request?;
        let Ok(request_slot) = request_slots.clone().try_acquire_owned() else {
            // Pre-authentication overload is not distinguishable from an
            // unknown path (SPEC §5.2: 429 is never visible to a prober).
            let mut respond = respond;
            serve_decoy(&mut respond, "/_").await;
            continue;
        };
        let handlers = handlers.clone();
        let slot = slot.clone();
        requests.spawn(async move {
            let _request_slot = request_slot;
            per_request(
                request,
                respond,
                handlers,
                slot,
            )
            .await;
        });
    }
    Ok::<(), Box<dyn Error + Send + Sync>>(())
    }.await;
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    result
}

async fn per_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    handlers: Handlers,
    slot: Arc<SourceSlot>,
) {
    let Handlers {
        registry,
        on_cell,
        on_queue_cell,
        on_stream,
        on_duplex,
        on_dispatch,
    } = handlers;
    let (parts, mut body) = request.into_parts();
    let path = parts.uri.path().to_string();
    match parts.method {
        Method::GET => serve_decoy(&mut respond, path.as_str()).await,
        Method::POST => {
            let token = path.trim_start_matches('/').to_string();
            if let Some(dispatch) = &on_dispatch {
                match dispatch(&token, registry.kind(&token).is_some()) {
                    Dispatch::Pass => (),
                    Dispatch::Rejected => {
                        serve_decoy(&mut respond, "/_").await;
                        return;
                    }
                    Dispatch::Accepted(accepted) => {
                        slot.authenticate();
                        accepted(body, respond).await;
                        return;
                    }
                }
            }
            // A random private path is a service capability. Promotion releases
            // only the unauthenticated source slot, never the global slot.
            if registry.kind(&token).is_some() {
                slot.authenticate();
            } else if let Some(accepted) = on_duplex.as_ref().and_then(|handler| handler(&token)) {
                slot.authenticate();
                accepted(body, respond).await;
                return;
            }
            match registry.kind(&token) {
                None => serve_decoy(&mut respond, "/_").await,
                Some(TokenKind::Post) => serve_post(&mut body, &mut respond, &token, on_cell).await,
                Some(TokenKind::Stream) => serve_stream(&mut body, &mut respond, on_stream).await,
                Some(TokenKind::Queue) => {
                    serve_queue(&mut body, &mut respond, &token, on_queue_cell, on_stream).await
                }
            }
        }
        _ => serve_decoy(&mut respond, "/_").await,
    }
}

async fn serve_queue(
    body: &mut h2::RecvStream,
    respond: &mut h2::server::SendResponse<Bytes>,
    token: &str,
    on_queue_cell: Option<QueueCellHandler>,
    on_stream: StreamHandler,
) {
    let data = match read_body(body, MAX_BODY).await {
        Ok(data) => data,
        Err(_) => {
            serve_decoy(respond, "/_").await;
            return;
        }
    };
    let cell = match decode(&data) {
        Ok(cell) => cell,
        Err(_) => {
            serve_decoy(respond, "/_").await;
            return;
        }
    };
    match cell.cell_type() {
        Some(CellType::RelaySub) => {
            let Some(accepted) = on_stream(&data) else {
                serve_decoy(respond, "/_").await;
                return;
            };
            serve_open_stream(respond, accepted).await;
        }
        Some(CellType::RelayPush) => {
            let Some(on_queue_cell) = on_queue_cell else {
                serve_decoy(respond, "/_").await;
                return;
            };
            serve_handler_result(respond, on_queue_cell(token, cell)).await;
        }
        _ => serve_decoy(respond, "/_").await,
    }
}

async fn serve_decoy(respond: &mut h2::server::SendResponse<Bytes>, path: &str) {
    let status = if path == "/" {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    let response = decoy::decoy_response(status.as_u16());
    let _ = send_with_body(respond, response, decoy::decoy_body(status.as_u16())).await;
}

async fn serve_post(
    body: &mut h2::RecvStream,
    respond: &mut h2::server::SendResponse<Bytes>,
    token: &str,
    on_cell: CellHandler,
) {
    let data = match read_body(body, MAX_BODY).await {
        Ok(d) => d,
        Err(_) => {
            serve_decoy(respond, "/_").await;
            return;
        }
    };
    let cell = match decode(&data) {
        Ok(c) => c,
        Err(_) => {
            serve_decoy(respond, "/_").await;
            return;
        }
    };
    serve_handler_result(respond, on_cell(token, cell)).await;
}

/// Every authenticated outcome is `200` with exactly one wire cell (SPEC
/// §5.2, §7.5). Only `Unauthorized` falls back to the decoy surface, and
/// it is indistinguishable from an unknown path.
async fn serve_handler_result(
    respond: &mut h2::server::SendResponse<Bytes>,
    result: Result<Option<Cell>, QueueReject>,
) {
    let reply = match result {
        Ok(Some(cell)) => cell,
        Ok(None) => HopReply::Accepted.cell(),
        Err(QueueReject::Unauthorized) => {
            serve_decoy(respond, "/_").await;
            return;
        }
        Err(QueueReject::Conflict) => HopReply::Conflict.cell(),
        Err(QueueReject::Overloaded) => HopReply::Overloaded.cell(),
    };
    serve_reply_cell(respond, reply).await;
}

async fn serve_reply_cell(respond: &mut h2::server::SendResponse<Bytes>, reply: Cell) {
    let buf = match reply.encode_wire() {
        Ok(b) => b,
        Err(_) => match HopReply::Internal.cell().encode_wire() {
            Ok(b) => b,
            Err(_) => return,
        },
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .expect("static response builds");
    let _ = send_with_body(respond, response, Bytes::from(buf)).await;
}

async fn serve_stream(
    body: &mut h2::RecvStream,
    respond: &mut h2::server::SendResponse<Bytes>,
    on_stream: StreamHandler,
) {
    let auth_body = match read_body(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            serve_decoy(respond, "/_").await;
            return;
        }
    };
    serve_accepted_stream(respond, &auth_body, on_stream).await;
}

async fn serve_accepted_stream(
    respond: &mut h2::server::SendResponse<Bytes>,
    auth_body: &[u8],
    on_stream: StreamHandler,
) {
    let Some(accepted) = on_stream(auth_body) else {
        serve_decoy(respond, "/_").await;
        return;
    };
    serve_open_stream(respond, accepted).await;
}

async fn serve_open_stream(
    respond: &mut h2::server::SendResponse<Bytes>,
    accepted: AcceptedStream,
) {
    let (tx, mut rx) = mpsc::channel::<QueuedCell>(STREAM_QUEUE);
    accepted(StreamSink { tx });
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .expect("static response builds");
    let mut stream = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    loop {
        let queued = tokio::select! {
            queued = rx.recv() => match queued {
                Some(queued) => queued,
                None => break,
            },
            reset = poll_fn(|cx| stream.poll_reset(cx)) => {
                let _ = reset;
                break;
            }
        };
        let buf = match queued.cell.encode_wire() {
            Ok(b) => b,
            Err(_) => {
                let _ = queued.ack.send(false);
                continue;
            }
        };
        if stream.send_data(Bytes::from(buf), false).is_err() {
            let _ = queued.ack.send(false);
            break;
        }
        let _ = queued.ack.send(true);
    }
    drop(rx);
    let _ = stream.send_data(Bytes::new(), true);
}

async fn send_with_body(
    respond: &mut h2::server::SendResponse<Bytes>,
    response: http::Response<()>,
    body: Bytes,
) -> Result<(), h2::Error> {
    let mut stream = respond.send_response(response, body.is_empty())?;
    if !body.is_empty() {
        stream.send_data(body, true)?;
    }
    Ok(())
}

pub async fn read_body(
    body: &mut h2::RecvStream,
    cap: usize,
) -> Result<Bytes, Box<dyn Error + Send + Sync>> {
    tokio::time::timeout(BODY_TIMEOUT, read_body_inner(body, cap))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request body timed out"))?
}

async fn read_body_inner(
    body: &mut h2::RecvStream,
    cap: usize,
) -> Result<Bytes, Box<dyn Error + Send + Sync>> {
    let mut buf = Vec::new();
    while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > cap {
            return Err("body exceeds cap".into());
        }
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}
