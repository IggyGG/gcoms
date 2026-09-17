use crate::connector::{Connector, DirectConnector};
use crate::hop::{HopOutcome, HopReply};
use crate::tls;
use bytes::Bytes;
use gcoms_core::TrafficClass;
use http::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Idle pull streams are abandoned when no cell arrives for this long.
pub const STREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Concurrent HTTP/2 connections kept warm. A lane never opens a fresh TLS
/// connection in response to real traffic when its peer is already pooled.
pub const MAX_POOLED_CONNECTIONS: usize = 8;
/// Hard bound includes busy connections and connection attempts.
pub const MAX_ACTIVE_CONNECTIONS: usize = 64;
const MAX_CONNECTION_ATTEMPTS: usize = 4;
pub const MAX_FINITE_REQUESTS: usize = 4;
pub const MAX_BULK_REQUESTS: usize = 3;
const SMALL_WIRE_CELL: usize = 4096;
const LARGE_WIRE_CELL: usize = 16384;
const MAX_STREAM_BUFFER: usize = LARGE_WIRE_CELL * 2;
/// One post-authentication reply is exactly one wire cell.
const MAX_REPLY_BODY: usize = LARGE_WIRE_CELL;
/// Every DATA frame we send or accept is one whole wire cell.
const H2_MAX_FRAME_SIZE: u32 = LARGE_WIRE_CELL as u32;
const H2_INITIAL_STREAM_WINDOW: u32 = 256 * 1024;
const H2_INITIAL_CONNECTION_WINDOW: u32 = 1024 * 1024;

/// Materialize authenticated request bytes only after connection and request
/// admission. Once prepared, retain the same bytes across a reconnect retry.
enum RequestBody<'a> {
    Ready(Option<Bytes>),
    Prepare(Option<Box<dyn FnOnce() -> Result<Bytes> + Send + 'a>>),
}

impl RequestBody<'_> {
    fn materialize(&mut self) -> Result<Option<Bytes>> {
        if let Self::Prepare(make) = self {
            let bytes = make.take().ok_or("request body was already prepared")?()?;
            *self = Self::Ready(Some(bytes));
        }
        match self {
            Self::Ready(bytes) => Ok(bytes.clone()),
            Self::Prepare(_) => unreachable!("prepared above"),
        }
    }
}

pub struct Tp1Client {
    connector: Arc<dyn Connector>,
    connections: Mutex<Pool>,
    connection_attempts: Semaphore,
    connection_slots: Arc<Semaphore>,
    connecting: Mutex<HashMap<PoolKey, Weak<Mutex<()>>>>,
}

/// A pooled peer is always addressed by its pinned service identity. There
/// is no unpinned path: a connection without a pin cannot be represented.
type PoolKey = (SocketAddr, [u8; 32], [u8; 32]);

#[derive(Clone, Copy)]
struct Route<'a> {
    addr: SocketAddr,
    service_id: [u8; 32],
    excluded: &'a [(SocketAddr, [u8; 32])],
}

impl Route<'_> {
    fn key(&self) -> Result<PoolKey> {
        if self.excluded.len() > 64 {
            return Err("too many terminal route exclusions".into());
        }
        if self.excluded.is_empty() {
            return Ok((self.addr, self.service_id, [0; 32]));
        }
        let mut excluded = self.excluded.to_vec();
        excluded.sort_unstable();
        excluded.dedup();
        let mut hash = Sha256::new();
        hash.update(b"ghost.tp1.route-exclusions.v1\0");
        for (addr, pin) in excluded {
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    hash.update([4]);
                    hash.update(ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    hash.update([6]);
                    hash.update(ip.octets());
                }
            }
            hash.update(addr.port().to_be_bytes());
            hash.update(pin);
        }
        Ok((self.addr, self.service_id, hash.finalize().into()))
    }
}

struct PooledConnection {
    sender: h2::client::SendRequest<Bytes>,
    /// Open streams (pull channels) that must not be evicted from under.
    in_flight: AtomicUsize,
    finite: Arc<Semaphore>,
    bulk: Arc<Semaphore>,
    _driver: ConnectionDriver,
}

struct ConnectionDriver(tokio::task::JoinHandle<()>);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Covers queueing, request transmission and the complete response body. Drop
/// also releases admission on timeout, cancellation and connection failure.
struct ConnectionLease {
    connection: Arc<PooledConnection>,
    _finite: Option<OwnedSemaphorePermit>,
    _bulk: Option<OwnedSemaphorePermit>,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.connection.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl PooledConnection {
    async fn lease(self: &Arc<Self>, finite: bool, class: TrafficClass) -> Result<ConnectionLease> {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let mut lease = ConnectionLease {
            connection: self.clone(),
            _finite: None,
            _bulk: None,
        };
        if finite {
            // Bulk waits for its own credit first, leaving one total permit
            // available to interactive/control requests even with a bulk backlog.
            if class == TrafficClass::Bulk {
                lease._bulk = Some(self.bulk.clone().acquire_owned().await?);
            }
            lease._finite = Some(self.finite.clone().acquire_owned().await?);
        }
        Ok(lease)
    }
}

#[derive(Default)]
struct Pool {
    entries: HashMap<PoolKey, Arc<PooledConnection>>,
    /// Least-recently-used order; front is the eviction candidate.
    order: VecDeque<PoolKey>,
}

impl Pool {
    fn touch(&mut self, key: PoolKey) {
        if let Some(pos) = self.order.iter().position(|k| *k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
    }

    fn get(&mut self, key: PoolKey) -> Option<Arc<PooledConnection>> {
        let entry = self.entries.get(&key).cloned()?;
        self.touch(key);
        Some(entry)
    }

    fn remove(&mut self, key: &PoolKey) -> Option<Arc<PooledConnection>> {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.entries.remove(key)
    }

    fn prune_idle(&mut self) {
        while self.entries.len() >= MAX_POOLED_CONNECTIONS {
            // Evict the least recently used connection that has no open
            // stream. If every pooled connection is busy, grow past the soft
            // idle bound rather than tear down a live subscription. A separate
            // permit enforces MAX_ACTIVE_CONNECTIONS for all busy connections.
            let Some(victim) = self.order.iter().copied().find(|k| {
                self.entries.get(k).is_some_and(|c| {
                    c.in_flight.load(Ordering::Acquire) == 0 && Arc::strong_count(c) == 1
                })
            }) else {
                break;
            };
            self.remove(&victim);
        }
    }

    fn insert(&mut self, key: PoolKey, connection: Arc<PooledConnection>) {
        self.prune_idle();
        self.entries.insert(key, connection);
        self.touch(key);
    }
}

impl Tp1Client {
    pub fn new() -> Result<Self> {
        Self::with_connector(Arc::new(DirectConnector))
    }

    /// Preserve TP1 endpoint pinning and pooling over a caller-owned route.
    pub fn with_connector(connector: Arc<dyn Connector>) -> Result<Self> {
        Ok(Tp1Client {
            connector,
            connections: Mutex::new(Pool::default()),
            connection_attempts: Semaphore::new(MAX_CONNECTION_ATTEMPTS),
            connection_slots: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
            connecting: Mutex::new(HashMap::new()),
        })
    }

    /// Decoy probe. Only useful for tests and diagnostics: a real peer never
    /// issues GETs.
    pub async fn get_pinned(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        path: &str,
    ) -> Result<(StatusCode, Bytes)> {
        self.finite_request(
            Route {
                addr,
                service_id,
                excluded: &[],
            },
            Method::GET,
            path,
            RequestBody::Ready(None),
            TrafficClass::Interactive,
        )
        .await
    }

    /// Deposit one wire cell and interpret the uniform in-band reply.
    pub async fn post_cell_pinned(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        token: &str,
        cell_buf: Bytes,
    ) -> Result<HopOutcome> {
        let (status, body) = self
            .finite_request(
                Route {
                    addr,
                    service_id,
                    excluded: &[],
                },
                Method::POST,
                &format!("/{token}"),
                RequestBody::Ready(Some(cell_buf)),
                TrafficClass::Interactive,
            )
            .await?;
        parse_hop_outcome(status, &body)
    }

    /// A constrained request cannot reuse a pool connection built for a different
    /// terminal set. Existing application methods keep their original signatures.
    pub async fn post_cell_pinned_excluding(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        token: &str,
        cell_buf: Bytes,
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<HopOutcome> {
        self.post_cell_with_class(
            addr,
            service_id,
            token,
            cell_buf,
            excluded,
            TrafficClass::Interactive,
        )
        .await
    }

    pub async fn post_cell_with_class(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        token: &str,
        cell_buf: Bytes,
        excluded: &[(SocketAddr, [u8; 32])],
        class: TrafficClass,
    ) -> Result<HopOutcome> {
        let (status, body) = self
            .finite_request(
                Route {
                    addr,
                    service_id,
                    excluded,
                },
                Method::POST,
                &format!("/{token}"),
                RequestBody::Ready(Some(cell_buf)),
                class,
            )
            .await?;
        parse_hop_outcome(status, &body)
    }

    /// Prepare a cell after the pinned connection, finite-request permit and
    /// HTTP/2 stream are ready. The builder runs once; reconnect retries reuse
    /// its exact bytes, including its nonce and committed ciphertext. The whole
    /// operation still shares the ordinary request deadline.
    pub async fn post_cell_prepared<F>(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        token: &str,
        excluded: &[(SocketAddr, [u8; 32])],
        class: TrafficClass,
        make: F,
    ) -> Result<HopOutcome>
    where
        F: FnOnce() -> Result<Bytes> + Send,
    {
        let (status, body) = self
            .finite_request(
                Route {
                    addr,
                    service_id,
                    excluded,
                },
                Method::POST,
                &format!("/{token}"),
                RequestBody::Prepare(Some(Box::new(make))),
                class,
            )
            .await?;
        parse_hop_outcome(status, &body)
    }

    pub async fn open_stream_body_pinned(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        token: &str,
        body: Option<&[u8]>,
    ) -> Result<CellStream> {
        let body_bytes = body.map(bytes::Bytes::copy_from_slice);
        let (response, connection) = self
            .request(
                addr,
                service_id,
                Method::POST,
                &format!("/{token}"),
                RequestBody::Ready(body_bytes.or_else(|| Some(bytes::Bytes::new()))),
            )
            .await?;
        if response.status() != 200 {
            return Err(format!("stream refused: {}", response.status()).into());
        }
        Ok(CellStream {
            body: response.into_body(),
            last_frame_len: 0,
            framing: CellFraming::new(),
            finished: false,
            guard: Some(connection),
        })
    }

    /// Prepare subscription authorization after the pinned HTTP/2 stream is
    /// ready. Reconnect retries reuse its exact authenticated bytes. The request
    /// deadline covers connection, admission, preparation and response headers.
    pub async fn open_stream_prepared<F>(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        token: &str,
        make: F,
    ) -> Result<CellStream>
    where
        F: FnOnce() -> Result<Bytes> + Send,
    {
        let (response, connection) = self
            .request(
                addr,
                service_id,
                Method::POST,
                &format!("/{token}"),
                RequestBody::Prepare(Some(Box::new(make))),
            )
            .await?;
        if response.status() != 200 {
            return Err(format!("stream refused: {}", response.status()).into());
        }
        Ok(CellStream {
            body: response.into_body(),
            last_frame_len: 0,
            framing: CellFraming::new(),
            finished: false,
            guard: Some(connection),
        })
    }

    async fn request(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        method: Method,
        path: &str,
        body: RequestBody<'_>,
    ) -> Result<(Response<h2::RecvStream>, ConnectionLease)> {
        match tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.request_inner(
                Route {
                    addr,
                    service_id,
                    excluded: &[],
                },
                method,
                path,
                body,
                false,
                TrafficClass::Interactive,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err("transport request timed out".into()),
        }
    }

    async fn finite_request(
        &self,
        route: Route<'_>,
        method: Method,
        path: &str,
        body: RequestBody<'_>,
        class: TrafficClass,
    ) -> Result<(StatusCode, Bytes)> {
        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let (response, _connection) = self
                .request_inner(route, method, path, body, true, class)
                .await?;
            let status = response.status();
            let mut body = response.into_body();
            Ok::<_, Box<dyn Error + Send + Sync>>((status, read_body(&mut body).await?))
        })
        .await;
        match result {
            Ok(result) => result,
            // A queued request or a slow response is not evidence that the
            // connection failed. Cancellation drops only this stream's lease.
            Err(_) => Err("transport request timed out".into()),
        }
    }

    async fn request_inner(
        &self,
        route: Route<'_>,
        method: Method,
        path: &str,
        mut body: RequestBody<'_>,
        finite: bool,
        class: TrafficClass,
    ) -> Result<(Response<h2::RecvStream>, ConnectionLease)> {
        let pool_key = route.key()?;
        let addr = route.addr;
        for attempt in 0..2 {
            let connection = self.connection(route).await?;
            let lease = connection.lease(finite, class).await?;
            let mut client = match connection.sender.clone().ready().await {
                Ok(client) => client,
                Err(_) => {
                    self.remove_connection(pool_key, &connection).await;
                    if attempt == 0 {
                        continue;
                    }
                    return Err("HTTP/2 connection unavailable".into());
                }
            };

            let body_bytes = body.materialize()?;
            let uri: http::Uri = format!("http://{addr}{path}").parse()?;
            let request = Request::builder()
                .method(method.clone())
                .uri(uri)
                .body(())
                .expect("request builds");
            let sent = client.send_request(request, body_bytes.is_none());
            let (response, mut send) = match sent {
                Ok(sent) => sent,
                Err(error) => {
                    self.remove_connection(pool_key, &connection).await;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(error.into());
                }
            };
            // send_data + response.await can still fail if the pooled stream
            // was reset after ready() succeeded (e.g. h2 InactiveStreamId when
            // a peer or an idle-timeout closed the connection under load).
            // These finite requests carry one self-contained cell and are
            // idempotent, so evict the stale connection and retry once on a
            // fresh one rather than surface a transient transport error.
            if let Some(b) = body_bytes {
                if let Err(error) = send.send_data(b, true) {
                    self.remove_connection(pool_key, &connection).await;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(error.into());
                }
            }
            match response.await {
                Ok(response) => return Ok((response, lease)),
                Err(error) => {
                    self.remove_connection(pool_key, &connection).await;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(error.into());
                }
            }
        }
        unreachable!("connection retry loop returns")
    }

    /// Open (or reuse) the pinned connection to a peer without sending
    /// anything. Lanes call this when they are created so that the TLS
    /// handshake happens on the lane's own schedule, never at the moment
    /// real traffic first arrives.
    pub async fn warm(&self, addr: SocketAddr, service_id: [u8; 32]) -> Result<()> {
        self.warm_excluding(addr, service_id, &[]).await
    }

    /// Warm the same constrained route that the eventual request will use.
    pub async fn warm_excluding(
        &self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<()> {
        self.connection(Route {
            addr,
            service_id,
            excluded,
        })
        .await
        .map(|_| ())
    }

    pub async fn pooled_connections(&self) -> usize {
        self.connections.lock().await.entries.len()
    }

    async fn connection(&self, route: Route<'_>) -> Result<Arc<PooledConnection>> {
        let pool_key = route.key()?;
        if let Some(connection) = self.connections.lock().await.get(pool_key) {
            return Ok(connection);
        }
        let lock = {
            let mut connecting = self.connecting.lock().await;
            connecting.retain(|_, lock| lock.strong_count() != 0);
            if let Some(lock) = connecting.get(&pool_key).and_then(Weak::upgrade) {
                lock
            } else {
                if connecting.len() >= MAX_ACTIVE_CONNECTIONS {
                    return Err("terminal connection attempt capacity exhausted".into());
                }
                let lock = Arc::new(Mutex::new(()));
                connecting.insert(pool_key, Arc::downgrade(&lock));
                lock
            }
        };
        let _establishing = lock.lock().await;
        if let Some(connection) = self.connections.lock().await.get(pool_key) {
            return Ok(connection);
        }

        // Same-peer waiters do not occupy independent connection-attempt slots.
        let _attempt = self
            .connection_attempts
            .acquire()
            .await
            .map_err(|_| "connection attempt limiter closed")?;
        self.connections.lock().await.prune_idle();
        let slot = self
            .connection_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "terminal connection capacity exhausted")?;
        let tcp = self
            .connector
            .connect_excluding(pool_key.0, pool_key.1, route.excluded)
            .await?;
        let config = tls::client_config_pinned(pool_key.1)?;
        let tls_stream = TlsConnector::from(Arc::new(config))
            .connect(tls::server_name_ip(pool_key.0.ip()), tcp)
            .await?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(tls::ALPN_H2) {
            return Err("endpoint did not negotiate h2".into());
        }
        let (sender, connection) = h2::client::Builder::new()
            .max_frame_size(H2_MAX_FRAME_SIZE)
            .initial_window_size(H2_INITIAL_STREAM_WINDOW)
            .initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW)
            .handshake(tls_stream)
            .await?;
        let driver = ConnectionDriver(tokio::spawn(async move {
            // Count the actual connection driver, including cancellation teardown.
            let _slot = slot;
            let _ = connection.await;
        }));
        let candidate = Arc::new(PooledConnection {
            sender,
            in_flight: AtomicUsize::new(0),
            finite: Arc::new(Semaphore::new(MAX_FINITE_REQUESTS)),
            bulk: Arc::new(Semaphore::new(MAX_BULK_REQUESTS)),
            _driver: driver,
        });

        let mut connections = self.connections.lock().await;
        if let Some(connection) = connections.get(pool_key) {
            return Ok(connection);
        }
        connections.insert(pool_key, candidate.clone());
        Ok(candidate)
    }

    async fn remove_connection(&self, pool_key: PoolKey, failed: &Arc<PooledConnection>) {
        let mut connections = self.connections.lock().await;
        if connections
            .entries
            .get(&pool_key)
            .is_some_and(|current| Arc::ptr_eq(current, failed))
        {
            connections.remove(&pool_key);
        }
    }
}

/// Map an HTTP reply onto the uniform hop outcome. Any non-200 is the decoy
/// surface; a 200 carries exactly one wire cell.
fn parse_hop_outcome(status: StatusCode, body: &[u8]) -> Result<HopOutcome> {
    if status != StatusCode::OK {
        return Ok(HopOutcome::Decoy(status.as_u16()));
    }
    let cell = gcoms_core::decode(body).map_err(|_| "hop reply is not one wire cell")?;
    Ok(match HopReply::parse(&cell) {
        Some(HopReply::Accepted) => HopOutcome::Accepted(None),
        Some(HopReply::Conflict) => HopOutcome::Conflict,
        Some(HopReply::Overloaded) => HopOutcome::Overloaded,
        Some(HopReply::Internal) => HopOutcome::Internal,
        None => HopOutcome::Accepted(Some(cell)),
    })
}

pub struct CellStream {
    body: h2::RecvStream,
    last_frame_len: usize,
    framing: CellFraming,
    finished: bool,
    /// Keeps the pooled connection marked busy for the stream's lifetime.
    guard: Option<ConnectionLease>,
}

impl Drop for CellStream {
    fn drop(&mut self) {
        self.guard.take();
    }
}

impl CellStream {
    pub async fn recv(&mut self) -> Option<Result<gcoms_core::Cell>> {
        if self.finished {
            return None;
        }
        loop {
            if let Some(decoded) = self.framing.next_cell() {
                if decoded.is_err() {
                    self.finished = true;
                }
                return Some(decoded.map_err(|e| e.into()));
            }

            // A relay that stops emitting entirely (no cover, no data) is
            // gone; do not hold the lane forever.
            let next =
                tokio::time::timeout(STREAM_IDLE_TIMEOUT, poll_fn(|cx| self.body.poll_data(cx)))
                    .await;
            let chunk = match next {
                Err(_) => {
                    self.finished = true;
                    return Some(Err("stream idle timeout".into()));
                }
                Ok(Some(Ok(chunk))) => chunk,
                Ok(Some(Err(error))) => {
                    self.finished = true;
                    return Some(Err(error.into()));
                }
                Ok(None) if self.framing.is_empty() => {
                    self.finished = true;
                    return None;
                }
                Ok(None) => {
                    let trailing = self.framing.len();
                    self.framing.clear();
                    self.finished = true;
                    return Some(Err(format!(
                        "stream ended with {trailing} bytes of a partial cell"
                    )
                    .into()));
                }
            };
            self.last_frame_len = chunk.len();
            let _ = self.body.flow_control().release_capacity(chunk.len());
            if let Err(error) = self.framing.push(&chunk) {
                self.finished = true;
                return Some(Err(error));
            }
        }
    }

    pub fn last_frame_len(&self) -> usize {
        self.last_frame_len
    }
}

struct CellFraming {
    buffer: Vec<u8>,
    expected_len: Option<usize>,
}

impl CellFraming {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            expected_len: None,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<()> {
        if self.buffer.len() + chunk.len() > MAX_STREAM_BUFFER {
            self.clear();
            return Err("stream cell buffer exceeds cap".into());
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    fn next_cell(
        &mut self,
    ) -> Option<std::result::Result<gcoms_core::Cell, gcoms_core::CellError>> {
        if self.expected_len.is_none() && self.buffer.len() >= gcoms_core::HEADER_LEN {
            let payload_len = u16::from_be_bytes([self.buffer[4], self.buffer[5]]) as usize;
            self.expected_len = Some(if payload_len <= SMALL_WIRE_CELL - gcoms_core::HEADER_LEN {
                SMALL_WIRE_CELL
            } else {
                LARGE_WIRE_CELL
            });
        }
        let cell_len = self.expected_len?;
        if self.buffer.len() < cell_len {
            return None;
        }
        let decoded = gcoms_core::decode(&self.buffer[..cell_len]);
        if decoded.is_ok() {
            self.buffer.drain(..cell_len);
            self.expected_len = None;
        } else {
            self.clear();
        }
        Some(decoded)
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.expected_len = None;
    }
}

async fn read_body(body: &mut h2::RecvStream) -> Result<Bytes> {
    let mut buf = Vec::new();
    while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > MAX_REPLY_BODY {
            return Err("body exceeds cap".into());
        }
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_core::{Cell, CellType};

    fn cell(payload_len: usize, round: u16) -> (Cell, Vec<u8>) {
        let cell = Cell::new(CellType::Msg, 0, round, vec![round as u8; payload_len]);
        let wire = cell.encode_wire().unwrap();
        (cell, wire)
    }

    #[test]
    fn framing_accepts_every_split_offset() {
        for (payload_len, round) in [(100, 1), (5000, 2)] {
            let (expected, wire) = cell(payload_len, round);
            for split in 0..=wire.len() {
                let mut framing = CellFraming::new();
                framing.push(&wire[..split]).unwrap();
                let before = framing.next_cell();
                framing.push(&wire[split..]).unwrap();
                let decoded = before
                    .or_else(|| framing.next_cell())
                    .expect("complete cell")
                    .unwrap();
                assert_eq!(decoded, expected, "split offset {split}");
                assert!(framing.is_empty());
            }
        }
    }

    #[test]
    fn framing_accepts_all_coalesced_wire_size_pairs() {
        for (left_len, right_len) in [(100, 200), (100, 5000), (5000, 100), (5000, 6000)] {
            let (left, mut wire) = cell(left_len, 1);
            let (right, right_wire) = cell(right_len, 2);
            wire.extend_from_slice(&right_wire);

            let mut framing = CellFraming::new();
            framing.push(&wire).unwrap();
            assert_eq!(framing.next_cell().unwrap().unwrap(), left);
            assert_eq!(framing.next_cell().unwrap().unwrap(), right);
            assert!(framing.is_empty());
        }
    }

    #[test]
    fn framing_rejects_excess_buffer_and_retains_partial_eof_state() {
        let mut framing = CellFraming::new();
        assert!(framing.push(&vec![0; MAX_STREAM_BUFFER + 1]).is_err());
        assert!(framing.is_empty());

        let (_, wire) = cell(100, 1);
        framing.push(&wire[..wire.len() - 1]).unwrap();
        assert!(framing.next_cell().is_none());
        assert_eq!(framing.len(), wire.len() - 1);
    }
}
