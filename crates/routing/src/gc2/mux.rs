//! Bounded logical circuits inside an authenticated GCT2 class channel. There
//! are no network dials or padding decisions here. The outer carrier must share
//! one budget across its two channels and supply independently pinned TLS above
//! each returned circuit stream.
use crate::{wire::Target, Result};
use bytes::Bytes;
use futures_util::{stream::FuturesUnordered, StreamExt};
use gcoms_core::TrafficClass;
use gcoms_transport::{connector::BoxStream, duplex::H2Stream};
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout, Instant},
};

pub const MAX_CIRCUITS: usize = 16;
pub const MAX_BULK_CIRCUITS: usize = MAX_CIRCUITS - 1;
pub const STREAM_WINDOW: u32 = 32 * 1024;
pub const CONNECTION_WINDOW: u32 = 256 * 1024;
const MAX_HEADERS: u32 = 1024;
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const OPERATIONS_PER_SECOND: usize = 64;

/// Connection-local admission shared by interactive and bulk channels. Bulk
/// cannot occupy the last logical circuit. Admission never waits holding other
/// credits, so there is no cross-class semaphore deadlock or unbounded queue.
pub(super) struct CircuitBudget {
    all: Arc<Semaphore>,
    bulk: Arc<Semaphore>,
    operations: Mutex<(Instant, usize)>,
}

impl Default for CircuitBudget {
    fn default() -> Self {
        Self {
            all: Arc::new(Semaphore::new(MAX_CIRCUITS)),
            bulk: Arc::new(Semaphore::new(MAX_BULK_CIRCUITS)),
            operations: Mutex::new((Instant::now(), 0)),
        }
    }
}

impl CircuitBudget {
    pub fn active(&self) -> usize {
        MAX_CIRCUITS - self.all.available_permits()
    }

    fn operation(&self) -> Result<()> {
        let mut state = self.operations.lock().unwrap_or_else(|p| p.into_inner());
        if state.0.elapsed() >= Duration::from_secs(1) {
            *state = (Instant::now(), 0);
        }
        if state.1 >= OPERATIONS_PER_SECOND {
            return Err("GCT2 circuit operation rate exceeded".into());
        }
        state.1 += 1;
        Ok(())
    }

    fn acquire(&self, class: TrafficClass) -> Result<CircuitPermit> {
        let bulk = if class == TrafficClass::Bulk {
            Some(self.bulk.clone().try_acquire_owned()?)
        } else {
            None
        };
        let all = self.all.clone().try_acquire_owned()?;
        Ok(CircuitPermit {
            _all: all,
            _bulk: bulk,
        })
    }
}

struct CircuitPermit {
    _all: OwnedSemaphorePermit,
    _bulk: Option<OwnedSemaphorePermit>,
}

/// A logical byte stream, not an authenticated terminal connection. The caller
/// must perform the next independent TLS handshake before exposing application
/// data. Dropping it resets unfinished I/O and immediately releases admission.
pub struct CircuitStream {
    io: H2Stream,
    _permit: CircuitPermit,
    class: TrafficClass,
}

impl CircuitStream {
    pub fn class(&self) -> TrafficClass {
        self.class
    }
}

impl AsyncRead for CircuitStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for CircuitStream {
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

#[derive(Clone)]
pub(super) struct MuxClient {
    sender: h2::client::SendRequest<Bytes>,
    class: TrafficClass,
    budget: Arc<CircuitBudget>,
}

impl MuxClient {
    /// Establish the inner multiplexor on an already protected class channel.
    /// The returned driver is owned by the enclosing carrier, never detached.
    pub(super) async fn handshake<S>(
        io: S,
        class: TrafficClass,
        budget: Arc<CircuitBudget>,
    ) -> Result<(Self, h2::client::Connection<S, Bytes>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (sender, driver) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_frame_size(16 * 1024)
            .max_header_list_size(MAX_HEADERS)
            .header_table_size(0)
            .max_send_buffer_size(STREAM_WINDOW as usize)
            .initial_max_send_streams(MAX_CIRCUITS)
            .max_concurrent_reset_streams(MAX_CIRCUITS)
            .max_pending_accept_reset_streams(MAX_CIRCUITS)
            .max_local_error_reset_streams(Some(MAX_CIRCUITS))
            .enable_push(false)
            .handshake(io)
            .await?;
        Ok((
            Self {
                sender,
                class,
                budget,
            },
            driver,
        ))
    }

    pub(super) async fn open(&self, target: &Target) -> Result<CircuitStream> {
        let encoded = target.encode();
        Target::decode(&encoded)?;
        self.budget.operation()?;
        let permit = self.budget.acquire(self.class)?;
        timeout(OPEN_TIMEOUT, async {
            let mut sender = self.sender.clone();
            poll_fn(|cx| sender.poll_ready(cx)).await?;
            let request = http::Request::builder()
                .method("POST")
                .uri(format!(
                    "https://gct2.invalid/circuit/{}",
                    gcoms_transport::encode_b64url(&encoded)
                ))
                .header("content-type", "application/octet-stream")
                .body(())?;
            let (response, send) = sender.send_request(request, false)?;
            // Reset on a canceled/timed-out open, including before headers arrive.
            let mut pending = PendingSend(Some(send));
            let response = response.await?;
            if response.status() != 200
                || response.headers().len() != 1
                || response.headers().get("content-type").map(|v| v.as_bytes())
                    != Some(b"application/octet-stream".as_slice())
            {
                return Err("GCT2 logical circuit refused".into());
            }
            Ok(CircuitStream {
                io: H2Stream::new(response.into_body(), pending.0.take().unwrap()),
                _permit: permit,
                class: self.class,
            })
        })
        .await
        .map_err(|_| "GCT2 logical circuit open timed out")?
    }
}

pub(super) struct PendingSend(pub(super) Option<h2::SendStream<Bytes>>);
impl Drop for PendingSend {
    fn drop(&mut self) {
        if let Some(send) = self.0.as_mut() {
            send.send_reset(h2::Reason::CANCEL);
        }
    }
}

/// Service policy is responsible for target admission, global relay capacity,
/// and resource ownership of the returned stream. No target is dialed before
/// the connection-local allowance and canonical request are accepted.
pub(crate) type TargetConnector = Arc<
    dyn Fn(Target, TrafficClass) -> Pin<Box<dyn Future<Output = Result<BoxStream>> + Send>>
        + Send
        + Sync,
>;

pub(super) async fn serve<S>(
    io: S,
    class: TrafficClass,
    budget: Arc<CircuitBudget>,
    connect: TargetConnector,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut connection = h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_frame_size(16 * 1024)
        .max_header_list_size(MAX_HEADERS)
        .header_table_size(0)
        .max_send_buffer_size(STREAM_WINDOW as usize)
        .max_concurrent_streams(MAX_CIRCUITS as u32)
        .max_concurrent_reset_streams(MAX_CIRCUITS)
        .max_pending_accept_reset_streams(MAX_CIRCUITS)
        .max_local_error_reset_streams(Some(MAX_CIRCUITS))
        .handshake(io)
        .await?;
    let mut circuits = FuturesUnordered::new();
    loop {
        let accepted = tokio::select! {
            result = connection.accept() => result,
            Some(()) = circuits.next(), if !circuits.is_empty() => continue,
        };
        let Some(accepted) = accepted else {
            return Ok(());
        };
        let (request, mut respond) = accepted?;
        if budget.operation().is_err() {
            // Stop a control flood with bounded reset state. This closes the
            // class channel as an error; it never changes its traffic profile.
            return Err("GCT2 circuit operation rate exceeded".into());
        }
        let target = match decode_target(&request) {
            Ok(target) => target,
            Err(_) => {
                reject(&mut respond, 400);
                continue;
            }
        };
        let permit = match budget.acquire(class) {
            Ok(permit) => permit,
            Err(_) => {
                reject(&mut respond, 503);
                continue;
            }
        };
        circuits.push(forward(
            request.into_body(),
            respond,
            target,
            class,
            permit,
            connect.clone(),
        ));
    }
}

fn decode_target(request: &http::Request<h2::RecvStream>) -> Result<Target> {
    let uri = request.uri();
    if request.method() != http::Method::POST
        || uri.scheme_str() != Some("https")
        || uri.authority().map(|a| a.as_str()) != Some("gct2.invalid")
        || uri.query().is_some()
        || request.headers().len() != 1
        || request.headers().get("content-type").map(|v| v.as_bytes())
            != Some(b"application/octet-stream".as_slice())
    {
        return Err("noncanonical GCT2 logical request".into());
    }
    let encoded = uri
        .path()
        .strip_prefix("/circuit/")
        .ok_or("GCT2 circuit path required")?;
    if encoded.len() > 342 {
        return Err("GCT2 circuit target exceeds bound".into());
    }
    let raw = gcoms_transport::decode_b64url(encoded).ok_or("invalid GCT2 target encoding")?;
    if gcoms_transport::encode_b64url(&raw) != encoded {
        return Err("noncanonical GCT2 target encoding".into());
    }
    Target::decode(&raw)
}

fn reject(respond: &mut h2::server::SendResponse<Bytes>, status: u16) {
    let _ = respond.send_response(
        http::Response::builder().status(status).body(()).unwrap(),
        true,
    );
}

async fn forward(
    body: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    target: Target,
    class: TrafficClass,
    _permit: CircuitPermit,
    connect: TargetConnector,
) {
    let connected = tokio::select! {
        _ = poll_fn(|cx| respond.poll_reset(cx)) => return,
        result = timeout(OPEN_TIMEOUT, connect(target, class)) => result,
    };
    let Ok(Ok(mut target)) = connected else {
        reject(&mut respond, 502);
        return;
    };
    let headers = http::Response::builder()
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();
    let Ok(send) = respond.send_response(headers, false) else {
        return;
    };
    let mut stream = H2Stream::new(body, send);
    let _ = tokio::io::copy_bidirectional_with_sizes(&mut stream, &mut target, 8192, 8192).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn target() -> Target {
        Target::Relay {
            addr: "192.0.2.7:443".parse().unwrap(),
            service_id: [7; 32],
        }
    }

    async fn pair(
        class: TrafficClass,
        client_budget: Arc<CircuitBudget>,
        server_budget: Arc<CircuitBudget>,
        connect: TargetConnector,
        tasks: &mut tokio::task::JoinSet<()>,
    ) -> MuxClient {
        let (client_io, server_io) = tokio::io::duplex(8192);
        tasks.spawn(async move {
            let _ = serve(server_io, class, server_budget, connect).await;
        });
        let (client, driver) = MuxClient::handshake(client_io, class, client_budget)
            .await
            .unwrap();
        tasks.spawn(async move {
            let _ = driver.await;
        });
        client
    }

    async fn until_active(budget: &CircuitBudget, expected: usize) {
        timeout(Duration::from_secs(2), async {
            while budget.active() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    fn connector(peers: Arc<Mutex<Vec<DuplexStream>>>) -> TargetConnector {
        Arc::new(move |requested, _class| {
            assert_eq!(requested, target());
            let (local, remote) = tokio::io::duplex(8192);
            peers.lock().unwrap().push(remote);
            Box::pin(async move { Ok(Box::new(local) as BoxStream) })
        })
    }

    #[tokio::test]
    async fn class_channels_share_sixteen_circuits_with_an_interactive_reserve() {
        let client_budget = Arc::new(CircuitBudget::default());
        let server_budget = Arc::new(CircuitBudget::default());
        let peers = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = tokio::task::JoinSet::new();
        let bulk = pair(
            TrafficClass::Bulk,
            client_budget.clone(),
            server_budget.clone(),
            connector(peers.clone()),
            &mut tasks,
        )
        .await;
        let chat = pair(
            TrafficClass::Interactive,
            client_budget.clone(),
            server_budget.clone(),
            connector(peers.clone()),
            &mut tasks,
        )
        .await;
        let mut streams = Vec::new();
        for _ in 0..MAX_BULK_CIRCUITS {
            streams.push(bulk.open(&target()).await.unwrap());
        }
        assert!(bulk.open(&target()).await.is_err());
        streams.push(chat.open(&target()).await.unwrap());
        assert_eq!(client_budget.active(), MAX_CIRCUITS);
        assert_eq!(server_budget.active(), MAX_CIRCUITS);
        assert_eq!(peers.lock().unwrap().len(), MAX_CIRCUITS);
        assert!(chat.open(&target()).await.is_err());
        drop(streams.remove(0));
        assert_eq!(client_budget.active(), MAX_CIRCUITS - 1);
        until_active(&server_budget, MAX_CIRCUITS - 1).await;
        let reopened = bulk.open(&target()).await.unwrap();
        assert_eq!(server_budget.active(), MAX_CIRCUITS);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(server_budget.active(), 0, "server owns all circuit work");
        drop((streams, reopened));
        assert_eq!(client_budget.active(), 0);
    }

    #[tokio::test]
    async fn server_enforces_shared_budget_even_with_uncooperative_client_budgets() {
        let server_budget = Arc::new(CircuitBudget::default());
        let peers = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = tokio::task::JoinSet::new();
        let bulk = pair(
            TrafficClass::Bulk,
            Arc::new(CircuitBudget::default()),
            server_budget.clone(),
            connector(peers.clone()),
            &mut tasks,
        )
        .await;
        let chat = pair(
            TrafficClass::Interactive,
            Arc::new(CircuitBudget::default()),
            server_budget.clone(),
            connector(peers.clone()),
            &mut tasks,
        )
        .await;
        let mut held = Vec::new();
        for _ in 0..MAX_BULK_CIRCUITS {
            held.push(bulk.open(&target()).await.unwrap());
        }
        held.push(chat.open(&target()).await.unwrap());
        // This client still has 15 local permits. The service must refuse it.
        assert!(chat.open(&target()).await.is_err());
        assert_eq!(
            peers.lock().unwrap().len(),
            MAX_CIRCUITS,
            "refused requests never dial a target"
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(server_budget.active(), 0);
    }

    #[tokio::test]
    async fn canceled_open_cancels_target_connection_and_returns_both_credits() {
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let observed = Arc::new(Mutex::new(Some(owner)));
        let connect: TargetConnector = Arc::new(move |_, _| {
            let owned = observed.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _owned = owned;
                std::future::pending().await
            })
        });
        let client_budget = Arc::new(CircuitBudget::default());
        let server_budget = Arc::new(CircuitBudget::default());
        let mut tasks = tokio::task::JoinSet::new();
        let client = pair(
            TrafficClass::Interactive,
            client_budget.clone(),
            server_budget.clone(),
            connect,
            &mut tasks,
        )
        .await;
        let opened = tokio::spawn(async move { client.open(&target()).await });
        until_active(&server_budget, 1).await;
        opened.abort();
        assert!(opened.await.err().unwrap().is_cancelled());
        assert_eq!(client_budget.active(), 0);
        until_active(&server_budget, 0).await;
        assert!(weak.upgrade().is_none());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn slow_bulk_consumer_does_not_block_interactive_streams() {
        let client_budget = Arc::new(CircuitBudget::default());
        let server_budget = Arc::new(CircuitBudget::default());
        let peers = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = tokio::task::JoinSet::new();
        let bulk = pair(
            TrafficClass::Bulk,
            client_budget.clone(),
            server_budget.clone(),
            connector(peers.clone()),
            &mut tasks,
        )
        .await;
        let chat = pair(
            TrafficClass::Interactive,
            client_budget,
            server_budget.clone(),
            connector(peers.clone()),
            &mut tasks,
        )
        .await;
        let mut stream = bulk.open(&target()).await.unwrap();
        let bulk_bytes = vec![1; 1024 * 1024];
        assert!(
            timeout(Duration::from_millis(30), stream.write_all(&bulk_bytes))
                .await
                .is_err()
        );
        let mut interactive = chat.open(&target()).await.unwrap();
        let mut peer = peers.lock().unwrap().pop().unwrap();
        timeout(Duration::from_secs(2), async {
            interactive.write_all(b"hello").await.unwrap();
            let mut received = [0; 5];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"hello");
            peer.write_all(b"reply").await.unwrap();
            interactive.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"reply");
        })
        .await
        .unwrap();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(server_budget.active(), 0);
    }
}
