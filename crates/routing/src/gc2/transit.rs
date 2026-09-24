//! Independently authenticated middle extension inside a protected entry
//! circuit. No second cover schedule or fixed padding is added at this hop.
use super::{
    entry::MAX_LIFETIME,
    mux::{PendingSend, TargetConnector},
};
use crate::{route::now_unix, wire::Target, Result};
use gcoms_core::TrafficClass;
use gcoms_transport::{connector::BoxStream, duplex::H2Stream, server::AcceptedDuplex, tls};
use std::{
    future::{poll_fn, Future},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::oneshot,
    time::{timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"GCX2";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const WINDOW: u32 = 32 * 1024;
type Driver = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone)]
pub struct TransitDescriptor {
    pub addr: SocketAddr,
    pub service_id: [u8; 32],
    pub transit_cap: [u8; 32],
    pub expires_at: u64,
}

impl Drop for TransitDescriptor {
    fn drop(&mut self) {
        self.transit_cap.zeroize();
    }
}

impl TransitDescriptor {
    pub fn validate(&self) -> Result<()> {
        crate::wire::decode_address(&crate::wire::encode_address(self.addr))?;
        if self.service_id == [0; 32]
            || self.transit_cap == [0; 32]
            || self.expires_at <= now_unix()
        {
            return Err("invalid or expired GC/2 transit authority".into());
        }
        Ok(())
    }
}

pub(super) async fn open(
    stream: BoxStream,
    class: TrafficClass,
    relay: &TransitDescriptor,
    target: &Target,
) -> Result<(BoxStream, Driver)> {
    relay.validate()?;
    let deadline = super::authority_deadline(relay.expires_at, MAX_LIFETIME)
        .ok_or("GC/2 middle authority expired")?;
    timeout_at(deadline.min(tokio::time::Instant::now() + HANDSHAKE_TIMEOUT), async {
        let tls = TlsConnector::from(Arc::new(tls::client_config_pinned(relay.service_id)?))
            .connect(tls::server_name_ip(relay.addr.ip()), stream).await
            .map_err(|error| format!("TLS handshake: {error}"))?;
        if tls.get_ref().1.alpn_protocol() != Some(tls::ALPN_H2) {
            return Err("GC/2 middle did not negotiate HTTP2".into());
        }
        let (mut sender, connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW).initial_connection_window_size(WINDOW * 2)
            .max_frame_size(16 * 1024).max_send_buffer_size(WINDOW as usize)
            .max_header_list_size(1024).header_table_size(0).initial_max_send_streams(1)
            .max_concurrent_reset_streams(1).max_pending_accept_reset_streams(1)
            .max_local_error_reset_streams(Some(1)).enable_push(false)
            .handshake(tls).await?;
        let mut connection = Box::pin(connection);
        let io = tokio::select! {
            result = &mut connection => { result?; return Err("GC/2 middle disconnected during open".into()); },
            result = async {
                poll_fn(|cx| sender.poll_ready(cx)).await?;
                let request = http::Request::builder().method("POST")
                    .uri(format!("https://{}/{}", relay.addr, gcoms_transport::encode_b64url(&relay.transit_cap)))
                    .header("content-type", "application/octet-stream").body(())?;
                let (response, send) = sender.send_request(request, false)?;
                let mut pending = PendingSend(Some(send));
                let response = response.await
                    .map_err(|error| format!("transit admission response: {error}"))?;
                if response.status() != 200 { return Err("GC/2 transit capability refused".into()); }
                let mut io = H2Stream::new(response.into_body(), pending.0.take().unwrap());
                let target = target.encode();
                Target::decode(&target)?;
                let mut opened = Vec::with_capacity(7 + target.len());
                opened.extend_from_slice(MAGIC);
                opened.push(class as u8);
                opened.extend_from_slice(&(target.len() as u16).to_be_bytes());
                opened.extend_from_slice(&target);
                io.write_all(&opened).await?;
                let mut ack = [0; 6];
                io.read_exact(&mut ack).await
                    .map_err(|error| format!("target connection acknowledgment: {error}"))?;
                if &ack[..4] != MAGIC || ack[4] != class as u8 || ack[5] != 0 {
                    return Err("GC/2 transit acknowledgment mismatch".into());
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(io)
            } => result?,
        };
        drop(sender);
        let (cancel, canceled) = oneshot::channel::<()>();
        let driver: Driver = Box::pin(async move {
            tokio::select! {
                _ = canceled => (),
                _ = tokio::time::sleep_until(deadline) => (),
                _ = connection => (),
            }
        });
        Ok((Box::new(TransitStream { io, _cancel: cancel }) as BoxStream, driver))
    }).await.map_err(|_| "GC/2 transit handshake timed out")?
}

struct TransitStream {
    io: H2Stream,
    _cancel: oneshot::Sender<()>,
}

impl AsyncRead for TransitStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for TransitStream {
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

pub(crate) fn accept(expires_at: u64, connect: TargetConnector) -> AcceptedDuplex {
    Box::new(move |body, mut respond| {
        Box::pin(async move {
            let Some(deadline) = super::authority_deadline(expires_at, MAX_LIFETIME) else {
                return;
            };
            let headers = http::Response::builder()
                .header("content-type", "application/octet-stream")
                .body(())
                .unwrap();
            let Ok(send) = respond.send_response(headers, false) else {
                return;
            };
            let mut io = H2Stream::new(body, send);
            let _ = timeout_at(deadline, async {
            let opened = timeout(HANDSHAKE_TIMEOUT, async {
                let mut header = [0; 7];
                io.read_exact(&mut header).await?;
                if &header[..4] != MAGIC { return Err("GC/2 transit version required".into()); }
                let class = TrafficClass::from_byte(header[4]).ok_or("invalid transit class")?;
                let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
                if !(1..=256).contains(&length) { return Err("GC/2 target exceeds bound".into()); }
                let mut target = vec![0; length];
                io.read_exact(&mut target).await?;
                let target = Target::decode(&target)?;
                let connected = tokio::select! {
                    _ = poll_fn(|cx| io.poll_reset(cx)) => return Err("GC/2 transit open canceled".into()),
                    connected = connect(target, class) => connected?,
                };
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connected, class))
            }).await.map_err(|_| "GC/2 transit open timed out")??;
            let (mut target, class) = opened;
            io.write_all(&[MAGIC.as_slice(), &[class as u8, 0]].concat()).await?;
            tokio::io::copy_bidirectional_with_sizes(&mut io, &mut target, 8192, 8192).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }).await;
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test(start_paused = true)]
    async fn authority_expiry_cancels_partial_open_before_a_target_is_dialed() {
        let connect: TargetConnector =
            Arc::new(|_, _| panic!("expired partial open dialed a target"));
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            tokio::select! {
                _ = accept(now_unix() + 2, connect)(request.into_body(), respond) => (),
                _ = async { while connection.accept().await.is_some() {} } => (),
            }
        });
        let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
        let connection = tokio::spawn(connection);
        let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
        let mut wire = H2Stream::new(response.await.unwrap().into_body(), send);
        wire.write_all(b"GC").await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        timeout(Duration::from_millis(1), server)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert!(!matches!(wire.read(&mut byte).await, Ok(n) if n > 0));
        drop((wire, sender));
        timeout(Duration::from_secs(1), connection)
            .await
            .unwrap()
            .unwrap()
            .ok();
    }

    #[tokio::test]
    async fn reset_cancels_an_admitted_middle_target_connection() {
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let (entered, started) = oneshot::channel::<()>();
        let capture = Arc::new(Mutex::new(Some((owner, entered))));
        let connect: TargetConnector = Arc::new(move |_, _| {
            let (owner, entered) = capture.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _owner = owner;
                entered.send(()).unwrap();
                std::future::pending().await
            })
        });
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            tokio::select! {
                _ = accept(now_unix() + 60, connect)(request.into_body(), respond) => (),
                _ = async { while connection.accept().await.is_some() {} } => (),
            }
        });
        let (mut sender, driver) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(driver);
        let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
        let mut io = H2Stream::new(response.await.unwrap().into_body(), send);
        let target = Target::Relay {
            addr: "192.0.2.7:443".parse().unwrap(),
            service_id: [7; 32],
        }
        .encode();
        let mut open = MAGIC.to_vec();
        open.push(TrafficClass::Bulk as u8);
        open.extend_from_slice(&(target.len() as u16).to_be_bytes());
        open.extend_from_slice(&target);
        io.write_all(&open).await.unwrap();
        timeout(Duration::from_secs(2), started)
            .await
            .unwrap()
            .unwrap();
        drop(io);
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            weak.upgrade().is_none(),
            "peer reset must cancel owned target work"
        );
        drop(sender);
        timeout(Duration::from_secs(2), driver)
            .await
            .unwrap()
            .unwrap()
            .ok();
    }
}
