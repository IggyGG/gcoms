//! Byte-stream acquisition beneath TP1's independent endpoint authentication.
use crate::client::Result;
use std::{future::Future, net::SocketAddr, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;
pub type ConnectFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxStream>> + Send + 'a>>;

/// Implementations return an unauthenticated stream to the exact terminal
/// service. TP1 still authenticates that service using its own TLS pin.
pub trait Connector: Send + Sync {
    fn connect(&self, addr: SocketAddr, service_id: [u8; 32]) -> ConnectFuture<'_>;

    /// Additional terminal services (for example inside an existing FRWD)
    /// cannot appear as an onion intermediary. Direct transit has no path to
    /// select; routing implementations must enforce these exclusions.
    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        if excluded.is_empty() {
            self.connect(addr, service_id)
        } else {
            Box::pin(async { Err("connector does not support terminal exclusions".into()) })
        }
    }
}

/// Direct transport for relay transit and explicitly local fixtures. Production
/// endpoint owners must install their routing connector with `with_connector`.
#[derive(Default)]
pub struct DirectConnector;

impl Connector for DirectConnector {
    fn connect(&self, addr: SocketAddr, _service_id: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        _excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        // Explicit transit/fixture connector: no intermediary path is selected.
        self.connect(addr, service_id)
    }
}
