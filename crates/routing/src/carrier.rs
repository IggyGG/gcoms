//! Fixed-size, bounded, full-duplex carriers. TLS remains above this byte stream.
use crate::{
    wire::{Kind, Record, Target, MAX_DATA, RECORD_SIZE},
    Result,
};
use bytes::Bytes;
use gcoms_transport::{connector::BoxStream, tls};
use http::{Request, Response};
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;

const STREAM_BUFFER: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const RECORD_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
pub struct CarrierConfig {
    /// One padded record per slot in each direction, including idle cover.
    pub slot: Duration,
    pub lifetime: Duration,
    pub byte_limit: u64,
}

impl Default for CarrierConfig {
    fn default() -> Self {
        Self {
            slot: Duration::from_millis(100),
            lifetime: Duration::from_secs(1800),
            byte_limit: 128 * 1024 * 1024,
        }
    }
}

impl CarrierConfig {
    pub fn fixture() -> Self {
        Self {
            slot: Duration::from_millis(1),
            ..Self::default()
        }
    }

    pub fn validate(self) -> Result<Self> {
        if self.slot.is_zero()
            || self.slot > Duration::from_secs(10)
            || self.lifetime.is_zero()
            || self.lifetime > Duration::from_secs(3600)
            || self.byte_limit == 0
            || self.byte_limit > 256 * 1024 * 1024
        {
            return Err("invalid carrier resource policy".into());
        }
        Ok(self)
    }
}

/// The guard cancels the complete nested stack when the outer owner drops it.
struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct CarrierStream {
    io: tokio::io::DuplexStream,
    _driver: Task,
}

impl AsyncRead for CarrierStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for CarrierStream {
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

pub async fn open(
    io: BoxStream,
    relay: &crate::Relay,
    target: &Target,
    config: CarrierConfig,
) -> Result<BoxStream> {
    let config = config.validate()?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let tls = TlsConnector::from(Arc::new(tls::client_config_pinned(relay.service_id)?))
            .connect(tls::server_name_ip(relay.addr.ip()), io)
            .await?;
        if tls.get_ref().1.alpn_protocol() != Some(tls::ALPN_H2) {
            return Err("circuit hop did not negotiate h2".into());
        }
        let (mut sender, connection) = h2::client::Builder::new()
            .max_frame_size(16384)
            .initial_window_size(STREAM_BUFFER as u32)
            .initial_connection_window_size((STREAM_BUFFER * 2) as u32)
            .handshake(tls)
            .await?;
        let connection = Task(tokio::spawn(async move {
            let _ = connection.await;
        }));
        poll_fn(|cx| sender.poll_ready(cx)).await?;
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/{token}",
                relay.addr,
                token = gcoms_transport::encode_b64url(&relay.circuit_cap)
            ))
            .header("content-type", "application/octet-stream")
            .body(())?;
        let (response, mut send) = sender.send_request(request, false)?;
        send_record(&mut send, Kind::Open, &target.encode(), false).await?;
        let response = response.await?;
        if response.status() != 200 {
            return Err("circuit capability refused".into());
        }
        let mut receive = Records::new(response.into_body());
        let opened = receive.next().await?;
        if opened.kind != Kind::Opened || opened.payload != [0] {
            return Err("circuit extension refused".into());
        }
        let (local, tunnel) = tokio::io::duplex(STREAM_BUFFER);
        let driver = Task(tokio::spawn(async move {
            let _connection = connection;
            let _ =
                tokio::time::timeout(config.lifetime, pump(tunnel, send, receive, config)).await;
        }));
        Ok(Box::new(CarrierStream {
            io: local,
            _driver: driver,
        }) as BoxStream)
    })
    .await
    .map_err(|_| "circuit handshake timed out")?
}

/// Refresh private introductions using a retained service pin and re-entry
/// capability. The supplied stream may be a bootstrap connection to an entry,
/// or a complete circuit once the node is online. This performs no application
/// operation and never grants queue ownership.
pub async fn refresh(io: BoxStream, seed: &crate::Relay) -> Result<Vec<crate::Relay>> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (_connection, mut records) = private_request(io, seed, Kind::Introduce, &[]).await?;
        let record = records.next().await?;
        let count = record.payload.first().copied().unwrap_or(0) as usize;
        if record.kind != Kind::Introductions
            || !(1..=8).contains(&count)
            || record.payload.len() != 1 + count * crate::directory::RELAY_BYTES
        {
            return Err("invalid private introduction response".into());
        }
        let mut introductions = Vec::with_capacity(count);
        for raw in record.payload[1..]
            .as_chunks::<{ crate::directory::RELAY_BYTES }>()
            .0
        {
            let relay = crate::Relay::decode(raw)?;
            if introductions
                .iter()
                .any(|r: &crate::Relay| r.service_id == relay.service_id)
            {
                return Err("duplicate introduced relay identity".into());
            }
            introductions.push(relay);
        }
        if introductions[0].service_id != seed.service_id
            || introductions[0].addr != seed.addr
            || introductions[0].reentry_cap != seed.reentry_cap
        {
            return Err("re-entry response changed pinned service".into());
        }
        Ok(introductions)
    })
    .await
    .map_err(|_| "re-entry handshake timed out")?
}

pub const MAX_PROVISION_BYTES: usize = 64 * 1024;

/// Queue authority is requested only over a complete circuit by the runtime.
/// The request ID remains stable across a bounded retry so a lost response does
/// not allocate another inbox. It never contains the client's GC identity.
/// Bounded trailing options may request later card kinds; a request ID is bound
/// to its options and is never reused with different ones.
pub async fn provision(
    io: BoxStream,
    relay: &crate::Relay,
    request_id: [u8; 32],
    options: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if options.len() > 8 {
        return Err("private provision options exceed the bound".into());
    }
    let mut request = Vec::with_capacity(32 + options.len());
    request.extend_from_slice(&request_id);
    request.extend_from_slice(options);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (_connection, mut records) =
            private_request(io, relay, Kind::Provision, &request).await?;
        let mut out = zeroize::Zeroizing::new(Vec::new());
        let mut total = None;
        loop {
            let mut record = records.next().await?;
            if record.kind != Kind::Provisioned || record.payload.len() <= 4 {
                return Err("invalid private provision response".into());
            }
            let length = u32::from_be_bytes(record.payload[..4].try_into()?) as usize;
            if length == 0 || length > MAX_PROVISION_BYTES || total.is_some_and(|n| n != length) {
                return Err("private provision exceeds bounds".into());
            }
            total = Some(length);
            if record.payload.len() - 4 > length - out.len() {
                return Err("private provision has trailing bytes".into());
            }
            out.extend_from_slice(&record.payload[4..]);
            zeroize::Zeroize::zeroize(&mut record.payload);
            if out.len() == length {
                return Ok(out);
            }
        }
    })
    .await
    .map_err(|_| "private provision timed out")?
}

/// Publish a service through a circuit. The receiving relay independently
/// probes the claimed public address and pin before admitting the descriptor.
pub async fn advertise(io: BoxStream, relay: &crate::Relay, own: &crate::Relay) -> Result<()> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (_connection, mut records) =
            private_request(io, relay, Kind::Advertise, &own.encode()?).await?;
        let record = records.next().await?;
        if record.kind != Kind::Advertised || record.payload != [0] {
            return Err("public reachability probe refused advertisement".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "advertisement probe timed out")?
}

async fn private_request(
    io: BoxStream,
    relay: &crate::Relay,
    kind: Kind,
    payload: &[u8],
) -> Result<(Task, Records)> {
    let tls = TlsConnector::from(Arc::new(tls::client_config_pinned(relay.service_id)?))
        .connect(tls::server_name_ip(relay.addr.ip()), io)
        .await?;
    if tls.get_ref().1.alpn_protocol() != Some(tls::ALPN_H2) {
        return Err("private relay service did not negotiate h2".into());
    }
    let (mut sender, connection) = h2::client::Builder::new()
        .max_frame_size(16384)
        .initial_window_size(STREAM_BUFFER as u32)
        .initial_connection_window_size((STREAM_BUFFER * 2) as u32)
        .handshake(tls)
        .await?;
    let connection = Task(tokio::spawn(async move {
        let _ = connection.await;
    }));
    poll_fn(|cx| sender.poll_ready(cx)).await?;
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://{}/{token}",
            relay.addr,
            token = gcoms_transport::encode_b64url(&relay.reentry_cap)
        ))
        .header("content-type", "application/octet-stream")
        .body(())?;
    let (response, mut send) = sender.send_request(request, false)?;
    send_record(&mut send, kind, payload, true).await?;
    let response = response.await?;
    if response.status() != 200 {
        return Err("private relay capability refused".into());
    }
    Ok((connection, Records::new(response.into_body())))
}

pub(crate) async fn respond(
    response: &mut h2::server::SendResponse<Bytes>,
    status: u8,
) -> Result<h2::SendStream<Bytes>> {
    let headers = Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(())?;
    let mut send = response.send_response(headers, false)?;
    send_record(&mut send, Kind::Opened, &[status], status != 0).await?;
    Ok(send)
}

pub(crate) async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    mut send: h2::SendStream<Bytes>,
    mut receive: Records,
    config: CarrierConfig,
) -> Result<()> {
    let (mut read, mut write) = tokio::io::split(io);
    tokio::try_join!(
        write_records(&mut read, &mut send, config),
        read_records(&mut receive, &mut write, config.byte_limit),
    )?;
    Ok(())
}

async fn write_records<R: AsyncRead + Unpin>(
    read: &mut R,
    send: &mut h2::SendStream<Bytes>,
    config: CarrierConfig,
) -> Result<()> {
    let mut timer = tokio::time::interval(config.slot);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buffer = [0; MAX_DATA];
    let mut len = 0;
    let mut eof = false;
    let mut sent = 0u64;
    loop {
        tokio::select! {
            biased;
            _ = timer.tick() => {
                if len != 0 {
                    sent = sent.checked_add(len as u64).ok_or("carrier byte count overflow")?;
                    if sent > config.byte_limit { return Err("carrier byte budget exhausted".into()); }
                    send_record(send, Kind::Data, &buffer[..len], false).await?;
                    len = 0;
                } else if eof {
                    send_record(send, Kind::Close, &[], true).await?;
                    return Ok(());
                } else {
                    send_record(send, Kind::Cover, &[], false).await?;
                }
            }
            result = read.read(&mut buffer[len..]), if len < MAX_DATA && !eof => {
                let count = result?;
                if count == 0 { eof = true; } else { len += count; }
            }
        }
    }
}

async fn read_records<W: AsyncWrite + Unpin>(
    receive: &mut Records,
    write: &mut W,
    limit: u64,
) -> Result<()> {
    let mut received = 0u64;
    loop {
        let record = receive.next().await?;
        match record.kind {
            Kind::Data => {
                received = received
                    .checked_add(record.payload.len() as u64)
                    .ok_or("carrier byte count overflow")?;
                if received > limit {
                    return Err("carrier byte budget exhausted".into());
                }
                write.write_all(&record.payload).await?;
            }
            Kind::Cover => (),
            Kind::Close => {
                write.shutdown().await?;
                return Ok(());
            }
            _ => return Err("unexpected established carrier operation".into()),
        }
    }
}

pub(crate) async fn send_record(
    send: &mut h2::SendStream<Bytes>,
    kind: Kind,
    payload: &[u8],
    end: bool,
) -> Result<()> {
    let bytes = Bytes::copy_from_slice(&Record::encode(kind, payload)?);
    send.reserve_capacity(RECORD_SIZE);
    while send.capacity() < RECORD_SIZE {
        match poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(_)) => (),
            Some(Err(error)) => return Err(error.into()),
            None => return Err("carrier send stream closed".into()),
        }
    }
    send.send_data(bytes, end)?;
    Ok(())
}

/// Accept arbitrary H2 fragmentation/coalescing with one fixed record buffer.
pub(crate) struct Records {
    body: h2::RecvStream,
    pending: Bytes,
}

impl Records {
    pub(crate) fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            pending: Bytes::new(),
        }
    }

    pub(crate) async fn next(&mut self) -> Result<Record> {
        tokio::time::timeout(RECORD_TIMEOUT, async {
            let mut bytes = [0; RECORD_SIZE];
            let mut len = 0;
            while len < RECORD_SIZE {
                if self.pending.is_empty() {
                    self.pending = self
                        .body
                        .data()
                        .await
                        .ok_or("carrier truncated before close")??;
                    if self.pending.len() > 16384 {
                        return Err("carrier H2 frame exceeds bound".into());
                    }
                    // Empty DATA frames cannot increase storage; the absolute
                    // record deadline bounds a peer sending empty frames only.
                    continue;
                }
                let n = (RECORD_SIZE - len).min(self.pending.len());
                bytes[len..len + n].copy_from_slice(&self.pending.split_to(n));
                self.body.flow_control().release_capacity(n)?;
                len += n;
            }
            Record::decode(&bytes)
        })
        .await
        .map_err(|_| "carrier record timed out")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn receive_fragments(parts: Vec<Vec<u8>>) -> (Records, Task) {
        let (client, server) = tokio::io::duplex(STREAM_BUFFER);
        let server = Task(tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            let count = parts.len();
            for (index, part) in parts.into_iter().enumerate() {
                send.send_data(Bytes::from(part), index + 1 == count)
                    .unwrap();
            }
            while connection.accept().await.is_some() {}
        }));
        let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
        let driver = Task(tokio::spawn(async move {
            let _server = server;
            let _ = connection.await;
        }));
        let (response, _) = sender.send_request(Request::new(()), true).unwrap();
        (Records::new(response.await.unwrap().into_body()), driver)
    }

    #[tokio::test]
    async fn arbitrary_h2_fragmentation_and_partial_eof() {
        let data = Record::encode(Kind::Data, &[7; 2000]).unwrap();
        let close = Record::encode(Kind::Close, &[]).unwrap();
        let all = [data.as_slice(), close.as_slice()].concat();
        for boundaries in [vec![1, 4, 100, 4100, all.len()], vec![all.len()]] {
            let mut start = 0;
            let parts = boundaries
                .into_iter()
                .map(|end| {
                    let part = all[start..end].to_vec();
                    start = end;
                    part
                })
                .collect();
            let (mut records, _driver) = receive_fragments(parts).await;
            assert_eq!(records.next().await.unwrap().payload, vec![7; 2000]);
            assert_eq!(records.next().await.unwrap().kind, Kind::Close);
        }
        let (mut records, _driver) =
            receive_fragments(vec![data[..RECORD_SIZE - 1].to_vec()]).await;
        assert!(records.next().await.is_err());
    }
}
