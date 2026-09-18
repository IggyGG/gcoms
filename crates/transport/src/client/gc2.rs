//! Explicit natural-cell transport. It never accepts GC/1 framing and adds no
//! cover schedule. A protected route must be provided by the caller's connector.
use super::{ConnectionLease, RequestBody, Result, Route, Tp1Client, REQUEST_TIMEOUT};
use crate::hop::HopReply;
use bytes::Bytes;
use gcoms_core::{
    gc2::{NaturalCell, MAX_CELL, VERSION},
    CellType, TrafficClass, HEADER_LEN,
};
use http::{Method, StatusCode};
use std::{future::poll_fn, net::SocketAddr};
use tokio::time::Instant;

/// A pinned terminal and authenticated traffic intent. Exclusions participate
/// in pool selection; a class-bound connector also fixes the circuit class.
#[derive(Clone, Copy)]
pub struct NaturalRoute<'a> {
    pub addr: SocketAddr,
    pub service_id: [u8; 32],
    pub token: &'a str,
    pub excluded: &'a [(SocketAddr, [u8; 32])],
    pub class: TrafficClass,
}

impl NaturalRoute<'_> {
    fn route(&self) -> Route<'_> {
        Route {
            addr: self.addr,
            service_id: self.service_id,
            excluded: self.excluded,
        }
    }
}

fn prepared<'a, F>(class: TrafficClass, make: F) -> RequestBody<'a>
where
    F: FnOnce() -> Result<NaturalCell> + Send + 'a,
{
    RequestBody::Prepare(Some(Box::new(move || {
        let cell = make()?;
        if matches!(
            cell.kind(),
            CellType::RelayPush | CellType::RelaySub | CellType::Frwd
        ) && cell.payload().first().copied() != Some(class as u8)
        {
            return Err("GC/2 envelope class does not match its route".into());
        }
        Ok(Bytes::from(cell.encode()))
    })))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaturalOutcome {
    /// Hop admission only, not recipient or application delivery.
    Accepted(Option<NaturalCell>),
    Conflict,
    Overloaded,
    Internal,
    Decoy(u16),
}

/// All status outcomes use the same eight-byte natural encoding. The selected
/// carrier supplies traffic protection; this helper does not pad the reply.
pub fn status_cell(reply: HopReply) -> NaturalCell {
    NaturalCell::new(
        CellType::Ack,
        0,
        vec![crate::hop::HOP_REPLY_VERSION, reply.code()],
    )
    .expect("static natural status")
}

pub fn parse_status(cell: &NaturalCell) -> Option<HopReply> {
    if cell.kind() != CellType::Ack
        || cell.flags() != 0
        || cell.payload().len() != 2
        || cell.payload()[0] != crate::hop::HOP_REPLY_VERSION
    {
        return None;
    }
    HopReply::from_code(cell.payload()[1])
}

fn outcome(status: StatusCode, body: &[u8]) -> Result<NaturalOutcome> {
    if status != StatusCode::OK {
        return Ok(NaturalOutcome::Decoy(status.as_u16()));
    }
    let cell = NaturalCell::decode(body)?;
    Ok(match parse_status(&cell) {
        Some(HopReply::Accepted) => NaturalOutcome::Accepted(None),
        Some(HopReply::Conflict) => NaturalOutcome::Conflict,
        Some(HopReply::Overloaded) => NaturalOutcome::Overloaded,
        Some(HopReply::Internal) => NaturalOutcome::Internal,
        None if cell.kind() == CellType::Ack && cell.payload().len() == 2 => {
            return Err("invalid GC/2 hop status".into())
        }
        None => NaturalOutcome::Accepted(Some(cell)),
    })
}

impl Tp1Client {
    /// Prepares exact authenticated bytes after connection/request admission.
    /// Ambiguous retries keep the original bytes, expiry and traffic class.
    pub async fn post_natural_prepared<F>(
        &self,
        route: NaturalRoute<'_>,
        make: F,
    ) -> Result<NaturalOutcome>
    where
        F: FnOnce() -> Result<NaturalCell> + Send,
    {
        let (status, body) = self
            .finite_request(
                route.route(),
                Method::POST,
                &format!("/{}", route.token),
                prepared(route.class, make),
                route.class,
            )
            .await?;
        outcome(status, &body)
    }

    /// The first cell must explicitly accept the subscription. Subsequent cells
    /// must be GC/2 MSGs. The absolute deadline bounds even a silent server; idle
    /// application periods have no cell-arrival timer or artificial cover here.
    pub async fn open_natural_prepared<F>(
        &self,
        route: NaturalRoute<'_>,
        deadline: Instant,
        make: F,
    ) -> Result<NaturalStream>
    where
        F: FnOnce() -> Result<NaturalCell> + Send,
    {
        if deadline <= Instant::now() {
            return Err("GC/2 subscription deadline elapsed".into());
        }
        let setup_deadline = deadline.min(Instant::now() + REQUEST_TIMEOUT);
        let (response, connection) = tokio::time::timeout_at(
            setup_deadline,
            self.request(
                route.route(),
                Method::POST,
                &format!("/{}", route.token),
                prepared(route.class, make),
                route.class,
            ),
        )
        .await
        .map_err(|_| "GC/2 subscription deadline elapsed")??;
        if response.status() != StatusCode::OK {
            return Err(format!("GC/2 stream refused: {}", response.status()).into());
        }
        let mut stream = NaturalStream {
            body: Some(response.into_body()),
            pending: Bytes::new(),
            buffer: Vec::with_capacity(HEADER_LEN),
            expected: HEADER_LEN,
            guard: Some(connection),
            deadline: setup_deadline,
        };
        let accepted = stream
            .next()
            .await
            .ok_or("GC/2 subscription ended before acceptance")??;
        if parse_status(&accepted) != Some(HopReply::Accepted) {
            return Err("GC/2 subscription was not accepted".into());
        }
        stream.deadline = deadline;
        Ok(stream)
    }
}

/// Cancellation-safe incremental framing with at most one natural cell and one
/// HTTP/2 frame buffered. Receive credit returns only as framing consumes bytes.
pub struct NaturalStream {
    body: Option<h2::RecvStream>,
    pending: Bytes,
    buffer: Vec<u8>,
    expected: usize,
    guard: Option<ConnectionLease>,
    deadline: Instant,
}

impl NaturalStream {
    fn finish(&mut self) {
        self.body.take();
        self.guard.take();
        self.pending = Bytes::new();
        self.buffer.clear();
    }

    async fn next(&mut self) -> Option<Result<NaturalCell>> {
        self.body.as_ref()?;
        if self.deadline <= Instant::now() {
            self.finish();
            return Some(Err("GC/2 subscription deadline elapsed".into()));
        }
        let result = match tokio::time::timeout_at(self.deadline, self.next_inner()).await {
            Ok(result) => result,
            Err(_) => Some(Err("GC/2 subscription deadline elapsed".into())),
        };
        if result.as_ref().is_none_or(|result| result.is_err()) {
            self.finish();
        }
        result
    }

    async fn next_inner(&mut self) -> Option<Result<NaturalCell>> {
        let mut empty_frames = 0;
        loop {
            if self.buffer.len() == self.expected {
                if self.expected == HEADER_LEN {
                    let header = &self.buffer;
                    let payload = u16::from_be_bytes([header[4], header[5]]) as usize;
                    if header[0] >> 4 != VERSION
                        || header[2..4] != [0, 0]
                        || payload > MAX_CELL - HEADER_LEN
                        || CellType::from_raw(header[0] & 15).is_none()
                    {
                        return Some(Err("invalid GC/2 stream header".into()));
                    }
                    self.expected = HEADER_LEN + payload;
                }
                if self.buffer.len() == self.expected {
                    let cell = NaturalCell::decode(&self.buffer).map_err(Into::into);
                    self.buffer.clear();
                    self.expected = HEADER_LEN;
                    return Some(cell);
                }
            }
            if !self.pending.is_empty() {
                let take = self.pending.len().min(self.expected - self.buffer.len());
                let bytes = self.pending.split_to(take);
                self.buffer.extend_from_slice(&bytes);
                if let Err(error) = self
                    .body
                    .as_mut()
                    .expect("live stream")
                    .flow_control()
                    .release_capacity(take)
                {
                    return Some(Err(error.into()));
                }
                continue;
            }
            match poll_fn(|cx| self.body.as_mut().expect("live stream").poll_data(cx)).await {
                Some(Ok(bytes)) => {
                    self.pending = bytes;
                    if self.pending.is_empty() {
                        empty_frames += 1;
                        if empty_frames == 16 {
                            tokio::task::yield_now().await;
                            empty_frames = 0;
                        }
                    }
                }
                Some(Err(error)) => return Some(Err(error.into())),
                None if self.buffer.is_empty() => return None,
                None => return Some(Err("GC/2 stream ended in a partial cell".into())),
            }
        }
    }

    pub async fn recv(&mut self) -> Option<Result<NaturalCell>> {
        match self.next().await {
            Some(Ok(cell)) if cell.kind() != CellType::Msg => {
                self.finish();
                Some(Err("GC/2 subscription carried a non-MSG cell".into()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        server::{AcceptedDuplex, Tp1Server},
        tls::TlsIdentity,
        TokenRegistry,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelled_partial_read_resumes_and_deadline_releases_connection_lease() {
        let cell = NaturalCell::new(CellType::Msg, 0, vec![42; 128]).unwrap();
        let bytes = Bytes::from(cell.encode());
        let (release, receive) = oneshot::channel();
        let receive = Arc::new(Mutex::new(Some(receive)));
        let handler = Arc::new(move |token: &str| {
            if token != "partial" {
                return None;
            }
            let receive = receive.lock().unwrap().take()?;
            let bytes = bytes.clone();
            let accepted: AcceptedDuplex = Box::new(move |mut body, mut respond| {
                Box::pin(async move {
                    crate::server::read_body(&mut body, MAX_CELL).await.unwrap();
                    let mut send = respond
                        .send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            false,
                        )
                        .unwrap();
                    send.send_data(Bytes::from(status_cell(HopReply::Accepted).encode()), false)
                        .unwrap();
                    send.send_data(bytes.slice(..3), false).unwrap();
                    receive.await.unwrap();
                    send.send_data(bytes.slice(3..), false).unwrap();
                    // Remain open until the client cancels its expired subscription.
                    let _ = poll_fn(|cx| send.poll_reset(cx)).await;
                })
            });
            Some(accepted)
        });
        let identity = TlsIdentity::generate().unwrap();
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            TokenRegistry::new(),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap()
        .with_duplex(handler);
        let address = server.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(server.run_until(async {
            let _ = stopped.await;
        }));
        let client = Tp1Client::new().unwrap();
        let route = NaturalRoute {
            addr: address,
            service_id: identity.service_id(),
            token: "partial",
            excluded: &[],
            class: TrafficClass::Interactive,
        };
        let mut stream = client
            .open_natural_prepared(route, Instant::now() + Duration::from_secs(10), || {
                Ok(NaturalCell::new(CellType::RelaySub, 0, vec![0])?)
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                assert!(
                    tokio::time::timeout(Duration::from_millis(1), stream.recv())
                        .await
                        .is_err()
                );
                if stream.buffer.len() == 3 {
                    break;
                }
            }
        })
        .await
        .unwrap();
        release.send(()).unwrap();
        assert_eq!(stream.recv().await.unwrap().unwrap(), cell);
        stream.deadline = Instant::now();
        assert!(stream.recv().await.unwrap().is_err());
        assert!(stream.body.is_none());
        assert!(stream.guard.is_none());
        assert!(stream.recv().await.is_none());
        // An already elapsed deadline never invokes the authorization builder.
        assert!(client
            .open_natural_prepared(route, Instant::now(), || panic!("expired builder ran"))
            .await
            .is_err());
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
