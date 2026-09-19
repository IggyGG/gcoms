//! Experimental terminal queue service for explicitly configured GC/2 routes.
//! It does not discover relays, select a profile, or change the production node.
use crate::queues::{gc2::AuthenticatedSubscription, LeaseStore, StoreError};
use bytes::Bytes;
use gcoms_core::{
    gc2::{NaturalCell, MAX_CELL},
    CellType,
};
use gcoms_protocol::relay::gc2::UnverifiedPush;
use gcoms_transport::{
    decode_b64url, decoy,
    duplex::H2Stream,
    encode_b64url,
    gc2::status_cell,
    server::{AcceptedDuplex, DuplexHandler},
    HopReply,
};
use std::{
    future::poll_fn,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Separate versioned endpoint. Callers still authenticate the complete envelope;
/// knowledge of this random queue path never grants deposit or consume authority.
pub fn queue_token(queue_id: &[u8; 32]) -> String {
    format!("gc2/{}", encode_b64url(queue_id))
}

#[derive(Clone)]
pub struct QueueService {
    store: Arc<Mutex<LeaseStore>>,
    active: Arc<AtomicUsize>,
}

impl QueueService {
    pub fn new(store: Arc<Mutex<LeaseStore>>) -> Self {
        Self {
            store,
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn active_subscriptions(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Attach through the transport's owned duplex handler. If combined with
    /// an entry service, supply this handler to
    /// `RelayService::gc2_handler_factory_with_terminal` and install the result
    /// with `Tp1Server::with_dispatch_factory` to enforce one connection role.
    pub fn handler(&self) -> DuplexHandler {
        let service = self.clone();
        Arc::new(move |token| {
            let encoded = token.strip_prefix("gc2/")?;
            let queue: [u8; 32] = decode_b64url(encoded)?.try_into().ok()?;
            if queue_token(&queue) != token
                || service
                    .store
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .lease(&queue, now())
                    .is_none()
            {
                return None;
            }
            let service = service.clone();
            let accepted: AcceptedDuplex =
                Box::new(move |body, respond| Box::pin(service.serve(queue, body, respond)));
            Some(accepted)
        })
    }

    async fn serve(
        self,
        queue: [u8; 32],
        mut body: h2::RecvStream,
        mut respond: h2::server::SendResponse<Bytes>,
    ) {
        let cell = match gcoms_transport::server::read_body(&mut body, MAX_CELL)
            .await
            .ok()
            .and_then(|bytes| NaturalCell::decode(&bytes).ok())
        {
            Some(cell) => cell,
            None => {
                reject(&mut respond).await;
                return;
            }
        };
        // Bind the authenticated envelope to the private path, not just to an
        // arbitrary queue that happens to be hosted by this service.
        if cell.payload().get(1..33) != Some(queue.as_slice()) {
            reject(&mut respond).await;
            return;
        }
        match cell.kind() {
            CellType::RelayPush => {
                let result = UnverifiedPush::parse(cell)
                    .map_err(StoreError::from)
                    .and_then(|push| {
                        let class = push.class();
                        self.store
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .authenticate_push_gc2(push, now())
                            .map(|outcome| (outcome, class))
                    });
                let reply = match result {
                    Ok((_, class)) => {
                        crate::metrics::log_event(
                            "gchat_push_accepted",
                            &[("class", format!("{class:?}"))],
                        );
                        Some(HopReply::Accepted)
                    }
                    Err(error) => status(&error),
                };
                reply_or_reject(&mut respond, reply).await;
            }
            CellType::RelaySub => {
                let result = self
                    .store
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .authenticate_sub_gc2(&cell, now());
                let mut handle = match result {
                    Ok(handle) => handle,
                    Err(error) => {
                        reply_or_reject(&mut respond, status(&error)).await;
                        return;
                    }
                };
                let remaining = UNIX_EPOCH
                    .checked_add(Duration::from_secs(handle.expiry()))
                    .and_then(|expiry| expiry.duration_since(SystemTime::now()).ok())
                    .unwrap_or_default();
                let deadline = tokio::time::Instant::now() + remaining;
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/octet-stream")
                    .body(())
                    .unwrap();
                let Ok(send) = respond.send_response(response, false) else {
                    return;
                };
                let mut io = H2Stream::new(body, send);
                self.active.fetch_add(1, Ordering::AcqRel);
                crate::metrics::log_event(
                    "gchat_sub_attached",
                    &[("class", format!("{:?}", handle.class()))],
                );
                let _active = Active(self.active.clone());
                let _ = tokio::time::timeout_at(deadline, async {
                    // read_body already consumed EOF. Record that half-close in
                    // the duplex adapter before sending the response stream.
                    if io.read(&mut [0u8; 1]).await.map_err(|_| ())? != 0 {
                        return Err(());
                    }
                    io.write_all(&status_cell(HopReply::Accepted).encode())
                        .await
                        .map_err(|_| ())?;
                    self.stream(&mut handle, &mut io).await
                })
                .await;
                let _ = io.shutdown().await;
            }
            _ => reject(&mut respond).await,
        }
    }

    async fn stream(
        &self,
        handle: &mut AuthenticatedSubscription,
        io: &mut H2Stream,
    ) -> Result<(), ()> {
        loop {
            let head = self
                .store
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .peek_gc2(handle, now())
                .map_err(|_| ())?
                .cloned();
            if let Some(head) = head {
                // HTTP/2 credit bounds buffering. Acceptance here means only
                // that the transport accepted bytes, not recipient persistence.
                let bytes = head.cell.encode();
                let write = io.write_all(&bytes);
                tokio::pin!(write);
                loop {
                    tokio::select! {
                        result = &mut write => { result.map_err(|_| ())?; break; },
                        result = handle.changed() => {
                            result.map_err(|_| ())?;
                            // A rotation/revocation must also interrupt a
                            // writer blocked on HTTP/2 credit. Keep the same
                            // write future on ordinary queue notifications.
                            self.store.lock().unwrap_or_else(|p| p.into_inner())
                                .peek_gc2(handle, now()).map_err(|_| ())?;
                        }
                    }
                }
                self.store
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .acknowledge_gc2(handle, &head.push_nonce, now())
                    .map_err(|_| ())?;
            } else {
                tokio::select! {
                    result=handle.changed()=>result.map_err(|_|())?,
                    _=poll_fn(|cx|io.poll_reset(cx))=>return Ok(()),
                }
            }
        }
    }
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn status(error: &StoreError) -> Option<HopReply> {
    match error {
        StoreError::QueueFull | StoreError::Capacity | StoreError::ReplayCapacity => {
            Some(HopReply::Overloaded)
        }
        StoreError::Replay | StoreError::GrantConsumed => Some(HopReply::Conflict),
        _ => None,
    }
}

async fn reject(respond: &mut h2::server::SendResponse<Bytes>) {
    if let Ok(mut send) = respond.send_response(decoy::decoy_response(404), false) {
        let _ = send.send_data(decoy::decoy_body(404), true);
    }
}

async fn reply_or_reject(respond: &mut h2::server::SendResponse<Bytes>, reply: Option<HopReply>) {
    let Some(reply) = reply else {
        reject(respond).await;
        return;
    };
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();
    if let Ok(mut send) = respond.send_response(response, false) {
        let _ = send.send_data(Bytes::from(status_cell(reply).encode()), true);
    }
}
