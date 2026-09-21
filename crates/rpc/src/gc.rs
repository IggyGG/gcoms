//! Durable application messages over the existing SDK. Run one pump per
//! component inbox. Trusted bindings supply both identities and reply cards.
use crate::*;
use gcoms_sdk::{ApplicationDelivery, ApplicationMessage, GcClient, IpcClient};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::sync::{oneshot, Semaphore};

pub use gcoms_sdk::Peer;
fn transport(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(ErrorCode::Transport, e.to_string())
}

#[async_trait]
pub trait Link: Send + Sync {
    fn local_component(&self) -> Option<[u8; 16]>;
    fn limit(&self, content_type: &str) -> Result<usize, RpcError>;
    async fn verify_peer(&self, peer: &Peer) -> Result<(), RpcError>;
    async fn send(&self, peer: &Peer, content_type: &str, bytes: &[u8]) -> Result<(), RpcError>;
    async fn inbox(&self, after: u64) -> Result<Vec<ApplicationDelivery>, RpcError>;
    async fn commit(&self, delivery: &ApplicationDelivery) -> Result<(), RpcError>;
}
pub struct DirectLink(pub Arc<dyn GcClient>);
#[async_trait]
impl Link for DirectLink {
    fn local_component(&self) -> Option<[u8; 16]> {
        None
    }
    fn limit(&self, content_type: &str) -> Result<usize, RpcError> {
        gcoms_sdk::application_body_limit(content_type).map_err(transport)
    }
    async fn verify_peer(&self, peer: &Peer) -> Result<(), RpcError> {
        if peer.component.is_some()
            || self
                .0
                .resolve_contact_identity(&peer.contact)
                .await
                .map_err(transport)?
                != peer.identity
        {
            return Err(RpcError::invalid("peer card and identity do not match"));
        }
        Ok(())
    }
    async fn send(&self, peer: &Peer, content_type: &str, bytes: &[u8]) -> Result<(), RpcError> {
        self.0
            .submit_durable_opaque(&peer.contact, content_type, bytes)
            .await
            .map(|_| ())
            .map_err(transport)
    }
    async fn inbox(&self, after: u64) -> Result<Vec<ApplicationDelivery>, RpcError> {
        self.0.application_inbox(after, 32).await.map_err(transport)
    }
    async fn commit(&self, delivery: &ApplicationDelivery) -> Result<(), RpcError> {
        self.0
            .commit_application(delivery.sequence, delivery.receipt_digest)
            .await
            .map_err(transport)
    }
}
pub struct ComponentLink(pub IpcClient);
#[async_trait]
impl Link for ComponentLink {
    fn local_component(&self) -> Option<[u8; 16]> {
        self.0.authenticated_component_id()
    }
    fn limit(&self, content_type: &str) -> Result<usize, RpcError> {
        self.0
            .application_body_limit(content_type)
            .map_err(transport)
    }
    async fn verify_peer(&self, peer: &Peer) -> Result<(), RpcError> {
        if self.local_component().is_none()
            || peer.component.is_none()
            || self
                .0
                .resolve_contact_identity(&peer.contact)
                .await
                .map_err(transport)?
                != peer.identity
        {
            return Err(RpcError::invalid(
                "component peer binding does not match card",
            ));
        }
        Ok(())
    }
    async fn send(&self, peer: &Peer, content_type: &str, bytes: &[u8]) -> Result<(), RpcError> {
        self.0
            .submit_component(
                &peer.contact,
                peer.component
                    .ok_or_else(|| RpcError::invalid("component required"))?,
                content_type,
                bytes,
            )
            .await
            .map(|_| ())
            .map_err(transport)
    }
    async fn inbox(&self, after: u64) -> Result<Vec<ApplicationDelivery>, RpcError> {
        self.0.application_inbox(after, 32).await.map_err(transport)
    }
    async fn commit(&self, delivery: &ApplicationDelivery) -> Result<(), RpcError> {
        self.0
            .commit_application(delivery.sequence, delivery.receipt_digest)
            .await
            .map_err(transport)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "direction",
    content = "message",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Frame {
    Request(Request),
    Reply(Reply),
}
struct Pending {
    peer: String,
    request: Request,
    sender: oneshot::Sender<Reply>,
}

pub struct GcEndpoint {
    link: Arc<dyn Link>,
    peers: RwLock<BTreeMap<String, Peer>>,
    content_types: BTreeSet<String>,
    router: RwLock<Option<Arc<Router>>>,
    pending: Mutex<BTreeMap<OperationId, Pending>>,
    pumping: std::sync::atomic::AtomicBool,
}
impl GcEndpoint {
    /// Binding verification is mandatory; no card or reply destination is read
    /// from an RPC payload. SDK component grants must independently allow routes.
    pub async fn new(
        link: Arc<dyn Link>,
        peers: Vec<Peer>,
        services: &[(String, u16)],
        router: Option<Arc<Router>>,
    ) -> Result<Arc<Self>, RpcError> {
        if peers.len() > 64 || services.len() > 64 {
            return Err(RpcError::invalid("too many GC bindings"));
        }
        let mut bindings = BTreeMap::new();
        for peer in peers {
            link.verify_peer(&peer).await?;
            if bindings.insert(peer.principal(), peer).is_some() {
                return Err(RpcError::invalid("duplicate peer binding"));
            }
        }
        let content_types = services.iter().map(|(s, v)| content_type(s, *v)).collect();
        Ok(Arc::new(Self {
            link,
            peers: RwLock::new(bindings),
            content_types,
            router: RwLock::new(router),
            pending: Mutex::new(BTreeMap::new()),
            pumping: std::sync::atomic::AtomicBool::new(false),
        }))
    }
    /// Stop an application-owned endpoint and release its service journals.
    pub async fn shutdown(&self) -> Result<(), RpcError> {
        self.pending.lock().map_err(transport)?.clear();
        let router = self.router.write().map_err(transport)?.take();
        if let Some(router) = router {
            router.shutdown().await;
        }
        Ok(())
    }
    /// Install an explicitly trusted binding, or refresh that identity's contact route.
    pub async fn trust_peer(&self, peer: Peer) -> Result<(), RpcError> {
        self.link.verify_peer(&peer).await?;
        let mut peers = self.peers.write().map_err(transport)?;
        if peers.len() >= 64 && !peers.contains_key(&peer.principal()) {
            return Err(RpcError::invalid("too many GC bindings"));
        }
        peers.insert(peer.principal(), peer);
        Ok(())
    }
    pub fn transport(
        self: &Arc<Self>,
        peer: &Peer,
        service: &str,
        version: u16,
    ) -> Result<GcTransport, RpcError> {
        let principal = peer.principal();
        let content_type = content_type(service, version);
        if !self
            .peers
            .read()
            .map_err(transport)?
            .contains_key(&principal)
            || !self.content_types.contains(&content_type)
        {
            return Err(RpcError::new(
                ErrorCode::Unauthorized,
                "GC route not configured",
            ));
        }
        // JSON frame overhead is fixed and smaller than 64 bytes.
        let limit = self
            .link
            .limit(&content_type)?
            .checked_sub(64)
            .ok_or_else(|| RpcError::invalid("GC payload limit"))?;
        Ok(GcTransport {
            endpoint: self.clone(),
            peer: principal.clone(),
            destination: format!("{principal}/{service}/v{version}"),
            content_type,
            limit,
        })
    }
    /// Dispatch one authenticated delivery when an application owns the shared inbox pump.
    /// False leaves unrelated application content untouched. Receipt follows durable reply.
    pub async fn dispatch_delivery(
        &self,
        delivery: &ApplicationDelivery,
    ) -> Result<bool, RpcError> {
        let Some(peer) = self
            .peers
            .read()
            .map_err(transport)?
            .values()
            .find(|p| {
                p.identity == delivery.peer_identity
                    && p.component == delivery.source_component
                    && self.link.local_component() == delivery.destination_component
            })
            .cloned()
        else {
            return Ok(false);
        };
        let Ok(application) = ApplicationMessage::decode(&delivery.body) else {
            return Ok(false);
        };
        if !self.content_types.contains(&application.content_type) {
            return Ok(false);
        }
        self.process(&peer, &application).await?;
        self.link.commit(delivery).await?;
        Ok(true)
    }

    pub async fn run<F: std::future::Future<Output = ()>>(
        self: &Arc<Self>,
        stop: F,
    ) -> Result<(), RpcError> {
        use std::sync::atomic::Ordering;
        if self.pumping.swap(true, Ordering::SeqCst) {
            return Err(RpcError::new(
                ErrorCode::Conflict,
                "GC inbox already has an RPC pump",
            ));
        }
        struct PumpGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for PumpGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = PumpGuard(&self.pumping);
        let slots = Arc::new(Semaphore::new(64));
        let active = Arc::new(Mutex::new(BTreeSet::new()));
        let mut tasks = tokio::task::JoinSet::new();
        let mut after = 0;
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    let deliveries = self.link.inbox(after).await?;
                    let count = deliveries.len();
                    for delivery in deliveries {
                        after = after.max(delivery.sequence);
                        let Some(peer) = self.peers.read().map_err(transport)?.values().find(|p| p.identity == delivery.peer_identity && p.component == delivery.source_component && self.link.local_component() == delivery.destination_component).cloned() else { continue; };
                        let Ok(application) = ApplicationMessage::decode(&delivery.body) else { continue; };
                        if !self.content_types.contains(&application.content_type) { continue; }
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        if !active.lock().map_err(transport)?.insert(delivery.sequence) { continue; }
                        let endpoint = self.clone(); let active = active.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let sequence = delivery.sequence;
                            let result = endpoint.process(&peer, &application).await;
                            if result.is_ok() { let _ = endpoint.link.commit(&delivery).await; }
                            if let Ok(mut active) = active.lock() { active.remove(&sequence); }
                        });
                    }
                    if count < 32 { after = 0; }
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
    async fn process(&self, peer: &Peer, application: &ApplicationMessage) -> Result<(), RpcError> {
        let Ok(frame) = serde_json::from_slice::<Frame>(&application.body) else {
            return Ok(());
        };
        match frame {
            Frame::Reply(reply) => {
                let mut pending = self.pending.lock().map_err(transport)?;
                if let Some(p) = pending.get(&reply.id) {
                    if p.peer == peer.principal()
                        && content_type(&p.request.service, p.request.version)
                            == application.content_type
                        && p.request.check_reply(&reply).is_ok()
                    {
                        if let Some(p) = pending.remove(&reply.id) {
                            let _ = p.sender.send(reply);
                        }
                    }
                }
            }
            Frame::Request(request) => {
                if content_type(&request.service, request.version) != application.content_type {
                    return Ok(());
                }
                let Some(router) = self.router.read().map_err(transport)?.clone() else {
                    return Ok(());
                };
                let limit = self.link.limit(&application.content_type)?;
                let reply = router
                    .handle(
                        Caller {
                            principal: peer.principal(),
                        },
                        request.clone(),
                    )
                    .await;
                let bytes = serde_json::to_vec(&Frame::Reply(reply)).map_err(transport)?;
                let bytes = if bytes.len() > limit {
                    serde_json::to_vec(&Frame::Reply(request.reply(ReplyBody::Failed {
                        error: RpcError::new(
                            ErrorCode::PayloadTooLarge,
                            "GC response exceeds route limit; paginate results",
                        ),
                    })))
                    .map_err(transport)?
                } else {
                    bytes
                };
                // Commit the inbound receipt only after reply outbox admission.
                self.link
                    .send(peer, &application.content_type, &bytes)
                    .await?;
            }
        }
        Ok(())
    }
}

pub struct GcTransport {
    endpoint: Arc<GcEndpoint>,
    peer: String,
    destination: String,
    content_type: String,
    limit: usize,
}
#[async_trait]
impl Transport for GcTransport {
    fn destination(&self) -> &str {
        &self.destination
    }
    fn frame_limit(&self) -> usize {
        self.limit
    }
    async fn exchange(&self, request: &Request) -> Result<Reply, RpcError> {
        if content_type(&request.service, request.version) != self.content_type {
            return Err(RpcError::new(
                ErrorCode::Unauthorized,
                "service not bound to GC transport",
            ));
        }
        let bytes = serde_json::to_vec(&Frame::Request(request.clone())).map_err(transport)?;
        if bytes.len() > self.endpoint.link.limit(&self.content_type)? {
            return Err(RpcError::new(
                ErrorCode::PayloadTooLarge,
                "GC request exceeds route limit",
            ));
        }
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.endpoint.pending.lock().map_err(transport)?;
            if pending.len() >= 64 || pending.contains_key(&request.id) {
                return Err(RpcError::new(ErrorCode::Busy, "GC pending call limit"));
            }
            pending.insert(
                request.id.clone(),
                Pending {
                    peer: self.peer.clone(),
                    request: request.clone(),
                    sender,
                },
            );
        }
        struct Guard<'a>(&'a GcEndpoint, OperationId);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if let Ok(mut pending) = self.0.pending.lock() {
                    pending.remove(&self.1);
                }
            }
        }
        let _guard = Guard(&self.endpoint, request.id.clone());
        let peer = self
            .endpoint
            .peers
            .read()
            .map_err(transport)?
            .get(&self.peer)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::Unauthorized, "GC peer removed"))?;
        self.endpoint
            .link
            .send(&peer, &self.content_type, &bytes)
            .await?;
        tokio::time::timeout(Duration::from_secs(30), receiver)
            .await
            .map_err(|_| {
                RpcError::new(
                    ErrorCode::Timeout,
                    "GC reply unavailable; recover using the original handle",
                )
            })?
            .map_err(|_| RpcError::new(ErrorCode::Transport, "GC reply channel closed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_sdk::ContactCard;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct FixtureLink {
        inbox: Mutex<Vec<ApplicationDelivery>>,
        committed: Mutex<Vec<u64>>,
        unavailable: AtomicBool,
    }
    #[async_trait]
    impl Link for FixtureLink {
        fn local_component(&self) -> Option<[u8; 16]> {
            Some([1; 16])
        }
        fn limit(&self, _: &str) -> Result<usize, RpcError> {
            Ok(16_000)
        }
        async fn verify_peer(&self, _: &Peer) -> Result<(), RpcError> {
            Ok(())
        }
        async fn send(&self, _: &Peer, _: &str, _: &[u8]) -> Result<(), RpcError> {
            if self.unavailable.load(Ordering::SeqCst) {
                Err(transport("fixture peer unavailable"))
            } else {
                Ok(())
            }
        }
        async fn inbox(&self, after: u64) -> Result<Vec<ApplicationDelivery>, RpcError> {
            Ok(self
                .inbox
                .lock()
                .unwrap()
                .iter()
                .filter(|d| d.sequence > after)
                .cloned()
                .collect())
        }
        async fn commit(&self, delivery: &ApplicationDelivery) -> Result<(), RpcError> {
            self.committed.lock().unwrap().push(delivery.sequence);
            self.inbox
                .lock()
                .unwrap()
                .retain(|d| d.sequence != delivery.sequence);
            Ok(())
        }
    }
    fn peer() -> Peer {
        Peer {
            identity: vec![2; 32],
            contact: ContactCard(vec![]),
            component: Some([2; 16]),
        }
    }
    fn request() -> Request {
        Request {
            rpc: WIRE_VERSION,
            id: new_id(),
            instance: "selected".into(),
            service: "example.echo".into(),
            version: 1,
            method: "echo".into(),
            invocation: Invocation::Call {
                args: serde_json::json!({}),
                operation: None,
            },
        }
    }
    async fn endpoint(link: Arc<FixtureLink>) -> Arc<GcEndpoint> {
        GcEndpoint::new(link, vec![peer()], &[("example.echo".into(), 1)], None)
            .await
            .unwrap()
    }
    fn pending(endpoint: &GcEndpoint, request: &Request) -> oneshot::Receiver<Reply> {
        let (sender, receiver) = oneshot::channel();
        endpoint.pending.lock().unwrap().insert(
            request.id.clone(),
            Pending {
                peer: peer().principal(),
                request: request.clone(),
                sender,
            },
        );
        receiver
    }
    fn application(reply: Reply) -> ApplicationMessage {
        ApplicationMessage {
            content_type: content_type("example.echo", 1),
            body: serde_json::to_vec(&Frame::Reply(reply)).unwrap(),
        }
    }
    #[tokio::test]
    async fn replies_require_every_binding_before_consuming_a_pending_call() {
        let endpoint = endpoint(Arc::new(FixtureLink::default())).await;
        let request = request();
        let mut receiver = pending(&endpoint, &request);
        let reply = request.reply(ReplyBody::Running);
        for field in 0..6 {
            let mut wrong = reply.clone();
            match field {
                0 => wrong.rpc += 1,
                1 => wrong.id = new_id(),
                2 => wrong.instance = "another".into(),
                3 => wrong.service = "another".into(),
                4 => wrong.version += 1,
                _ => wrong.method = "another".into(),
            }
            endpoint
                .process(&peer(), &application(wrong))
                .await
                .unwrap();
            assert!(receiver.try_recv().is_err());
            assert_eq!(endpoint.pending.lock().unwrap().len(), 1);
        }
        let mut wrong_peer = peer();
        wrong_peer.identity[0] ^= 1;
        endpoint
            .process(&wrong_peer, &application(reply.clone()))
            .await
            .unwrap();
        let mut wrong_type = application(reply.clone());
        wrong_type.content_type = content_type("another", 1);
        endpoint.process(&peer(), &wrong_type).await.unwrap();
        assert!(receiver.try_recv().is_err());
        endpoint
            .process(&peer(), &application(reply))
            .await
            .unwrap();
        assert_eq!(receiver.await.unwrap().instance, "selected");
    }
    #[tokio::test]
    async fn inbox_requires_authenticated_peer_and_both_component_bindings() {
        let link = Arc::new(FixtureLink::default());
        let endpoint = endpoint(link.clone()).await;
        let request = request();
        let receiver = pending(&endpoint, &request);
        let good = ApplicationDelivery {
            source_component: peer().component,
            destination_component: Some([1; 16]),
            sequence: 4,
            peer_identity: peer().identity,
            message_id: [0; 16],
            received_at_unix: unix_time(),
            receipt_digest: [0; 32],
            body: application(request.reply(ReplyBody::Running))
                .encode()
                .unwrap(),
        };
        for index in 1..=3 {
            let mut wrong = good.clone();
            wrong.sequence = index;
            match index {
                1 => wrong.peer_identity[0] ^= 1,
                2 => wrong.source_component = Some([9; 16]),
                _ => wrong.destination_component = Some([9; 16]),
            }
            link.inbox.lock().unwrap().push(wrong);
        }
        // Unrelated authenticated inbox traffic belongs to another consumer.
        endpoint
            .run(tokio::time::sleep(Duration::from_millis(140)))
            .await
            .unwrap();
        assert!(link.committed.lock().unwrap().is_empty());
        assert_eq!(endpoint.pending.lock().unwrap().len(), 1);
        link.inbox.lock().unwrap().push(good);
        endpoint
            .run(tokio::time::sleep(Duration::from_millis(140)))
            .await
            .unwrap();
        assert_eq!(receiver.await.unwrap().body, ReplyBody::Running);
        assert_eq!(*link.committed.lock().unwrap(), vec![4]);
    }
    #[tokio::test]
    async fn unavailable_peer_and_pending_limits_leave_no_extra_waiters() {
        let link = Arc::new(FixtureLink::default());
        let endpoint = endpoint(link.clone()).await;
        let transport = endpoint.transport(&peer(), "example.echo", 1).unwrap();
        link.unavailable.store(true, Ordering::SeqCst);
        assert_eq!(
            transport.exchange(&request()).await.unwrap_err().code,
            ErrorCode::Transport
        );
        assert!(endpoint.pending.lock().unwrap().is_empty());
        let mut receivers = Vec::new();
        for _ in 0..64 {
            receivers.push(pending(&endpoint, &request()));
        }
        assert_eq!(
            transport.exchange(&request()).await.unwrap_err().code,
            ErrorCode::Busy
        );
        assert_eq!(endpoint.pending.lock().unwrap().len(), 64);
        let mut wrong = request();
        wrong.service = "another".into();
        assert_eq!(
            transport.exchange(&wrong).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
    }
}
