use super::*;
use crate::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct GateClient {
    identity: Identity,
    events: std::sync::Mutex<Option<mpsc::Receiver<ClientEvent>>>,
    observed: mpsc::Sender<(u8, tokio::sync::oneshot::Sender<Result<(), SdkError>>)>,
    active: Arc<AtomicUsize>,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl GcClient for GateClient {
    fn identity(&self) -> Identity {
        self.identity.clone()
    }
    fn subscribe_events(&self) -> mpsc::Receiver<ClientEvent> {
        self.events.lock().unwrap().take().unwrap()
    }
    fn contact_identity(&self, _: &ContactCard) -> Result<Vec<u8>, SdkError> {
        Ok(vec![3; 1952])
    }
    async fn submit_volatile_opaque(
        &self,
        _: &ContactCard,
        kind: &str,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        let wire = ApplicationMessage {
            content_type: kind.into(),
            body: bytes.to_vec(),
        }
        .encode()?;
        let route = gcoms_core::component::RoutedApplication::decode(&wire).unwrap();
        assert_eq!((route.source, route.destination), ([7; 16], [4; 16]));
        let message = ApplicationMessage::decode(&route.application)?;
        assert_eq!(message.content_type, gcoms_core::VOLATILE_FILE_CONTENT_TYPE);
        let (done, result) = tokio::sync::oneshot::channel();
        assert!(self.active.fetch_add(1, Ordering::SeqCst) < 32);
        let _active = Active(self.active.clone());
        self.observed.send((message.body[0], done)).await.unwrap();
        result.await.map_err(|_| SdkError::ConnectionClosed)?
    }
    async fn list_channels(&self) -> Result<Vec<JoinedChannel>, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn channel_roster(&self, _channel: &str) -> Result<Vec<ChannelMemberSummary>, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn public_channel_descriptor(
        &self,
        _channel: &str,
        _description: &str,
        _activity: ActivityBucket,
        _automatic_join: AutomaticJoinEndpoint,
        _expires_at_unix: u64,
    ) -> Result<PublicChannelDescriptor, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn send_direct(
        &self,
        _peer: &ContactCard,
        _body: &[u8],
        _via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_direct_presence(
        &self,
        _peer: &ContactCard,
        _mode: PresenceMode,
        _lease_secs: u32,
        _via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_direct_presence_opt_in(
        &self,
        _peer: &ContactCard,
        _enabled: bool,
        _via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn create_channel(
        &self,
        _channel: &str,
        _display_name: &str,
        _capacity: usize,
        _visibility: ChannelVisibility,
    ) -> Result<ChannelId, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn prepare_channel_join(&self, _display_name: &str) -> Result<JoinRequest, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn channel_key_package(&self, _request: JoinRequest) -> Result<Blob, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn admit_channel(
        &self,
        _channel: &str,
        _key_package: &Blob,
        _member_name: &str,
    ) -> Result<Blob, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn join_channel(
        &self,
        _request: JoinRequest,
        _channel: &str,
        _visibility: ChannelVisibility,
        _welcome: &Blob,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn send_channel(&self, _channel: &str, _body: &[u8]) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_channel_presence(
        &self,
        _channel: &str,
        _mode: PresenceMode,
        _lease_secs: u32,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_channel_presence_opt_in(
        &self,
        _channel: &str,
        _enabled: bool,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn send_channel_direct(
        &self,
        _channel: &str,
        _recipient_member_id: [u8; 32],
        _body: &[u8],
    ) -> Result<MessageId, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn remove_channel_member(
        &self,
        _channel: &str,
        _member_id: [u8; 32],
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
}

async fn bulk_request(
    peer: &mut (impl AsyncWrite + Unpin),
    id: u64,
    recipient: &ContactCard,
    destination: [u8; 16],
) {
    write_frame(
        peer,
        &Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id: id,
            request: Request::SubmitBootstrap {
                recipient: recipient.clone(),
                destination,
                content_type: gcoms_core::VOLATILE_FILE_CONTENT_TYPE.into(),
                body: vec![id as u8],
            },
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn bootstrap_bulk_ipc_is_bounded_and_matches_own_reply_without_reordering_admission() {
    let node = node().await;
    let identity = crate::EmbeddedClient::new(node.clone()).identity();
    let recipient = identity.contact_card.clone();
    let (events, incoming) = mpsc::channel(8);
    let (observed, mut calls) = mpsc::channel(64);
    let active = Arc::new(AtomicUsize::new(0));
    let client = GateClient {
        identity,
        events: std::sync::Mutex::new(Some(incoming)),
        observed,
        active: active.clone(),
    };
    let (mut peer, stream) = tokio::io::duplex(1024 * 1024);
    let server = tokio::spawn(serve_connection(stream, client, vec![], Some(registry())));
    write_frame(
        &mut peer,
        &Frame::Hello(Hello {
            min_version: VERSION,
            max_version: VERSION,
            application: "bounded-bulk-fixture".into(),
            requested_capabilities: registry().components[0].capabilities.clone(),
            component: Some(credentials()),
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        read_frame(&mut peer).await.unwrap(),
        Frame::Welcome(_)
    ));
    // Neither an unseen peer nor an unadmitted one acquires a concurrent slot.
    bulk_request(&mut peer, 1, &recipient, [4; 16]).await;
    let Frame::Response(reply) = read_frame(&mut peer).await.unwrap() else {
        panic!("response")
    };
    assert_eq!(reply.result, Err(SdkError::PermissionDenied));
    assert_eq!(active.load(Ordering::SeqCst), 0);
    let mut event = bootstrap_event();
    if let ClientEvent::VolatileApplication { body, .. } = &mut event {
        *body = gcoms_core::component::RoutedApplication {
            source: [4; 16],
            destination: [7; 16],
            application: body.clone(),
        }
        .encode()
        .unwrap();
    }
    events.send(event).await.unwrap();
    assert!(matches!(
        read_frame(&mut peer).await.unwrap(),
        Frame::Event(_)
    ));
    let expires_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    write_frame(
        &mut peer,
        &Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id: 2,
            request: Request::AdmitBootstrapPeer {
                peer_identity: vec![3; 1952],
                source: [4; 16],
                expires_at_unix,
            },
        }),
    )
    .await
    .unwrap();
    let Frame::Response(reply) = read_frame(&mut peer).await.unwrap() else {
        panic!("response")
    };
    assert_eq!(reply.result, Ok(Response::Empty));
    bulk_request(&mut peer, 3, &recipient, [5; 16]).await;
    let Frame::Response(reply) = read_frame(&mut peer).await.unwrap() else {
        panic!("response")
    };
    assert_eq!(reply.result, Err(SdkError::PermissionDenied));
    assert_eq!(active.load(Ordering::SeqCst), 0);
    for id in 4..=36 {
        bulk_request(&mut peer, id, &recipient, [4; 16]).await;
    }
    let mut receipts = Vec::new();
    for _ in 0..32 {
        receipts.push(
            tokio::time::timeout(Duration::from_secs(2), calls.recv())
                .await
                .expect("32 authorized bulk requests must dispatch before the first completes")
                .unwrap(),
        );
    }
    assert_eq!(active.load(Ordering::SeqCst), 32);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), calls.recv())
            .await
            .is_err()
    );
    let (second, done) = receipts.remove(1);
    done.send(Err(SdkError::Runtime("owned hop refused".into())))
        .unwrap();
    let Frame::Response(reply) =
        tokio::time::timeout(Duration::from_secs(2), read_frame(&mut peer))
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("response")
    };
    assert_eq!(reply.request_id, u64::from(second));
    assert_eq!(
        reply.result,
        Err(SdkError::Runtime("owned hop refused".into()))
    );
    receipts.push(
        tokio::time::timeout(Duration::from_secs(2), calls.recv())
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(active.load(Ordering::SeqCst), 32);
    let (_, done) = receipts.pop().unwrap();
    done.send(Ok(())).unwrap();
    assert!(matches!(
        read_frame(&mut peer).await.unwrap(),
        Frame::Response(_)
    ));
    assert_eq!(active.load(Ordering::SeqCst), 31);
    // Disconnect cancels the still-owned network calls; none is detached.
    drop(peer);
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    tokio::time::timeout(Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for (_, done) in receipts {
        assert!(done.send(Ok(())).is_err());
    }
    node.shutdown().await;
}
