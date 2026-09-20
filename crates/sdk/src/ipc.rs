//! Versioned messages shared by daemon and SDK IPC backends.

use crate::{
    ActivityBucket, ApplicationMessage, AutomaticJoinEndpoint, Blob, ChannelId,
    ChannelMemberSummary, ChannelVisibility, ClientEvent, ContactCard, Identity, JoinRequest,
    JoinedChannel, PresenceMode, PublicChannelDescriptor, SdkError,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(any(unix, windows), feature = "ipc"))]
use crate::local::{self, ClientStream, LocalListener};
#[cfg(all(any(unix, windows), feature = "ipc"))]
use crate::GcClient;
#[cfg(all(any(unix, windows), feature = "ipc"))]
use async_trait::async_trait;
#[cfg(all(any(unix, windows), feature = "ipc"))]
use std::collections::HashMap;
#[cfg(all(any(unix, windows), feature = "ipc"))]
use std::path::Path;
#[cfg(all(any(unix, windows), feature = "ipc"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(all(any(unix, windows), feature = "ipc"))]
use std::sync::Arc;
#[cfg(all(any(unix, windows), feature = "ipc"))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(all(any(unix, windows), feature = "ipc"))]
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};

pub const VERSION: u16 = 17;
// IPC17 appends channel metadata; all existing message tags remain unchanged.
// new operations/capabilities/events are never admitted under an older version.
#[cfg(all(any(unix, windows), feature = "ipc"))]
const MIN_SERVER_VERSION: u16 = 10;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    FileTransfer,
    IdentityRead,
    DirectMessage,
    ChannelMember,
    ChannelAdmin,
    OpaqueTransfer,
    EventRead,
    ProfileAdmin,
    IdentitySign,
    DurableApplication,
    HostShell,
    VolatileApplication,
    CatalogAccess,
    BootstrapApplication,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub component: Option<crate::machine::ComponentCredentials>,
    pub min_version: u16,
    pub max_version: u16,
    pub application: String,
    pub requested_capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub version: u16,
    pub granted_capabilities: Vec<Capability>,
    pub event_stream_id: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u16,
    pub request_id: u64,
    pub request: Request,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    ContactIdentity {
        card: ContactCard,
    },
    FileRoute,
    File(crate::files::FileRequest),
    SubmitComponent {
        recipient: ContactCard,
        destination: gcoms_core::component::ComponentId,
        content_type: String,
        body: Vec<u8>,
    },
    Identity,
    SubscribeEvents,
    SendDirect {
        peer: ContactCard,
        body: Vec<u8>,
        via: Option<ContactCard>,
    },
    SetDirectPresence {
        peer: ContactCard,
        mode: PresenceMode,
        lease_secs: u32,
        via: Option<ContactCard>,
    },
    SetDirectPresenceOptIn {
        peer: ContactCard,
        enabled: bool,
        via: Option<ContactCard>,
    },
    CreateChannel {
        channel: String,
        display_name: String,
        capacity: u32,
        visibility: ChannelVisibility,
    },
    PrepareChannelJoin {
        display_name: String,
    },
    ChannelKeyPackage {
        request: JoinRequest,
    },
    AdmitChannel {
        channel: String,
        key_package: Blob,
        member_name: String,
    },
    JoinChannel {
        request: JoinRequest,
        channel: String,
        visibility: ChannelVisibility,
        welcome: Blob,
    },
    SendChannel {
        channel: String,
        body: Vec<u8>,
    },
    SetChannelPresence {
        channel: String,
        mode: PresenceMode,
        lease_secs: u32,
    },
    SetChannelPresenceOptIn {
        channel: String,
        enabled: bool,
    },
    SendChannelDirect {
        channel: String,
        recipient_member_id: [u8; 32],
        body: Vec<u8>,
    },
    RemoveChannelMember {
        channel: String,
        member_id: [u8; 32],
    },
    SubmitOpaque {
        recipient: ContactCard,
        content_type: String,
        body: Vec<u8>,
    },
    ListChannels,
    ChannelRoster {
        channel: String,
    },
    PublicChannelDescriptor {
        channel: String,
        description: String,
        activity: ActivityBucket,
        automatic_join: AutomaticJoinEndpoint,
        expires_at_unix: u64,
    },
    SignIdentityDigest {
        digest: [u8; 32],
    },
    SignPrincipalBindingHash {
        claims_hash: [u8; 32],
    },
    SubmitDurableOpaque {
        recipient: ContactCard,
        content_type: String,
        body: Vec<u8>,
    },
    ApplicationInbox {
        after: u64,
        limit: u16,
    },
    CommitApplication {
        sequence: u64,
        digest: [u8; 32],
    },
    Shell(crate::shell::ShellRequest),
    SubmitVolatileComponent {
        recipient: ContactCard,
        destination: gcoms_core::component::ComponentId,
        content_type: String,
        body: Vec<u8>,
    },
    SendDirectTracked {
        peer: ContactCard,
        body: Vec<u8>,
        via: Option<ContactCard>,
    },
    SendChannelTracked {
        channel: String,
        body: Vec<u8>,
    },
    RecoverChannelRoute {
        channel: String,
        expected_channel_id: ChannelId,
        expected_epoch: u64,
        retained_welcome: Blob,
        peer: ContactCard,
    },
    ConfigureCatalogOrigins {
        origins: Vec<String>,
    },
    CatalogHttp(crate::CatalogHttpRequest),
    AdmitBootstrapPeer {
        peer_identity: Vec<u8>,
        source: gcoms_core::component::ComponentId,
        expires_at_unix: u64,
    },
    SubmitBootstrap {
        recipient: ContactCard,
        destination: gcoms_core::component::ComponentId,
        content_type: String,
        body: Vec<u8>,
    },
    ChannelTopic {
        channel: String,
    },
    ChangeChannel {
        channel: String,
        change: crate::ChannelChange,
    },
}

impl Request {
    pub fn minimum_version(&self) -> u16 {
        match self {
            Self::ChannelTopic { .. } | Self::ChangeChannel { .. } => 17,
            Self::ConfigureCatalogOrigins { .. } | Self::CatalogHttp(_) => 15,
            Self::RecoverChannelRoute { .. } => 14,
            Self::SendDirectTracked { .. } | Self::SendChannelTracked { .. } => 13,
            Self::AdmitBootstrapPeer { .. } | Self::SubmitBootstrap { .. } => 16,
            Self::SubmitVolatileComponent { .. } => 12,
            Self::File(request) if request.is_managed() => 12,
            Self::Shell(_) => 11,
            _ => 10,
        }
    }
    pub fn required_capability(&self) -> Capability {
        match self {
            Self::ConfigureCatalogOrigins { .. } | Self::CatalogHttp(_) => {
                Capability::CatalogAccess
            }
            Self::AdmitBootstrapPeer { .. } | Self::SubmitBootstrap { .. } => {
                Capability::BootstrapApplication
            }
            Self::SubmitVolatileComponent { .. } => Capability::VolatileApplication,
            Self::File(_) => Capability::FileTransfer,
            Self::Shell(_) => Capability::HostShell,
            Self::Identity | Self::FileRoute | Self::ContactIdentity { .. } => {
                Capability::IdentityRead
            }
            Self::SignIdentityDigest { .. } | Self::SignPrincipalBindingHash { .. } => {
                Capability::IdentitySign
            }
            Self::ListChannels | Self::ChannelRoster { .. } => Capability::ChannelMember,
            Self::SubscribeEvents => Capability::EventRead,
            Self::SendDirect { .. }
            | Self::SendDirectTracked { .. }
            | Self::SetDirectPresence { .. }
            | Self::SetDirectPresenceOptIn { .. } => Capability::DirectMessage,
            Self::ChangeChannel {
                change:
                    crate::ChannelChange::Topic(_)
                    | crate::ChannelChange::Transfer(_)
                    | crate::ChannelChange::Close,
                ..
            } => Capability::ChannelAdmin,
            Self::ChangeChannel { .. } | Self::ChannelTopic { .. } => Capability::ChannelMember,
            Self::CreateChannel { .. }
            | Self::PublicChannelDescriptor { .. }
            | Self::AdmitChannel { .. }
            | Self::RecoverChannelRoute { .. }
            | Self::RemoveChannelMember { .. } => Capability::ChannelAdmin,
            Self::PrepareChannelJoin { .. }
            | Self::ChannelKeyPackage { .. }
            | Self::JoinChannel { .. }
            | Self::SendChannel { .. }
            | Self::SendChannelTracked { .. }
            | Self::SetChannelPresence { .. }
            | Self::SetChannelPresenceOptIn { .. }
            | Self::SendChannelDirect { .. } => Capability::ChannelMember,
            Self::SubmitOpaque { .. } => Capability::OpaqueTransfer,
            Self::SubmitComponent { .. }
            | Self::SubmitDurableOpaque { .. }
            | Self::ApplicationInbox { .. }
            | Self::CommitApplication { .. } => Capability::DurableApplication,
        }
    }

    fn validate_application_payload(&self) -> Result<(), SdkError> {
        match self {
            Self::CatalogHttp(request) => request.validate_size(),
            Self::ConfigureCatalogOrigins { origins }
                if origins.len() > 8 || origins.iter().any(|h| h.len() > 253) =>
            {
                Err(SdkError::Protocol(
                    "invalid catalog origin allowlist".into(),
                ))
            }
            Self::SendDirect { body, .. }
            | Self::SendDirectTracked { body, .. }
            | Self::SendChannelTracked { body, .. }
            | Self::SendChannel { body, .. }
            | Self::SendChannelDirect { body, .. }
            | Self::SubmitOpaque { body, .. }
            | Self::SubmitVolatileComponent { body, .. }
            | Self::SubmitBootstrap { body, .. }
            | Self::SubmitComponent { body, .. }
            | Self::SubmitDurableOpaque { body, .. } => {
                crate::types::validate_application_payload(body)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u16,
    pub request_id: u64,
    pub result: Result<Response, SdkError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    File(crate::files::FileReply),
    Empty,
    Identity(Identity),
    JoinPrepared(JoinRequest),
    Blob(Blob),
    EventsSubscribed,
    Channels(Vec<JoinedChannel>),
    ChannelCreated(ChannelId),
    ChannelRoster(Vec<ChannelMemberSummary>),
    PublicChannelDescriptor(PublicChannelDescriptor),
    MessageId(crate::MessageId),
    Signature(Vec<u8>),
    ApplicationInbox(Vec<crate::ApplicationDelivery>),
    Shell(crate::shell::ShellReply),
    CatalogHttp(crate::CatalogHttpResponse),
    ChannelTopic(String),
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
fn tracked_response(result: Result<Response, SdkError>) -> Result<crate::MessageId, SdkError> {
    match result {
        Ok(Response::MessageId(id)) => Ok(id),
        Err(SdkError::PermissionDenied) => Err(SdkError::PermissionDenied),
        // Even a malformed/lost reply can follow a committed send. Never
        // translate it into an ordinary retryable failure.
        _ => Err(SdkError::SendUncertain(
            "native submission reply unavailable or invalid".into(),
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub version: u16,
    pub sequence: u64,
    pub event: ClientEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    Hello(Hello),
    Welcome(Welcome),
    Request(RequestEnvelope),
    Response(ResponseEnvelope),
    Event(EventEnvelope),
}

// Keep the public Vec-returning codec compatible. Runtime I/O uses the guarded
// variant: count first, allocate once, then serialize directly into guarded storage.
fn encode_guarded(frame: &Frame) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    if let Frame::Request(request) = frame {
        request.request.validate_application_payload()?;
    }
    let length = postcard::experimental::serialized_size(frame)
        .map_err(|error| SdkError::Protocol(error.to_string()))?;
    if length > MAX_FRAME_BYTES {
        return Err(SdkError::Protocol("IPC frame exceeds limit".into()));
    }
    let mut payload = Zeroizing::new(vec![0; length]);
    postcard::to_slice(frame, &mut payload)
        .map_err(|error| SdkError::Protocol(error.to_string()))?;
    Ok(payload)
}

pub fn encode(frame: &Frame) -> Result<Vec<u8>, SdkError> {
    let mut payload = encode_guarded(frame)?;
    Ok(std::mem::take(&mut *payload))
}

// This guard covers request application bodies only; it does not promise to
// clear every field of every IPC variant. No Drop implementation changes enum
// moves, public frame layout, serde ordinals or dispatch semantics.
impl Zeroize for Request {
    fn zeroize(&mut self) {
        match self {
            Self::CatalogHttp(request) => request.body.as_mut_slice().zeroize(),
            Self::SubmitVolatileComponent { body, .. }
            | Self::SubmitBootstrap { body, .. }
            | Self::SubmitComponent { body, .. }
            | Self::SubmitDurableOpaque { body, .. }
            | Self::SendDirect { body, .. }
            | Self::SendDirectTracked { body, .. }
            | Self::SendChannelTracked { body, .. } => body.as_mut_slice().zeroize(),
            _ => {}
        }
    }
}
impl Zeroize for Frame {
    fn zeroize(&mut self) {
        if let Self::Request(envelope) = self {
            envelope.request.zeroize();
        }
    }
}

pub fn decode(payload: &[u8]) -> Result<Frame, SdkError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(SdkError::Protocol("IPC frame exceeds limit".into()));
    }
    let (frame, trailing) = postcard::take_from_bytes(payload)
        .map_err(|error| SdkError::Protocol(error.to_string()))?;
    let mut frame = Zeroizing::new(frame);
    if !trailing.is_empty() {
        return Err(SdkError::Protocol("trailing IPC bytes".into()));
    }
    if let Frame::Request(request) = &*frame {
        request.request.validate_application_payload()?;
    }
    Ok(std::mem::replace(
        &mut *frame,
        Frame::Response(ResponseEnvelope {
            version: VERSION,
            request_id: 0,
            result: Ok(Response::Empty),
        }),
    ))
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<(), SdkError> {
    let payload = encode_guarded(frame)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| SdkError::Protocol("IPC frame exceeds u32 length".into()))?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| SdkError::Runtime(error.to_string()))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|error| SdkError::Runtime(error.to_string()))
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, SdkError> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => SdkError::ConnectionClosed,
            _ => SdkError::Runtime(error.to_string()),
        })?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(SdkError::Protocol("IPC frame exceeds limit".into()));
    }
    let mut payload = Zeroizing::new(vec![0; length]);
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => SdkError::ConnectionClosed,
            _ => SdkError::Runtime(error.to_string()),
        })?;
    decode(&payload)
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
struct IpcInner {
    component_scoped: bool,
    authenticated_component_id: Option<[u8; 16]>,
    identity: std::sync::OnceLock<Identity>,
    granted: Vec<Capability>,
    event_stream_id: [u8; 16],
    writer: Mutex<tokio::io::WriteHalf<ClientStream>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Response, SdkError>>>>,
    events: broadcast::Sender<EventEnvelope>,
    closed: watch::Sender<bool>,
    next_request_id: AtomicU64,
    reader_abort: std::sync::OnceLock<tokio::task::AbortHandle>,
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
#[derive(Clone)]
pub struct IpcClient(Arc<IpcInner>, Option<([u8; 16], [u8; 16])>);

#[cfg(all(any(unix, windows), feature = "ipc"))]
impl IpcClient {
    pub async fn resolve_contact_identity(&self, card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        match self
            .request(Request::ContactIdentity { card: card.clone() })
            .await?
        {
            Response::Blob(Blob(bytes)) => Ok(bytes),
            _ => Err(SdkError::Protocol(
                "unexpected contact identity reply".into(),
            )),
        }
    }

    pub async fn shell_request(
        &self,
        request: crate::shell::ShellRequest,
    ) -> Result<crate::shell::ShellReply, SdkError> {
        match self.request(Request::Shell(request)).await? {
            Response::Shell(reply) => Ok(reply),
            _ => Err(SdkError::Protocol("unexpected shell reply".into())),
        }
    }

    pub async fn file_request(
        &self,
        request: crate::files::FileRequest,
    ) -> Result<crate::files::FileReply, SdkError> {
        match self.request(Request::File(request)).await? {
            Response::File(reply) => Ok(reply),
            _ => Err(SdkError::Protocol("unexpected file reply".into())),
        }
    }

    pub async fn connect(
        path: impl AsRef<Path>,
        application: impl Into<String>,
        requested_capabilities: Vec<Capability>,
    ) -> Result<Self, SdkError> {
        Self::connect_authenticated(path, application, requested_capabilities, None).await
    }

    pub async fn connect_component(
        path: impl AsRef<Path>,
        application: impl Into<String>,
        requested_capabilities: Vec<Capability>,
        credentials: crate::machine::ComponentCredentials,
    ) -> Result<Self, SdkError> {
        Self::connect_authenticated(path, application, requested_capabilities, Some(credentials))
            .await
    }

    pub async fn submit_volatile_component(
        &self,
        recipient: &ContactCard,
        destination: gcoms_core::component::ComponentId,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SubmitVolatileComponent {
            recipient: recipient.clone(),
            destination,
            content_type: content_type.into(),
            body: body.to_vec(),
        })
        .await
    }

    pub async fn submit_component(
        &self,
        recipient: &ContactCard,
        destination: gcoms_core::component::ComponentId,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SubmitComponent {
            recipient: recipient.clone(),
            destination,
            content_type: content_type.into(),
            body: body.to_vec(),
        })
        .await
    }

    async fn connect_authenticated(
        path: impl AsRef<Path>,
        application: impl Into<String>,
        requested_capabilities: Vec<Capability>,
        component: Option<crate::machine::ComponentCredentials>,
    ) -> Result<Self, SdkError> {
        let endpoint = crate::LocalEndpoint::new(path.as_ref());
        let mut stream = local::connect(&endpoint).await?;
        let bootstrap_requested =
            requested_capabilities.contains(&Capability::BootstrapApplication);
        let component_scoped = component.is_some();
        let authenticated_component_id = component.as_ref().map(|c| c.component_id);
        write_frame(
            &mut stream,
            &Frame::Hello(Hello {
                component,
                min_version: VERSION,
                max_version: VERSION,
                application: application.into(),
                requested_capabilities,
            }),
        )
        .await?;
        let (granted, event_stream_id) = match read_frame(&mut stream).await? {
            Frame::Welcome(welcome) if welcome.version == VERSION => {
                (welcome.granted_capabilities, welcome.event_stream_id)
            }
            _ => return Err(SdkError::Protocol("invalid IPC welcome".into())),
        };
        if bootstrap_requested && !granted.contains(&Capability::BootstrapApplication) {
            return Err(SdkError::PermissionDenied);
        }
        let (mut reader, writer) = tokio::io::split(stream);
        let (events, _) = broadcast::channel(256);
        let inner = Arc::new(IpcInner {
            component_scoped,
            authenticated_component_id,
            identity: std::sync::OnceLock::new(),
            granted,
            event_stream_id,
            writer: Mutex::new(writer),
            pending: Mutex::new(HashMap::new()),
            events,
            closed: watch::channel(false).0,
            next_request_id: AtomicU64::new(1),
            reader_abort: std::sync::OnceLock::new(),
        });
        let reader_inner = inner.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                match read_frame(&mut reader).await {
                    Ok(Frame::Response(response)) if response.version == VERSION => {
                        if let Some(sender) = reader_inner
                            .pending
                            .lock()
                            .await
                            .remove(&response.request_id)
                        {
                            let _ = sender.send(response.result);
                        }
                    }
                    Ok(Frame::Event(event)) if event.version == VERSION => {
                        let _ = reader_inner.events.send(event);
                    }
                    _ => {
                        reader_inner.closed.send_replace(true);
                        let pending = std::mem::take(&mut *reader_inner.pending.lock().await);
                        for (_, sender) in pending {
                            let _ = sender.send(Err(SdkError::ConnectionClosed));
                        }
                        break;
                    }
                }
            }
        });
        inner
            .reader_abort
            .set(reader_task.abort_handle())
            .expect("IPC reader abort handle initialized once");
        let client = Self(inner, None);
        let identity = match client.request(Request::Identity).await? {
            Response::Identity(identity) => identity,
            _ => return Err(SdkError::Protocol("identity response mismatch".into())),
        };
        client
            .0
            .identity
            .set(identity)
            .map_err(|_| SdkError::Protocol("identity initialized twice".into()))?;
        Ok(client)
    }

    /// Reply to a routed peer from an unscoped server socket. Machine sockets
    /// assign the source themselves and reject nested envelopes.
    pub fn routed(&self, source: [u8; 16], destination: [u8; 16]) -> Self {
        Self(self.0.clone(), Some((source, destination)))
    }

    /// Component authenticated by this connection's successful Hello/Welcome.
    /// Unscoped sockets return None; cloning or selecting a reply route cannot
    /// change the authenticated subject. This is not a grant or key attestation.
    pub fn authenticated_component_id(&self) -> Option<[u8; 16]> {
        self.0.authenticated_component_id
    }

    pub fn application_body_limit(&self, content_type: &str) -> Result<usize, SdkError> {
        let overhead = if self.0.component_scoped || self.1.is_some() {
            gcoms_core::component::OVERHEAD
        } else {
            0
        };
        crate::application_body_limit(content_type)?
            .checked_sub(overhead)
            .ok_or_else(|| {
                SdkError::Protocol("component content type exceeds payload limit".into())
            })
    }

    pub fn granted_capabilities(&self) -> &[Capability] {
        &self.0.granted
    }

    pub fn event_stream_id(&self) -> [u8; 16] {
        self.0.event_stream_id
    }

    /// Events with the monotonic sequence assigned by the authenticated local IPC server.
    pub fn subscribe_event_envelopes(&self) -> mpsc::Receiver<EventEnvelope> {
        let mut source = self.0.events.subscribe();
        let mut closed = self.0.closed.subscribe();
        let (sender, receiver) = mpsc::channel(256);
        tokio::spawn(async move {
            loop {
                if *closed.borrow() {
                    break;
                }
                let next = tokio::select! {
                    _ = closed.changed() => break,
                    _ = sender.closed() => break,
                    event = source.recv() => event,
                };
                let event = match next {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => EventEnvelope {
                        version: VERSION,
                        sequence: 0,
                        event: ClientEvent::EventsLagged { skipped },
                    },
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if sender.send(event).await.is_err() {
                    break;
                }
            }
        });
        receiver
    }

    pub(crate) async fn request(&self, request: Request) -> Result<Response, SdkError> {
        let mut request = Zeroizing::new(request);
        if !self.0.granted.contains(&request.required_capability()) {
            return Err(SdkError::PermissionDenied);
        }
        let request_id = self.0.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.0.pending.lock().await;
            if *self.0.closed.borrow() {
                return Err(SdkError::ConnectionClosed);
            }
            pending.insert(request_id, sender);
        }
        let frame = Zeroizing::new(Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id,
            request: std::mem::replace(&mut *request, Request::Identity),
        }));
        if let Err(error) = write_frame(&mut *self.0.writer.lock().await, &frame).await {
            self.0.pending.lock().await.remove(&request_id);
            return Err(error);
        }
        // The response correlation owns only a oneshot, never the payload.
        // Release the sent frame before waiting for the daemon's reply.
        drop(frame);
        receiver.await.map_err(|_| SdkError::ConnectionClosed)?
    }

    async fn expect_empty(&self, request: Request) -> Result<(), SdkError> {
        match self.request(request).await? {
            Response::Empty => Ok(()),
            _ => Err(SdkError::Protocol("empty response mismatch".into())),
        }
    }
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
impl Drop for IpcClient {
    fn drop(&mut self) {
        // The reader task owns the only non-client Arc. Abort it when the last
        // public handle drops so both split pipe halves close.
        if Arc::strong_count(&self.0) <= 2 {
            if let Some(reader_abort) = self.0.reader_abort.get() {
                reader_abort.abort();
            }
        }
    }
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
#[async_trait]
impl GcClient for IpcClient {
    async fn configure_catalog_origins(&self, origins: Vec<String>) -> Result<(), SdkError> {
        match self
            .request(Request::ConfigureCatalogOrigins { origins })
            .await?
        {
            Response::Empty => Ok(()),
            _ => Err(SdkError::Protocol(
                "unexpected catalog configuration response".into(),
            )),
        }
    }
    async fn catalog_request(
        &self,
        request: crate::CatalogHttpRequest,
    ) -> Result<crate::CatalogHttpResponse, SdkError> {
        request.validate_size()?;
        match self.request(Request::CatalogHttp(request)).await? {
            Response::CatalogHttp(response) => Ok(response),
            _ => Err(SdkError::Protocol("unexpected catalog response".into())),
        }
    }

    async fn file_route(&self) -> Result<Vec<u8>, SdkError> {
        match self.request(Request::FileRoute).await? {
            Response::Blob(Blob(bytes)) => Ok(bytes),
            _ => Err(SdkError::Protocol("unexpected file route reply".into())),
        }
    }

    fn identity(&self) -> Identity {
        self.0
            .identity
            .get()
            .expect("IPC identity initialized before connect returns")
            .clone()
    }

    async fn refresh_identity(&self) -> Result<Identity, SdkError> {
        match self.request(Request::Identity).await? {
            Response::Identity(identity) => Ok(identity),
            _ => Err(SdkError::Protocol("identity response mismatch".into())),
        }
    }

    async fn sign_identity_digest(&self, digest: [u8; 32]) -> Result<Vec<u8>, SdkError> {
        match self.request(Request::SignIdentityDigest { digest }).await? {
            Response::Signature(signature) => Ok(signature),
            _ => Err(SdkError::Protocol(
                "identity signature response mismatch".into(),
            )),
        }
    }

    async fn sign_principal_binding_hash(
        &self,
        claims_hash: [u8; 32],
    ) -> Result<Vec<u8>, SdkError> {
        match self
            .request(Request::SignPrincipalBindingHash { claims_hash })
            .await?
        {
            Response::Signature(signature) => Ok(signature),
            _ => Err(SdkError::Protocol(
                "principal binding signature response mismatch".into(),
            )),
        }
    }

    fn subscribe_events(&self) -> mpsc::Receiver<ClientEvent> {
        let mut source = self.0.events.subscribe();
        let mut closed = self.0.closed.subscribe();
        let (sender, receiver) = mpsc::channel(256);
        tokio::spawn(async move {
            loop {
                if *closed.borrow() {
                    break;
                }
                let next = tokio::select! {
                    _ = closed.changed() => break,
                    event = source.recv() => event,
                };
                let event = match next {
                    Ok(event) => event.event,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        ClientEvent::EventsLagged { skipped }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if sender.send(event).await.is_err() {
                    break;
                }
            }
        });
        receiver
    }

    async fn list_channels(&self) -> Result<Vec<JoinedChannel>, SdkError> {
        match self.request(Request::ListChannels).await? {
            Response::Channels(channels) => Ok(channels),
            _ => Err(SdkError::Protocol("channel list response mismatch".into())),
        }
    }

    async fn channel_roster(&self, channel: &str) -> Result<Vec<ChannelMemberSummary>, SdkError> {
        match self
            .request(Request::ChannelRoster {
                channel: channel.into(),
            })
            .await?
        {
            Response::ChannelRoster(roster) => Ok(roster),
            _ => Err(SdkError::Protocol(
                "channel roster response mismatch".into(),
            )),
        }
    }

    async fn channel_topic(&self, channel: &str) -> Result<String, SdkError> {
        match self
            .request(Request::ChannelTopic {
                channel: channel.into(),
            })
            .await?
        {
            Response::ChannelTopic(topic) => Ok(topic),
            _ => Err(SdkError::Protocol("channel topic response mismatch".into())),
        }
    }
    async fn change_channel(
        &self,
        channel: &str,
        change: crate::ChannelChange,
    ) -> Result<crate::MessageId, SdkError> {
        tracked_response(
            self.request(Request::ChangeChannel {
                channel: channel.into(),
                change,
            })
            .await,
        )
    }

    async fn public_channel_descriptor(
        &self,
        channel: &str,
        description: &str,
        activity: ActivityBucket,
        automatic_join: AutomaticJoinEndpoint,
        expires_at_unix: u64,
    ) -> Result<PublicChannelDescriptor, SdkError> {
        match self
            .request(Request::PublicChannelDescriptor {
                channel: channel.into(),
                description: description.into(),
                activity,
                automatic_join,
                expires_at_unix,
            })
            .await?
        {
            Response::PublicChannelDescriptor(descriptor) => Ok(descriptor),
            _ => Err(SdkError::Protocol(
                "channel descriptor response mismatch".into(),
            )),
        }
    }

    async fn send_direct(
        &self,
        peer: &ContactCard,
        body: &[u8],
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        crate::types::validate_application_payload(body)?;
        self.expect_empty(Request::SendDirect {
            peer: peer.clone(),
            body: body.to_vec(),
            via: via.cloned(),
        })
        .await
    }

    async fn send_direct_tracked(
        &self,
        peer: &ContactCard,
        body: &[u8],
        via: Option<&ContactCard>,
    ) -> Result<crate::MessageId, SdkError> {
        crate::types::validate_application_payload(body)?;
        tracked_response(
            self.request(Request::SendDirectTracked {
                peer: peer.clone(),
                body: body.to_vec(),
                via: via.cloned(),
            })
            .await,
        )
    }

    async fn submit_durable_opaque(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let mut app = crate::ApplicationMessage {
            content_type: content_type.into(),
            body: body.to_vec(),
        };
        let wire = app.encode()?;
        if let Some((source, destination)) = self.1 {
            app = crate::ApplicationMessage::decode(
                &gcoms_core::component::RoutedApplication {
                    source,
                    destination,
                    application: wire,
                }
                .encode()
                .map_err(|e| SdkError::Protocol(e.into()))?,
            )?;
        }
        self.expect_empty(Request::SubmitDurableOpaque {
            recipient: recipient.clone(),
            content_type: app.content_type,
            body: app.body,
        })
        .await
    }

    async fn application_inbox(
        &self,
        after: u64,
        limit: u16,
    ) -> Result<Vec<crate::ApplicationDelivery>, SdkError> {
        match self
            .request(Request::ApplicationInbox { after, limit })
            .await?
        {
            Response::ApplicationInbox(entries) => Ok(entries),
            _ => Err(SdkError::Protocol(
                "application inbox response mismatch".into(),
            )),
        }
    }

    async fn commit_application(&self, sequence: u64, digest: [u8; 32]) -> Result<(), SdkError> {
        self.expect_empty(Request::CommitApplication { sequence, digest })
            .await
    }

    async fn set_direct_presence(
        &self,
        peer: &ContactCard,
        mode: PresenceMode,
        lease_secs: u32,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SetDirectPresence {
            peer: peer.clone(),
            mode,
            lease_secs,
            via: via.cloned(),
        })
        .await
    }

    async fn set_direct_presence_opt_in(
        &self,
        peer: &ContactCard,
        enabled: bool,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SetDirectPresenceOptIn {
            peer: peer.clone(),
            enabled,
            via: via.cloned(),
        })
        .await
    }

    async fn submit_opaque(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SubmitOpaque {
            recipient: recipient.clone(),
            content_type: content_type.into(),
            body: body.to_vec(),
        })
        .await
    }

    async fn create_channel(
        &self,
        channel: &str,
        display_name: &str,
        capacity: usize,
        visibility: ChannelVisibility,
    ) -> Result<ChannelId, SdkError> {
        let capacity = u32::try_from(capacity)
            .map_err(|_| SdkError::Protocol("channel capacity exceeds u32".into()))?;
        match self
            .request(Request::CreateChannel {
                channel: channel.into(),
                display_name: display_name.into(),
                capacity,
                visibility,
            })
            .await?
        {
            Response::ChannelCreated(id) => Ok(id),
            _ => Err(SdkError::Protocol(
                "channel creation response mismatch".into(),
            )),
        }
    }

    async fn prepare_channel_join(&self, display_name: &str) -> Result<JoinRequest, SdkError> {
        match self
            .request(Request::PrepareChannelJoin {
                display_name: display_name.into(),
            })
            .await?
        {
            Response::JoinPrepared(request) => Ok(request),
            _ => Err(SdkError::Protocol("join response mismatch".into())),
        }
    }

    async fn channel_key_package(&self, request: JoinRequest) -> Result<Blob, SdkError> {
        match self.request(Request::ChannelKeyPackage { request }).await? {
            Response::Blob(blob) => Ok(blob),
            _ => Err(SdkError::Protocol("blob response mismatch".into())),
        }
    }

    async fn admit_channel(
        &self,
        channel: &str,
        key_package: &Blob,
        member_name: &str,
    ) -> Result<Blob, SdkError> {
        match self
            .request(Request::AdmitChannel {
                channel: channel.into(),
                key_package: key_package.clone(),
                member_name: member_name.into(),
            })
            .await?
        {
            Response::Blob(blob) => Ok(blob),
            _ => Err(SdkError::Protocol("blob response mismatch".into())),
        }
    }

    async fn recover_channel_route(
        &self,
        channel: &str,
        expected_channel_id: ChannelId,
        expected_epoch: u64,
        retained_welcome: &Blob,
        peer: &ContactCard,
    ) -> Result<crate::MessageId, SdkError> {
        match self
            .request(Request::RecoverChannelRoute {
                channel: channel.into(),
                expected_channel_id,
                expected_epoch,
                retained_welcome: retained_welcome.clone(),
                peer: peer.clone(),
            })
            .await?
        {
            Response::MessageId(id) => Ok(id),
            _ => Err(SdkError::Protocol("message ID response mismatch".into())),
        }
    }

    async fn join_channel(
        &self,
        request: JoinRequest,
        channel: &str,
        visibility: ChannelVisibility,
        welcome: &Blob,
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::JoinChannel {
            request,
            channel: channel.into(),
            visibility,
            welcome: welcome.clone(),
        })
        .await
    }

    async fn send_channel(&self, channel: &str, body: &[u8]) -> Result<(), SdkError> {
        crate::types::validate_application_payload(body)?;
        self.expect_empty(Request::SendChannel {
            channel: channel.into(),
            body: body.to_vec(),
        })
        .await
    }

    async fn send_channel_tracked(
        &self,
        channel: &str,
        body: &[u8],
    ) -> Result<crate::MessageId, SdkError> {
        crate::types::validate_application_payload(body)?;
        tracked_response(
            self.request(Request::SendChannelTracked {
                channel: channel.into(),
                body: body.to_vec(),
            })
            .await,
        )
    }

    async fn set_channel_presence(
        &self,
        channel: &str,
        mode: PresenceMode,
        lease_secs: u32,
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SetChannelPresence {
            channel: channel.into(),
            mode,
            lease_secs,
        })
        .await
    }

    async fn set_channel_presence_opt_in(
        &self,
        channel: &str,
        enabled: bool,
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::SetChannelPresenceOptIn {
            channel: channel.into(),
            enabled,
        })
        .await
    }

    async fn send_channel_direct(
        &self,
        channel: &str,
        recipient_member_id: [u8; 32],
        body: &[u8],
    ) -> Result<crate::MessageId, SdkError> {
        crate::types::validate_application_payload(body)?;
        match self
            .request(Request::SendChannelDirect {
                channel: channel.into(),
                recipient_member_id,
                body: body.to_vec(),
            })
            .await?
        {
            Response::MessageId(message_id) => Ok(message_id),
            _ => Err(SdkError::Protocol("message id response mismatch".into())),
        }
    }

    async fn remove_channel_member(
        &self,
        channel: &str,
        member_id: [u8; 32],
    ) -> Result<(), SdkError> {
        self.expect_empty(Request::RemoveChannelMember {
            channel: channel.into(),
            member_id,
        })
        .await
    }
}

#[cfg(all(unix, feature = "ipc"))]
pub async fn serve_unix<C: GcClient + Clone + 'static>(
    path: impl AsRef<Path>,
    client: C,
    allowed_capabilities: Vec<Capability>,
) -> Result<(), SdkError> {
    serve_local(path, client, allowed_capabilities).await
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub async fn serve_local<C: GcClient + Clone + 'static>(
    endpoint: impl AsRef<Path>,
    client: C,
    allowed_capabilities: Vec<Capability>,
) -> Result<(), SdkError> {
    serve_local_until(
        endpoint,
        client,
        allowed_capabilities,
        std::future::pending(),
    )
    .await
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub async fn serve_local_until<C, F>(
    endpoint: impl AsRef<Path>,
    client: C,
    allowed: Vec<Capability>,
    shutdown: F,
) -> Result<(), SdkError>
where
    C: GcClient + Clone + 'static,
    F: std::future::Future<Output = ()>,
{
    let listener = LocalListener::bind(&crate::LocalEndpoint::new(endpoint.as_ref()))?;
    serve_listener_until(listener, client, allowed, None, shutdown).await
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub async fn serve_machine<C: GcClient + Clone + 'static>(
    endpoint: impl AsRef<Path>,
    client: C,
    registry: crate::machine::MachineRegistry,
) -> Result<(), SdkError> {
    serve_machine_until(endpoint, client, registry, std::future::pending()).await
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub async fn serve_machine_until<C, F>(
    endpoint: impl AsRef<Path>,
    client: C,
    registry: crate::machine::MachineRegistry,
    shutdown: F,
) -> Result<(), SdkError>
where
    C: GcClient + Clone + 'static,
    F: std::future::Future<Output = ()>,
{
    registry.validate()?;
    let listener = LocalListener::bind(&crate::LocalEndpoint::new(endpoint.as_ref()))?;
    serve_machine_on_listener_until(listener, client, registry, shutdown).await
}

/// The caller owns socket path cleanup. Accepted tasks are owned by the listener.
#[cfg(all(any(unix, windows), feature = "ipc"))]
pub async fn serve_machine_on_listener<C: GcClient + Clone + 'static>(
    listener: LocalListener,
    client: C,
    registry: crate::machine::MachineRegistry,
) -> Result<(), SdkError> {
    serve_machine_on_listener_until(listener, client, registry, std::future::pending()).await
}

/// Stop, cancel and drain all accepted connections before returning.
#[cfg(all(any(unix, windows), feature = "ipc"))]
pub async fn serve_machine_on_listener_until<C, F>(
    listener: LocalListener,
    client: C,
    registry: crate::machine::MachineRegistry,
    shutdown: F,
) -> Result<(), SdkError>
where
    C: GcClient + Clone + 'static,
    F: std::future::Future<Output = ()>,
{
    registry.validate()?;
    serve_listener_until(
        listener,
        client,
        Vec::new(),
        Some(Arc::new(registry)),
        shutdown,
    )
    .await
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
async fn serve_listener_until<C, F>(
    mut listener: LocalListener,
    client: C,
    allowed: Vec<Capability>,
    registry: Option<Arc<crate::machine::MachineRegistry>>,
    shutdown: F,
) -> Result<(), SdkError>
where
    C: GcClient + Clone + 'static,
    F: std::future::Future<Output = ()>,
{
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(stream) => {
                    let client = client.clone();
                    let allowed = allowed.clone();
                    let registry = registry.clone();
                    connections.spawn(async move {
                        let _ = serve_connection(stream, client, allowed, registry).await;
                    });
                }
                Err(error) => break Err(error),
            },
            _ = connections.join_next(), if !connections.is_empty() => {},
        }
    };
    drop(listener);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
async fn serve_connection<C, S>(
    mut stream: S,
    client: C,
    allowed: Vec<Capability>,
    registry: Option<Arc<crate::machine::MachineRegistry>>,
) -> Result<(), SdkError>
where
    C: GcClient,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = match read_frame(&mut stream).await? {
        Frame::Hello(hello)
            if hello.min_version <= hello.max_version
                && hello.min_version <= VERSION
                && hello.max_version >= MIN_SERVER_VERSION =>
        {
            hello
        }
        unexpected => {
            let _unexpected = Zeroizing::new(unexpected);
            return Err(SdkError::Protocol("incompatible IPC hello".into()));
        }
    };
    let version = hello.max_version.min(VERSION);
    // Tag 12 meant BootstrapApplication in the unreleased bootstrap-v13 fork.
    // Never downgrade/filter that Hello: tags 30/31 now mean network sends.
    if (version < 15
        && hello
            .requested_capabilities
            .contains(&Capability::CatalogAccess))
        || (version < 16
            && hello
                .requested_capabilities
                .contains(&Capability::BootstrapApplication))
    {
        return Err(SdkError::Protocol(
            "incompatible IPC capability version".into(),
        ));
    }

    let component = match (&registry, &hello.component) {
        (Some(registry), Some(credentials)) => Some(registry.authenticate(credentials)?),
        (None, None) => None,
        _ => return Err(SdkError::PermissionDenied),
    };
    if version < 16
        && component.as_ref().is_some_and(|entry| {
            entry
                .capabilities
                .contains(&Capability::BootstrapApplication)
        })
    {
        return Err(SdkError::Protocol(
            "bootstrap registration requires IPC16".into(),
        ));
    }
    let allowed = component
        .as_ref()
        .map_or(allowed, |entry| entry.capabilities.clone());
    let granted = hello
        .requested_capabilities
        .into_iter()
        .filter(|capability| {
            allowed.contains(capability)
                && (version >= 11 || *capability != Capability::HostShell)
                && (version >= 12 || *capability != Capability::VolatileApplication)
                && (version >= 15 || *capability != Capability::CatalogAccess)
                && (version >= 16 || *capability != Capability::BootstrapApplication)
        })
        .collect::<Vec<_>>();
    write_frame(
        &mut stream,
        &Frame::Welcome(Welcome {
            version,
            granted_capabilities: granted.clone(),
            event_stream_id: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_be_bytes(),
        }),
    )
    .await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut events = client.subscribe_events();
    let send_events = granted.contains(&Capability::EventRead);
    let mut sequence = 1u64;
    let mut bootstrap = crate::bootstrap::Session::default();
    loop {
        let frame = read_request_with_events(
            &mut reader,
            &mut writer,
            &mut events,
            &granted,
            send_events,
            &mut sequence,
            component.as_ref(),
            version,
            &mut bootstrap,
        )
        .await?;
        let Frame::Request(mut request) = frame else {
            return Err(SdkError::Protocol("expected IPC request".into()));
        };
        let mut guarded_request =
            Zeroizing::new(std::mem::replace(&mut request.request, Request::Identity));
        if request.version != version {
            return Err(SdkError::Protocol("IPC request version mismatch".into()));
        }
        let result = if version >= guarded_request.minimum_version()
            && granted.contains(&guarded_request.required_capability())
        {
            if matches!(
                &*guarded_request,
                Request::AdmitBootstrapPeer { .. } | Request::SubmitBootstrap { .. }
            ) {
                match component.as_ref() {
                    Some(component)
                        if component
                            .capabilities
                            .contains(&Capability::BootstrapApplication) =>
                    {
                        bootstrap
                            .dispatch(
                                &client,
                                component.credentials.component_id,
                                std::mem::replace(&mut *guarded_request, Request::Identity),
                            )
                            .await
                    }
                    _ => Err(SdkError::PermissionDenied),
                }
            } else if let Some(component) = &component {
                crate::machine::dispatch(
                    &client,
                    component,
                    std::mem::replace(&mut *guarded_request, Request::Identity),
                )
                .await
            } else {
                dispatch(
                    &client,
                    std::mem::replace(&mut *guarded_request, Request::Identity),
                )
                .await
            }
        } else {
            Err(SdkError::PermissionDenied)
        };
        write_frame(
            &mut writer,
            &Frame::Response(ResponseEnvelope {
                version,
                request_id: request.request_id,
                result,
            }),
        )
        .await?;
    }
}

/// Retain the in-progress frame read while forwarding events. `read_exact` is
/// not cancellation safe: recreating it after an event loses a consumed prefix.
#[cfg(all(any(unix, windows), feature = "ipc"))]
#[allow(clippy::too_many_arguments)]
async fn read_request_with_events<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    events: &mut mpsc::Receiver<ClientEvent>,
    granted: &[Capability],
    send_events: bool,
    sequence: &mut u64,
    component: Option<&crate::machine::ComponentRegistration>,
    version: u16,
    bootstrap: &mut crate::bootstrap::Session,
) -> Result<Frame, SdkError> {
    let incoming = read_frame(reader);
    tokio::pin!(incoming);
    loop {
        tokio::select! {
            frame = &mut incoming => return frame,
            event = events.recv(), if send_events => {
                let event = event.ok_or(SdkError::ConnectionClosed)?;
                let event = match &component {
                    Some(component) => match component.filter_event(event, version) { Some(event) => event, None => continue },
                    None if matches!(event, ClientEvent::VolatileApplication { .. }) => continue,
                    None => event,
                };
                let event = if version >= 16 && granted.contains(&Capability::BootstrapApplication) {
                    match bootstrap.filter_event(event) { Some(event) => event, None => continue }
                } else { event };
                if !event_allowed_for_version(&event, granted, version) { continue; }
                write_frame(writer, &Frame::Event(EventEnvelope {
                    version, sequence: *sequence, event,
                })).await?;
                *sequence = sequence.checked_add(1).ok_or_else(|| SdkError::Protocol("IPC event sequence exhausted".into()))?;
            }
        }
    }
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
fn event_allowed_for_version(event: &ClientEvent, granted: &[Capability], version: u16) -> bool {
    if version < 16 && granted.contains(&Capability::BootstrapApplication) {
        return false;
    }
    if let ClientEvent::VolatileApplication { body, .. } = event {
        if version < 12 {
            return false;
        }
        if gcoms_core::component::application_parts(body)
            .is_some_and(|(kind, _)| kind == gcoms_core::bootstrap::CONTENT_TYPE)
            && (version < 16 || !granted.contains(&Capability::BootstrapApplication))
        {
            return false;
        }
    }
    event_allowed(event, granted)
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
fn event_allowed(event: &ClientEvent, granted: &[Capability]) -> bool {
    if !granted.contains(&Capability::EventRead) {
        return false;
    }
    match event {
        ClientEvent::VolatileApplication { .. } => {
            granted.contains(&Capability::VolatileApplication)
                || granted.contains(&Capability::BootstrapApplication)
        }
        ClientEvent::IdentityUpdated { .. } => granted.contains(&Capability::IdentityRead),
        ClientEvent::SessionOpened { .. }
        | ClientEvent::DirectDelivered { .. }
        | ClientEvent::PresenceChanged { .. } => granted.contains(&Capability::DirectMessage),
        ClientEvent::DirectMessage { body, .. } => {
            granted.contains(&Capability::DirectMessage)
                || (granted.contains(&Capability::OpaqueTransfer)
                    && ApplicationMessage::decode(body).is_ok())
        }
        ClientEvent::ChannelPresenceChanged { .. }
        | ClientEvent::ChannelMessage { .. }
        | ClientEvent::ChannelDelivered { .. }
        | ClientEvent::ChannelRemoved { .. }
        | ClientEvent::ChannelRosterChanged { .. }
        | ClientEvent::ChannelDirectMessage { .. }
        | ClientEvent::ChannelDirectDelivered { .. } => {
            granted.contains(&Capability::ChannelMember)
        }
        ClientEvent::EventsLagged { .. } => true,
    }
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub(crate) async fn dispatch<C: GcClient>(
    client: &C,
    request: Request,
) -> Result<Response, SdkError> {
    match request {
        Request::ConfigureCatalogOrigins { origins } => {
            client.configure_catalog_origins(origins).await?;
            Ok(Response::Empty)
        }
        Request::CatalogHttp(request) => client
            .catalog_request(request)
            .await
            .map(Response::CatalogHttp),
        Request::AdmitBootstrapPeer { .. } | Request::SubmitBootstrap { .. } => {
            Err(SdkError::PermissionDenied)
        }
        Request::SubmitVolatileComponent { body, .. } | Request::SubmitComponent { body, .. } => {
            let _body = Zeroizing::new(body);
            Err(SdkError::PermissionDenied)
        }
        Request::File(_) | Request::Shell(_) => Err(SdkError::PermissionDenied),
        Request::ContactIdentity { card } => client
            .contact_identity(&card)
            .map(|bytes| Response::Blob(Blob(bytes))),
        Request::Identity => client.refresh_identity().await.map(Response::Identity),
        Request::FileRoute => client
            .file_route()
            .await
            .map(|bytes| Response::Blob(Blob(bytes))),
        Request::SignIdentityDigest { digest } => client
            .sign_identity_digest(digest)
            .await
            .map(Response::Signature),
        Request::SignPrincipalBindingHash { claims_hash } => client
            .sign_principal_binding_hash(claims_hash)
            .await
            .map(Response::Signature),
        Request::ListChannels => client.list_channels().await.map(Response::Channels),
        Request::ChannelRoster { channel } => client
            .channel_roster(&channel)
            .await
            .map(Response::ChannelRoster),
        Request::ChannelTopic { channel } => client
            .channel_topic(&channel)
            .await
            .map(Response::ChannelTopic),
        Request::ChangeChannel { channel, change } => client
            .change_channel(&channel, change)
            .await
            .map(Response::MessageId),
        Request::PublicChannelDescriptor {
            channel,
            description,
            activity,
            automatic_join,
            expires_at_unix,
        } => client
            .public_channel_descriptor(
                &channel,
                &description,
                activity,
                automatic_join,
                expires_at_unix,
            )
            .await
            .map(Response::PublicChannelDescriptor),
        Request::SubmitDurableOpaque {
            recipient,
            content_type,
            body,
        } => {
            client
                .submit_durable_opaque(&recipient, &content_type, &body)
                .await?;
            Ok(Response::Empty)
        }
        Request::ApplicationInbox { after, limit } => client
            .application_inbox(after, limit)
            .await
            .map(Response::ApplicationInbox),
        Request::CommitApplication { sequence, digest } => {
            client.commit_application(sequence, digest).await?;
            Ok(Response::Empty)
        }
        Request::SubscribeEvents => Ok(Response::EventsSubscribed),
        Request::SendDirect { peer, body, via } => {
            crate::types::validate_application_payload(&body)?;
            client.send_direct(&peer, &body, via.as_ref()).await?;
            Ok(Response::Empty)
        }
        Request::SendDirectTracked { peer, body, via } => {
            crate::types::validate_application_payload(&body)?;
            client
                .send_direct_tracked(&peer, &body, via.as_ref())
                .await
                .map(Response::MessageId)
        }
        Request::SendChannelTracked { channel, body } => {
            crate::types::validate_application_payload(&body)?;
            client
                .send_channel_tracked(&channel, &body)
                .await
                .map(Response::MessageId)
        }
        Request::SetDirectPresence {
            peer,
            mode,
            lease_secs,
            via,
        } => {
            client
                .set_direct_presence(&peer, mode, lease_secs, via.as_ref())
                .await?;
            Ok(Response::Empty)
        }
        Request::SetDirectPresenceOptIn { peer, enabled, via } => {
            client
                .set_direct_presence_opt_in(&peer, enabled, via.as_ref())
                .await?;
            Ok(Response::Empty)
        }
        Request::CreateChannel {
            channel,
            display_name,
            capacity,
            visibility,
        } => client
            .create_channel(&channel, &display_name, capacity as usize, visibility)
            .await
            .map(Response::ChannelCreated),
        Request::PrepareChannelJoin { display_name } => client
            .prepare_channel_join(&display_name)
            .await
            .map(Response::JoinPrepared),
        Request::ChannelKeyPackage { request } => client
            .channel_key_package(request)
            .await
            .map(Response::Blob),
        Request::AdmitChannel {
            channel,
            key_package,
            member_name,
        } => client
            .admit_channel(&channel, &key_package, &member_name)
            .await
            .map(Response::Blob),
        Request::RecoverChannelRoute {
            channel,
            expected_channel_id,
            expected_epoch,
            retained_welcome,
            peer,
        } => client
            .recover_channel_route(
                &channel,
                expected_channel_id,
                expected_epoch,
                &retained_welcome,
                &peer,
            )
            .await
            .map(Response::MessageId),
        Request::JoinChannel {
            request,
            channel,
            visibility,
            welcome,
        } => {
            client
                .join_channel(request, &channel, visibility, &welcome)
                .await?;
            Ok(Response::Empty)
        }
        Request::SendChannel { channel, body } => {
            crate::types::validate_application_payload(&body)?;
            client.send_channel(&channel, &body).await?;
            Ok(Response::Empty)
        }
        Request::SetChannelPresence {
            channel,
            mode,
            lease_secs,
        } => {
            client
                .set_channel_presence(&channel, mode, lease_secs)
                .await?;
            Ok(Response::Empty)
        }
        Request::SetChannelPresenceOptIn { channel, enabled } => {
            client
                .set_channel_presence_opt_in(&channel, enabled)
                .await?;
            Ok(Response::Empty)
        }
        Request::SendChannelDirect {
            channel,
            recipient_member_id,
            body,
        } => {
            crate::types::validate_application_payload(&body)?;
            client
                .send_channel_direct(&channel, recipient_member_id, &body)
                .await
                .map(Response::MessageId)
        }
        Request::RemoveChannelMember { channel, member_id } => {
            client.remove_channel_member(&channel, member_id).await?;
            Ok(Response::Empty)
        }
        Request::SubmitOpaque {
            recipient,
            content_type,
            body,
        } => {
            client
                .submit_opaque(&recipient, &content_type, &body)
                .await?;
            Ok(Response::Empty)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracked_send_wire_version_and_capabilities_are_explicit() {
        let direct = Request::SendDirectTracked {
            peer: ContactCard(vec![]),
            body: vec![],
            via: None,
        };
        let channel = Request::SendChannelTracked {
            channel: "room".into(),
            body: vec![],
        };
        assert_eq!(direct.minimum_version(), 13);
        assert_eq!(channel.minimum_version(), 13);
        assert_eq!(direct.required_capability(), Capability::DirectMessage);
        assert_eq!(channel.required_capability(), Capability::ChannelMember);
        assert_eq!(
            Request::SendDirect {
                peer: ContactCard(vec![]),
                body: vec![],
                via: None
            }
            .minimum_version(),
            10
        );
    }

    #[cfg(all(any(unix, windows), feature = "ipc"))]
    #[test]
    fn tracked_send_lost_or_malformed_response_is_uncertain() {
        let id = crate::MessageId([0x41; 16]);
        assert_eq!(tracked_response(Ok(Response::MessageId(id))), Ok(id));
        for value in [
            Err(SdkError::ConnectionClosed),
            Err(SdkError::Runtime("send failed after persistence".into())),
            Ok(Response::Empty),
        ] {
            assert!(matches!(
                tracked_response(value),
                Err(SdkError::SendUncertain(_))
            ));
        }
        assert_eq!(
            tracked_response(Err(SdkError::PermissionDenied)),
            Err(SdkError::PermissionDenied)
        );
    }

    #[test]
    fn channel_management_requires_ipc17_and_the_correct_capability() {
        let topic = Request::ChannelTopic {
            channel: "test".into(),
        };
        assert_eq!(topic.minimum_version(), 17);
        assert_eq!(topic.required_capability(), Capability::ChannelMember);
        assert_eq!(postcard::to_allocvec(&topic).unwrap()[0], 37);
        for (change, capability) in [
            (
                crate::ChannelChange::Nickname("Alice".into()),
                Capability::ChannelMember,
            ),
            (crate::ChannelChange::Leave, Capability::ChannelMember),
            (
                crate::ChannelChange::Topic("New topic".into()),
                Capability::ChannelAdmin,
            ),
            (
                crate::ChannelChange::Transfer([7; 32]),
                Capability::ChannelAdmin,
            ),
            (crate::ChannelChange::Close, Capability::ChannelAdmin),
        ] {
            let request = Request::ChangeChannel {
                channel: "test".into(),
                change,
            };
            assert_eq!(request.minimum_version(), 17);
            assert_eq!(request.required_capability(), capability);
            let wire = postcard::to_allocvec(&request).unwrap();
            assert_eq!(wire[0], 38);
            assert_eq!(postcard::from_bytes::<Request>(&wire).unwrap(), request);
        }
        assert_eq!(
            postcard::to_allocvec(&Response::ChannelTopic("Topic".into())).unwrap()[0],
            15
        );
    }

    fn cleanup_frame() -> Frame {
        Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id: 93,
            request: Request::SubmitVolatileComponent {
                recipient: ContactCard(vec![7; 32]),
                destination: [9; 16],
                content_type: "application/vnd.ghost.file-volatile.v1+binary".into(),
                body: vec![0xa7; 4096],
            },
        })
    }

    fn assert_body_cleared(frame: &Frame) {
        let Frame::Request(RequestEnvelope {
            request:
                Request::SubmitVolatileComponent {
                    body, destination, ..
                },
            ..
        }) = frame
        else {
            panic!("request body expected")
        };
        assert_eq!(body.len(), 4096);
        assert!(body.iter().all(|byte| *byte == 0));
        assert_eq!(*destination, [9; 16]);
    }

    // Observe the production Frame::zeroize primitive before storage is freed.
    // The borrowed adapter allows inspection after RAII release without reading
    // freed memory or instrumenting payload bytes into logs.
    struct BorrowedFrame<'a>(&'a mut Frame);
    impl Zeroize for BorrowedFrame<'_> {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    #[test]
    fn payload_cleanup_codec_preserves_exact_wire_and_owned_body() {
        let mut frame = cleanup_frame();
        let expected = postcard::to_allocvec(&frame).unwrap();
        let guarded = encode_guarded(&frame).unwrap();
        assert_eq!(&*guarded, &expected);
        assert_eq!(decode(&guarded).unwrap(), frame);
        frame.zeroize();
        assert_body_cleared(&frame);
    }

    #[cfg(all(any(unix, windows), feature = "ipc"))]
    #[tokio::test]
    async fn payload_cleanup_on_partial_write_error_and_cancel() {
        // Failed write releases the same guard/primitive used by request().
        let mut frame = cleanup_frame();
        let (mut writer, reader) = tokio::io::duplex(8);
        drop(reader);
        {
            let owned = Zeroizing::new(BorrowedFrame(&mut frame));
            assert!(write_frame(&mut writer, owned.0).await.is_err());
        }
        assert_body_cleared(&frame);

        // Cancellation while the write is blocked after its prefix clears the
        // retained request body. Bytes already accepted by I/O are not retracted.
        let mut frame = cleanup_frame();
        let (mut writer, mut reader) = tokio::io::duplex(8);
        let mut pending = Box::pin(async {
            let owned = Zeroizing::new(BorrowedFrame(&mut frame));
            write_frame(&mut writer, owned.0).await
        });
        tokio::select! {
            result = &mut pending => panic!("write should block: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }
        drop(pending);
        assert_body_cleared(&frame);
        let mut prefix = [0; 8];
        reader.read_exact(&mut prefix).await.unwrap();
        assert_ne!(prefix, [0; 8]);
    }

    #[cfg(all(any(unix, windows), feature = "ipc"))]
    #[tokio::test]
    async fn payload_cleanup_read_errors_reject_partial_and_trailing_frames() {
        let frame = cleanup_frame();
        let wire = encode(&frame).unwrap();
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        writer
            .write_all(&(wire.len() as u32).to_be_bytes())
            .await
            .unwrap();
        writer.write_all(&wire[..100]).await.unwrap();
        drop(writer);
        assert!(read_frame(&mut reader).await.is_err());
    }

    #[test]
    fn older_fleet_v11_hello_is_rejected_before_negotiation() {
        // Independent postcard fixture for the Hello layout at COMS
        // 46aac82980adf259501ac49a53a5757ab4b88888: Frame::Hello,
        // min/max=11, empty application, one IdentityRead capability (ordinal 0).
        // That family has no component Option and is NOT shared-machine v11.
        let old_hello = [0, 11, 11, 0, 1, 0];
        assert!(matches!(decode(&old_hello), Err(SdkError::Protocol(_))));
    }

    #[test]
    fn shared_family_hello_layout_and_capability_ordinals_are_pinned() {
        // A current unscoped Hello adds the None tag and uses IdentityRead=1.
        // Literal fixtures prevent a simultaneous serializer/decoder reshuffle
        // from silently redefining the supported shared v10/v11 families.
        for version in [10, 11, 12] {
            let bytes = [0, 0, version, version, 0, 1, 1];
            let frame = Frame::Hello(Hello {
                component: None,
                min_version: u16::from(version),
                max_version: u16::from(version),
                application: String::new(),
                requested_capabilities: vec![Capability::IdentityRead],
            });
            assert_eq!(decode(&bytes).unwrap(), frame);
            assert_eq!(encode(&frame).unwrap(), bytes);
        }
    }

    #[test]
    fn frame_roundtrip_and_trailing_bytes_rejected() {
        let frame = Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id: 7,
            request: Request::SubmitOpaque {
                recipient: ContactCard(b"card".to_vec()),
                content_type: "application/vnd.ghost.report".into(),
                body: vec![1, 2, 3],
            },
        });
        let encoded = encode(&frame).unwrap();
        assert_eq!(decode(&encoded).unwrap(), frame);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn removal_request_roundtrips_canonical_member_id() {
        let frame = Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id: 8,
            request: Request::RemoveChannelMember {
                channel: "ops".into(),
                member_id: [0xa5; 32],
            },
        });
        assert_eq!(decode(&encode(&frame).unwrap()).unwrap(), frame);
    }

    #[test]
    fn requests_declare_required_capability() {
        assert_eq!(VERSION, 17);
        for request in [
            Request::SubmitDurableOpaque {
                recipient: ContactCard(Vec::new()),
                content_type: String::new(),
                body: Vec::new(),
            },
            Request::ApplicationInbox {
                after: 0,
                limit: 32,
            },
            Request::CommitApplication {
                sequence: 1,
                digest: [0; 32],
            },
        ] {
            assert_eq!(
                request.required_capability(),
                Capability::DurableApplication
            );
        }

        assert_eq!(
            Request::SignIdentityDigest { digest: [0; 32] }.required_capability(),
            Capability::IdentitySign
        );
        assert_eq!(
            Request::SignPrincipalBindingHash {
                claims_hash: [0; 32]
            }
            .required_capability(),
            Capability::IdentitySign
        );
        assert_eq!(
            Request::SubscribeEvents.required_capability(),
            Capability::EventRead
        );
        assert_eq!(
            Request::ListChannels.required_capability(),
            Capability::ChannelMember
        );
        assert_eq!(
            Request::SubmitOpaque {
                recipient: ContactCard(Vec::new()),
                content_type: String::new(),
                body: Vec::new(),
            }
            .required_capability(),
            Capability::OpaqueTransfer
        );
        assert_eq!(
            Request::SetDirectPresence {
                peer: ContactCard(Vec::new()),
                mode: PresenceMode::Invisible,
                lease_secs: 0,
                via: None,
            }
            .required_capability(),
            Capability::DirectMessage
        );
        assert_eq!(
            Request::SetChannelPresence {
                channel: "ops".into(),
                mode: PresenceMode::Away,
                lease_secs: 60,
            }
            .required_capability(),
            Capability::ChannelMember
        );
        assert_eq!(
            Request::SetDirectPresenceOptIn {
                peer: ContactCard(Vec::new()),
                enabled: true,
                via: None,
            }
            .required_capability(),
            Capability::DirectMessage
        );
        assert_eq!(
            Request::SetChannelPresenceOptIn {
                channel: "ops".into(),
                enabled: true,
            }
            .required_capability(),
            Capability::ChannelMember
        );
    }

    #[cfg(all(any(unix, windows), feature = "ipc"))]
    #[test]
    fn events_require_their_domain_capability_in_addition_to_event_read() {
        let identity = ClientEvent::IdentityUpdated {
            identity: Identity {
                contact_card: ContactCard(Vec::new()),
                safety_number: String::new(),
            },
            generation: 1,
        };
        let direct = ClientEvent::DirectMessage {
            peer_identity: Vec::new(),
            message_id: crate::MessageId([0; 16]),
            timestamp_unix: 0,
            body: b"ordinary chat".to_vec(),
            latency_hint_ms: 0,
        };
        let channel = ClientEvent::ChannelMessage {
            channel: "ops".into(),
            message_id: crate::MessageId([0; 16]),
            timestamp_unix: 0,
            sender: "member".into(),
            channel_epoch: 1,
            sender_index: 0,
            body: Vec::new(),
            latency_hint_ms: 0,
        };
        let opaque = ClientEvent::DirectMessage {
            peer_identity: Vec::new(),
            message_id: crate::MessageId([1; 16]),
            timestamp_unix: 0,
            body: ApplicationMessage {
                content_type: "application/vnd.ghost.report".into(),
                body: b"sealed".to_vec(),
            }
            .encode()
            .unwrap(),
            latency_hint_ms: 0,
        };

        assert!(!event_allowed(&identity, &[Capability::IdentityRead]));
        assert!(!event_allowed(&direct, &[Capability::DirectMessage]));
        assert!(!event_allowed(&channel, &[Capability::ChannelMember]));
        assert!(!event_allowed(&identity, &[Capability::EventRead]));
        assert!(!event_allowed(&direct, &[Capability::EventRead]));
        assert!(!event_allowed(&channel, &[Capability::EventRead]));
        assert!(event_allowed(
            &identity,
            &[Capability::EventRead, Capability::IdentityRead]
        ));
        assert!(event_allowed(
            &direct,
            &[Capability::EventRead, Capability::DirectMessage]
        ));
        assert!(event_allowed(
            &channel,
            &[Capability::EventRead, Capability::ChannelMember]
        ));
        assert!(!event_allowed(
            &direct,
            &[Capability::EventRead, Capability::OpaqueTransfer]
        ));
        assert!(event_allowed(
            &opaque,
            &[Capability::EventRead, Capability::OpaqueTransfer]
        ));
        assert!(event_allowed(
            &ClientEvent::EventsLagged { skipped: 1 },
            &[Capability::EventRead]
        ));
    }

    #[test]
    fn ipc_payload_boundary_is_enforced_before_encoding() {
        let request = |body| {
            Frame::Request(RequestEnvelope {
                version: VERSION,
                request_id: 1,
                request: Request::SendChannel {
                    channel: "bounded".into(),
                    body,
                },
            })
        };
        assert!(encode(&request(vec![0; gcoms_core::APPLICATION_PAYLOAD_LIMIT])).is_ok());
        assert!(encode(&request(vec![0; gcoms_core::APPLICATION_PAYLOAD_LIMIT + 1])).is_err());
    }
}

#[cfg(all(test, windows, feature = "embedded", feature = "ipc"))]
mod windows_pipe_tests {
    use super::*;
    use crate::{EmbeddedClient, GcClient, LocalEndpoint};
    use gcoms_node::node::{start, NodeConfig};
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::ClientOptions;

    async fn embedded() -> EmbeddedClient {
        EmbeddedClient::new(
            start(NodeConfig {
                seed: [0x77; 32],
                listen: "127.0.0.1:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: gcoms_node::node::NodeProfile::fixture(),
                alias_lifecycle: Default::default(),
            })
            .await
            .expect("start node"),
        )
    }

    fn endpoint(test: &str) -> LocalEndpoint {
        LocalEndpoint::new(
            std::env::temp_dir().join(format!("gc-sdk-windows-{}-{test}.pipe", std::process::id())),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn framing_security_reconnect_malformed_and_capability_denial() {
        let embedded = embedded().await;
        let endpoint = endpoint("resilience");
        let server_client = embedded.clone();
        let server_endpoint = endpoint.clone();
        let server = tokio::spawn(async move {
            serve_local(
                server_endpoint.path(),
                server_client,
                vec![Capability::IdentityRead],
            )
            .await
        });

        let name = crate::local::pipe_name(endpoint.path());
        let mut malformed = for_attempts(500, || ClientOptions::new().open(&name)).await;
        malformed
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        drop(malformed);

        for _ in 0..2 {
            let client = IpcClient::connect(
                endpoint.path(),
                "windows-test",
                vec![Capability::IdentityRead, Capability::DirectMessage],
            )
            .await
            .expect("connect after malformed or disconnected client");
            assert_eq!(client.identity(), embedded.identity());
            assert_eq!(
                client
                    .send_direct(&embedded.identity().contact_card, b"denied", None)
                    .await
                    .unwrap_err(),
                SdkError::PermissionDenied
            );
            drop(client);
        }

        server.abort();
        embedded.node().shutdown().await;
    }

    async fn for_attempts<T>(attempts: usize, mut open: impl FnMut() -> std::io::Result<T>) -> T {
        for attempt in 0..attempts {
            match open() {
                Ok(pipe) => return pipe,
                Err(error)
                    if attempt + 1 < attempts
                        && matches!(error.raw_os_error(), Some(2) | Some(231)) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => panic!("open malformed client: {error}"),
            }
        }
        unreachable!("attempt loop is non-empty")
    }
}

#[cfg(all(test, any(unix, windows), feature = "ipc"))]
mod interrupted_read_tests {
    use super::*;

    #[tokio::test]
    async fn inbound_event_does_not_discard_a_partial_request_prefix() {
        let (mut peer, server) = tokio::io::duplex(1);
        let (mut reader, mut writer) = tokio::io::split(server);
        let (events, mut incoming_events) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            read_request_with_events(
                &mut reader,
                &mut writer,
                &mut incoming_events,
                &[Capability::EventRead],
                true,
                &mut 1,
                None,
                VERSION,
                &mut crate::bootstrap::Session::default(),
            )
            .await
        });
        let payload = encode(&Frame::Request(RequestEnvelope {
            version: VERSION,
            request_id: 42,
            request: Request::Identity,
        }))
        .unwrap();
        let length = (payload.len() as u32).to_be_bytes();
        // The capacity-one pipe forces the server to consume part of the
        // prefix before the event arrives; no timing assumptions or sleeps.
        peer.write_all(&length[..3]).await.unwrap();
        events
            .send(ClientEvent::EventsLagged { skipped: 1 })
            .await
            .unwrap();
        assert!(matches!(
            read_frame(&mut peer).await.unwrap(),
            Frame::Event(_)
        ));
        peer.write_all(&length[3..]).await.unwrap();
        peer.write_all(&payload).await.unwrap();
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            frame,
            Frame::Request(RequestEnvelope { request_id: 42, .. })
        ));
    }
}

#[cfg(all(test, unix, feature = "ipc"))]
mod disconnect_tests {
    use super::*;

    #[tokio::test]
    async fn daemon_disconnect_closes_subscriptions_and_rejects_new_requests() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let path = std::env::temp_dir().join(format!("gc-close-{}.sock", std::process::id()));
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let (stop, stopped) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                assert!(matches!(
                    read_frame(&mut socket).await.unwrap(),
                    Frame::Hello(_)
                ));
                write_frame(
                    &mut socket,
                    &Frame::Welcome(Welcome {
                        version: VERSION,
                        granted_capabilities: vec![Capability::IdentityRead, Capability::EventRead],
                        event_stream_id: [1; 16],
                    }),
                )
                .await
                .unwrap();
                let Frame::Request(request) = read_frame(&mut socket).await.unwrap() else {
                    panic!("expected request")
                };
                write_frame(
                    &mut socket,
                    &Frame::Response(ResponseEnvelope {
                        version: VERSION,
                        request_id: request.request_id,
                        result: Ok(Response::Identity(Identity {
                            contact_card: ContactCard(vec![]),
                            safety_number: "fixture".into(),
                        })),
                    }),
                )
                .await
                .unwrap();
                stopped.await.unwrap();
            });
            let client = IpcClient::connect(
                &path,
                "disconnect-test",
                vec![Capability::IdentityRead, Capability::EventRead],
            )
            .await
            .unwrap();
            let mut events = client.subscribe_events();
            let mut envelopes = client.subscribe_event_envelopes();
            stop.send(()).unwrap();
            server.await.unwrap();
            assert!(events.recv().await.is_none());
            assert!(envelopes.recv().await.is_none());
            assert_eq!(
                client.refresh_identity().await.unwrap_err(),
                SdkError::ConnectionClosed
            );
            let mut late = client.subscribe_events();
            assert!(late.recv().await.is_none());
            drop(client);
            std::fs::remove_file(path).unwrap();
        })
        .await
        .expect("disconnect must not hang subscribers or requests");
    }
}

#[cfg(all(test, any(unix, windows), feature = "ipc", feature = "embedded"))]
mod compatible_machine_clients {
    use super::*;
    #[tokio::test]
    async fn old_chat_versions_keep_identity_and_refuse_catalog_extension() {
        let node = gcoms_node::node::start(gcoms_node::node::NodeConfig {
            seed: [92; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::Production,
            alias_lifecycle: Default::default(),
        })
        .await
        .unwrap();
        for version in [10, 11, 12, 13, 14, 15] {
            let (mut peer, stream) = tokio::io::duplex(65536);
            let server = tokio::spawn(serve_connection(
                stream,
                crate::EmbeddedClient::new(node.clone()),
                vec![Capability::IdentityRead, Capability::CatalogAccess],
                None,
            ));
            write_frame(
                &mut peer,
                &Frame::Hello(Hello {
                    min_version: version,
                    max_version: version,
                    application: "chat-compatibility".into(),
                    requested_capabilities: if version >= 15 {
                        vec![Capability::IdentityRead, Capability::CatalogAccess]
                    } else {
                        vec![Capability::IdentityRead]
                    },
                    component: None,
                }),
            )
            .await
            .unwrap();
            let Frame::Welcome(welcome) = read_frame(&mut peer).await.unwrap() else {
                panic!("welcome")
            };
            assert_eq!(welcome.version, version);
            assert_eq!(
                welcome
                    .granted_capabilities
                    .contains(&Capability::CatalogAccess),
                version >= 15
            );
            for (id, request) in [
                (1, Request::Identity),
                (
                    2,
                    Request::ConfigureCatalogOrigins {
                        origins: vec!["catalog.example".into()],
                    },
                ),
            ] {
                write_frame(
                    &mut peer,
                    &Frame::Request(RequestEnvelope {
                        version,
                        request_id: id,
                        request,
                    }),
                )
                .await
                .unwrap();
                let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
                    panic!("response")
                };
                assert_eq!(response.version, version);
                if id == 1 {
                    assert!(matches!(response.result, Ok(Response::Identity(_))));
                } else if version < 15 {
                    assert_eq!(response.result, Err(SdkError::PermissionDenied));
                } else {
                    assert_eq!(response.result, Ok(Response::Empty));
                }
            }
            server.abort();
            let _ = server.await;
        }
        node.shutdown().await;
    }

    #[tokio::test]
    async fn version_ten_machine_client_keeps_identity_access_without_shell() {
        use crate::machine::{ComponentCredentials, ComponentRegistration, MachineRegistry};
        let node = gcoms_node::node::start(gcoms_node::node::NodeConfig {
            seed: [78; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        })
        .await
        .unwrap();
        let client = crate::EmbeddedClient::new(node.clone());
        let credentials = ComponentCredentials {
            component_id: [1; 16],
            token: [2; 32],
        };
        let registry = MachineRegistry {
            version: 1,
            components: vec![ComponentRegistration {
                credentials: credentials.clone(),
                capabilities: vec![Capability::IdentityRead, Capability::HostShell],
                peers: vec![],
                files: None,
            }],
        };
        let (mut peer, stream) = tokio::io::duplex(65536);
        let server = tokio::spawn(serve_connection(
            stream,
            client,
            vec![],
            Some(Arc::new(registry)),
        ));
        write_frame(
            &mut peer,
            &Frame::Hello(Hello {
                min_version: 10,
                max_version: 10,
                application: "previous-machine-client".into(),
                requested_capabilities: vec![Capability::IdentityRead, Capability::HostShell],
                component: Some(credentials),
            }),
        )
        .await
        .unwrap();
        let Frame::Welcome(welcome) = read_frame(&mut peer).await.unwrap() else {
            panic!("welcome expected")
        };
        assert_eq!(welcome.version, 10);
        assert_eq!(welcome.granted_capabilities, vec![Capability::IdentityRead]);
        write_frame(
            &mut peer,
            &Frame::Request(RequestEnvelope {
                version: 10,
                request_id: 1,
                request: Request::Identity,
            }),
        )
        .await
        .unwrap();
        let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
            panic!("response expected")
        };
        assert_eq!(response.version, 10);
        assert!(matches!(response.result, Ok(Response::Identity(_))));
        server.abort();
        node.shutdown().await;
    }
    #[tokio::test]
    async fn previous_versions_deny_new_volatile_and_bootstrap_capabilities_and_requests() {
        use crate::machine::{ComponentCredentials, ComponentRegistration, MachineRegistry};
        for (version, capability) in [
            (11, Capability::VolatileApplication),
            (12, Capability::BootstrapApplication),
        ] {
            let node = gcoms_node::node::start(gcoms_node::node::NodeConfig {
                seed: [78; 32],
                listen: "127.0.0.1:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: gcoms_node::node::NodeProfile::fixture(),
                alias_lifecycle: Default::default(),
            })
            .await
            .unwrap();
            let client = crate::EmbeddedClient::new(node.clone());
            let credentials = ComponentCredentials {
                component_id: [1; 16],
                token: [2; 32],
            };
            let registry = MachineRegistry {
                version: 1,
                components: vec![ComponentRegistration {
                    credentials: credentials.clone(),
                    capabilities: vec![Capability::IdentityRead, capability],
                    peers: vec![],
                    files: None,
                }],
            };
            let (mut peer, stream) = tokio::io::duplex(65536);
            let server = tokio::spawn(serve_connection(
                stream,
                client,
                vec![],
                Some(Arc::new(registry)),
            ));
            write_frame(
                &mut peer,
                &Frame::Hello(Hello {
                    min_version: version,
                    max_version: version,
                    application: "previous-machine-client".into(),
                    requested_capabilities: vec![Capability::IdentityRead, capability],
                    component: Some(credentials),
                }),
            )
            .await
            .unwrap();
            if capability == Capability::BootstrapApplication {
                assert!(server.await.unwrap().is_err());
                assert!(read_frame(&mut peer).await.is_err());
                node.shutdown().await;
                continue;
            }
            let Frame::Welcome(welcome) = read_frame(&mut peer).await.unwrap() else {
                panic!("welcome expected")
            };
            assert_eq!(welcome.version, version);
            assert_eq!(welcome.granted_capabilities, vec![Capability::IdentityRead]);
            write_frame(
                &mut peer,
                &Frame::Request(RequestEnvelope {
                    version,
                    request_id: 1,
                    request: Request::Identity,
                }),
            )
            .await
            .unwrap();
            let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
                panic!("response expected")
            };
            assert_eq!(response.version, version);
            assert!(matches!(response.result, Ok(Response::Identity(_))));
            write_frame(
                &mut peer,
                &Frame::Request(RequestEnvelope {
                    version,
                    request_id: 2,
                    request: if version == 12 {
                        Request::AdmitBootstrapPeer {
                            peer_identity: vec![3; 1952],
                            source: [3; 16],
                            expires_at_unix: u64::MAX,
                        }
                    } else {
                        Request::SubmitVolatileComponent {
                            recipient: ContactCard(vec![]),
                            destination: [3; 16],
                            content_type: gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE.into(),
                            body: vec![],
                        }
                    },
                }),
            )
            .await
            .unwrap();
            let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
                panic!("response expected")
            };
            assert_eq!(response.result, Err(SdkError::PermissionDenied));
            server.abort();
            node.shutdown().await;
        }
    }
}

#[cfg(all(test, unix, feature = "ipc", feature = "embedded"))]
mod owned_listener_tests {
    use super::*;
    use crate::{EmbeddedClient, GcClient};
    use gcoms_node::node::{start, NodeConfig, NodeProfile};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn central_listener_stop_drains_authenticated_and_partial_connections() {
        let temp = tempfile::tempdir().unwrap();
        let embedded = EmbeddedClient::new(
            start(NodeConfig {
                seed: [0x69; 32],
                listen: "127.0.0.1:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: NodeProfile::fixture(),
                alias_lifecycle: Default::default(),
            })
            .await
            .unwrap(),
        );
        let credentials = crate::machine::ComponentCredentials {
            component_id: [7; 16],
            token: [8; 32],
        };
        let registry = crate::machine::MachineRegistry {
            version: 1,
            components: vec![crate::machine::ComponentRegistration {
                credentials: credentials.clone(),
                capabilities: vec![Capability::IdentityRead],
                peers: Vec::new(),
                files: None,
            }],
        };
        let path = temp.path().join("scoped.sock");
        let listener = LocalListener::bind(&crate::LocalEndpoint::new(&path)).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let hosted = embedded.clone();
        let task = tokio::spawn(async move {
            serve_machine_on_listener_until(listener, hosted, registry, async {
                let _ = stopped.await;
            })
            .await
        });
        assert!(
            IpcClient::connect(&path, "unscoped-refused", vec![Capability::IdentityRead])
                .await
                .is_err()
        );
        let mut wrong = credentials.clone();
        wrong.token[0] ^= 1;
        assert!(IpcClient::connect_component(
            &path,
            "wrong-refused",
            vec![Capability::IdentityRead],
            wrong
        )
        .await
        .is_err());
        let client = IpcClient::connect_component(
            &path,
            "owned",
            vec![Capability::IdentityRead],
            credentials,
        )
        .await
        .unwrap();
        assert_eq!(
            client.refresh_identity().await.unwrap(),
            embedded.identity()
        );
        let mut partial = tokio::net::UnixStream::connect(&path).await.unwrap();
        partial.write_all(&[0, 0]).await.unwrap();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.refresh_identity())
                .await
                .unwrap()
                .is_err()
        );
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(2), partial.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
        drop(client);
        drop(partial);
        embedded.node().shutdown().await;
        crate::LocalEndpoint::new(&path).cleanup().unwrap();
    }
}

#[cfg(all(test, feature = "ipc", feature = "embedded", any(unix, windows)))]
mod route_recovery_compatibility_tests {
    use super::*;
    fn recovery() -> Request {
        Request::RecoverChannelRoute {
            channel: "channel".into(),
            expected_channel_id: ChannelId([1; 32]),
            expected_epoch: 1,
            retained_welcome: Blob(vec![2]),
            peer: ContactCard(vec![3]),
        }
    }
    #[test]
    fn route_recovery_appends_codec_without_changing_existing_v13_requests() {
        let old = vec![13, 7, 1, b'x', 1, 2, 1, 2];
        let request = Request::JoinChannel {
            request: JoinRequest(7),
            channel: "x".into(),
            visibility: ChannelVisibility::Private,
            welcome: Blob(vec![1, 2]),
        };
        assert_eq!(postcard::to_allocvec(&request).unwrap(), old);
        assert_eq!(postcard::from_bytes::<Request>(&old).unwrap(), request);
        for (tag, request) in [
            (
                14,
                Request::SendChannel {
                    channel: "x".into(),
                    body: vec![42],
                },
            ),
            (20, Request::ListChannels),
            (
                30,
                Request::SendDirectTracked {
                    peer: ContactCard(vec![]),
                    body: vec![],
                    via: None,
                },
            ),
            (
                31,
                Request::SendChannelTracked {
                    channel: "x".into(),
                    body: vec![],
                },
            ),
            (32, recovery()),
            (33, Request::ConfigureCatalogOrigins { origins: vec![] }),
            (
                34,
                Request::CatalogHttp(crate::CatalogHttpRequest {
                    method: "GET".into(),
                    url: "https://catalog.example/v1/channels".into(),
                    body: vec![],
                }),
            ),
        ] {
            let encoded = postcard::to_allocvec(&request).unwrap();
            assert_eq!(encoded[0], tag);
            assert_eq!(postcard::from_bytes::<Request>(&encoded).unwrap(), request);
            if tag >= 33 {
                assert_eq!(request.minimum_version(), 15);
                assert_eq!(request.required_capability(), Capability::CatalogAccess);
            }
        }
        assert_eq!(recovery().minimum_version(), 14);
        assert_eq!(recovery().required_capability(), Capability::ChannelAdmin);
    }

    #[test]
    fn retained_tracked_and_recovery_bytes_keep_the_deployed_schema() {
        let direct = vec![30, 0, 0, 0];
        let channel = vec![31, 1, b'x', 0];
        let mut carrier = vec![32, 7];
        carrier.extend_from_slice(b"channel");
        carrier.extend_from_slice(&[1; 32]);
        carrier.extend_from_slice(&[1, 1, 2, 1, 3]);
        for (bytes, request, version) in [
            (
                direct,
                Request::SendDirectTracked {
                    peer: ContactCard(vec![]),
                    body: vec![],
                    via: None,
                },
                13,
            ),
            (
                channel,
                Request::SendChannelTracked {
                    channel: "x".into(),
                    body: vec![],
                },
                13,
            ),
            (carrier, recovery(), 14),
        ] {
            assert_eq!(postcard::from_bytes::<Request>(&bytes).unwrap(), request);
            assert_eq!(postcard::to_allocvec(&request).unwrap(), bytes);
            assert_eq!(request.minimum_version(), version);
        }
        let mut response = vec![10];
        response.extend_from_slice(&[9; 16]);
        assert_eq!(
            postcard::from_bytes::<Response>(&response).unwrap(),
            Response::MessageId(crate::MessageId([9; 16]))
        );
        assert_eq!(
            postcard::to_allocvec(&Response::MessageId(crate::MessageId([9; 16]))).unwrap(),
            response
        );
    }
    #[tokio::test]
    async fn route_recovery_preserves_v13_identity_and_requires_v14_owner_capability() {
        for (version, cap) in [
            (13, Capability::ChannelAdmin),
            (14, Capability::ChannelMember),
        ] {
            let node = gcoms_node::node::start(gcoms_node::node::NodeConfig {
                seed: [77; 32],
                listen: "127.0.0.1:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: gcoms_node::node::NodeProfile::fixture(),
                alias_lifecycle: Default::default(),
            })
            .await
            .unwrap();
            let client = crate::EmbeddedClient::new(node.clone());
            let (mut peer, stream) = tokio::io::duplex(65536);
            let server = tokio::spawn(serve_connection(
                stream,
                client,
                vec![Capability::IdentityRead, cap],
                None,
            ));
            write_frame(
                &mut peer,
                &Frame::Hello(Hello {
                    min_version: version,
                    max_version: version,
                    application: "retained-v13-client".into(),
                    requested_capabilities: vec![Capability::IdentityRead, cap],
                    component: None,
                }),
            )
            .await
            .unwrap();
            let Frame::Welcome(welcome) = read_frame(&mut peer).await.unwrap() else {
                panic!("welcome")
            };
            assert_eq!(welcome.version, version);
            write_frame(
                &mut peer,
                &Frame::Request(RequestEnvelope {
                    version,
                    request_id: 1,
                    request: Request::Identity,
                }),
            )
            .await
            .unwrap();
            let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
                panic!("identity")
            };
            assert_eq!(response.version, version);
            assert!(matches!(response.result, Ok(Response::Identity(_))));
            write_frame(
                &mut peer,
                &Frame::Request(RequestEnvelope {
                    version,
                    request_id: 2,
                    request: recovery(),
                }),
            )
            .await
            .unwrap();
            let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
                panic!("recovery")
            };
            assert_eq!(response.result, Err(SdkError::PermissionDenied));
            drop(peer);
            server.abort();
            let _ = server.await;
            node.shutdown().await;
        }
    }
}

#[cfg(all(test, any(unix, windows), feature = "ipc", feature = "embedded"))]
#[path = "ipc/bootstrap_compat_tests.rs"]
mod bootstrap_compat_tests;
