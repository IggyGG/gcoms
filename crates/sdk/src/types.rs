use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

const APPLICATION_MAGIC: &[u8; 6] = b"GCAPP1";

/// Maximum body size for an application message with this content type.
/// The returned limit includes the exact GCAPP1 framing overhead.
pub fn application_body_limit(content_type: &str) -> Result<usize, SdkError> {
    validate_content_type(content_type)?;
    gcoms_core::APPLICATION_PAYLOAD_LIMIT
        .checked_sub(8 + content_type.len())
        .ok_or_else(|| SdkError::Protocol("application content type exceeds payload limit".into()))
}

pub(crate) fn validate_application_payload(body: &[u8]) -> Result<(), SdkError> {
    if body.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT {
        return Err(SdkError::Protocol(format!(
            "application payload exceeds {} byte limit",
            gcoms_core::APPLICATION_PAYLOAD_LIMIT
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationMessage {
    pub content_type: String,
    pub body: Vec<u8>,
}

impl zeroize::Zeroize for ApplicationMessage {
    fn zeroize(&mut self) {
        self.body.as_mut_slice().zeroize();
    }
}

impl ApplicationMessage {
    fn encoded_len(&self) -> Result<usize, SdkError> {
        let body_limit = application_body_limit(&self.content_type)?;
        if self.body.len() > body_limit {
            return Err(SdkError::Protocol(format!(
                "application body exceeds {body_limit} byte limit for content type"
            )));
        }
        let encoded_len = 8usize
            .checked_add(self.content_type.len())
            .and_then(|length| length.checked_add(self.body.len()))
            .ok_or_else(|| SdkError::Protocol("application message length overflow".into()))?;
        if encoded_len > gcoms_core::APPLICATION_PAYLOAD_LIMIT {
            return Err(SdkError::Protocol(format!(
                "application payload exceeds {} byte limit",
                gcoms_core::APPLICATION_PAYLOAD_LIMIT
            )));
        }
        Ok(encoded_len)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SdkError> {
        let mut encoded = Vec::with_capacity(self.encoded_len()?);
        encoded.extend_from_slice(APPLICATION_MAGIC);
        encoded.extend_from_slice(&(self.content_type.len() as u16).to_be_bytes());
        encoded.extend_from_slice(self.content_type.as_bytes());
        encoded.extend_from_slice(&self.body);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SdkError> {
        if encoded.len() < 8 || &encoded[..6] != APPLICATION_MAGIC {
            return Err(SdkError::Protocol("not a GC application message".into()));
        }
        let content_type_len = u16::from_be_bytes([encoded[6], encoded[7]]) as usize;
        let body_offset = 8usize
            .checked_add(content_type_len)
            .ok_or_else(|| SdkError::Protocol("application message length overflow".into()))?;
        let content_type = std::str::from_utf8(
            encoded
                .get(8..body_offset)
                .ok_or_else(|| SdkError::Protocol("truncated application message".into()))?,
        )
        .map_err(|_| SdkError::Protocol("application content type is not UTF-8".into()))?
        .to_string();
        let value = Self {
            content_type,
            body: encoded
                .get(body_offset..)
                .ok_or_else(|| SdkError::Protocol("truncated application message".into()))?
                .to_vec(),
        };
        let mut value = zeroize::Zeroizing::new(value);
        value.encoded_len()?;
        Ok(Self {
            content_type: std::mem::take(&mut value.content_type),
            body: std::mem::take(&mut value.body),
        })
    }
}

fn validate_content_type(content_type: &str) -> Result<(), SdkError> {
    if content_type.is_empty()
        || content_type.len() > u16::MAX as usize
        || !content_type.is_ascii()
        || content_type.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(SdkError::Protocol(
            "invalid application content type".into(),
        ));
    }
    Ok(())
}

/// A delivery retained by the daemon until its exact receipt is committed.
/// `sequence` is persistent within this daemon identity; normal event-envelope
/// sequence numbers remain connection-local and must not be used as cursors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDelivery {
    pub source_component: Option<gcoms_core::component::ComponentId>,
    pub destination_component: Option<gcoms_core::component::ComponentId>,
    pub sequence: u64,
    pub peer_identity: Vec<u8>,
    pub message_id: [u8; 16],
    pub received_at_unix: u64,
    pub body: Vec<u8>,
    pub receipt_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChannelId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelVisibility {
    Public,
    Private,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMemberSummary {
    pub member_id: [u8; 32],
    pub display_name: String,
    pub is_self: bool,
    pub join_order: u32,
    pub joined_at_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityBucket {
    None,
    Today,
    ThisWeek,
    Older,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomaticJoinEndpoint {
    pub catalog: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicChannelDescriptor {
    pub version: u16,
    pub expires_at_unix: u64,
    pub channel_id: ChannelId,
    pub owner_public_key: Vec<u8>,
    pub capacity: u32,
    pub title: String,
    pub description: String,
    pub activity: ActivityBucket,
    pub automatic_join: AutomaticJoinEndpoint,
    pub signature: Vec<u8>,
}

impl PublicChannelDescriptor {
    pub fn signing_payload(&self) -> Option<Vec<u8>> {
        let fields = [
            self.owner_public_key.as_slice(),
            self.title.as_bytes(),
            self.description.as_bytes(),
            self.automatic_join.catalog.as_bytes(),
            self.automatic_join.endpoint.as_bytes(),
        ];
        if fields.iter().any(|field| field.len() > u16::MAX as usize) {
            return None;
        }
        let mut payload = b"GC1/PUBLIC-CHANNEL-DESCRIPTOR\0".to_vec();
        payload.extend_from_slice(&self.version.to_be_bytes());
        payload.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        payload.extend_from_slice(&self.channel_id.0);
        payload.extend_from_slice(&self.capacity.to_be_bytes());
        payload.push(match self.activity {
            ActivityBucket::None => 0,
            ActivityBucket::Today => 1,
            ActivityBucket::ThisWeek => 2,
            ActivityBucket::Older => 3,
        });
        for field in fields {
            payload.extend_from_slice(&(field.len() as u16).to_be_bytes());
            payload.extend_from_slice(field);
        }
        Some(payload)
    }

    #[cfg(any(feature = "in-process", feature = "descriptor-verification"))]
    pub fn verify_at(&self, now_unix: u64) -> bool {
        self.version == 1
            && self.expires_at_unix > now_unix
            && self.capacity >= 2
            && !self.title.is_empty()
            && !self.automatic_join.catalog.is_empty()
            && !self.automatic_join.endpoint.is_empty()
            && self.signing_payload().is_some_and(|payload| {
                gcoms_crypto::verify_signature(&self.owner_public_key, &payload, &self.signature)
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRequest {
    pub cursor: Option<String>,
    pub limit: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogResponse {
    pub descriptors: Vec<PublicChannelDescriptor>,
    pub next_cursor: Option<String>,
}

#[cfg(any(feature = "in-process", feature = "descriptor-verification"))]
#[derive(Default)]
pub struct InMemoryCatalog {
    descriptors: std::sync::RwLock<Vec<PublicChannelDescriptor>>,
}

#[cfg(any(feature = "in-process", feature = "descriptor-verification"))]
impl InMemoryCatalog {
    pub fn publish(
        &self,
        descriptor: PublicChannelDescriptor,
        now_unix: u64,
    ) -> Result<(), SdkError> {
        if !descriptor.verify_at(now_unix) {
            return Err(SdkError::Protocol(
                "invalid public channel descriptor".into(),
            ));
        }
        let mut descriptors = self.descriptors.write().unwrap_or_else(|p| p.into_inner());
        descriptors.retain(|known| known.channel_id != descriptor.channel_id);
        descriptors.push(descriptor);
        Ok(())
    }

    pub fn query(&self, request: &CatalogRequest, now_unix: u64) -> CatalogResponse {
        let offset = request
            .cursor
            .as_deref()
            .and_then(|cursor| cursor.parse::<usize>().ok())
            .unwrap_or(0);
        let descriptors = self.descriptors.read().unwrap_or_else(|p| p.into_inner());
        let valid = descriptors
            .iter()
            .filter(|descriptor| descriptor.verify_at(now_unix))
            .skip(offset)
            .take(usize::from(request.limit.clamp(1, 100)))
            .cloned()
            .collect::<Vec<_>>();
        let next = offset + valid.len();
        CatalogResponse {
            descriptors: valid,
            next_cursor: (next < descriptors.len()).then(|| next.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub contact_card: ContactCard,
    pub safety_number: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinedChannel {
    pub id: ChannelId,
    pub channel: String,
    pub visibility: ChannelVisibility,
    pub status: ChannelStatus,
    pub role: ChannelRole,
    pub epoch: u64,
}

/// Presentation changes keep stable MLS identities and routing names intact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelChange {
    Topic(String),
    Nickname(String),
    Transfer([u8; 32]),
    Leave,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    Active,
    MembershipPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRole {
    Owner,
    Member,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceMode {
    RecentlyReachable,
    Away,
    Invisible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reachability {
    RecentlyReachable,
    Away,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientEvent {
    IdentityUpdated {
        identity: Identity,
        generation: u64,
    },
    SessionOpened {
        peer_identity: Vec<u8>,
        safety_number: String,
    },
    DirectMessage {
        peer_identity: Vec<u8>,
        message_id: MessageId,
        timestamp_unix: u64,
        body: Vec<u8>,
        latency_hint_ms: u64,
    },
    /// Authenticated ACK for a pending direct application or presence record.
    /// Presence ACKs prove peer contact, never application execution.
    DirectDelivered {
        peer_identity: Vec<u8>,
        message_id: MessageId,
    },
    PresenceChanged {
        peer_identity: Vec<u8>,
        reachability: Reachability,
    },
    ChannelPresenceChanged {
        channel: String,
        member_id: [u8; 32],
        reachability: Reachability,
    },
    ChannelMessage {
        channel: String,
        message_id: MessageId,
        timestamp_unix: u64,
        sender: String,
        channel_epoch: u64,
        sender_index: u32,
        body: Vec<u8>,
        latency_hint_ms: u64,
    },
    ChannelDelivered {
        channel: String,
        message_id: MessageId,
    },
    ChannelRemoved {
        channel: String,
    },
    ChannelRosterChanged {
        channel: String,
        channel_id: ChannelId,
    },
    ChannelDirectMessage {
        channel: String,
        sender_member_id: [u8; 32],
        recipient_member_id: [u8; 32],
        message_id: MessageId,
        timestamp_unix: u64,
        body: Vec<u8>,
    },
    ChannelDirectDelivered {
        channel: String,
        recipient_member_id: [u8; 32],
        message_id: MessageId,
    },
    EventsLagged {
        skipped: u64,
    },
    /// RAM-only scoped traffic; never retain in chat or application archives.
    VolatileApplication {
        peer_identity: Vec<u8>,
        message_id: MessageId,
        timestamp_unix: u64,
        source_component: Option<[u8; 16]>,
        destination_component: Option<[u8; 16]>,
        body: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdkError {
    InvalidContactCard,
    Runtime(String),
    ConnectionClosed,
    Protocol(String),
    PermissionDenied,
    /// Submission may have been durably accepted. Never automatically resend
    /// the plaintext under a new message ID after this error.
    SendUncertain(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContactCard => f.write_str("invalid contact card"),
            Self::Runtime(error) => write!(f, "runtime: {error}"),
            Self::ConnectionClosed => f.write_str("connection closed"),
            Self::Protocol(error) => write!(f, "protocol: {error}"),
            Self::PermissionDenied => f.write_str("permission denied"),
            Self::SendUncertain(error) => write!(f, "send outcome uncertain: {error}"),
        }
    }
}

impl std::error::Error for SdkError {}

/// Private provisioning material supplied by an application host, never a public peer card.
#[derive(Clone, Serialize, Deserialize)]
pub struct RelayCard(pub Vec<u8>);
impl Drop for RelayCard {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
impl std::fmt::Debug for RelayCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayCard([redacted])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkNameStatus {
    pub published: bool,
    pub opted_in: bool,
    pub pending: bool,
    pub removed: bool,
    pub name: Option<String>,
    pub lease_expires_at: Option<u64>,
}

/// Public runtime facts; relay admission is independent of message readiness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub connection: ConnectionState,
    pub relay: RelayState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    NeedsInvitation,
    Connecting,
    Online,
    Recovering,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayState {
    Disabled,
    Attempting,
    Published,
    Unreachable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInvitation {
    pub link: String,
    pub channel: String,
    pub expires_at: u64,
    pub local_only: bool,
}

#[async_trait]
pub trait GcClient: Send + Sync {
    async fn network_status(&self) -> Result<crate::NetworkStatus, SdkError> {
        Err(SdkError::Protocol(
            "host does not support network status".into(),
        ))
    }
    async fn sharing(
        &self,
        request: crate::sharing::Request,
    ) -> Result<crate::sharing::Reply, SdkError> {
        request.validate()?;
        Err(SdkError::Protocol(
            "host was built without file sharing".into(),
        ))
    }

    async fn persist_profile(&self) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn recover_network(&self, _urls: Vec<String>) -> Result<String, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn configure_network_dns(&self, _enabled: bool) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn network_dns_status(&self) -> Result<NetworkNameStatus, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn resolve_contact_identity(&self, card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        self.contact_identity(card)
    }
    async fn runtime_status(&self) -> Result<RuntimeStatus, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn import_network_invitation(&self, _invitation: &str) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn create_channel_invitation(
        &self,
        _channel: &str,
        _ttl_secs: u64,
    ) -> Result<ChannelInvitation, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn inspect_channel_invitation(&self, _link: &str) -> Result<ChannelInvitation, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn join_channel_invitation(
        &self,
        _link: &str,
        _display: &str,
        _timeout_secs: u64,
    ) -> Result<String, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn configure_catalog_origins(&self, _origins: Vec<String>) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn catalog_request(
        &self,
        _request: crate::CatalogHttpRequest,
    ) -> Result<crate::CatalogHttpResponse, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn component_shell(
        &self,
        _component: [u8; 16],
        _request: crate::shell::ShellRequest,
    ) -> Result<crate::shell::ShellReply, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn file_route(&self) -> Result<Vec<u8>, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn component_files(
        &self,
        _component: [u8; 16],
        _request: crate::files::FileRequest,
    ) -> Result<crate::files::FileReply, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    fn contact_identity(&self, _card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        Err(SdkError::InvalidContactCard)
    }
    fn identity(&self) -> Identity;

    async fn refresh_identity(&self) -> Result<Identity, SdkError> {
        Ok(self.identity())
    }

    async fn sign_identity_digest(&self, _digest: [u8; 32]) -> Result<Vec<u8>, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn sign_principal_binding_hash(
        &self,
        _claims_hash: [u8; 32],
    ) -> Result<Vec<u8>, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    fn subscribe_events(&self) -> mpsc::Receiver<ClientEvent>;

    async fn list_channels(&self) -> Result<Vec<JoinedChannel>, SdkError>;

    async fn channel_roster(&self, channel: &str) -> Result<Vec<ChannelMemberSummary>, SdkError>;

    async fn channel_topic(&self, _channel: &str) -> Result<String, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn change_channel(
        &self,
        _channel: &str,
        _change: ChannelChange,
    ) -> Result<MessageId, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn public_channel_descriptor(
        &self,
        channel: &str,
        description: &str,
        activity: ActivityBucket,
        automatic_join: AutomaticJoinEndpoint,
        expires_at_unix: u64,
    ) -> Result<PublicChannelDescriptor, SdkError>;

    async fn send_direct(
        &self,
        peer: &ContactCard,
        body: &[u8],
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError>;

    /// Returns the exact ID used by DirectDelivered after persistent local
    /// acceptance. Subscribe before calling and match both peer and message ID.
    /// A disconnected response/event stream is uncertain, never a retry signal.
    async fn send_direct_tracked(
        &self,
        _peer: &ContactCard,
        _body: &[u8],
        _via: Option<&ContactCard>,
    ) -> Result<MessageId, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn set_direct_presence(
        &self,
        peer: &ContactCard,
        mode: PresenceMode,
        lease_secs: u32,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError>;

    async fn set_direct_presence_opt_in(
        &self,
        peer: &ContactCard,
        enabled: bool,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError>;

    async fn submit_opaque(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let application = ApplicationMessage {
            content_type: content_type.into(),
            body: body.to_vec(),
        }
        .encode()?;
        self.send_direct(recipient, &application, None).await
    }

    /// Requires persistent sender and receiver state. Durable messages are
    /// consumed through application_inbox, never through volatile events.
    async fn submit_volatile_opaque(
        &self,
        _recipient: &ContactCard,
        _content_type: &str,
        _body: &[u8],
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn submit_durable_opaque(
        &self,
        _recipient: &ContactCard,
        _content_type: &str,
        _body: &[u8],
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }

    /// Durable opaque application send with an explicit scheduling class.
    /// Deferred copies re-derive the class from the record, so the hint only
    /// affects the immediate reservation. The default ignores it.
    async fn submit_durable_opaque_class(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
        _class: gcoms_core::TrafficClass,
    ) -> Result<(), SdkError> {
        self.submit_durable_opaque(recipient, content_type, body)
            .await
    }

    /// Trusted host seam used only after authenticated component dispatch.
    /// No IPC request exposes this operation directly; unsupported hosts deny it.
    async fn submit_local_component(&self, _wire: &[u8]) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn application_inbox(
        &self,
        _after: u64,
        _limit: u16,
    ) -> Result<Vec<ApplicationDelivery>, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn commit_application(&self, _sequence: u64, _digest: [u8; 32]) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn create_channel(
        &self,
        channel: &str,
        display_name: &str,
        capacity: usize,
        visibility: ChannelVisibility,
    ) -> Result<ChannelId, SdkError>;

    async fn prepare_channel_join(&self, display_name: &str) -> Result<JoinRequest, SdkError>;

    async fn channel_key_package(&self, request: JoinRequest) -> Result<Blob, SdkError>;

    async fn admit_channel(
        &self,
        channel: &str,
        key_package: &Blob,
        member_name: &str,
    ) -> Result<Blob, SdkError>;

    /// A local, out-of-band exchange between existing members; not a new invitation.
    async fn channel_reconnect(
        &self,
        _channel: &str,
        _code: Option<&str>,
    ) -> Result<String, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    /// Existing owner admission only. Returns the exact locally durable Dir ID
    /// after a bounded hop receipt; never asserts membership/application delivery.
    async fn recover_channel_route(
        &self,
        _channel: &str,
        _expected_channel_id: ChannelId,
        _expected_epoch: u64,
        _retained_welcome: &Blob,
        _peer: &ContactCard,
    ) -> Result<MessageId, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn join_channel(
        &self,
        request: JoinRequest,
        channel: &str,
        visibility: ChannelVisibility,
        welcome: &Blob,
    ) -> Result<(), SdkError>;

    async fn send_channel(&self, channel: &str, body: &[u8]) -> Result<(), SdkError>;

    /// Returns the exact channel wire ID after persistent local acceptance.
    /// ChannelDelivered means every recipient captured by this send ACKed;
    /// it does not prove application consumption or execution.
    async fn send_channel_tracked(
        &self,
        _channel: &str,
        _body: &[u8],
    ) -> Result<MessageId, SdkError> {
        Err(SdkError::PermissionDenied)
    }

    async fn set_channel_presence(
        &self,
        channel: &str,
        mode: PresenceMode,
        lease_secs: u32,
    ) -> Result<(), SdkError>;

    async fn set_channel_presence_opt_in(
        &self,
        channel: &str,
        enabled: bool,
    ) -> Result<(), SdkError>;

    /// Versioned binary channel application data. Receivers must dispatch this
    /// envelope before their text archiver. File completion is application-owned.
    async fn send_channel_application(
        &self,
        channel: &str,
        recipient_member_id: [u8; 32],
        content_type: &str,
        body: &[u8],
    ) -> Result<MessageId, SdkError> {
        if content_type != gcoms_core::PIECE_CONTENT_TYPE {
            return Err(SdkError::PermissionDenied);
        }
        let wire = ApplicationMessage {
            content_type: content_type.into(),
            body: body.to_vec(),
        }
        .encode()?;
        self.send_channel_direct(channel, recipient_member_id, &wire)
            .await
    }

    async fn send_channel_direct(
        &self,
        channel: &str,
        recipient_member_id: [u8; 32],
        body: &[u8],
    ) -> Result<MessageId, SdkError>;

    async fn remove_channel_member(
        &self,
        channel: &str,
        member_id: [u8; 32],
    ) -> Result<(), SdkError>;
}

// Preserve the complete interface when sharing either backend as a trait object.
#[async_trait]
impl<T: GcClient + ?Sized> GcClient for std::sync::Arc<T> {
    async fn sharing(
        &self,
        request: crate::sharing::Request,
    ) -> Result<crate::sharing::Reply, SdkError> {
        (**self).sharing(request).await
    }
    async fn network_status(&self) -> Result<crate::NetworkStatus, SdkError> {
        (**self).network_status().await
    }

    async fn persist_profile(&self) -> Result<(), SdkError> {
        (**self).persist_profile().await
    }
    async fn recover_network(&self, _urls: Vec<String>) -> Result<String, SdkError> {
        (**self).recover_network(_urls).await
    }
    async fn configure_network_dns(&self, _enabled: bool) -> Result<(), SdkError> {
        (**self).configure_network_dns(_enabled).await
    }
    async fn network_dns_status(&self) -> Result<NetworkNameStatus, SdkError> {
        (**self).network_dns_status().await
    }
    async fn resolve_contact_identity(&self, card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        (**self).resolve_contact_identity(card).await
    }
    async fn runtime_status(&self) -> Result<RuntimeStatus, SdkError> {
        (**self).runtime_status().await
    }
    async fn import_network_invitation(&self, _invitation: &str) -> Result<(), SdkError> {
        (**self).import_network_invitation(_invitation).await
    }
    async fn create_channel_invitation(
        &self,
        _channel: &str,
        _ttl_secs: u64,
    ) -> Result<ChannelInvitation, SdkError> {
        (**self)
            .create_channel_invitation(_channel, _ttl_secs)
            .await
    }
    async fn inspect_channel_invitation(&self, _link: &str) -> Result<ChannelInvitation, SdkError> {
        (**self).inspect_channel_invitation(_link).await
    }
    async fn join_channel_invitation(
        &self,
        _link: &str,
        _display: &str,
        _timeout_secs: u64,
    ) -> Result<String, SdkError> {
        (**self)
            .join_channel_invitation(_link, _display, _timeout_secs)
            .await
    }
    async fn configure_catalog_origins(&self, _origins: Vec<String>) -> Result<(), SdkError> {
        (**self).configure_catalog_origins(_origins).await
    }
    async fn catalog_request(
        &self,
        _request: crate::CatalogHttpRequest,
    ) -> Result<crate::CatalogHttpResponse, SdkError> {
        (**self).catalog_request(_request).await
    }
    async fn component_shell(
        &self,
        _component: [u8; 16],
        _request: crate::shell::ShellRequest,
    ) -> Result<crate::shell::ShellReply, SdkError> {
        (**self).component_shell(_component, _request).await
    }
    async fn file_route(&self) -> Result<Vec<u8>, SdkError> {
        (**self).file_route().await
    }
    async fn component_files(
        &self,
        _component: [u8; 16],
        _request: crate::files::FileRequest,
    ) -> Result<crate::files::FileReply, SdkError> {
        (**self).component_files(_component, _request).await
    }
    fn contact_identity(&self, _card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        (**self).contact_identity(_card)
    }
    fn identity(&self) -> Identity {
        (**self).identity()
    }
    async fn refresh_identity(&self) -> Result<Identity, SdkError> {
        (**self).refresh_identity().await
    }
    async fn sign_identity_digest(&self, _digest: [u8; 32]) -> Result<Vec<u8>, SdkError> {
        (**self).sign_identity_digest(_digest).await
    }
    async fn sign_principal_binding_hash(
        &self,
        _claims_hash: [u8; 32],
    ) -> Result<Vec<u8>, SdkError> {
        (**self).sign_principal_binding_hash(_claims_hash).await
    }
    fn subscribe_events(&self) -> mpsc::Receiver<ClientEvent> {
        (**self).subscribe_events()
    }
    async fn list_channels(&self) -> Result<Vec<JoinedChannel>, SdkError> {
        (**self).list_channels().await
    }
    async fn channel_roster(&self, channel: &str) -> Result<Vec<ChannelMemberSummary>, SdkError> {
        (**self).channel_roster(channel).await
    }
    async fn channel_topic(&self, channel: &str) -> Result<String, SdkError> {
        (**self).channel_topic(channel).await
    }
    async fn change_channel(
        &self,
        channel: &str,
        change: ChannelChange,
    ) -> Result<MessageId, SdkError> {
        (**self).change_channel(channel, change).await
    }
    async fn public_channel_descriptor(
        &self,
        channel: &str,
        description: &str,
        activity: ActivityBucket,
        automatic_join: AutomaticJoinEndpoint,
        expires_at_unix: u64,
    ) -> Result<PublicChannelDescriptor, SdkError> {
        (**self)
            .public_channel_descriptor(
                channel,
                description,
                activity,
                automatic_join,
                expires_at_unix,
            )
            .await
    }
    async fn send_direct(
        &self,
        peer: &ContactCard,
        body: &[u8],
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        (**self).send_direct(peer, body, via).await
    }
    async fn send_direct_tracked(
        &self,
        _peer: &ContactCard,
        _body: &[u8],
        _via: Option<&ContactCard>,
    ) -> Result<MessageId, SdkError> {
        (**self).send_direct_tracked(_peer, _body, _via).await
    }
    async fn set_direct_presence(
        &self,
        peer: &ContactCard,
        mode: PresenceMode,
        lease_secs: u32,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        (**self)
            .set_direct_presence(peer, mode, lease_secs, via)
            .await
    }
    async fn set_direct_presence_opt_in(
        &self,
        peer: &ContactCard,
        enabled: bool,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        (**self)
            .set_direct_presence_opt_in(peer, enabled, via)
            .await
    }
    async fn submit_opaque(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        (**self).submit_opaque(recipient, content_type, body).await
    }
    async fn submit_volatile_opaque(
        &self,
        _recipient: &ContactCard,
        _content_type: &str,
        _body: &[u8],
    ) -> Result<(), SdkError> {
        (**self)
            .submit_volatile_opaque(_recipient, _content_type, _body)
            .await
    }
    async fn submit_durable_opaque(
        &self,
        _recipient: &ContactCard,
        _content_type: &str,
        _body: &[u8],
    ) -> Result<(), SdkError> {
        (**self)
            .submit_durable_opaque(_recipient, _content_type, _body)
            .await
    }
    async fn submit_local_component(&self, _wire: &[u8]) -> Result<(), SdkError> {
        (**self).submit_local_component(_wire).await
    }
    async fn application_inbox(
        &self,
        _after: u64,
        _limit: u16,
    ) -> Result<Vec<ApplicationDelivery>, SdkError> {
        (**self).application_inbox(_after, _limit).await
    }
    async fn commit_application(&self, _sequence: u64, _digest: [u8; 32]) -> Result<(), SdkError> {
        (**self).commit_application(_sequence, _digest).await
    }
    async fn create_channel(
        &self,
        channel: &str,
        display_name: &str,
        capacity: usize,
        visibility: ChannelVisibility,
    ) -> Result<ChannelId, SdkError> {
        (**self)
            .create_channel(channel, display_name, capacity, visibility)
            .await
    }
    async fn prepare_channel_join(&self, display_name: &str) -> Result<JoinRequest, SdkError> {
        (**self).prepare_channel_join(display_name).await
    }
    async fn channel_key_package(&self, request: JoinRequest) -> Result<Blob, SdkError> {
        (**self).channel_key_package(request).await
    }
    async fn admit_channel(
        &self,
        channel: &str,
        key_package: &Blob,
        member_name: &str,
    ) -> Result<Blob, SdkError> {
        (**self)
            .admit_channel(channel, key_package, member_name)
            .await
    }
    async fn channel_reconnect(
        &self,
        channel: &str,
        code: Option<&str>,
    ) -> Result<String, SdkError> {
        (**self).channel_reconnect(channel, code).await
    }

    async fn recover_channel_route(
        &self,
        _channel: &str,
        _expected_channel_id: ChannelId,
        _expected_epoch: u64,
        _retained_welcome: &Blob,
        _peer: &ContactCard,
    ) -> Result<MessageId, SdkError> {
        (**self)
            .recover_channel_route(
                _channel,
                _expected_channel_id,
                _expected_epoch,
                _retained_welcome,
                _peer,
            )
            .await
    }
    async fn join_channel(
        &self,
        request: JoinRequest,
        channel: &str,
        visibility: ChannelVisibility,
        welcome: &Blob,
    ) -> Result<(), SdkError> {
        (**self)
            .join_channel(request, channel, visibility, welcome)
            .await
    }
    async fn send_channel(&self, channel: &str, body: &[u8]) -> Result<(), SdkError> {
        (**self).send_channel(channel, body).await
    }
    async fn send_channel_tracked(
        &self,
        _channel: &str,
        _body: &[u8],
    ) -> Result<MessageId, SdkError> {
        (**self).send_channel_tracked(_channel, _body).await
    }
    async fn set_channel_presence(
        &self,
        channel: &str,
        mode: PresenceMode,
        lease_secs: u32,
    ) -> Result<(), SdkError> {
        (**self)
            .set_channel_presence(channel, mode, lease_secs)
            .await
    }
    async fn set_channel_presence_opt_in(
        &self,
        channel: &str,
        enabled: bool,
    ) -> Result<(), SdkError> {
        (**self).set_channel_presence_opt_in(channel, enabled).await
    }
    async fn send_channel_direct(
        &self,
        channel: &str,
        recipient_member_id: [u8; 32],
        body: &[u8],
    ) -> Result<MessageId, SdkError> {
        (**self)
            .send_channel_direct(channel, recipient_member_id, body)
            .await
    }
    async fn remove_channel_member(
        &self,
        channel: &str,
        member_id: [u8; 32],
    ) -> Result<(), SdkError> {
        (**self).remove_channel_member(channel, member_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_cleanup_application_keeps_type_and_clears_owned_bytes() {
        use zeroize::Zeroize;
        let mut app = ApplicationMessage {
            content_type: "application/octet-stream".into(),
            body: vec![0xa7; 4096],
        };
        app.zeroize();
        assert_eq!(app.body, vec![0; 4096]);
        assert_eq!(app.content_type, "application/octet-stream");
    }

    #[test]
    fn application_message_roundtrip_is_strict() {
        let message = ApplicationMessage {
            content_type: "application/vnd.ghost.report+json".into(),
            body: vec![1, 2, 3],
        };
        let encoded = message.encode().unwrap();
        assert_eq!(ApplicationMessage::decode(&encoded).unwrap(), message);
        assert!(ApplicationMessage {
            content_type: "bad\nvalue".into(),
            body: Vec::new(),
        }
        .encode()
        .is_err());
        assert!(ApplicationMessage::decode(b"GCAPP1\0").is_err());
    }

    #[test]
    fn application_payload_boundary_is_explicit() {
        assert!(
            validate_application_payload(&vec![0; gcoms_core::APPLICATION_PAYLOAD_LIMIT]).is_ok()
        );
        assert!(
            validate_application_payload(&vec![0; gcoms_core::APPLICATION_PAYLOAD_LIMIT + 1])
                .is_err()
        );
        let content_type = "application/vnd.ghost.recorder-batch.v2+json";
        assert_eq!(application_body_limit(content_type).unwrap(), 12_236);
        assert!(ApplicationMessage {
            content_type: content_type.into(),
            body: vec![0; 12_236],
        }
        .encode()
        .is_ok());
        assert!(ApplicationMessage {
            content_type: content_type.into(),
            body: vec![0; 12_237],
        }
        .encode()
        .is_err());
    }

    #[test]
    fn channel_ids_order_lexicographically_by_canonical_bytes() {
        let low = ChannelId([0; 32]);
        let mut high_bytes = [0; 32];
        high_bytes[31] = 1;

        assert!(low < ChannelId(high_bytes));
    }
}

/// Explicit wire carrier selection. Never inferred from addresses or cargo features.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CarrierProfile {
    #[default]
    Legacy,
    Gc2,
}

#[derive(Clone)]
pub struct Peer {
    pub identity: Vec<u8>,
    pub contact: ContactCard,
    pub component: Option<[u8; 16]>,
}
impl Peer {
    pub fn principal(&self) -> String {
        format!(
            "gc:{}:{}",
            peer_hex(&self.identity),
            self.component.map(|c| peer_hex(&c)).unwrap_or_default()
        )
    }
}

fn peer_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
