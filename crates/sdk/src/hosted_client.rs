//! Application-facing hosted channel operations. These are distinct from the
//! ciphertext service exchange: the runtime owns member keys and durable state.
use serde::{Deserialize, Serialize};

/// Invitation secrets may be copied for an explicit share, but never formatted
/// by request diagnostics. Profile and command-history owners must encrypt them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InviteLink(pub String);
impl std::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteLink([redacted])")
    }
}
impl Drop for InviteLink {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

pub type ChannelId = [u8; 32];
pub type MemberId = [u8; 32];
pub type MessageId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Admission {
    InviteOnly,
    Public,
    ReusableCode,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Moderated,
    InviteOnly,
    TopicOperators,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Operator,
    Voice,
    Member,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Discovery {
    Public,
    Private,
    Secret,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessList {
    Ban,
    Exemption,
    InviteException,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change {
    Mode(Mode, bool),
    Operator(MemberId, bool),
    Voice(MemberId, bool),
    AccessList(AccessList, MemberId, bool),
    Capacity(u32),
    Discovery(Discovery),
    Transfer(MemberId),
    Kick(MemberId),
    Leave,
    Close,
    Role(MemberId, Role),
    Invitation { verifier: [u8; 32], expires_at: u64 },
    AccessCode { verifier: Option<[u8; 32]> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Available,
    Away { reason: String },
    Invisible,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    Text(String),
    Action(String),
    Notice(String),
    Topic(String),
    Nickname(String),
    Presence {
        state: Presence,
        lease_secs: u32,
    },
    /// Opaque, versioned channel file protocol data. Private contact files use
    /// the independent direct-conversation transport, never channel broadcast.
    File {
        content_type: String,
        body: Vec<u8>,
    },
    /// Encrypted handoff from a currently authorized topic writer. Only fills
    /// unknown state; it never overwrites a topic already observed by this client.
    TopicState {
        topic: String,
        through: u64,
        source: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Delivery {
    Pending,
    ServiceAccepted { sequence: u64 },
    Delivered,
    Failed { reason: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub id: MemberId,
    pub nickname: String,
    pub role: Role,
    pub operator: bool,
    pub voice: bool,
    pub presence: Presence,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub alias: String,
    pub endpoint: String,
    pub self_member: MemberId,
    pub epoch: u64,
    pub revision: u64,
    pub active: bool,
    pub topic: String,
    #[serde(default)]
    pub topic_pending: bool,
    pub members: Vec<Member>,
    pub capacity: u32,
    pub bans: Vec<MemberId>,
    pub exemptions: Vec<MemberId>,
    pub invite_exceptions: Vec<MemberId>,
    pub moderated: bool,
    pub invite_only: bool,
    pub topic_operators: bool,
    pub discovery: Discovery,
    pub cursor: u64,
    pub pending: usize,
    pub presence_opt_in: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Local durable event sequence; independent of network record pagination.
    pub sequence: u64,
    pub channel: ChannelId,
    pub accepted_at: u64,
    pub kind: EventKind,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    Message {
        id: MessageId,
        sender: MemberId,
        content: Content,
        delivery: Delivery,
    },
    Delivery {
        id: MessageId,
        state: Delivery,
    },
    Activity {
        actor: MemberId,
        change: Change,
        reason: Option<String>,
    },
    Joined {
        member: MemberId,
        nickname: String,
    },
    Removed,
    OperationFailed {
        reason: String,
    },
    Unavailable {
        sender: MemberId,
        reason: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    List,
    Create {
        endpoint: String,
        alias: String,
        nickname: String,
        capacity: u32,
        admission: Admission,
    },
    Join {
        link: InviteLink,
        alias: String,
        nickname: String,
    },
    Send {
        channel: ChannelId,
        content: Content,
    },
    Change {
        channel: ChannelId,
        change: Change,
        reason: String,
    },
    Invite {
        channel: ChannelId,
        ttl_secs: u32,
    },
    RotateCode {
        channel: ChannelId,
    },
    ClearCode {
        channel: ChannelId,
    },
    Links {
        channel: ChannelId,
    },
    SetPresence {
        channel: ChannelId,
        enabled: bool,
        state: Presence,
    },
    Sync {
        channel: ChannelId,
    },
    Events {
        channel: ChannelId,
        after: u64,
        limit: u16,
    },
    /// The application must archive these events durably before committing.
    CommitEvents {
        channel: ChannelId,
        through: u64,
    },
    /// IPC23: ciphertext-only bulk piece storage; these calls do not ACK chat.
    PutBlob {
        channel: ChannelId,
        reference: crate::hosted::BlobRef,
        bytes: Vec<u8>,
    },
    GetBlob {
        channel: ChannelId,
        reference: crate::hosted::BlobRef,
    },
    /// IPC23: independent durable file-consumer cursor. Event sequences here
    /// are service record sequences, not the ordinary local event sequence.
    FileEvents {
        channel: ChannelId,
        limit: u16,
    },
    CommitFileEvents {
        channel: ChannelId,
        through: u64,
    },
    /// Retry an immutable application identity after an uncertain response.
    SendIdentified {
        channel: ChannelId,
        id: MessageId,
        content: Content,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Channels(Vec<Channel>),
    Channel(Box<Channel>),
    Queued(MessageId),
    Link(InviteLink),
    Links(Vec<InviteLink>),
    Events(Vec<Event>),
    Done,
    Blob(Vec<u8>),
    FileEvents(Vec<Event>),
}
