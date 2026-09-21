use crate::alias::{AliasContact, OwnedAlias};
use crate::relay::RelayTarget;
use gcoms_gossip::{NodeId, Overlay, OverlayConfig, PeerDescriptor};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

pub mod metadata;
pub use metadata::ChannelChange;

pub const CHAN_TEXT: u8 = 0;
pub const CHAN_DIR: u8 = 1;
pub const CHAN_COMMIT_ACK: u8 = 2;
pub const CHAN_TEXT_ACK: u8 = 3;
pub const CHAN_DIRECT_INTRO: u8 = 4;
pub const CHAN_DIR_BATCH: u8 = 5;
pub const CHAN_PRESENCE_LEASE: u8 = 6;
pub const CHAN_TEXT_WITH_PRESENCE: u8 = 7;
pub const CHAN_COMMIT_ACK_WITH_PRESENCE: u8 = 8;
pub const CHAN_TEXT_ACK_WITH_PRESENCE: u8 = 9;
pub const CHAN_METADATA: u8 = 10;
// 3 is the volatile file-piece application disposition.
pub const CHANNEL_DIRECT_PEX: u8 = 4;
pub const CHANNEL_DIR_BATCH_LIMIT: usize = 32;
const CHANNEL_ROUTE_VERSION: u8 = 2;
const PEX_VERSION: u8 = 1;
const CONTACT_LEN: usize = 131;
const LEGACY_CHANNEL_ROUTE_LEN: usize = 1 + 32 + 2 * CONTACT_LEN;
const CHANNEL_ROUTE_LEN: usize = LEGACY_CHANNEL_ROUTE_LEN + 32;
const JOIN_PACKAGE_DOMAIN: &[u8] = b"GC1/CHANNEL-JOIN\0";
pub const CHANNEL_ACK_LIMIT: usize = 64;
pub const FUTURE_EPOCH_DISTANCE_LIMIT: u64 = 8;
pub const FUTURE_MESSAGE_COUNT_LIMIT: usize = 256;
pub const FUTURE_MESSAGE_BYTES_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelVisibility {
    Public,
    Private,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelMemberSummary {
    pub member_id: [u8; 32],
    pub display_name: String,
    pub is_self: bool,
    pub join_order: u32,
    pub joined_at_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityBucket {
    None,
    Today,
    ThisWeek,
    Older,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomaticJoinEndpoint {
    pub catalog: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

pub fn msg_id(chan: &str, mls_wire: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"gc1/cid");
    h.update(chan.as_bytes());
    h.update(mls_wire);
    let d = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    id
}

pub fn peer_id(route: &ChannelRoute) -> NodeId {
    u64::from_le_bytes(
        sha2::Sha256::digest(route.pseudonym)[..8]
            .try_into()
            .unwrap(),
    )
}

pub fn encode_text(text: &[u8], share_presence: bool) -> Vec<u8> {
    let mut v = vec![if share_presence {
        CHAN_TEXT_WITH_PRESENCE
    } else {
        CHAN_TEXT
    }];
    let ts = now_ms();
    v.extend_from_slice(&ts.to_be_bytes());
    if share_presence {
        v.push(1);
    }
    v.extend_from_slice(text);
    v
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn encode_dir(name: &str, route: &ChannelRoute) -> Vec<u8> {
    let mut v = vec![CHAN_DIR];
    v.extend_from_slice(&(name.len() as u16).to_be_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(&route.encode());
    v
}

pub fn encode_dir_batch(entries: &[(String, ChannelRoute)]) -> Option<Vec<u8>> {
    if entries.is_empty() || entries.len() > CHANNEL_DIR_BATCH_LIMIT {
        return None;
    }
    let count = u16::try_from(entries.len()).ok()?;
    let mut encoded = vec![CHAN_DIR_BATCH];
    encoded.extend_from_slice(&count.to_be_bytes());
    for (name, route) in entries {
        let name_len = u16::try_from(name.len()).ok()?;
        encoded.extend_from_slice(&name_len.to_be_bytes());
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(&route.encode());
    }
    Some(encoded)
}

pub fn encode_direct_intro(name: &str, pseudonym: [u8; 32], direct_public: [u8; 32]) -> Vec<u8> {
    let mut encoded = vec![CHAN_DIRECT_INTRO];
    encoded.extend_from_slice(&(name.len() as u16).to_be_bytes());
    encoded.extend_from_slice(name.as_bytes());
    encoded.extend_from_slice(&pseudonym);
    encoded.extend_from_slice(&direct_public);
    encoded
}

pub fn encode_commit_ack(commit_id: [u8; 16], epoch: u64, share_presence: bool) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(25 + usize::from(share_presence));
    encoded.push(if share_presence {
        CHAN_COMMIT_ACK_WITH_PRESENCE
    } else {
        CHAN_COMMIT_ACK
    });
    encoded.extend_from_slice(&commit_id);
    encoded.extend_from_slice(&epoch.to_be_bytes());
    if share_presence {
        encoded.push(1);
    }
    encoded
}

pub fn encode_text_ack(message_id: [u8; 16], share_presence: bool) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(17 + usize::from(share_presence));
    encoded.push(if share_presence {
        CHAN_TEXT_ACK_WITH_PRESENCE
    } else {
        CHAN_TEXT_ACK
    });
    encoded.extend_from_slice(&message_id);
    if share_presence {
        encoded.push(1);
    }
    encoded
}

pub fn encode_presence(
    counter: u64,
    mode: crate::proto::PresenceMode,
    lease_secs: u32,
) -> Option<Vec<u8>> {
    let valid_lease = match mode {
        crate::proto::PresenceMode::Invisible => lease_secs == 0,
        crate::proto::PresenceMode::RecentlyReachable | crate::proto::PresenceMode::Away => {
            (crate::proto::MIN_PRESENCE_LEASE_SECS..=crate::proto::MAX_PRESENCE_LEASE_SECS)
                .contains(&lease_secs)
        }
    };
    if counter == 0 || !valid_lease {
        return None;
    }
    let mut encoded = Vec::with_capacity(14);
    encoded.push(CHAN_PRESENCE_LEASE);
    encoded.extend_from_slice(&counter.to_be_bytes());
    encoded.push(match mode {
        crate::proto::PresenceMode::RecentlyReachable => 1,
        crate::proto::PresenceMode::Away => 2,
        crate::proto::PresenceMode::Invisible => 3,
    });
    encoded.extend_from_slice(&lease_secs.to_be_bytes());
    Some(encoded)
}

pub enum ChannelInner {
    Metadata(Vec<u8>),
    Text {
        ts_ms: u64,
        share_presence: bool,
        body: Vec<u8>,
    },
    Dir(String, Box<ChannelRoute>),
    CommitAck {
        commit_id: [u8; 16],
        epoch: u64,
        share_presence: bool,
    },
    TextAck {
        message_id: [u8; 16],
        share_presence: bool,
    },
    DirectIntro {
        name: String,
        pseudonym: [u8; 32],
        direct_public: [u8; 32],
    },
    DirBatch(Vec<(String, ChannelRoute)>),
    PresenceLease {
        counter: u64,
        mode: crate::proto::PresenceMode,
        lease_secs: u32,
    },
}

pub fn decode_inner(plain: &[u8]) -> Option<ChannelInner> {
    match *plain.first()? {
        CHAN_METADATA if plain.len() <= metadata::MAX_UPDATE_BYTES + 1 => {
            Some(ChannelInner::Metadata(plain[1..].to_vec()))
        }
        CHAN_TEXT => {
            if plain.len() < 9 {
                return None;
            }
            let ts_ms = u64::from_be_bytes(plain[1..9].try_into().ok()?);
            Some(ChannelInner::Text {
                ts_ms,
                share_presence: false,
                body: plain[9..].to_vec(),
            })
        }
        CHAN_TEXT_WITH_PRESENCE if plain.len() >= 10 && matches!(plain[9], 0 | 1) => {
            Some(ChannelInner::Text {
                ts_ms: u64::from_be_bytes(plain[1..9].try_into().ok()?),
                share_presence: plain[9] == 1,
                body: plain[10..].to_vec(),
            })
        }
        CHAN_DIR => {
            let mut p = 1usize;
            let nlen = u16::from_be_bytes([*plain.get(p)?, *plain.get(p + 1)?]) as usize;
            p += 2;
            let name = String::from_utf8(plain.get(p..p + nlen)?.to_vec()).ok()?;
            p += nlen;
            let route = ChannelRoute::decode(plain.get(p..)?)?;
            Some(ChannelInner::Dir(name, Box::new(route)))
        }
        CHAN_COMMIT_ACK if plain.len() == 25 => Some(ChannelInner::CommitAck {
            commit_id: plain[1..17].try_into().ok()?,
            epoch: u64::from_be_bytes(plain[17..25].try_into().ok()?),
            share_presence: false,
        }),
        CHAN_TEXT_ACK if plain.len() == 17 => Some(ChannelInner::TextAck {
            message_id: plain[1..17].try_into().ok()?,
            share_presence: false,
        }),
        CHAN_COMMIT_ACK_WITH_PRESENCE if plain.len() == 26 && matches!(plain[25], 0 | 1) => {
            Some(ChannelInner::CommitAck {
                commit_id: plain[1..17].try_into().ok()?,
                epoch: u64::from_be_bytes(plain[17..25].try_into().ok()?),
                share_presence: plain[25] == 1,
            })
        }
        CHAN_TEXT_ACK_WITH_PRESENCE if plain.len() == 18 && matches!(plain[17], 0 | 1) => {
            Some(ChannelInner::TextAck {
                message_id: plain[1..17].try_into().ok()?,
                share_presence: plain[17] == 1,
            })
        }
        CHAN_DIRECT_INTRO => {
            let name_len = u16::from_be_bytes(plain.get(1..3)?.try_into().ok()?) as usize;
            let name_end = 3usize.checked_add(name_len)?;
            (plain.len() == name_end + 64).then_some(ChannelInner::DirectIntro {
                name: String::from_utf8(plain.get(3..name_end)?.to_vec()).ok()?,
                pseudonym: plain.get(name_end..name_end + 32)?.try_into().ok()?,
                direct_public: plain.get(name_end + 32..name_end + 64)?.try_into().ok()?,
            })
        }
        CHAN_DIR_BATCH => {
            let mut position = 1usize;
            let count =
                u16::from_be_bytes(plain.get(position..position + 2)?.try_into().ok()?) as usize;
            if count == 0 || count > CHANNEL_DIR_BATCH_LIMIT {
                return None;
            }
            position += 2;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let name_len =
                    u16::from_be_bytes(plain.get(position..position + 2)?.try_into().ok()?)
                        as usize;
                position += 2;
                let name_end = position.checked_add(name_len)?;
                let name = String::from_utf8(plain.get(position..name_end)?.to_vec()).ok()?;
                position = name_end;
                let route_end = position.checked_add(CHANNEL_ROUTE_LEN)?;
                let route = ChannelRoute::decode(plain.get(position..route_end)?)?;
                position = route_end;
                entries.push((name, route));
            }
            (position == plain.len()).then_some(ChannelInner::DirBatch(entries))
        }
        CHAN_PRESENCE_LEASE if plain.len() == 14 => {
            let counter = u64::from_be_bytes(plain[1..9].try_into().ok()?);
            let mode = match plain[9] {
                1 => crate::proto::PresenceMode::RecentlyReachable,
                2 => crate::proto::PresenceMode::Away,
                3 => crate::proto::PresenceMode::Invisible,
                _ => return None,
            };
            let lease_secs = u32::from_be_bytes(plain[10..14].try_into().ok()?);
            encode_presence(counter, mode, lease_secs).map(|_| ChannelInner::PresenceLease {
                counter,
                mode,
                lease_secs,
            })
        }
        _ => None,
    }
}

pub enum ChannelRole {
    Owner(gcoms_mls::OwnerSession),
    Member(gcoms_mls::ChannelMember),
}

impl ChannelRole {
    pub(crate) fn owner(&self) -> Option<[u8; 32]> {
        match self {
            Self::Owner(o) => o.channel_owner(),
            Self::Member(m) => m.channel_owner(),
        }
    }
    pub(crate) fn is_owner(&self) -> bool {
        self.owner() == Some(self.own_pseudonym())
    }
    pub(crate) fn is_owner_name(&self, name: &str) -> bool {
        self.pseudonym_for_name(name)
            .is_some_and(|member| self.owner() == Some(member))
    }
    pub(crate) fn propose_owner(&mut self, next: [u8; 32]) -> Result<Vec<u8>, gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.propose_owner(next),
            Self::Member(m) => m.propose_owner(next),
        }
    }
    pub(crate) fn ownership_certificate(&self) -> Result<Vec<u8>, gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.ownership_certificate(),
            Self::Member(m) => m.ownership_certificate(),
        }
    }
    pub(crate) fn install_owner(
        &mut self,
        actor: [u8; 32],
        chain: &[u8],
    ) -> Result<(), gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.install_owner_from(actor, chain),
            Self::Member(m) => m.install_owner_from(actor, chain),
        }
    }
    pub(crate) fn stage_admit(
        &mut self,
        package: &[u8],
        name: &str,
    ) -> Result<gcoms_mls::StagedAdmission, gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => {
                let invite =
                    o.sign_invite_key_package(package, name, gcoms_mls::Caps::member(), 3600);
                o.stage_admit(&invite, package)
            }
            Self::Member(m) => m.stage_admit_current(package, name),
        }
    }
    pub(crate) fn stage_remove(
        &mut self,
        member: [u8; 32],
    ) -> Result<gcoms_mls::StagedRemoval, gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.stage_remove(member),
            Self::Member(m) => m.stage_remove_current(member),
        }
    }
    pub(crate) fn merge_pending(&mut self) -> Result<(), gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.merge_pending(),
            Self::Member(m) => m.merge_pending(),
        }
    }
    pub(crate) fn channel_metadata(&self) -> Result<Vec<u8>, gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.channel_metadata(),
            Self::Member(m) => m.channel_metadata(),
        }
    }
    pub(crate) fn set_channel_metadata(&mut self, bytes: &[u8]) -> Result<(), gcoms_mls::MlsError> {
        match self {
            Self::Owner(o) => o.set_channel_metadata(bytes),
            Self::Member(m) => m.set_channel_metadata(bytes),
        }
    }
    pub(crate) fn channel_admin(&self, member: [u8; 32]) -> bool {
        match self {
            Self::Owner(o) => o.channel_admin(member),
            Self::Member(m) => m.channel_admin(member),
        }
    }
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, gcoms_mls::MlsError> {
        match self {
            ChannelRole::Owner(o) => o.send(payload),
            ChannelRole::Member(m) => m.send(payload),
        }
    }

    pub fn receive(
        &mut self,
        wire: &[u8],
    ) -> Result<gcoms_mls::ReceiveOutcome, gcoms_mls::MlsError> {
        match self {
            ChannelRole::Owner(o) => o.receive_outcome(wire),
            ChannelRole::Member(m) => m.receive_outcome(wire),
        }
    }

    /// Sealed snapshot of the MLS state under the channel wrapping key.
    #[cfg(feature = "client-persist")]
    pub(crate) fn checkpoint(
        &self,
        wrapping_key: &[u8; 32],
    ) -> Result<Vec<u8>, gcoms_mls::MlsError> {
        match self {
            ChannelRole::Owner(owner) => owner.persist(wrapping_key),
            ChannelRole::Member(member) => member.persist(wrapping_key),
        }
    }

    #[cfg(not(feature = "client-persist"))]
    pub(crate) fn checkpoint(
        &self,
        _wrapping_key: &[u8; 32],
    ) -> Result<Vec<u8>, gcoms_mls::MlsError> {
        Ok(Vec::new())
    }

    /// Rebuild the MLS state from a [`ChannelRole::checkpoint`]. The owner
    /// identity is re-derived by the caller; it is never inside the archive.
    #[cfg(feature = "client-persist")]
    pub(crate) fn restore_checkpoint(
        &self,
        wrapping_key: &[u8; 32],
        checkpoint: &[u8],
        owner_identity: impl FnOnce() -> gcoms_crypto::IdentityKeypair,
    ) -> Result<Self, gcoms_mls::MlsError> {
        match self {
            ChannelRole::Owner(_) => {
                gcoms_mls::OwnerSession::restore(wrapping_key, checkpoint, owner_identity())
                    .map(Self::Owner)
            }
            ChannelRole::Member(_) => {
                gcoms_mls::ChannelMember::restore(wrapping_key, checkpoint).map(Self::Member)
            }
        }
    }

    #[cfg(not(feature = "client-persist"))]
    pub(crate) fn restore_checkpoint(
        &self,
        _wrapping_key: &[u8; 32],
        _checkpoint: &[u8],
        _owner_identity: impl FnOnce() -> gcoms_crypto::IdentityKeypair,
    ) -> Result<Self, gcoms_mls::MlsError> {
        Err(gcoms_mls::MlsError::OpenMls(
            "channel persistence is disabled".into(),
        ))
    }

    pub fn roster(&self) -> Vec<(u32, String)> {
        match self {
            ChannelRole::Owner(o) => o.roster(),
            ChannelRole::Member(m) => m.roster(),
        }
    }

    pub fn roster_members(&self) -> Vec<gcoms_mls::RosterMember> {
        match self {
            ChannelRole::Owner(owner) => owner.roster_members(),
            ChannelRole::Member(member) => member.roster_members(),
        }
    }

    pub fn channel_id(&self) -> ChannelId {
        ChannelId(match self {
            ChannelRole::Owner(owner) => owner.stable_channel_id(),
            ChannelRole::Member(member) => member.stable_channel_id(),
        })
    }

    pub fn sign_public_descriptor(
        &self,
        expires_at_unix: u64,
        title: String,
        description: String,
        activity: ActivityBucket,
        automatic_join: AutomaticJoinEndpoint,
    ) -> Result<PublicChannelDescriptor, &'static str> {
        let ChannelRole::Owner(owner) = self else {
            return Err("not owner");
        };
        let mut descriptor = PublicChannelDescriptor {
            version: 1,
            expires_at_unix,
            channel_id: ChannelId(owner.stable_channel_id()),
            owner_public_key: owner.owner_public_key(),
            capacity: u32::try_from(owner.capacity()).map_err(|_| "capacity too large")?,
            title,
            description,
            activity,
            automatic_join,
            signature: Vec::new(),
        };
        let payload = descriptor
            .signing_payload()
            .ok_or("descriptor field too large")?;
        descriptor.signature = owner.sign_owner_metadata(&payload);
        Ok(descriptor)
    }

    pub fn epoch(&self) -> u64 {
        match self {
            ChannelRole::Owner(o) => o.epoch(),
            ChannelRole::Member(m) => m.epoch(),
        }
    }

    pub fn own_pseudonym(&self) -> [u8; 32] {
        match self {
            ChannelRole::Owner(owner) => owner.own_pseudonym(),
            ChannelRole::Member(member) => member.own_pseudonym(),
        }
    }

    pub fn pseudonym_for_name(&self, name: &str) -> Option<[u8; 32]> {
        match self {
            ChannelRole::Owner(owner) => owner.pseudonym_for_name(name),
            ChannelRole::Member(member) => member.pseudonym_for_name(name),
        }
    }
}

pub fn mls_epoch_of(wire: &[u8]) -> Option<u64> {
    gcoms_mls::epoch_of_wire(wire)
}

/// Bound on forward-queue entries per channel.
pub const PENDING_MAX_ENTRIES: usize = 256;
/// Bound on forward-queue bytes per channel.
pub const PENDING_MAX_BYTES: usize = 4 * 1024 * 1024;
/// A wire still not fully forwarded after this many ticks is dropped; the
/// pull sweep (§11.2) closes the tail for anyone who missed it.
pub const PENDING_MAX_ATTEMPTS: u32 = 8;
/// Bound on queued anti-entropy replies per channel.
pub const PULL_OUTBOX_MAX: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingForward {
    pub id: [u8; 16],
    pub wire: Vec<u8>,
    pub attempts: u32,
}

#[derive(Clone)]
pub(crate) struct RouteAnnouncement {
    pub epoch: u64,
    pub route: ChannelRoute,
    pub wire: Vec<u8>,
}
impl Drop for RouteAnnouncement {
    fn drop(&mut self) {
        self.wire.fill(0);
    }
}

pub struct ChannelState {
    pub id: ChannelId,
    pub title: String,
    pub visibility: ChannelVisibility,
    pub role: ChannelRole,
    pub own_route: OwnedChannelRoute,
    /// Most recent expired owned grant, retained only as bounded history. It is
    /// never activated, subscribed, renewed or rebound by directory updates.
    pub previous_own_route: Option<OwnedChannelRoute>,
    pub directory: HashMap<String, ChannelRoute>,
    pub overlay: Overlay,
    pub id_to_ref: HashMap<NodeId, PeerRef>,
    pub recent: VecDeque<[u8; 16]>,
    pub cell_cache: HashMap<[u8; 16], Vec<u8>>,
    pub cache_order: VecDeque<[u8; 16]>,
    /// Forward queue: wires this node still owes its overlay view. Bounded
    /// in entries, bytes, and attempts (SPEC §11.2); an unreachable peer
    /// cannot keep a message here forever.
    pub pending: VecDeque<PendingForward>,
    pending_bytes: usize,
    /// Anti-entropy replies owed to PEX partners, drained on the channel
    /// tick rather than pushed at receive time (no receive->send timing).
    pub pull_outbox: VecDeque<(PeerRef, [u8; 16], Vec<u8>)>,
    out_of_order: std::collections::BTreeMap<u64, Vec<Vec<u8>>>,
    future_message_count: usize,
    future_message_bytes: usize,
    pub membership_outbox: Option<MembershipOutbox>,
    /// Woken whenever `membership_outbox` clears.
    pub membership_done: Arc<tokio::sync::Notify>,
    pub pending_control: VecDeque<(ChannelRoute, Vec<u8>)>,
    // Transient dedup only. The exact ciphertext is durably held in pending_control.
    pub(crate) route_announcement: Option<RouteAnnouncement>,
    pub admission_cache: HashMap<[u8; 32], CachedAdmission>,
    pub admission_cache_order: VecDeque<[u8; 32]>,
    /// Single-use invite links this owner has minted. Keyed by invite id; the
    /// `consumed` flag is set atomically under the same `NodeState` lock that
    /// stages the MLS add, so two redemptions of one link cannot both succeed.
    /// Bounded FIFO like `admission_cache`.
    pub invites: HashMap<[u8; 16], InviteRecord>,
    pub invite_order: VecDeque<[u8; 16]>,
    pub completed_removals: HashSet<String>,
    pub commit_ack_cache: HashMap<[u8; 16], (ChannelRoute, Vec<u8>)>,
    pub commit_ack_order: VecDeque<[u8; 16]>,
    pub unrouted_ack_journal: HashMap<UnroutedAckKey, Vec<u8>>,
    pub unrouted_ack_order: VecDeque<UnroutedAckKey>,
    pub message_outbox: HashMap<[u8; 16], ChannelMessageOutbox>,
    pub seen_direct: VecDeque<[u8; 16]>,
    pub seen_pex: VecDeque<([u8; 32], [u8; 16])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnroutedAckKey {
    pub original_id: [u8; 16],
    pub sender_pseudonym: [u8; 32],
}

#[derive(Clone)]
pub struct ChannelMessageOutbox {
    pub wire: Vec<u8>,
    pub expected: HashMap<[u8; 32], ChannelRoute>,
    pub acknowledged: HashSet<[u8; 32]>,
}

/// Route descriptors changed by one authenticated directory entry. Keep only
/// routing metadata: rollback must never copy or regenerate retained MLS wires.
pub(crate) struct AuthenticatedRouteChange {
    name: String,
    pseudonym: [u8; 32],
    directory: Option<ChannelRoute>,
    peer: Option<PeerRef>,
    messages: Vec<([u8; 16], ChannelRoute)>,
    membership: Option<ChannelRoute>,
    controls: Vec<(usize, ChannelRoute)>,
    acks: Vec<([u8; 16], ChannelRoute)>,
    pulls: Vec<(usize, PeerRef)>,
}

impl Drop for ChannelMessageOutbox {
    fn drop(&mut self) {
        self.wire.fill(0);
    }
}

pub struct CachedAdmission {
    pub name: String,
    pub pseudonym: [u8; 32],
    pub welcome: Vec<u8>,
}

impl Drop for CachedAdmission {
    fn drop(&mut self) {
        self.welcome.fill(0);
    }
}

/// One minted single-use invite. `secret` is the high-entropy bearer secret a
/// redeemer must present; `consumed` records the pseudonym that redeemed it (so
/// a retry by the SAME key package replays idempotently while any other
/// redemption is rejected). Persisted so single-use survives an owner restart.
pub struct InviteRecord {
    pub secret: [u8; 32],
    pub expiry: u64,
    pub consumed: Option<[u8; 32]>,
}

impl Drop for InviteRecord {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

pub struct MembershipOutbox {
    pub commit_id: [u8; 16],
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub expected: HashMap<[u8; 32], ChannelRoute>,
    pub acknowledged: HashSet<[u8; 32]>,
}

impl Drop for MembershipOutbox {
    fn drop(&mut self) {
        self.commit.fill(0);
    }
}

impl Drop for ChannelState {
    fn drop(&mut self) {
        for route in std::iter::once(&mut self.own_route).chain(self.previous_own_route.iter_mut())
        {
            route.direct_secret.fill(0);
            for alias in &mut route.aliases {
                alias.zeroize();
            }
        }
        for wire in self.cell_cache.values_mut() {
            wire.fill(0);
        }
        for entry in &mut self.pending {
            entry.wire.fill(0);
        }
        for (_, _, wire) in &mut self.pull_outbox {
            wire.fill(0);
        }
        for wires in self.out_of_order.values_mut() {
            for wire in wires {
                wire.fill(0);
            }
        }
        for (_, wire) in &mut self.pending_control {
            wire.fill(0);
        }
        for (_, wire) in self.commit_ack_cache.values_mut() {
            wire.fill(0);
        }
        for wire in self.unrouted_ack_journal.values_mut() {
            wire.fill(0);
        }
    }
}

impl ChannelState {
    pub(crate) fn discard_forward_queue(&mut self) {
        for pending in &mut self.pending {
            pending.wire.fill(0);
        }
        self.pending.clear();
        self.pending_bytes = 0;
    }
    /// Queue a wire for overlay forwarding. Evicts the oldest entries when
    /// the entry or byte bound would be exceeded; never grows unbounded.
    pub fn enqueue_forward(&mut self, id: [u8; 16], wire: Vec<u8>) {
        if self.pending.iter().any(|entry| entry.id == id) {
            return;
        }
        if wire.len() > PENDING_MAX_BYTES {
            return;
        }
        while self.pending.len() >= PENDING_MAX_ENTRIES
            || self.pending_bytes + wire.len() > PENDING_MAX_BYTES
        {
            let Some(mut evicted) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes -= evicted.wire.len();
            evicted.wire.fill(0);
            crate::metrics::log_event("chan_pending_evicted", &[]);
        }
        self.pending_bytes += wire.len();
        self.pending.push_back(PendingForward {
            id,
            wire,
            attempts: 0,
        });
    }

    /// Drop a forwarded wire once every target accepted it, or after its
    /// attempt budget is spent.
    pub fn settle_forward(&mut self, id: [u8; 16], fully_sent: bool) {
        let Some(pos) = self.pending.iter().position(|entry| entry.id == id) else {
            return;
        };
        let entry = &mut self.pending[pos];
        entry.attempts = entry.attempts.saturating_add(1);
        if fully_sent || entry.attempts >= PENDING_MAX_ATTEMPTS {
            if let Some(mut removed) = self.pending.remove(pos) {
                self.pending_bytes -= removed.wire.len();
                removed.wire.fill(0);
            }
        }
    }

    pub fn forget_forward(&mut self, id: &[u8; 16]) {
        if let Some(pos) = self.pending.iter().position(|entry| entry.id == *id) {
            if let Some(mut removed) = self.pending.remove(pos) {
                self.pending_bytes -= removed.wire.len();
                removed.wire.fill(0);
            }
        }
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub fn queue_pull(&mut self, target: PeerRef, id: [u8; 16], wire: Vec<u8>) {
        while self.pull_outbox.len() >= PULL_OUTBOX_MAX {
            if let Some((_, _, mut old)) = self.pull_outbox.pop_front() {
                old.fill(0);
            }
        }
        self.pull_outbox.push_back((target, id, wire));
    }

    pub fn new(
        role: ChannelRole,
        own_route: OwnedChannelRoute,
        seed: u64,
        title: String,
        visibility: ChannelVisibility,
    ) -> Self {
        let cfg = OverlayConfig {
            origin_fanout: 8,
            forward_fanout: 1,
            forward_prob: 0.1,
            ..OverlayConfig::default()
        };
        ChannelState {
            id: role.channel_id(),
            title,
            visibility,
            overlay: Overlay::new(peer_id(&own_route.public), cfg, seed),
            role,
            own_route,
            previous_own_route: None,
            directory: HashMap::new(),
            id_to_ref: HashMap::new(),
            recent: VecDeque::new(),
            cell_cache: HashMap::new(),
            cache_order: VecDeque::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            pull_outbox: VecDeque::new(),
            out_of_order: std::collections::BTreeMap::new(),
            future_message_count: 0,
            future_message_bytes: 0,
            membership_outbox: None,
            membership_done: Arc::new(tokio::sync::Notify::new()),
            pending_control: VecDeque::new(),
            route_announcement: None,
            admission_cache: HashMap::new(),
            admission_cache_order: VecDeque::new(),
            invites: HashMap::new(),
            invite_order: VecDeque::new(),
            completed_removals: HashSet::new(),
            commit_ack_cache: HashMap::new(),
            commit_ack_order: VecDeque::new(),
            unrouted_ack_journal: HashMap::new(),
            unrouted_ack_order: VecDeque::new(),
            message_outbox: HashMap::new(),
            seen_direct: VecDeque::new(),
            seen_pex: VecDeque::new(),
        }
    }

    pub fn roster(&self) -> Vec<ChannelMemberSummary> {
        let own = self.role.own_pseudonym();
        let metadata = metadata::Metadata::read(&self.role).unwrap_or_default();
        let mut roster = self
            .role
            .roster_members()
            .into_iter()
            .map(|member| ChannelMemberSummary {
                member_id: member.pseudonym,
                display_name: metadata
                    .nickname(member.pseudonym)
                    .map(str::to_owned)
                    .unwrap_or(member.display_name),
                is_self: member.pseudonym == own,
                join_order: member.leaf_index,
                joined_at_unix: None,
            })
            .collect::<Vec<_>>();
        roster.sort_by_key(|member| member.join_order);
        roster
    }

    pub fn can_journal_unrouted_ack(&self, key: &UnroutedAckKey) -> bool {
        self.unrouted_ack_journal.contains_key(key)
            || self.unrouted_ack_journal.len() < CHANNEL_ACK_LIMIT
    }

    pub fn journal_unrouted_ack(&mut self, key: UnroutedAckKey, mut wire: Vec<u8>) -> bool {
        if let Some(existing) = self.unrouted_ack_journal.get(&key) {
            let exact_duplicate = existing == &wire;
            wire.fill(0);
            return exact_duplicate;
        }
        if self.unrouted_ack_journal.len() >= CHANNEL_ACK_LIMIT {
            wire.fill(0);
            return false;
        }
        self.unrouted_ack_order.push_back(key);
        self.unrouted_ack_journal.insert(key, wire);
        true
    }

    pub fn cache_ack(&mut self, original_id: [u8; 16], route: ChannelRoute, wire: Vec<u8>) {
        if let Some((_, mut replaced)) = self.commit_ack_cache.insert(original_id, (route, wire)) {
            replaced.fill(0);
            return;
        }
        self.commit_ack_order.push_back(original_id);
        while self.commit_ack_order.len() > CHANNEL_ACK_LIMIT {
            if let Some(oldest) = self.commit_ack_order.pop_front() {
                if let Some((_, mut wire)) = self.commit_ack_cache.remove(&oldest) {
                    wire.fill(0);
                }
            }
        }
    }

    pub fn promote_unrouted_acks(&mut self, route: &ChannelRoute) -> Vec<Vec<u8>> {
        let available = CHANNEL_ACK_LIMIT.saturating_sub(self.pending_control.len());
        if available == 0 {
            return Vec::new();
        }
        let keys = self
            .unrouted_ack_order
            .iter()
            .filter(|key| key.sender_pseudonym == route.pseudonym)
            .take(available)
            .copied()
            .collect::<Vec<_>>();
        let mut scheduled = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(wire) = self.unrouted_ack_journal.remove(&key) else {
                continue;
            };
            self.unrouted_ack_order
                .retain(|candidate| candidate != &key);
            let scheduled_wire = wire.clone();
            self.cache_ack(key.original_id, route.clone(), wire.clone());
            self.pending_control.push_back((route.clone(), wire));
            scheduled.push(scheduled_wire);
        }
        scheduled
    }

    /// The caller must first authenticate the MLS directory sender and bind the
    /// name/pseudonym to its roster. PEX and bootstrap learning cannot call this.
    /// Activate the overlay with `learn` only after the durable state commit.
    pub(crate) fn install_authenticated_route(
        &mut self,
        name: &str,
        route: &ChannelRoute,
    ) -> Option<AuthenticatedRouteChange> {
        let id = peer_id(route);
        if !route.is_valid()
            || self
                .id_to_ref
                .get(&id)
                .is_some_and(|known| known.pseudonym != route.pseudonym)
            || self.directory.get(name).is_some_and(|known| {
                known.pseudonym != route.pseudonym
                    || route.data.expiry < known.data.expiry
                    || route.control.expiry < known.control.expiry
            })
        {
            return None;
        }
        // Alias epochs are random identifiers, not revisions. Expiry is the
        // only ordering in the existing payload; equal expiries cannot order
        // two different authenticated contacts and remain admissible.
        let peer = PeerRef::from_route(route);
        let mut change = AuthenticatedRouteChange {
            name: name.to_string(),
            pseudonym: route.pseudonym,
            directory: self.directory.insert(name.to_string(), route.clone()),
            peer: self.id_to_ref.insert(id, peer.clone()),
            messages: Vec::new(),
            membership: None,
            controls: Vec::new(),
            acks: Vec::new(),
            pulls: Vec::new(),
        };
        for (message_id, outbox) in &mut self.message_outbox {
            if let Some(expected) = outbox.expected.get_mut(&route.pseudonym) {
                change
                    .messages
                    .push((*message_id, std::mem::replace(expected, route.clone())));
            }
        }
        if let Some(expected) = self
            .membership_outbox
            .as_mut()
            .and_then(|outbox| outbox.expected.get_mut(&route.pseudonym))
        {
            change.membership = Some(std::mem::replace(expected, route.clone()));
        }
        for (index, (target, _)) in self.pending_control.iter_mut().enumerate() {
            if target.pseudonym == route.pseudonym {
                change
                    .controls
                    .push((index, std::mem::replace(target, route.clone())));
            }
        }
        for (message_id, (target, _)) in &mut self.commit_ack_cache {
            if target.pseudonym == route.pseudonym {
                change
                    .acks
                    .push((*message_id, std::mem::replace(target, route.clone())));
            }
        }
        for (index, (target, _, _)) in self.pull_outbox.iter_mut().enumerate() {
            if target.pseudonym == route.pseudonym {
                change
                    .pulls
                    .push((index, std::mem::replace(target, peer.clone())));
            }
        }
        Some(change)
    }

    /// Called under the same state lock, before queues or overlay membership
    /// can change. For a batch, unwind these records in reverse order.
    pub(crate) fn rollback_authenticated_route(&mut self, change: AuthenticatedRouteChange) {
        if let Some(previous) = change.directory {
            self.directory.insert(change.name, previous);
        } else {
            self.directory.remove(&change.name);
        }
        let id = peer_id_from_pseudonym(&change.pseudonym);
        if let Some(previous) = change.peer {
            self.id_to_ref.insert(id, previous);
        } else {
            self.id_to_ref.remove(&id);
        }
        for (message_id, previous) in change.messages {
            self.message_outbox
                .get_mut(&message_id)
                .expect("outbox retained during route installation")
                .expected
                .insert(change.pseudonym, previous);
        }
        if let Some(previous) = change.membership {
            self.membership_outbox
                .as_mut()
                .expect("membership retained during route installation")
                .expected
                .insert(change.pseudonym, previous);
        }
        for (index, previous) in change.controls {
            self.pending_control[index].0 = previous;
        }
        for (message_id, previous) in change.acks {
            self.commit_ack_cache
                .get_mut(&message_id)
                .expect("ACK retained during route installation")
                .0 = previous;
        }
        for (index, previous) in change.pulls {
            self.pull_outbox[index].0 = previous;
        }
    }

    pub fn learn(&mut self, route: &ChannelRoute) {
        let id = peer_id(route);
        if self
            .id_to_ref
            .get(&id)
            .is_some_and(|known| known.pseudonym != route.pseudonym || known.contact != route.data)
        {
            return;
        }
        let r = PeerRef::from_route(route);
        self.id_to_ref.entry(id).or_insert(r);
        self.overlay.view.absorb(PeerDescriptor {
            id,
            pseudonym: route.pseudonym,
        });
    }

    pub fn learn_ref(&mut self, r: &PeerRef) {
        if peer_id_from_pseudonym(&r.pseudonym) != r.id {
            return;
        }
        if let Some(known) = self.id_to_ref.get(&r.id) {
            if known != r {
                return;
            }
        }
        if !self
            .directory
            .values()
            .any(|route| route.pseudonym == r.pseudonym && route.data == r.contact)
        {
            return;
        }
        self.id_to_ref.entry(r.id).or_insert_with(|| r.clone());
        self.overlay.view.absorb(PeerDescriptor {
            id: r.id,
            pseudonym: r.pseudonym,
        });
    }

    pub fn resolve(&self, id: &NodeId) -> Option<PeerRef> {
        self.id_to_ref.get(id).cloned()
    }

    pub fn note(&mut self, id: [u8; 16], wire: Vec<u8>) {
        self.recent.push_back(id);
        if self.recent.len() > 512 {
            self.recent.pop_front();
        }
        self.cell_cache.insert(id, wire);
        self.cache_order.push_back(id);
        while self.cache_order.len() > 512 {
            if let Some(old) = self.cache_order.pop_front() {
                if let Some(mut wire) = self.cell_cache.remove(&old) {
                    wire.fill(0);
                }
            }
        }
    }

    pub fn have_list(&self) -> Vec<[u8; 16]> {
        self.recent.iter().rev().take(16).copied().collect()
    }

    pub(crate) fn park_future_message(
        &mut self,
        current_epoch: u64,
        message_epoch: u64,
        mut wire: Vec<u8>,
    ) -> Result<(), FutureMessageRejection> {
        let Some(distance) = message_epoch.checked_sub(current_epoch) else {
            wire.fill(0);
            return Err(FutureMessageRejection::NotFuture);
        };
        let rejection = if distance == 0 {
            Some(FutureMessageRejection::NotFuture)
        } else if distance > FUTURE_EPOCH_DISTANCE_LIMIT {
            Some(FutureMessageRejection::EpochDistance)
        } else if self.future_message_count >= FUTURE_MESSAGE_COUNT_LIMIT {
            Some(FutureMessageRejection::CountLimit)
        } else if wire.len() > FUTURE_MESSAGE_BYTES_LIMIT.saturating_sub(self.future_message_bytes)
        {
            Some(FutureMessageRejection::BytesLimit)
        } else {
            None
        };
        if let Some(rejection) = rejection {
            wire.fill(0);
            return Err(rejection);
        }
        self.future_message_count += 1;
        self.future_message_bytes += wire.len();
        self.out_of_order
            .entry(message_epoch)
            .or_default()
            .push(wire);
        Ok(())
    }

    pub(crate) fn take_ready_out_of_order(&mut self, current_epoch: u64) -> Option<Vec<Vec<u8>>> {
        let epoch = self.out_of_order.keys().next().copied()?;
        if epoch > current_epoch {
            return None;
        }
        let wires = self.out_of_order.remove(&epoch)?;
        let bytes = wires.iter().map(Vec::len).sum::<usize>();
        self.future_message_count = self
            .future_message_count
            .checked_sub(wires.len())
            .expect("future message count accounting");
        self.future_message_bytes = self
            .future_message_bytes
            .checked_sub(bytes)
            .expect("future message byte accounting");
        Some(wires)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FutureMessageRejection {
    NotFuture,
    EpochDistance,
    CountLimit,
    BytesLimit,
}

pub fn encode_join_package(key_package: &[u8], route: &ChannelRoute) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        JOIN_PACKAGE_DOMAIN.len() + 1 + CHANNEL_ROUTE_LEN + 4 + key_package.len(),
    );
    encoded.extend_from_slice(JOIN_PACKAGE_DOMAIN);
    encoded.push(1);
    encoded.extend_from_slice(&route.encode());
    encoded.extend_from_slice(&(key_package.len() as u32).to_be_bytes());
    encoded.extend_from_slice(key_package);
    encoded
}

pub fn decode_join_package(encoded: &[u8]) -> Option<(ChannelRoute, &[u8])> {
    let mut position = 0;
    if take(encoded, &mut position, JOIN_PACKAGE_DOMAIN.len())? != JOIN_PACKAGE_DOMAIN
        || take(encoded, &mut position, 1)? != [1]
    {
        return None;
    }
    let route = ChannelRoute::decode(take(encoded, &mut position, CHANNEL_ROUTE_LEN)?)?;
    let key_package_len =
        u32::from_be_bytes(take(encoded, &mut position, 4)?.try_into().ok()?) as usize;
    let key_package = take(encoded, &mut position, key_package_len)?;
    (position == encoded.len()).then_some((route, key_package))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRef {
    pub id: NodeId,
    pub pseudonym: [u8; 32],
    pub contact: crate::alias::AliasContact,
}

impl PeerRef {
    pub fn from_route(route: &ChannelRoute) -> Self {
        PeerRef {
            id: peer_id(route),
            pseudonym: route.pseudonym,
            contact: route.data.clone(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.id.to_le_bytes());
        v.extend_from_slice(&self.pseudonym);
        put_contact(&mut v, &self.contact);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != 8 + 32 + CONTACT_LEN {
            return None;
        }
        let mut p = 0usize;
        let id = u64::from_le_bytes(buf.get(p..p + 8)?.try_into().ok()?);
        p += 8;
        let pseudonym = buf.get(p..p + 32)?.try_into().ok()?;
        p += 32;
        let contact = take_contact(buf, &mut p)?;
        if id != peer_id_from_pseudonym(&pseudonym) {
            return None;
        }
        Some(PeerRef {
            id,
            pseudonym,
            contact,
        })
    }
}

/// PEX uses the established pairwise channel-direct plaintext family, never
/// the shared MLS application ratchet or a raw relay inner cell.
pub fn encode_channel_pex(chan: &str, refs: &[PeerRef], have: &[[u8; 16]]) -> Option<Vec<u8>> {
    if chan.is_empty()
        || chan.len() > u16::MAX as usize
        || refs.is_empty()
        || refs.len() > 8
        || have.len() > 16
    {
        return None;
    }
    let mut encoded = vec![CHANNEL_DIRECT_PEX];
    encoded.extend_from_slice(&encode_pex(chan, refs, have));
    Some(encoded)
}

pub fn decode_channel_pex(plaintext: &[u8]) -> Option<(String, Vec<PeerRef>, Vec<[u8; 16]>)> {
    if plaintext.first() != Some(&CHANNEL_DIRECT_PEX) {
        return None;
    }
    let (channel, refs, have) = decode_pex_bounded(plaintext.get(1..)?, 8, 16)?;
    if channel.is_empty() || refs.is_empty() {
        return None;
    }
    Some((channel, refs, have))
}

pub fn encode_pex(chan: &str, refs: &[PeerRef], have: &[[u8; 16]]) -> Vec<u8> {
    let refs = &refs[..refs.len().min(u8::MAX as usize)];
    let have = &have[..have.len().min(u8::MAX as usize)];
    let mut v = Vec::new();
    v.push(PEX_VERSION);
    v.extend_from_slice(&(chan.len() as u16).to_be_bytes());
    v.extend_from_slice(chan.as_bytes());
    v.push(refs.len() as u8);
    for r in refs {
        v.extend_from_slice(&r.encode());
    }
    v.push(have.len() as u8);
    for id in have {
        v.extend_from_slice(id);
    }
    v
}

pub fn decode_pex(payload: &[u8]) -> Option<(String, Vec<PeerRef>, Vec<[u8; 16]>)> {
    decode_pex_bounded(payload, u8::MAX as usize, u8::MAX as usize)
}

fn decode_pex_bounded(
    payload: &[u8],
    refs_limit: usize,
    have_limit: usize,
) -> Option<(String, Vec<PeerRef>, Vec<[u8; 16]>)> {
    if payload.first() != Some(&PEX_VERSION) {
        return None;
    }
    let mut p = 1usize;
    let clen = u16::from_be_bytes([*payload.get(p)?, *payload.get(p + 1)?]) as usize;
    p += 2;
    let chan = String::from_utf8(payload.get(p..p + clen)?.to_vec()).ok()?;
    p += clen;
    let dcount = *payload.get(p)? as usize;
    if dcount > refs_limit {
        return None;
    }
    p += 1;
    let mut refs = Vec::new();
    for _ in 0..dcount {
        let start = p;
        let consumed = 8 + 32 + CONTACT_LEN;
        let r = PeerRef::decode(payload.get(start..start + consumed)?)?;
        p += consumed;
        refs.push(r);
    }
    let hcount = *payload.get(p)? as usize;
    if hcount > have_limit {
        return None;
    }
    p += 1;
    let mut have = Vec::new();
    for _ in 0..hcount {
        let mut id = [0u8; 16];
        id.copy_from_slice(payload.get(p..p + 16)?);
        p += 16;
        have.push(id);
    }
    (p == payload.len()).then_some((chan, refs, have))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRoute {
    pub pseudonym: [u8; 32],
    pub direct_public: [u8; 32],
    pub data: AliasContact,
    pub control: AliasContact,
}

impl ChannelRoute {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(CHANNEL_ROUTE_LEN);
        encoded.push(CHANNEL_ROUTE_VERSION);
        encoded.extend_from_slice(&self.pseudonym);
        encoded.extend_from_slice(&self.direct_public);
        put_contact(&mut encoded, &self.data);
        put_contact(&mut encoded, &self.control);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        let version = *encoded.first()?;
        if !matches!(
            (version, encoded.len()),
            (1, LEGACY_CHANNEL_ROUTE_LEN) | (CHANNEL_ROUTE_VERSION, CHANNEL_ROUTE_LEN)
        ) {
            return None;
        }
        let mut position = 1;
        let pseudonym = take(encoded, &mut position, 32)?.try_into().ok()?;
        let direct_public = if version == CHANNEL_ROUTE_VERSION {
            take(encoded, &mut position, 32)?.try_into().ok()?
        } else {
            [0; 32]
        };
        let data = take_contact(encoded, &mut position)?;
        let control = take_contact(encoded, &mut position)?;
        let route = Self {
            pseudonym,
            direct_public,
            data,
            control,
        };
        route.is_valid().then_some(route)
    }

    pub fn is_valid(&self) -> bool {
        if self.pseudonym == [0; 32]
            || self.data.epoch == 0
            || self.control.epoch == 0
            || self.data.expiry == 0
            || self.control.expiry == 0
        {
            return false;
        }
        let values = [
            &self.data.queue_id,
            &self.data.push_cap,
            &self.control.queue_id,
            &self.control.push_cap,
        ];
        values.iter().all(|value| **value != [0; 32])
            && (0..values.len())
                .all(|left| (left + 1..values.len()).all(|right| values[left] != values[right]))
    }
}

pub struct OwnedChannelRoute {
    pub public: ChannelRoute,
    pub direct_secret: [u8; 32],
    pub aliases: Vec<OwnedAlias>,
}

fn peer_id_from_pseudonym(pseudonym: &[u8; 32]) -> NodeId {
    u64::from_le_bytes(
        Sha256::digest(pseudonym)[..8]
            .try_into()
            .expect("fixed slice"),
    )
}

fn put_contact(encoded: &mut Vec<u8>, contact: &AliasContact) {
    match contact.target.address.ip() {
        std::net::IpAddr::V4(ip) => {
            encoded.push(4);
            encoded.extend_from_slice(&ip.octets());
            encoded.extend_from_slice(&[0; 12]);
        }
        std::net::IpAddr::V6(ip) => {
            encoded.push(6);
            encoded.extend_from_slice(&ip.octets());
        }
    }
    encoded.extend_from_slice(&contact.target.address.port().to_be_bytes());
    encoded.extend_from_slice(&contact.target.relay_service_id);
    encoded.extend_from_slice(&contact.queue_id);
    encoded.extend_from_slice(&contact.epoch.to_be_bytes());
    encoded.extend_from_slice(&contact.push_cap);
    encoded.extend_from_slice(&contact.expiry.to_be_bytes());
}

fn take<'a>(encoded: &'a [u8], position: &mut usize, length: usize) -> Option<&'a [u8]> {
    let value = encoded.get(*position..position.checked_add(length)?)?;
    *position += length;
    Some(value)
}

fn take_contact(encoded: &[u8], position: &mut usize) -> Option<AliasContact> {
    let family = *take(encoded, position, 1)?.first()?;
    let address: [u8; 16] = take(encoded, position, 16)?.try_into().ok()?;
    let ip = match family {
        4 if address[4..].iter().all(|byte| *byte == 0) => std::net::IpAddr::V4(
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&address[..4]).ok()?),
        ),
        6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(address)),
        _ => return None,
    };
    let port = u16::from_be_bytes(take(encoded, position, 2)?.try_into().ok()?);
    Some(AliasContact {
        target: RelayTarget {
            address: std::net::SocketAddr::new(ip, port),
            relay_service_id: take(encoded, position, 32)?.try_into().ok()?,
        },
        queue_id: take(encoded, position, 32)?.try_into().ok()?,
        epoch: u64::from_be_bytes(take(encoded, position, 8)?.try_into().ok()?),
        push_cap: take(encoded, position, 32)?.try_into().ok()?,
        expiry: u64::from_be_bytes(take(encoded, position, 8)?.try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(byte: u8) -> AliasContact {
        AliasContact {
            target: RelayTarget {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [byte; 32],
            },
            queue_id: [byte.wrapping_add(1); 32],
            epoch: u64::from(byte) + 1,
            push_cap: [byte.wrapping_add(2); 32],
            expiry: 10_000,
        }
    }

    fn route(byte: u8) -> ChannelRoute {
        ChannelRoute {
            pseudonym: [byte; 32],
            direct_public: [byte.wrapping_add(1); 32],
            data: contact(byte.wrapping_add(10)),
            control: contact(byte.wrapping_add(20)),
        }
    }

    fn owned(route: ChannelRoute) -> OwnedChannelRoute {
        OwnedChannelRoute {
            public: route,
            direct_secret: [1; 32],
            aliases: Vec::new(),
        }
    }

    fn state() -> ChannelState {
        let owner = gcoms_mls::OwnerSession::create(
            gcoms_crypto::IdentityKeypair::from_seed([0x5A; 32]),
            "founder",
            8,
        )
        .unwrap();
        let mut own = route(1);
        // Preserve the full MLS pseudonym; repeating its first random byte
        // occasionally made the owner identical to a fixture peer.
        own.pseudonym = owner.own_pseudonym();
        ChannelState::new(
            ChannelRole::Owner(owner),
            owned(own),
            42,
            "ops".into(),
            ChannelVisibility::Private,
        )
    }

    #[test]
    fn learn_feeds_overlay_and_pex() {
        let mut cs = state();
        let other = route(9);
        cs.directory.insert("other".into(), other.clone());
        cs.learn(&other);
        let (partner, descs) = cs.overlay.pex_outbound().expect("pex partner");
        assert_eq!(partner, peer_id(&other));
        assert_eq!(descs.len(), 2, "self + absorbed other");
        assert!(cs.id_to_ref.contains_key(&partner));
        let pending_id = msg_id("ops", b"wire");
        cs.note(pending_id, b"wire".to_vec());
        cs.enqueue_forward(pending_id, b"wire".to_vec());
        assert_eq!(cs.have_list().len(), 1);
        assert!(cs.cell_cache.contains_key(&pending_id));
    }

    #[test]
    fn authenticated_route_rebinds_retained_targets_without_changing_delivery_state() {
        let mut cs = state();
        let historical_owned_route = route(77);
        cs.previous_own_route = Some(owned(historical_owned_route.clone()));
        let old = route(9);
        let other = route(8);
        cs.directory.insert("member".into(), old.clone());
        cs.learn(&old);
        let mut fresh = old.clone();
        fresh.data = contact(31);
        fresh.control = contact(41);
        fresh.data.expiry += 100;
        fresh.control.expiry += 100;
        // Alias epochs are random and may decrease across relay replacement.
        fresh.data.epoch = 1;
        fresh.control.epoch = 1;
        let expected = HashMap::from([
            (old.pseudonym, old.clone()),
            (other.pseudonym, other.clone()),
        ]);
        let acknowledged = HashSet::from([other.pseudonym]);
        let message_id = [1; 16];
        let message_wire = b"exact retained MLS application".to_vec();
        cs.message_outbox.insert(
            message_id,
            ChannelMessageOutbox {
                wire: message_wire.clone(),
                expected: expected.clone(),
                acknowledged: acknowledged.clone(),
            },
        );
        cs.membership_outbox = Some(MembershipOutbox {
            commit_id: [2; 16],
            epoch: 7,
            commit: b"exact retained MLS commit".to_vec(),
            expected: expected.clone(),
            acknowledged: acknowledged.clone(),
        });
        let mut historical = old.clone();
        historical.control.expiry -= 1;
        cs.pending_control
            .push_back((historical.clone(), b"exact queued ACK".to_vec()));
        cs.pending_control
            .push_back((other.clone(), b"other queued ACK".to_vec()));
        cs.cache_ack([3; 16], historical.clone(), b"exact cached ACK".to_vec());
        cs.queue_pull(
            PeerRef::from_route(&old),
            [4; 16],
            b"exact pull wire".to_vec(),
        );
        cs.enqueue_forward(message_id, message_wire.clone());
        let unrouted = UnroutedAckKey {
            original_id: [5; 16],
            sender_pseudonym: old.pseudonym,
        };
        assert!(cs.journal_unrouted_ack(unrouted, b"unrouted ACK".to_vec()));
        let pending = cs.pending.clone();
        let pending_bytes = cs.pending_bytes();
        let controls = cs.pending_control.clone();
        let cached = cs.commit_ack_cache.clone();
        let cache_order = cs.commit_ack_order.clone();
        let pulls = cs.pull_outbox.clone();

        let change = cs
            .install_authenticated_route("member", &fresh)
            .expect("authenticated replacement");
        cs.learn(&fresh);
        assert!(cs.overlay.view.contains(peer_id(&old)));
        assert_eq!(
            cs.resolve(&peer_id(&old)),
            Some(PeerRef::from_route(&fresh))
        );
        assert_eq!(cs.directory["member"], fresh);
        let mut rebound = expected.clone();
        rebound.insert(old.pseudonym, fresh.clone());
        let message = &cs.message_outbox[&message_id];
        assert_eq!(message.wire, message_wire);
        assert_eq!(message.expected, rebound);
        assert_eq!(message.acknowledged, acknowledged);
        let membership = cs.membership_outbox.as_ref().unwrap();
        assert_eq!(membership.commit_id, [2; 16]);
        assert_eq!(membership.epoch, 7);
        assert_eq!(membership.commit, b"exact retained MLS commit");
        assert_eq!(membership.expected, rebound);
        assert_eq!(membership.acknowledged, acknowledged);
        assert_eq!(cs.pending_control[0].0, fresh);
        assert_eq!(cs.pending_control[0].1, controls[0].1);
        assert_eq!(cs.pending_control[1], controls[1]);
        assert_eq!(cs.commit_ack_cache[&[3; 16]].0, fresh);
        assert_eq!(cs.commit_ack_cache[&[3; 16]].1, cached[&[3; 16]].1);
        assert_eq!(cs.commit_ack_order, cache_order);
        assert_eq!(cs.pull_outbox[0].0, PeerRef::from_route(&fresh));
        assert_eq!(cs.pull_outbox[0].1, pulls[0].1);
        assert_eq!(cs.pull_outbox[0].2, pulls[0].2);
        assert_eq!(cs.pending, pending);
        assert_eq!(cs.pending_bytes(), pending_bytes);
        assert_eq!(cs.unrouted_ack_journal[&unrouted], b"unrouted ACK");
        assert_eq!(
            cs.previous_own_route.as_ref().unwrap().public,
            historical_owned_route
        );
        assert!(cs.resolve(&peer_id(&historical_owned_route)).is_none());

        cs.rollback_authenticated_route(change);
        assert_eq!(cs.directory["member"], old);
        assert_eq!(cs.resolve(&peer_id(&old)), Some(PeerRef::from_route(&old)));
        assert_eq!(cs.message_outbox[&message_id].expected, expected);
        assert_eq!(cs.message_outbox[&message_id].wire, message_wire);
        assert_eq!(cs.message_outbox[&message_id].acknowledged, acknowledged);
        assert_eq!(cs.membership_outbox.as_ref().unwrap().expected, expected);
        assert_eq!(cs.pending_control, controls);
        assert_eq!(cs.commit_ack_cache, cached);
        assert_eq!(cs.pull_outbox, pulls);
        assert_eq!(cs.pending, pending);
    }

    #[test]
    fn authenticated_route_expiries_are_monotonic_while_pex_cannot_replace_contacts() {
        let mut cs = state();
        let old = route(9);
        cs.directory.insert("member".into(), old.clone());
        cs.learn(&old);
        let mut replacement = old.clone();
        replacement.data = contact(31);
        replacement.control = contact(41);
        replacement.data.expiry += 100;
        replacement.control.expiry += 100;
        cs.learn(&replacement);
        cs.learn_ref(&PeerRef::from_route(&replacement));
        assert_eq!(cs.resolve(&peer_id(&old)), Some(PeerRef::from_route(&old)));
        cs.install_authenticated_route("member", &replacement)
            .unwrap();
        cs.learn_ref(&PeerRef::from_route(&old));
        assert_eq!(
            cs.resolve(&peer_id(&old)),
            Some(PeerRef::from_route(&replacement))
        );
        assert!(cs.install_authenticated_route("member", &old).is_none());

        let mut renewed = replacement.clone();
        renewed.data.expiry += 100;
        cs.install_authenticated_route("member", &renewed).unwrap();
        assert_eq!(
            cs.resolve(&peer_id(&old)),
            Some(PeerRef::from_route(&renewed))
        );
        let mut reordered_control_renewal = replacement;
        reordered_control_renewal.control.expiry += 200;
        assert!(cs
            .install_authenticated_route("member", &reordered_control_renewal)
            .is_none());
        assert_eq!(cs.directory["member"], renewed);

        let mut equal_expiry = renewed.clone();
        equal_expiry.data.queue_id = [71; 32];
        cs.install_authenticated_route("member", &equal_expiry)
            .expect("equal expiry carries no route ordering");
        let mut different_member = equal_expiry.clone();
        different_member.pseudonym = [72; 32];
        assert!(cs
            .install_authenticated_route("member", &different_member)
            .is_none());
        assert_eq!(cs.directory["member"], equal_expiry);
    }

    #[test]
    fn authenticated_route_batch_rollback_restores_absent_and_repeated_entries() {
        let mut cs = state();
        let old = route(9);
        let mut renewed = old.clone();
        renewed.data.expiry += 1;
        let first = cs.install_authenticated_route("member", &old).unwrap();
        let second = cs.install_authenticated_route("member", &renewed).unwrap();
        assert!(!cs.overlay.view.contains(peer_id(&old)));
        cs.rollback_authenticated_route(second);
        assert_eq!(cs.directory["member"], old);
        cs.rollback_authenticated_route(first);
        assert!(!cs.directory.contains_key("member"));
        assert!(cs.resolve(&peer_id(&old)).is_none());
        assert!(!cs.overlay.view.contains(peer_id(&old)));
    }

    #[test]
    fn inner_text_roundtrip() {
        let enc = encode_text(b"hello", true);
        match decode_inner(&enc) {
            Some(ChannelInner::Text {
                body,
                ts_ms,
                share_presence,
            }) => {
                assert_eq!(body, b"hello");
                assert!(ts_ms > 0);
                assert!(share_presence);
            }
            _ => panic!("text"),
        }
        let mut legacy = vec![CHAN_TEXT];
        legacy.extend_from_slice(&1u64.to_be_bytes());
        legacy.extend_from_slice(b"legacy");
        assert!(matches!(
            decode_inner(&legacy),
            Some(ChannelInner::Text {
                share_presence: false,
                ..
            })
        ));
    }

    #[test]
    fn inner_presence_is_fixed_width_and_strict() {
        let encoded = encode_presence(7, crate::proto::PresenceMode::Away, 60).unwrap();
        assert_eq!(encoded.len(), 14);
        assert!(matches!(
            decode_inner(&encoded),
            Some(ChannelInner::PresenceLease {
                counter: 7,
                mode: crate::proto::PresenceMode::Away,
                lease_secs: 60,
            })
        ));
        assert!(encode_presence(0, crate::proto::PresenceMode::Away, 60).is_none());
        assert!(encode_presence(8, crate::proto::PresenceMode::Invisible, 60).is_none());
        assert!(encode_presence(8, crate::proto::PresenceMode::Invisible, 0).is_some());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_inner(&trailing).is_none());
    }

    #[test]
    fn inner_dir_roundtrip() {
        let route = route(7);
        let enc = encode_dir("redwing", &route);
        match decode_inner(&enc) {
            Some(ChannelInner::Dir(name, decoded)) => {
                assert_eq!(name, "redwing");
                assert_eq!(*decoded, route);
            }
            _ => panic!("dir"),
        }
    }

    #[test]
    fn inner_dir_batch_roundtrip_rejects_trailing_data() {
        let entries = vec![
            ("owner".to_string(), route(1)),
            ("member".to_string(), route(2)),
        ];
        let encoded = encode_dir_batch(&entries).unwrap();
        match decode_inner(&encoded) {
            Some(ChannelInner::DirBatch(decoded)) => assert_eq!(decoded, entries),
            _ => panic!("directory batch"),
        }

        let mut malformed = encoded;
        malformed.push(0);
        assert!(decode_inner(&malformed).is_none());
        assert!(encode_dir_batch(&[]).is_none());
        assert!(encode_dir_batch(&vec![entries[0].clone(); CHANNEL_DIR_BATCH_LIMIT + 1]).is_none());
    }

    #[test]
    fn pex_have_list_is_bounded_without_count_wrap() {
        let mut cs = state();
        for i in 0..300u16 {
            let mut id = [0u8; 16];
            id[..2].copy_from_slice(&i.to_be_bytes());
            cs.note(id, vec![i as u8]);
        }

        let have = cs.have_list();
        assert_eq!(have.len(), 16);
        let encoded = encode_pex("ops", &[], &have);
        let (_, _, decoded) = decode_pex(&encoded).unwrap();
        assert_eq!(decoded, have);
    }

    #[test]
    fn out_of_order_message_waits_for_its_epoch() {
        let mut cs = state();
        cs.park_future_message(3, 4, b"future".to_vec()).unwrap();

        assert!(cs.take_ready_out_of_order(3).is_none());
        assert_eq!(cs.out_of_order.get(&4).unwrap().len(), 1);
        assert_eq!(cs.future_message_count, 1);
        assert_eq!(cs.future_message_bytes, 6);
        assert_eq!(
            cs.take_ready_out_of_order(4).unwrap(),
            vec![b"future".to_vec()]
        );
        assert!(cs.out_of_order.is_empty());
        assert_eq!(cs.future_message_count, 0);
        assert_eq!(cs.future_message_bytes, 0);
    }

    #[test]
    fn thousands_of_unique_future_records_leave_bounded_state() {
        let mut cs = state();
        for record in 0..10_000u64 {
            let mut wire = vec![0xA5; 64];
            wire[..8].copy_from_slice(&record.to_be_bytes());
            let _ = cs.park_future_message(10, 11 + record % 8, wire);
        }

        assert_eq!(cs.future_message_count, FUTURE_MESSAGE_COUNT_LIMIT);
        assert_eq!(cs.future_message_bytes, FUTURE_MESSAGE_COUNT_LIMIT * 64);
        assert_eq!(
            cs.out_of_order.values().map(Vec::len).sum::<usize>(),
            FUTURE_MESSAGE_COUNT_LIMIT
        );
        assert!(cs.out_of_order.len() <= FUTURE_EPOCH_DISTANCE_LIMIT as usize);
    }

    #[test]
    fn future_epoch_distance_and_total_bytes_are_enforced() {
        let mut cs = state();
        assert_eq!(
            cs.park_future_message(20, 29, vec![0xCC; 32]),
            Err(FutureMessageRejection::EpochDistance)
        );
        assert!(cs.out_of_order.is_empty());
        assert_eq!(cs.future_message_count, 0);
        assert_eq!(cs.future_message_bytes, 0);

        let half = FUTURE_MESSAGE_BYTES_LIMIT / 2;
        cs.park_future_message(20, 21, vec![1; half]).unwrap();
        cs.park_future_message(20, 22, vec![2; half]).unwrap();
        assert_eq!(
            cs.park_future_message(20, 23, vec![3]),
            Err(FutureMessageRejection::BytesLimit)
        );
        assert_eq!(cs.future_message_count, 2);
        assert_eq!(cs.future_message_bytes, FUTURE_MESSAGE_BYTES_LIMIT);

        assert_eq!(cs.take_ready_out_of_order(21).unwrap().len(), 1);
        assert_eq!(cs.future_message_count, 1);
        assert_eq!(cs.future_message_bytes, half);
        assert_eq!(cs.take_ready_out_of_order(22).unwrap().len(), 1);
        assert_eq!(cs.future_message_count, 0);
        assert_eq!(cs.future_message_bytes, 0);
    }

    #[test]
    fn pex_cannot_add_or_overwrite_authenticated_routes() {
        let mut cs = state();
        let known = route(7);
        cs.directory.insert("known".into(), known.clone());
        cs.learn(&known);
        let known_id = peer_id(&known);
        let original = cs.resolve(&known_id).unwrap();
        let mut poisoned = original.clone();
        poisoned.contact.queue_id = [99; 32];
        cs.learn_ref(&poisoned);
        assert_eq!(cs.resolve(&known_id), Some(original));

        let mut unknown = poisoned;
        unknown.id = known_id.wrapping_add(1);
        cs.learn_ref(&unknown);
        assert!(cs.resolve(&unknown.id).is_none());
    }

    #[test]
    fn encrypted_pex_inner_rejects_missing_oversized_and_noncanonical_fields() {
        let peer = PeerRef::from_route(&route(33));
        let encoded = encode_channel_pex("room", std::slice::from_ref(&peer), &[[4; 16]]).unwrap();
        assert!(
            matches!(decode_channel_pex(&encoded), Some((channel, refs, have))
            if channel == "room" && refs == vec![peer.clone()] && have == vec![[4; 16]])
        );
        for (channel, refs, have) in [
            ("", vec![peer.clone()], vec![]),
            ("room", vec![], vec![]),
            ("room", vec![peer.clone(); 9], vec![]),
            ("room", vec![peer.clone()], vec![[4; 16]; 17]),
        ] {
            assert!(encode_channel_pex(channel, &refs, &have).is_none());
            let mut raw = vec![CHANNEL_DIRECT_PEX];
            raw.extend_from_slice(&encode_pex(channel, &refs, &have));
            assert!(decode_channel_pex(&raw).is_none());
        }
        for end in 0..encoded.len() {
            assert!(decode_channel_pex(&encoded[..end]).is_none());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_channel_pex(&trailing).is_none());
    }

    #[test]
    fn route_and_pex_codecs_are_canonical_and_channel_local() {
        let route = route(33);
        let encoded = route.encode();
        assert_eq!(ChannelRoute::decode(&encoded), Some(route.clone()));
        assert!(ChannelRoute::decode(&encoded[..encoded.len() - 1]).is_none());
        let mut legacy_version_with_v2_length = encoded.clone();
        legacy_version_with_v2_length[0] = 1;
        assert!(ChannelRoute::decode(&legacy_version_with_v2_length).is_none());
        let mut v2_without_direct_key = encoded.clone();
        v2_without_direct_key.drain(33..65);
        assert!(ChannelRoute::decode(&v2_without_direct_key).is_none());
        let pex = encode_pex("ops", &[PeerRef::from_route(&route)], &[[4; 16]]);
        let (_, refs, have) = decode_pex(&pex).unwrap();
        assert_eq!(refs, vec![PeerRef::from_route(&route)]);
        assert_eq!(have, vec![[4; 16]]);
        let mut trailing = pex;
        trailing.push(0);
        assert!(decode_pex(&trailing).is_none());

        let mut non_independent = route;
        non_independent.control.queue_id = non_independent.data.queue_id;
        assert!(ChannelRoute::decode(&non_independent.encode()).is_none());
    }

    #[test]
    fn routes_for_two_channels_are_unlinkable() {
        let left = route(40);
        let right = route(41);
        assert_ne!(left.pseudonym, right.pseudonym);
        assert_ne!(left.data.queue_id, right.data.queue_id);
        assert_ne!(left.control.queue_id, right.control.queue_id);
        assert_ne!(peer_id(&left), peer_id(&right));
    }

    #[test]
    fn join_package_binds_route_to_fresh_mls_leaf() {
        let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
        let key_package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let mut route = route(50);
        route.pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
        let encoded = encode_join_package(&key_package, &route);
        let (decoded_route, decoded_key_package) = decode_join_package(&encoded).unwrap();
        assert_eq!(decoded_route, route);
        assert_eq!(decoded_key_package, key_package);
        assert_eq!(
            gcoms_mls::pseudonym_of_key_package(decoded_key_package),
            Some(decoded_route.pseudonym)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_join_package(&trailing).is_none());
    }

    #[test]
    fn unrouted_ack_journal_rejects_new_entries_at_bound_and_promotes_exact_wire() {
        let mut cs = state();
        let sender = route(9);
        let first_key = UnroutedAckKey {
            original_id: [1; 16],
            sender_pseudonym: sender.pseudonym,
        };
        assert!(cs.journal_unrouted_ack(first_key, b"exact MLS ACK".to_vec()));
        assert!(cs.journal_unrouted_ack(first_key, b"exact MLS ACK".to_vec()));
        assert!(!cs.journal_unrouted_ack(first_key, b"different MLS ACK".to_vec()));
        for byte in 2..=CHANNEL_ACK_LIMIT as u8 {
            assert!(cs.journal_unrouted_ack(
                UnroutedAckKey {
                    original_id: [byte; 16],
                    sender_pseudonym: sender.pseudonym,
                },
                vec![byte],
            ));
        }
        assert_eq!(cs.unrouted_ack_journal.len(), CHANNEL_ACK_LIMIT);
        assert!(!cs.journal_unrouted_ack(
            UnroutedAckKey {
                original_id: [0xFE; 16],
                sender_pseudonym: sender.pseudonym,
            },
            b"rejected".to_vec(),
        ));

        let promoted = cs.promote_unrouted_acks(&sender);
        assert_eq!(promoted.len(), CHANNEL_ACK_LIMIT);
        assert_eq!(promoted[0], b"exact MLS ACK");
        assert!(cs.unrouted_ack_journal.is_empty());
        assert_eq!(cs.pending_control[0].1, b"exact MLS ACK");
        assert_eq!(
            cs.commit_ack_cache.get(&first_key.original_id).unwrap().1,
            b"exact MLS ACK"
        );
    }
}
