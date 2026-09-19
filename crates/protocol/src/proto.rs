use crate::alias::{AliasContact, OwnedAlias, RelayProvision};
use crate::lease::{Capabilities, LeaseLimits};
use crate::relay::RelayTarget;
use alloc::collections::VecDeque;
use alloc::{string::String, vec, vec::Vec};
use gcoms_core::{Cell, CellType};
use gcoms_crypto::session::{FirstMove, Frame};
use gcoms_crypto::Bundle;
use sha2::{Digest, Sha256};

pub const KIND_FIRST_MOVE: u8 = 0;
pub const KIND_FRAME: u8 = 1;
pub const KIND_BUNDLE: u8 = 2;
pub const KIND_BOOTSTRAP: u8 = 3;
pub const KIND_CHAN: u8 = 4;
const KIND_PROVISIONING: u8 = 5;
pub const KIND_CHANNEL_DIRECT: u8 = 6;
pub const KIND_CHAN_FRAGMENT: u8 = 7;
/// Private relay card carrying an explicit GC/2 introduction advertisement.
/// Version 1 clients reject this kind outright; there is no fallback.
pub const KIND_PROVISIONING_GC2: u8 = 8;
/// Request option asking a relay to advertise its GC/2 introduction.
pub const PROVISION_OPTION_GC2: u8 = 1;
/// Largest advertised GC/2 introduction accepted from a private card.
pub const MAX_PROVISION_GC2_BYTES: usize = 1024;
const CHAN_FRAGMENT_HEADER: usize = 21;
const CHAN_FRAGMENT_SLOTS: usize = 64;
const MAX_CHAN_FRAGMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHAN_FRAGMENTS: usize = 2048;
const INFO_VERSION: u8 = 1;
const DIRECT_VERSION: u8 = 1;
const DIRECT_DATA: u8 = 1;
const DIRECT_ACK: u8 = 2;
const DIRECT_CONTACT_UPDATE: u8 = 3;
const DIRECT_PRESENCE_LEASE: u8 = 4;
const DIRECT_DATA_WITH_PRESENCE: u8 = 5;
const DIRECT_ACK_WITH_PRESENCE: u8 = 6;
const DIRECT_FORWARD_GRANT: u8 = 7;
const DIRECT_INVITE_REDEEM: u8 = 8;
const DIRECT_INVITE_WELCOME: u8 = 9;
const DIRECT_DURABLE_DATA: u8 = 10;
const DIRECT_VOLATILE_APPLICATION: u8 = 11;
/// Upper bound on the encoded body of an invite record, so a malicious peer
/// cannot make us allocate unboundedly from a single sealed frame.
const MAX_INVITE_RECORD_BYTES: usize = 256 * 1024;
const CONTACT_UPDATE_VERSION: u8 = 1;
pub const MAX_CONTACT_UPDATE_BYTES: usize = 64 * 1024;
pub const MAX_BUNDLE_AGE_SECS: u64 = 30 * 24 * 60 * 60;
pub const MIN_PRESENCE_LEASE_SECS: u32 = 30;
pub const MAX_PRESENCE_LEASE_SECS: u32 = 60 * 60;
const CHANNEL_DIRECT_VERSION: u8 = 1;

struct FragmentEntry {
    id: [u8; 16],
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
}

#[derive(Default)]
pub struct ChannelFragmentBuffer {
    entries: VecDeque<FragmentEntry>,
    bytes: usize,
}

impl ChannelFragmentBuffer {
    pub fn push(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.first() != Some(&KIND_CHAN_FRAGMENT) || payload.len() <= CHAN_FRAGMENT_HEADER {
            return None;
        }
        let id: [u8; 16] = payload.get(1..17)?.try_into().ok()?;
        let index = u16::from_be_bytes(payload.get(17..19)?.try_into().ok()?) as usize;
        let total = u16::from_be_bytes(payload.get(19..21)?.try_into().ok()?) as usize;
        if !(2..=MAX_CHAN_FRAGMENTS).contains(&total) || index >= total {
            return None;
        }
        let chunk = payload.get(CHAN_FRAGMENT_HEADER..)?;
        let position = self.entries.iter().position(|entry| entry.id == id);
        let position = match position {
            Some(position) if self.entries[position].parts.len() == total => position,
            Some(position) => {
                self.remove(position);
                return None;
            }
            None => {
                while self.entries.len() >= CHAN_FRAGMENT_SLOTS {
                    self.remove(0);
                }
                self.entries.push_back(FragmentEntry {
                    id,
                    parts: vec![None; total],
                    bytes: 0,
                });
                self.entries.len() - 1
            }
        };
        if let Some(existing) = &self.entries[position].parts[index] {
            if existing.as_slice() != chunk {
                self.remove(position);
            }
            return None;
        }
        if self.bytes.saturating_add(chunk.len()) > MAX_CHAN_FRAGMENT_BYTES {
            self.remove(position);
            return None;
        }
        self.entries[position].parts[index] = Some(chunk.to_vec());
        self.entries[position].bytes += chunk.len();
        self.bytes += chunk.len();
        if self.entries[position].parts.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.remove(position);
        let mut encoded = Vec::with_capacity(entry.bytes);
        for part in entry.parts {
            encoded.extend_from_slice(part.as_deref()?);
        }
        (fragment_id(&encoded) == id).then_some(encoded)
    }

    fn remove(&mut self, position: usize) -> FragmentEntry {
        let entry = self.entries.remove(position).expect("known fragment entry");
        self.bytes = self.bytes.saturating_sub(entry.bytes);
        entry
    }
}

fn fragment_id(encoded: &[u8]) -> [u8; 16] {
    Sha256::digest(encoded)[..16]
        .try_into()
        .expect("SHA-256 prefix")
}

pub fn encode_chan_cells(channel: &str, wire: &[u8]) -> Result<Vec<Cell>, String> {
    if channel.len() > u16::MAX as usize {
        return Err("channel name exceeds framing limit".into());
    }
    let encoded = encode_chan(channel, wire);
    if encoded.len() <= gcoms_core::MAX_MESSAGE {
        return Ok(vec![Cell::new(CellType::Msg, 0, 0, encoded)]);
    }
    if encoded.len() > MAX_CHAN_FRAGMENT_BYTES {
        return Err("channel MLS frame exceeds reassembly limit".into());
    }
    let chunk_size = gcoms_core::MAX_MESSAGE - CHAN_FRAGMENT_HEADER;
    let total = encoded.len().div_ceil(chunk_size);
    let total_u16 = u16::try_from(total).map_err(|_| "too many channel MLS fragments")?;
    if total > MAX_CHAN_FRAGMENTS {
        return Err("too many channel MLS fragments".into());
    }
    let id = fragment_id(&encoded);
    Ok(encoded
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            let mut payload = Vec::with_capacity(CHAN_FRAGMENT_HEADER + chunk.len());
            payload.push(KIND_CHAN_FRAGMENT);
            payload.extend_from_slice(&id);
            payload.extend_from_slice(&(index as u16).to_be_bytes());
            payload.extend_from_slice(&total_u16.to_be_bytes());
            payload.extend_from_slice(chunk);
            Cell::new(CellType::Msg, 0, 0, payload)
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelDirectEnvelope {
    pub channel: String,
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub message_id: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl ChannelDirectEnvelope {
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = b"gc1/channel-direct/envelope/v1\0".to_vec();
        aad.extend_from_slice(&(self.channel.len() as u16).to_be_bytes());
        aad.extend_from_slice(self.channel.as_bytes());
        aad.extend_from_slice(&self.sender);
        aad.extend_from_slice(&self.recipient);
        aad.extend_from_slice(&self.message_id);
        aad
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        let channel_len = u16::try_from(self.channel.len()).ok()?;
        let mut encoded = Vec::with_capacity(97 + self.channel.len() + self.ciphertext.len());
        encoded.extend_from_slice(&[KIND_CHANNEL_DIRECT, CHANNEL_DIRECT_VERSION]);
        encoded.extend_from_slice(&channel_len.to_be_bytes());
        encoded.extend_from_slice(self.channel.as_bytes());
        encoded.extend_from_slice(&self.sender);
        encoded.extend_from_slice(&self.recipient);
        encoded.extend_from_slice(&self.message_id);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.ciphertext);
        Some(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        if encoded.get(..2)? != [KIND_CHANNEL_DIRECT, CHANNEL_DIRECT_VERSION] {
            return None;
        }
        let channel_len = u16::from_be_bytes(encoded.get(2..4)?.try_into().ok()?) as usize;
        let mut position = 4;
        let channel =
            String::from_utf8(encoded.get(position..position + channel_len)?.to_vec()).ok()?;
        position += channel_len;
        let sender = encoded.get(position..position + 32)?.try_into().ok()?;
        position += 32;
        let recipient = encoded.get(position..position + 32)?.try_into().ok()?;
        position += 32;
        let message_id = encoded.get(position..position + 16)?.try_into().ok()?;
        position += 16;
        let nonce = encoded.get(position..position + 12)?.try_into().ok()?;
        position += 12;
        let ciphertext = encoded.get(position..)?.to_vec();
        (!ciphertext.is_empty()).then_some(Self {
            channel,
            sender,
            recipient,
            message_id,
            nonce,
            ciphertext,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectRecord {
    VolatileApplication {
        message_id: [u8; 16],
        sent_ms: u64,
        body: Vec<u8>,
    },
    Data {
        durable: bool,
        message_id: [u8; 16],
        sent_ms: u64,
        share_presence: bool,
        body: Vec<u8>,
    },
    Ack {
        message_id: [u8; 16],
        share_presence: bool,
    },
    ContactUpdate {
        message_id: [u8; 16],
        update: ContactUpdate,
    },
    PresenceLease {
        message_id: [u8; 16],
        counter: u64,
        mode: PresenceMode,
        lease_secs: u32,
    },
    /// The sender offers itself as a FRWD intermediary (SPEC §11.1, §12).
    ForwardGrant {
        message_id: [u8; 16],
        grant: crate::alias::ForwardGrant,
    },
    /// A friend redeems a single-use channel invite: it carries the invite id
    /// and secret plus the friend's encoded channel join package. Sent sealed
    /// over the normal direct-message session, so the relay never sees the
    /// secret. The owner replies with `InviteWelcome`.
    InviteRedeem {
        message_id: [u8; 16],
        channel: String,
        member_name: String,
        invite_id: [u8; 16],
        invite_secret: [u8; 32],
        key_package: Vec<u8>,
    },
    /// The owner's reply to `InviteRedeem`: either the MLS Welcome (on success)
    /// or a short error string ("invite already used", "invite expired", …).
    InviteWelcome {
        message_id: [u8; 16],
        result: Result<Vec<u8>, String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceMode {
    RecentlyReachable,
    Away,
    Invisible,
}

impl PresenceMode {
    fn code(self) -> u8 {
        match self {
            Self::RecentlyReachable => 1,
            Self::Away => 2,
            Self::Invisible => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::RecentlyReachable),
            2 => Some(Self::Away),
            3 => Some(Self::Invisible),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactUpdate {
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub info: NodeInfo,
    pub signature: Vec<u8>,
}

impl ContactUpdate {
    fn unsigned(&self) -> Option<Vec<u8>> {
        let info = self.info.public().encode();
        let info_len = u32::try_from(info.len()).ok()?;
        let mut encoded = Vec::with_capacity(30 + info.len());
        encoded.extend_from_slice(b"gc1/contact-update/v1\0");
        encoded.push(CONTACT_UPDATE_VERSION);
        encoded.extend_from_slice(&self.generation.to_be_bytes());
        encoded.extend_from_slice(&self.issued_at.to_be_bytes());
        encoded.extend_from_slice(&self.expires_at.to_be_bytes());
        encoded.extend_from_slice(&info_len.to_be_bytes());
        encoded.extend_from_slice(&info);
        Some(encoded)
    }

    pub fn sign(
        generation: u64,
        issued_at: u64,
        expires_at: u64,
        info: NodeInfo,
        identity: &gcoms_crypto::IdentityKeypair,
    ) -> Option<Self> {
        let mut update = Self {
            generation,
            issued_at,
            expires_at,
            info: info.public(),
            signature: Vec::new(),
        };
        update.signature = identity.sign(&update.unsigned()?);
        Some(update)
    }

    pub fn verify(&self, established_identity: &[u8], now: u64) -> bool {
        if self.generation == 0
            || self.info.identity_pk != established_identity
            || self.info.provisioning.is_some()
            || self.info.aliases.len() != 2
            || self.issued_at > now.saturating_add(300)
            || self.expires_at <= now
            || self.expires_at > self.issued_at.saturating_add(24 * 60 * 60)
        {
            return false;
        }
        let Some(bundle) = Bundle::decode(&self.info.bundle) else {
            return false;
        };
        if bundle.encode() != self.info.bundle
            || !bundle.verify(established_identity)
            || bundle.created > self.issued_at.saturating_add(300)
            || self.issued_at.saturating_sub(bundle.created) > MAX_BUNDLE_AGE_SECS
        {
            return false;
        }
        let data = &self.info.aliases[0];
        let control = &self.info.aliases[1];
        if data == control
            || data.queue_id == data.push_cap
            || control.queue_id == control.push_cap
            || data.queue_id == control.queue_id
            || data.queue_id == control.push_cap
            || data.push_cap == control.queue_id
            || data.push_cap == control.push_cap
            || self.info.aliases.iter().any(|alias| {
                alias.queue_id == [0; 32]
                    || alias.epoch == 0
                    || alias.push_cap == [0; 32]
                    || alias.target.relay_service_id == [0; 32]
                    || alias.target.address.port() == 0
                    || alias.expiry < self.expires_at
            })
        {
            return false;
        }
        let Some(unsigned) = self.unsigned() else {
            return false;
        };
        gcoms_crypto::verify_signature(established_identity, &unsigned, &self.signature)
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut encoded = self.unsigned()?;
        let signature_len = u16::try_from(self.signature.len()).ok()?;
        encoded.extend_from_slice(&signature_len.to_be_bytes());
        encoded.extend_from_slice(&self.signature);
        (encoded.len() <= MAX_CONTACT_UPDATE_BYTES).then_some(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        if encoded.len() > MAX_CONTACT_UPDATE_BYTES
            || !encoded.starts_with(b"gc1/contact-update/v1\0")
        {
            return None;
        }
        let mut position = b"gc1/contact-update/v1\0".len();
        if *take(encoded, &mut position, 1)?.first()? != CONTACT_UPDATE_VERSION {
            return None;
        }
        let generation = u64::from_be_bytes(take(encoded, &mut position, 8)?.try_into().ok()?);
        let issued_at = u64::from_be_bytes(take(encoded, &mut position, 8)?.try_into().ok()?);
        let expires_at = u64::from_be_bytes(take(encoded, &mut position, 8)?.try_into().ok()?);
        let info_len =
            u32::from_be_bytes(take(encoded, &mut position, 4)?.try_into().ok()?) as usize;
        let info = NodeInfo::decode(take(encoded, &mut position, info_len)?)?;
        let signature_len =
            u16::from_be_bytes(take(encoded, &mut position, 2)?.try_into().ok()?) as usize;
        let signature = take(encoded, &mut position, signature_len)?.to_vec();
        let update = Self {
            generation,
            issued_at,
            expires_at,
            info,
            signature,
        };
        (position == encoded.len() && update.encode().as_deref() == Some(encoded)).then_some(update)
    }
}

pub fn encode_direct_data(
    message_id: [u8; 16],
    sent_ms: u64,
    share_presence: bool,
    body: &[u8],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(26 + usize::from(share_presence) + body.len());
    encoded.extend_from_slice(&[
        DIRECT_VERSION,
        if share_presence {
            DIRECT_DATA_WITH_PRESENCE
        } else {
            DIRECT_DATA
        },
    ]);
    encoded.extend_from_slice(&message_id);
    encoded.extend_from_slice(&sent_ms.to_be_bytes());
    if share_presence {
        encoded.push(1);
    }
    encoded.extend_from_slice(body);
    encoded
}

/// A distinct record kind requires the receiver to persist application bytes
/// before acknowledging. Older peers do not decode or ACK this record kind.
pub fn encode_direct_durable_data(message_id: [u8; 16], sent_ms: u64, body: &[u8]) -> Vec<u8> {
    let mut encoded = encode_direct_data(message_id, sent_ms, false, body);
    encoded[1] = DIRECT_DURABLE_DATA;
    encoded
}

pub fn is_durable_direct_data(encoded: &[u8]) -> bool {
    encoded.len() >= 26 && encoded[..2] == [DIRECT_VERSION, DIRECT_DURABLE_DATA]
}

/// One-use application control data: never retain its logical body or frame.
pub fn encode_volatile_application(message_id: [u8; 16], sent_ms: u64, body: &[u8]) -> Vec<u8> {
    let mut encoded = encode_direct_data(message_id, sent_ms, false, body);
    encoded[1] = DIRECT_VOLATILE_APPLICATION;
    encoded
}
pub fn is_volatile_application(encoded: &[u8]) -> bool {
    encoded.starts_with(&[DIRECT_VERSION, DIRECT_VOLATILE_APPLICATION])
}

pub fn encode_direct_ack(message_id: [u8; 16], share_presence: bool) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(18 + usize::from(share_presence));
    encoded.extend_from_slice(&[
        DIRECT_VERSION,
        if share_presence {
            DIRECT_ACK_WITH_PRESENCE
        } else {
            DIRECT_ACK
        },
    ]);
    encoded.extend_from_slice(&message_id);
    if share_presence {
        encoded.push(1);
    }
    encoded
}

pub fn encode_contact_update(message_id: [u8; 16], update: &ContactUpdate) -> Option<Vec<u8>> {
    let update = update.encode()?;
    let mut encoded = Vec::with_capacity(18 + update.len());
    encoded.extend_from_slice(&[DIRECT_VERSION, DIRECT_CONTACT_UPDATE]);
    encoded.extend_from_slice(&message_id);
    encoded.extend_from_slice(&update);
    Some(encoded)
}

pub fn encode_direct_presence(
    message_id: [u8; 16],
    counter: u64,
    mode: PresenceMode,
    lease_secs: u32,
) -> Option<Vec<u8>> {
    let valid_lease = match mode {
        PresenceMode::Invisible => lease_secs == 0,
        PresenceMode::RecentlyReachable | PresenceMode::Away => {
            (MIN_PRESENCE_LEASE_SECS..=MAX_PRESENCE_LEASE_SECS).contains(&lease_secs)
        }
    };
    if counter == 0 || !valid_lease {
        return None;
    }
    let mut encoded = Vec::with_capacity(31);
    encoded.extend_from_slice(&[DIRECT_VERSION, DIRECT_PRESENCE_LEASE]);
    encoded.extend_from_slice(&message_id);
    encoded.extend_from_slice(&counter.to_be_bytes());
    encoded.push(mode.code());
    encoded.extend_from_slice(&lease_secs.to_be_bytes());
    Some(encoded)
}

pub fn encode_forward_grant(
    message_id: [u8; 16],
    grant: &crate::alias::ForwardGrant,
) -> Option<Vec<u8>> {
    let grant = grant.encode();
    if grant.len() > crate::alias::ForwardGrant::MAX_ENCODED {
        return None;
    }
    let mut encoded = Vec::with_capacity(18 + grant.len());
    encoded.extend_from_slice(&[DIRECT_VERSION, DIRECT_FORWARD_GRANT]);
    encoded.extend_from_slice(&message_id);
    encoded.extend_from_slice(&grant);
    Some(encoded)
}

pub fn encode_invite_redeem(
    message_id: [u8; 16],
    channel: &str,
    member_name: &str,
    invite_id: &[u8; 16],
    invite_secret: &[u8; 32],
    key_package: &[u8],
) -> Option<Vec<u8>> {
    if channel.len() > u16::MAX as usize
        || member_name.len() > u16::MAX as usize
        || key_package.len() > MAX_INVITE_RECORD_BYTES
    {
        return None;
    }
    let mut encoded = Vec::with_capacity(64 + channel.len() + key_package.len());
    encoded.extend_from_slice(&[DIRECT_VERSION, DIRECT_INVITE_REDEEM]);
    encoded.extend_from_slice(&message_id);
    put16(&mut encoded, channel.as_bytes());
    put16(&mut encoded, member_name.as_bytes());
    encoded.extend_from_slice(invite_id);
    encoded.extend_from_slice(invite_secret);
    put32(&mut encoded, key_package);
    Some(encoded)
}

pub fn encode_invite_welcome(
    message_id: [u8; 16],
    result: &Result<Vec<u8>, String>,
) -> Option<Vec<u8>> {
    let mut encoded = Vec::with_capacity(32);
    encoded.extend_from_slice(&[DIRECT_VERSION, DIRECT_INVITE_WELCOME]);
    encoded.extend_from_slice(&message_id);
    match result {
        Ok(welcome) => {
            if welcome.len() > MAX_INVITE_RECORD_BYTES {
                return None;
            }
            encoded.push(1);
            put32(&mut encoded, welcome);
        }
        Err(error) => {
            if error.len() > u16::MAX as usize {
                return None;
            }
            encoded.push(0);
            put16(&mut encoded, error.as_bytes());
        }
    }
    Some(encoded)
}

pub fn decode_direct_record(encoded: &[u8]) -> Option<DirectRecord> {
    if encoded.first() != Some(&DIRECT_VERSION) {
        return None;
    }
    let message_id = encoded.get(2..18)?.try_into().ok()?;
    match *encoded.get(1)? {
        DIRECT_VOLATILE_APPLICATION => Some(DirectRecord::VolatileApplication {
            message_id,
            sent_ms: u64::from_be_bytes(encoded.get(18..26)?.try_into().ok()?),
            body: encoded.get(26..)?.to_vec(),
        }),
        DIRECT_DATA | DIRECT_DURABLE_DATA => Some(DirectRecord::Data {
            durable: encoded[1] == DIRECT_DURABLE_DATA,
            message_id,
            sent_ms: u64::from_be_bytes(encoded.get(18..26)?.try_into().ok()?),
            share_presence: false,
            body: encoded.get(26..)?.to_vec(),
        }),
        DIRECT_DATA_WITH_PRESENCE if encoded.len() >= 27 && matches!(encoded[26], 0 | 1) => {
            Some(DirectRecord::Data {
                durable: false,
                message_id,
                sent_ms: u64::from_be_bytes(encoded.get(18..26)?.try_into().ok()?),
                share_presence: encoded[26] == 1,
                body: encoded.get(27..)?.to_vec(),
            })
        }
        DIRECT_ACK if encoded.len() == 18 => Some(DirectRecord::Ack {
            message_id,
            share_presence: false,
        }),
        DIRECT_ACK_WITH_PRESENCE if encoded.len() == 19 && matches!(encoded[18], 0 | 1) => {
            Some(DirectRecord::Ack {
                message_id,
                share_presence: encoded[18] == 1,
            })
        }
        DIRECT_CONTACT_UPDATE => Some(DirectRecord::ContactUpdate {
            message_id,
            update: ContactUpdate::decode(encoded.get(18..)?)?,
        }),
        DIRECT_FORWARD_GRANT => Some(DirectRecord::ForwardGrant {
            message_id,
            grant: crate::alias::ForwardGrant::decode(encoded.get(18..)?)?,
        }),
        DIRECT_PRESENCE_LEASE if encoded.len() == 31 => {
            let counter = u64::from_be_bytes(encoded.get(18..26)?.try_into().ok()?);
            let mode = PresenceMode::from_code(*encoded.get(26)?)?;
            let lease_secs = u32::from_be_bytes(encoded.get(27..31)?.try_into().ok()?);
            encode_direct_presence(message_id, counter, mode, lease_secs).map(|_| {
                DirectRecord::PresenceLease {
                    message_id,
                    counter,
                    mode,
                    lease_secs,
                }
            })
        }
        DIRECT_INVITE_REDEEM => {
            let mut p = 18usize;
            let channel = String::from_utf8(take16(encoded, &mut p)?).ok()?;
            let member_name = String::from_utf8(take16(encoded, &mut p)?).ok()?;
            let invite_id: [u8; 16] = take(encoded, &mut p, 16)?.try_into().ok()?;
            let invite_secret: [u8; 32] = take(encoded, &mut p, 32)?.try_into().ok()?;
            let key_package = take32(encoded, &mut p)?;
            if p != encoded.len() || key_package.len() > MAX_INVITE_RECORD_BYTES {
                return None;
            }
            Some(DirectRecord::InviteRedeem {
                message_id,
                channel,
                member_name,
                invite_id,
                invite_secret,
                key_package,
            })
        }
        DIRECT_INVITE_WELCOME => {
            let mut p = 18usize;
            let result = match *encoded.get(p)? {
                1 => {
                    p += 1;
                    let welcome = take32(encoded, &mut p)?;
                    if welcome.len() > MAX_INVITE_RECORD_BYTES {
                        return None;
                    }
                    Ok(welcome)
                }
                0 => {
                    p += 1;
                    Err(String::from_utf8(take16(encoded, &mut p)?).ok()?)
                }
                _ => return None,
            };
            if p != encoded.len() {
                return None;
            }
            Some(DirectRecord::InviteWelcome { message_id, result })
        }
        _ => None,
    }
}

pub fn encode_chan(name: &str, mls_wire: &[u8]) -> Vec<u8> {
    let mut v = vec![KIND_CHAN];
    v.extend_from_slice(&(name.len() as u16).to_be_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(mls_wire);
    v
}

pub fn decode_chan(cell: &gcoms_core::Cell) -> Option<(String, Vec<u8>)> {
    let p = cell.payload.as_slice();
    if p.first() != Some(&KIND_CHAN) {
        return None;
    }
    let mut q = 1usize;
    let nlen = u16::from_be_bytes([*p.get(q)?, *p.get(q + 1)?]) as usize;
    q += 2;
    let name = String::from_utf8(p.get(q..q + nlen)?.to_vec()).ok()?;
    q += nlen;
    Some((name, p.get(q..)?.to_vec()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub identity_pk: Vec<u8>,
    pub bundle: Vec<u8>,
    pub aliases: Vec<AliasContact>,
    pub provisioning: Option<RelayProvision>,
}

fn put16(v: &mut Vec<u8>, b: &[u8]) {
    v.extend_from_slice(&(b.len() as u16).to_be_bytes());
    v.extend_from_slice(b);
}

fn put32(v: &mut Vec<u8>, b: &[u8]) {
    v.extend_from_slice(&(b.len() as u32).to_be_bytes());
    v.extend_from_slice(b);
}

pub fn put_contact(v: &mut Vec<u8>, contact: &AliasContact) {
    match contact.target.address.ip() {
        core::net::IpAddr::V4(ip) => {
            v.push(4);
            v.extend_from_slice(&ip.octets());
            v.extend_from_slice(&[0; 12]);
        }
        core::net::IpAddr::V6(ip) => {
            v.push(6);
            v.extend_from_slice(&ip.octets());
        }
    }
    v.extend_from_slice(&contact.target.address.port().to_be_bytes());
    v.extend_from_slice(&contact.target.relay_service_id);
    v.extend_from_slice(&contact.queue_id);
    v.extend_from_slice(&contact.epoch.to_be_bytes());
    v.extend_from_slice(&contact.push_cap);
    v.extend_from_slice(&contact.expiry.to_be_bytes());
}

fn take<'a>(buf: &'a [u8], p: &mut usize, len: usize) -> Option<&'a [u8]> {
    let value = buf.get(*p..p.checked_add(len)?)?;
    *p += len;
    Some(value)
}

fn take16(buf: &[u8], p: &mut usize) -> Option<Vec<u8>> {
    let len = u16::from_be_bytes(take(buf, p, 2)?.try_into().ok()?) as usize;
    Some(take(buf, p, len)?.to_vec())
}

fn take32(buf: &[u8], p: &mut usize) -> Option<Vec<u8>> {
    let len = u32::from_be_bytes(take(buf, p, 4)?.try_into().ok()?) as usize;
    Some(take(buf, p, len)?.to_vec())
}

pub fn take_contact(buf: &[u8], p: &mut usize) -> Option<AliasContact> {
    let family = *take(buf, p, 1)?.first()?;
    let address_bytes: [u8; 16] = take(buf, p, 16)?.try_into().ok()?;
    let ip = match family {
        4 if address_bytes[4..].iter().all(|byte| *byte == 0) => core::net::IpAddr::V4(
            core::net::Ipv4Addr::from(<[u8; 4]>::try_from(&address_bytes[..4]).ok()?),
        ),
        6 => core::net::IpAddr::V6(core::net::Ipv6Addr::from(address_bytes)),
        _ => return None,
    };
    let port = u16::from_be_bytes(take(buf, p, 2)?.try_into().ok()?);
    let relay_service_id = take(buf, p, 32)?.try_into().ok()?;
    let queue_id = take(buf, p, 32)?.try_into().ok()?;
    let epoch = u64::from_be_bytes(take(buf, p, 8)?.try_into().ok()?);
    let push_cap = take(buf, p, 32)?.try_into().ok()?;
    let expiry = u64::from_be_bytes(take(buf, p, 8)?.try_into().ok()?);
    Some(AliasContact {
        target: RelayTarget {
            address: core::net::SocketAddr::new(ip, port),
            relay_service_id,
        },
        queue_id,
        epoch,
        push_cap,
        expiry,
    })
}

impl NodeInfo {
    pub fn public(&self) -> Self {
        Self {
            identity_pk: self.identity_pk.clone(),
            bundle: self.bundle.clone(),
            aliases: self.aliases.clone(),
            provisioning: None,
        }
    }

    pub fn primary(&self) -> Option<&AliasContact> {
        self.aliases.first()
    }

    pub fn control(&self) -> Option<&AliasContact> {
        self.aliases.get(1).or_else(|| self.aliases.first())
    }

    /// Public encoding deliberately excludes every relay-private capability.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_common(KIND_BOOTSTRAP)
    }

    fn encode_common(&self, kind: u8) -> Vec<u8> {
        let mut v = vec![kind, INFO_VERSION];
        put16(&mut v, &self.identity_pk);
        put32(&mut v, &self.bundle);
        v.push(self.aliases.len().min(u8::MAX as usize) as u8);
        for contact in self.aliases.iter().take(u8::MAX as usize) {
            put_contact(&mut v, contact);
        }
        v
    }

    pub fn encode_private(&self) -> Option<Vec<u8>> {
        let provision = self.provisioning.as_ref()?;
        let mut v = self.encode_common(KIND_PROVISIONING);
        Self::encode_private_provision(&mut v, provision)?;
        Some(v)
    }

    /// Same layout as [`Self::encode_private`] with an explicit GC/2
    /// introduction advertisement appended. Version 1 clients never receive
    /// this kind because the relay only emits it for opted-in requests.
    pub fn encode_private_gc2(&self, introduction: &[u8]) -> Option<Vec<u8>> {
        let provision = self.provisioning.as_ref()?;
        if introduction.is_empty() || introduction.len() > MAX_PROVISION_GC2_BYTES {
            return None;
        }
        let mut v = self.encode_common(KIND_PROVISIONING_GC2);
        Self::encode_private_provision(&mut v, provision)?;
        put16(&mut v, introduction);
        Some(v)
    }

    fn encode_private_provision(v: &mut Vec<u8>, provision: &RelayProvision) -> Option<()> {
        v.push(provision.aliases.len().min(u8::MAX as usize) as u8);
        for owned in provision.aliases.iter().take(u8::MAX as usize) {
            put_contact(v, &owned.contact);
            v.extend_from_slice(&owned.capabilities.push);
            v.extend_from_slice(&owned.capabilities.sub);
            v.extend_from_slice(&owned.capabilities.admin);
            v.extend_from_slice(&owned.limits.max_queue_cells.to_be_bytes());
            v.extend_from_slice(&owned.limits.max_queue_bytes.to_be_bytes());
            put16(v, owned.create_path.as_bytes());
            let wire = owned.lease_create.encode_wire().ok()?;
            put16(v, &wire);
        }
        put16(v, provision.frwd_path.as_bytes());
        v.extend_from_slice(&provision.hop_key);
        Some(())
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        let (info, consumed) = Self::decode_common(buf, KIND_BOOTSTRAP)?;
        (consumed == buf.len()).then_some(info)
    }

    pub fn decode_private(buf: &[u8]) -> Option<Self> {
        Self::decode_private_inner(buf, KIND_PROVISIONING).map(|(info, _)| info)
    }

    /// Decode a private relay card of either kind. Version 1 cards never carry
    /// a GC/2 introduction; a version 2 card always does.
    pub fn decode_private_any(buf: &[u8]) -> Option<(Self, Option<Vec<u8>>)> {
        match buf.first().copied()? {
            KIND_PROVISIONING => Self::decode_private_inner(buf, KIND_PROVISIONING),
            KIND_PROVISIONING_GC2 => {
                let (info, introduction) = Self::decode_private_inner(buf, KIND_PROVISIONING_GC2)?;
                Some((info, Some(introduction?)))
            }
            _ => None,
        }
    }

    pub fn decode_private_gc2(buf: &[u8]) -> Option<(Self, Vec<u8>)> {
        let (info, introduction) = Self::decode_private_inner(buf, KIND_PROVISIONING_GC2)?;
        Some((info, introduction?))
    }

    fn decode_private_inner(buf: &[u8], kind: u8) -> Option<(Self, Option<Vec<u8>>)> {
        let (mut info, mut p) = Self::decode_common(buf, kind)?;
        let count = *take(buf, &mut p, 1)?.first()? as usize;
        let mut aliases = Vec::with_capacity(count);
        for _ in 0..count {
            let contact = take_contact(buf, &mut p)?;
            let capabilities = Capabilities {
                push: take(buf, &mut p, 32)?.try_into().ok()?,
                sub: take(buf, &mut p, 32)?.try_into().ok()?,
                admin: take(buf, &mut p, 32)?.try_into().ok()?,
            };
            let limits = LeaseLimits {
                max_queue_cells: u16::from_be_bytes(take(buf, &mut p, 2)?.try_into().ok()?),
                max_queue_bytes: u64::from_be_bytes(take(buf, &mut p, 8)?.try_into().ok()?),
            };
            let create_path = String::from_utf8(take16(buf, &mut p)?).ok()?;
            let lease_create = gcoms_core::decode(&take16(buf, &mut p)?).ok()?;
            aliases.push(OwnedAlias {
                contact,
                capabilities,
                limits,
                create_path,
                lease_create,
            });
        }
        let frwd_path = String::from_utf8(take16(buf, &mut p)?).ok()?;
        let hop_key = take(buf, &mut p, 32)?.try_into().ok()?;
        let introduction = if kind == KIND_PROVISIONING_GC2 {
            let bytes = take16(buf, &mut p)?.to_vec();
            if bytes.is_empty() || bytes.len() > MAX_PROVISION_GC2_BYTES {
                return None;
            }
            Some(bytes)
        } else {
            None
        };
        if p != buf.len() {
            return None;
        }
        info.provisioning = Some(RelayProvision {
            aliases,
            frwd_path,
            hop_key,
        });
        Some((info, introduction))
    }

    /// Structural validation for a freshly received private relay card:
    /// exactly two usable, distinct, unexpired aliases whose public contacts
    /// match the private entries. `allow_local` permits loopback targets for
    /// isolated test deployments.
    pub fn validate_relay_provision(&self, now_unix: u64, allow_local: bool) -> bool {
        let Some(provision) = &self.provisioning else {
            return false;
        };
        if provision.aliases.len() != 2 || self.aliases.len() != 2 {
            return false;
        }
        let mut queue_ids = alloc::collections::BTreeSet::new();
        let mut push_caps = alloc::collections::BTreeSet::new();
        for owned in &provision.aliases {
            let contact = &owned.contact;
            if contact.queue_id == [0; 32]
                || contact.push_cap == [0; 32]
                || contact.epoch == 0
                || contact.expiry <= now_unix.saturating_add(300)
                || contact.target.address.port() == 0
                || contact.target.address.ip().is_unspecified()
                || (!allow_local && contact.target.address.ip().is_loopback())
                || owned.create_path.is_empty()
                || owned.capabilities.push == [0; 32]
                || owned.capabilities.sub == [0; 32]
                || owned.capabilities.admin == [0; 32]
                || owned.limits.max_queue_cells == 0
                || owned.limits.max_queue_bytes == 0
            {
                return false;
            }
            if !queue_ids.insert(contact.queue_id) || !push_caps.insert(owned.capabilities.push) {
                return false;
            }
        }
        if provision.frwd_path.is_empty() || provision.hop_key == [0; 32] {
            return false;
        }
        let public = provision
            .aliases
            .iter()
            .map(|owned| owned.contact.clone())
            .collect::<Vec<_>>();
        self.aliases == public
    }

    fn decode_common(buf: &[u8], kind: u8) -> Option<(Self, usize)> {
        if buf.get(..2)? != [kind, INFO_VERSION] {
            return None;
        }
        let mut p = 2;
        let identity_pk = take16(buf, &mut p)?;
        let bundle = take32(buf, &mut p)?;
        let count = *take(buf, &mut p, 1)?.first()? as usize;
        let mut aliases = Vec::with_capacity(count);
        for _ in 0..count {
            aliases.push(take_contact(buf, &mut p)?);
        }
        Some((
            Self {
                identity_pk,
                bundle,
                aliases,
                provisioning: None,
            },
            p,
        ))
    }
}

pub fn encode_first_move(fm: &FirstMove) -> Vec<u8> {
    let mut v = vec![KIND_FIRST_MOVE];
    v.extend_from_slice(&fm.encode());
    v
}

pub fn encode_frame(sender_pk: &[u8], f: &Frame) -> Vec<u8> {
    let mut v = vec![KIND_FRAME];
    put16(&mut v, sender_pk);
    v.extend_from_slice(&f.encode());
    v
}

pub fn encode_bundle(b: &Bundle) -> Vec<u8> {
    let mut v = vec![KIND_BUNDLE];
    v.extend_from_slice(&b.encode());
    v
}

pub enum NodePayload {
    FirstMove(FirstMove),
    Frame(Vec<u8>, Frame),
    Bundle(Bundle),
    Bootstrap(NodeInfo),
}

pub fn decode_payload(cell: &gcoms_core::Cell) -> Option<NodePayload> {
    let kind = *cell.payload.first()?;
    match kind {
        KIND_FIRST_MOVE => FirstMove::decode(&cell.payload[1..]).map(NodePayload::FirstMove),
        KIND_FRAME => {
            let mut p = 1usize;
            let plen =
                u16::from_be_bytes([*cell.payload.get(p)?, *cell.payload.get(p + 1)?]) as usize;
            p += 2;
            let pk = cell.payload.get(p..p + plen)?.to_vec();
            p += plen;
            Frame::decode(&cell.payload[p..]).map(|f| NodePayload::Frame(pk, f))
        }
        KIND_BUNDLE => Bundle::decode(&cell.payload[1..]).map(NodePayload::Bundle),
        KIND_BOOTSTRAP => NodeInfo::decode(cell.payload.as_slice()).map(NodePayload::Bootstrap),
        _ => None,
    }
}

pub fn b64_info(info: &NodeInfo) -> String {
    gcoms_core::encoding::encode_b64url(&info.encode())
}

pub fn b64_private_info(info: &NodeInfo) -> Option<String> {
    Some(gcoms_core::encoding::encode_b64url(&info.encode_private()?))
}

pub fn info_from_b64(s: &str) -> Option<NodeInfo> {
    NodeInfo::decode(&gcoms_core::encoding::decode_b64url(s)?)
}

pub fn private_info_from_b64(s: &str) -> Option<NodeInfo> {
    NodeInfo::decode_private(&gcoms_core::encoding::decode_b64url(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(byte: u8) -> AliasContact {
        AliasContact {
            target: RelayTarget {
                address: "127.0.0.1:443".parse().unwrap(),
                relay_service_id: [byte; 32],
            },
            queue_id: [byte + 1; 32],
            epoch: 7,
            push_cap: [byte + 2; 32],
            expiry: 99,
        }
    }

    fn sample_info() -> NodeInfo {
        NodeInfo {
            identity_pk: vec![9; 1952],
            bundle: vec![3; 4537],
            aliases: vec![contact(7), contact(20)],
            provisioning: None,
        }
    }

    #[test]
    fn public_node_info_roundtrip() {
        let info = sample_info();
        assert_eq!(NodeInfo::decode(&info.encode()).unwrap(), info);
    }

    #[test]
    fn public_encoding_strips_private_fields() {
        let mut info = sample_info();
        info.provisioning = Some(RelayProvision {
            aliases: vec![],
            frwd_path: "private".into(),
            hop_key: [4; 32],
        });
        let decoded = NodeInfo::decode(&info.encode()).unwrap();
        assert!(decoded.provisioning.is_none());
        assert!(!info.encode().windows(7).any(|window| window == b"private"));
    }

    #[test]
    fn gc2_private_card_roundtrips_and_keeps_v1_bytes_unchanged() {
        let mut info = sample_info();
        info.provisioning = Some(RelayProvision {
            aliases: vec![],
            frwd_path: "private".into(),
            hop_key: [4; 32],
        });
        let v1 = info.encode_private().unwrap();
        assert_eq!(v1[0], KIND_PROVISIONING);
        let introduction = vec![0xA5; 155];
        let v2 = info.encode_private_gc2(&introduction).unwrap();
        assert_eq!(v2[0], KIND_PROVISIONING_GC2);
        // The layouts are identical apart from the leading kind byte.
        assert_eq!(v2[1..v1.len()], v1[1..]);
        let (decoded, advertised) = NodeInfo::decode_private_gc2(&v2).unwrap();
        assert_eq!(advertised, introduction);
        assert_eq!(decoded.aliases, info.aliases);
        assert!(NodeInfo::decode_private(&v2).is_none());
        assert!(NodeInfo::decode_private_gc2(&v1).is_none());
        let (_, advertised) = NodeInfo::decode_private_any(&v2).unwrap();
        assert_eq!(advertised, Some(introduction.clone()));
        let (_, advertised) = NodeInfo::decode_private_any(&v1).unwrap();
        assert!(advertised.is_none());
        let mut trailing = v2.clone();
        trailing.push(0);
        assert!(NodeInfo::decode_private_gc2(&trailing).is_none());
        let mut truncated = v2;
        truncated.pop();
        assert!(NodeInfo::decode_private_gc2(&truncated).is_none());
        assert!(info.encode_private_gc2(&[]).is_none());
        assert!(info
            .encode_private_gc2(&vec![0; MAX_PROVISION_GC2_BYTES + 1])
            .is_none());
    }

    #[test]
    fn node_info_rejects_legacy_and_truncated() {
        assert!(NodeInfo::decode(b"legacy card").is_none());
        let mut enc = sample_info().encode();
        enc.truncate(10);
        assert!(NodeInfo::decode(&enc).is_none());
    }

    #[test]
    fn frame_payload_roundtrip() {
        let frame = Frame {
            ctr: 5,
            pn: 4,
            sender_pub: [2; 32],
            mixed_with: None,
            pq_ct: None,
            ct: vec![1, 2, 3, 4],
        };
        let payload = encode_frame(&[8; 33], &frame);
        let cell = gcoms_core::Cell::new(gcoms_core::CellType::Msg, 0, 0, payload);
        match decode_payload(&cell) {
            Some(NodePayload::Frame(pk, f)) => {
                assert_eq!(pk, vec![8; 33]);
                assert_eq!(f, frame);
            }
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn direct_records_are_strict_and_round_trip() {
        let id = [7; 16];
        assert_eq!(
            decode_direct_record(&encode_direct_data(id, 42, true, b"hello")),
            Some(DirectRecord::Data {
                durable: false,
                message_id: id,
                sent_ms: 42,
                share_presence: true,
                body: b"hello".to_vec(),
            })
        );
        assert_eq!(
            decode_direct_record(&encode_direct_ack(id, true)),
            Some(DirectRecord::Ack {
                message_id: id,
                share_presence: true,
            })
        );
        let mut legacy_data = vec![DIRECT_VERSION, DIRECT_DATA];
        legacy_data.extend_from_slice(&id);
        legacy_data.extend_from_slice(&42u64.to_be_bytes());
        legacy_data.extend_from_slice(b"legacy");
        assert!(matches!(
            decode_direct_record(&legacy_data),
            Some(DirectRecord::Data {
                share_presence: false,
                ..
            })
        ));
        let mut bad_presence_flag = encode_direct_ack(id, true);
        bad_presence_flag[18] = 2;
        assert!(decode_direct_record(&bad_presence_flag).is_none());
        let presence = encode_direct_presence(id, 9, PresenceMode::Away, 60).unwrap();
        assert_eq!(
            decode_direct_record(&presence),
            Some(DirectRecord::PresenceLease {
                message_id: id,
                counter: 9,
                mode: PresenceMode::Away,
                lease_secs: 60,
            })
        );
        assert_eq!(presence.len(), 31);
        assert!(encode_direct_presence(id, 0, PresenceMode::Away, 60).is_none());
        assert!(encode_direct_presence(id, 10, PresenceMode::Away, 1).is_none());
        assert!(encode_direct_presence(id, 10, PresenceMode::Invisible, 1).is_none());
        assert!(encode_direct_presence(id, 10, PresenceMode::Invisible, 0).is_some());
        let mut ack_with_trailing = encode_direct_ack(id, false);
        ack_with_trailing.push(0);
        assert!(decode_direct_record(&ack_with_trailing).is_none());
        assert!(decode_direct_record(&[DIRECT_VERSION, DIRECT_DATA]).is_none());
        assert!(decode_direct_record(&[9; 26]).is_none());
    }

    #[test]
    fn contact_update_is_canonical_signed_and_bounded() {
        let identity = gcoms_crypto::IdentityKeypair::from_seed([0x51; 32]);
        let (bundle, _) = identity.issue_bundle();
        let issued_at = bundle.created;
        let mut info = sample_info();
        info.identity_pk = identity.public_bytes();
        info.bundle = bundle.encode();
        for alias in &mut info.aliases {
            alias.expiry = issued_at + 3600;
        }
        let update = ContactUpdate::sign(7, issued_at, issued_at + 3600, info, &identity).unwrap();
        assert!(update.verify(&identity.public_bytes(), issued_at));
        let encoded = update.encode().unwrap();
        assert_eq!(ContactUpdate::decode(&encoded), Some(update.clone()));

        let mut tampered = encoded.clone();
        tampered[40] ^= 1;
        assert!(ContactUpdate::decode(&tampered)
            .is_none_or(|decoded| !decoded.verify(&identity.public_bytes(), issued_at)));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(ContactUpdate::decode(&trailing).is_none());

        let expired_info = update.info.clone();
        let mut wrong_identity = update;
        wrong_identity.info.identity_pk[0] ^= 1;
        assert!(!wrong_identity.verify(&identity.public_bytes(), issued_at));

        let expired =
            ContactUpdate::sign(8, issued_at, issued_at + 1, expired_info, &identity).unwrap();
        assert!(!expired.verify(&identity.public_bytes(), issued_at + 2));

        let mut old_bundle = expired.clone();
        old_bundle.issued_at = issued_at + MAX_BUNDLE_AGE_SECS + 1;
        old_bundle.expires_at = old_bundle.issued_at + 3600;
        for alias in &mut old_bundle.info.aliases {
            alias.expiry = old_bundle.expires_at;
        }
        old_bundle.signature = identity.sign(&old_bundle.unsigned().unwrap());
        assert!(!old_bundle.verify(&identity.public_bytes(), old_bundle.issued_at));
    }

    #[test]
    fn oversized_channel_wire_fragments_and_reassembles_out_of_order() {
        let wire = vec![0x5a; gcoms_core::MAX_MESSAGE * 2];
        let mut cells = encode_chan_cells("pq-channel", &wire).unwrap();
        assert!(cells.len() >= 3);
        assert!(cells.iter().all(|cell| cell.encode_wire().is_ok()));
        cells.reverse();

        let mut fragments = ChannelFragmentBuffer::default();
        let mut reassembled = None;
        for cell in cells {
            reassembled = fragments.push(&cell.payload).or(reassembled);
        }
        let cell = Cell::new(CellType::Msg, 0, 0, reassembled.unwrap());
        assert_eq!(decode_chan(&cell), Some(("pq-channel".into(), wire)));
    }

    #[test]
    fn channel_fragment_reassembly_rejects_tampering() {
        let wire = vec![0xa5; gcoms_core::MAX_MESSAGE + 1];
        let mut cells = encode_chan_cells("pq-channel", &wire).unwrap();
        *cells.last_mut().unwrap().payload.last_mut().unwrap() ^= 1;
        let mut fragments = ChannelFragmentBuffer::default();
        assert!(cells
            .iter()
            .all(|cell| fragments.push(&cell.payload).is_none()));
    }

    #[test]
    fn invite_redeem_record_roundtrips() {
        let encoded = encode_invite_redeem(
            [0x11; 16],
            "friends",
            "alice",
            &[0x22; 16],
            &[0x33; 32],
            &[0x44; 200],
        )
        .unwrap();
        match decode_direct_record(&encoded) {
            Some(DirectRecord::InviteRedeem {
                message_id,
                channel,
                member_name,
                invite_id,
                invite_secret,
                key_package,
            }) => {
                assert_eq!(message_id, [0x11; 16]);
                assert_eq!(channel, "friends");
                assert_eq!(member_name, "alice");
                assert_eq!(invite_id, [0x22; 16]);
                assert_eq!(invite_secret, [0x33; 32]);
                assert_eq!(key_package, vec![0x44; 200]);
            }
            other => panic!("expected InviteRedeem, got {other:?}"),
        }
        // Trailing garbage is rejected (exact-length parse).
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(decode_direct_record(&extra).is_none());
    }

    #[test]
    fn invite_welcome_record_roundtrips_both_ways() {
        let ok = encode_invite_welcome([0x55; 16], &Ok(vec![0x66; 300])).unwrap();
        assert_eq!(
            decode_direct_record(&ok),
            Some(DirectRecord::InviteWelcome {
                message_id: [0x55; 16],
                result: Ok(vec![0x66; 300]),
            })
        );
        let err = encode_invite_welcome([0x77; 16], &Err("invite already used".into())).unwrap();
        assert_eq!(
            decode_direct_record(&err),
            Some(DirectRecord::InviteWelcome {
                message_id: [0x77; 16],
                result: Err("invite already used".into()),
            })
        );
    }
}
