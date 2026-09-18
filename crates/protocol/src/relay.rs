#[cfg(feature = "experimental-gc2")]
pub mod gc2;

use alloc::{format, string::String, vec::Vec};
use core::error::Error;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use gcoms_core::{Bucket, Cell, CellType, HEADER_LEN, PROTOCOL_VERSION};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub type PushCap = [u8; 32];
pub type SubCap = [u8; 32];
pub type HopKey = [u8; 32];
pub type ServiceId = [u8; 32];
pub type QueueId = [u8; 32];
pub type Nonce = [u8; 16];

const RELAY_PUSH_DOMAIN: &[u8] = b"GC1/RELAY-PUSH\0";
const RELAY_SUB_DOMAIN: &[u8] = b"GC1/RELAY-SUB\0";
const FRWD_DOMAIN: &[u8] = b"GC1/FRWD\0";
const MAC_LEN: usize = 32;
const RELAY_SUBSCRIBE: u8 = 0x05;
const TARGET_LEN: usize = 51;
const MAX_MSG_NATURAL_LEN: usize = 15_366;
const RELAY_PUSH_FIXED_LEN: usize = 99;
const RELAY_SUB_LEN: usize = 98;
const FRWD_FIXED_LEN: usize = 110;
const MAX_RELAY_PUSH_NATURAL_LEN: usize = HEADER_LEN + RELAY_PUSH_FIXED_LEN + MAX_MSG_NATURAL_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayCodecError {
    WrongCellType,
    NonCanonicalCell,
    Malformed,
    TrailingBytes,
    InvalidMac,
    Expired { expires_unix: u64, now_unix: u64 },
    InnerNotMsg,
    InnerNotRelayPush,
    CellTooLarge,
    InvalidTarget,
    NonCanonicalTarget,
}

impl fmt::Display for RelayCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongCellType => write!(f, "wrong cell type"),
            Self::NonCanonicalCell => write!(f, "non-canonical cell"),
            Self::Malformed => write!(f, "malformed relay cell"),
            Self::TrailingBytes => write!(f, "trailing bytes in relay cell"),
            Self::InvalidMac => write!(f, "invalid relay MAC"),
            Self::Expired {
                expires_unix,
                now_unix,
            } => write!(f, "relay cell expired at {expires_unix} (now {now_unix})"),
            Self::InnerNotMsg => write!(f, "RELAY_PUSH does not contain exactly one MSG"),
            Self::InnerNotRelayPush => write!(f, "FRWD does not contain a RELAY_PUSH"),
            Self::CellTooLarge => write!(f, "relay cell exceeds the canonical capacity"),
            Self::InvalidTarget => write!(f, "FRWD target is not permitted"),
            Self::NonCanonicalTarget => write!(f, "FRWD target encoding is not canonical"),
        }
    }
}

impl Error for RelayCodecError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayTarget {
    pub address: SocketAddr,
    pub relay_service_id: ServiceId,
}

#[derive(Clone, Debug)]
pub struct FrwdTargetPolicy {
    allow_local_fixture: bool,
    private_targets: Vec<PrivateTarget>,
}

#[derive(Clone, Debug)]
struct PrivateTarget {
    network: IpAddr,
    prefix: u8,
    /// `None` permits every port in the range; `Some(p)` pins the allowance
    /// to exactly that target port.
    port: Option<u16>,
}

impl FrwdTargetPolicy {
    pub fn new(allow_local_fixture: bool) -> Self {
        Self {
            allow_local_fixture,
            private_targets: Vec::new(),
        }
    }

    /// Permit one already authenticated endpoint without parsing a CIDR or
    /// broadening it to other ports. Used by the freestanding bootstrap client.
    pub fn allow_exact_address(mut self, address: SocketAddr) -> Result<Self, String> {
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err("invalid exact FRWD endpoint".into());
        }
        self.private_targets.push(PrivateTarget {
            network: address.ip(),
            prefix: if address.is_ipv4() { 32 } else { 128 },
            port: Some(address.port()),
        });
        Ok(self)
    }

    pub fn allow_private_cidr(mut self, cidr: &str, port: u16) -> Result<Self, String> {
        let (network, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid FRWD target CIDR {cidr}"))?;
        let network: IpAddr = network
            .parse()
            .map_err(|e| format!("invalid FRWD target CIDR {cidr}: {e}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|e| format!("invalid FRWD target CIDR {cidr}: {e}"))?;
        let max_prefix = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix || port == 0 {
            return Err(format!("invalid FRWD target CIDR or port {cidr}:{port}"));
        }
        self.private_targets.push(PrivateTarget {
            network,
            prefix,
            port: Some(port),
        });
        Ok(self)
    }

    /// Allow a private CIDR on every target port (operators usually mean
    /// "peers in this subnet" rather than one pinned port).
    pub fn allow_private_cidr_any_port(mut self, cidr: &str) -> Result<Self, String> {
        let (network, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid FRWD target CIDR {cidr}"))?;
        let network: IpAddr = network
            .parse()
            .map_err(|e| format!("invalid FRWD target CIDR {cidr}: {e}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|e| format!("invalid FRWD target CIDR {cidr}: {e}"))?;
        let max_prefix = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(format!("invalid FRWD target CIDR prefix {cidr}"));
        }
        self.private_targets.push(PrivateTarget {
            network,
            prefix,
            port: None,
        });
        Ok(self)
    }

    pub fn permits(&self, target: &RelayTarget) -> bool {
        self.allow_local_fixture
            || is_ordinary_global(target.address.ip())
            || self.private_targets.iter().any(|allowed| {
                allowed
                    .port
                    .is_none_or(|port| port == target.address.port())
                    && allowed.contains(target.address.ip())
            })
    }
}

impl PrivateTarget {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl RelayTarget {
    /// Canonical 51-byte descriptor (SPEC §10.1), for embedding in grants.
    pub fn encode_public(&self) -> [u8; TARGET_LEN] {
        self.encode()
    }

    pub fn decode_public(encoded: &[u8]) -> Option<Self> {
        Self::decode(encoded).ok()
    }

    fn encode(&self) -> [u8; TARGET_LEN] {
        let mut encoded = [0u8; TARGET_LEN];
        match self.address.ip() {
            IpAddr::V4(ip) => {
                encoded[0] = 4;
                encoded[1..5].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                encoded[0] = 6;
                encoded[1..17].copy_from_slice(&ip.octets());
            }
        }
        encoded[17..19].copy_from_slice(&self.address.port().to_be_bytes());
        encoded[19..].copy_from_slice(&self.relay_service_id);
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, RelayCodecError> {
        let encoded: &[u8; TARGET_LEN] =
            encoded.try_into().map_err(|_| RelayCodecError::Malformed)?;
        let ip = match encoded[0] {
            4 => {
                if encoded[5..17].iter().any(|byte| *byte != 0) {
                    return Err(RelayCodecError::NonCanonicalTarget);
                }
                IpAddr::V4(Ipv4Addr::new(
                    encoded[1], encoded[2], encoded[3], encoded[4],
                ))
            }
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&encoded[1..17]).map_err(|_| RelayCodecError::Malformed)?,
            )),
            _ => return Err(RelayCodecError::NonCanonicalTarget),
        };
        Ok(Self {
            address: SocketAddr::new(ip, u16::from_be_bytes([encoded[17], encoded[18]])),
            relay_service_id: encoded[19..]
                .try_into()
                .map_err(|_| RelayCodecError::Malformed)?,
        })
    }
}

/// Validates a literal FRWD destination. Local/special addresses are accepted
/// only for an explicitly configured test fixture; port zero is never valid.
pub fn validate_frwd_target(
    target: &RelayTarget,
    allow_local_fixture: bool,
) -> Result<(), RelayCodecError> {
    validate_frwd_target_with_policy(target, &FrwdTargetPolicy::new(allow_local_fixture))
}

pub fn validate_frwd_target_with_policy(
    target: &RelayTarget,
    policy: &FrwdTargetPolicy,
) -> Result<(), RelayCodecError> {
    if target.address.port() == 0 {
        return Err(RelayCodecError::InvalidTarget);
    }
    if policy.permits(target) {
        Ok(())
    } else {
        Err(RelayCodecError::InvalidTarget)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayPush {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub push_nonce: Nonce,
    pub push_expiry: u64,
    /// `None` is an authenticated **cover deposit** (SPEC §7.4): the relay
    /// verifies it exactly like a real deposit, records its nonce, returns
    /// the identical hop receipt, and enqueues nothing.
    pub msg: Option<Cell>,
}

impl RelayPush {
    pub fn is_cover(&self) -> bool {
        self.msg.is_none()
    }

    /// Checks the opaque inner message's canonical shape and capacity without
    /// encoding, allocating or generating authority. This is not authentication.
    /// Callers can reject impossible jobs before opening a transport connection.
    pub fn validate_message(cell: &Cell) -> Result<(), RelayCodecError> {
        if cell.cell_type() != Some(CellType::Msg) {
            return Err(RelayCodecError::InnerNotMsg);
        }
        natural_length(cell, MAX_MSG_NATURAL_LEN).map(|_| ())
    }

    pub fn encode_into_cell(
        &self,
        push_cap: &PushCap,
        relay_service_id: &ServiceId,
    ) -> Result<Cell, RelayCodecError> {
        let msg_natural = match &self.msg {
            Some(msg) => encode_msg_natural(msg)?,
            None => Vec::new(),
        };
        if msg_natural.len() > MAX_MSG_NATURAL_LEN {
            return Err(RelayCodecError::CellTooLarge);
        }
        let msg_len =
            u16::try_from(msg_natural.len()).map_err(|_| RelayCodecError::CellTooLarge)?;
        let payload_len = RELAY_PUSH_FIXED_LEN
            .checked_add(msg_natural.len())
            .ok_or(RelayCodecError::CellTooLarge)?;
        if payload_len > Bucket::B3.max_payload() {
            return Err(RelayCodecError::CellTooLarge);
        }

        let mut payload = Vec::with_capacity(payload_len);
        payload.push(PROTOCOL_VERSION);
        payload.extend_from_slice(&self.queue_id);
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(&self.push_nonce);
        payload.extend_from_slice(&self.push_expiry.to_be_bytes());
        payload.extend_from_slice(&msg_len.to_be_bytes());
        payload.extend_from_slice(&msg_natural);
        let tag = relay_push_tag(push_cap, relay_service_id, self, msg_len, &msg_natural)?;
        payload.extend_from_slice(&tag);
        Ok(Cell::new(CellType::RelayPush, 0, 0, payload))
    }

    pub fn decode_from_cell(
        cell: &Cell,
        push_cap: &PushCap,
        relay_service_id: &ServiceId,
        now_unix: u64,
    ) -> Result<Self, RelayCodecError> {
        require_outer(cell, CellType::RelayPush)?;
        let parts = parse_push_payload(&cell.payload)?;
        verify_relay_push_tag(push_cap, relay_service_id, &parts)?;
        reject_expired(parts.push_expiry, now_unix)?;
        Ok(Self {
            queue_id: parts.queue_id,
            epoch: parts.epoch,
            push_nonce: parts.push_nonce,
            push_expiry: parts.push_expiry,
            msg: if parts.msg_len == 0 {
                None
            } else {
                Some(decode_msg_natural(parts.msg_natural)?)
            },
        })
    }

    /// A cover deposit for `contact`-shaped parameters: random bucket
    /// padding is applied by the caller through `pad_cover`.
    pub fn cover(queue_id: QueueId, epoch: u64, push_nonce: Nonce, push_expiry: u64) -> Self {
        Self {
            queue_id,
            epoch,
            push_nonce,
            push_expiry,
            msg: None,
        }
    }
}

/// A canonical RELAY_PUSH whose destination MAC has deliberately not been
/// checked. Intermediaries can validate and forward this structure without
/// possessing the destination's private push capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnauthenticatedRelayPush {
    cell: Cell,
}

impl UnauthenticatedRelayPush {
    pub fn parse(cell: Cell) -> Result<Self, RelayCodecError> {
        require_outer(&cell, CellType::RelayPush)?;
        parse_push_payload(&cell.payload)?;
        Ok(Self { cell })
    }

    pub fn as_cell(&self) -> &Cell {
        &self.cell
    }

    pub fn into_cell(self) -> Cell {
        self.cell
    }

    pub fn queue_id(&self) -> QueueId {
        self.parts().queue_id
    }

    pub fn epoch(&self) -> u64 {
        self.parts().epoch
    }

    pub fn push_expiry(&self) -> u64 {
        self.parts().push_expiry
    }

    pub fn authenticate(
        self,
        push_cap: &PushCap,
        relay_service_id: &ServiceId,
        now_unix: u64,
    ) -> Result<RelayPush, RelayCodecError> {
        RelayPush::decode_from_cell(&self.cell, push_cap, relay_service_id, now_unix)
    }

    fn parts(&self) -> PushParts<'_> {
        parse_push_payload(&self.cell.payload).expect("validated RELAY_PUSH")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaySub {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub subscription_expiry: u64,
    pub nonce: Nonce,
}

impl RelaySub {
    pub fn encode_into_cell(
        &self,
        sub_cap: &SubCap,
        relay_service_id: &ServiceId,
    ) -> Result<Cell, RelayCodecError> {
        let mut payload = Vec::with_capacity(RELAY_SUB_LEN);
        payload.push(PROTOCOL_VERSION);
        payload.push(RELAY_SUBSCRIBE);
        payload.extend_from_slice(&self.queue_id);
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(&self.subscription_expiry.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&relay_sub_tag(sub_cap, relay_service_id, self)?);
        Ok(Cell::new(CellType::RelaySub, 0, 0, payload))
    }

    pub fn decode_from_cell(
        cell: &Cell,
        sub_cap: &SubCap,
        relay_service_id: &ServiceId,
        now_unix: u64,
    ) -> Result<Self, RelayCodecError> {
        require_outer(cell, CellType::RelaySub)?;
        match cell.payload.len().cmp(&RELAY_SUB_LEN) {
            core::cmp::Ordering::Less => return Err(RelayCodecError::Malformed),
            core::cmp::Ordering::Greater => return Err(RelayCodecError::TrailingBytes),
            core::cmp::Ordering::Equal => {}
        }
        if cell.payload[0] != PROTOCOL_VERSION || cell.payload[1] != RELAY_SUBSCRIBE {
            return Err(RelayCodecError::NonCanonicalCell);
        }
        let value = Self {
            queue_id: cell.payload[2..34]
                .try_into()
                .map_err(|_| RelayCodecError::Malformed)?,
            epoch: read_u64(&cell.payload[34..42])?,
            subscription_expiry: read_u64(&cell.payload[42..50])?,
            nonce: cell.payload[50..66]
                .try_into()
                .map_err(|_| RelayCodecError::Malformed)?,
        };
        relay_sub_mac(sub_cap, relay_service_id, &value)?
            .verify_slice(&cell.payload[66..])
            .map_err(|_| RelayCodecError::InvalidMac)?;
        reject_expired(value.subscription_expiry, now_unix)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frwd {
    pub target: RelayTarget,
    pub frwd_expiry: u64,
    /// `None` is a cover FRWD (`push_len = 0`): authenticated and admitted
    /// like a real one, but the intermediary opens no downstream connection.
    pub relay_push: Option<UnauthenticatedRelayPush>,
    pub nonce: Nonce,
}

impl Frwd {
    pub fn is_cover(&self) -> bool {
        self.relay_push.is_none()
    }
}

impl Frwd {
    pub fn encode_into_cell(
        &self,
        hop_key: &HopKey,
        intermediary_service_id: &ServiceId,
        allow_local_fixture: bool,
    ) -> Result<Cell, RelayCodecError> {
        self.encode_into_cell_with_policy(
            hop_key,
            intermediary_service_id,
            &FrwdTargetPolicy::new(allow_local_fixture),
        )
    }

    pub fn encode_into_cell_with_policy(
        &self,
        hop_key: &HopKey,
        intermediary_service_id: &ServiceId,
        policy: &FrwdTargetPolicy,
    ) -> Result<Cell, RelayCodecError> {
        validate_frwd_target_with_policy(&self.target, policy)?;
        let push_natural = match &self.relay_push {
            Some(push) => encode_relay_push_natural(push.as_cell())?,
            None => Vec::new(),
        };
        if push_natural.len() > MAX_RELAY_PUSH_NATURAL_LEN {
            return Err(RelayCodecError::CellTooLarge);
        }
        let push_len =
            u16::try_from(push_natural.len()).map_err(|_| RelayCodecError::CellTooLarge)?;
        let payload_len = FRWD_FIXED_LEN
            .checked_add(push_natural.len())
            .ok_or(RelayCodecError::CellTooLarge)?;
        if payload_len > Bucket::B3.max_payload() {
            return Err(RelayCodecError::CellTooLarge);
        }
        let target = self.target.encode();
        let mut payload = Vec::with_capacity(payload_len);
        payload.push(PROTOCOL_VERSION);
        payload.extend_from_slice(&target);
        payload.extend_from_slice(&self.frwd_expiry.to_be_bytes());
        payload.extend_from_slice(&push_len.to_be_bytes());
        payload.extend_from_slice(&push_natural);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&frwd_tag(
            hop_key,
            intermediary_service_id,
            self,
            &push_natural,
            push_len,
        )?);
        Ok(Cell::new(CellType::Frwd, 0, 0, payload))
    }

    pub fn decode_from_cell(
        cell: &Cell,
        hop_key: &HopKey,
        intermediary_service_id: &ServiceId,
        now_unix: u64,
        allow_local_fixture: bool,
    ) -> Result<Self, RelayCodecError> {
        Self::decode_from_cell_with_policy(
            cell,
            hop_key,
            intermediary_service_id,
            now_unix,
            &FrwdTargetPolicy::new(allow_local_fixture),
        )
    }

    pub fn decode_from_cell_with_policy(
        cell: &Cell,
        hop_key: &HopKey,
        intermediary_service_id: &ServiceId,
        now_unix: u64,
        policy: &FrwdTargetPolicy,
    ) -> Result<Self, RelayCodecError> {
        require_outer(cell, CellType::Frwd)?;
        if cell.payload.len() > Bucket::B3.max_payload() {
            return Err(RelayCodecError::CellTooLarge);
        }
        if cell.payload.len() < FRWD_FIXED_LEN {
            return Err(RelayCodecError::Malformed);
        }
        if cell.payload[0] != PROTOCOL_VERSION {
            return Err(RelayCodecError::NonCanonicalCell);
        }
        let target = RelayTarget::decode(&cell.payload[1..52])?;
        let frwd_expiry = read_u64(&cell.payload[52..60])?;
        let push_len = read_u16(&cell.payload[60..62])? as usize;
        if push_len > MAX_RELAY_PUSH_NATURAL_LEN {
            return Err(RelayCodecError::CellTooLarge);
        }
        let expected_len = FRWD_FIXED_LEN
            .checked_add(push_len)
            .ok_or(RelayCodecError::CellTooLarge)?;
        match cell.payload.len().cmp(&expected_len) {
            core::cmp::Ordering::Less => return Err(RelayCodecError::Malformed),
            core::cmp::Ordering::Greater => return Err(RelayCodecError::TrailingBytes),
            core::cmp::Ordering::Equal => {}
        }
        let push_end = 62 + push_len;
        let relay_push = if push_len == 0 {
            None
        } else {
            let nested = decode_relay_push_natural(&cell.payload[62..push_end])?;
            Some(UnauthenticatedRelayPush::parse(nested)?)
        };
        let nonce = cell.payload[push_end..push_end + 16]
            .try_into()
            .map_err(|_| RelayCodecError::Malformed)?;
        let value = Self {
            target,
            frwd_expiry,
            relay_push,
            nonce,
        };
        frwd_mac(
            hop_key,
            intermediary_service_id,
            &value,
            &cell.payload[62..push_end],
            push_len as u16,
        )?
        .verify_slice(&cell.payload[push_end + 16..])
        .map_err(|_| RelayCodecError::InvalidMac)?;
        reject_expired(value.frwd_expiry, now_unix)?;
        if let Some(push) = &value.relay_push {
            reject_expired(push.push_expiry(), now_unix)?;
        }
        validate_frwd_target_with_policy(&value.target, policy)?;
        Ok(value)
    }
}

struct PushParts<'a> {
    queue_id: QueueId,
    epoch: u64,
    push_nonce: Nonce,
    push_expiry: u64,
    msg_len: u16,
    msg_natural: &'a [u8],
    supplied_tag: &'a [u8],
}

fn parse_push_payload(payload: &[u8]) -> Result<PushParts<'_>, RelayCodecError> {
    if payload.len() > RELAY_PUSH_FIXED_LEN + MAX_MSG_NATURAL_LEN {
        return Err(RelayCodecError::CellTooLarge);
    }
    if payload.len() < RELAY_PUSH_FIXED_LEN {
        return Err(RelayCodecError::Malformed);
    }
    if payload[0] != PROTOCOL_VERSION {
        return Err(RelayCodecError::NonCanonicalCell);
    }
    let msg_len = read_u16(&payload[65..67])?;
    if msg_len != 0 && (msg_len as usize) < HEADER_LEN {
        return Err(RelayCodecError::Malformed);
    }
    if msg_len as usize > MAX_MSG_NATURAL_LEN {
        return Err(RelayCodecError::CellTooLarge);
    }
    let expected_len = RELAY_PUSH_FIXED_LEN
        .checked_add(msg_len as usize)
        .ok_or(RelayCodecError::CellTooLarge)?;
    match payload.len().cmp(&expected_len) {
        core::cmp::Ordering::Less => return Err(RelayCodecError::Malformed),
        core::cmp::Ordering::Greater => return Err(RelayCodecError::TrailingBytes),
        core::cmp::Ordering::Equal => {}
    }
    let msg_end = 67 + msg_len as usize;
    if msg_len != 0 {
        validate_natural(&payload[67..msg_end], CellType::Msg)?;
    }
    Ok(PushParts {
        queue_id: payload[1..33]
            .try_into()
            .map_err(|_| RelayCodecError::Malformed)?,
        epoch: read_u64(&payload[33..41])?,
        push_nonce: payload[41..57]
            .try_into()
            .map_err(|_| RelayCodecError::Malformed)?,
        push_expiry: read_u64(&payload[57..65])?,
        msg_len,
        msg_natural: &payload[67..msg_end],
        supplied_tag: &payload[msg_end..],
    })
}

fn relay_push_tag(
    key: &PushCap,
    relay_service_id: &ServiceId,
    value: &RelayPush,
    msg_len: u16,
    msg_natural: &[u8],
) -> Result<[u8; MAC_LEN], RelayCodecError> {
    let mut mac = new_mac(key)?;
    mac.update(RELAY_PUSH_DOMAIN);
    mac.update(&[PROTOCOL_VERSION]);
    mac.update(relay_service_id);
    mac.update(&value.queue_id);
    mac.update(&value.epoch.to_be_bytes());
    mac.update(&[CellType::RelayPush as u8]);
    mac.update(&value.push_nonce);
    mac.update(&value.push_expiry.to_be_bytes());
    mac.update(&msg_len.to_be_bytes());
    mac.update(msg_natural);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_relay_push_tag(
    key: &PushCap,
    relay_service_id: &ServiceId,
    parts: &PushParts<'_>,
) -> Result<(), RelayCodecError> {
    let mut mac = new_mac(key)?;
    mac.update(RELAY_PUSH_DOMAIN);
    mac.update(&[PROTOCOL_VERSION]);
    mac.update(relay_service_id);
    mac.update(&parts.queue_id);
    mac.update(&parts.epoch.to_be_bytes());
    mac.update(&[CellType::RelayPush as u8]);
    mac.update(&parts.push_nonce);
    mac.update(&parts.push_expiry.to_be_bytes());
    mac.update(&parts.msg_len.to_be_bytes());
    mac.update(parts.msg_natural);
    mac.verify_slice(parts.supplied_tag)
        .map_err(|_| RelayCodecError::InvalidMac)
}

fn relay_sub_tag(
    key: &SubCap,
    relay_service_id: &ServiceId,
    value: &RelaySub,
) -> Result<[u8; MAC_LEN], RelayCodecError> {
    Ok(relay_sub_mac(key, relay_service_id, value)?
        .finalize()
        .into_bytes()
        .into())
}

fn relay_sub_mac(
    key: &SubCap,
    relay_service_id: &ServiceId,
    value: &RelaySub,
) -> Result<Hmac<Sha256>, RelayCodecError> {
    let mut mac = new_mac(key)?;
    mac.update(RELAY_SUB_DOMAIN);
    mac.update(&[PROTOCOL_VERSION]);
    mac.update(relay_service_id);
    mac.update(&value.queue_id);
    mac.update(&value.epoch.to_be_bytes());
    mac.update(&[RELAY_SUBSCRIBE]);
    mac.update(&value.subscription_expiry.to_be_bytes());
    mac.update(&value.nonce);
    mac.update(&0u16.to_be_bytes());
    Ok(mac)
}

fn frwd_tag(
    key: &HopKey,
    intermediary_service_id: &ServiceId,
    value: &Frwd,
    push_natural: &[u8],
    push_len: u16,
) -> Result<[u8; MAC_LEN], RelayCodecError> {
    Ok(
        frwd_mac(key, intermediary_service_id, value, push_natural, push_len)?
            .finalize()
            .into_bytes()
            .into(),
    )
}

fn frwd_mac(
    key: &HopKey,
    intermediary_service_id: &ServiceId,
    value: &Frwd,
    push_natural: &[u8],
    push_len: u16,
) -> Result<Hmac<Sha256>, RelayCodecError> {
    let mut mac = new_mac(key)?;
    mac.update(FRWD_DOMAIN);
    mac.update(&[PROTOCOL_VERSION]);
    mac.update(intermediary_service_id);
    mac.update(&value.target.relay_service_id);
    // A cover FRWD binds zero queue/epoch fields: it carries no deposit.
    let (queue_id, epoch) = match &value.relay_push {
        Some(push) => (push.queue_id(), push.epoch()),
        None => ([0u8; 32], 0u64),
    };
    mac.update(&queue_id);
    mac.update(&epoch.to_be_bytes());
    mac.update(&[CellType::Frwd as u8]);
    mac.update(&value.frwd_expiry.to_be_bytes());
    mac.update(&value.nonce);
    mac.update(&push_len.to_be_bytes());
    mac.update(push_natural);
    Ok(mac)
}

fn new_mac(key: &[u8; 32]) -> Result<Hmac<Sha256>, RelayCodecError> {
    Hmac::<Sha256>::new_from_slice(key).map_err(|_| RelayCodecError::Malformed)
}

fn reject_expired(expires_unix: u64, now_unix: u64) -> Result<(), RelayCodecError> {
    if expires_unix <= now_unix {
        Err(RelayCodecError::Expired {
            expires_unix,
            now_unix,
        })
    } else {
        Ok(())
    }
}

fn require_outer(cell: &Cell, expected: CellType) -> Result<(), RelayCodecError> {
    if cell.cell_type() != Some(expected) {
        return Err(RelayCodecError::WrongCellType);
    }
    if cell.version != PROTOCOL_VERSION || cell.flags != 0 {
        return Err(RelayCodecError::NonCanonicalCell);
    }
    Ok(())
}

fn encode_msg_natural(cell: &Cell) -> Result<Vec<u8>, RelayCodecError> {
    RelayPush::validate_message(cell)?;
    encode_natural(cell, MAX_MSG_NATURAL_LEN)
}

fn encode_relay_push_natural(cell: &Cell) -> Result<Vec<u8>, RelayCodecError> {
    require_outer(cell, CellType::RelayPush)?;
    parse_push_payload(&cell.payload)?;
    encode_natural(cell, MAX_RELAY_PUSH_NATURAL_LEN)
}

fn natural_length(cell: &Cell, max_len: usize) -> Result<usize, RelayCodecError> {
    if cell.version != PROTOCOL_VERSION
        || cell.flags & !0x03 != 0
        || CellType::from_raw(cell.raw_type).is_none()
    {
        return Err(RelayCodecError::NonCanonicalCell);
    }
    let natural_len = HEADER_LEN
        .checked_add(cell.payload.len())
        .ok_or(RelayCodecError::CellTooLarge)?;
    if natural_len > max_len || cell.payload.len() > u16::MAX as usize {
        return Err(RelayCodecError::CellTooLarge);
    }
    Ok(natural_len)
}

fn encode_natural(cell: &Cell, max_len: usize) -> Result<Vec<u8>, RelayCodecError> {
    let natural_len = natural_length(cell, max_len)?;
    let payload_len =
        u16::try_from(cell.payload.len()).map_err(|_| RelayCodecError::CellTooLarge)?;
    let mut encoded = Vec::with_capacity(natural_len);
    encoded.push((cell.version << 4) | cell.raw_type);
    encoded.push(cell.flags);
    encoded.extend_from_slice(&cell.round_ctr.to_be_bytes());
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(&cell.payload);
    Ok(encoded)
}

fn validate_natural(encoded: &[u8], expected: CellType) -> Result<(), RelayCodecError> {
    if encoded.len() < HEADER_LEN {
        return Err(RelayCodecError::Malformed);
    }
    let version = encoded[0] >> 4;
    let raw_type = encoded[0] & 0x0f;
    if raw_type != expected as u8 {
        return Err(match expected {
            CellType::Msg => RelayCodecError::InnerNotMsg,
            CellType::RelayPush => RelayCodecError::InnerNotRelayPush,
            _ => RelayCodecError::WrongCellType,
        });
    }
    if version != PROTOCOL_VERSION || encoded[1] & !0x03 != 0 {
        return Err(RelayCodecError::NonCanonicalCell);
    }
    let payload_len = read_u16(&encoded[4..6])? as usize;
    let expected_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(RelayCodecError::CellTooLarge)?;
    match encoded.len().cmp(&expected_len) {
        core::cmp::Ordering::Less => Err(RelayCodecError::Malformed),
        core::cmp::Ordering::Greater => Err(RelayCodecError::TrailingBytes),
        core::cmp::Ordering::Equal => Ok(()),
    }
}

fn decode_msg_natural(encoded: &[u8]) -> Result<Cell, RelayCodecError> {
    validate_natural(encoded, CellType::Msg)?;
    decode_validated_natural(encoded)
}

fn decode_relay_push_natural(encoded: &[u8]) -> Result<Cell, RelayCodecError> {
    validate_natural(encoded, CellType::RelayPush)?;
    decode_validated_natural(encoded)
}

fn decode_validated_natural(encoded: &[u8]) -> Result<Cell, RelayCodecError> {
    Ok(Cell {
        version: encoded[0] >> 4,
        raw_type: encoded[0] & 0x0f,
        flags: encoded[1],
        round_ctr: read_u16(&encoded[2..4])?,
        payload: encoded[HEADER_LEN..].to_vec(),
    })
}

fn read_u16(bytes: &[u8]) -> Result<u16, RelayCodecError> {
    Ok(u16::from_be_bytes(
        bytes.try_into().map_err(|_| RelayCodecError::Malformed)?,
    ))
}

fn read_u64(bytes: &[u8]) -> Result<u64, RelayCodecError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| RelayCodecError::Malformed)?,
    ))
}

fn is_ordinary_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let octets = ip.octets();
            // Ordinary global unicast is 2000::/3. Exclude reserved and
            // documentation/benchmark prefixes inside that block.
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001
                    && (segments[1] == 0x0002
                        || segments[1] == 0x000d
                        || (0x0010..=0x002f).contains(&segments[1])
                        || segments[1] == 0x0db8))
                && !(segments[0] == 0x2002)
                && !(segments[0] == 0x3fff && octets[2] < 0x10)
                && ip.to_ipv4_mapped().is_none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const PUSH_CAP: PushCap = [0x41; 32];
    const SUB_CAP: SubCap = [0x53; 32];
    const HOP_KEY: HopKey = [0x48; 32];
    const RELAY_ID: ServiceId = [0x72; 32];
    const INTERMEDIARY_ID: ServiceId = [0x69; 32];

    fn push() -> RelayPush {
        RelayPush {
            queue_id: [1; 32],
            epoch: 0x0102_0304_0506_0708,
            push_nonce: [2; 16],
            push_expiry: NOW + 60,
            msg: Some(Cell::new(CellType::Msg, 0x02, 0x1234, vec![3, 4, 5])),
        }
    }

    fn push_wire() -> UnauthenticatedRelayPush {
        UnauthenticatedRelayPush::parse(push().encode_into_cell(&PUSH_CAP, &RELAY_ID).unwrap())
            .unwrap()
    }

    fn target(address: &str) -> RelayTarget {
        RelayTarget {
            address: address.parse().unwrap(),
            relay_service_id: RELAY_ID,
        }
    }

    fn frwd(address: &str) -> Frwd {
        Frwd {
            target: target(address),
            frwd_expiry: NOW + 30,
            relay_push: Some(push_wire()),
            nonce: [8; 16],
        }
    }

    #[test]
    fn relay_push_exact_layout_roundtrip_and_context() {
        let value = push();
        let cell = value.encode_into_cell(&PUSH_CAP, &RELAY_ID).unwrap();
        assert_eq!(cell.payload.len(), RELAY_PUSH_FIXED_LEN + 9);
        assert_eq!(cell.payload[0], 1);
        assert_eq!(&cell.payload[1..33], &[1; 32]);
        assert_eq!(&cell.payload[33..41], &value.epoch.to_be_bytes());
        assert_eq!(&cell.payload[41..57], &[2; 16]);
        assert_eq!(&cell.payload[57..65], &(NOW + 60).to_be_bytes());
        assert_eq!(&cell.payload[65..67], &9u16.to_be_bytes());
        assert_eq!(
            &cell.payload[67..76],
            &[0x12, 0x02, 0x12, 0x34, 0, 3, 3, 4, 5]
        );
        assert_eq!(
            RelayPush::decode_from_cell(&cell, &PUSH_CAP, &RELAY_ID, NOW).unwrap(),
            value
        );
        assert_eq!(
            RelayPush::decode_from_cell(&cell, &PUSH_CAP, &[9; 32], NOW),
            Err(RelayCodecError::InvalidMac)
        );
    }

    #[test]
    fn relay_push_domain_has_nul_and_rejects_tamper_expiry_and_non_msg() {
        assert_eq!(RELAY_PUSH_DOMAIN.last(), Some(&0));
        let cell = push().encode_into_cell(&PUSH_CAP, &RELAY_ID).unwrap();
        for index in [1, 33, 41, 57, 67, cell.payload.len() - 1] {
            let mut tampered = cell.clone();
            tampered.payload[index] ^= 1;
            assert!(RelayPush::decode_from_cell(&tampered, &PUSH_CAP, &RELAY_ID, NOW).is_err());
        }
        assert!(matches!(
            RelayPush::decode_from_cell(&cell, &PUSH_CAP, &RELAY_ID, NOW + 60),
            Err(RelayCodecError::Expired { .. })
        ));
        let mut not_msg = push();
        not_msg.msg = Some(Cell::new(CellType::Ack, 0, 0, vec![]));
        assert_eq!(
            not_msg.encode_into_cell(&PUSH_CAP, &RELAY_ID),
            Err(RelayCodecError::InnerNotMsg)
        );
    }

    #[test]
    fn message_preflight_matches_encoder_at_type_header_and_capacity_boundaries() {
        for raw_type in 0..16 {
            for version in [0, PROTOCOL_VERSION, 2, 15] {
                for flags in [0, 1, 3, 4, 255] {
                    let mut cell = Cell::new(CellType::Msg, flags, 65535, vec![7; 128]);
                    cell.raw_type = raw_type;
                    cell.version = version;
                    let preflight = RelayPush::validate_message(&cell);
                    assert_eq!(
                        preflight.is_ok(),
                        raw_type == CellType::Msg as u8
                            && version == PROTOCOL_VERSION
                            && flags & !3 == 0,
                        "{raw_type}/{version}/{flags}"
                    );
                    let encoded = RelayPush {
                        msg: Some(cell),
                        ..push()
                    }
                    .encode_into_cell(&PUSH_CAP, &RELAY_ID)
                    .map(|_| ());
                    assert_eq!(preflight, encoded, "{raw_type}/{version}/{flags}");
                }
            }
        }
        for length in [0, 15_359, 15_360, 15_361, 65_536] {
            let cell = Cell::new(CellType::Msg, 3, 1, vec![7; length]);
            assert_eq!(RelayPush::validate_message(&cell).is_ok(), length <= 15_360);
            let expected = RelayPush::validate_message(&cell);
            assert_eq!(
                expected,
                RelayPush {
                    msg: Some(cell),
                    ..push()
                }
                .encode_into_cell(&PUSH_CAP, &RELAY_ID)
                .map(|_| ())
            );
        }
    }

    #[test]
    fn relay_push_rejects_trailing_truncation_and_capacity_before_allocation() {
        let cell = push().encode_into_cell(&PUSH_CAP, &RELAY_ID).unwrap();
        let mut trailing = cell.clone();
        trailing.payload.push(0);
        assert_eq!(
            RelayPush::decode_from_cell(&trailing, &PUSH_CAP, &RELAY_ID, NOW),
            Err(RelayCodecError::TrailingBytes)
        );
        for len in 0..cell.payload.len() {
            let mut truncated = cell.clone();
            truncated.payload.truncate(len);
            assert!(RelayPush::decode_from_cell(&truncated, &PUSH_CAP, &RELAY_ID, NOW).is_err());
        }
        let too_large = RelayPush {
            msg: Some(Cell::new(
                CellType::Msg,
                0,
                0,
                vec![0; MAX_MSG_NATURAL_LEN - HEADER_LEN + 1],
            )),
            ..push()
        };
        assert_eq!(
            too_large.encode_into_cell(&PUSH_CAP, &RELAY_ID),
            Err(RelayCodecError::CellTooLarge)
        );
    }

    #[test]
    fn relay_subscribe_exact_layout_roundtrip_tamper_and_expiry() {
        assert_eq!(RELAY_SUB_DOMAIN.last(), Some(&0));
        let value = RelaySub {
            queue_id: [11; 32],
            epoch: 12,
            subscription_expiry: NOW + 1,
            nonce: [13; 16],
        };
        let cell = value.encode_into_cell(&SUB_CAP, &RELAY_ID).unwrap();
        assert_eq!(cell.payload.len(), RELAY_SUB_LEN);
        assert_eq!(&cell.payload[..2], &[1, 5]);
        assert_eq!(&cell.payload[2..34], &[11; 32]);
        assert_eq!(&cell.payload[34..42], &12u64.to_be_bytes());
        assert_eq!(&cell.payload[42..50], &(NOW + 1).to_be_bytes());
        assert_eq!(&cell.payload[50..66], &[13; 16]);
        assert_eq!(
            RelaySub::decode_from_cell(&cell, &SUB_CAP, &RELAY_ID, NOW).unwrap(),
            value
        );
        for (index, expected) in [
            (1, RelayCodecError::NonCanonicalCell),
            (50, RelayCodecError::InvalidMac),
            (97, RelayCodecError::InvalidMac),
        ] {
            let mut tampered = cell.clone();
            tampered.payload[index] ^= 1;
            assert_eq!(
                RelaySub::decode_from_cell(&tampered, &SUB_CAP, &RELAY_ID, NOW),
                Err(expected)
            );
        }
        assert_eq!(
            RelaySub::decode_from_cell(&cell, &SUB_CAP, &[0; 32], NOW),
            Err(RelayCodecError::InvalidMac)
        );
        assert!(matches!(
            RelaySub::decode_from_cell(&cell, &SUB_CAP, &RELAY_ID, NOW + 1),
            Err(RelayCodecError::Expired { .. })
        ));
        for len in 0..cell.payload.len() {
            let mut truncated = cell.clone();
            truncated.payload.truncate(len);
            assert!(RelaySub::decode_from_cell(&truncated, &SUB_CAP, &RELAY_ID, NOW).is_err());
        }
    }

    #[test]
    fn frwd_exact_ipv4_layout_roundtrip_and_fixed_fields() {
        assert_eq!(FRWD_DOMAIN.last(), Some(&0));
        let value = frwd("8.8.8.8:443");
        let cell = value
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();
        let push_len = encode_relay_push_natural(value.relay_push.as_ref().unwrap().as_cell())
            .unwrap()
            .len();
        let msg_len = encode_msg_natural(push().msg.as_ref().unwrap())
            .unwrap()
            .len();
        assert_eq!(cell.payload.len(), FRWD_FIXED_LEN + push_len);
        assert_eq!(cell.payload.len(), 215 + msg_len);
        assert_eq!(cell.payload[0], 1);
        assert_eq!(&cell.payload[1..6], &[4, 8, 8, 8, 8]);
        assert!(cell.payload[6..18].iter().all(|byte| *byte == 0));
        assert_eq!(&cell.payload[18..20], &443u16.to_be_bytes());
        assert_eq!(&cell.payload[20..52], &RELAY_ID);
        assert_eq!(&cell.payload[52..60], &(NOW + 30).to_be_bytes());
        assert_eq!(&cell.payload[60..62], &(push_len as u16).to_be_bytes());
        assert_eq!(cell.payload[62] & 0x0f, CellType::RelayPush as u8);
        assert_eq!(&cell.payload[62 + push_len..78 + push_len], &[8; 16]);
        let decoded =
            Frwd::decode_from_cell(&cell, &HOP_KEY, &INTERMEDIARY_ID, NOW, false).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn frwd_tag_matches_the_spec_transcript() {
        let value = frwd("8.8.8.8:443");
        let push_natural =
            encode_relay_push_natural(value.relay_push.as_ref().unwrap().as_cell()).unwrap();
        let push_len = push_natural.len() as u16;
        let cell = value
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();

        let mut mac = Hmac::<Sha256>::new_from_slice(&HOP_KEY).unwrap();
        mac.update(b"GC1/FRWD\0");
        mac.update(&[PROTOCOL_VERSION]);
        mac.update(&INTERMEDIARY_ID);
        mac.update(&RELAY_ID);
        mac.update(&value.relay_push.as_ref().unwrap().queue_id());
        mac.update(&value.relay_push.as_ref().unwrap().epoch().to_be_bytes());
        mac.update(&[CellType::Frwd as u8]);
        mac.update(&value.frwd_expiry.to_be_bytes());
        mac.update(&value.nonce);
        mac.update(&push_len.to_be_bytes());
        mac.update(&push_natural);
        mac.verify_slice(&cell.payload[cell.payload.len() - MAC_LEN..])
            .unwrap();
    }

    #[test]
    fn frwd_accepts_the_maximum_natural_msg_with_capacity_to_spare() {
        let max_push = RelayPush {
            msg: Some(Cell::new(
                CellType::Msg,
                0,
                0,
                vec![0; MAX_MSG_NATURAL_LEN - HEADER_LEN],
            )),
            ..push()
        };
        let value = Frwd {
            relay_push: Some(
                UnauthenticatedRelayPush::parse(
                    max_push.encode_into_cell(&PUSH_CAP, &RELAY_ID).unwrap(),
                )
                .unwrap(),
            ),
            ..frwd("8.8.8.8:443")
        };
        let cell = value
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();

        assert_eq!(cell.payload.len(), 215 + MAX_MSG_NATURAL_LEN);
        assert_eq!(Bucket::B3.max_payload() - cell.payload.len(), 797);
        assert_eq!(
            Frwd::decode_from_cell(&cell, &HOP_KEY, &INTERMEDIARY_ID, NOW, false).unwrap(),
            value
        );
    }

    #[test]
    fn frwd_ipv6_roundtrip_context_tamper_expiry_and_trailing() {
        let value = frwd("[2606:4700:4700::1111]:8443");
        let cell = value
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();
        assert_eq!(cell.payload[1], 6);
        assert_eq!(
            Frwd::decode_from_cell(&cell, &HOP_KEY, &[0; 32], NOW, false),
            Err(RelayCodecError::InvalidMac)
        );
        for index in [1, 20, 52, 62, cell.payload.len() - 1] {
            let mut tampered = cell.clone();
            tampered.payload[index] ^= 1;
            assert!(
                Frwd::decode_from_cell(&tampered, &HOP_KEY, &INTERMEDIARY_ID, NOW, false).is_err()
            );
        }
        assert!(matches!(
            Frwd::decode_from_cell(&cell, &HOP_KEY, &INTERMEDIARY_ID, NOW + 30, false),
            Err(RelayCodecError::Expired { .. })
        ));
        let mut trailing = cell;
        trailing.payload.push(0);
        assert_eq!(
            Frwd::decode_from_cell(&trailing, &HOP_KEY, &INTERMEDIARY_ID, NOW, false),
            Err(RelayCodecError::TrailingBytes)
        );
    }

    #[test]
    fn intermediary_parses_push_without_destination_capability() {
        let mut bad_push = push().encode_into_cell(&PUSH_CAP, &RELAY_ID).unwrap();
        let last = bad_push.payload.len() - 1;
        bad_push.payload[last] ^= 1;
        let value = Frwd {
            relay_push: Some(UnauthenticatedRelayPush::parse(bad_push).unwrap()),
            ..frwd("8.8.4.4:443")
        };
        let cell = value
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();
        let decoded =
            Frwd::decode_from_cell(&cell, &HOP_KEY, &INTERMEDIARY_ID, NOW, false).unwrap();
        assert_eq!(
            decoded
                .relay_push
                .unwrap()
                .authenticate(&PUSH_CAP, &RELAY_ID, NOW),
            Err(RelayCodecError::InvalidMac)
        );
    }

    #[test]
    fn frwd_rejects_every_truncation_and_noncanonical_nested_cell() {
        let cell = frwd("1.1.1.1:443")
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();
        for len in 0..cell.payload.len() {
            let mut truncated = cell.clone();
            truncated.payload.truncate(len);
            assert!(
                Frwd::decode_from_cell(&truncated, &HOP_KEY, &INTERMEDIARY_ID, NOW, false).is_err()
            );
        }
        let mut non_push = cell;
        non_push.payload[62] = 0x12;
        assert_eq!(
            Frwd::decode_from_cell(&non_push, &HOP_KEY, &INTERMEDIARY_ID, NOW, false),
            Err(RelayCodecError::InnerNotRelayPush)
        );
    }

    #[test]
    fn target_validation_rejects_special_ranges_and_allows_explicit_fixtures() {
        for address in [
            "0.0.0.0:443",
            "10.0.0.1:443",
            "100.64.0.1:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "172.16.0.1:443",
            "192.0.2.1:443",
            "192.168.1.1:443",
            "198.18.0.1:443",
            "198.51.100.1:443",
            "203.0.113.1:443",
            "224.0.0.1:443",
            "[::]:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[2001:db8::1]:443",
            "[ff02::1]:443",
            "[::ffff:8.8.8.8]:443",
        ] {
            let target = target(address);
            assert_eq!(
                validate_frwd_target(&target, false),
                Err(RelayCodecError::InvalidTarget),
                "{address}"
            );
            assert_eq!(validate_frwd_target(&target, true), Ok(()), "{address}");
        }
        assert_eq!(validate_frwd_target(&target("8.8.8.8:443"), false), Ok(()));
        assert_eq!(
            validate_frwd_target(&target("[2606:4700::1111]:443"), false),
            Ok(())
        );
        assert_eq!(
            validate_frwd_target(&target("8.8.8.8:0"), true),
            Err(RelayCodecError::InvalidTarget)
        );
    }

    #[test]
    fn exact_address_policy_does_not_authorize_neighbor_addresses_or_ports() {
        for address in ["127.0.0.1:8443", "[::1]:8443"] {
            let endpoint = target(address);
            let policy = FrwdTargetPolicy::new(false)
                .allow_exact_address(endpoint.address)
                .unwrap();
            assert!(validate_frwd_target_with_policy(&endpoint, &policy).is_ok());
            let mut other = endpoint.clone();
            other.address.set_port(8444);
            assert!(validate_frwd_target_with_policy(&other, &policy).is_err());
            other.address = if endpoint.address.is_ipv4() {
                "127.0.0.2:8443"
            } else {
                "[::2]:8443"
            }
            .parse()
            .unwrap();
            assert!(validate_frwd_target_with_policy(&other, &policy).is_err());
        }
        for address in [
            "0.0.0.0:443",
            "127.0.0.1:0",
            "224.0.0.1:443",
            "[ff02::1]:443",
        ] {
            assert!(FrwdTargetPolicy::new(false)
                .allow_exact_address(address.parse().unwrap())
                .is_err());
        }
    }

    #[test]
    fn target_policy_limits_private_destinations_by_cidr_and_port() {
        let policy = FrwdTargetPolicy::new(false)
            .allow_private_cidr("10.244.0.0/16", 8443)
            .unwrap();
        assert_eq!(
            validate_frwd_target_with_policy(&target("10.244.7.42:8443"), &policy),
            Ok(())
        );
        for address in ["10.245.0.1:8443", "10.244.7.42:443", "127.0.0.1:8443"] {
            assert_eq!(
                validate_frwd_target_with_policy(&target(address), &policy),
                Err(RelayCodecError::InvalidTarget),
                "{address}"
            );
        }

        let value = frwd("10.244.7.42:8443");
        let cell = value
            .encode_into_cell_with_policy(&HOP_KEY, &INTERMEDIARY_ID, &policy)
            .unwrap();
        assert_eq!(
            Frwd::decode_from_cell_with_policy(&cell, &HOP_KEY, &INTERMEDIARY_ID, NOW, &policy,)
                .unwrap(),
            value
        );
        assert!(FrwdTargetPolicy::new(false)
            .allow_private_cidr("10.244.0.0/33", 8443)
            .is_err());
        assert!(FrwdTargetPolicy::new(false)
            .allow_private_cidr("10.244.0.0/16", 0)
            .is_err());
    }

    #[test]
    fn target_ipv4_encoding_requires_twelve_zero_bytes() {
        let cell = frwd("8.8.8.8:443")
            .encode_into_cell(&HOP_KEY, &INTERMEDIARY_ID, false)
            .unwrap();
        let mut malformed = cell;
        malformed.payload[6] = 1;
        assert_eq!(
            Frwd::decode_from_cell(&malformed, &HOP_KEY, &INTERMEDIARY_ID, NOW, false),
            Err(RelayCodecError::NonCanonicalTarget)
        );
    }
}
