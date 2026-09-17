//! Canonical GC/1 private streaming file application records (SPEC section 11.4).

use alloc::vec::Vec;
use core::error::Error;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const PROFILE: u8 = 0x01;
/// Legacy per-record stop-and-wait file profile.
pub const PROFILE_VERSION_V1: u8 = 1;
/// Checkpoint-batched file profile.
pub const PROFILE_VERSION_V2: u8 = 2;
/// Kept as the byte-exact legacy default for callers which explicitly build
/// GC/1 v1 fixtures.
pub const PROFILE_VERSION: u8 = PROFILE_VERSION_V1;
pub const CHECKPOINT_BATCH_CHUNKS_MAX: u64 = 32;
pub const CONTACT_LEN: usize = 132;
pub const FILE_CONTACT_LEN: usize = 213;
pub const FILE_INIT_LEN: usize = 249;
pub const FILE_CHUNK_FIXED_LEN: usize = 67;
pub const FILE_FINISH_LEN: usize = 59;
pub const FILE_ACK_LEN: usize = 62;
pub const MAX_FILE_RECORD_LEN: usize = super::MAX_MESSAGE;
pub const MAX_FILE_CHUNK_DATA: usize = MAX_FILE_RECORD_LEN - FILE_CHUNK_FIXED_LEN;

const COMMON_LEN: usize = 19;
const FILE_INIT: u8 = 0x01;
const FILE_CHUNK: u8 = 0x02;
const FILE_FINISH: u8 = 0x03;
const FILE_ACK: u8 = 0x04;
const FILE_INIT_DOMAIN: &[u8] = b"GC1/FILE-INIT\0";

pub type TransferId = [u8; 16];
pub type FileCapability = [u8; 32];
pub type Sha256Digest = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileCodecError {
    Truncated { needed: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    InvalidProfile(u8),
    InvalidProfileVersion(u8),
    ProfileVersionMismatch { expected: u8, actual: u8 },
    InvalidRecordType(u8),
    InvalidContactVersion(u8),
    InvalidAddressFamily(u8),
    NonCanonicalIpv4,
    InvalidContact,
    Expired { expiry_unix: u64, now_unix: u64 },
    InvalidAckRouteLength(u16),
    RecordTooLarge { actual: usize, maximum: usize },
    ChunkTooLarge { actual: u64, maximum: u64 },
    EmptyChunk,
    InvalidChunkDigest,
    InvalidAckStage(u8),
    InvalidAckCode(u16),
    InvalidAckDisposition,
    TransferMismatch,
    FileSizeExceeded,
    InvalidChunkSize,
    InvalidInflightLimit,
    OffsetMismatch { expected: u64, actual: u64 },
    ChunkExceedsFile,
    FileSizeMismatch,
    FileDigestMismatch,
    InvalidBearerProof,
}

impl fmt::Display for FileCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, actual } => {
                write!(
                    f,
                    "truncated file record: need {needed} bytes, got {actual}"
                )
            }
            Self::TrailingBytes { expected, actual } => {
                write!(
                    f,
                    "file record has trailing bytes: expected {expected}, got {actual}"
                )
            }
            Self::InvalidProfile(value) => write!(f, "invalid file profile {value:#04x}"),
            Self::InvalidProfileVersion(value) => {
                write!(f, "invalid file profile version {value}")
            }
            Self::ProfileVersionMismatch { expected, actual } => write!(
                f,
                "file profile version {actual} does not match authorized version {expected}"
            ),
            Self::InvalidRecordType(value) => write!(f, "invalid file record type {value:#04x}"),
            Self::InvalidContactVersion(value) => write!(f, "invalid contact version {value}"),
            Self::InvalidAddressFamily(value) => write!(f, "invalid address family {value}"),
            Self::NonCanonicalIpv4 => f.write_str("non-canonical IPv4 contact encoding"),
            Self::InvalidContact => f.write_str("invalid contact descriptor"),
            Self::Expired {
                expiry_unix,
                now_unix,
            } => write!(f, "contact expired at {expiry_unix} (now {now_unix})"),
            Self::InvalidAckRouteLength(value) => {
                write!(f, "invalid ACK route length {value}")
            }
            Self::RecordTooLarge { actual, maximum } => {
                write!(f, "file record is {actual} bytes; maximum is {maximum}")
            }
            Self::ChunkTooLarge { actual, maximum } => {
                write!(f, "file chunk is {actual} bytes; maximum is {maximum}")
            }
            Self::EmptyChunk => f.write_str("file chunk data must be nonempty"),
            Self::InvalidChunkDigest => f.write_str("file chunk digest mismatch"),
            Self::InvalidAckStage(value) => write!(f, "invalid file ACK stage {value:#04x}"),
            Self::InvalidAckCode(value) => write!(f, "invalid file ACK code {value:#06x}"),
            Self::InvalidAckDisposition => f.write_str("invalid file ACK stage/code combination"),
            Self::TransferMismatch => f.write_str("file transfer ID mismatch"),
            Self::FileSizeExceeded => f.write_str("file size exceeds authorization"),
            Self::InvalidChunkSize => f.write_str("invalid file chunk size"),
            Self::InvalidInflightLimit => f.write_str("invalid in-flight byte limit"),
            Self::OffsetMismatch { expected, actual } => {
                write!(
                    f,
                    "file chunk offset {actual} does not equal expected {expected}"
                )
            }
            Self::ChunkExceedsFile => f.write_str("file chunk exceeds remaining file length"),
            Self::FileSizeMismatch => f.write_str("file size does not match FileInit"),
            Self::FileDigestMismatch => f.write_str("file digest does not match FileInit"),
            Self::InvalidBearerProof => f.write_str("invalid file bearer proof"),
        }
    }
}

impl Error for FileCodecError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub address: SocketAddr,
    pub relay_service_id: [u8; 32],
    pub queue_id: [u8; 32],
    pub epoch: u64,
    pub push_cap: [u8; 32],
    pub lease_expiry: u64,
}

impl Contact {
    pub fn encode(&self) -> Result<[u8; CONTACT_LEN], FileCodecError> {
        validate_contact_fields(self)?;
        let mut out = [0; CONTACT_LEN];
        out[0] = PROFILE_VERSION;
        match self.address.ip() {
            IpAddr::V4(address) => {
                out[1] = 4;
                out[2..6].copy_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                out[1] = 6;
                out[2..18].copy_from_slice(&address.octets());
            }
        }
        out[18..20].copy_from_slice(&self.address.port().to_be_bytes());
        out[20..52].copy_from_slice(&self.relay_service_id);
        out[52..84].copy_from_slice(&self.queue_id);
        out[84..92].copy_from_slice(&self.epoch.to_be_bytes());
        out[92..124].copy_from_slice(&self.push_cap);
        out[124..132].copy_from_slice(&self.lease_expiry.to_be_bytes());
        Ok(out)
    }

    pub fn decode(encoded: &[u8], now_unix: u64) -> Result<Self, FileCodecError> {
        require_exact(encoded.len(), CONTACT_LEN)?;
        if encoded[0] != PROFILE_VERSION {
            return Err(FileCodecError::InvalidContactVersion(encoded[0]));
        }
        let address_bytes: [u8; 16] = encoded[2..18].try_into().expect("fixed contact slice");
        let ip = match encoded[1] {
            4 if address_bytes[4..].iter().all(|byte| *byte == 0) => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&address_bytes[..4]).unwrap(),
            )),
            4 => return Err(FileCodecError::NonCanonicalIpv4),
            6 => IpAddr::V6(Ipv6Addr::from(address_bytes)),
            family => return Err(FileCodecError::InvalidAddressFamily(family)),
        };
        let contact = Self {
            address: SocketAddr::new(ip, u16::from_be_bytes(encoded[18..20].try_into().unwrap())),
            relay_service_id: encoded[20..52].try_into().unwrap(),
            queue_id: encoded[52..84].try_into().unwrap(),
            epoch: u64::from_be_bytes(encoded[84..92].try_into().unwrap()),
            push_cap: encoded[92..124].try_into().unwrap(),
            lease_expiry: u64::from_be_bytes(encoded[124..132].try_into().unwrap()),
        };
        validate_contact_fields(&contact)?;
        if contact.lease_expiry <= now_unix {
            return Err(FileCodecError::Expired {
                expiry_unix: contact.lease_expiry,
                now_unix,
            });
        }
        Ok(contact)
    }
}

fn validate_contact_fields(contact: &Contact) -> Result<(), FileCodecError> {
    if contact.address.port() == 0
        || contact.epoch == 0
        || contact.relay_service_id.iter().all(|byte| *byte == 0)
        || contact.queue_id.iter().all(|byte| *byte == 0)
        || contact.push_cap.iter().all(|byte| *byte == 0)
    {
        return Err(FileCodecError::InvalidContact);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileContact {
    pub profile_version: u8,
    pub transfer_id: TransferId,
    pub recipient_contact: Contact,
    pub file_cap: FileCapability,
    pub contact_expiry: u64,
    pub max_file_size: u64,
    pub max_chunk_size: u64,
    pub max_inflight_bytes: u64,
}

impl FileContact {
    pub fn encode(&self) -> Result<[u8; FILE_CONTACT_LEN], FileCodecError> {
        self.validate(0)?;
        let mut out = [0; FILE_CONTACT_LEN];
        out[0] = self.profile_version;
        out[1..17].copy_from_slice(&self.transfer_id);
        out[17..149].copy_from_slice(&self.recipient_contact.encode()?);
        out[149..181].copy_from_slice(&self.file_cap);
        out[181..189].copy_from_slice(&self.contact_expiry.to_be_bytes());
        out[189..197].copy_from_slice(&self.max_file_size.to_be_bytes());
        out[197..205].copy_from_slice(&self.max_chunk_size.to_be_bytes());
        out[205..213].copy_from_slice(&self.max_inflight_bytes.to_be_bytes());
        Ok(out)
    }

    pub fn decode(encoded: &[u8], now_unix: u64) -> Result<Self, FileCodecError> {
        require_exact(encoded.len(), FILE_CONTACT_LEN)?;
        validate_profile_version(encoded[0])
            .map_err(|_| FileCodecError::InvalidContactVersion(encoded[0]))?;
        let value = Self {
            profile_version: encoded[0],
            transfer_id: encoded[1..17].try_into().unwrap(),
            recipient_contact: Contact::decode(&encoded[17..149], now_unix)?,
            file_cap: encoded[149..181].try_into().unwrap(),
            contact_expiry: u64::from_be_bytes(encoded[181..189].try_into().unwrap()),
            max_file_size: u64::from_be_bytes(encoded[189..197].try_into().unwrap()),
            max_chunk_size: u64::from_be_bytes(encoded[197..205].try_into().unwrap()),
            max_inflight_bytes: u64::from_be_bytes(encoded[205..213].try_into().unwrap()),
        };
        value.validate(now_unix)?;
        Ok(value)
    }

    pub fn validate(&self, now_unix: u64) -> Result<(), FileCodecError> {
        validate_profile_version(self.profile_version)?;
        validate_contact_fields(&self.recipient_contact)?;
        if self.transfer_id.iter().all(|byte| *byte == 0)
            || self.file_cap.iter().all(|byte| *byte == 0)
        {
            return Err(FileCodecError::InvalidContact);
        }
        if self.contact_expiry <= now_unix {
            return Err(FileCodecError::Expired {
                expiry_unix: self.contact_expiry,
                now_unix,
            });
        }
        if self.contact_expiry > self.recipient_contact.lease_expiry {
            return Err(FileCodecError::InvalidContact);
        }
        if self.max_chunk_size == 0 {
            return Err(FileCodecError::InvalidChunkSize);
        }
        if self.max_inflight_bytes == 0 {
            return Err(FileCodecError::InvalidInflightLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileInit {
    pub profile_version: u8,
    pub transfer_id: TransferId,
    pub file_size: u64,
    pub chunk_size: u64,
    pub file_sha256: Sha256Digest,
    pub ack_route: Contact,
    pub init_nonce: [u8; 16],
    pub bearer_proof: [u8; 32],
}

impl FileInit {
    pub fn set_bearer_proof(&mut self, contact: &FileContact) -> Result<(), FileCodecError> {
        self.bearer_proof = self.compute_bearer_proof(contact)?;
        Ok(())
    }

    pub fn validate_authorization(
        &self,
        contact: &FileContact,
        now_unix: u64,
    ) -> Result<(), FileCodecError> {
        contact.validate(now_unix)?;
        Contact::decode(&self.ack_route.encode()?, now_unix)?;
        if self.profile_version != contact.profile_version {
            return Err(FileCodecError::ProfileVersionMismatch {
                expected: contact.profile_version,
                actual: self.profile_version,
            });
        }
        if self.transfer_id != contact.transfer_id {
            return Err(FileCodecError::TransferMismatch);
        }
        if self.file_size > contact.max_file_size {
            return Err(FileCodecError::FileSizeExceeded);
        }
        if self.chunk_size == 0 || self.chunk_size > contact.max_chunk_size {
            return Err(FileCodecError::InvalidChunkSize);
        }
        if self.chunk_size > contact.max_inflight_bytes {
            return Err(FileCodecError::InvalidInflightLimit);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&contact.file_cap)
            .map_err(|_| FileCodecError::InvalidBearerProof)?;
        mac.update(&self.proof_transcript(contact)?);
        mac.verify_slice(&self.bearer_proof)
            .map_err(|_| FileCodecError::InvalidBearerProof)
    }

    fn compute_bearer_proof(&self, contact: &FileContact) -> Result<[u8; 32], FileCodecError> {
        if self.transfer_id != contact.transfer_id {
            return Err(FileCodecError::TransferMismatch);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&contact.file_cap)
            .map_err(|_| FileCodecError::InvalidBearerProof)?;
        mac.update(&self.proof_transcript(contact)?);
        Ok(mac.finalize().into_bytes().into())
    }

    fn proof_transcript(&self, contact: &FileContact) -> Result<Vec<u8>, FileCodecError> {
        let ack_route = self.ack_route.encode()?;
        let recipient_contact = contact.recipient_contact.encode()?;
        let mut transcript = Vec::with_capacity(FILE_INIT_DOMAIN.len() + 249 + 213);
        transcript.extend_from_slice(FILE_INIT_DOMAIN);
        put_common(
            &mut transcript,
            self.profile_version,
            FILE_INIT,
            &self.transfer_id,
        );
        transcript.extend_from_slice(&recipient_contact);
        transcript.extend_from_slice(&contact.contact_expiry.to_be_bytes());
        transcript.extend_from_slice(&contact.max_file_size.to_be_bytes());
        transcript.extend_from_slice(&contact.max_chunk_size.to_be_bytes());
        transcript.extend_from_slice(&contact.max_inflight_bytes.to_be_bytes());
        transcript.extend_from_slice(&self.file_size.to_be_bytes());
        transcript.extend_from_slice(&self.chunk_size.to_be_bytes());
        transcript.extend_from_slice(&self.file_sha256);
        transcript.extend_from_slice(&(CONTACT_LEN as u16).to_be_bytes());
        transcript.extend_from_slice(&ack_route);
        transcript.extend_from_slice(&self.init_nonce);
        Ok(transcript)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChunk {
    pub profile_version: u8,
    pub transfer_id: TransferId,
    pub offset: u64,
    pub chunk_sha256: Sha256Digest,
    pub data: Vec<u8>,
}

impl FileChunk {
    pub fn validate_stream_bounds(
        &self,
        expected_offset: u64,
        file_size: u64,
        chunk_size: u64,
        max_chunk_size: u64,
        max_plaintext_len: usize,
    ) -> Result<(), FileCodecError> {
        if self.offset != expected_offset {
            return Err(FileCodecError::OffsetMismatch {
                expected: expected_offset,
                actual: self.offset,
            });
        }
        let length = self.data.len() as u64;
        if length == 0 {
            return Err(FileCodecError::EmptyChunk);
        }
        let plaintext_max = max_plaintext_len.saturating_sub(FILE_CHUNK_FIXED_LEN) as u64;
        let maximum = chunk_size.min(max_chunk_size).min(plaintext_max);
        if length > maximum {
            return Err(FileCodecError::ChunkTooLarge {
                actual: length,
                maximum,
            });
        }
        let Some(end) = self.offset.checked_add(length) else {
            return Err(FileCodecError::ChunkExceedsFile);
        };
        if end > file_size {
            return Err(FileCodecError::ChunkExceedsFile);
        }
        if end < file_size && length != chunk_size {
            return Err(FileCodecError::InvalidChunkSize);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFinish {
    pub profile_version: u8,
    pub transfer_id: TransferId,
    pub file_size: u64,
    pub file_sha256: Sha256Digest,
}

impl FileFinish {
    pub fn validate(&self, init: &FileInit, received_size: u64) -> Result<(), FileCodecError> {
        if self.transfer_id != init.transfer_id {
            return Err(FileCodecError::TransferMismatch);
        }
        if self.profile_version != init.profile_version {
            return Err(FileCodecError::ProfileVersionMismatch {
                expected: init.profile_version,
                actual: self.profile_version,
            });
        }
        if self.file_size != init.file_size || received_size != init.file_size {
            return Err(FileCodecError::FileSizeMismatch);
        }
        if self.file_sha256 != init.file_sha256 {
            return Err(FileCodecError::FileDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AckStage {
    Accepted = 0x01,
    Complete = 0x02,
    Error = 0x03,
}

impl TryFrom<u8> for AckStage {
    type Error = FileCodecError;

    fn try_from(value: u8) -> Result<Self, FileCodecError> {
        match value {
            0x01 => Ok(Self::Accepted),
            0x02 => Ok(Self::Complete),
            0x03 => Ok(Self::Error),
            value => Err(FileCodecError::InvalidAckStage(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AckCode {
    Ok = 0x0000,
    Expired = 0x0001,
    Auth = 0x0002,
    Quota = 0x0003,
    Format = 0x0004,
    Conflict = 0x0005,
    Io = 0x0006,
    Digest = 0x0007,
    Internal = 0x00ff,
}

impl TryFrom<u16> for AckCode {
    type Error = FileCodecError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::Ok),
            0x0001 => Ok(Self::Expired),
            0x0002 => Ok(Self::Auth),
            0x0003 => Ok(Self::Quota),
            0x0004 => Ok(Self::Format),
            0x0005 => Ok(Self::Conflict),
            0x0006 => Ok(Self::Io),
            0x0007 => Ok(Self::Digest),
            0x00ff => Ok(Self::Internal),
            value => Err(FileCodecError::InvalidAckCode(value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileAck {
    pub profile_version: u8,
    pub transfer_id: TransferId,
    pub stage: AckStage,
    pub code: AckCode,
    pub received_size: u64,
    pub file_sha256: Sha256Digest,
}

impl FileAck {
    fn validate(&self) -> Result<(), FileCodecError> {
        validate_profile_version(self.profile_version)?;
        match (self.stage, self.code) {
            (AckStage::Accepted | AckStage::Complete, AckCode::Ok) => Ok(()),
            (AckStage::Error, code) if code != AckCode::Ok => Ok(()),
            _ => Err(FileCodecError::InvalidAckDisposition),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileRecord {
    Init(FileInit),
    Chunk(FileChunk),
    Finish(FileFinish),
    Ack(FileAck),
}

impl FileRecord {
    pub fn profile_version(&self) -> u8 {
        match self {
            Self::Init(value) => value.profile_version,
            Self::Chunk(value) => value.profile_version,
            Self::Finish(value) => value.profile_version,
            Self::Ack(value) => value.profile_version,
        }
    }

    pub fn transfer_id(&self) -> TransferId {
        match self {
            Self::Init(value) => value.transfer_id,
            Self::Chunk(value) => value.transfer_id,
            Self::Finish(value) => value.transfer_id,
            Self::Ack(value) => value.transfer_id,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FileCodecError> {
        match self {
            Self::Init(value) => {
                let mut out = Vec::with_capacity(FILE_INIT_LEN);
                validate_profile_version(value.profile_version)?;
                put_common(
                    &mut out,
                    value.profile_version,
                    FILE_INIT,
                    &value.transfer_id,
                );
                out.extend_from_slice(&value.file_size.to_be_bytes());
                out.extend_from_slice(&value.chunk_size.to_be_bytes());
                out.extend_from_slice(&value.file_sha256);
                out.extend_from_slice(&(CONTACT_LEN as u16).to_be_bytes());
                out.extend_from_slice(&value.ack_route.encode()?);
                out.extend_from_slice(&value.init_nonce);
                out.extend_from_slice(&value.bearer_proof);
                Ok(out)
            }
            Self::Chunk(value) => {
                validate_profile_version(value.profile_version)?;
                if value.data.is_empty() {
                    return Err(FileCodecError::EmptyChunk);
                }
                if value.data.len() > MAX_FILE_CHUNK_DATA {
                    return Err(FileCodecError::ChunkTooLarge {
                        actual: value.data.len() as u64,
                        maximum: MAX_FILE_CHUNK_DATA as u64,
                    });
                }
                let digest: [u8; 32] = Sha256::digest(&value.data).into();
                if digest != value.chunk_sha256 {
                    return Err(FileCodecError::InvalidChunkDigest);
                }
                let mut out = Vec::with_capacity(FILE_CHUNK_FIXED_LEN + value.data.len());
                put_common(
                    &mut out,
                    value.profile_version,
                    FILE_CHUNK,
                    &value.transfer_id,
                );
                out.extend_from_slice(&value.offset.to_be_bytes());
                out.extend_from_slice(&(value.data.len() as u64).to_be_bytes());
                out.extend_from_slice(&value.chunk_sha256);
                out.extend_from_slice(&value.data);
                Ok(out)
            }
            Self::Finish(value) => {
                validate_profile_version(value.profile_version)?;
                let mut out = Vec::with_capacity(FILE_FINISH_LEN);
                put_common(
                    &mut out,
                    value.profile_version,
                    FILE_FINISH,
                    &value.transfer_id,
                );
                out.extend_from_slice(&value.file_size.to_be_bytes());
                out.extend_from_slice(&value.file_sha256);
                Ok(out)
            }
            Self::Ack(value) => {
                value.validate()?;
                let mut out = Vec::with_capacity(FILE_ACK_LEN);
                put_common(
                    &mut out,
                    value.profile_version,
                    FILE_ACK,
                    &value.transfer_id,
                );
                out.push(value.stage as u8);
                out.extend_from_slice(&(value.code as u16).to_be_bytes());
                out.extend_from_slice(&value.received_size.to_be_bytes());
                out.extend_from_slice(&value.file_sha256);
                Ok(out)
            }
        }
    }

    /// Decodes one exact application record. `max_plaintext_len` is the
    /// caller's E2E application-plaintext capacity (`P_msg` in the spec).
    pub fn decode(
        encoded: &[u8],
        now_unix: u64,
        max_plaintext_len: usize,
    ) -> Result<Self, FileCodecError> {
        let maximum = max_plaintext_len.min(MAX_FILE_RECORD_LEN);
        if encoded.len() > maximum {
            return Err(FileCodecError::RecordTooLarge {
                actual: encoded.len(),
                maximum,
            });
        }
        if encoded.len() < COMMON_LEN {
            return Err(FileCodecError::Truncated {
                needed: COMMON_LEN,
                actual: encoded.len(),
            });
        }
        if encoded[0] != PROFILE {
            return Err(FileCodecError::InvalidProfile(encoded[0]));
        }
        validate_profile_version(encoded[1])?;
        let profile_version = encoded[1];
        let transfer_id = encoded[3..19].try_into().unwrap();
        match encoded[2] {
            FILE_INIT => {
                require_exact(encoded.len(), FILE_INIT_LEN)?;
                let route_len = u16::from_be_bytes(encoded[67..69].try_into().unwrap());
                if route_len as usize != CONTACT_LEN {
                    return Err(FileCodecError::InvalidAckRouteLength(route_len));
                }
                Ok(Self::Init(FileInit {
                    profile_version,
                    transfer_id,
                    file_size: u64::from_be_bytes(encoded[19..27].try_into().unwrap()),
                    chunk_size: u64::from_be_bytes(encoded[27..35].try_into().unwrap()),
                    file_sha256: encoded[35..67].try_into().unwrap(),
                    ack_route: Contact::decode(&encoded[69..201], now_unix)?,
                    init_nonce: encoded[201..217].try_into().unwrap(),
                    bearer_proof: encoded[217..249].try_into().unwrap(),
                }))
            }
            FILE_CHUNK => {
                if encoded.len() < FILE_CHUNK_FIXED_LEN {
                    return Err(FileCodecError::Truncated {
                        needed: FILE_CHUNK_FIXED_LEN,
                        actual: encoded.len(),
                    });
                }
                let data_len = u64::from_be_bytes(encoded[27..35].try_into().unwrap());
                if data_len == 0 {
                    return Err(FileCodecError::EmptyChunk);
                }
                let maximum_data = maximum.saturating_sub(FILE_CHUNK_FIXED_LEN) as u64;
                if data_len > maximum_data {
                    return Err(FileCodecError::ChunkTooLarge {
                        actual: data_len,
                        maximum: maximum_data,
                    });
                }
                let data_len =
                    usize::try_from(data_len).map_err(|_| FileCodecError::ChunkTooLarge {
                        actual: data_len,
                        maximum: maximum_data,
                    })?;
                let expected = FILE_CHUNK_FIXED_LEN + data_len;
                require_exact(encoded.len(), expected)?;
                let data = &encoded[FILE_CHUNK_FIXED_LEN..];
                let chunk_sha256 = encoded[35..67].try_into().unwrap();
                let actual: [u8; 32] = Sha256::digest(data).into();
                if actual != chunk_sha256 {
                    return Err(FileCodecError::InvalidChunkDigest);
                }
                Ok(Self::Chunk(FileChunk {
                    profile_version,
                    transfer_id,
                    offset: u64::from_be_bytes(encoded[19..27].try_into().unwrap()),
                    chunk_sha256,
                    data: data.to_vec(),
                }))
            }
            FILE_FINISH => {
                require_exact(encoded.len(), FILE_FINISH_LEN)?;
                Ok(Self::Finish(FileFinish {
                    profile_version,
                    transfer_id,
                    file_size: u64::from_be_bytes(encoded[19..27].try_into().unwrap()),
                    file_sha256: encoded[27..59].try_into().unwrap(),
                }))
            }
            FILE_ACK => {
                require_exact(encoded.len(), FILE_ACK_LEN)?;
                let ack = FileAck {
                    profile_version,
                    transfer_id,
                    stage: AckStage::try_from(encoded[19])?,
                    code: AckCode::try_from(u16::from_be_bytes(
                        encoded[20..22].try_into().unwrap(),
                    ))?,
                    received_size: u64::from_be_bytes(encoded[22..30].try_into().unwrap()),
                    file_sha256: encoded[30..62].try_into().unwrap(),
                };
                ack.validate()?;
                Ok(Self::Ack(ack))
            }
            record_type => Err(FileCodecError::InvalidRecordType(record_type)),
        }
    }
}

fn put_common(out: &mut Vec<u8>, profile_version: u8, record_type: u8, transfer_id: &TransferId) {
    out.extend_from_slice(&[PROFILE, profile_version, record_type]);
    out.extend_from_slice(transfer_id);
}

pub fn validate_profile_version(profile_version: u8) -> Result<(), FileCodecError> {
    match profile_version {
        PROFILE_VERSION_V1 | PROFILE_VERSION_V2 => Ok(()),
        value => Err(FileCodecError::InvalidProfileVersion(value)),
    }
}

/// Number of data records in one v2 checkpoint batch. The negotiated chunk
/// size, rather than a shorter final chunk, defines the sender's byte credit.
pub fn checkpoint_batch_chunks(
    max_inflight_bytes: u64,
    chunk_size: u64,
) -> Result<u64, FileCodecError> {
    if chunk_size == 0 {
        return Err(FileCodecError::InvalidChunkSize);
    }
    let credit = max_inflight_bytes / chunk_size;
    if credit == 0 {
        return Err(FileCodecError::InvalidInflightLimit);
    }
    Ok(credit.min(CHECKPOINT_BATCH_CHUNKS_MAX))
}

fn require_exact(actual: usize, expected: usize) -> Result<(), FileCodecError> {
    match actual.cmp(&expected) {
        core::cmp::Ordering::Less => Err(FileCodecError::Truncated {
            needed: expected,
            actual,
        }),
        core::cmp::Ordering::Greater => Err(FileCodecError::TrailingBytes { expected, actual }),
        core::cmp::Ordering::Equal => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    fn contact() -> Contact {
        Contact {
            address: "203.0.113.8:443".parse().unwrap(),
            relay_service_id: [0x11; 32],
            queue_id: [0x22; 32],
            epoch: 7,
            push_cap: [0x33; 32],
            lease_expiry: 2_000,
        }
    }

    fn file_contact() -> FileContact {
        FileContact {
            profile_version: PROFILE_VERSION_V1,
            transfer_id: [0x44; 16],
            recipient_contact: contact(),
            file_cap: [0x55; 32],
            contact_expiry: 1_900,
            max_file_size: 10_000,
            max_chunk_size: 1_024,
            max_inflight_bytes: 2_048,
        }
    }

    fn init() -> FileInit {
        let mut value = FileInit {
            profile_version: PROFILE_VERSION_V1,
            transfer_id: [0x44; 16],
            file_size: 3,
            chunk_size: 3,
            file_sha256: Sha256::digest(b"abc").into(),
            ack_route: contact(),
            init_nonce: [0x66; 16],
            bearer_proof: [0; 32],
        };
        value.set_bearer_proof(&file_contact()).unwrap();
        value
    }

    fn records() -> Vec<FileRecord> {
        vec![
            FileRecord::Init(init()),
            FileRecord::Chunk(FileChunk {
                profile_version: PROFILE_VERSION_V1,
                transfer_id: [0x44; 16],
                offset: 0,
                chunk_sha256: Sha256::digest(b"abc").into(),
                data: b"abc".to_vec(),
            }),
            FileRecord::Finish(FileFinish {
                profile_version: PROFILE_VERSION_V1,
                transfer_id: [0x44; 16],
                file_size: 3,
                file_sha256: Sha256::digest(b"abc").into(),
            }),
            FileRecord::Ack(FileAck {
                profile_version: PROFILE_VERSION_V1,
                transfer_id: [0x44; 16],
                stage: AckStage::Complete,
                code: AckCode::Ok,
                received_size: 3,
                file_sha256: Sha256::digest(b"abc").into(),
            }),
        ]
    }

    #[test]
    fn contact_and_file_contact_round_trip() {
        let contact = contact();
        assert_eq!(
            Contact::decode(&contact.encode().unwrap(), NOW).unwrap(),
            contact
        );
        let file_contact = file_contact();
        assert_eq!(
            FileContact::decode(&file_contact.encode().unwrap(), NOW).unwrap(),
            file_contact
        );
    }

    #[test]
    fn all_records_round_trip_at_canonical_lengths() {
        for (record, expected_len) in records().into_iter().zip([
            FILE_INIT_LEN,
            FILE_CHUNK_FIXED_LEN + 3,
            FILE_FINISH_LEN,
            FILE_ACK_LEN,
        ]) {
            let encoded = record.encode().unwrap();
            assert_eq!(encoded.len(), expected_len);
            assert_eq!(
                FileRecord::decode(&encoded, NOW, MAX_FILE_RECORD_LEN).unwrap(),
                record
            );
        }
    }

    #[test]
    fn every_record_truncation_is_rejected() {
        for record in records() {
            let encoded = record.encode().unwrap();
            for length in 0..encoded.len() {
                assert!(matches!(
                    FileRecord::decode(&encoded[..length], NOW, MAX_FILE_RECORD_LEN),
                    Err(FileCodecError::Truncated { .. })
                        | Err(FileCodecError::ChunkTooLarge { .. })
                        | Err(FileCodecError::EmptyChunk)
                ));
            }
        }
    }

    #[test]
    fn every_record_rejects_trailing_bytes() {
        for record in records() {
            let mut encoded = record.encode().unwrap();
            encoded.push(0);
            assert!(matches!(
                FileRecord::decode(&encoded, NOW, MAX_FILE_RECORD_LEN),
                Err(FileCodecError::TrailingBytes { .. })
            ));
        }
    }

    #[test]
    fn invalid_profile_record_and_ack_enums_are_rejected() {
        let mut finish = records()[2].encode().unwrap();
        finish[0] = 2;
        assert!(matches!(
            FileRecord::decode(&finish, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidProfile(2))
        ));
        finish[0] = PROFILE;
        finish[1] = 3;
        assert!(matches!(
            FileRecord::decode(&finish, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidProfileVersion(3))
        ));
        finish[1] = PROFILE_VERSION;
        finish[2] = 0xff;
        assert!(matches!(
            FileRecord::decode(&finish, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidRecordType(0xff))
        ));

        let mut ack = records()[3].encode().unwrap();
        ack[19] = 0xff;
        assert!(matches!(
            FileRecord::decode(&ack, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidAckStage(0xff))
        ));
        ack[19] = AckStage::Error as u8;
        ack[20..22].copy_from_slice(&0x0008u16.to_be_bytes());
        assert!(matches!(
            FileRecord::decode(&ack, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidAckCode(0x0008))
        ));
        ack[20..22].copy_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            FileRecord::decode(&ack, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidAckDisposition)
        ));
    }

    #[test]
    fn malformed_lengths_and_oversize_chunks_are_rejected_before_copy() {
        let mut init = records()[0].encode().unwrap();
        init[67..69].copy_from_slice(&131u16.to_be_bytes());
        assert!(matches!(
            FileRecord::decode(&init, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidAckRouteLength(131))
        ));

        let mut chunk = records()[1].encode().unwrap();
        chunk[27..35].copy_from_slice(&4u64.to_be_bytes());
        assert!(matches!(
            FileRecord::decode(&chunk, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::Truncated { .. })
        ));
        chunk[27..35].copy_from_slice(&2u64.to_be_bytes());
        assert!(matches!(
            FileRecord::decode(&chunk, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::TrailingBytes { .. })
        ));
        chunk[27..35].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            FileRecord::decode(&chunk, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::ChunkTooLarge { .. })
        ));

        let large = FileChunk {
            profile_version: PROFILE_VERSION_V1,
            transfer_id: [1; 16],
            offset: 0,
            chunk_sha256: [0; 32],
            data: vec![0; MAX_FILE_CHUNK_DATA + 1],
        };
        assert!(matches!(
            FileRecord::Chunk(large).encode(),
            Err(FileCodecError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn chunk_digest_and_contextual_bounds_are_strict() {
        let mut encoded = records()[1].encode().unwrap();
        *encoded.last_mut().unwrap() ^= 1;
        assert!(matches!(
            FileRecord::decode(&encoded, NOW, MAX_FILE_RECORD_LEN),
            Err(FileCodecError::InvalidChunkDigest)
        ));

        let chunk = match &records()[1] {
            FileRecord::Chunk(value) => value.clone(),
            _ => unreachable!(),
        };
        chunk.validate_stream_bounds(0, 3, 3, 3, 70).unwrap();
        assert!(matches!(
            chunk.validate_stream_bounds(1, 3, 3, 3, 70),
            Err(FileCodecError::OffsetMismatch { .. })
        ));
        assert!(matches!(
            chunk.validate_stream_bounds(0, 2, 3, 3, 70),
            Err(FileCodecError::ChunkExceedsFile)
        ));
        assert!(matches!(
            chunk.validate_stream_bounds(0, 3, 2, 3, 70),
            Err(FileCodecError::ChunkTooLarge { .. })
        ));
        assert!(matches!(
            chunk.validate_stream_bounds(0, 3, 3, 3, 69),
            Err(FileCodecError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn contact_canonicality_expiry_and_limits_are_enforced() {
        let mut encoded = contact().encode().unwrap();
        encoded[6] = 1;
        assert!(matches!(
            Contact::decode(&encoded, NOW),
            Err(FileCodecError::NonCanonicalIpv4)
        ));
        encoded[6] = 0;
        encoded[1] = 5;
        assert!(matches!(
            Contact::decode(&encoded, NOW),
            Err(FileCodecError::InvalidAddressFamily(5))
        ));
        assert!(matches!(
            Contact::decode(&contact().encode().unwrap(), 2_000),
            Err(FileCodecError::Expired { .. })
        ));

        let mut file_contact = file_contact();
        file_contact.max_chunk_size = 0;
        assert_eq!(
            file_contact.validate(NOW),
            Err(FileCodecError::InvalidChunkSize)
        );
        file_contact.max_chunk_size = 1;
        file_contact.max_inflight_bytes = 0;
        assert_eq!(
            file_contact.validate(NOW),
            Err(FileCodecError::InvalidInflightLimit)
        );
    }

    #[test]
    fn bearer_proof_binds_every_transcript_field() {
        let init = init();
        init.validate_authorization(&file_contact(), NOW).unwrap();

        let mut changed = file_contact();
        changed.max_inflight_bytes += 1;
        assert_eq!(
            init.validate_authorization(&changed, NOW),
            Err(FileCodecError::InvalidBearerProof)
        );
        let mut changed = init.clone();
        changed.init_nonce[0] ^= 1;
        assert_eq!(
            changed.validate_authorization(&file_contact(), NOW),
            Err(FileCodecError::InvalidBearerProof)
        );
        let mut changed = init;
        changed.ack_route.queue_id[0] ^= 1;
        assert_eq!(
            changed.validate_authorization(&file_contact(), NOW),
            Err(FileCodecError::InvalidBearerProof)
        );
    }

    #[test]
    fn finish_requires_exact_init_values_and_received_size() {
        let init = init();
        let finish = FileFinish {
            profile_version: PROFILE_VERSION_V1,
            transfer_id: init.transfer_id,
            file_size: init.file_size,
            file_sha256: init.file_sha256,
        };
        finish.validate(&init, 3).unwrap();
        assert_eq!(
            finish.validate(&init, 2),
            Err(FileCodecError::FileSizeMismatch)
        );
        let mut changed = finish;
        changed.file_sha256[0] ^= 1;
        assert_eq!(
            changed.validate(&init, 3),
            Err(FileCodecError::FileDigestMismatch)
        );
    }

    #[test]
    fn v2_round_trips_and_binds_authorization_without_changing_lengths() {
        let mut contact = file_contact();
        contact.profile_version = PROFILE_VERSION_V2;
        let encoded_contact = contact.encode().unwrap();
        assert_eq!(encoded_contact.len(), FILE_CONTACT_LEN);
        assert_eq!(encoded_contact[0], PROFILE_VERSION_V2);
        assert_eq!(FileContact::decode(&encoded_contact, NOW).unwrap(), contact);

        let mut init = init();
        init.profile_version = PROFILE_VERSION_V2;
        init.set_bearer_proof(&contact).unwrap();
        init.validate_authorization(&contact, NOW).unwrap();
        let encoded_init = FileRecord::Init(init.clone()).encode().unwrap();
        assert_eq!(encoded_init.len(), FILE_INIT_LEN);
        assert_eq!(encoded_init[1], PROFILE_VERSION_V2);
        assert_eq!(
            FileRecord::decode(&encoded_init, NOW, MAX_FILE_RECORD_LEN).unwrap(),
            FileRecord::Init(init)
        );

        let mut downgraded = encoded_init;
        downgraded[1] = PROFILE_VERSION_V1;
        let FileRecord::Init(downgraded) =
            FileRecord::decode(&downgraded, NOW, MAX_FILE_RECORD_LEN).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(
            downgraded.validate_authorization(&contact, NOW),
            Err(FileCodecError::ProfileVersionMismatch {
                expected: PROFILE_VERSION_V2,
                actual: PROFILE_VERSION_V1,
            })
        );
    }

    #[test]
    fn checkpoint_batch_and_nonfinal_chunk_bounds_are_exact() {
        assert_eq!(checkpoint_batch_chunks(481_280, 13_933).unwrap(), 32);
        assert_eq!(checkpoint_batch_chunks(8, 4).unwrap(), 2);
        assert_eq!(
            checkpoint_batch_chunks(3, 4),
            Err(FileCodecError::InvalidInflightLimit)
        );

        let chunk = FileChunk {
            profile_version: PROFILE_VERSION_V2,
            transfer_id: [1; 16],
            offset: 0,
            chunk_sha256: Sha256::digest(b"abc").into(),
            data: b"abc".to_vec(),
        };
        assert_eq!(
            chunk.validate_stream_bounds(0, 6, 4, 4, 100),
            Err(FileCodecError::InvalidChunkSize)
        );
        chunk.validate_stream_bounds(0, 3, 4, 4, 100).unwrap();
    }
}
