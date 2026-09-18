//! Experimental shared-carrier framing. These are candidate profiles, not
//! qualified privacy settings. Records require an authenticated TLS service;
//! the codec itself provides neither authentication nor a sending schedule.
use gcoms_core::TrafficClass;
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub mod channel;
pub mod connector;
pub mod directory;
pub mod discovery;
pub mod entry;
pub mod mux;
pub mod owner;
pub mod transit;

const MAGIC: &[u8; 4] = b"GCT2";
pub const HEADER_LEN: usize = 9;
pub const MAX_RECORD: usize = 16 * 1024;
const RECORD_LENGTHS: [usize; 3] = [1024, 2048, 4096];
const PERIODS_MS: [u16; 4] = [250, 500, 1000, 1500];

/// Preserve the fractional second at an absolute credential deadline. Invalid
/// timestamps and expired authority have no remaining lifetime.
pub(super) fn remaining_authority_at(expires_at: u64, now: SystemTime) -> Duration {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(expires_at))
        .and_then(|expiry| expiry.duration_since(now).ok())
        .unwrap_or_default()
}

pub(super) fn authority_deadline(
    expires_at: u64,
    maximum: Duration,
) -> Option<tokio::time::Instant> {
    // Sample the monotonic clock first so sampling overhead cannot extend the
    // advertised expiry when converting the wall-clock interval.
    let now = tokio::time::Instant::now();
    let remaining = remaining_authority_at(expires_at, SystemTime::now()).min(maximum);
    if remaining.is_zero() {
        return None;
    }
    now.checked_add(remaining)
        .filter(|deadline| *deadline > tokio::time::Instant::now())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateProfile {
    id: u8,
}

impl CandidateProfile {
    pub fn new(record_len: usize, period_ms: u16) -> Result<Self, RecordError> {
        let size = RECORD_LENGTHS.iter().position(|value| *value == record_len);
        let period = PERIODS_MS.iter().position(|value| *value == period_ms);
        match (size, period) {
            (Some(size), Some(period)) => Ok(Self {
                id: (size * 4 + period) as u8,
            }),
            _ => Err(RecordError::Profile),
        }
    }

    pub fn from_id(id: u8) -> Result<Self, RecordError> {
        if usize::from(id) < RECORD_LENGTHS.len() * PERIODS_MS.len() {
            Ok(Self { id })
        } else {
            Err(RecordError::Profile)
        }
    }

    pub fn id(self) -> u8 {
        self.id
    }
    pub fn record_len(self) -> usize {
        RECORD_LENGTHS[usize::from(self.id) / 4]
    }
    pub fn period(self) -> Duration {
        Duration::from_millis(u64::from(PERIODS_MS[usize::from(self.id) % 4]))
    }

    /// Two directions of one continuously connected carrier for exactly 30 days.
    /// Excludes TLS/HTTP2/TCP overhead, retransmission and additional bulk bytes.
    pub fn duplex_record_bytes_30_days(self) -> u64 {
        self.record_len() as u64 * 2 * 30 * 24 * 60 * 60 * 1000
            / u64::from(PERIODS_MS[usize::from(self.id) % 4])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Cover = 0,
    Data = 1,
    Close = 2,
    Open = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    Version,
    Profile,
    Class,
    Kind,
    Length,
    Padding,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "GCT2 record version required",
            Self::Profile => "unrecognized or mismatched GCT2 candidate profile",
            Self::Class => "mismatched GCT2 traffic class",
            Self::Kind => "invalid GCT2 record kind",
            Self::Length => "noncanonical GCT2 record length",
            Self::Padding => "noncanonical GCT2 record padding",
        })
    }
}
impl std::error::Error for RecordError {}

#[derive(Debug, PartialEq, Eq)]
pub struct RecordRef<'a> {
    kind: RecordKind,
    payload: &'a [u8],
}

impl<'a> RecordRef<'a> {
    pub fn kind(&self) -> RecordKind {
        self.kind
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Fixed-size interactive records and natural-length bulk records. Class and
/// profile are immutable for the lifetime of a channel; mismatches fail closed.
#[derive(Clone, Copy, Debug)]
pub struct RecordCodec {
    class: TrafficClass,
    profile: CandidateProfile,
}

impl RecordCodec {
    pub fn new(class: TrafficClass, profile: CandidateProfile) -> Self {
        Self { class, profile }
    }
    pub fn class(self) -> TrafficClass {
        self.class
    }
    pub fn profile(self) -> CandidateProfile {
        self.profile
    }
    pub fn payload_limit(self) -> usize {
        match self.class {
            TrafficClass::Interactive => self.profile.record_len() - HEADER_LEN,
            TrafficClass::Bulk => MAX_RECORD - HEADER_LEN,
        }
    }

    /// Select a channel only from its canonical initial Open header. The full
    /// padded Open still needs decoding before connection state is committed.
    pub fn from_open_header(header: &[u8]) -> Result<Self, RecordError> {
        if header.len() != HEADER_LEN {
            return Err(RecordError::Length);
        }
        let class = TrafficClass::from_byte(header[4]).ok_or(RecordError::Class)?;
        let profile = CandidateProfile::from_id(header[5])?;
        let codec = Self::new(class, profile);
        if codec.header(header)?.0 != RecordKind::Open {
            return Err(RecordError::Kind);
        }
        Ok(codec)
    }

    /// Validate exactly one header before allocating or reading its body.
    pub fn wire_len(self, header: &[u8]) -> Result<usize, RecordError> {
        self.header(header).map(|(_, _, wire_len)| wire_len)
    }

    fn header(self, header: &[u8]) -> Result<(RecordKind, usize, usize), RecordError> {
        if header.len() != HEADER_LEN {
            return Err(RecordError::Length);
        }
        if &header[..4] != MAGIC {
            return Err(RecordError::Version);
        }
        if header[4] != self.class as u8 {
            return Err(RecordError::Class);
        }
        if header[5] != self.profile.id() {
            return Err(RecordError::Profile);
        }
        let kind = match header[6] {
            0 if self.class == TrafficClass::Interactive => RecordKind::Cover,
            1 => RecordKind::Data,
            2 => RecordKind::Close,
            3 => RecordKind::Open,
            _ => return Err(RecordError::Kind),
        };
        let payload_len = usize::from(u16::from_be_bytes([header[7], header[8]]));
        let valid_payload = match kind {
            RecordKind::Data => payload_len != 0,
            RecordKind::Cover | RecordKind::Close | RecordKind::Open => payload_len == 0,
        };
        if payload_len > self.payload_limit() || !valid_payload {
            return Err(RecordError::Length);
        }
        let wire_len = match self.class {
            TrafficClass::Interactive => self.profile.record_len(),
            TrafficClass::Bulk => HEADER_LEN + payload_len,
        };
        Ok((kind, payload_len, wire_len))
    }

    pub fn encode(self, kind: RecordKind, payload: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut wire = Vec::new();
        self.encode_into(kind, payload, &mut wire)?;
        Ok(wire)
    }

    /// Reuse bounded storage without retaining data in the padding of a later
    /// record. Invalid input leaves the destination unchanged.
    pub fn encode_into(
        self,
        kind: RecordKind,
        payload: &[u8],
        wire: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        let payload_len = u16::try_from(payload.len()).map_err(|_| RecordError::Length)?;
        let mut header = [0; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = self.class as u8;
        header[5] = self.profile.id();
        header[6] = kind as u8;
        header[7..9].copy_from_slice(&payload_len.to_be_bytes());
        let wire_len = self.wire_len(&header)?;
        wire.clear();
        wire.resize(wire_len, 0);
        wire[..HEADER_LEN].copy_from_slice(&header);
        wire[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
        Ok(())
    }

    pub fn decode(self, wire: &[u8]) -> Result<RecordRef<'_>, RecordError> {
        let (kind, payload_len, wire_len) =
            self.header(wire.get(..HEADER_LEN).ok_or(RecordError::Length)?)?;
        if wire.len() != wire_len {
            return Err(RecordError::Length);
        }
        if wire[HEADER_LEN + payload_len..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(RecordError::Padding);
        }
        Ok(RecordRef {
            kind,
            payload: &wire[HEADER_LEN..HEADER_LEN + payload_len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_expiry_does_not_round_up_or_revive_invalid_timestamps() {
        assert_eq!(
            remaining_authority_at(10, UNIX_EPOCH + Duration::from_millis(9750)),
            Duration::from_millis(250)
        );
        assert_eq!(
            remaining_authority_at(10, UNIX_EPOCH + Duration::from_secs(10)),
            Duration::ZERO
        );
        assert_eq!(
            remaining_authority_at(10, UNIX_EPOCH + Duration::from_millis(10001)),
            Duration::ZERO
        );
        assert_eq!(remaining_authority_at(u64::MAX, UNIX_EPOCH), Duration::ZERO);
        assert!(authority_deadline(crate::route::now_unix(), Duration::from_secs(30)).is_none());
        assert!(authority_deadline(crate::route::now_unix() + 30, Duration::ZERO).is_none());
    }

    #[test]
    fn all_candidates_keep_interactive_size_fixed_and_bulk_natural() {
        for id in 0..12 {
            let profile = CandidateProfile::from_id(id).unwrap();
            assert_eq!(
                CandidateProfile::new(profile.record_len(), profile.period().as_millis() as u16)
                    .unwrap(),
                profile
            );
            let chat = RecordCodec::new(TrafficClass::Interactive, profile);
            for (kind, bytes) in [
                (RecordKind::Cover, 0),
                (RecordKind::Open, 0),
                (RecordKind::Data, 1),
                (RecordKind::Data, chat.payload_limit()),
                (RecordKind::Close, 0),
            ] {
                let payload = vec![42; bytes];
                let wire = chat.encode(kind, &payload).unwrap();
                assert_eq!(wire.len(), profile.record_len());
                assert_eq!(
                    chat.decode(&wire).unwrap(),
                    RecordRef {
                        kind,
                        payload: &payload
                    }
                );
            }
            let bulk = RecordCodec::new(TrafficClass::Bulk, profile);
            for bytes in [1, 128, bulk.payload_limit()] {
                let payload = vec![7; bytes];
                let wire = bulk.encode(RecordKind::Data, &payload).unwrap();
                assert_eq!(wire.len(), HEADER_LEN + bytes);
                assert_eq!(bulk.decode(&wire).unwrap().payload(), payload);
            }
            assert_eq!(bulk.encode(RecordKind::Cover, &[]), Err(RecordError::Kind));
            assert_eq!(
                bulk.encode(RecordKind::Open, &[]).unwrap().len(),
                HEADER_LEN
            );
            assert!(bulk
                .encode(RecordKind::Data, &vec![0; bulk.payload_limit() + 1])
                .is_err());
            assert_eq!(
                bulk.encode(RecordKind::Close, &[]).unwrap().len(),
                HEADER_LEN
            );
        }
        assert_eq!(CandidateProfile::from_id(12), Err(RecordError::Profile));
        assert_eq!(CandidateProfile::new(4096, 0), Err(RecordError::Profile));
        assert_eq!(
            CandidateProfile::new(16384, 1000),
            Err(RecordError::Profile)
        );
    }

    #[test]
    fn wrong_version_profile_class_lengths_and_padding_fail_closed() {
        let profile = CandidateProfile::new(4096, 1000).unwrap();
        let codec = RecordCodec::new(TrafficClass::Interactive, profile);
        let wire = codec
            .encode(RecordKind::Data, b"opaque inner TLS/HTTP2 fragments")
            .unwrap();
        for (at, value, expected) in [
            (3, b'1', RecordError::Version),
            (4, TrafficClass::Bulk as u8, RecordError::Class),
            (5, 255, RecordError::Profile),
            (6, 255, RecordError::Kind),
            (7, 255, RecordError::Length),
            (4095, 1, RecordError::Padding),
        ] {
            let mut altered = wire.clone();
            altered[at] = value;
            assert_eq!(codec.decode(&altered), Err(expected));
        }
        for cut in [0, HEADER_LEN - 1, HEADER_LEN, wire.len() - 1] {
            assert!(codec.decode(&wire[..cut]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(codec.decode(&trailing), Err(RecordError::Length));
        assert!(codec.encode(RecordKind::Data, &[]).is_err());
        assert!(codec.encode(RecordKind::Cover, b"hidden data").is_err());
        assert!(codec.encode(RecordKind::Close, b"hidden data").is_err());
        assert!(codec
            .encode(RecordKind::Data, &vec![0; codec.payload_limit() + 1])
            .is_err());
    }

    #[test]
    fn raw_cover_cost_is_explicit_and_never_an_adaptive_quota() {
        assert_eq!(
            CandidateProfile::new(4096, 1000)
                .unwrap()
                .duplex_record_bytes_30_days(),
            21_233_664_000
        );
        assert_eq!(
            CandidateProfile::new(4096, 1500)
                .unwrap()
                .duplex_record_bytes_30_days(),
            14_155_776_000
        );
    }
}
