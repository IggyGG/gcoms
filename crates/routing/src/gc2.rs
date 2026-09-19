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
const PROFILES_PER_MODE: u8 = 12;
/// Fixed 4096-byte/1000-ms interactive cover with natural unpaced bulk.
pub const FILE_TRANSFER_PROFILE: u8 = 22;

/// Explicit experimental traffic policies. Existing IDs 0..12 retain their
/// full-cover semantics; new modes have distinct authenticated profile IDs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum CoverMode {
    #[default]
    Full = 0,
    Interactive = 1,
    InteractiveJitter = 2,
}

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
        if id < PROFILES_PER_MODE * 3 {
            Ok(Self { id })
        } else {
            Err(RecordError::Profile)
        }
    }

    pub fn id(self) -> u8 {
        self.id
    }
    pub fn file_transfer() -> Self {
        Self {
            id: FILE_TRANSFER_PROFILE,
        }
    }
    pub fn with_mode(self, mode: CoverMode) -> Self {
        Self {
            id: self.id % PROFILES_PER_MODE + mode as u8 * PROFILES_PER_MODE,
        }
    }
    pub fn mode(self) -> CoverMode {
        match self.id / PROFILES_PER_MODE {
            0 => CoverMode::Full,
            1 => CoverMode::Interactive,
            _ => CoverMode::InteractiveJitter,
        }
    }
    pub fn record_len(self) -> usize {
        RECORD_LENGTHS[usize::from(self.id % PROFILES_PER_MODE) / 4]
    }
    pub fn period(self) -> Duration {
        Duration::from_millis(u64::from(PERIODS_MS[usize::from(self.id) % 4]))
    }

    /// Two directions of one continuously covered class channel for 30 days.
    /// Excludes TLS/HTTP2/TCP overhead, retransmission and additional bulk bytes.
    pub fn duplex_record_bytes_30_days(self) -> u64 {
        self.record_len() as u64 * 2 * 30 * 24 * 60 * 60 * 1000
            / u64::from(PERIODS_MS[usize::from(self.id) % 4])
    }

    /// Record-layer idle cost across every selected entry and covered class.
    /// Excludes connection setup, TLS/H2/TCP overhead and retransmissions.
    pub fn duplex_idle_bytes_30_days(self, entries: usize) -> u64 {
        let classes = if self.mode() == CoverMode::Full { 2 } else { 1 };
        self.duplex_record_bytes_30_days()
            .saturating_mul(classes)
            .saturating_mul(entries as u64)
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
        if self.unshaped_bulk() {
            MAX_RECORD - HEADER_LEN
        } else {
            self.profile.record_len() - HEADER_LEN
        }
    }
    pub fn unshaped_bulk(self) -> bool {
        self.class == TrafficClass::Bulk && self.profile.mode() != CoverMode::Full
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
            0 => RecordKind::Cover,
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
        let wire_len = if self.unshaped_bulk() {
            match kind {
                RecordKind::Cover => return Err(RecordError::Kind),
                RecordKind::Open => self.profile.record_len(),
                RecordKind::Data | RecordKind::Close => HEADER_LEN + payload_len,
            }
        } else {
            self.profile.record_len()
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
    fn experimental_modes_use_distinct_ids_and_bounded_bulk_frames() {
        for old_id in 0..12 {
            let legacy = CandidateProfile::from_id(old_id).unwrap();
            assert_eq!(legacy.mode(), CoverMode::Full);
            for mode in [CoverMode::Interactive, CoverMode::InteractiveJitter] {
                let profile = legacy.with_mode(mode);
                assert_ne!(profile.id(), old_id);
                assert_eq!(CandidateProfile::from_id(profile.id()).unwrap(), profile);
                assert_eq!(profile.with_mode(CoverMode::Full), legacy);
                let bulk = RecordCodec::new(TrafficClass::Bulk, profile);
                let data = vec![42; MAX_RECORD - HEADER_LEN];
                let wire = bulk.encode(RecordKind::Data, &data).unwrap();
                assert_eq!(wire.len(), MAX_RECORD);
                assert_eq!(bulk.decode(&wire).unwrap().payload(), data);
                assert_eq!(
                    bulk.encode(RecordKind::Data, &vec![42; MAX_RECORD]),
                    Err(RecordError::Length)
                );
                assert_eq!(bulk.encode(RecordKind::Cover, &[]), Err(RecordError::Kind));
                assert_eq!(
                    bulk.encode(RecordKind::Close, &[]).unwrap().len(),
                    HEADER_LEN
                );
                assert!(RecordCodec::new(TrafficClass::Bulk, legacy)
                    .decode(&wire)
                    .is_err());
                let chat = RecordCodec::new(TrafficClass::Interactive, profile);
                assert_eq!(
                    chat.encode(RecordKind::Data, &[1]).unwrap().len(),
                    profile.record_len()
                );
                assert_eq!(
                    profile.duplex_idle_bytes_30_days(2) * 2,
                    legacy.duplex_idle_bytes_30_days(2)
                );
            }
        }
    }

    #[test]
    fn file_profile_is_explicit_and_does_not_reinterpret_old_ids() {
        let profile = CandidateProfile::file_transfer();
        assert_eq!(CandidateProfile::from_id(22).unwrap(), profile);
        assert_eq!(profile.record_len(), 4096);
        assert_eq!(profile.period(), Duration::from_secs(1));
        let bulk = RecordCodec::new(TrafficClass::Bulk, profile);
        let interactive = RecordCodec::new(TrafficClass::Interactive, profile);
        assert!(bulk.encode(RecordKind::Cover, &[]).is_err());
        assert_eq!(
            interactive.encode(RecordKind::Cover, &[]).unwrap().len(),
            4096
        );
        for length in [1, 11 * 1024, MAX_RECORD - HEADER_LEN] {
            let wire = bulk.encode(RecordKind::Data, &vec![17; length]).unwrap();
            assert_eq!(wire.len(), HEADER_LEN + length);
            assert_eq!(bulk.decode(&wire).unwrap().payload().len(), length);
            assert!(interactive.decode(&wire).is_err());
            let old = RecordCodec::new(
                TrafficClass::Bulk,
                CandidateProfile::new(4096, 1000).unwrap(),
            );
            assert!(old.decode(&wire).is_err());
        }
        assert!(bulk.encode(RecordKind::Data, &vec![0; MAX_RECORD]).is_err());
        let open = bulk.encode(RecordKind::Open, &[]).unwrap();
        assert_eq!(open.len(), 4096);
        assert_eq!(
            profile,
            CandidateProfile::new(4096, 1000)
                .unwrap()
                .with_mode(CoverMode::Interactive)
        );
        assert_eq!(
            RecordCodec::from_open_header(&open[..HEADER_LEN])
                .unwrap()
                .profile(),
            profile
        );
    }

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
    fn all_candidates_keep_both_classes_size_fixed_and_padded() {
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
            for (kind, bytes) in [
                (RecordKind::Cover, 0),
                (RecordKind::Open, 0),
                (RecordKind::Data, 1),
                (RecordKind::Data, 128),
                (RecordKind::Data, bulk.payload_limit()),
                (RecordKind::Close, 0),
            ] {
                let payload = vec![7; bytes];
                let wire = bulk.encode(kind, &payload).unwrap();
                assert_eq!(wire.len(), profile.record_len());
                assert_eq!(
                    bulk.decode(&wire).unwrap(),
                    RecordRef {
                        kind,
                        payload: &payload
                    }
                );
            }
            assert!(bulk
                .encode(RecordKind::Data, &vec![0; bulk.payload_limit() + 1])
                .is_err());
        }
        assert_eq!(CandidateProfile::from_id(36), Err(RecordError::Profile));
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
