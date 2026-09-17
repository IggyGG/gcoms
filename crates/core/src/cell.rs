use alloc::{vec, vec::Vec};
use core::error::Error;
use core::fmt;

pub const PROTOCOL_VERSION: u8 = 0x1;
pub const HEADER_LEN: usize = 6;

pub const F_MORE: u8 = 0x01;
pub const F_LAST: u8 = 0x02;

pub const MAX_MESSAGE: usize = 15 * 1024;
/// Maximum application body accepted by message send APIs.
///
/// The 3 KiB reserve covers the largest current direct-session rekey frame,
/// channel/MLS framing, and relay encapsulation below [`MAX_MESSAGE`].
pub const APPLICATION_PAYLOAD_LIMIT: usize = MAX_MESSAGE - 3 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    Cover = 0x0,
    Hello = 0x1,
    Msg = 0x2,
    CtrlAlias = 0x3,
    Presence = 0x4,
    Pex = 0x5,
    RelaySub = 0x6,
    RelayPush = 0x7,
    Frwd = 0x8,
    Ack = 0x9,
}

impl CellType {
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0x0 => Some(CellType::Cover),
            0x1 => Some(CellType::Hello),
            0x2 => Some(CellType::Msg),
            0x3 => Some(CellType::CtrlAlias),
            0x4 => Some(CellType::Presence),
            0x5 => Some(CellType::Pex),
            0x6 => Some(CellType::RelaySub),
            0x7 => Some(CellType::RelayPush),
            0x8 => Some(CellType::Frwd),
            0x9 => Some(CellType::Ack),
            _ => None,
        }
    }

    pub fn class(self) -> CellClass {
        match self {
            CellType::Cover
            | CellType::Pex
            | CellType::RelaySub
            | CellType::RelayPush
            | CellType::Frwd => CellClass::Hop,
            CellType::Msg | CellType::CtrlAlias | CellType::Presence | CellType::Ack => {
                CellClass::E2e
            }
            CellType::Hello => CellClass::Session,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellClass {
    Hop,
    E2e,
    Session,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bucket {
    B0,
    B1,
    B2,
    B3,
}

impl Bucket {
    pub const fn size(self) -> usize {
        match self {
            Bucket::B0 => 256,
            Bucket::B1 => 1024,
            Bucket::B2 => 4096,
            Bucket::B3 => 16384,
        }
    }

    pub const fn max_payload(self) -> usize {
        self.size() - HEADER_LEN
    }

    pub fn from_len(len: usize) -> Option<Self> {
        match len {
            256 => Some(Bucket::B0),
            1024 => Some(Bucket::B1),
            4096 => Some(Bucket::B2),
            16384 => Some(Bucket::B3),
            _ => None,
        }
    }

    pub fn smallest_for(payload_len: usize) -> Option<Self> {
        match payload_len {
            0..=250 => Some(Bucket::B0),
            251..=1018 => Some(Bucket::B1),
            1019..=4090 => Some(Bucket::B2),
            4091..=16378 => Some(Bucket::B3),
            _ => None,
        }
    }

    pub const fn wire(self) -> Self {
        match self {
            Bucket::B3 => Bucket::B3,
            _ => Bucket::B2,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CellError {
    BadVersion { got: u8 },
    BadLength { len: usize },
    LengthMismatch { declared: u16, available: usize },
    NotPadded { at: usize },
    ReservedType { raw: u8 },
    PayloadTooLarge { payload: usize, bucket: Bucket },
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellError::BadVersion { got } => write!(f, "bad protocol version nibble: {got}"),
            CellError::BadLength { len } => write!(f, "buffer is not a bucket size: {len}"),
            CellError::LengthMismatch {
                declared,
                available,
            } => {
                write!(
                    f,
                    "payload len {declared} exceeds bucket capacity {available}"
                )
            }
            CellError::NotPadded { at } => write!(f, "nonzero padding byte at offset {at}"),
            CellError::ReservedType { raw } => write!(f, "reserved cell type: 0x{raw:X}"),
            CellError::PayloadTooLarge { payload, bucket } => {
                write!(f, "payload {payload} does not fit {bucket:?}")
            }
        }
    }
}

impl Error for CellError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub version: u8,
    pub raw_type: u8,
    pub flags: u8,
    pub round_ctr: u16,
    pub payload: Vec<u8>,
}

impl Cell {
    pub fn new(cell_type: CellType, flags: u8, round_ctr: u16, payload: Vec<u8>) -> Self {
        Cell {
            version: PROTOCOL_VERSION,
            raw_type: cell_type as u8,
            flags,
            round_ctr,
            payload,
        }
    }

    pub fn cell_type(&self) -> Option<CellType> {
        CellType::from_raw(self.raw_type)
    }

    pub fn is_fragment_continuation(&self) -> bool {
        self.flags & F_MORE != 0
    }

    pub fn is_fragment_last(&self) -> bool {
        self.flags & F_LAST != 0
    }

    pub fn encode(&self, bucket: Bucket) -> Result<Vec<u8>, CellError> {
        if self.version & 0x0F != PROTOCOL_VERSION {
            return Err(CellError::BadVersion {
                got: self.version & 0x0F,
            });
        }
        if self.raw_type & 0x0F != self.raw_type {
            return Err(CellError::ReservedType { raw: self.raw_type });
        }
        if self.payload.len() > bucket.max_payload() {
            return Err(CellError::PayloadTooLarge {
                payload: self.payload.len(),
                bucket,
            });
        }
        let mut buf = vec![0u8; bucket.size()];
        buf[0] = ((self.version & 0x0F) << 4) | (self.raw_type & 0x0F);
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&self.round_ctr.to_be_bytes());
        buf[4..6].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf[HEADER_LEN..HEADER_LEN + self.payload.len()].copy_from_slice(&self.payload);
        Ok(buf)
    }

    pub fn encode_auto(&self) -> Result<Vec<u8>, CellError> {
        let bucket =
            Bucket::smallest_for(self.payload.len()).ok_or(CellError::PayloadTooLarge {
                payload: self.payload.len(),
                bucket: Bucket::B3,
            })?;
        self.encode(bucket)
    }

    pub fn encode_wire(&self) -> Result<Vec<u8>, CellError> {
        let bucket =
            Bucket::smallest_for(self.payload.len()).ok_or(CellError::PayloadTooLarge {
                payload: self.payload.len(),
                bucket: Bucket::B3,
            })?;
        self.encode(bucket.wire())
    }
}

pub fn decode(buf: &[u8]) -> Result<Cell, CellError> {
    let bucket = Bucket::from_len(buf.len()).ok_or(CellError::BadLength { len: buf.len() })?;
    let version = buf[0] >> 4;
    if version != PROTOCOL_VERSION {
        return Err(CellError::BadVersion { got: version });
    }
    let raw_type = buf[0] & 0x0F;
    if CellType::from_raw(raw_type).is_none() {
        return Err(CellError::ReservedType { raw: raw_type });
    }
    let flags = buf[1];
    let round_ctr = u16::from_be_bytes([buf[2], buf[3]]);
    let declared = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if declared > bucket.max_payload() {
        return Err(CellError::LengthMismatch {
            declared: declared as u16,
            available: bucket.max_payload(),
        });
    }
    for (i, b) in buf[HEADER_LEN + declared..].iter().enumerate() {
        if *b != 0 {
            return Err(CellError::NotPadded {
                at: HEADER_LEN + declared + i,
            });
        }
    }
    Ok(Cell {
        version,
        raw_type,
        flags,
        round_ctr,
        payload: buf[HEADER_LEN..HEADER_LEN + declared].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_all_buckets() {
        for (bucket, len) in [
            (Bucket::B0, 250),
            (Bucket::B1, 1018),
            (Bucket::B2, 4090),
            (Bucket::B3, 16378),
        ] {
            let cell = Cell::new(CellType::Msg, F_MORE | F_LAST, 0xBEEF, payload(len));
            let buf = cell.encode(bucket).unwrap();
            assert_eq!(buf.len(), bucket.size());
            assert!(buf.iter().skip(HEADER_LEN + len).all(|b| *b == 0));
            let back = decode(&buf).unwrap();
            assert_eq!(back, cell);
        }
    }

    #[test]
    fn auto_bucket_selection() {
        for (len, want) in [
            (0, Bucket::B0),
            (250, Bucket::B0),
            (251, Bucket::B1),
            (1019, Bucket::B2),
            (4091, Bucket::B3),
        ] {
            let cell = Cell::new(CellType::Msg, 0, 0, payload(len));
            let buf = cell.encode_auto().unwrap();
            assert_eq!(buf.len(), want.size());
            assert_eq!(decode(&buf).unwrap(), cell);
        }
    }

    #[test]
    fn max_message_fits_b3() {
        assert!(MAX_MESSAGE <= Bucket::B3.max_payload());
        let cell = Cell::new(CellType::Msg, 0, 0, payload(MAX_MESSAGE));
        assert_eq!(cell.encode_auto().unwrap().len(), Bucket::B3.size());
    }

    #[test]
    fn oversize_payload_rejected() {
        let cell = Cell::new(CellType::Msg, 0, 0, payload(Bucket::B3.max_payload() + 1));
        assert!(matches!(
            cell.encode_auto(),
            Err(CellError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn bad_version_rejected() {
        let cell = Cell::new(CellType::Msg, 0, 1, vec![]);
        let mut buf = cell.encode(Bucket::B0).unwrap();
        buf[0] = 0x2 << 4;
        assert!(matches!(
            decode(&buf),
            Err(CellError::BadVersion { got: 0x2 })
        ));
    }

    #[test]
    fn reserved_type_rejected() {
        let mut buf = vec![0u8; 256];
        buf[0] = (PROTOCOL_VERSION << 4) | 0xC;
        assert!(matches!(
            decode(&buf),
            Err(CellError::ReservedType { raw: 0xC })
        ));
    }

    #[test]
    fn nonzero_padding_rejected() {
        let cell = Cell::new(CellType::Ack, 0, 3, payload(10));
        let mut buf = cell.encode(Bucket::B0).unwrap();
        let last = buf.len() - 1;
        buf[last] = 0x01;
        assert!(matches!(decode(&buf), Err(CellError::NotPadded { .. })));
    }

    #[test]
    fn length_mismatch_rejected() {
        let mut buf = vec![0u8; 256];
        buf[0] = PROTOCOL_VERSION << 4;
        buf[4..6].copy_from_slice(&251u16.to_be_bytes());
        assert!(matches!(
            decode(&buf),
            Err(CellError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn bad_buffer_len_rejected() {
        assert!(matches!(
            decode(&[0u8; 255]),
            Err(CellError::BadLength { .. })
        ));
    }

    #[test]
    fn wire_encoding_folds_small_buckets_to_4k() {
        for (payload_len, wire_len) in [
            (0, 4096),
            (250, 4096),
            (1018, 4096),
            (1019, 4096),
            (4091, 16384),
        ] {
            let cell = Cell::new(CellType::Msg, 0, 0, payload(payload_len));
            let buf = cell.encode_wire().unwrap();
            assert_eq!(buf.len(), wire_len);
            assert_eq!(decode(&buf).unwrap(), cell);
        }
    }

    #[test]
    fn classes_match_spec() {
        assert_eq!(CellType::Hello.class(), CellClass::Session);
        for t in [
            CellType::Msg,
            CellType::CtrlAlias,
            CellType::Presence,
            CellType::Ack,
        ] {
            assert_eq!(t.class(), CellClass::E2e);
        }
        for t in [
            CellType::Cover,
            CellType::Pex,
            CellType::RelaySub,
            CellType::RelayPush,
            CellType::Frwd,
        ] {
            assert_eq!(t.class(), CellClass::Hop);
        }
    }
}
