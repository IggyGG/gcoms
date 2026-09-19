//! Experimental GC/2 natural cells. Padding belongs to the selected protected
//! carrier, never to this codec. GC/1 must be selected through its own codec.
use crate::{CellType, F_LAST, F_MORE, HEADER_LEN, MAX_MESSAGE};
use alloc::vec::Vec;
use core::fmt;

pub const VERSION: u8 = 2;
pub const MAX_CELL: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    Length,
    Type,
    Reserved,
    Payload,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "GC/2 wire version required",
            Self::Length => "noncanonical natural-cell length",
            Self::Type => "reserved natural-cell type",
            Self::Reserved => "reserved natural-cell header bits",
            Self::Payload => "natural-cell payload exceeds its bound",
        })
    }
}

impl core::error::Error for Error {}

/// The fields are private so a validated cell cannot later acquire GC/1's
/// version, an unchecked payload size, or a downstream scheduling counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NaturalCell {
    kind: CellType,
    flags: u8,
    payload: Vec<u8>,
}

impl NaturalCell {
    pub fn new(kind: CellType, flags: u8, payload: Vec<u8>) -> Result<Self, Error> {
        let allowed_flags = if kind == CellType::Msg {
            F_MORE | F_LAST
        } else {
            0
        };
        if flags & !allowed_flags != 0 {
            return Err(Error::Reserved);
        }
        let limit = if kind == CellType::Msg {
            MAX_MESSAGE
        } else {
            MAX_CELL - HEADER_LEN
        };
        if payload.len() > limit {
            return Err(Error::Payload);
        }
        Ok(Self {
            kind,
            flags,
            payload,
        })
    }

    pub fn kind(&self) -> CellType {
        self.kind
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Allocated payload storage for bounded queue admission. This includes
    /// spare capacity retained by a caller-provided buffer.
    pub fn payload_capacity(&self) -> usize {
        self.payload.capacity()
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.encoded_len());
        wire.extend_from_slice(&[(VERSION << 4) | self.kind as u8, self.flags, 0, 0]);
        wire.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&self.payload);
        wire
    }

    pub fn decode(wire: &[u8]) -> Result<Self, Error> {
        if !(HEADER_LEN..=MAX_CELL).contains(&wire.len()) {
            return Err(Error::Length);
        }
        if wire[0] >> 4 != VERSION {
            return Err(Error::Version);
        }
        let kind = CellType::from_raw(wire[0] & 0xf).ok_or(Error::Type)?;
        if wire[2..4] != [0, 0] {
            return Err(Error::Reserved);
        }
        let len = u16::from_be_bytes([wire[4], wire[5]]) as usize;
        if len != wire.len() - HEADER_LEN {
            return Err(Error::Length);
        }
        Self::new(kind, wire[1], wire[HEADER_LEN..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn natural_sizes_and_maximum_message_are_exact() {
        for size in [0, 1, 128, 4090, MAX_MESSAGE] {
            let cell = NaturalCell::new(CellType::Msg, 0, vec![7; size]).unwrap();
            let wire = cell.encode();
            assert_eq!(wire.len(), HEADER_LEN + size);
            assert_eq!(NaturalCell::decode(&wire).unwrap(), cell);
        }
        assert_eq!(
            NaturalCell::new(CellType::Msg, 0, vec![0; MAX_MESSAGE + 1]),
            Err(Error::Payload)
        );
        assert_eq!(
            NaturalCell::new(CellType::Frwd, 0, vec![0; MAX_CELL - HEADER_LEN])
                .unwrap()
                .encoded_len(),
            MAX_CELL
        );
    }

    #[test]
    fn cross_version_padding_and_reserved_headers_fail_closed() {
        let old = crate::Cell::new(CellType::Msg, 0, 0, vec![7]);
        assert_eq!(
            NaturalCell::decode(&old.encode_wire().unwrap()),
            Err(Error::Version)
        );
        let cell = NaturalCell::new(CellType::Msg, 0, vec![7]).unwrap();
        let wire = cell.encode();
        let mut padded = wire.clone();
        padded.resize(4096, 0);
        assert_eq!(NaturalCell::decode(&padded), Err(Error::Length));
        assert!(crate::decode(&padded).is_err());
        for (offset, value, error) in [
            (0, 0x2f, Error::Type),
            (1, 0x80, Error::Reserved),
            (2, 1, Error::Reserved),
            (5, 2, Error::Length),
        ] {
            let mut changed = wire.clone();
            changed[offset] = value;
            assert_eq!(NaturalCell::decode(&changed), Err(error));
        }
        for cut in 0..wire.len() {
            assert!(NaturalCell::decode(&wire[..cut]).is_err());
        }
    }
}
