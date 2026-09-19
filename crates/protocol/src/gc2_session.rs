//! Explicit GC/2 peer-session envelopes. A tag is a routing hint until the
//! handshake authenticates it; it grants no authority by itself.
use crate::flow::{Error, CREDIT_BYTES};
use alloc::vec::Vec;
use gcoms_core::MAX_MESSAGE;
use gcoms_crypto::{FirstMove, Frame};

#[cfg(feature = "std")]
mod handshake;
#[cfg(feature = "std")]
mod storage;
#[cfg(feature = "std")]
pub use handshake::{accept, initiate, initiate_recovery, Accepted, Initiated};
#[cfg(feature = "std")]
pub use storage::SealedState;
#[cfg(all(test, feature = "std"))]
mod tests;

pub const SESSION_HEADER: usize = 4 + 16;
const FIRST: &[u8; 4] = b"GCH2";
const FRAME: &[u8; 4] = b"GCM2";
const CREDIT: &[u8; 4] = b"GCA2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    FirstMove,
    Frame,
    Credit,
}

/// Borrowed and size-bounded. FirstMove/Frame decoders still do not authenticate
/// their contents; a caller must not publish the tag or peer before verification.
pub struct Packet<'a> {
    kind: Kind,
    tag: [u8; 16],
    bytes: &'a [u8],
}
impl<'a> Packet<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if !(SESSION_HEADER..=MAX_MESSAGE).contains(&bytes.len()) {
            return Err(Error::Length);
        }
        let kind = match bytes.get(..4) {
            Some(value) if value == FIRST => Kind::FirstMove,
            Some(value) if value == FRAME => Kind::Frame,
            Some(value) if value == CREDIT && bytes.len() == CREDIT_BYTES => Kind::Credit,
            _ => return Err(Error::Version),
        };
        let tag = bytes[4..SESSION_HEADER]
            .try_into()
            .map_err(|_| Error::Length)?;
        validate_tag(&tag)?;
        let value = Self { kind, tag, bytes };
        match kind {
            Kind::FirstMove => {
                let body = &bytes[SESSION_HEADER..];
                if body.len() < 32 + 2 + 1088 + 12 + 16
                    || body.get(32..34) != Some(&1088u16.to_be_bytes())
                {
                    return Err(Error::Length);
                }
            }
            Kind::Frame => validate_frame_bytes(&bytes[SESSION_HEADER..])?,
            Kind::Credit => (),
        }
        Ok(value)
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn tag(&self) -> &[u8; 16] {
        &self.tag
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn first_move(&self) -> Result<FirstMove, Error> {
        if self.kind != Kind::FirstMove {
            return Err(Error::Version);
        }
        let first = FirstMove::decode(&self.bytes[SESSION_HEADER..]).ok_or(Error::Length)?;
        validate_first(&first)?;
        Ok(first)
    }
    pub fn frame(&self) -> Result<Frame, Error> {
        if self.kind != Kind::Frame {
            return Err(Error::Version);
        }
        Frame::decode(&self.bytes[SESSION_HEADER..]).ok_or(Error::Length)
    }
}

fn validate_tag(tag: &[u8; 16]) -> Result<(), Error> {
    if *tag == [0; 16] {
        Err(Error::State)
    } else {
        Ok(())
    }
}
fn validate_frame_bytes(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() < 8 + 8 + 32 + 1 + 1 + 16 {
        return Err(Error::Length);
    }
    let counter = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::Length)?);
    let previous = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::Length)?);
    if counter == 0 || previous >= counter {
        return Err(Error::Counter);
    }
    let mut position = match bytes[48] {
        0 => 49,
        1 => 81,
        _ => return Err(Error::Version),
    };
    // Strict option flags, unlike the compatibility GC/1 decoder.
    match bytes.get(position) {
        Some(0) => position += 1,
        Some(1) => {
            if bytes.get(position + 1..position + 3) != Some(&1088u16.to_be_bytes()) {
                return Err(Error::Length);
            }
            position += 3 + 1088;
        }
        _ => return Err(Error::Version),
    }
    if bytes.len() < position + 16 {
        return Err(Error::Length);
    }
    Ok(())
}
fn validate_first(first: &FirstMove) -> Result<(), Error> {
    if first.kem_ct.len() != gcoms_crypto::bundle::KEM_CT_LEN
        || first.ct.len() < 16
        || first.ct.len() > MAX_MESSAGE - SESSION_HEADER - (32 + 2 + 1088 + 12)
    {
        return Err(Error::Length);
    }
    Ok(())
}
pub(crate) fn validate_frame(frame: &Frame) -> Result<(), Error> {
    let header = 8
        + 8
        + 32
        + 1
        + if frame.mixed_with.is_some() { 32 } else { 0 }
        + 1
        + if frame.pq_ct.is_some() { 2 + 1088 } else { 0 };
    if frame.ctr == 0
        || frame.pn >= frame.ctr
        || frame
            .pq_ct
            .as_ref()
            .is_some_and(|ct| ct.len() != gcoms_crypto::bundle::KEM_CT_LEN)
        || frame.ct.len() < 16
        || frame.ct.len() > MAX_MESSAGE - SESSION_HEADER - header
    {
        return Err(Error::Length);
    }
    Ok(())
}
pub fn encode_first_move(tag: &[u8; 16], first: &FirstMove) -> Result<Vec<u8>, Error> {
    validate_tag(tag)?;
    validate_first(first)?;
    Ok(envelope(FIRST, tag, &first.encode()))
}
pub fn encode_frame(tag: &[u8; 16], frame: &Frame) -> Result<Vec<u8>, Error> {
    validate_tag(tag)?;
    validate_frame(frame)?;
    Ok(envelope(FRAME, tag, &frame.encode()))
}
#[cfg(feature = "std")]
pub(crate) fn encode_frame_bytes(tag: &[u8; 16], bytes: &[u8]) -> Result<Vec<u8>, Error> {
    validate_tag(tag)?;
    if bytes.len() > MAX_MESSAGE - SESSION_HEADER {
        return Err(Error::Length);
    }
    validate_frame_bytes(bytes)?;
    Ok(envelope(FRAME, tag, bytes))
}
fn envelope(magic: &[u8; 4], tag: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SESSION_HEADER + body.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(body);
    bytes
}
