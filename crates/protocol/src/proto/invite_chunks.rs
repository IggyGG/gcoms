//! Bounded invitation control records carried inside authenticated direct sessions.
use super::*;

pub const WELCOME_CHUNK_BYTES: usize = 8192;
const HEADER: usize = 18 + 16 + 32 + 4 + 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeChunk {
    pub digest: [u8; 32],
    pub total: u32,
    pub offset: u32,
    pub bytes: Vec<u8>,
}

impl WelcomeChunk {
    fn valid(&self) -> bool {
        let total = self.total as usize;
        let offset = self.offset as usize;
        (1..=MAX_INVITE_RECORD_BYTES).contains(&total)
            && offset < total
            && offset.is_multiple_of(WELCOME_CHUNK_BYTES)
            && self.bytes.len() == WELCOME_CHUNK_BYTES.min(total - offset)
    }
}

pub fn encode_invite_welcome_chunk(
    message_id: [u8; 16],
    request_id: [u8; 16],
    chunk: &WelcomeChunk,
) -> Option<Vec<u8>> {
    if !chunk.valid() {
        return None;
    }
    let mut encoded = Vec::with_capacity(HEADER + chunk.bytes.len());
    encoded.extend_from_slice(&[DIRECT_VERSION, DIRECT_INVITE_WELCOME_CHUNK]);
    encoded.extend_from_slice(&message_id);
    encoded.extend_from_slice(&request_id);
    encoded.extend_from_slice(&chunk.digest);
    encoded.extend_from_slice(&chunk.total.to_be_bytes());
    encoded.extend_from_slice(&chunk.offset.to_be_bytes());
    encoded.extend_from_slice(&chunk.bytes);
    Some(encoded)
}

pub(super) fn decode(encoded: &[u8]) -> Option<DirectRecord> {
    if !(HEADER + 1..=HEADER + WELCOME_CHUNK_BYTES).contains(&encoded.len()) {
        return None;
    }
    let message_id = encoded[2..18].try_into().ok()?;
    let request_id = encoded[18..34].try_into().ok()?;
    let chunk = WelcomeChunk {
        digest: encoded[34..66].try_into().ok()?,
        total: u32::from_be_bytes(encoded[66..70].try_into().ok()?),
        offset: u32::from_be_bytes(encoded[70..74].try_into().ok()?),
        bytes: encoded[HEADER..].to_vec(),
    };
    chunk.valid().then_some(DirectRecord::InviteWelcomeChunk {
        message_id,
        request_id,
        chunk,
    })
}

/// A transient, request-owned assembly. Call only after checking the authenticated
/// sender against the pending request. At most 256 KiB and 32 parts per request;
/// the node separately bounds pending requests and their original lifetimes.
#[derive(Clone, Default)]
pub struct WelcomeChunks {
    digest: Option<[u8; 32]>,
    total: usize,
    parts: Vec<Option<Vec<u8>>>,
}

impl WelcomeChunks {
    pub fn push(&mut self, chunk: &WelcomeChunk) -> Result<Option<Vec<u8>>, &'static str> {
        if !chunk.valid() {
            return Err("invalid invitation reply chunk");
        }
        if let Some(digest) = self.digest {
            if digest != chunk.digest || self.total != chunk.total as usize {
                return Err("inconsistent invitation reply chunks");
            }
        } else {
            self.digest = Some(chunk.digest);
            self.total = chunk.total as usize;
            self.parts = vec![None; self.total.div_ceil(WELCOME_CHUNK_BYTES)];
        }
        let slot = &mut self.parts[chunk.offset as usize / WELCOME_CHUNK_BYTES];
        if let Some(bytes) = slot {
            if bytes != &chunk.bytes {
                return Err("conflicting invitation reply chunk");
            }
        } else {
            *slot = Some(chunk.bytes.clone());
        }
        if self.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let mut welcome = Vec::with_capacity(self.total);
        for part in &self.parts {
            welcome.extend_from_slice(part.as_deref().expect("complete"));
        }
        let digest: [u8; 32] = Sha256::digest(&welcome).into();
        if Some(digest) != self.digest {
            return Err("invitation reply digest mismatch");
        }
        Ok(Some(welcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pieces(bytes: &[u8]) -> Vec<WelcomeChunk> {
        let digest = Sha256::digest(bytes).into();
        bytes
            .chunks(WELCOME_CHUNK_BYTES)
            .enumerate()
            .map(|(i, part)| WelcomeChunk {
                digest,
                total: bytes.len() as u32,
                offset: (i * WELCOME_CHUNK_BYTES) as u32,
                bytes: part.to_vec(),
            })
            .collect()
    }
    #[test]
    fn bounded_large_reply_roundtrips_out_of_order_without_partial_success() {
        let welcome = vec![37; MAX_INVITE_RECORD_BYTES];
        let parts = pieces(&welcome);
        let mut assembly = WelcomeChunks::default();
        for part in parts.iter().skip(1).rev() {
            let encoded = encode_invite_welcome_chunk([1; 16], [2; 16], part).unwrap();
            assert!(encoded.len() < 12217);
            assert_eq!(
                decode_direct_record(&encoded),
                Some(DirectRecord::InviteWelcomeChunk {
                    message_id: [1; 16],
                    request_id: [2; 16],
                    chunk: part.clone(),
                })
            );
            assert!(assembly.push(part).unwrap().is_none());
            assert!(assembly.push(part).unwrap().is_none());
        }
        assert_eq!(assembly.push(&parts[0]).unwrap(), Some(welcome));
    }
    #[test]
    fn rejects_overflow_noncanonical_conflicts_and_corrupted_complete_reply() {
        let parts = pieces(&vec![1; WELCOME_CHUNK_BYTES + 3]);
        for mutate in 0..5 {
            let mut part = parts[0].clone();
            match mutate {
                0 => part.total = u32::MAX,
                1 => part.total = 0,
                2 => part.offset = u32::MAX,
                3 => part.offset = 1,
                _ => {
                    part.bytes.pop();
                }
            }
            assert!(encode_invite_welcome_chunk([1; 16], [2; 16], &part).is_none());
            assert!(WelcomeChunks::default().push(&part).is_err());
        }
        let mut assembly = WelcomeChunks::default();
        assembly.push(&parts[0]).unwrap();
        let mut conflict = parts[0].clone();
        conflict.bytes[0] ^= 1;
        assert!(assembly.push(&conflict).is_err());
        let mut mismatch = parts[1].clone();
        mismatch.digest[0] ^= 1;
        assert!(assembly.push(&mismatch).is_err());
        let mut corrupt = parts[1].clone();
        corrupt.bytes[0] ^= 1;
        assert!(assembly.push(&corrupt).is_err());
        let encoded = encode_invite_welcome_chunk([1; 16], [2; 16], &parts[0]).unwrap();
        for end in [0, 17, 73, 74, encoded.len() - 1] {
            assert!(decode_direct_record(&encoded[..end]).is_none());
        }
    }
}
