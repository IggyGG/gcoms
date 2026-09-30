//! Return-path proof inside the existing authenticated invite request/reply.
//! These envelopes do not mint membership or extend a relay lease.
const REQUEST: &[u8; 6] = b"GCEJ01";
const CHALLENGE: &[u8; 6] = b"GCEC01";
const MAX_PACKAGE: usize = 192 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Proof {
    pub expires: u64,
    pub tag: [u8; 32],
}

pub(crate) fn request(package: &[u8], proof: Option<Proof>) -> Option<Vec<u8>> {
    if package.is_empty() || package.len() > MAX_PACKAGE {
        return None;
    }
    let mut bytes = Vec::with_capacity(11 + package.len() + 40);
    bytes.extend_from_slice(REQUEST);
    bytes.push(u8::from(proof.is_some()));
    bytes.extend_from_slice(&(package.len() as u32).to_be_bytes());
    bytes.extend_from_slice(package);
    if let Some(proof) = proof {
        bytes.extend_from_slice(&proof.expires.to_be_bytes());
        bytes.extend_from_slice(&proof.tag);
    }
    Some(bytes)
}

pub(crate) fn decode_request(bytes: &[u8]) -> Option<(&[u8], Option<Proof>)> {
    if bytes.get(..6)? != REQUEST {
        return None;
    }
    let length = u32::from_be_bytes(bytes.get(7..11)?.try_into().ok()?) as usize;
    if length == 0 || length > MAX_PACKAGE {
        return None;
    }
    let end = 11usize.checked_add(length)?;
    let package = bytes.get(11..end)?;
    let proof = match bytes[6] {
        0 if bytes.len() == end => None,
        1 if bytes.len() == end + 40 => Some(Proof {
            expires: u64::from_be_bytes(bytes.get(end..end + 8)?.try_into().ok()?),
            tag: bytes.get(end + 8..end + 40)?.try_into().ok()?,
        }),
        _ => return None,
    };
    Some((package, proof))
}

pub(crate) fn challenge(proof: Proof) -> Vec<u8> {
    let mut bytes = CHALLENGE.to_vec();
    bytes.extend_from_slice(&proof.expires.to_be_bytes());
    bytes.extend_from_slice(&proof.tag);
    bytes
}

pub(crate) fn decode_challenge(bytes: &[u8]) -> Option<Proof> {
    if bytes.len() != 46 || bytes.get(..6)? != CHALLENGE {
        return None;
    }
    Some(Proof {
        expires: u64::from_be_bytes(bytes[6..14].try_into().ok()?),
        tag: bytes[14..].try_into().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_request_and_challenge_boundaries() {
        let proof = Proof {
            expires: 100,
            tag: [7; 32],
        };
        for p in [None, Some(proof)] {
            let bytes = request(b"package", p).unwrap();
            let (package, decoded) = decode_request(&bytes).unwrap();
            assert_eq!(package, b"package");
            assert_eq!(decoded.is_some(), p.is_some());
            for n in 0..bytes.len() {
                assert!(decode_request(&bytes[..n]).is_none());
            }
            let mut extra = bytes;
            extra.push(0);
            assert!(decode_request(&extra).is_none());
        }
        assert_eq!(decode_challenge(&challenge(proof)).unwrap().tag, proof.tag);
        assert!(decode_challenge(b"not a welcome").is_none());
    }
}
