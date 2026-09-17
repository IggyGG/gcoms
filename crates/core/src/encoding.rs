//! Canonical base64url shared with the transport token registry.
use alloc::{string::String, vec::Vec};

/// Strict, canonical, unpadded base64url. Rejects invalid lengths, non
/// alphabet characters, and non-zero trailing bits so that exactly one
/// string maps to a given byte sequence (a token registry keyed by string
/// and a queue keyed by bytes must agree).
pub fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    if s.len() % 4 == 1 {
        return None;
    }
    let decoded = Base64UrlUnpadded::decode_vec(s).ok()?;
    // Canonical form: re-encoding must reproduce the input exactly.
    (Base64UrlUnpadded::encode_string(&decoded) == s).then_some(decoded)
}

pub fn encode_b64url(data: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(data)
}
