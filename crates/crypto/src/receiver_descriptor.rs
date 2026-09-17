//! Canonical public DSP1 receiver material. It contains no one-use contact or
//! capability. Signature validity proves control of the embedded identity, not
//! an owner's authorization to deliver to that identity.
use crate::bundle::Bundle;
use crate::identity::IDENTITY_PK_LEN;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const RECEIVER_DESCRIPTOR_BYTES: usize = 6 + IDENTITY_PK_LEN + 32 + 2 + 1184 + 8 + 2 + 3309;

#[derive(Clone)]
pub struct ReceiverDescriptor {
    identity_key: Vec<u8>,
    bundle: Bundle,
}
impl ReceiverDescriptor {
    /// Verifies the exact DSP1 encoding and signed public key bundle. Historical
    /// descriptors may be inspected; transport must separately check freshness.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RECEIVER_DESCRIPTOR_BYTES
            || bytes.get(..4)? != b"DSP1"
            || u16::from_be_bytes(bytes.get(4..6)?.try_into().ok()?) as usize != IDENTITY_PK_LEN
        {
            return None;
        }
        let identity_key = bytes.get(6..6 + IDENTITY_PK_LEN)?.to_vec();
        let bundle = Bundle::decode(bytes.get(6 + IDENTITY_PK_LEN..)?)?;
        if !bundle.verify(&identity_key) {
            return None;
        }
        let descriptor = Self {
            identity_key,
            bundle,
        };
        (descriptor.encode() == bytes).then_some(descriptor)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIVER_DESCRIPTOR_BYTES);
        out.extend_from_slice(b"DSP1");
        out.extend_from_slice(&(IDENTITY_PK_LEN as u16).to_be_bytes());
        out.extend_from_slice(&self.identity_key);
        out.extend_from_slice(&self.bundle.encode());
        out
    }
    pub fn identity_key(&self) -> &[u8] {
        &self.identity_key
    }
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        self.bundle.is_fresh(now_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bundle::LocalSecrets, IdentityKeypair};
    fn fixture() -> Vec<u8> {
        let identity = IdentityKeypair::from_seed([1; 32]);
        let secrets = LocalSecrets::from_seed_material([2; 32], [3; 64]);
        let (ecdh_pub, kem_pub) = secrets.public_material();
        let mut bundle = Bundle {
            ecdh_pub,
            kem_pub,
            created: 1788894000,
            sig: vec![],
        };
        bundle.sig = identity.sign(&bundle.signing_payload());
        ReceiverDescriptor {
            identity_key: identity.public_bytes(),
            bundle,
        }
        .encode()
    }
    #[test]
    fn canonical_public_descriptor_retains_exact_identity_bundle_and_digest() {
        let bytes = fixture();
        let parsed = ReceiverDescriptor::decode(&bytes).unwrap();
        assert_eq!(parsed.encode(), bytes);
        assert_eq!(parsed.sha256(), <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(
            parsed.identity_key(),
            IdentityKeypair::from_seed([1; 32]).public_bytes()
        );
        assert!(parsed.is_fresh(1788894000));
        assert!(!parsed.is_fresh(1788894000 + crate::bundle::MAX_BUNDLE_AGE_SECS + 1));
        assert!(!parsed.is_fresh(1788894000 - crate::bundle::MAX_BUNDLE_FUTURE_SKEW_SECS - 1));
        // Inspection remains possible after expiry; runtime freshness is explicit.
        assert!(ReceiverDescriptor::decode(&bytes).is_some());
    }
    #[test]
    fn rejects_every_truncation_extensions_and_tampered_public_material() {
        let bytes = fixture();
        for len in 0..bytes.len() {
            assert!(ReceiverDescriptor::decode(&bytes[..len]).is_none());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(ReceiverDescriptor::decode(&extra).is_none());
        for offset in [
            0,
            4,
            5,
            6,
            6 + IDENTITY_PK_LEN,
            6 + IDENTITY_PK_LEN + 34,
            bytes.len() - 1,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 128;
            assert!(
                ReceiverDescriptor::decode(&changed).is_none(),
                "offset {offset}"
            );
        }
    }
}
