use alloc::{string::String, vec::Vec};
use ml_dsa::{MlDsa65, SigningKey, VerifyingKey};
use ml_kem::array::Array;
#[cfg(feature = "std")]
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Encoded length of an ML-DSA-65 verifying key (FIPS 204).
pub const IDENTITY_PK_LEN: usize = 1952;

const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub struct IdentityKeypair {
    sk: SigningKey<MlDsa65>,
    seed: [u8; 32],
}

impl IdentityKeypair {
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        IdentityKeypair::from_seed(seed)
    }

    /// Create a fresh identity using caller-provided cryptographically secure entropy.
    /// No fallback keys are generated if the platform RNG fails.
    pub fn try_generate(
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<Self, crate::CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(seed.as_mut())
            .map_err(|_| crate::CryptoError::Entropy)?;
        Ok(Self::from_seed(*seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = zeroize::Zeroizing::new(seed);
        let seed_arr = Array::try_from(seed.as_slice()).expect("seed is 32 bytes");
        IdentityKeypair {
            sk: SigningKey::<MlDsa65>::from_seed(&seed_arr),
            seed: *seed,
        }
    }

    /// The 32-byte seed this keypair was deterministically derived from.
    /// Key material: the returned buffer zeroizes itself on drop.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.seed)
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        let vk: &VerifyingKey<MlDsa65> = self.sk.as_ref();
        vk.encode().as_slice().to_vec()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ml_dsa::signature::Signer;
        self.sk.sign(msg).encode().as_slice().to_vec()
    }

    pub fn safety_number(&self) -> String {
        safety_number_of(&self.public_bytes())
    }
}

impl Drop for IdentityKeypair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl ZeroizeOnDrop for IdentityKeypair {}

pub fn verify_signature(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::signature::Verifier;
    let vk_bytes =
        match <ml_dsa::EncodedVerifyingKey<MlDsa65> as TryFrom<&[u8]>>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_bytes);
    let sig_bytes = match <ml_dsa::EncodedSignature<MlDsa65> as TryFrom<&[u8]>>::try_from(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = match ml_dsa::Signature::<MlDsa65>::decode(&sig_bytes) {
        Some(s) => s,
        None => return false,
    };
    vk.verify(msg, &sig).is_ok()
}

/// Whether `pk_bytes` is a well-formed ML-DSA-65 verifying key.
pub fn is_valid_identity_pk(pk_bytes: &[u8]) -> bool {
    pk_bytes.len() == IDENTITY_PK_LEN
        && <ml_dsa::EncodedVerifyingKey<MlDsa65> as TryFrom<&[u8]>>::try_from(pk_bytes).is_ok()
}

/// Safety number of a well-formed identity key. The safety number is the
/// root of all trust; a malformed key yields `None` rather than a
/// confident-looking fingerprint.
pub fn checked_safety_number_of(pk_bytes: &[u8]) -> Option<String> {
    is_valid_identity_pk(pk_bytes).then(|| safety_number_of(pk_bytes))
}

pub fn safety_number_of(pk_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"gc1/id");
    h.update(pk_bytes);
    let d = h.finalize();
    let base32 = encode_base32(&d);
    let chars: Vec<char> = base32.chars().take(40).collect();
    (0..5)
        .map(|i| chars[i * 8..i * 8 + 8].iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in data {
        buf = (buf << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buf >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_format() {
        let kp = IdentityKeypair::from_seed([7u8; 32]);
        let sn = kp.safety_number();
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().all(|g| g.len() == 8));
        assert!(sn
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn safety_number_deterministic_and_keyed() {
        let a = IdentityKeypair::from_seed([1u8; 32]);
        let a2 = IdentityKeypair::from_seed([1u8; 32]);
        let b = IdentityKeypair::from_seed([2u8; 32]);
        assert_eq!(a.safety_number(), a2.safety_number());
        assert_ne!(a.safety_number(), b.safety_number());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = IdentityKeypair::from_seed([9u8; 32]);
        let pk = kp.public_bytes();
        let sig = kp.sign(b"gc1 test");
        assert!(verify_signature(&pk, b"gc1 test", &sig));
        assert!(!verify_signature(&pk, b"gc1 tesu", &sig));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!verify_signature(&pk, b"gc1 test", &bad));
    }

    #[test]
    fn dsa65_sizes() {
        let kp = IdentityKeypair::from_seed([3u8; 32]);
        assert_eq!(kp.public_bytes().len(), 1952);
        assert_eq!(kp.sign(b"x").len(), 3309);
    }

    #[test]
    fn identity_has_zeroizing_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningKey<MlDsa65>>();
        assert_zeroize_on_drop::<IdentityKeypair>();
    }
}
