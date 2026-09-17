use crate::identity::IdentityKeypair;
use alloc::vec::Vec;
use ml_kem::array::Array;
use ml_kem::{EncapsulationKey, KeyExport, MlKem768};
#[cfg(feature = "std")]
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub const KEM_EK_LEN: usize = 1184;
/// Encoded length of an ML-KEM-768 ciphertext (FIPS 203).
pub const KEM_CT_LEN: usize = 1088;
/// Bundles rotate every 30 days (SPEC §8.5); anything older is stale.
pub const MAX_BUNDLE_AGE_SECS: u64 = 30 * 24 * 60 * 60;
/// Tolerated clock skew for a bundle whose `created` is in our future.
pub const MAX_BUNDLE_FUTURE_SKEW_SECS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub ecdh_pub: [u8; 32],
    pub kem_pub: Vec<u8>,
    pub created: u64,
    pub sig: Vec<u8>,
}

impl Bundle {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.kem_pub.len());
        v.extend_from_slice(b"gc1/bundle");
        v.extend_from_slice(&self.ecdh_pub);
        v.extend_from_slice(&self.kem_pub);
        v.extend_from_slice(&self.created.to_be_bytes());
        v
    }

    /// Signature check only. Prefer [`Bundle::verify_fresh`], which also
    /// enforces the 30-day rotation window from SPEC §8.5.
    pub fn verify(&self, identity_pk: &[u8]) -> bool {
        self.kem_pub.len() == KEM_EK_LEN
            && crate::identity::verify_signature(identity_pk, &self.signing_payload(), &self.sig)
    }

    /// Whether `created` is within the rotation window at `now_unix`.
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        self.created <= now_unix.saturating_add(MAX_BUNDLE_FUTURE_SKEW_SECS)
            && now_unix.saturating_sub(self.created) <= MAX_BUNDLE_AGE_SECS
    }

    /// Signature and freshness check.
    pub fn verify_fresh(&self, identity_pk: &[u8], now_unix: u64) -> bool {
        self.is_fresh(now_unix) && self.verify(identity_pk)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.ecdh_pub);
        v.extend_from_slice(&(self.kem_pub.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.kem_pub);
        v.extend_from_slice(&self.created.to_be_bytes());
        v.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.sig);
        v
    }

    /// Strict decoder: rejects trailing bytes so the received encoding is
    /// exactly the canonical one the signature covers.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 32 + 2 + 8 + 2 {
            return None;
        }
        let mut p = 0;
        let mut ecdh_pub = [0u8; 32];
        ecdh_pub.copy_from_slice(&buf[p..p + 32]);
        p += 32;
        let klen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if buf.len() < p + klen + 8 + 2 {
            return None;
        }
        let kem_pub = buf[p..p + klen].to_vec();
        p += klen;
        let created = u64::from_be_bytes(buf[p..p + 8].try_into().ok()?);
        p += 8;
        let slen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if buf.len() < p + slen {
            return None;
        }
        let sig = buf[p..p + slen].to_vec();
        if p + slen != buf.len() {
            return None;
        }
        Some(Bundle {
            ecdh_pub,
            kem_pub,
            created,
            sig,
        })
    }
}

#[derive(Clone)]
pub struct LocalSecrets {
    pub(crate) ecdh: StaticSecret,
    pub(crate) kem_dk: ml_kem::DecapsulationKey<MlKem768>,
}

impl ZeroizeOnDrop for LocalSecrets {}

impl LocalSecrets {
    /// Reconstruct receiver secrets from provisioned seed material.
    ///
    /// This is intended for applications whose signed public bundle was
    /// minted from explicit seeds. Callers remain responsible for protecting
    /// the seed material at rest.
    pub fn from_seed_material(ecdh_seed: [u8; 32], kem_seed: [u8; 64]) -> Self {
        let ecdh_seed = Zeroizing::new(ecdh_seed);
        let kem_seed = Zeroizing::new(kem_seed);
        let ecdh = StaticSecret::from(*ecdh_seed);
        let seed = Array::try_from(kem_seed.as_slice()).expect("64-byte seed");
        let kem_dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
        Self { ecdh, kem_dk }
    }

    /// Our ML-KEM decapsulation key, for installing into a session so that
    /// PQ refreshes addressed to this bundle decrypt (`Session::provide_local_kem`).
    pub fn kem_decapsulation_key(&self) -> ml_kem::DecapsulationKey<MlKem768> {
        self.kem_dk.clone()
    }

    pub fn public_material(&self) -> ([u8; 32], Vec<u8>) {
        (
            PublicKey::from(&self.ecdh).to_bytes(),
            self.kem_dk
                .encapsulation_key()
                .to_bytes()
                .as_slice()
                .to_vec(),
        )
    }
}

impl IdentityKeypair {
    #[cfg(feature = "std")]
    pub fn issue_bundle(&self) -> (Bundle, LocalSecrets) {
        let mut ecdh_bytes = Zeroizing::new([0u8; 32]);
        let mut seed_bytes = Zeroizing::new([0u8; 64]);
        rand::thread_rng().fill_bytes(ecdh_bytes.as_mut());
        rand::thread_rng().fill_bytes(seed_bytes.as_mut());
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.issue_bundle_from_material(*ecdh_bytes, *seed_bytes, created)
    }

    /// Issue a signed bundle with platform entropy and an explicit Unix timestamp.
    pub fn issue_bundle_with_rng(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        now_unix: u64,
    ) -> Result<(Bundle, LocalSecrets), crate::CryptoError> {
        let mut ecdh = Zeroizing::new([0u8; 32]);
        let mut kem = Zeroizing::new([0u8; 64]);
        rng.try_fill_bytes(ecdh.as_mut())
            .map_err(|_| crate::CryptoError::Entropy)?;
        rng.try_fill_bytes(kem.as_mut())
            .map_err(|_| crate::CryptoError::Entropy)?;
        Ok(self.issue_bundle_from_material(*ecdh, *kem, now_unix))
    }

    pub(crate) fn issue_bundle_from_material(
        &self,
        ecdh_bytes: [u8; 32],
        seed_bytes: [u8; 64],
        created: u64,
    ) -> (Bundle, LocalSecrets) {
        let ecdh_bytes = Zeroizing::new(ecdh_bytes);
        let seed_bytes = Zeroizing::new(seed_bytes);
        let secrets = LocalSecrets::from_seed_material(*ecdh_bytes, *seed_bytes);
        let ecdh = secrets.ecdh.clone();
        let kem_dk = secrets.kem_dk.clone();
        let kem_ek = kem_dk.encapsulation_key().to_bytes().as_slice().to_vec();
        let unsigned = Bundle {
            ecdh_pub: x25519_dalek::PublicKey::from(&ecdh).to_bytes(),
            kem_pub: kem_ek,
            created,
            sig: Vec::new(),
        };
        let sig = self.sign(&unsigned.signing_payload());
        (Bundle { sig, ..unsigned }, secrets)
    }
}

pub fn ek_from_bytes(bytes: &[u8]) -> Option<EncapsulationKey<MlKem768>> {
    let arr = Array::try_from(bytes).ok()?;
    EncapsulationKey::new(&arr).ok()
}

pub fn dh_public(sec: &StaticSecret) -> PublicKey {
    PublicKey::from(sec.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_signs_and_verifies() {
        let id = IdentityKeypair::from_seed([4u8; 32]);
        let (bundle, _secrets) = id.issue_bundle();
        let pk = id.public_bytes();
        assert!(bundle.verify(&pk));
        assert_eq!(bundle.kem_pub.len(), KEM_EK_LEN);
    }

    #[test]
    fn tampered_bundle_fails() {
        let id = IdentityKeypair::from_seed([4u8; 32]);
        let (mut bundle, _s) = id.issue_bundle();
        bundle.created += 1;
        assert!(!bundle.verify(&id.public_bytes()));
    }

    #[test]
    fn bundle_wrong_identity_fails() {
        let a = IdentityKeypair::from_seed([4u8; 32]);
        let b = IdentityKeypair::from_seed([5u8; 32]);
        let (bundle, _s) = a.issue_bundle();
        assert!(!bundle.verify(&b.public_bytes()));
    }

    #[test]
    fn bundle_encoding_roundtrip() {
        let id = IdentityKeypair::from_seed([4u8; 32]);
        let (bundle, _s) = id.issue_bundle();
        let enc = bundle.encode();
        let dec = Bundle::decode(&enc).unwrap();
        assert_eq!(dec, bundle);
    }

    #[test]
    fn bundle_decode_rejects_truncated() {
        assert!(Bundle::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn ek_from_bytes_matches_generated() {
        let mut seed_bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed_bytes);
        let seed = Array::try_from(seed_bytes.as_slice()).expect("64-byte seed");
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
        let bytes = dk.encapsulation_key().to_bytes().as_slice().to_vec();
        let ek2 = ek_from_bytes(&bytes).unwrap();
        assert_eq!(bytes.as_slice(), ek2.to_bytes().as_slice());
    }

    #[test]
    fn local_secrets_have_zeroizing_drop() {
        fn assert_zeroize<T: zeroize::Zeroize>() {}
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        // x25519-dalek 2 uses `#[zeroize(drop)]` but predates the marker impl.
        assert_zeroize::<StaticSecret>();
        assert_zeroize_on_drop::<ml_kem::DecapsulationKey<MlKem768>>();
        assert_zeroize_on_drop::<LocalSecrets>();
    }
}
