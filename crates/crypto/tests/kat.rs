//! Known-answer pins for the post-quantum primitives GC/1 relies on.
//!
//! The upstream crates carry the Wycheproof/NIST vectors as a git submodule
//! that is not part of the published package, so this file pins the exact
//! outputs the `ml-kem` and `ml-dsa` crates produce for fixed inputs. A
//! dependency bump that changes any of these values is a wire-incompatible
//! change to every GC/1 handshake and signature and must be reviewed as such.

use ml_dsa::{MlDsa65, SigningKey};
use ml_kem::array::Array;
use ml_kem::{Decapsulate, KeyExport, MlKem768};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn ml_kem_768_deterministic_answers() {
    let seed: [u8; 64] = std::array::from_fn(|i| i as u8);
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(Array::from(seed));
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();
    assert_eq!(ek_bytes.len(), gcoms_crypto::KEM_EK_LEN);
    let m = Array::from([0x42u8; 32]);
    let (ct, ss_enc) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.len(), gcoms_crypto::KEM_CT_LEN);
    let ss_dec = dk.decapsulate_slice(ct.as_slice()).unwrap();
    assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    // Implicit rejection: a corrupted ciphertext yields a different secret.
    let mut bad = ct.as_slice().to_vec();
    bad[0] ^= 1;
    let ss_bad = dk.decapsulate_slice(&bad).unwrap();
    assert_ne!(ss_bad.as_slice(), ss_enc.as_slice());

    assert_eq!(
        hex(&Sha256::digest(ek_bytes.as_slice())),
        "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
        "ML-KEM-768 encapsulation key changed"
    );
    assert_eq!(
        hex(&Sha256::digest(ct.as_slice())),
        "9c7b2f8d05c70575ec03ed8f93b7bb298e1506b97e54e5e885748965b1466f1c",
        "ML-KEM-768 ciphertext changed"
    );
    assert_eq!(
        hex(ss_enc.as_slice()),
        "b83e7f23b33f909715c7a50b0d4b1f6684d53e1f4b9056f803b29f058ccb5566",
        "ML-KEM-768 shared secret changed"
    );
}

#[test]
fn ml_dsa_65_deterministic_answers() {
    let seed: [u8; 32] = std::array::from_fn(|i| 0xa0 ^ i as u8);
    let sk = SigningKey::<MlDsa65>::from_seed(&Array::from(seed));
    let vk: &ml_dsa::VerifyingKey<MlDsa65> = sk.as_ref();
    let vk_bytes = vk.encode();
    assert_eq!(vk_bytes.len(), gcoms_crypto::IDENTITY_PK_LEN);
    assert!(gcoms_crypto::is_valid_identity_pk(vk_bytes.as_slice()));
    assert!(!gcoms_crypto::is_valid_identity_pk(
        &vk_bytes.as_slice()[..100]
    ));
    assert!(gcoms_crypto::checked_safety_number_of(&vk_bytes.as_slice()[..100]).is_none());

    use ml_dsa::signature::Signer;
    let sig = sk.sign(b"GC/1 KAT").encode();
    assert!(gcoms_crypto::verify_signature(
        vk_bytes.as_slice(),
        b"GC/1 KAT",
        sig.as_slice()
    ));
    assert!(!gcoms_crypto::verify_signature(
        vk_bytes.as_slice(),
        b"GC/1 KAT!",
        sig.as_slice()
    ));

    assert_eq!(
        hex(&Sha256::digest(vk_bytes.as_slice())),
        "01d49c7013b1eb414d51e5d5ca01e53988af1329512e71bcbe2b3260dad3edf2",
        "ML-DSA-65 verifying key changed"
    );
    // ML-DSA signing is randomised by default; only the deterministic
    // verification result is pinned above. The safety number of this key is
    // pinned so the user-facing fingerprint format cannot drift silently.
    assert_eq!(
        gcoms_crypto::safety_number_of(vk_bytes.as_slice()),
        "ZPJ62ZQT 635TILI5 EZK4QQCN PWU7AE3X QRW4YBJ2"
    );
}
