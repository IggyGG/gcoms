//! TP-1 relay authentication for the native C TLS shim.
//!
//! Trust is SHA-256 over canonical SubjectPublicKeyInfo, exactly as in the
//! standard transport. The pinned key must also verify TLS 1.3 CertificateVerify;
//! seeing a matching public certificate alone is not proof of possession.
//! The native ClientHello offers only ecdsa_secp256r1_sha256 (0x0403).
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

pub const MAX_CERTIFICATE_BYTES: usize = 8192;
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    Certificate,
    Pin,
    Algorithm,
    Signature,
}

pub fn certificate_service_id(der: &[u8]) -> Result<[u8; 32], PinError> {
    let certificate = parse(der)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| PinError::Certificate)?;
    Ok(Sha256::digest(&spki).into())
}

fn parse(der: &[u8]) -> Result<x509_cert::Certificate, PinError> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(PinError::Certificate);
    }
    // from_der rejects trailing bytes and noncanonical DER, unlike a substring
    // search for the SPKI or an accept-any certificate parser.
    x509_cert::Certificate::from_der(der).map_err(|_| PinError::Certificate)
}

pub fn verify_server_certificate_verify(
    certificate_der: &[u8],
    expected_service_id: &[u8; 32],
    signature_scheme: u16,
    transcript_sha256: &[u8; 32],
    signature_der: &[u8],
) -> Result<(), PinError> {
    if signature_scheme != ECDSA_SECP256R1_SHA256 {
        return Err(PinError::Algorithm);
    }
    let certificate = parse(certificate_der)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| PinError::Certificate)?;
    let service_id: [u8; 32] = Sha256::digest(&spki).into();
    if &service_id != expected_service_id || expected_service_id == &[0; 32] {
        return Err(PinError::Pin);
    }
    let key = VerifyingKey::from_public_key_der(&spki).map_err(|_| PinError::Algorithm)?;
    let signature = Signature::from_der(signature_der).map_err(|_| PinError::Signature)?;
    const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
    let mut message = [0x20; 64 + CONTEXT.len() + 1 + 32];
    message[64..64 + CONTEXT.len()].copy_from_slice(CONTEXT);
    message[64 + CONTEXT.len()] = 0;
    message[65 + CONTEXT.len()..].copy_from_slice(transcript_sha256);
    key.verify(&message, &signature)
        .map_err(|_| PinError::Signature)
}

impl crate::LocalSecrets {
    /// TLS 1.3 X25519MLKEM768 shared secret, in the standardized KEM || DH order.
    /// Callers generate fresh seed material for each handshake and never reuse
    /// a GC session's bundle secrets for TLS.
    pub fn tls13_hybrid_secret(
        &self,
        peer_ecdh: &[u8; 32],
        kem_ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 64]>, crate::CryptoError> {
        use ml_kem::Decapsulate;
        let dh = self
            .ecdh
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer_ecdh));
        if !dh.was_contributory() {
            return Err(crate::CryptoError::Decrypt);
        }
        let kem = zeroize::Zeroizing::new(
            self.kem_dk
                .decapsulate_slice(kem_ciphertext)
                .map_err(|_| crate::CryptoError::BadKemCiphertext)?,
        );
        let mut shared = zeroize::Zeroizing::new([0; 64]);
        shared[..32].copy_from_slice(kem.as_slice());
        shared[32..].copy_from_slice(dh.as_bytes());
        Ok(shared)
    }
}
