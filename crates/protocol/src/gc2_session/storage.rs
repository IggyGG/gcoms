//! One authenticated archive value for both the ratchet and counter credit.
use crate::flow::{CreditedSession, Error, SessionError, MAX_PRIVATE_BYTES};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use alloc::vec::Vec;
use core::time::Duration;
use gcoms_crypto::{CryptoError, SealedSession, SessionContext, SessionTime};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 5] = b"GCPS\x02";
const HEADER: usize = 5 + 16 + 12;
const MAX_RATCHET: usize = 64 * 1024;
const MAX_BYTES: usize = HEADER + 4 + MAX_RATCHET + MAX_PRIVATE_BYTES + 16;

/// A GC/2 archive cannot be opened as a GC/1 ratchet. The public tag is bound
/// by AEAD; the enclosed ratchet additionally authenticates the peer/context.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SealedState(Vec<u8>);
impl SealedState {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SessionError> {
        if bytes.len() < HEADER + 4 + 38 + 16
            || bytes.len() > MAX_BYTES
            || bytes.get(..5) != Some(MAGIC)
            || bytes[5..21] == [0; 16]
        {
            return Err(Error::Length.into());
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn tag(&self) -> &[u8; 16] {
        self.0[5..21].try_into().expect("validated tag")
    }

    /// Both parts must come from the same live session/prepared transaction.
    /// Their counter consistency is checked again when opening the archive.
    pub fn seal_parts(
        tag: &[u8; 16],
        ratchet: &SealedSession,
        private_flow: &[u8],
        wrapping_key: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, SessionError> {
        if *tag == [0; 16]
            || ratchet.as_bytes().len() > MAX_RATCHET
            || private_flow.len() > MAX_PRIVATE_BYTES
        {
            return Err(Error::Length.into());
        }
        let mut bytes = Vec::with_capacity(HEADER);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(tag);
        let mut nonce = [0; 12];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::Entropy)?;
        bytes.extend_from_slice(&nonce);
        let mut plain = Zeroizing::new(Vec::with_capacity(
            4 + ratchet.as_bytes().len() + private_flow.len(),
        ));
        plain.extend_from_slice(&(ratchet.as_bytes().len() as u32).to_be_bytes());
        plain.extend_from_slice(ratchet.as_bytes());
        plain.extend_from_slice(private_flow);
        let key = key(wrapping_key, tag);
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .expect("AES key length")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &bytes,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        bytes.extend_from_slice(&cipher);
        Self::from_bytes(bytes)
    }
    #[cfg(feature = "std")]
    pub fn open(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<CreditedSession, SessionError> {
        self.open_at(
            wrapping_key,
            context,
            std::time::Instant::now(),
            Duration::ZERO,
            &mut rand_core::OsRng,
        )
    }

    pub fn open_at(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        offline: Duration,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<CreditedSession, SessionError> {
        let key = key(wrapping_key, self.tag());
        let plain = Aes256Gcm::new_from_slice(&*key)
            .expect("AES key length")
            .decrypt(
                Nonce::from_slice(&self.0[21..HEADER]),
                Payload {
                    msg: &self.0[HEADER..],
                    aad: &self.0[..HEADER],
                },
            )
            .map_err(|_| CryptoError::StateAuthentication)?;
        let plain = Zeroizing::new(plain);
        let length = u32::from_be_bytes(
            plain
                .get(..4)
                .ok_or(Error::Length)?
                .try_into()
                .map_err(|_| Error::Length)?,
        ) as usize;
        if length > MAX_RATCHET || plain.len().saturating_sub(4 + length) > MAX_PRIVATE_BYTES {
            return Err(Error::Length.into());
        }
        let ratchet =
            SealedSession::from_bytes(plain.get(4..4 + length).ok_or(Error::Length)?.to_vec())?;
        let session = CreditedSession::restore_at(
            &ratchet,
            plain.get(4 + length..).ok_or(Error::Length)?,
            wrapping_key,
            context,
            now,
            offline,
            entropy,
        )?;
        if session.window().session() != self.tag() {
            return Err(Error::Authentication.into());
        }
        Ok(session)
    }
}
fn key(wrapping_key: &[u8; 32], tag: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(tag), wrapping_key)
        .expand(b"GC2/sealed-peer-state/v1", key.as_mut())
        .expect("HKDF key length");
    key
}
