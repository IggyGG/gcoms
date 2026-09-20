#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::error::Error;
use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    BundleInvalid,
    BadKemKey,
    BadKemCiphertext,
    Encrypt,
    Decrypt,
    Replay,
    Gap,
    UnknownMixKey,
    NoPqKey,
    BadEncoding,
    InvalidStateContext,
    StateTooLarge,
    StateAuthentication,
    StaleTransaction,
    BadSignature,
    Entropy,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::BundleInvalid => write!(f, "bundle signature invalid"),
            CryptoError::BadKemKey => write!(f, "malformed ML-KEM encapsulation key"),
            CryptoError::BadKemCiphertext => write!(f, "malformed ML-KEM ciphertext"),
            CryptoError::Encrypt => write!(f, "encryption failed"),
            CryptoError::Decrypt => write!(f, "decryption failed (tamper or desync)"),
            CryptoError::Replay => write!(f, "replayed frame"),
            CryptoError::Gap => write!(f, "missing frame (out of order)"),
            CryptoError::UnknownMixKey => write!(f, "rotation references unknown key"),
            CryptoError::NoPqKey => write!(f, "no decapsulation key for PQ refresh"),
            CryptoError::BadEncoding => write!(f, "malformed encoding"),
            CryptoError::InvalidStateContext => write!(f, "invalid session state context"),
            CryptoError::StateTooLarge => write!(f, "session state exceeds its limit"),
            CryptoError::StateAuthentication => {
                write!(f, "session state authentication failed")
            }
            CryptoError::StaleTransaction => write!(f, "stale session transaction"),
            CryptoError::BadSignature => write!(f, "initiator signature invalid"),
            CryptoError::Entropy => write!(f, "secure randomness unavailable"),
        }
    }
}

impl Error for CryptoError {}

pub mod bundle;
pub mod conformance;
pub mod identity;
pub mod receiver_descriptor;
pub mod session;
#[cfg(feature = "tls-pin")]
pub mod tls_pin;

pub use bundle::{
    Bundle, LocalSecrets, KEM_CT_LEN, KEM_EK_LEN, MAX_BUNDLE_AGE_SECS, MAX_BUNDLE_FUTURE_SKEW_SECS,
};
pub use identity::{
    checked_safety_number_of, is_valid_identity_pk, safety_number_of, verify_signature,
    IdentityKeypair, IDENTITY_PK_LEN,
};
#[cfg(any(test, feature = "test-vectors"))]
pub use session::initiate;
#[cfg(feature = "std")]
pub use session::initiate_authenticated;
pub use session::{
    frame_authenticated_payload, initiate_authenticated_with_rng_at, split_authenticated_payload,
    verify_first_move_auth, FirstMove, Frame, Session, SessionTime, DEFAULT_PQ_AFTER,
    DEFAULT_PQ_EVERY_MSGS, FIRST_MOVE_AUTH_DOMAIN, MAX_SKIP, SKIP_KEY_TTL,
};
#[cfg(any(feature = "std", feature = "sealed-state"))]
pub use session::{PreparedReceive, PreparedSend, SealedSession, SessionContext};
