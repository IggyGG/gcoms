//! Sealed storage and transactional prepare/commit APIs. Freestanding callers
//! supply entropy, monotonic time and the elapsed time across a restart.
use super::*;
use aes_gcm::aead::Payload;
use aes_gcm::Aes256Gcm;
#[cfg(feature = "std")]
use rand::rngs::OsRng;
use rand::CryptoRng;

const SEALED_MAGIC: &[u8; 8] = b"GCSEAL1\0";
const SEALED_VERSION: u16 = 1;
const MAX_CONTEXT_FIELD: usize = 128;
const MAX_SEALED_STATE: usize = 64 * 1024;
const MAX_STATE_ATTACHMENT: usize = 4 * 1024;

/// Stable application identity binding for sealed ratchet state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionContext {
    machine: Vec<u8>,
    component: Vec<u8>,
    peer: Vec<u8>,
    conversation: Vec<u8>,
}

impl SessionContext {
    pub fn new(
        machine: impl AsRef<[u8]>,
        component: impl AsRef<[u8]>,
        peer: impl AsRef<[u8]>,
        conversation: impl AsRef<[u8]>,
    ) -> Result<Self, CryptoError> {
        let fields = [
            machine.as_ref(),
            component.as_ref(),
            peer.as_ref(),
            conversation.as_ref(),
        ];
        if fields
            .iter()
            .any(|field| field.is_empty() || field.len() > MAX_CONTEXT_FIELD)
        {
            return Err(CryptoError::InvalidStateContext);
        }
        Ok(Self {
            machine: fields[0].to_vec(),
            component: fields[1].to_vec(),
            peer: fields[2].to_vec(),
            conversation: fields[3].to_vec(),
        })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = b"gc1/sealed-session/v1".to_vec();
        for field in [
            &self.machine,
            &self.component,
            &self.peer,
            &self.conversation,
        ] {
            aad.extend_from_slice(&(field.len() as u16).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }
}

/// Opaque authenticated session state. Its plaintext and ratchet keys are never exposed.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SealedSession(Vec<u8>);

impl SealedSession {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() < 8 + 2 + 12 + 16 || bytes.len() > MAX_SEALED_STATE {
            return Err(CryptoError::BadEncoding);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

pub struct PreparedSend {
    base_send_ctr: u64,
    base_recv_ctr: u64,
    wire: Vec<u8>,
    sealed: SealedSession,
    next: Option<Session>,
}

impl PreparedSend {
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    pub fn sealed_state(&self) -> &SealedSession {
        &self.sealed
    }
}

impl Drop for PreparedSend {
    fn drop(&mut self) {
        self.wire.zeroize();
    }
}
impl ZeroizeOnDrop for PreparedSend {}

pub struct PreparedReceive {
    base_send_ctr: u64,
    base_recv_ctr: u64,
    plaintext: Vec<u8>,
    sealed: SealedSession,
    next: Option<Session>,
}

impl PreparedReceive {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub fn sealed_state(&self) -> &SealedSession {
        &self.sealed
    }
}

impl Drop for PreparedReceive {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}
impl ZeroizeOnDrop for PreparedReceive {}

impl Session {
    /// Encrypt the complete session state under a caller-owned wrapping key.
    #[cfg(feature = "std")]
    pub fn seal_state(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<SealedSession, CryptoError> {
        self.seal_state_with_attachment(wrapping_key, context, &[])
    }

    /// Seals small caller metadata in the same transaction as the session.
    /// This is intended for capabilities needed to resume delivery after restart.
    #[cfg(feature = "std")]
    pub fn seal_state_with_attachment(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        attachment: &[u8],
    ) -> Result<SealedSession, CryptoError> {
        self.seal_state_with_attachment_at(
            wrapping_key,
            context,
            attachment,
            Instant::now(),
            &mut OsRng,
        )
    }

    pub fn seal_state_with_attachment_at(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        attachment: &[u8],
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<SealedSession, CryptoError> {
        if attachment.len() > MAX_STATE_ATTACHMENT {
            return Err(CryptoError::StateTooLarge);
        }
        if now < self.last_pq || self.skipped.iter().any(|key| now < key.stored_at) {
            return Err(CryptoError::StaleTransaction);
        }
        let state = Zeroizing::new(self.encode_private_at(now));
        let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + state.len() + attachment.len()));
        plaintext.extend_from_slice(&(state.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&state);
        plaintext.extend_from_slice(attachment);
        if plaintext.len() > MAX_SEALED_STATE - 64 {
            return Err(CryptoError::StateTooLarge);
        }
        let mut nonce = [0u8; 12];
        entropy
            .try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::Entropy)?;
        let aad = context.aad();
        let ciphertext = Aes256Gcm::new_from_slice(wrapping_key)
            .expect("AES-256 key length")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        let mut encoded = Vec::with_capacity(22 + ciphertext.len());
        encoded.extend_from_slice(SEALED_MAGIC);
        encoded.extend_from_slice(&SEALED_VERSION.to_be_bytes());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        SealedSession::from_bytes(encoded)
    }

    /// Restore authenticated state. Wrong keys, contexts, versions and truncation fail closed.
    #[cfg(feature = "std")]
    pub fn open_state(
        sealed: &SealedSession,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<Self, CryptoError> {
        Self::open_state_with_attachment(sealed, wrapping_key, context).map(|(session, _)| session)
    }

    /// Opens state while enforcing caller-durable counter floors to detect rollback.
    #[cfg(feature = "std")]
    pub fn open_state_at_least(
        sealed: &SealedSession,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        minimum_send_ctr: u64,
        minimum_recv_ctr: u64,
    ) -> Result<Self, CryptoError> {
        let session = Self::open_state(sealed, wrapping_key, context)?;
        if session.send_ctr < minimum_send_ctr || session.recv_ctr < minimum_recv_ctr {
            return Err(CryptoError::StaleTransaction);
        }
        Ok(session)
    }

    #[cfg(feature = "std")]
    pub fn open_state_with_attachment(
        sealed: &SealedSession,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), CryptoError> {
        Self::open_state_with_attachment_at(
            sealed,
            wrapping_key,
            context,
            Instant::now(),
            Duration::ZERO,
            &mut OsRng,
        )
    }

    /// `offline` must conservatively include elapsed time since the snapshot.
    /// Caller-durable timestamps/deadlines remain the authority for run expiry.
    pub fn open_state_with_attachment_at(
        sealed: &SealedSession,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        offline: Duration,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, Zeroizing<Vec<u8>>), CryptoError> {
        let bytes = sealed.as_bytes();
        if bytes.len() < 38
            || &bytes[..8] != SEALED_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != SEALED_VERSION
        {
            return Err(CryptoError::BadEncoding);
        }
        let plaintext = Aes256Gcm::new_from_slice(wrapping_key)
            .expect("AES-256 key length")
            .decrypt(
                Nonce::from_slice(&bytes[10..22]),
                Payload {
                    msg: &bytes[22..],
                    aad: &context.aad(),
                },
            )
            .map_err(|_| CryptoError::StateAuthentication)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() < 4 {
            return Err(CryptoError::BadEncoding);
        }
        let state_len = u32::from_be_bytes(
            plaintext[..4]
                .try_into()
                .map_err(|_| CryptoError::BadEncoding)?,
        ) as usize;
        if state_len > plaintext.len() - 4 || plaintext.len() - 4 - state_len > MAX_STATE_ATTACHMENT
        {
            return Err(CryptoError::BadEncoding);
        }
        let rng = StdRng::from_rng(entropy).map_err(|_| CryptoError::Entropy)?;
        let session = Self::decode_private_at(&plaintext[4..4 + state_len], now, offline, rng)
            .ok_or(CryptoError::BadEncoding)?;
        let attachment = Zeroizing::new(plaintext[4 + state_len..].to_vec());
        Ok((session, attachment))
    }

    /// Compute wire bytes and post-send state without advancing this session.
    #[cfg(feature = "std")]
    pub fn prepare_send(
        &self,
        payload: &[u8],
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedSend, CryptoError> {
        self.prepare_send_with_attachment(payload, wrapping_key, context, &[])
    }

    #[cfg(feature = "std")]
    pub fn prepare_send_with_attachment(
        &self,
        payload: &[u8],
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        attachment: &[u8],
    ) -> Result<PreparedSend, CryptoError> {
        self.prepare_send_with_attachment_at(
            payload,
            wrapping_key,
            context,
            attachment,
            Instant::now(),
            &mut OsRng,
        )
    }

    pub fn prepare_send_with_attachment_at(
        &self,
        payload: &[u8],
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        attachment: &[u8],
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<PreparedSend, CryptoError> {
        let mut next = self.clone_with_fresh_entropy(entropy)?;
        let wire = next.send_at(payload, now)?.encode();
        let sealed =
            next.seal_state_with_attachment_at(wrapping_key, context, attachment, now, entropy)?;
        Ok(PreparedSend {
            base_send_ctr: self.send_ctr,
            base_recv_ctr: self.recv_ctr,
            wire,
            sealed,
            next: Some(next),
        })
    }

    /// Advance only after the caller has durably stored `wire` and `sealed_state`.
    pub fn commit_send(&mut self, prepared: PreparedSend) -> Result<(), CryptoError> {
        if self.send_ctr != prepared.base_send_ctr || self.recv_ctr != prepared.base_recv_ctr {
            return Err(CryptoError::StaleTransaction);
        }
        let mut prepared = prepared;
        *self = prepared.next.take().ok_or(CryptoError::StaleTransaction)?;
        Ok(())
    }

    /// Authenticate/decrypt without advancing until application durability is complete.
    #[cfg(feature = "std")]
    pub fn prepare_receive(
        &self,
        frame: &Frame,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedReceive, CryptoError> {
        self.prepare_receive_at(frame, wrapping_key, context, Instant::now(), &mut OsRng)
    }

    pub fn prepare_receive_at(
        &self,
        frame: &Frame,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<PreparedReceive, CryptoError> {
        let mut next = self.clone_with_fresh_entropy(entropy)?;
        let plaintext = next.receive_at(frame, now)?;
        let sealed =
            next.seal_state_with_attachment_at(wrapping_key, context, &[], now, entropy)?;
        Ok(PreparedReceive {
            base_send_ctr: self.send_ctr,
            base_recv_ctr: self.recv_ctr,
            plaintext,
            sealed,
            next: Some(next),
        })
    }

    pub fn commit_receive(&mut self, prepared: PreparedReceive) -> Result<(), CryptoError> {
        if self.send_ctr != prepared.base_send_ctr || self.recv_ctr != prepared.base_recv_ctr {
            return Err(CryptoError::StaleTransaction);
        }
        let mut prepared = prepared;
        *self = prepared.next.take().ok_or(CryptoError::StaleTransaction)?;
        Ok(())
    }

    /// A copy whose randomness is independent of `self`. Cloning the RNG
    /// verbatim would make two prepared sends from one state derive the same
    /// ephemeral keys and the same AEAD nonce; that must never happen.
    fn clone_with_fresh_entropy(
        &self,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, CryptoError> {
        let mut next = self.clone();
        next.rng = StdRng::from_rng(entropy).map_err(|_| CryptoError::Entropy)?;
        Ok(next)
    }
}
