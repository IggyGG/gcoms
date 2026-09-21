//! Transaction boundary between GC/2 credit and the existing hybrid ratchet.
use super::{Error, Record, Window, CREDIT_BYTES};
use alloc::{sync::Arc, vec::Vec};
use core::time::Duration;
use gcoms_crypto::{CryptoError, Frame, SealedSession, Session, SessionContext, SessionTime};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum SessionError {
    Flow(Error),
    Crypto(CryptoError),
    StaleTransaction,
    RecoveryRequired,
}

impl From<Error> for SessionError {
    fn from(error: Error) -> Self {
        Self::Flow(error)
    }
}
impl From<CryptoError> for SessionError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}
impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Flow(error) => error.fmt(f),
            Self::Crypto(error) => error.fmt(f),
            Self::StaleTransaction => f.write_str("GC/2 transaction no longer matches its session"),
            Self::RecoveryRequired => f.write_str("GC/2 session requires authenticated recovery"),
        }
    }
}
impl core::error::Error for SessionError {}

/// Owns the ratchet so a caller cannot bypass its GC/2 counter credit.
/// Preparation never emits bytes or advances state. Persist each prepared
/// ratchet snapshot and private flow snapshot in the same authenticated archive
/// transaction as the application effects, then commit, then emit the wire bytes.
/// Never reuse an emitted archive's older state to roll back a session.
pub struct CreditedSession {
    ratchet: Session,
    window: Window,
    revision: Arc<()>,
}

impl CreditedSession {
    /// The caller must have authenticated the explicit GC/2 handshake, including
    /// its session tag and peer identity. Record its first move in `window` first.
    /// Existing GC/1 sessions cannot be promoted by copying their highest counter.
    pub fn from_authenticated(ratchet: Session, window: Window) -> Result<Self, SessionError> {
        if ratchet.send_ctr() != window.sent || ratchet.recv_ctr() != window.received.highest()? {
            return Err(Error::State.into());
        }
        Ok(Self {
            ratchet,
            window,
            revision: Arc::new(()),
        })
    }

    /// `private_flow` must already be authenticated by the containing archive.
    /// Bind `context` to the peer and GC/2 session tag, and persist both inputs
    /// atomically. Restoring also invalidates every earlier prepared transaction.
    #[cfg(feature = "std")]
    pub fn restore(
        sealed: &SealedSession,
        private_flow: &[u8],
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<Self, SessionError> {
        Self::restore_at(
            sealed,
            private_flow,
            wrapping_key,
            context,
            std::time::Instant::now(),
            Duration::ZERO,
            &mut rand_core::OsRng,
        )
    }

    pub fn restore_at(
        sealed: &SealedSession,
        private_flow: &[u8],
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        offline: Duration,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, SessionError> {
        Self::from_authenticated(
            Session::open_state_with_attachment_at(
                sealed,
                wrapping_key,
                context,
                now,
                offline,
                entropy,
            )?
            .0,
            Window::decode_private(private_flow)?,
        )
    }

    pub fn window(&self) -> &Window {
        &self.window
    }

    pub fn provide_local_secrets(&mut self, secrets: &gcoms_crypto::LocalSecrets) {
        self.ratchet
            .provide_local_kem(secrets.kem_decapsulation_key());
        self.revision = Arc::new(());
    }

    pub fn provide_peer_kem(&mut self, key: Vec<u8>) -> Result<(), SessionError> {
        self.ratchet.provide_peer_kem(key)?;
        self.revision = Arc::new(());
        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn seal_ratchet(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<SealedSession, SessionError> {
        self.seal_ratchet_at(
            wrapping_key,
            context,
            std::time::Instant::now(),
            &mut rand_core::OsRng,
        )
    }

    pub fn seal_ratchet_at(
        &self,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<SealedSession, SessionError> {
        Ok(self
            .ratchet
            .seal_state_with_attachment_at(wrapping_key, context, &[], now, entropy)?)
    }

    #[cfg(feature = "std")]
    pub fn prepare_send(
        &self,
        record: &Record,
        now_unix: u64,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedSend, SessionError> {
        self.prepare_send_at(
            record,
            now_unix,
            wrapping_key,
            context,
            std::time::Instant::now(),
            &mut rand_core::OsRng,
        )
    }

    pub fn prepare_send_at(
        &self,
        record: &Record,
        now_unix: u64,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<PreparedSend, SessionError> {
        self.prepare_send_inner(record, now_unix, wrapping_key, context, false, now, entropy)
    }

    /// Keep retry ciphertext in RAM without writing it to a private archive.
    /// A restored missing counter requires authenticated recovery, unless peer
    /// credit proves it arrived. First moves and control records stay durable.
    #[cfg(feature = "std")]
    pub fn prepare_volatile_send(
        &self,
        record: &Record,
        now_unix: u64,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedSend, SessionError> {
        self.prepare_volatile_send_at(
            record,
            now_unix,
            wrapping_key,
            context,
            std::time::Instant::now(),
            &mut rand_core::OsRng,
        )
    }

    pub fn prepare_volatile_send_at(
        &self,
        record: &Record,
        now_unix: u64,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<PreparedSend, SessionError> {
        if record.purpose() == super::Purpose::Control {
            return Err(Error::State.into());
        }
        self.prepare_send_inner(record, now_unix, wrapping_key, context, true, now, entropy)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_send_inner(
        &self,
        record: &Record,
        now_unix: u64,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        volatile: bool,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<PreparedSend, SessionError> {
        if self.window.recovery_required(now_unix) {
            return Err(SessionError::RecoveryRequired);
        }
        let counter = self.window.next_counter(record.purpose())?;
        let prepared = self.ratchet.prepare_send_with_attachment_at(
            &record.encode(),
            wrapping_key,
            context,
            &[],
            now,
            entropy,
        )?;
        let mut window = self.window.clone();
        let packet = crate::gc2_session::encode_frame_bytes(window.session(), prepared.wire())?;
        window.record_sent(counter, &packet, record, now_unix)?;
        window
            .tx
            .get_mut(&counter)
            .expect("recorded counter")
            .volatile = volatile;
        Ok(PreparedSend {
            revision: self.revision.clone(),
            ratchet: prepared,
            window,
        })
    }

    pub fn commit_send(&mut self, prepared: PreparedSend) -> Result<(), SessionError> {
        self.check_revision(&prepared.revision)?;
        self.ratchet.commit_send(prepared.ratchet)?;
        self.window = prepared.window;
        self.revision = Arc::new(());
        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn prepare_receive(
        &self,
        frame: &Frame,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedReceive, SessionError> {
        self.prepare_receive_at(
            frame,
            wrapping_key,
            context,
            std::time::Instant::now(),
            &mut rand_core::OsRng,
        )
    }

    pub fn prepare_receive_at(
        &self,
        frame: &Frame,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<PreparedReceive, SessionError> {
        crate::gc2_session::validate_frame(frame)?;
        let packet = crate::gc2_session::encode_frame(self.window.session(), frame)?;
        let mut window = self.window.clone();
        let (ratchet, record) = if window.received.contains(frame.ctr) {
            (None, None)
        } else {
            let prepared =
                self.ratchet
                    .prepare_receive_at(frame, wrapping_key, context, now, entropy)?;
            let record = Record::decode(prepared.plaintext())?;
            window.record_authenticated(frame.ctr, &packet, &record)?;
            (Some(prepared), Some(record))
        };
        // Exact packet authentication is mandatory even on the duplicate path.
        let credit = window.credit_for_duplicate(frame.ctr, &packet)?;
        Ok(PreparedReceive {
            revision: self.revision.clone(),
            next_revision: Arc::new(()),
            ratchet,
            record,
            window,
            credit,
        })
    }

    pub fn commit_receive(&mut self, prepared: PreparedReceive) -> Result<(), SessionError> {
        self.check_revision(&prepared.revision)?;
        if let Some(ratchet) = prepared.ratchet {
            self.ratchet.commit_receive(ratchet)?;
        }
        self.window = prepared.window;
        self.revision = prepared.next_revision;
        Ok(())
    }

    /// Stage a post-receive session for an application ACK in the same archive
    /// transaction. Committing this receive installs the exact revision used by
    /// that ACK. A restored or unrelated session cannot reuse either operation.
    #[cfg(feature = "std")]
    pub fn stage_received(
        &self,
        prepared: &PreparedReceive,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<Self, SessionError> {
        self.stage_received_at(
            prepared,
            wrapping_key,
            context,
            std::time::Instant::now(),
            &mut rand_core::OsRng,
        )
    }

    pub fn stage_received_at(
        &self,
        prepared: &PreparedReceive,
        wrapping_key: &[u8; 32],
        context: &SessionContext,
        now: SessionTime,
        entropy: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, SessionError> {
        self.check_revision(&prepared.revision)?;
        let current;
        let sealed = match prepared.sealed_ratchet() {
            Some(sealed) => sealed,
            None => {
                current = self.seal_ratchet_at(wrapping_key, context, now, entropy)?;
                &current
            }
        };
        let ratchet = Session::open_state_with_attachment_at(
            sealed,
            wrapping_key,
            context,
            now,
            Duration::ZERO,
            entropy,
        )?
        .0;
        Ok(Self {
            ratchet,
            window: prepared.window.clone(),
            revision: prepared.next_revision.clone(),
        })
    }

    /// Recover a lost setup receipt using the exact previously authenticated
    /// first move. Never decrypt again, create another session or reapply its
    /// contact information. Persist the candidate before sending its credit.
    pub fn prepare_first_move_retry(
        &self,
        packet: &crate::gc2_session::Packet<'_>,
    ) -> Result<PreparedReceive, SessionError> {
        if packet.kind() != crate::gc2_session::Kind::FirstMove
            || packet.tag() != self.window.session()
        {
            return Err(Error::Authentication.into());
        }
        let mut window = self.window.clone();
        let credit = window.credit_for_duplicate(1, packet.bytes())?;
        Ok(PreparedReceive {
            revision: self.revision.clone(),
            next_revision: Arc::new(()),
            ratchet: None,
            record: None,
            window,
            credit,
        })
    }

    /// Credit only retires transport counter state. It neither accepts an
    /// application message nor generates another receipt.
    pub fn prepare_credit(&self, bytes: &[u8]) -> Result<Option<PreparedCredit>, SessionError> {
        let mut window = self.window.clone();
        if !window.accept_credit(bytes)? {
            return Ok(None);
        }
        Ok(Some(PreparedCredit {
            revision: self.revision.clone(),
            window,
        }))
    }

    pub fn commit_credit(&mut self, prepared: PreparedCredit) -> Result<(), SessionError> {
        self.check_revision(&prepared.revision)?;
        self.window = prepared.window;
        self.revision = Arc::new(());
        Ok(())
    }

    fn check_revision(&self, revision: &Arc<()>) -> Result<(), SessionError> {
        if !Arc::ptr_eq(&self.revision, revision) {
            return Err(SessionError::StaleTransaction);
        }
        Ok(())
    }
}

pub struct PreparedSend {
    revision: Arc<()>,
    ratchet: gcoms_crypto::PreparedSend,
    window: Window,
}
impl PreparedSend {
    pub fn wire(&self) -> &[u8] {
        self.ratchet.wire()
    }
    pub fn sealed_ratchet(&self) -> &SealedSession {
        self.ratchet.sealed_state()
    }
    pub fn private_flow(&self) -> Zeroizing<Vec<u8>> {
        self.window.encode_private()
    }
    pub fn cached_payload_count(&self) -> usize {
        self.window.cached_payload_count()
    }
    pub fn cached_payload_bytes(&self) -> usize {
        self.window.cached_payload_bytes()
    }
}

pub struct PreparedReceive {
    revision: Arc<()>,
    next_revision: Arc<()>,
    ratchet: Option<gcoms_crypto::PreparedReceive>,
    record: Option<Record>,
    window: Window,
    credit: [u8; CREDIT_BYTES],
}
impl PreparedReceive {
    /// None on an exact duplicate: it must never execute application effects again.
    pub fn record(&self) -> Option<&Record> {
        self.record.as_ref()
    }
    /// None on a duplicate means retain the current sealed ratchet in the archive.
    pub fn sealed_ratchet(&self) -> Option<&SealedSession> {
        self.ratchet.as_ref().map(|value| value.sealed_state())
    }
    pub fn private_flow(&self) -> Zeroizing<Vec<u8>> {
        self.window.encode_private()
    }
    pub fn cached_payload_count(&self) -> usize {
        self.window.cached_payload_count()
    }
    pub fn cached_payload_bytes(&self) -> usize {
        self.window.cached_payload_bytes()
    }
    pub fn credit(&self) -> &[u8; CREDIT_BYTES] {
        &self.credit
    }
}

pub struct PreparedCredit {
    revision: Arc<()>,
    window: Window,
}
impl PreparedCredit {
    pub fn window(&self) -> &Window {
        &self.window
    }
    pub fn private_flow(&self) -> Zeroizing<Vec<u8>> {
        self.window.encode_private()
    }
    pub fn cached_payload_count(&self) -> usize {
        self.window.cached_payload_count()
    }
    pub fn cached_payload_bytes(&self) -> usize {
        self.window.cached_payload_bytes()
    }
}
