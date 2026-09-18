//! Versioned direct-session transactions shared by live delivery and archives.
use super::*;
#[cfg(feature = "experimental-gc2")]
use crate::scheduler::PayloadUsage;
use gcoms_crypto::{CryptoError, Frame};
#[cfg(feature = "experimental-gc2")]
use gcoms_protocol::{flow, gc2_session};

pub(crate) enum PeerSession {
    Legacy(Session),
    #[cfg(feature = "experimental-gc2")]
    Credited(flow::CreditedSession),
}
impl From<Session> for PeerSession {
    fn from(value: Session) -> Self {
        Self::Legacy(value)
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    Crypto(CryptoError),
    #[cfg(feature = "experimental-gc2")]
    Flow(flow::SessionError),
}
impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}
#[cfg(feature = "experimental-gc2")]
impl From<flow::SessionError> for Error {
    fn from(e: flow::SessionError) -> Self {
        Self::Flow(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(e) => e.fmt(f),
            #[cfg(feature = "experimental-gc2")]
            Self::Flow(e) => e.fmt(f),
        }
    }
}

#[derive(Clone)]
pub(crate) enum Snapshot {
    Legacy(SealedSession),
    #[cfg(feature = "experimental-gc2")]
    Credited(gc2_session::SealedState, Option<PayloadUsage>),
}
impl Snapshot {
    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn retained_payload(&self) -> Result<PayloadUsage, String> {
        match self {
            Self::Legacy(_) => Ok(PayloadUsage::default()),
            Self::Credited(_, Some(usage)) => Ok(*usage),
            Self::Credited(_, None) => {
                Err("parsed session must be authenticated before accounting".into())
            }
        }
    }
    #[cfg(feature = "client-persist")]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Legacy(s) => s.as_bytes(),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s, _) => s.as_bytes(),
        }
    }
    #[cfg(feature = "client-persist")]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.starts_with(b"GCPS\x02") {
            #[cfg(feature = "experimental-gc2")]
            {
                return Ok(Self::Credited(
                    gc2_session::SealedState::from_bytes(bytes)?,
                    None,
                ));
            }
            #[cfg(not(feature = "experimental-gc2"))]
            {
                return Err(CryptoError::BadEncoding.into());
            }
        }
        Ok(Self::Legacy(SealedSession::from_bytes(bytes)?))
    }
    #[cfg(any(feature = "client-persist", feature = "experimental-gc2"))]
    pub fn tag(&self) -> Option<&[u8; 16]> {
        match self {
            Self::Legacy(_) => None,
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s, _) => Some(s.tag()),
        }
    }
    pub fn open(&self, key: &[u8; 32], context: &SessionContext) -> Result<PeerSession, Error> {
        match self {
            Self::Legacy(s) => Ok(PeerSession::Legacy(Session::open_state(s, key, context)?)),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s, _) => Ok(PeerSession::Credited(s.open(key, context)?)),
        }
    }
}

pub(crate) struct PreparedSend {
    inner: Send,
    sealed: Snapshot,
}
enum Send {
    Legacy(gcoms_crypto::PreparedSend),
    #[cfg(feature = "experimental-gc2")]
    Credited(flow::PreparedSend),
}
impl PreparedSend {
    pub fn wire(&self) -> &[u8] {
        match &self.inner {
            Send::Legacy(s) => s.wire(),
            #[cfg(feature = "experimental-gc2")]
            Send::Credited(s) => s.wire(),
        }
    }
    pub fn sealed_state(&self) -> &Snapshot {
        &self.sealed
    }
    pub fn packet(&self, sender: &[u8]) -> Result<Vec<u8>, String> {
        let frame = Frame::decode(self.wire()).ok_or("invalid prepared frame")?;
        #[cfg(feature = "experimental-gc2")]
        if let Some(tag) = self.sealed.tag() {
            return gc2_session::encode_frame(tag, &frame).map_err(|e| e.to_string());
        }
        Ok(encode_frame(sender, &frame))
    }
}
pub(crate) struct PreparedReceive {
    // Evaluate application expiry once, after authenticated preparation. Later
    // receipt hashing and ACK staging must see the same accepted record.
    #[cfg(feature = "experimental-gc2")]
    expired: bool,
    inner: Receive,
    sealed: Snapshot,
}
enum Receive {
    Legacy(Box<gcoms_crypto::PreparedReceive>),
    #[cfg(feature = "experimental-gc2")]
    Credited(Box<flow::PreparedReceive>),
}
impl PreparedReceive {
    pub fn plaintext(&self) -> &[u8] {
        match &self.inner {
            Receive::Legacy(r) => r.plaintext(),
            #[cfg(feature = "experimental-gc2")]
            Receive::Credited(r) => r
                .record()
                .filter(|_| !self.expired)
                .map_or(&[], |r| r.body()),
        }
    }
    pub fn sealed_state(&self) -> &Snapshot {
        &self.sealed
    }
    pub fn credit(&self) -> Option<&[u8]> {
        match &self.inner {
            Receive::Legacy(_) => None,
            #[cfg(feature = "experimental-gc2")]
            Receive::Credited(r) => Some(r.credit()),
        }
    }
    pub fn duplicate(&self) -> bool {
        match &self.inner {
            Receive::Legacy(_) => false,
            #[cfg(feature = "experimental-gc2")]
            Receive::Credited(r) => r.record().is_none(),
        }
    }
}

impl PeerSession {
    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn retained_payload(&self) -> PayloadUsage {
        match self {
            Self::Legacy(_) => PayloadUsage::default(),
            Self::Credited(s) => PayloadUsage {
                items: s.window().cached_payload_count(),
                bytes: s.window().cached_payload_bytes(),
            },
        }
    }
    pub fn tag(&self) -> Option<&[u8; 16]> {
        match self {
            Self::Legacy(_) => None,
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => Some(s.window().session()),
        }
    }
    #[cfg(feature = "client-persist")]
    pub fn seal_state(&self, key: &[u8; 32], context: &SessionContext) -> Result<Snapshot, Error> {
        match self {
            Self::Legacy(s) => Ok(Snapshot::Legacy(s.seal_state(key, context)?)),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => seal(
                s.window().session(),
                &s.seal_ratchet(key, context)?,
                &s.window().encode_private(),
                self.retained_payload(),
                key,
            ),
        }
    }
    pub fn prepare_send(
        &self,
        bytes: &[u8],
        key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedSend, Error> {
        let deadline = if matches!(decode_direct_record(bytes), Some(DirectRecord::Data { .. })) {
            now_unix().saturating_add(600)
        } else {
            0
        };
        self.prepare_send_until(bytes, deadline, key, context)
    }
    pub fn prepare_send_until(
        &self,
        bytes: &[u8],
        deadline: u64,
        key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedSend, Error> {
        #[cfg(not(feature = "experimental-gc2"))]
        let _ = deadline;
        match self {
            Self::Legacy(s) => {
                let prepared = s.prepare_send(bytes, key, context)?;
                let sealed = Snapshot::Legacy(prepared.sealed_state().clone());
                Ok(PreparedSend {
                    inner: Send::Legacy(prepared),
                    sealed,
                })
            }
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => {
                // Volatile media requires a RAM-only repair policy before it
                // may use a durable GC/2 send window.
                let purpose = match decode_direct_record(bytes) {
                    Some(DirectRecord::VolatileApplication { .. }) => {
                        return Err(CryptoError::BadEncoding.into())
                    }
                    Some(DirectRecord::Data { .. }) => flow::Purpose::Interactive,
                    _ => flow::Purpose::Control,
                };
                let deadline = match decode_direct_record(bytes) {
                    Some(DirectRecord::Data { sent_ms, .. }) => {
                        deadline.min(gc2_receipts::horizon(sent_ms))
                    }
                    _ => deadline,
                };
                let record = flow::Record::new(purpose, deadline, bytes, &mut rand::thread_rng())
                    .map_err(flow::SessionError::from)?;
                let prepared = s.prepare_send(&record, now_unix(), key, context)?;
                let sealed = seal(
                    s.window().session(),
                    prepared.sealed_ratchet(),
                    &prepared.private_flow(),
                    PayloadUsage {
                        items: prepared.cached_payload_count(),
                        bytes: prepared.cached_payload_bytes(),
                    },
                    key,
                )?;
                Ok(PreparedSend {
                    inner: Send::Credited(prepared),
                    sealed,
                })
            }
        }
    }
    pub fn commit_send(&mut self, prepared: PreparedSend) -> Result<(), Error> {
        match (self, prepared.inner) {
            (Self::Legacy(s), Send::Legacy(p)) => Ok(s.commit_send(p)?),
            #[cfg(feature = "experimental-gc2")]
            (Self::Credited(s), Send::Credited(p)) => Ok(s.commit_send(p)?),
            #[cfg(feature = "experimental-gc2")]
            _ => Err(CryptoError::StaleTransaction.into()),
        }
    }
    pub fn prepare_receive(
        &self,
        frame: &Frame,
        key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedReceive, Error> {
        match self {
            Self::Legacy(s) => {
                let p = s.prepare_receive(frame, key, context)?;
                let sealed = Snapshot::Legacy(p.sealed_state().clone());
                Ok(PreparedReceive {
                    #[cfg(feature = "experimental-gc2")]
                    expired: false,
                    inner: Receive::Legacy(Box::new(p)),
                    sealed,
                })
            }
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => {
                let p = s.prepare_receive(frame, key, context)?;
                let current;
                let ratchet = match p.sealed_ratchet() {
                    Some(r) => r,
                    None => {
                        current = s.seal_ratchet(key, context)?;
                        &current
                    }
                };
                let sealed = seal(
                    s.window().session(),
                    ratchet,
                    &p.private_flow(),
                    PayloadUsage {
                        items: p.cached_payload_count(),
                        bytes: p.cached_payload_bytes(),
                    },
                    key,
                )?;
                let expired = p.record().is_some_and(|record| record.expired(now_unix()));
                Ok(PreparedReceive {
                    expired,
                    inner: Receive::Credited(Box::new(p)),
                    sealed,
                })
            }
        }
    }
    #[cfg(feature = "experimental-gc2")]
    pub fn prepare_first_move_retry(
        &self,
        packet: &gc2_session::Packet<'_>,
        key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<PreparedReceive, Error> {
        let Self::Credited(s) = self else {
            return Err(CryptoError::BadEncoding.into());
        };
        let p = s.prepare_first_move_retry(packet)?;
        let sealed = seal(
            s.window().session(),
            &s.seal_ratchet(key, context)?,
            &p.private_flow(),
            PayloadUsage {
                items: p.cached_payload_count(),
                bytes: p.cached_payload_bytes(),
            },
            key,
        )?;
        Ok(PreparedReceive {
            expired: false,
            inner: Receive::Credited(Box::new(p)),
            sealed,
        })
    }

    pub fn can_send(&self, bytes: &[u8]) -> bool {
        #[cfg(not(feature = "experimental-gc2"))]
        let _ = bytes;
        match self {
            Self::Legacy(_) => true,
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => {
                s.window().next_counter(purpose(bytes)).is_ok()
                    && !s.window().repair_expired(now_unix())
            }
        }
    }
    pub fn stage_received(
        &self,
        prepared: &PreparedReceive,
        key: &[u8; 32],
        context: &SessionContext,
    ) -> Result<Self, Error> {
        match (self, &prepared.inner) {
            (Self::Legacy(_), Receive::Legacy(_)) => prepared.sealed.open(key, context),
            #[cfg(feature = "experimental-gc2")]
            (Self::Credited(s), Receive::Credited(p)) => {
                Ok(Self::Credited(s.stage_received(p, key, context)?))
            }
            #[cfg(feature = "experimental-gc2")]
            _ => Err(CryptoError::StaleTransaction.into()),
        }
    }
    pub fn commit_receive(&mut self, prepared: PreparedReceive) -> Result<(), Error> {
        match (self, prepared.inner) {
            (Self::Legacy(s), Receive::Legacy(p)) => Ok(s.commit_receive(*p)?),
            #[cfg(feature = "experimental-gc2")]
            (Self::Credited(s), Receive::Credited(p)) => Ok(s.commit_receive(*p)?),
            #[cfg(feature = "experimental-gc2")]
            _ => Err(CryptoError::StaleTransaction.into()),
        }
    }
    pub fn provide_local_secrets(&mut self, secrets: &LocalSecrets) {
        match self {
            Self::Legacy(s) => s.provide_local_kem(secrets.kem_decapsulation_key()),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => s.provide_local_secrets(secrets),
        }
    }
    pub fn provide_peer_kem(&mut self, key: Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Legacy(s) => Ok(s.provide_peer_kem(key)?),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => Ok(s.provide_peer_kem(key)?),
        }
    }
    #[cfg(all(test, feature = "client-persist"))]
    pub fn send_ctr(&self) -> u64 {
        match self {
            Self::Legacy(s) => s.send_ctr(),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => s.window().sent_counter(),
        }
    }
    #[cfg(all(test, feature = "client-persist"))]
    pub fn recv_ctr(&self) -> u64 {
        match self {
            Self::Legacy(s) => s.recv_ctr(),
            #[cfg(feature = "experimental-gc2")]
            Self::Credited(s) => s.window().received_floor(),
        }
    }
}

#[cfg(feature = "experimental-gc2")]
pub(super) fn seal(
    tag: &[u8; 16],
    ratchet: &SealedSession,
    flow: &[u8],
    retained: PayloadUsage,
    key: &[u8; 32],
) -> Result<Snapshot, Error> {
    Ok(Snapshot::Credited(
        gc2_session::SealedState::seal_parts(tag, ratchet, flow, key, &mut rand::thread_rng())?,
        Some(retained),
    ))
}

#[cfg(feature = "experimental-gc2")]
fn purpose(bytes: &[u8]) -> flow::Purpose {
    match decode_direct_record(bytes) {
        Some(DirectRecord::Data { .. }) => flow::Purpose::Interactive,
        _ => flow::Purpose::Control,
    }
}

pub(super) fn cell(payload: Vec<u8>, legacy_flags: u16) -> Cell {
    let gc2 = payload.starts_with(b"GCH2")
        || payload.starts_with(b"GCM2")
        || payload.starts_with(b"GCA2");
    Cell::new(
        CellType::Msg,
        0,
        if gc2 { 0 } else { legacy_flags },
        payload,
    )
}

pub(super) fn initiate(st: &NodeState, peer: &NodeInfo) -> Result<(Vec<u8>, PeerSession), String> {
    let identity = IdentityKeypair::from_seed(st.identity_seed);
    #[cfg(feature = "experimental-gc2")]
    if st.gc2_sessions {
        let candidate = gc2_session::initiate(
            &identity,
            &st.info.public(),
            &st.secrets,
            &peer.public(),
            now_unix(),
            &mut rand::thread_rng(),
        )
        .map_err(|e| e.to_string())?;
        return Ok((candidate.packet, PeerSession::Credited(candidate.session)));
    }
    let bundle = Bundle::decode(&peer.bundle).ok_or("invalid peer bundle")?;
    if !bundle.is_fresh(now_unix()) {
        return Err("peer bundle is outside its rotation window".into());
    }
    let (first, mut session) = gcoms_crypto::initiate_authenticated(
        &identity,
        &peer.identity_pk,
        &bundle,
        &st.info.encode(),
    )
    .map_err(|e| e.to_string())?;
    session.provide_local_kem(st.secrets.kem_decapsulation_key());
    Ok((encode_first_move(&first), session.into()))
}
