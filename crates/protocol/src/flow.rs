//! GC/2 ratchet credit. Credit receipts are encrypted, non-ratcheted control
//! records: they cannot consume the very counter credit they need to release.
//!
//! This state must be committed atomically with the matching ratchet state and
//! application transaction, before any prepared frame or receipt leaves the
//! process. Clone a window to stage a transaction; retain its old value on a
//! failed durable commit. Private encodings contain secrets and require the
//! application's authenticated encrypted archive. No GC/1 state is inferred.
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use gcoms_core::{TrafficClass, MAX_MESSAGE};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod storage;
pub use storage::MAX_PRIVATE_BYTES;
#[cfg(feature = "std")]
mod session;
#[cfg(feature = "std")]
pub use session::{CreditedSession, PreparedCredit, PreparedReceive, PreparedSend, SessionError};
#[cfg(all(test, feature = "std"))]
mod tests;

/// Includes data, presence, application ACKs, and all other ratcheted records.
pub const COUNTER_WINDOW: u64 = gcoms_crypto::session::MAX_SKIP as u64 - 1;
pub const INTERACTIVE_WINDOW: u64 = COUNTER_WINDOW - 8;
pub const BULK_WINDOW: u64 = INTERACTIVE_WINDOW - 8;
pub const RECORD_HEADER: usize = 4 + 1 + 8 + 32 + 2;
pub const MAX_RECORD_BODY: usize = MAX_MESSAGE
    - crate::gc2_session::SESSION_HEADER
    - gcoms_crypto::session::MAX_FRAME_OVERHEAD
    - RECORD_HEADER;
pub const CREDIT_BYTES: usize = 4 + 16 + 16 + 12 + 16 + 16;
const RECORD_MAGIC: &[u8; 4] = b"GCF2";
const CREDIT_MAGIC: &[u8; 4] = b"GCA2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    Length,
    Counter,
    Full,
    Authentication,
    UnknownReceipt,
    State,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Version => "explicit GC/2 flow record required",
            Self::Length => "GC/2 flow record exceeds its canonical bound",
            Self::Counter => "invalid GC/2 credit counter",
            Self::Full => "GC/2 ratchet window is full",
            Self::Authentication => "GC/2 credit authentication failed",
            Self::UnknownReceipt => "GC/2 receipt is no longer outstanding",
            Self::State => "invalid GC/2 flow state",
        })
    }
}
impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Bulk = 0,
    Interactive = 1,
    Control = 2,
}

impl Purpose {
    pub fn traffic(self) -> TrafficClass {
        if self == Self::Bulk {
            TrafficClass::Bulk
        } else {
            TrafficClass::Interactive
        }
    }
    fn limit(self) -> u64 {
        match self {
            Self::Bulk => BULK_WINDOW,
            Self::Interactive => INTERACTIVE_WINDOW,
            Self::Control => COUNTER_WINDOW,
        }
    }
    fn decode(byte: u8) -> Result<Self, Error> {
        match byte {
            0 => Ok(Self::Bulk),
            1 => Ok(Self::Interactive),
            2 => Ok(Self::Control),
            _ => Err(Error::Version),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Secret([u8; 32]);

/// Plaintext for the existing hybrid ratchet, never a wire-level plaintext.
/// The random receipt key is learned only after authenticated decryption.
pub struct Record {
    purpose: Purpose,
    not_after: u64,
    secret: Secret,
    body: Zeroizing<Vec<u8>>,
}

impl Record {
    pub fn new<R: RngCore + CryptoRng>(
        purpose: Purpose,
        not_after: u64,
        body: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if body.len() > MAX_RECORD_BODY || (not_after == 0 && purpose != Purpose::Control) {
            return Err(Error::Length);
        }
        let mut secret = Secret([0; 32]);
        rng.fill_bytes(&mut secret.0);
        Ok(Self {
            purpose,
            not_after,
            secret,
            body: Zeroizing::new(body.to_vec()),
        })
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    /// Expiry suppresses application effects, not counter repair. Even an
    /// expired authenticated frame must advance and persist the receive window.
    pub fn expired(&self, now_unix: u64) -> bool {
        self.not_after != 0 && self.not_after <= now_unix
    }
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(RECORD_HEADER + self.body.len()));
        bytes.extend_from_slice(RECORD_MAGIC);
        bytes.push(self.purpose as u8);
        bytes.extend_from_slice(&self.not_after.to_be_bytes());
        bytes.extend_from_slice(&self.secret.0);
        bytes.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.get(..4) != Some(RECORD_MAGIC) {
            return Err(Error::Version);
        }
        if !(RECORD_HEADER..=RECORD_HEADER + MAX_RECORD_BODY).contains(&bytes.len()) {
            return Err(Error::Length);
        }
        let purpose = Purpose::decode(bytes[4])?;
        let not_after = u64::from_be_bytes(bytes[5..13].try_into().map_err(|_| Error::Length)?);
        let length =
            u16::from_be_bytes(bytes[45..47].try_into().map_err(|_| Error::Length)?) as usize;
        if bytes.len() != RECORD_HEADER + length || (not_after == 0 && purpose != Purpose::Control)
        {
            return Err(Error::Length);
        }
        Ok(Self {
            purpose,
            not_after,
            secret: Secret(bytes[13..45].try_into().map_err(|_| Error::Length)?),
            body: Zeroizing::new(bytes[RECORD_HEADER..].to_vec()),
        })
    }
}

#[derive(Clone)]
struct Authority {
    secret: Arc<Secret>,
    packet_hash: [u8; 32],
    reference: [u8; 16],
}

impl Authority {
    fn new(session: &[u8; 16], packet_hash: [u8; 32], secret: Secret) -> Self {
        let mut reference = [0; 16];
        let mut info = b"GC2/credit-reference\0".to_vec();
        info.extend_from_slice(session);
        Hkdf::<Sha256>::new(Some(&packet_hash), &secret.0)
            .expand(&info, &mut reference)
            .expect("fixed HKDF length");
        Self {
            secret: Arc::new(secret),
            packet_hash,
            reference,
        }
    }
    fn key(&self, session: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0; 32]);
        let mut info = b"GC2/credit-encryption\0".to_vec();
        info.extend_from_slice(session);
        Hkdf::<Sha256>::new(Some(&self.packet_hash), &self.secret.0)
            .expand(&info, key.as_mut())
            .expect("fixed HKDF length");
        key
    }
}

#[derive(Clone)]
struct Sent {
    authority: Authority,
    packet: Arc<Zeroizing<Vec<u8>>>,
    purpose: Purpose,
    sent_unix: u64,
}

#[derive(Clone)]
struct Received {
    authority: Authority,
    cached_credit: Option<[u8; CREDIT_BYTES]>,
}

/// Bounded receive coverage, independent of expiring ratchet skipped keys.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Coverage {
    floor: u64,
    mask: u64,
}

impl Coverage {
    fn highest(self) -> Result<u64, Error> {
        self.floor
            .checked_add(u64::from(64 - self.mask.leading_zeros()))
            .ok_or(Error::Counter)
    }
    fn count(self) -> Result<u64, Error> {
        self.floor
            .checked_add(u64::from(self.mask.count_ones()))
            .ok_or(Error::Counter)
    }
    fn contains(self, counter: u64) -> bool {
        counter <= self.floor
            || counter
                .checked_sub(self.floor + 1)
                .is_some_and(|shift| shift < 63 && self.mask & (1u64 << shift) != 0)
    }
    fn accept(&mut self, counter: u64) -> Result<(), Error> {
        let distance = counter.checked_sub(self.floor).ok_or(Error::Counter)?;
        if distance == 0 || distance > COUNTER_WINDOW || self.contains(counter) {
            return Err(Error::Counter);
        }
        self.mask |= 1 << (distance - 1);
        while self.mask & 1 != 0 {
            self.floor = self.floor.checked_add(1).ok_or(Error::Counter)?;
            self.mask >>= 1;
        }
        Ok(())
    }
    fn valid(self) -> bool {
        self.mask & 1 == 0 && self.mask >> 63 == 0 && self.highest().is_ok()
    }
}

/// One explicitly negotiated GC/2 session, beginning before its first move.
/// Every ratcheted counter, including the first move and application ACKs, must
/// be recorded. This cannot be created from a GC/1 session's highest counters.
#[derive(Clone)]
pub struct Window {
    session: [u8; 16],
    sent: u64,
    credited: Coverage,
    received: Coverage,
    tx: BTreeMap<u64, Sent>,
    rx: BTreeMap<u64, Received>,
}

impl Window {
    pub fn new(session: [u8; 16]) -> Result<Self, Error> {
        if session == [0; 16] {
            return Err(Error::State);
        }
        Ok(Self {
            session,
            sent: 0,
            credited: Coverage::default(),
            received: Coverage::default(),
            tx: BTreeMap::new(),
            rx: BTreeMap::new(),
        })
    }
    pub fn session(&self) -> &[u8; 16] {
        &self.session
    }
    pub fn sent_counter(&self) -> u64 {
        self.sent
    }
    pub fn credited_floor(&self) -> u64 {
        self.credited.floor
    }
    pub fn received_floor(&self) -> u64 {
        self.received.floor
    }
    pub fn cached_payload_bytes(&self) -> usize {
        self.tx.values().map(|entry| entry.packet.len()).sum()
    }
    pub fn oldest_uncredited_unix(&self) -> Option<u64> {
        self.tx.values().map(|entry| entry.sent_unix).min()
    }

    /// Conservatively stop reusing this session before a missing skipped key
    /// can have expired. Recovery creates an explicitly authenticated session;
    /// it preserves still-live logical message IDs and their original deadlines.
    pub fn repair_expired(&self, now_unix: u64) -> bool {
        self.oldest_uncredited_unix().is_some_and(|oldest| {
            now_unix.saturating_sub(oldest) >= gcoms_crypto::session::SKIP_KEY_TTL.as_secs()
        })
    }

    /// Check before preparing or consuming the next ratchet counter.
    pub fn next_counter(&self, purpose: Purpose) -> Result<u64, Error> {
        let next = self.sent.checked_add(1).ok_or(Error::Counter)?;
        if next - self.credited.floor > purpose.limit() {
            return Err(Error::Full);
        }
        Ok(next)
    }

    /// Stage a committed ciphertext copy, without manufacturing a retry. The
    /// caller atomically persists this staged window with the prepared ratchet.
    pub fn record_sent(
        &mut self,
        counter: u64,
        packet: &[u8],
        record: &Record,
        sent_unix: u64,
    ) -> Result<(), Error> {
        if packet.is_empty() || packet.len() > MAX_MESSAGE {
            return Err(Error::Length);
        }
        if sent_unix == 0 || self.next_counter(record.purpose)? != counter {
            return Err(Error::Counter);
        }
        let authority = Authority::new(
            &self.session,
            Sha256::digest(packet).into(),
            record.secret.clone(),
        );
        if self
            .tx
            .values()
            .any(|entry| entry.authority.reference == authority.reference)
        {
            return Err(Error::State);
        }
        self.tx.insert(
            counter,
            Sent {
                authority,
                packet: Arc::new(Zeroizing::new(packet.to_vec())),
                purpose: record.purpose,
                sent_unix,
            },
        );
        self.sent = counter;
        Ok(())
    }

    /// Record only a newly authenticated/decrypted ratchet packet. Do this on
    /// the same staged transaction as the receive commit, including for expired
    /// application records. Duplicates use `credit_for_duplicate` instead.
    pub fn record_authenticated(
        &mut self,
        counter: u64,
        packet: &[u8],
        record: &Record,
    ) -> Result<(), Error> {
        if packet.is_empty() || packet.len() > MAX_MESSAGE {
            return Err(Error::Length);
        }
        let mut coverage = self.received;
        coverage.accept(counter)?;
        let authority = Authority::new(
            &self.session,
            Sha256::digest(packet).into(),
            record.secret.clone(),
        );
        self.rx.insert(
            counter,
            Received {
                authority,
                cached_credit: None,
            },
        );
        self.received = coverage;
        let minimum = coverage.highest()?.saturating_sub(COUNTER_WINDOW - 1);
        self.rx.retain(|counter, _| *counter >= minimum);
        Ok(())
    }

    /// Produce a non-ACK-eliciting credit receipt for an exact authenticated
    /// packet (new or duplicate). Persist the resulting window before sending.
    /// Credit says only that ratchet state was committed, never that an
    /// application accepted or completed a message.
    pub fn credit_for_duplicate(
        &mut self,
        counter: u64,
        packet: &[u8],
    ) -> Result<[u8; CREDIT_BYTES], Error> {
        if packet.len() > MAX_MESSAGE {
            return Err(Error::Length);
        }
        let entry = self.rx.get_mut(&counter).ok_or(Error::UnknownReceipt)?;
        if entry.authority.packet_hash != <[u8; 32]>::from(Sha256::digest(packet)) {
            return Err(Error::Authentication);
        }
        // Coverage count strictly increases on every new authenticated packet.
        // Atomic persistence before emission prevents reuse after a crash. ACKs
        // for duplicate packets replay the cached bytes without another AEAD call.
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.received.count()?.to_be_bytes());
        if let Some(cached) = entry.cached_credit.filter(|bytes| bytes[36..48] == nonce) {
            return Ok(cached);
        }
        let mut bytes = [0; CREDIT_BYTES];
        bytes[..4].copy_from_slice(CREDIT_MAGIC);
        bytes[4..20].copy_from_slice(&self.session);
        bytes[20..36].copy_from_slice(&entry.authority.reference);
        bytes[36..48].copy_from_slice(&nonce);
        let mut plaintext = Zeroizing::new([0u8; 16]);
        plaintext[..8].copy_from_slice(&self.received.floor.to_be_bytes());
        plaintext[8..].copy_from_slice(&self.received.mask.to_be_bytes());
        let key = entry.authority.key(&self.session);
        let ciphertext = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| Error::State)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &bytes[..36],
                },
            )
            .map_err(|_| Error::Authentication)?;
        bytes[48..].copy_from_slice(&ciphertext);
        entry.cached_credit = Some(bytes);
        Ok(bytes)
    }

    /// Authenticate credit before changing or retiring anything. A stale receipt
    /// can never move the floor backwards or remove selective receipt coverage.
    pub fn accept_credit(&mut self, bytes: &[u8]) -> Result<bool, Error> {
        if bytes.len() != CREDIT_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..4] != CREDIT_MAGIC {
            return Err(Error::Version);
        }
        if bytes[4..20] != self.session {
            return Err(Error::Authentication);
        }
        let entry = self
            .tx
            .values()
            .find(|entry| entry.authority.reference == bytes[20..36])
            .ok_or(Error::UnknownReceipt)?;
        let coverage = decode_credit(&self.session, &entry.authority, bytes)?;
        if coverage.highest()? > self.sent {
            return Err(Error::Counter);
        }
        if coverage.floor < self.credited.floor {
            return Ok(false);
        }
        let advance = coverage.floor - self.credited.floor;
        let previous_mask = self.credited.mask.checked_shr(advance as u32).unwrap_or(0);
        let mut credited = Coverage {
            floor: coverage.floor,
            mask: coverage.mask | previous_mask,
        };
        while credited.mask & 1 != 0 {
            credited.floor = credited.floor.checked_add(1).ok_or(Error::Counter)?;
            credited.mask >>= 1;
        }
        let changed = credited != self.credited;
        self.credited = credited;
        self.tx.retain(|counter, _| *counter > credited.floor);
        Ok(changed)
    }

    /// Retained original bytes, skipping selectively received packets. Expired
    /// application deadlines do not silently erase a missing ratchet counter.
    pub fn retries(&self) -> impl Iterator<Item = (u64, Purpose, &[u8])> {
        self.tx
            .iter()
            .filter(|(counter, _)| !self.credited.contains(**counter))
            .map(|(counter, entry)| (*counter, entry.purpose, entry.packet.as_slice()))
    }
}

fn decode_credit(
    session: &[u8; 16],
    authority: &Authority,
    bytes: &[u8],
) -> Result<Coverage, Error> {
    if bytes.len() != CREDIT_BYTES
        || &bytes[..4] != CREDIT_MAGIC
        || bytes[4..20] != *session
        || bytes[20..36] != authority.reference
        || bytes[36..40] != [0; 4]
    {
        return Err(Error::Authentication);
    }
    let key = authority.key(session);
    let plaintext = Zeroizing::new(
        Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| Error::State)?
            .decrypt(
                Nonce::from_slice(&bytes[36..48]),
                Payload {
                    msg: &bytes[48..],
                    aad: &bytes[..36],
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let coverage = Coverage {
        floor: u64::from_be_bytes(plaintext[..8].try_into().map_err(|_| Error::Length)?),
        mask: u64::from_be_bytes(plaintext[8..].try_into().map_err(|_| Error::Length)?),
    };
    if !coverage.valid() || coverage.count()?.to_be_bytes() != bytes[40..48] {
        return Err(Error::Counter);
    }
    Ok(coverage)
}
