use crate::bundle::{ek_from_bytes, Bundle, LocalSecrets};
use crate::identity::IdentityKeypair;
use crate::CryptoError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use ml_kem::array::Array;
use ml_kem::{Decapsulate, MlKem768};

use alloc::{collections::VecDeque, vec::Vec};
use core::time::Duration;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
#[cfg(feature = "std")]
use std::time::Instant;

/// Monotonic timestamps supplied by the platform. All operations in a session
/// must use the same clock and must never move it backwards.
#[cfg(feature = "std")]
pub type SessionTime = Instant;
#[cfg(not(feature = "std"))]
pub type SessionTime = Duration;

fn elapsed(now: SessionTime, then: SessionTime) -> Duration {
    #[cfg(feature = "std")]
    {
        now.saturating_duration_since(then)
    }
    #[cfg(not(feature = "std"))]
    {
        now.saturating_sub(then)
    }
}

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) fn rand32(rng: &mut StdRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

/// Bounded out-of-order tolerance per direction (SPEC §8.3). Frames that
/// arrive after a gap are decrypted from a retained message key as long as
/// the gap is no wider than this; beyond it the session must be reset.
pub const MAX_SKIP: usize = 64;
/// Largest encoded Frame overhead: counters, both ratchet keys, optional-field
/// tags/length, ML-KEM-768 ciphertext and the AES-GCM authentication tag.
pub const MAX_FRAME_OVERHEAD: usize = 8 + 8 + 32 + 1 + 32 + 1 + 2 + 1088 + 16;
/// Skipped message keys are retained for at most this long.
pub const SKIP_KEY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

fn encaps_deterministic(
    ek: &ml_kem::EncapsulationKey<MlKem768>,
    rng: &mut StdRng,
) -> (ml_kem::Ciphertext<MlKem768>, Zeroizing<ml_kem::SharedKey>) {
    let m = Zeroizing::new(rand32(rng));
    encaps_from_message(ek, &m)
}

fn encaps_from_message(
    ek: &ml_kem::EncapsulationKey<MlKem768>,
    message: &[u8; 32],
) -> (ml_kem::Ciphertext<MlKem768>, Zeroizing<ml_kem::SharedKey>) {
    let m = Zeroizing::new(Array::try_from(message.as_slice()).expect("32 bytes"));
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    (ct, Zeroizing::new(ss))
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct InitiatorMaterial {
    pub(crate) eph: [u8; 32],
    pub(crate) kem_message: [u8; 32],
    pub(crate) nonce: [u8; 12],
    pub(crate) ratchet: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ResponderMaterial {
    pub(crate) ratchet: [u8; 32],
}

const OLD_KP_CAP: usize = 8;

/// Length prefix for a variable field. Wire fields are bounded far below
/// `u16::MAX` by the cell size; a larger value is a caller bug and must not
/// silently wrap into a header that disagrees with the body.
fn len16(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).expect("wire field exceeds 16-bit length prefix")
}
pub const DEFAULT_PQ_EVERY_MSGS: u32 = 32;
pub const DEFAULT_PQ_AFTER: Duration = Duration::from_secs(30 * 60);

pub struct FirstMove {
    pub eph_pub: [u8; 32],
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
}

impl FirstMove {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 2 + self.kem_ct.len() + 12 + self.ct.len());
        v.extend_from_slice(&self.eph_pub);
        v.extend_from_slice(&len16(&self.kem_ct).to_be_bytes());
        v.extend_from_slice(&self.kem_ct);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 32 + 2 + 12 {
            return None;
        }
        let mut p = 0;
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&buf[p..p + 32]);
        p += 32;
        let klen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if buf.len() < p + klen + 12 {
            return None;
        }
        let kem_ct = buf[p..p + klen].to_vec();
        p += klen;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[p..p + 12]);
        p += 12;
        Some(FirstMove {
            eph_pub,
            kem_ct,
            nonce,
            ct: buf[p..].to_vec(),
        })
    }

    fn header(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 2 + self.kem_ct.len() + 12);
        v.extend_from_slice(&self.eph_pub);
        v.extend_from_slice(&len16(&self.kem_ct).to_be_bytes());
        v.extend_from_slice(&self.kem_ct);
        v.extend_from_slice(&self.nonce);
        v
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub ctr: u64,
    /// Counter of the last frame sent under the previous sending epoch
    /// (Signal's `pn`). Constant for every frame of an epoch, so a receiver
    /// that first sees any frame of a new epoch can derive the keys it
    /// skipped in the old one and in the new one.
    pub pn: u64,
    /// The sender's ratchet public key for this epoch.
    pub sender_pub: [u8; 32],
    /// The receiver ratchet key this epoch's chain was mixed with. Constant
    /// for the epoch; `None` for the initiator's first epoch.
    pub mixed_with: Option<[u8; 32]>,
    /// ML-KEM ciphertext mixed at this epoch's start, repeated on every frame
    /// of the epoch so that losing the first frame never strands the peer.
    pub pq_ct: Option<Vec<u8>>,
    pub ct: Vec<u8>,
}

impl Frame {
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.ctr.to_be_bytes());
        v.extend_from_slice(&self.pn.to_be_bytes());
        v.extend_from_slice(&self.sender_pub);
        match self.mixed_with {
            Some(m) => {
                v.push(1);
                v.extend_from_slice(&m);
            }
            None => v.push(0),
        }
        match &self.pq_ct {
            Some(c) => {
                v.push(1);
                v.extend_from_slice(&len16(c).to_be_bytes());
                v.extend_from_slice(c);
            }
            None => v.push(0),
        }
        v
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.header_bytes();
        v.extend_from_slice(&self.ct);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 + 8 + 32 + 1 + 1 {
            return None;
        }
        let mut p = 0;
        let ctr = u64::from_be_bytes(buf[p..p + 8].try_into().ok()?);
        p += 8;
        let pn = u64::from_be_bytes(buf[p..p + 8].try_into().ok()?);
        p += 8;
        if pn >= ctr {
            return None;
        }
        let mut sender_pub = [0u8; 32];
        sender_pub.copy_from_slice(&buf[p..p + 32]);
        p += 32;
        let mixed_with = if buf[p] == 1 {
            if buf.len() < p + 33 {
                return None;
            }
            let mut m = [0u8; 32];
            m.copy_from_slice(&buf[p + 1..p + 33]);
            p += 33;
            Some(m)
        } else {
            p += 1;
            None
        };
        if buf.len() < p + 1 {
            return None;
        }
        let pq_ct = if buf[p] == 1 {
            if buf.len() < p + 3 {
                return None;
            }
            let l = u16::from_be_bytes([buf[p + 1], buf[p + 2]]) as usize;
            p += 3;
            if buf.len() < p + l {
                return None;
            }
            let c = buf[p..p + l].to_vec();
            p += l;
            Some(c)
        } else {
            p += 1;
            None
        };
        Some(Frame {
            ctr,
            pn,
            sender_pub,
            mixed_with,
            pq_ct,
            ct: buf[p..].to_vec(),
        })
    }
}

/// A message key retained for a frame that has not arrived yet.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    ctr: u64,
    mk: [u8; 32],
    nonce: [u8; 12],
    #[zeroize(skip)]
    stored_at: SessionTime,
}

#[derive(Clone)]
pub struct Session {
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
    my_kp: StaticSecret,
    old_kps: VecDeque<([u8; 32], StaticSecret)>,
    peer_pub: Option<[u8; 32]>,
    /// Message keys for frames skipped on the receive chain (bounded, SPEC §8.3).
    skipped: VecDeque<SkippedKey>,
    /// Counter of the first frame of the current sending epoch. `pn` on the
    /// wire is `send_rotated_at - 1`.
    send_rotated_at: u64,
    /// The peer ratchet key our current sending epoch was mixed with.
    mixed_peer: Option<[u8; 32]>,
    /// KEM ciphertext of the current sending epoch, repeated on each frame.
    epoch_pq_ct: Option<Vec<u8>>,
    /// The peer's current ML-KEM encapsulation key (learned from its bundle
    /// or a `KemRefresh` control record). `None` until learned.
    peer_kem: Option<Vec<u8>>,
    /// Our own ML-KEM decapsulation key for refreshes addressed to us.
    kem_dk: Option<ml_kem::DecapsulationKey<ml_kem::MlKem768>>,
    /// Messages sent since our last outbound PQ encapsulation.
    sent_since_pq: u32,
    pq_every: u32,
    pq_after: Duration,
    last_pq: SessionTime,
    rng: StdRng,
}

#[cfg(any(feature = "std", feature = "sealed-state"))]
mod storage;
#[cfg(any(feature = "std", feature = "sealed-state"))]
pub use storage::{PreparedReceive, PreparedSend, SealedSession, SessionContext};

impl Session {
    /// Test-only: pin the session randomness for deterministic vectors. Never
    /// available in a production build.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn set_rng_seed(&mut self, seed: u64) {
        self.rng = StdRng::seed_from_u64(seed);
    }

    pub fn set_pq_policy(&mut self, every_msgs: u32, after: Duration) {
        self.pq_every = every_msgs.max(1);
        self.pq_after = after;
    }

    /// Install or replace the peer's ML-KEM encapsulation key so that this
    /// side can perform PQ refreshes toward it. Carried by a `KemRefresh`
    /// control record or learned from the peer's bundle at handshake.
    pub fn provide_peer_kem(&mut self, kem_pub: Vec<u8>) -> Result<(), CryptoError> {
        if kem_pub.len() != crate::KEM_EK_LEN || ek_from_bytes(&kem_pub).is_none() {
            return Err(CryptoError::BadKemKey);
        }
        self.peer_kem = Some(kem_pub);
        Ok(())
    }

    /// Whether this side currently holds a key it can PQ-refresh toward.
    pub fn has_peer_kem(&self) -> bool {
        self.peer_kem.is_some()
    }

    /// Install our own decapsulation key so PQ refreshes addressed to us decrypt.
    pub fn provide_local_kem(&mut self, dk: ml_kem::DecapsulationKey<ml_kem::MlKem768>) {
        self.kem_dk = Some(dk);
    }

    pub fn can_receive_pq(&self) -> bool {
        self.kem_dk.is_some()
    }

    pub fn skipped_keys(&self) -> usize {
        self.skipped.len()
    }

    pub fn send_ctr(&self) -> u64 {
        self.send_ctr
    }

    pub fn recv_ctr(&self) -> u64 {
        self.recv_ctr
    }

    /// Plaintext state export. Only for legacy-archive migration; new code
    /// must use [`Session::seal_state`].
    #[cfg(feature = "client-persist")]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.encode_private())
    }

    /// Plaintext state import counterpart of [`Session::encode`].
    #[cfg(feature = "client-persist")]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        Self::decode_private(buf)
    }

    #[cfg(feature = "std")]
    pub fn send(&mut self, payload: &[u8]) -> Result<Frame, CryptoError> {
        self.send_at(payload, Instant::now())
    }

    /// Encrypt with an explicit monotonic timestamp (including timed PQ refresh).
    pub fn send_at(&mut self, payload: &[u8], now: SessionTime) -> Result<Frame, CryptoError> {
        let ctr = self.send_ctr + 1;
        let mut chain = Zeroizing::new(self.send_chain);
        // Double Ratchet discipline: a new sending epoch (fresh X25519
        // ephemeral, DH with the peer's newest ratchet key) begins only when
        // the peer has sent us a key we have not mixed with yet. Within an
        // epoch the chain is a symmetric KDF ratchet, which is what lets a
        // receiver derive keys for frames it never saw (SPEC §8.3). A due PQ
        // refresh rides on that rotation so both mixes share one epoch.
        let rotate = matches!(self.peer_pub, Some(peer) if Some(peer) != self.mixed_peer);
        if rotate {
            let peer = self.peer_pub.expect("checked above");
            let new_sk = StaticSecret::random_from_rng(&mut self.rng);
            let dh = new_sk.diffie_hellman(&PublicKey::from(peer));
            *chain = mix(&chain, dh.as_bytes());
            self.rotate_self_key(new_sk);
            self.mixed_peer = Some(peer);
            self.epoch_pq_ct = None;
            let pq_due =
                self.sent_since_pq >= self.pq_every || elapsed(now, self.last_pq) >= self.pq_after;
            if pq_due {
                if let Some(ekb) = self.peer_kem.clone() {
                    let ek = ek_from_bytes(&ekb).ok_or(CryptoError::BadKemKey)?;
                    let (ct, ss) = encaps_deterministic(&ek, &mut self.rng);
                    *chain = mix(&chain, ss.as_slice());
                    self.epoch_pq_ct = Some(ct.as_slice().to_vec());
                    self.sent_since_pq = 0;
                    self.last_pq = now;
                }
            }
            self.send_rotated_at = ctr;
        }
        let pn = self.send_rotated_at.saturating_sub(1);
        let frame_pub = self.my_pub();
        let (next, mk, nonce) = chain_step(&chain, ctr);
        let next = Zeroizing::new(next);
        let mk = Zeroizing::new(mk);
        let mut hdr = Frame {
            ctr,
            pn,
            sender_pub: frame_pub,
            mixed_with: self.mixed_peer,
            pq_ct: self.epoch_pq_ct.clone(),
            ct: Vec::new(),
        }
        .header_bytes();
        let ct = seal(&mk, &nonce, payload, &hdr).map_err(|_| CryptoError::Encrypt)?;
        hdr.clear();
        self.send_chain = *next;
        self.send_ctr = ctr;
        self.sent_since_pq = self.sent_since_pq.saturating_add(1);
        Ok(Frame {
            ctr,
            pn,
            sender_pub: frame_pub,
            mixed_with: self.mixed_peer,
            pq_ct: self.epoch_pq_ct.clone(),
            ct,
        })
    }

    #[cfg(feature = "std")]
    pub fn receive(&mut self, frame: &Frame) -> Result<Vec<u8>, CryptoError> {
        self.receive_at(frame, Instant::now())
    }

    /// Authenticate with an explicit monotonic timestamp. Expired skipped keys
    /// cannot be used even when no subsequent in-order frame has arrived.
    pub fn receive_at(&mut self, frame: &Frame, now: SessionTime) -> Result<Vec<u8>, CryptoError> {
        self.prune_skipped(now);
        if frame.ctr <= self.recv_ctr {
            return self.receive_skipped(frame);
        }
        let rotates = Some(frame.sender_pub) != self.peer_pub;
        // Frames `recv_ctr+1 ..= pn` were sent under the chain as we hold it
        // now; frames `pn+1 .. ctr` under the rotated chain this frame
        // announces. Without a rotation `pn == ctr - 1` and only the first
        // range exists.
        if frame.pn >= frame.ctr {
            return Err(CryptoError::Decrypt);
        }
        let before_rotation = if rotates {
            frame.pn.saturating_sub(self.recv_ctr)
        } else {
            frame.ctr - 1 - self.recv_ctr
        };
        let after_rotation = if rotates {
            frame.ctr - 1 - frame.pn.max(self.recv_ctr)
        } else {
            0
        };
        let total_gap = before_rotation.saturating_add(after_rotation) as usize;
        if total_gap > MAX_SKIP || self.skipped.len().saturating_add(total_gap) > MAX_SKIP {
            return Err(CryptoError::Gap);
        }
        let mut chain = Zeroizing::new(self.recv_chain);
        let mut newly_skipped = Vec::with_capacity(total_gap);
        let mut skipped_ctr = self.recv_ctr + 1;
        for _ in 0..before_rotation {
            let (next, mk, nonce) = chain_step(&chain, skipped_ctr);
            newly_skipped.push(SkippedKey {
                ctr: skipped_ctr,
                mk,
                nonce,
                stored_at: now,
            });
            *chain = next;
            skipped_ctr += 1;
        }
        let mut peer_pub = self.peer_pub;
        if Some(frame.sender_pub) != self.peer_pub {
            let target = frame.mixed_with.ok_or(CryptoError::UnknownMixKey)?;
            let sk = self
                .find_keypair(&target)
                .ok_or(CryptoError::UnknownMixKey)?;
            let dh = sk.diffie_hellman(&PublicKey::from(frame.sender_pub));
            *chain = mix(&chain, dh.as_bytes());
            peer_pub = Some(frame.sender_pub);
        }
        if rotates {
            if let Some(ct) = &frame.pq_ct {
                let dk = self.kem_dk.as_ref().ok_or(CryptoError::NoPqKey)?;
                let ss = Zeroizing::new(
                    dk.decapsulate_slice(ct)
                        .map_err(|_| CryptoError::BadKemCiphertext)?,
                );
                *chain = mix(&chain, ss.as_slice());
            }
        }
        for _ in 0..after_rotation {
            let (next, mk, nonce) = chain_step(&chain, skipped_ctr);
            newly_skipped.push(SkippedKey {
                ctr: skipped_ctr,
                mk,
                nonce,
                stored_at: now,
            });
            *chain = next;
            skipped_ctr += 1;
        }
        debug_assert_eq!(skipped_ctr, frame.ctr);
        let (next, mk, nonce) = chain_step(&chain, frame.ctr);
        let next = Zeroizing::new(next);
        let mk = Zeroizing::new(mk);
        let payload = open(&mk, &nonce, &frame.ct, &frame.header_bytes())
            .map_err(|_| CryptoError::Decrypt)?;
        // Only an authenticated frame may retain skipped keys or advance state.
        self.recv_chain = *next;
        self.recv_ctr = frame.ctr;
        self.peer_pub = peer_pub;
        self.skipped.extend(newly_skipped);
        self.prune_skipped(now);
        Ok(payload)
    }

    /// Decrypt a frame whose counter is at or below `recv_ctr` using a
    /// retained skipped key. A frame we already consumed is a replay.
    fn receive_skipped(&mut self, frame: &Frame) -> Result<Vec<u8>, CryptoError> {
        let position = self
            .skipped
            .iter()
            .position(|key| key.ctr == frame.ctr)
            .ok_or(CryptoError::Replay)?;
        let key = &self.skipped[position];
        let mk = Zeroizing::new(key.mk);
        let nonce = key.nonce;
        let payload = open(&mk, &nonce, &frame.ct, &frame.header_bytes())
            .map_err(|_| CryptoError::Decrypt)?;
        self.skipped.remove(position);
        Ok(payload)
    }

    fn prune_skipped(&mut self, now: SessionTime) {
        self.skipped
            .retain(|key| elapsed(now, key.stored_at) < SKIP_KEY_TTL);
        while self.skipped.len() > MAX_SKIP {
            self.skipped.pop_front();
        }
    }

    fn rotate_self_key(&mut self, new_sk: StaticSecret) {
        let old_pub = self.my_pub();
        self.old_kps
            .push_back((old_pub, core::mem::replace(&mut self.my_kp, new_sk)));
        while self.old_kps.len() > OLD_KP_CAP {
            self.old_kps.pop_front();
        }
    }

    fn my_pub(&self) -> [u8; 32] {
        PublicKey::from(&self.my_kp).to_bytes()
    }

    fn find_keypair(&self, pub_bytes: &[u8; 32]) -> Option<&StaticSecret> {
        if self.my_pub() == *pub_bytes {
            return Some(&self.my_kp);
        }
        self.old_kps
            .iter()
            .find(|(p, _)| p == pub_bytes)
            .map(|(_, sk)| sk)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.send_chain.zeroize();
        self.recv_chain.zeroize();
    }
}
impl ZeroizeOnDrop for Session {}

#[cfg(any(feature = "std", feature = "sealed-state"))]
mod persist {
    use super::*;
    use ml_kem::KeyExport;

    const MAGIC_V1: &[u8; 6] = b"GCSES1";
    const MAGIC: &[u8; 6] = b"GCSES2";

    fn put_opt32(v: &mut Vec<u8>, x: &Option<[u8; 32]>) {
        match x {
            Some(b) => {
                v.push(1);
                v.extend_from_slice(b);
            }
            None => v.push(0),
        }
    }

    fn take_opt32(buf: &[u8], p: &mut usize) -> Option<Option<[u8; 32]>> {
        match *buf.get(*p)? {
            1 => {
                let mut b = [0u8; 32];
                b.copy_from_slice(buf.get(*p + 1..*p + 33)?);
                *p += 33;
                Some(Some(b))
            }
            0 => {
                *p += 1;
                Some(None)
            }
            _ => None,
        }
    }

    impl Session {
        #[cfg(all(feature = "std", any(test, feature = "client-persist")))]
        pub(super) fn encode_private(&self) -> Vec<u8> {
            self.encode_private_at(Instant::now())
        }

        pub(super) fn encode_private_at(&self, now: SessionTime) -> Vec<u8> {
            let mut v = Vec::with_capacity(256);
            v.extend_from_slice(MAGIC);
            v.extend_from_slice(&self.send_chain);
            v.extend_from_slice(&self.recv_chain);
            v.extend_from_slice(&self.send_ctr.to_be_bytes());
            v.extend_from_slice(&self.recv_ctr.to_be_bytes());
            v.extend_from_slice(&self.my_kp.to_bytes());
            v.push(self.old_kps.len() as u8);
            for (pk, sk) in &self.old_kps {
                v.extend_from_slice(pk);
                v.extend_from_slice(&sk.to_bytes());
            }
            put_opt32(&mut v, &self.peer_pub);
            match &self.peer_kem {
                Some(k) => {
                    v.push(1);
                    v.extend_from_slice(&(k.len() as u16).to_be_bytes());
                    v.extend_from_slice(k);
                }
                None => v.push(0),
            }
            match &self.kem_dk {
                Some(dk) => {
                    let seed = Zeroizing::new(dk.to_bytes());
                    let s = seed.as_slice();
                    v.push(1);
                    v.extend_from_slice(&(s.len() as u16).to_be_bytes());
                    v.extend_from_slice(s);
                }
                None => v.push(0),
            }
            v.extend_from_slice(&self.sent_since_pq.to_be_bytes());
            v.extend_from_slice(&self.pq_every.to_be_bytes());
            v.extend_from_slice(&(self.pq_after.as_secs()).to_be_bytes());
            let since_pq_secs = elapsed(now, self.last_pq).as_secs().min(u32::MAX as u64) as u32;
            v.extend_from_slice(&since_pq_secs.to_be_bytes());
            v.extend_from_slice(&self.send_rotated_at.to_be_bytes());
            put_opt32(&mut v, &self.mixed_peer);
            match &self.epoch_pq_ct {
                Some(ct) => {
                    v.push(1);
                    v.extend_from_slice(&(ct.len() as u16).to_be_bytes());
                    v.extend_from_slice(ct);
                }
                None => v.push(0),
            }
            v.push(self.skipped.len() as u8);
            for key in &self.skipped {
                v.extend_from_slice(&key.ctr.to_be_bytes());
                v.extend_from_slice(&key.mk);
                v.extend_from_slice(&key.nonce);
                let age = elapsed(now, key.stored_at).as_secs().min(u32::MAX as u64) as u32;
                v.extend_from_slice(&age.to_be_bytes());
            }
            v
        }

        #[cfg(all(feature = "std", any(test, feature = "client-persist")))]
        pub(super) fn decode_private(buf: &[u8]) -> Option<Self> {
            Self::decode_private_at(buf, Instant::now(), Duration::ZERO, StdRng::from_entropy())
        }

        pub(super) fn decode_private_at(
            buf: &[u8],
            now: SessionTime,
            offline: Duration,
            rng: StdRng,
        ) -> Option<Self> {
            if buf.len() < 6 + 32 * 3 + 8 * 2 + 32 + 1 {
                return None;
            }
            let legacy = match &buf[..6] {
                m if m == MAGIC => false,
                m if m == MAGIC_V1 => true,
                _ => return None,
            };
            let mut p = 6usize;
            let take32 = |p: &mut usize| -> Option<[u8; 32]> {
                let mut b = [0u8; 32];
                b.copy_from_slice(buf.get(*p..*p + 32)?);
                *p += 32;
                Some(b)
            };
            let send_chain = take32(&mut p)?;
            let recv_chain = take32(&mut p)?;
            let send_ctr = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
            p += 8;
            let recv_ctr = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
            p += 8;
            let my_kp = StaticSecret::from(take32(&mut p)?);
            let n_old = *buf.get(p)? as usize;
            p += 1;
            if n_old > OLD_KP_CAP {
                return None;
            }
            let mut old_kps = VecDeque::with_capacity(n_old);
            for _ in 0..n_old {
                let pk = take32(&mut p)?;
                let sk = StaticSecret::from(take32(&mut p)?);
                old_kps.push_back((pk, sk));
            }
            let peer_pub = take_opt32(buf, &mut p)?;
            let peer_kem = match *buf.get(p)? {
                1 => {
                    let l = u16::from_be_bytes([*buf.get(p + 1)?, *buf.get(p + 2)?]) as usize;
                    p += 3;
                    let k = buf.get(p..p + l)?.to_vec();
                    p += l;
                    if l != crate::KEM_EK_LEN {
                        return None;
                    }
                    Some(k)
                }
                0 => {
                    p += 1;
                    None
                }
                _ => return None,
            };
            let kem_dk = match *buf.get(p)? {
                1 => {
                    let l = u16::from_be_bytes([*buf.get(p + 1)?, *buf.get(p + 2)?]) as usize;
                    p += 3;
                    if l != 64 {
                        return None;
                    }
                    let seed = Array::try_from(buf.get(p..p + l)?).ok()?;
                    p += l;
                    Some(ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed))
                }
                0 => {
                    p += 1;
                    None
                }
                _ => return None,
            };
            let mut sent_since_pq = u32::from_be_bytes(buf.get(p..p + 4)?.try_into().ok()?);
            p += 4;
            let pq_every = u32::from_be_bytes(buf.get(p..p + 4)?.try_into().ok()?);
            p += 4;
            let pq_after_secs = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
            p += 8;
            if pq_every == 0 || pq_after_secs > 366 * 24 * 60 * 60 {
                return None;
            }
            let pq_after = Duration::from_secs(pq_after_secs);
            let (last_pq, send_rotated_at, mixed_peer, epoch_pq_ct, skipped) = if legacy {
                // A v1 archive did not record refresh age or epoch material:
                // force a fresh epoch and refresh on the next send.
                sent_since_pq = pq_every;
                (
                    now.checked_sub(pq_after).unwrap_or(now),
                    send_ctr,
                    None,
                    None,
                    VecDeque::new(),
                )
            } else {
                let since_pq_secs = u32::from_be_bytes(buf.get(p..p + 4)?.try_into().ok()?);
                p += 4;
                let send_rotated_at = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
                p += 8;
                if send_rotated_at > send_ctr {
                    return None;
                }
                let mixed_peer = take_opt32(buf, &mut p)?;
                let epoch_pq_ct = match *buf.get(p)? {
                    1 => {
                        let l = u16::from_be_bytes([*buf.get(p + 1)?, *buf.get(p + 2)?]) as usize;
                        p += 3;
                        if l != crate::KEM_CT_LEN {
                            return None;
                        }
                        let ct = buf.get(p..p + l)?.to_vec();
                        p += l;
                        Some(ct)
                    }
                    0 => {
                        p += 1;
                        None
                    }
                    _ => return None,
                };
                let n_skipped = *buf.get(p)? as usize;
                p += 1;
                if n_skipped > MAX_SKIP {
                    return None;
                }
                let mut skipped = VecDeque::with_capacity(n_skipped);
                for _ in 0..n_skipped {
                    let ctr = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
                    p += 8;
                    let mk = take32(&mut p)?;
                    let mut nonce = [0u8; 12];
                    nonce.copy_from_slice(buf.get(p..p + 12)?);
                    p += 12;
                    let age = u32::from_be_bytes(buf.get(p..p + 4)?.try_into().ok()?);
                    p += 4;
                    if ctr > recv_ctr {
                        return None;
                    }
                    let age = Duration::from_secs(u64::from(age)).saturating_add(offline);
                    if age >= SKIP_KEY_TTL {
                        continue;
                    }
                    // An earlier boot's age may exceed this boot's monotonic
                    // clock. Drop that key instead of granting it a fresh TTL.
                    let Some(stored_at) = now.checked_sub(age) else {
                        continue;
                    };
                    skipped.push_back(SkippedKey {
                        ctr,
                        mk,
                        nonce,
                        stored_at,
                    });
                }
                let age = Duration::from_secs(u64::from(since_pq_secs)).saturating_add(offline);
                let last_pq = now.checked_sub(age).unwrap_or_else(|| {
                    sent_since_pq = pq_every;
                    now
                });
                (last_pq, send_rotated_at, mixed_peer, epoch_pq_ct, skipped)
            };
            if p != buf.len() {
                return None;
            }
            Some(Session {
                send_chain,
                recv_chain,
                send_ctr,
                recv_ctr,
                my_kp,
                old_kps,
                peer_pub,
                skipped,
                send_rotated_at,
                mixed_peer,
                epoch_pq_ct,
                peer_kem,
                kem_dk,
                sent_since_pq,
                pq_every,
                pq_after,
                last_pq,
                rng,
            })
        }
    }

    #[cfg(all(test, feature = "std"))]
    mod tests {
        use super::*;
        use crate::identity::IdentityKeypair;

        #[test]
        fn session_state_roundtrip_continues_ratchet() {
            let bob = IdentityKeypair::from_seed([0xB2; 32]);
            let (bundle, secrets) = bob.issue_bundle();
            let (fm, mut a) = initiate(&bob.public_bytes(), &bundle, b"hi").unwrap();
            let (_p, mut b) = secrets.accept(&fm).unwrap();

            // exchange a few messages so both ratchets advance
            let f1 = a.send(b"one").unwrap();
            assert_eq!(b.receive(&f1).unwrap(), b"one");
            let f2 = b.send(b"two").unwrap();
            assert_eq!(a.receive(&f2).unwrap(), b"two");

            // persist + restore both sides
            let mut a2 = Session::decode_private(&a.encode_private()).unwrap();
            let mut b2 = Session::decode_private(&b.encode_private()).unwrap();
            assert_eq!(a2.skipped_keys(), 0);
            assert_eq!(a2.send_ctr(), a.send_ctr());
            assert_eq!(a2.recv_ctr(), a.recv_ctr());

            // conversation continues both directions
            let f3 = a2.send(b"three").unwrap();
            assert_eq!(b2.receive(&f3).unwrap(), b"three");
            let f4 = b2.send(b"four").unwrap();
            assert_eq!(a2.receive(&f4).unwrap(), b"four");

            // replay still rejected after restore
            assert!(b2.receive(&f3).is_err());
        }

        #[test]
        fn decode_rejects_garbage() {
            assert!(Session::decode_private(&[0u8; 10]).is_none());
            let bob = IdentityKeypair::from_seed([0xB2; 32]);
            let (bundle, _s) = bob.issue_bundle();
            let (_fm, a) = initiate(&bob.public_bytes(), &bundle, b"hi").unwrap();
            let mut enc = a.encode_private();
            enc.truncate(20);
            assert!(Session::decode_private(&enc).is_none());
            let mut bad = a.encode_private();
            bad[0] ^= 1;
            assert!(Session::decode_private(&bad).is_none());
        }
    }
}

/// Initiate without proving the initiator identity. The responder cannot
/// authenticate the claimed sender, so GC-only production paths use
/// [`initiate_authenticated`]; this remains for the legacy dropship transport
/// and harnesses/vectors.
#[cfg(feature = "std")]
pub fn initiate(
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
) -> Result<(FirstMove, Session), CryptoError> {
    initiate_unauthenticated(peer_identity_pk, bundle, payload0)
}

#[cfg(feature = "std")]
pub(crate) fn initiate_unauthenticated(
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
) -> Result<(FirstMove, Session), CryptoError> {
    let mut rng = StdRng::from_entropy();
    let material = initiator_material(&mut rng);
    initiate_from_material(peer_identity_pk, bundle, payload0, &material, rng)
}

fn initiator_material(rng: &mut StdRng) -> InitiatorMaterial {
    InitiatorMaterial {
        eph: rand32(rng),
        kem_message: rand32(rng),
        nonce: {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);
            nonce
        },
        ratchet: rand32(rng),
    }
}

#[cfg(feature = "std")]
pub(crate) fn initiate_from_material(
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
    material: &InitiatorMaterial,
    rng: StdRng,
) -> Result<(FirstMove, Session), CryptoError> {
    initiate_core(
        peer_identity_pk,
        bundle,
        material,
        rng,
        Instant::now(),
        |_, _, _| payload0.to_vec(),
    )
}

fn initiate_core(
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    material: &InitiatorMaterial,
    rng: StdRng,
    now: SessionTime,
    build_payload: impl FnOnce(&[u8; 32], &[u8], &[u8; 12]) -> Vec<u8>,
) -> Result<(FirstMove, Session), CryptoError> {
    if !bundle.verify(peer_identity_pk) {
        return Err(CryptoError::BundleInvalid);
    }
    let eph = StaticSecret::from(material.eph);
    let ek = ek_from_bytes(&bundle.kem_pub).ok_or(CryptoError::BadKemKey)?;
    let es = eph.diffie_hellman(&PublicKey::from(bundle.ecdh_pub));
    let (kem_ct, pq_ss) = encaps_from_message(&ek, &material.kem_message);
    let nonce = material.nonce;
    let mut salt = Vec::with_capacity(44);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    salt.extend_from_slice(&eph_pub);
    salt.extend_from_slice(&nonce);
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(es.as_bytes());
    ikm.extend_from_slice(pq_ss.as_slice());
    let root = Zeroizing::new(hkdf32(&salt, &ikm, b"gc1/handshake"));
    let a2b = Zeroizing::new(dir_key(&root, b"a2b"));
    let b2a = Zeroizing::new(dir_key(&root, b"b2a"));
    let my_kp = StaticSecret::from(material.ratchet);
    let payload = build_payload(&eph_pub, kem_ct.as_slice(), &nonce);
    let mut plaintext0 = Zeroizing::new(Vec::with_capacity(32 + payload.len()));
    plaintext0.extend_from_slice(&PublicKey::from(&my_kp).to_bytes());
    plaintext0.extend_from_slice(&payload);
    let (next_chain, mk, mk_nonce) = chain_step(&a2b, 1);
    let next_chain = Zeroizing::new(next_chain);
    let mk = Zeroizing::new(mk);
    let fm = FirstMove {
        eph_pub,
        kem_ct: kem_ct.as_slice().to_vec(),
        nonce,
        ct: Vec::new(),
    };
    let hdr = fm.header();
    let ct = seal(&mk, &mk_nonce, &plaintext0, &hdr).map_err(|_| CryptoError::Encrypt)?;
    let fm = FirstMove { ct, ..fm };
    let session = Session {
        send_chain: *next_chain,
        recv_chain: *b2a,
        send_ctr: 1,
        recv_ctr: 0,
        my_kp,
        old_kps: VecDeque::new(),
        peer_pub: None,
        skipped: VecDeque::new(),
        send_rotated_at: 1,
        mixed_peer: None,
        epoch_pq_ct: None,
        peer_kem: Some(bundle.kem_pub.clone()),
        // The initiator learns its own decapsulation key from the caller via
        // `provide_local_kem` (its bundle secrets), enabling responder->initiator
        // PQ refresh. Until then refreshes addressed to it are rejected.
        kem_dk: None,
        sent_since_pq: 1,
        pq_every: DEFAULT_PQ_EVERY_MSGS,
        pq_after: DEFAULT_PQ_AFTER,
        last_pq: now,
        rng,
    };
    Ok((fm, session))
}

/// Domain separator for the initiator-authentication signature inside a
/// first move. The signature never appears on the wire; it lives inside the
/// AEAD-encrypted bootstrap payload, consistent with the deniability rule
/// that ML-DSA appears only on bundles and encrypted control statements.
pub const FIRST_MOVE_AUTH_DOMAIN: &[u8] = b"gc1/first-move-auth/v1";

/// Canonical transcript covered by the initiator's ML-DSA signature. It binds
/// the claimed bootstrap payload to this exact handshake instance (eph,
/// KEM ciphertext, nonce), the intended responder identity, and the responder
/// bundle the initiator used. A signature therefore cannot be replayed into
/// a different handshake, responder, or bundle generation.
pub fn first_move_auth_transcript(
    eph_pub: &[u8; 32],
    kem_ct: &[u8],
    nonce: &[u8; 12],
    responder_identity_pk: &[u8],
    responder_bundle: &Bundle,
    payload: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        FIRST_MOVE_AUTH_DOMAIN.len() + responder_identity_pk.len() + 32 * 4 + 12,
    );
    transcript.extend_from_slice(FIRST_MOVE_AUTH_DOMAIN);
    transcript.extend_from_slice(responder_identity_pk);
    transcript.extend_from_slice(&Sha256::digest(responder_bundle.encode()));
    transcript.extend_from_slice(eph_pub);
    transcript.extend_from_slice(&Sha256::digest(kem_ct));
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(&Sha256::digest(payload));
    transcript
}

/// Framing of an authenticated first-move payload:
/// `info_len:u32be || info || sig_len:u16be || sig`.
pub fn frame_authenticated_payload(info: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + info.len() + 2 + signature.len());
    framed.extend_from_slice(&(info.len() as u32).to_be_bytes());
    framed.extend_from_slice(info);
    framed.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    framed.extend_from_slice(signature);
    framed
}

/// Inverse of [`frame_authenticated_payload`]. Strict: rejects truncation,
/// length overflow, and trailing bytes.
pub fn split_authenticated_payload(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let info_len = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?) as usize;
    let info_end = 4usize.checked_add(info_len)?;
    let info = payload.get(4..info_end)?;
    let sig_len =
        u16::from_be_bytes(payload.get(info_end..info_end + 2)?.try_into().ok()?) as usize;
    let sig_start = info_end.checked_add(2)?;
    let sig_end = sig_start.checked_add(sig_len)?;
    if sig_end != payload.len() {
        return None;
    }
    Some((info, payload.get(sig_start..sig_end)?))
}

/// Initiate a direct session whose bootstrap payload proves possession of the
/// claimed identity. The responder MUST reject first moves that do not carry
/// this framing and a valid signature (see `verify_first_move_auth`).
#[cfg(feature = "std")]
pub fn initiate_authenticated(
    identity: &IdentityKeypair,
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
) -> Result<(FirstMove, Session), CryptoError> {
    let mut rng = StdRng::from_entropy();
    let material = initiator_material(&mut rng);
    initiate_authenticated_from_material(
        identity,
        peer_identity_pk,
        bundle,
        payload0,
        &material,
        rng,
    )
}

#[cfg(feature = "std")]
pub(crate) fn initiate_authenticated_from_material(
    identity: &IdentityKeypair,
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
    material: &InitiatorMaterial,
    rng: StdRng,
) -> Result<(FirstMove, Session), CryptoError> {
    initiate_authenticated_from_material_at(
        identity,
        peer_identity_pk,
        bundle,
        payload0,
        material,
        rng,
        Instant::now(),
    )
}

/// Authenticate using caller-provided secure entropy and monotonic time.
/// The caller must validate the peer bundle's freshness against its wall clock.
pub fn initiate_authenticated_with_rng_at(
    identity: &IdentityKeypair,
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
    entropy: &mut (impl rand::RngCore + rand::CryptoRng),
    now: SessionTime,
) -> Result<(FirstMove, Session), CryptoError> {
    let mut rng = StdRng::from_rng(entropy).map_err(|_| CryptoError::Entropy)?;
    let material = initiator_material(&mut rng);
    initiate_authenticated_from_material_at(
        identity,
        peer_identity_pk,
        bundle,
        payload0,
        &material,
        rng,
        now,
    )
}

fn initiate_authenticated_from_material_at(
    identity: &IdentityKeypair,
    peer_identity_pk: &[u8],
    bundle: &Bundle,
    payload0: &[u8],
    material: &InitiatorMaterial,
    rng: StdRng,
    now: SessionTime,
) -> Result<(FirstMove, Session), CryptoError> {
    initiate_core(
        peer_identity_pk,
        bundle,
        material,
        rng,
        now,
        |eph_pub, kem_ct, nonce| {
            let transcript = first_move_auth_transcript(
                eph_pub,
                kem_ct,
                nonce,
                peer_identity_pk,
                bundle,
                payload0,
            );
            let signature = identity.sign(&transcript);
            frame_authenticated_payload(payload0, &signature)
        },
    )
}

/// Verify the initiator-authentication signature of a first move against the
/// claimed initiator identity and this responder's identity and bundle.
/// `payload` must be the unframed bootstrap bytes returned by
/// [`split_authenticated_payload`].
pub fn verify_first_move_auth(
    fm: &FirstMove,
    initiator_identity_pk: &[u8],
    responder_identity_pk: &[u8],
    responder_bundle: &Bundle,
    payload: &[u8],
    signature: &[u8],
) -> bool {
    let transcript = first_move_auth_transcript(
        &fm.eph_pub,
        &fm.kem_ct,
        &fm.nonce,
        responder_identity_pk,
        responder_bundle,
        payload,
    );
    crate::identity::verify_signature(initiator_identity_pk, &transcript, signature)
}

impl LocalSecrets {
    #[cfg(feature = "std")]
    pub fn accept(&self, fm: &FirstMove) -> Result<(Vec<u8>, Session), CryptoError> {
        let mut rng = StdRng::from_entropy();
        let material = ResponderMaterial {
            ratchet: rand32(&mut rng),
        };
        self.accept_from_material(fm, &material, rng)
    }

    #[cfg(feature = "std")]
    pub(crate) fn accept_from_material(
        &self,
        fm: &FirstMove,
        material: &ResponderMaterial,
        rng: StdRng,
    ) -> Result<(Vec<u8>, Session), CryptoError> {
        self.accept_from_material_at(fm, material, rng, Instant::now())
    }

    /// Accept a first move with platform entropy and a monotonic timestamp.
    /// The caller must verify the authenticated payload before trusting the peer.
    pub fn accept_with_rng_at(
        &self,
        fm: &FirstMove,
        entropy: &mut (impl rand::RngCore + rand::CryptoRng),
        now: SessionTime,
    ) -> Result<(Vec<u8>, Session), CryptoError> {
        let mut rng = StdRng::from_rng(entropy).map_err(|_| CryptoError::Entropy)?;
        let material = ResponderMaterial {
            ratchet: rand32(&mut rng),
        };
        self.accept_from_material_at(fm, &material, rng, now)
    }

    fn accept_from_material_at(
        &self,
        fm: &FirstMove,
        material: &ResponderMaterial,
        rng: StdRng,
        now: SessionTime,
    ) -> Result<(Vec<u8>, Session), CryptoError> {
        let es = self.ecdh.diffie_hellman(&PublicKey::from(fm.eph_pub));
        let pq_ss = Zeroizing::new(
            self.kem_dk
                .decapsulate_slice(&fm.kem_ct)
                .map_err(|_| CryptoError::BadKemCiphertext)?,
        );
        let mut salt = Vec::with_capacity(44);
        salt.extend_from_slice(&fm.eph_pub);
        salt.extend_from_slice(&fm.nonce);
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(es.as_bytes());
        ikm.extend_from_slice(pq_ss.as_slice());
        let root = Zeroizing::new(hkdf32(&salt, &ikm, b"gc1/handshake"));
        let a2b = Zeroizing::new(dir_key(&root, b"a2b"));
        let b2a = Zeroizing::new(dir_key(&root, b"b2a"));
        let (next_chain, mk, mk_nonce) = chain_step(&a2b, 1);
        let next_chain = Zeroizing::new(next_chain);
        let mk = Zeroizing::new(mk);
        let plaintext0 = Zeroizing::new(
            open(&mk, &mk_nonce, &fm.ct, &fm.header()).map_err(|_| CryptoError::Decrypt)?,
        );
        if plaintext0.len() < 32 {
            return Err(CryptoError::Decrypt);
        }
        let mut peer_ratchet = [0u8; 32];
        peer_ratchet.copy_from_slice(&plaintext0[..32]);
        let payload = plaintext0[32..].to_vec();
        let my_kp = StaticSecret::from(material.ratchet);
        let session = Session {
            send_chain: *b2a,
            recv_chain: *next_chain,
            send_ctr: 0,
            recv_ctr: 1,
            my_kp,
            old_kps: VecDeque::new(),
            peer_pub: Some(peer_ratchet),
            skipped: VecDeque::new(),
            send_rotated_at: 0,
            mixed_peer: None,
            epoch_pq_ct: None,
            // The responder learns the initiator's encapsulation key from the
            // authenticated bootstrap payload via `provide_peer_kem`.
            peer_kem: None,
            kem_dk: Some(self.kem_dk.clone()),
            sent_since_pq: 1,
            pq_every: DEFAULT_PQ_EVERY_MSGS,
            pq_after: DEFAULT_PQ_AFTER,
            last_pq: now,
            rng,
        };
        Ok((payload, session))
    }
}

fn mix(chain: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    hkdf32(chain, secret, b"gc1/mix")
}

fn dir_key(root: &[u8; 32], label: &[u8]) -> [u8; 32] {
    hkdf32(root, label, b"gc1/dir")
}

/// One symmetric ratchet step. HKDF-Extract is HMAC keyed by `salt`, so the
/// chain secret is passed as the salt and the counter as the input keying
/// material; the effective construction is `HMAC(chain, ctr)` expanded with
/// the `gc1/step` label. Kept byte-for-byte compatible with prior vectors.
fn chain_step(chain: &[u8; 32], ctr: u64) -> ([u8; 32], [u8; 32], [u8; 12]) {
    let hk = HkdfSha256::new(Some(chain), &ctr.to_be_bytes());
    let mut okm = Zeroizing::new([0u8; 76]);
    hk.expand(b"gc1/step", okm.as_mut())
        .expect("76 bytes fit hkdf-sha256");
    let mut next = [0u8; 32];
    let mut mk = [0u8; 32];
    let mut nonce = [0u8; 12];
    next.copy_from_slice(&okm[..32]);
    mk.copy_from_slice(&okm[32..64]);
    nonce.copy_from_slice(&okm[64..76]);
    (next, mk, nonce)
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = HkdfSha256::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 bytes fit hkdf-sha256");
    okm
}

type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;

fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key[..16]));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ())
}

fn open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key[..16]));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeypair;

    #[test]
    fn handshake_stage_isolation() {
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, secrets) = bob.issue_bundle();
        let mut rng = StdRng::from_entropy();

        let eph = StaticSecret::random_from_rng(&mut rng);
        let es1 = eph.diffie_hellman(&PublicKey::from(bundle.ecdh_pub));
        let es2 = secrets
            .ecdh
            .diffie_hellman(&PublicKey::from(PublicKey::from(&eph).to_bytes()));
        assert_eq!(es1.as_bytes(), es2.as_bytes(), "dh symmetric");

        let ek = ek_from_bytes(&bundle.kem_pub).unwrap();
        let (ct, ss1) = encaps_deterministic(&ek, &mut rng);
        let ss2 = secrets.kem_dk.decapsulate_slice(ct.as_slice()).unwrap();
        assert_eq!(ss1.as_slice(), ss2.as_slice(), "kem agree");
    }

    #[test]
    fn handshake_chain_symmetry() {
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, secrets) = bob.issue_bundle();
        let (fm, a) = initiate(&bob.public_bytes(), &bundle, b"x").unwrap();
        let (_p, b) = secrets.accept(&fm).unwrap();
        assert_eq!(a.send_chain, b.recv_chain, "a2b chains must match");
        assert_eq!(a.recv_chain, b.send_chain, "b2a chains must match");
        assert_eq!(a.send_ctr, 1);
        assert_eq!(b.recv_ctr, 1);
    }

    #[test]
    fn authenticated_first_move_roundtrips_and_verifies() {
        let alice = IdentityKeypair::from_seed([0xA1; 32]);
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, secrets) = bob.issue_bundle();
        let info = b"bootstrap-node-info";

        let (fm, _session) =
            initiate_authenticated(&alice, &bob.public_bytes(), &bundle, info).unwrap();
        let (payload, _responder) = secrets.accept(&fm).unwrap();
        let (framed_info, signature) = split_authenticated_payload(&payload).unwrap();
        assert_eq!(framed_info, info);
        assert!(verify_first_move_auth(
            &fm,
            &alice.public_bytes(),
            &bob.public_bytes(),
            &bundle,
            framed_info,
            signature
        ));
    }

    #[test]
    fn authenticated_first_move_rejects_wrong_claimed_identity() {
        let alice = IdentityKeypair::from_seed([0xA1; 32]);
        let mallory = IdentityKeypair::from_seed([0xE7; 32]);
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, secrets) = bob.issue_bundle();
        let info = b"bootstrap-node-info";

        // Mallory signs but claims Alice's identity at verification time.
        let (fm, _session) =
            initiate_authenticated(&mallory, &bob.public_bytes(), &bundle, info).unwrap();
        let (payload, _responder) = secrets.accept(&fm).unwrap();
        let (framed_info, signature) = split_authenticated_payload(&payload).unwrap();
        assert!(!verify_first_move_auth(
            &fm,
            &alice.public_bytes(),
            &bob.public_bytes(),
            &bundle,
            framed_info,
            signature
        ));
    }

    #[test]
    fn authenticated_first_move_rejects_cross_responder_replay() {
        let alice = IdentityKeypair::from_seed([0xA1; 32]);
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let carol = IdentityKeypair::from_seed([0xC3; 32]);
        let (bob_bundle, bob_secrets) = bob.issue_bundle();
        let (carol_bundle, _carol_secrets) = carol.issue_bundle();
        let info = b"bootstrap-node-info";

        let (fm, _session) =
            initiate_authenticated(&alice, &bob.public_bytes(), &bob_bundle, info).unwrap();
        let (payload, _responder) = bob_secrets.accept(&fm).unwrap();
        let (framed_info, signature) = split_authenticated_payload(&payload).unwrap();

        // The same signature must not verify for a different responder.
        assert!(!verify_first_move_auth(
            &fm,
            &alice.public_bytes(),
            &carol.public_bytes(),
            &carol_bundle,
            framed_info,
            signature
        ));
    }

    #[test]
    fn authenticated_first_move_rejects_tampered_payload_and_header() {
        let alice = IdentityKeypair::from_seed([0xA1; 32]);
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, secrets) = bob.issue_bundle();
        let info = b"bootstrap-node-info";

        let (fm, _session) =
            initiate_authenticated(&alice, &bob.public_bytes(), &bundle, info).unwrap();
        let (payload, _responder) = secrets.accept(&fm).unwrap();
        let (framed_info, signature) = split_authenticated_payload(&payload).unwrap();

        assert!(!verify_first_move_auth(
            &fm,
            &alice.public_bytes(),
            &bob.public_bytes(),
            &bundle,
            b"forged-info",
            signature
        ));
        let mut tampered = FirstMove {
            eph_pub: fm.eph_pub,
            kem_ct: fm.kem_ct.clone(),
            nonce: fm.nonce,
            ct: fm.ct.clone(),
        };
        tampered.nonce[0] ^= 1;
        assert!(!verify_first_move_auth(
            &tampered,
            &alice.public_bytes(),
            &bob.public_bytes(),
            &bundle,
            framed_info,
            signature
        ));
    }

    #[test]
    fn authenticated_payload_framing_is_strict() {
        let framed = frame_authenticated_payload(b"abc", b"sig");
        assert_eq!(
            split_authenticated_payload(&framed),
            Some((&b"abc"[..], &b"sig"[..]))
        );
        assert!(split_authenticated_payload(&framed[..framed.len() - 1]).is_none());
        let mut trailing = framed.clone();
        trailing.push(0);
        assert!(split_authenticated_payload(&trailing).is_none());
        assert!(split_authenticated_payload(&[0, 0]).is_none());
        let mut overflowing = vec![0xFF, 0xFF, 0xFF, 0xFF];
        overflowing.extend_from_slice(b"abc");
        assert!(split_authenticated_payload(&overflowing).is_none());
    }

    #[test]
    fn unauthenticated_first_move_payload_does_not_split() {
        let bob = IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, secrets) = bob.issue_bundle();
        let (fm, _session) = initiate(&bob.public_bytes(), &bundle, b"plain").unwrap();
        let (payload, _responder) = secrets.accept(&fm).unwrap();
        assert!(split_authenticated_payload(&payload).is_none());
    }
}
