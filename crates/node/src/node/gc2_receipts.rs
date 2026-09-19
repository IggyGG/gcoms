//! Bounded logical receipts across GC/2 session replacement. No message bodies.
use gcoms_protocol::flow::Window;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_RECEIPTS: usize = 2048;
const MAX_PER_PEER: usize = 128;
const MAX_PENDING_ACKS: usize = 1024;
#[cfg(feature = "client-persist")]
const MAX_LEGACY: usize = 8192;
#[cfg(feature = "client-persist")]
pub(super) const MAX_ENCODED: usize =
    5 + 8 + 2 + MAX_RECEIPTS * 112 + 2 + MAX_LEGACY * 56 + 2 + MAX_PENDING_ACKS * 57;
type Key = ([u8; 32], [u8; 16]);
type Barrier = ([u8; 16], u64);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Receipt {
    hash: [u8; 32],
    horizon: u64,
    ack: Option<Barrier>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingAck {
    expires: u64,
    share_presence: bool,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct Ledger {
    entries: BTreeMap<Key, Receipt>,
    legacy: BTreeMap<[u8; 32], Barrier>,
    pending: BTreeMap<Key, PendingAck>,
    // Expired effects cannot become live again after a wall-clock correction.
    clock_floor: u64,
}

#[derive(Debug)]
pub(super) struct Undo {
    clock_floor: u64,
    inserted: Option<Key>,
    removed: Vec<(Key, Receipt)>,
    legacy: Option<([u8; 32], Barrier)>,
    pending_inserted: Option<Key>,
    pending_removed: Vec<(Key, PendingAck)>,
}

pub(super) fn peer_key(peer: &[u8]) -> [u8; 32] {
    Sha256::digest(peer).into()
}

/// Direct application records currently have a ten-minute logical lifetime. Its authenticated
/// original timestamp provides an immutable ceiling across re-encryption.
pub(super) fn horizon(sent_ms: u64) -> u64 {
    (sent_ms / 1000).saturating_add(600)
}

impl Ledger {
    #[cfg(all(test, feature = "client-persist"))]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn now(&self, now: u64) -> u64 {
        now.max(self.clock_floor)
    }

    /// Check before staging an inbox effect or consuming a ratchet counter.
    pub(super) fn check(
        &self,
        peer: &[u8],
        id: [u8; 16],
        hash: [u8; 32],
        horizon: u64,
        now: u64,
    ) -> Result<bool, String> {
        let now = self.now(now);
        if horizon <= now {
            return Err("expired GC/2 logical record".into());
        }
        let key = (peer_key(peer), id);
        if let Some(receipt) = self.entries.get(&key) {
            if receipt.hash != hash || receipt.horizon != horizon {
                return Err("conflicting GC/2 logical record".into());
            }
            return Ok(true);
        }
        let live = self.entries.iter().filter(|(_, r)| r.horizon > now);
        if live.clone().count() >= MAX_RECEIPTS
            || live.filter(|(k, _)| k.0 == key.0).count() >= MAX_PER_PEER
        {
            return Err("GC/2 logical receipt capacity reached".into());
        }
        Ok(false)
    }

    fn expire(&mut self, now: u64) -> Undo {
        let old_clock = self.clock_floor;
        self.clock_floor = self.now(now);
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, r)| r.horizon <= self.clock_floor)
            .map(|(k, _)| *k)
            .collect();
        let removed = keys
            .into_iter()
            .map(|k| (k, self.entries.remove(&k).unwrap()))
            .collect();
        let keys: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, ack)| ack.expires <= self.clock_floor)
            .map(|(k, _)| *k)
            .collect();
        let pending_removed = keys
            .into_iter()
            .map(|key| (key, self.pending.remove(&key).unwrap()))
            .collect();
        Undo {
            clock_floor: old_clock,
            inserted: None,
            removed,
            legacy: None,
            pending_inserted: None,
            pending_removed,
        }
    }

    pub(super) fn stage_data(
        &mut self,
        peer: &[u8],
        id: [u8; 16],
        hash: [u8; 32],
        horizon: u64,
        ack: Barrier,
        now: u64,
    ) -> Result<Undo, String> {
        self.check(peer, id, hash, horizon, now)?;
        let mut undo = self.expire(now);
        let key = (peer_key(peer), id);
        if let Some(old) = self.entries.insert(
            key,
            Receipt {
                hash,
                horizon,
                ack: Some(ack),
            },
        ) {
            undo.removed.push((key, old));
        }
        if let Some(old) = self.pending.remove(&key) {
            undo.pending_removed.push((key, old));
        }
        undo.inserted = Some(key);
        Ok(undo)
    }

    pub(super) fn stage_credit(&mut self, peer: &[u8], window: &Window, now: u64) -> Undo {
        let mut undo = self.expire(now);
        let peer = peer_key(peer);
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(k, r)| {
                k.0 == peer
                    && r.ack.is_some_and(|(tag, counter)| {
                        &tag == window.session() && window.is_credited(counter)
                    })
            })
            .map(|(k, _)| *k)
            .collect();
        undo.removed.extend(
            keys.into_iter()
                .map(|k| (k, self.entries.remove(&k).unwrap())),
        );
        if self.legacy.get(&peer).is_some_and(|(tag, counter)| {
            tag == window.session() && *counter <= window.credited_floor()
        }) {
            undo.legacy = self.legacy.remove(&peer).map(|b| (peer, b));
        }
        undo
    }

    pub(super) fn rollback(&mut self, undo: Undo) {
        if let Some(key) = undo.inserted {
            self.entries.remove(&key);
        }
        self.entries.extend(undo.removed);
        if let Some(key) = undo.pending_inserted {
            self.pending.remove(&key);
        }
        self.pending.extend(undo.pending_removed);
        self.clock_floor = undo.clock_floor;
        if let Some((peer, barrier)) = undo.legacy {
            self.legacy.insert(peer, barrier);
        }
    }

    pub(super) fn recovery_allowed(&self, peer: &[u8]) -> bool {
        !self.legacy.contains_key(&peer_key(peer))
    }

    /// Persist the obligation, not an unbounded queue of received bodies. A
    /// full transmit window must not prevent independent receive credit.
    pub(super) fn stage_deferred_ack(
        &mut self,
        peer: &[u8],
        id: [u8; 16],
        application: Option<([u8; 32], u64)>,
        share_presence: bool,
        now: u64,
    ) -> Result<Undo, String> {
        let key = (peer_key(peer), id);
        let now = self.now(now);
        if let Some((hash, horizon)) = application {
            self.check(peer, id, hash, horizon, now)?;
        }
        let existing = self
            .entries
            .get(&key)
            .filter(|receipt| receipt.horizon > now);
        let pending = self.pending.get(&key).filter(|ack| ack.expires > now);
        if (application.is_none() && existing.is_some())
            || (application.is_some() && pending.is_some() && existing.is_none())
        {
            return Err("conflicting GC/2 deferred ACK identity".into());
        }
        let live = self.pending.iter().filter(|(_, ack)| ack.expires > now);
        if pending.is_none()
            && (live.clone().count() >= MAX_PENDING_ACKS
                || live.filter(|(k, _)| k.0 == key.0).count() >= MAX_PER_PEER)
        {
            return Err("GC/2 deferred ACK capacity reached".into());
        }
        let mut undo = self.expire(now);
        let expires = application.map_or(now.saturating_add(600), |(_, horizon)| horizon);
        if let Some(old) = self.pending.insert(
            key,
            PendingAck {
                expires,
                share_presence,
            },
        ) {
            self.pending.get_mut(&key).unwrap().expires = expires.min(old.expires);
            undo.pending_removed.push((key, old));
        }
        undo.pending_inserted = Some(key);
        if let Some((hash, horizon)) = application {
            if let Some(old) = self.entries.insert(
                key,
                Receipt {
                    hash,
                    horizon,
                    ack: None,
                },
            ) {
                undo.removed.push((key, old));
            }
            undo.inserted = Some(key);
        }
        Ok(undo)
    }

    pub(super) fn pending_acks(&self, now: u64) -> Vec<(Key, bool, u64)> {
        let mut pending: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, ack)| ack.expires > self.now(now))
            .map(|(key, ack)| (*key, ack.share_presence, ack.expires))
            .collect();
        // Older obligations get priority; a busy peer cannot perpetually move
        // new obligations ahead of another peer's already accepted records.
        pending.sort_by_key(|(key, _, expires)| (*expires, *key));
        pending
    }

    pub(super) fn stage_prepared_ack(&mut self, key: Key, ack: Barrier, now: u64) -> Undo {
        let mut undo = self.expire(now);
        if let Some(old) = self.pending.remove(&key) {
            undo.pending_removed.push((key, old));
            if let Some(receipt) = self.entries.get_mut(&key) {
                undo.removed.push((key, receipt.clone()));
                undo.inserted = Some(key);
                receipt.ack = Some(ack);
            }
        }
        undo
    }

    /// Historical v20 archives cannot reconstruct consumed application IDs.
    /// Retain their session until every possibly outstanding application ACK
    /// has been credited. No old ciphertext is relabeled as recovery-safe.
    #[cfg(feature = "client-persist")]
    pub(super) fn migrate(&mut self, peer: &[u8], window: &Window) {
        let barrier = window
            .retries()
            .filter(|(_, purpose, bytes)| {
                *purpose == gcoms_protocol::flow::Purpose::Control && bytes.starts_with(b"GCM2")
            })
            .map(|(counter, _, _)| counter)
            .max();
        if let Some(counter) = barrier {
            self.legacy
                .insert(peer_key(peer), (*window.session(), counter));
        }
    }

    #[cfg(feature = "client-persist")]
    pub(super) fn encode(&self) -> Vec<u8> {
        self.encode_version(true)
    }

    #[cfg(feature = "client-persist")]
    fn encode_version(&self, deferred: bool) -> Vec<u8> {
        let mut bytes = if deferred { b"GC2R2" } else { b"GC2R1" }.to_vec();
        bytes.extend_from_slice(&self.clock_floor.to_be_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for ((peer, id), r) in &self.entries {
            bytes.extend_from_slice(peer);
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&r.hash);
            bytes.extend_from_slice(&r.horizon.to_be_bytes());
            let (tag, counter) = r.ack.unwrap_or(([0; 16], 0));
            bytes.extend_from_slice(&tag);
            bytes.extend_from_slice(&counter.to_be_bytes());
        }
        bytes.extend_from_slice(&(self.legacy.len() as u16).to_be_bytes());
        for (peer, (tag, counter)) in &self.legacy {
            bytes.extend_from_slice(peer);
            bytes.extend_from_slice(tag);
            bytes.extend_from_slice(&counter.to_be_bytes());
        }
        if deferred {
            bytes.extend_from_slice(&(self.pending.len() as u16).to_be_bytes());
            for ((peer, id), ack) in &self.pending {
                bytes.extend_from_slice(peer);
                bytes.extend_from_slice(id);
                bytes.extend_from_slice(&ack.expires.to_be_bytes());
                bytes.push(u8::from(ack.share_presence));
            }
        }
        bytes
    }

    #[cfg(feature = "client-persist")]
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, String> {
        fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], String> {
            let value = bytes.get(..N).ok_or("truncated GC/2 receipt history")?;
            let result = value.try_into().unwrap();
            *bytes = &bytes[N..];
            Ok(result)
        }
        if bytes.len() > MAX_ENCODED {
            return Err("oversized GC/2 receipt history".into());
        }
        let mut remaining = bytes;
        let deferred = match &take::<5>(&mut remaining)? {
            b"GC2R1" => false,
            b"GC2R2" => true,
            _ => return Err("invalid GC/2 receipt version".into()),
        };
        let mut ledger = Self {
            clock_floor: u64::from_be_bytes(take(&mut remaining)?),
            ..Self::default()
        };
        let count = usize::from(u16::from_be_bytes(take(&mut remaining)?));
        if count > MAX_RECEIPTS {
            return Err("oversized GC/2 receipt history".into());
        }
        let mut counts = BTreeMap::<[u8; 32], usize>::new();
        for _ in 0..count {
            let peer = take(&mut remaining)?;
            let id = take(&mut remaining)?;
            let receipt = Receipt {
                hash: take(&mut remaining)?,
                horizon: u64::from_be_bytes(take(&mut remaining)?),
                ack: Some((
                    take(&mut remaining)?,
                    u64::from_be_bytes(take(&mut remaining)?),
                )),
            };
            let mut receipt = receipt;
            if deferred && receipt.ack == Some(([0; 16], 0)) {
                receipt.ack = None;
            }
            let count = counts.entry(peer).or_default();
            *count += 1;
            if *count > MAX_PER_PEER
                || receipt.horizon == 0
                || receipt
                    .ack
                    .is_some_and(|(tag, counter)| tag == [0; 16] || counter == 0)
                || ledger.entries.insert((peer, id), receipt).is_some()
            {
                return Err("invalid GC/2 receipt history".into());
            }
        }
        let count = usize::from(u16::from_be_bytes(take(&mut remaining)?));
        if count > MAX_LEGACY {
            return Err("oversized GC/2 legacy receipt history".into());
        }
        for _ in 0..count {
            let peer = take(&mut remaining)?;
            let tag = take(&mut remaining)?;
            let counter = u64::from_be_bytes(take(&mut remaining)?);
            if tag == [0; 16]
                || counter == 0
                || ledger.legacy.insert(peer, (tag, counter)).is_some()
            {
                return Err("invalid GC/2 legacy receipt history".into());
            }
        }
        if deferred {
            let count = usize::from(u16::from_be_bytes(take(&mut remaining)?));
            if count > MAX_PENDING_ACKS {
                return Err("oversized GC/2 deferred ACK history".into());
            }
            let mut counts = BTreeMap::<[u8; 32], usize>::new();
            for _ in 0..count {
                let key: Key = (take(&mut remaining)?, take(&mut remaining)?);
                let expires = u64::from_be_bytes(take(&mut remaining)?);
                let share_presence = match take::<1>(&mut remaining)? {
                    [0] => false,
                    [1] => true,
                    _ => return Err("invalid GC/2 deferred presence flag".into()),
                };
                let count = counts.entry(key.0).or_default();
                *count += 1;
                if expires == 0
                    || *count > MAX_PER_PEER
                    || ledger
                        .pending
                        .insert(
                            key,
                            PendingAck {
                                expires,
                                share_presence,
                            },
                        )
                        .is_some()
                {
                    return Err("invalid GC/2 deferred ACK history".into());
                }
            }
        }
        if ledger.entries.iter().any(|(key, receipt)| {
            receipt.ack.is_none()
                && !ledger
                    .pending
                    .get(key)
                    .is_some_and(|ack| ack.expires == receipt.horizon)
        }) {
            return Err("GC/2 receipt has no durable ACK obligation".into());
        }
        if !remaining.is_empty() || ledger.encode_version(deferred) != bytes {
            return Err("noncanonical GC/2 receipt history".into());
        }
        Ok(ledger)
    }
}

#[cfg(all(test, feature = "client-persist"))]
mod tests {
    use super::*;

    #[test]
    fn deferred_ack_bounds_restart_rollback_and_historical_archive() {
        let mut ledger = Ledger::default();
        let empty = ledger.encode();
        let undo = ledger
            .stage_deferred_ack(b"peer", [1; 16], Some(([2; 32], 100)), true, 1)
            .unwrap();
        assert_eq!(Ledger::decode(&ledger.encode()).unwrap(), ledger);
        let saved = ledger.encode();
        ledger.rollback(undo);
        assert_eq!(ledger.encode(), empty);
        ledger = Ledger::decode(&saved).unwrap();
        assert!(ledger.check(b"peer", [1; 16], [2; 32], 100, 2).unwrap());
        let undo = ledger.stage_prepared_ack((peer_key(b"peer"), [1; 16]), ([3; 16], 1), 2);
        assert!(ledger.pending_acks(2).is_empty());
        ledger.rollback(undo);
        assert_eq!(ledger.encode(), saved);
        let window = Window::new([3; 16]).unwrap();
        ledger.stage_credit(b"peer", &window, 2);
        assert_eq!(
            ledger.len(),
            1,
            "no credit for an ACK that has not been prepared"
        );
        // A missing obligation, forged boolean, truncation or version relabel
        // cannot turn a pending receipt into a delivered acknowledgment.
        let mut missing = saved.clone();
        missing.truncate(missing.len() - 57);
        let len = missing.len();
        missing[len - 2..].copy_from_slice(&[0, 0]);
        assert!(Ledger::decode(&missing).is_err());
        let mut invalid = saved.clone();
        *invalid.last_mut().unwrap() = 2;
        assert!(Ledger::decode(&invalid).is_err());
        let mut old = saved.clone();
        old[..5].copy_from_slice(b"GC2R1");
        assert!(Ledger::decode(&old).is_err());
        ledger.stage_prepared_ack((peer_key(b"peer"), [1; 16]), ([3; 16], 1), 2);
        let old = ledger.encode_version(false);
        assert_eq!(Ledger::decode(&old).unwrap(), ledger);
        let mut ledger = Ledger::default();
        for peer in 0..8u8 {
            for id in 0..128u8 {
                ledger
                    .stage_deferred_ack(&[peer], [id; 16], None, false, 1)
                    .unwrap();
            }
        }
        let full = ledger.encode();
        assert_eq!(ledger.pending_acks(1).len(), MAX_PENDING_ACKS);
        assert!(full.len() <= MAX_ENCODED);
        assert_eq!(Ledger::decode(&full).unwrap(), ledger);
        assert!(ledger
            .stage_deferred_ack(b"other", [0; 16], None, false, 1)
            .unwrap_err()
            .contains("capacity"));
        assert!(ledger
            .stage_deferred_ack(&[0], [255; 16], None, false, 1)
            .unwrap_err()
            .contains("capacity"));
        assert_eq!(ledger.encode(), full);
        // Expiry can reclaim capacity; rolling back the checkpoint restores it.
        let undo = ledger
            .stage_deferred_ack(b"other", [0; 16], None, false, 601)
            .unwrap();
        assert_eq!(ledger.pending_acks(601).len(), 1);
        ledger.rollback(undo);
        assert_eq!(ledger.encode(), full);
    }

    #[test]
    fn bounded_history_conflicts_expiry_clock_rollback_and_transaction_rollback() {
        let mut ledger = Ledger::default();
        for id in 0..MAX_PER_PEER {
            let mut key = [0; 16];
            key[..8].copy_from_slice(&(id as u64).to_be_bytes());
            ledger
                .stage_data(b"peer", key, [3; 32], 100, ([4; 16], 1), 10)
                .unwrap();
        }
        assert!(ledger
            .check(b"peer", [255; 16], [3; 32], 100, 10)
            .unwrap_err()
            .contains("capacity"));
        assert!(ledger.check(b"peer", [0; 16], [3; 32], 100, 10).unwrap());
        assert!(ledger
            .check(b"peer", [0; 16], [2; 32], 100, 10)
            .unwrap_err()
            .contains("conflict"));
        let before = ledger.encode();
        let undo = ledger
            .stage_data(b"peer", [255; 16], [3; 32], 200, ([4; 16], 2), 100)
            .unwrap();
        assert_eq!(ledger.len(), 1);
        ledger.rollback(undo);
        assert_eq!(ledger.encode(), before);
        ledger
            .stage_data(b"peer", [255; 16], [3; 32], 200, ([4; 16], 2), 100)
            .unwrap();
        let restored = Ledger::decode(&ledger.encode()).unwrap();
        assert!(restored
            .check(b"peer", [0; 16], [3; 32], 100, 20)
            .unwrap_err()
            .contains("expired"));
        assert_eq!(restored, ledger);
    }

    #[test]
    fn total_capacity_and_canonical_archive_bounds() {
        let mut ledger = Ledger::default();
        for peer in 0..16u8 {
            for id in 0..128u8 {
                ledger
                    .stage_data(&[peer], [id; 16], [1; 32], 100, ([2; 16], 3), 1)
                    .unwrap();
            }
        }
        assert_eq!(ledger.len(), MAX_RECEIPTS);
        assert!(ledger
            .check(b"extra peer", [0; 16], [1; 32], 100, 1)
            .unwrap_err()
            .contains("capacity"));
        let bytes = ledger.encode();
        assert!(bytes.len() < MAX_ENCODED);
        assert_eq!(Ledger::decode(&bytes).unwrap(), ledger);
        for size in [0, 4, 13, 14, bytes.len() - 1] {
            assert!(Ledger::decode(&bytes[..size]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Ledger::decode(&trailing).is_err());
        let mut reordered = bytes.clone();
        reordered[15..127].copy_from_slice(&bytes[127..239]);
        reordered[127..239].copy_from_slice(&bytes[15..127]);
        assert!(Ledger::decode(&reordered).is_err());
        let mut duplicate = bytes.clone();
        duplicate[127..239].copy_from_slice(&bytes[15..127]);
        assert!(Ledger::decode(&duplicate).is_err());
    }
}
