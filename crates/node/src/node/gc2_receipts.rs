//! Bounded logical receipts across GC/2 session replacement. No message bodies.
use gcoms_protocol::flow::Window;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_RECEIPTS: usize = 2048;
const MAX_PER_PEER: usize = 128;
#[cfg(feature = "client-persist")]
const MAX_LEGACY: usize = 8192;
#[cfg(feature = "client-persist")]
pub(super) const MAX_ENCODED: usize = 5 + 8 + 2 + MAX_RECEIPTS * 112 + 2 + MAX_LEGACY * 56;
type Key = ([u8; 32], [u8; 16]);
type Barrier = ([u8; 16], u64);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Receipt {
    hash: [u8; 32],
    horizon: u64,
    ack: Barrier,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct Ledger {
    entries: BTreeMap<Key, Receipt>,
    legacy: BTreeMap<[u8; 32], Barrier>,
    // Expired effects cannot become live again after a wall-clock correction.
    clock_floor: u64,
}

pub(super) struct Undo {
    clock_floor: u64,
    inserted: Option<Key>,
    removed: Vec<(Key, Receipt)>,
    legacy: Option<([u8; 32], Barrier)>,
}

pub(super) fn peer_key(peer: &[u8]) -> [u8; 32] {
    Sha256::digest(peer).into()
}

/// Direct Data currently has a ten-minute logical lifetime. Its authenticated
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
        Undo {
            clock_floor: old_clock,
            inserted: None,
            removed,
            legacy: None,
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
        if let Some(old) = self.entries.insert(key, Receipt { hash, horizon, ack }) {
            undo.removed.push((key, old));
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
                k.0 == peer && &r.ack.0 == window.session() && window.is_credited(r.ack.1)
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
        self.clock_floor = undo.clock_floor;
        if let Some((peer, barrier)) = undo.legacy {
            self.legacy.insert(peer, barrier);
        }
    }

    pub(super) fn recovery_allowed(&self, peer: &[u8]) -> bool {
        !self.legacy.contains_key(&peer_key(peer))
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
        let mut bytes = b"GC2R1".to_vec();
        bytes.extend_from_slice(&self.clock_floor.to_be_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for ((peer, id), r) in &self.entries {
            bytes.extend_from_slice(peer);
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&r.hash);
            bytes.extend_from_slice(&r.horizon.to_be_bytes());
            bytes.extend_from_slice(&r.ack.0);
            bytes.extend_from_slice(&r.ack.1.to_be_bytes());
        }
        bytes.extend_from_slice(&(self.legacy.len() as u16).to_be_bytes());
        for (peer, (tag, counter)) in &self.legacy {
            bytes.extend_from_slice(peer);
            bytes.extend_from_slice(tag);
            bytes.extend_from_slice(&counter.to_be_bytes());
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
        if &take::<5>(&mut remaining)? != b"GC2R1" {
            return Err("invalid GC/2 receipt version".into());
        }
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
                ack: (
                    take(&mut remaining)?,
                    u64::from_be_bytes(take(&mut remaining)?),
                ),
            };
            let count = counts.entry(peer).or_default();
            *count += 1;
            if *count > MAX_PER_PEER
                || receipt.horizon == 0
                || receipt.ack.0 == [0; 16]
                || receipt.ack.1 == 0
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
        if !remaining.is_empty() || ledger.encode() != bytes {
            return Err("noncanonical GC/2 receipt history".into());
        }
        Ok(ledger)
    }
}

#[cfg(all(test, feature = "client-persist"))]
mod tests {
    use super::*;

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
