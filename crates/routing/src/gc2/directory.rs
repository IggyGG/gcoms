//! Explicit private GC/2 introductions. Stale descriptors retain only re-entry
//! authority; fresh entry/transit credentials are never manufactured locally.
mod storage;
use super::{entry::EntryDescriptor, transit::TransitDescriptor};
use crate::{
    wire::{decode_address, encode_address},
    Result,
};
use std::{
    fmt,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};
use zeroize::{Zeroize, Zeroizing};

pub const INTRODUCTION_BYTES: usize = 155;
pub const MAX_INTRODUCTIONS: usize = 8;
pub const MAX_BUNDLE_BYTES: usize = 6 + MAX_INTRODUCTIONS * INTRODUCTION_BYTES;
pub const MAX_RELAYS: usize = 64;
pub const MAX_GUARDS: usize = 3;
pub const MAX_OWN_SERVICES: usize = 8;
pub const MAX_PRIVATE_BYTES: usize =
    8 + MAX_RELAYS * INTRODUCTION_BYTES + MAX_GUARDS * 32 + MAX_OWN_SERVICES * 51;
pub const MAX_ADVERTISEMENT_AGE: u64 = 24 * 60 * 60;

#[derive(Clone, PartialEq, Eq)]
pub struct Introduction {
    pub addr: SocketAddr,
    pub service_id: [u8; 32],
    pub reentry_cap: [u8; 32],
    pub entry_cap: [u8; 32],
    pub transit_cap: [u8; 32],
    pub expires_at: u64,
}
impl fmt::Debug for Introduction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gc2Introduction")
            .field("addr", &self.addr)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl Drop for Introduction {
    fn drop(&mut self) {
        self.reentry_cap.zeroize();
        self.entry_cap.zeroize();
        self.transit_cap.zeroize();
    }
}
impl Introduction {
    pub fn validate(&self) -> Result<()> {
        decode_address(&encode_address(self.addr))?;
        if self.service_id == [0; 32]
            || self.reentry_cap == [0; 32]
            || self.entry_cap == [0; 32]
            || self.transit_cap == [0; 32]
            || self.reentry_cap == self.entry_cap
            || self.reentry_cap == self.transit_cap
            || self.entry_cap == self.transit_cap
            || self.expires_at == 0
        {
            return Err("incomplete or overlapping GC/2 relay authorities".into());
        }
        Ok(())
    }
    pub fn conflicts(&self, addr: SocketAddr, pin: [u8; 32]) -> bool {
        self.addr.ip() == addr.ip() || self.service_id == pin
    }
    fn fresh(&self, now: u64) -> Result<()> {
        self.validate()?;
        if self.expires_at <= now || self.expires_at.saturating_sub(now) > MAX_ADVERTISEMENT_AGE {
            return Err("GC/2 relay advertisement outside freshness window".into());
        }
        Ok(())
    }
    pub fn entry(&self, now: u64) -> Result<EntryDescriptor> {
        self.fresh(now)?;
        Ok(EntryDescriptor {
            addr: self.addr,
            service_id: self.service_id,
            entry_cap: self.entry_cap,
            expires_at: self.expires_at,
        })
    }
    pub fn transit(&self, now: u64) -> Result<TransitDescriptor> {
        self.fresh(now)?;
        Ok(TransitDescriptor {
            addr: self.addr,
            service_id: self.service_id,
            transit_cap: self.transit_cap,
            expires_at: self.expires_at,
        })
    }
    pub fn encode(&self) -> Result<Zeroizing<[u8; INTRODUCTION_BYTES]>> {
        self.validate()?;
        let mut bytes = Zeroizing::new([0; INTRODUCTION_BYTES]);
        bytes[..19].copy_from_slice(&encode_address(self.addr));
        bytes[19..51].copy_from_slice(&self.service_id);
        bytes[51..83].copy_from_slice(&self.reentry_cap);
        bytes[83..115].copy_from_slice(&self.entry_cap);
        bytes[115..147].copy_from_slice(&self.transit_cap);
        bytes[147..].copy_from_slice(&self.expires_at.to_be_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != INTRODUCTION_BYTES {
            return Err("invalid GC/2 introduction length".into());
        }
        let value = Self {
            addr: decode_address(&bytes[..19])?,
            service_id: bytes[19..51].try_into()?,
            reentry_cap: bytes[51..83].try_into()?,
            entry_cap: bytes[83..115].try_into()?,
            transit_cap: bytes[115..147].try_into()?,
            expires_at: u64::from_be_bytes(bytes[147..].try_into()?),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct BootstrapBundle {
    pub relays: Vec<Introduction>,
}
impl BootstrapBundle {
    pub fn validate(&self) -> Result<()> {
        if self.relays.is_empty() || self.relays.len() > MAX_INTRODUCTIONS {
            return Err("GC/2 bootstrap bundle exceeds bounds".into());
        }
        for (index, relay) in self.relays.iter().enumerate() {
            relay.validate()?;
            if self.relays[..index]
                .iter()
                .any(|old| old.service_id == relay.service_id)
            {
                return Err("duplicate GC/2 bootstrap service".into());
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = Zeroizing::new(b"GCRB\x02".to_vec());
        bytes.push(self.relays.len() as u8);
        for relay in &self.relays {
            bytes.extend_from_slice(relay.encode()?.as_ref());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if !(6..=MAX_BUNDLE_BYTES).contains(&bytes.len()) || &bytes[..5] != b"GCRB\x02" {
            return Err("GC/2 routing bootstrap required".into());
        }
        let count = bytes[5] as usize;
        if count == 0 || count > MAX_INTRODUCTIONS || bytes.len() != 6 + count * INTRODUCTION_BYTES
        {
            return Err("GC/2 bootstrap bundle exceeds bounds".into());
        }
        let relays = bytes[6..]
            .as_chunks::<INTRODUCTION_BYTES>()
            .0
            .iter()
            .map(|record| Introduction::decode(record))
            .collect::<Result<Vec<_>>>()?;
        let bundle = Self { relays };
        bundle.validate()?;
        Ok(bundle)
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct View {
    relays: Vec<Introduction>,
    guards: Vec<[u8; 32]>,
    own: Vec<(SocketAddr, [u8; 32])>,
}
type AddressPolicy = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;
/// Durably save the complete private view before making it available to routing.
/// Called under the directory write lock; must not reenter the directory.
pub type Checkpoint = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// Bounded private metadata, separate from GC/1's directory. Installing a
/// descriptor never opens a connection or changes its authenticated expiry.
pub struct Directory {
    view: RwLock<View>,
    allowed: AddressPolicy,
    checkpoint: Option<Checkpoint>,
    persistence_failed: AtomicBool,
}
impl Default for Directory {
    fn default() -> Self {
        Self::new()
    }
}
impl Directory {
    pub fn new() -> Self {
        Self::with_address_policy(Arc::new(|addr| crate::service::public_ip(addr.ip())))
    }
    pub fn for_loopback_fixture() -> Self {
        Self::with_address_policy(Arc::new(|addr| addr.ip().is_loopback()))
    }
    pub(crate) fn with_address_policy(allowed: AddressPolicy) -> Self {
        Self {
            view: RwLock::new(View::default()),
            allowed,
            checkpoint: None,
            persistence_failed: AtomicBool::new(false),
        }
    }
    /// Installs persistence before the directory is shared with a connection
    /// owner. Failure leaves no directory available for new connections.
    pub fn with_checkpoint(mut self, checkpoint: Checkpoint) -> Result<Self> {
        checkpoint(&self.encode_private()?)?;
        self.checkpoint = Some(checkpoint);
        Ok(self)
    }
    fn commit(&self, current: &mut View, next: View) -> Result<()> {
        self.check_persistence()?;
        if *current != next {
            if let Some(checkpoint) = &self.checkpoint {
                if let Err(error) = checkpoint(&next.encode()?) {
                    // Atomic replacement may have succeeded before directory
                    // fsync failed. Neither view is safe to use or overwrite
                    // until the authenticated checkpoint is reloaded.
                    self.persistence_failed.store(true, Ordering::Release);
                    return Err(error);
                }
            }
            *current = next;
        }
        Ok(())
    }
    pub fn check_persistence(&self) -> Result<()> {
        if self.persistence_failed.load(Ordering::Acquire) {
            return Err("GC/2 directory checkpoint failed; authenticated reload required".into());
        }
        Ok(())
    }
    fn admissible(&self, relay: &Introduction, now: u64) -> Result<()> {
        relay.validate()?;
        if !(self.allowed)(relay.addr)
            || relay.expires_at.saturating_sub(now) > MAX_ADVERTISEMENT_AGE
        {
            return Err("GC/2 introduction violates address or freshness policy".into());
        }
        Ok(())
    }
    pub fn set_own_services(&self, services: Vec<(SocketAddr, [u8; 32])>) -> Result<()> {
        if services.len() > MAX_OWN_SERVICES {
            return Err("too many own GC/2 services".into());
        }
        for (index, (addr, pin)) in services.iter().enumerate() {
            decode_address(&encode_address(*addr))?;
            if *pin == [0; 32] || services[..index].contains(&(*addr, *pin)) {
                return Err("invalid own GC/2 service identity".into());
            }
        }
        let mut view = self.view.write().unwrap_or_else(|p| p.into_inner());
        let mut next = view.clone();
        next.own = services;
        Self::prune_guards(&mut next);
        self.commit(&mut view, next)
    }
    pub fn set_guards(&self, guards: Vec<[u8; 32]>) -> Result<()> {
        if guards.len() > MAX_GUARDS {
            return Err("too many GC/2 guards".into());
        }
        let mut view = self.view.write().unwrap_or_else(|p| p.into_inner());
        Self::validate_guards(&view, &guards)?;
        let mut next = view.clone();
        next.guards = guards;
        self.commit(&mut view, next)
    }
    fn validate_guards(view: &View, guards: &[[u8; 32]]) -> Result<()> {
        let mut selected: Vec<&Introduction> = Vec::new();
        for pin in guards {
            let relay = view
                .relays
                .iter()
                .find(|r| &r.service_id == pin)
                .ok_or("unknown GC/2 guard")?;
            if selected
                .iter()
                .any(|old| old.conflicts(relay.addr, relay.service_id))
                || view
                    .own
                    .iter()
                    .any(|(addr, pin)| relay.conflicts(*addr, *pin))
            {
                return Err("GC/2 guard overlaps another guard or own service".into());
            }
            selected.push(relay);
        }
        Ok(())
    }
    /// Atomically retain one known independent guard. Full, duplicate or
    /// overlapping candidates return false; persistence failures return errors.
    pub fn retain_guard(&self, pin: [u8; 32]) -> Result<bool> {
        let mut view = self.view.write().unwrap_or_else(|p| p.into_inner());
        self.check_persistence()?;
        if !view.relays.iter().any(|relay| relay.service_id == pin) {
            return Err("unknown GC/2 guard".into());
        }
        if view.guards.len() == MAX_GUARDS || view.guards.contains(&pin) {
            return Ok(false);
        }
        let mut next = view.clone();
        next.guards.push(pin);
        if Self::validate_guards(&next, &next.guards).is_err() {
            return Ok(false);
        }
        self.commit(&mut view, next)?;
        Ok(true)
    }
    pub fn guards(&self) -> Vec<[u8; 32]> {
        let view = self.view.read().unwrap_or_else(|p| p.into_inner());
        if self.check_persistence().is_err() {
            return Vec::new();
        }
        view.guards.clone()
    }
    /// Validates the complete bundle before changing the view. Expired entries
    /// remain re-entry seeds only; an older reply cannot replace newer authority.
    pub fn remember(&self, bundle: &BootstrapBundle, now: u64) -> Result<usize> {
        bundle.validate()?;
        for relay in &bundle.relays {
            self.admissible(relay, now)?;
        }
        let mut view = self.view.write().unwrap_or_else(|p| p.into_inner());
        for relay in &bundle.relays {
            if view.relays.iter().any(|old| {
                old.service_id == relay.service_id && old.reentry_cap != relay.reentry_cap
            }) {
                return Err(
                    "GC/2 stable re-entry authority requires explicit bootstrap migration".into(),
                );
            }
        }
        let mut next = view.clone();
        let mut fresh = 0;
        for relay in &bundle.relays {
            if let Some(index) = next
                .relays
                .iter()
                .position(|old| old.service_id == relay.service_id)
            {
                if next.relays[index].expires_at > relay.expires_at {
                    continue;
                }
                next.relays[index] = relay.clone();
            } else {
                if next.relays.len() == MAX_RELAYS {
                    let victim = next
                        .relays
                        .iter()
                        .enumerate()
                        .filter(|(_, old)| !next.guards.contains(&old.service_id))
                        .min_by_key(|(_, old)| old.expires_at)
                        .map(|(index, _)| index)
                        .expect("at most three of sixty-four entries are guards");
                    next.relays.remove(victim);
                }
                next.relays.push(relay.clone());
            }
            if relay.expires_at > now {
                fresh += 1;
            }
        }
        Self::prune_guards(&mut next);
        self.commit(&mut view, next)?;
        Ok(fresh)
    }
    pub fn eligible(
        &self,
        excluded: &[(SocketAddr, [u8; 32])],
        now: u64,
    ) -> Result<Vec<Introduction>> {
        if excluded.len() > 64 {
            return Err("too many GC/2 route exclusions".into());
        }
        let view = self.view.read().unwrap_or_else(|p| p.into_inner());
        self.check_persistence()?;
        Ok(view
            .relays
            .iter()
            .filter(|relay| {
                relay.fresh(now).is_ok()
                    && (self.allowed)(relay.addr)
                    && !view
                        .own
                        .iter()
                        .chain(excluded)
                        .any(|(addr, pin)| relay.conflicts(*addr, *pin))
            })
            .cloned()
            .collect())
    }
    /// Retained guards are tried first. The background discovery owner applies
    /// retry timing; a data request must not cause direct re-entry.
    pub fn reentry_candidates(&self) -> Vec<Introduction> {
        let view = self.view.read().unwrap_or_else(|p| p.into_inner());
        if self.check_persistence().is_err() {
            return Vec::new();
        }
        let mut relays: Vec<_> = view
            .relays
            .iter()
            .filter(|relay| {
                (self.allowed)(relay.addr)
                    && !view
                        .own
                        .iter()
                        .any(|(addr, pin)| relay.conflicts(*addr, *pin))
            })
            .cloned()
            .collect();
        relays.sort_by_key(|relay| {
            view.guards
                .iter()
                .position(|pin| *pin == relay.service_id)
                .unwrap_or(MAX_GUARDS)
        });
        relays.truncate(MAX_INTRODUCTIONS);
        relays
    }

    fn prune_guards(view: &mut View) {
        // An authenticated address update can make two previously independent
        // guards share an IP. Keep the first retained guard and reselect the
        // other only through the background connection owner's policy.
        let old = std::mem::take(&mut view.guards);
        for pin in old {
            let Some(relay) = view.relays.iter().find(|relay| relay.service_id == pin) else {
                continue;
            };
            if view
                .own
                .iter()
                .any(|(addr, pin)| relay.conflicts(*addr, *pin))
                || view.guards.iter().any(|pin| {
                    view.relays
                        .iter()
                        .find(|relay| relay.service_id == *pin)
                        .is_some_and(|prior| prior.conflicts(relay.addr, relay.service_id))
                })
            {
                continue;
            }
            view.guards.push(pin);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_000_000;
    fn relay(seed: u8) -> Introduction {
        Introduction {
            addr: format!("127.0.0.{seed}:443").parse().unwrap(),
            service_id: [seed; 32],
            reentry_cap: [201; 32],
            entry_cap: [202; 32],
            transit_cap: [203; 32],
            expires_at: NOW + 100,
        }
    }
    fn remember(directory: &Directory, relay: Introduction) {
        directory
            .remember(
                &BootstrapBundle {
                    relays: vec![relay],
                },
                NOW,
            )
            .unwrap();
    }
    fn restore(bytes: &[u8], now: u64) -> Result<Directory> {
        Directory::restore_with_policy(bytes, now, Arc::new(|addr| addr.ip().is_loopback()))
    }
    #[test]
    fn private_restart_keeps_stale_guards_exclusions_and_exact_authority() {
        let directory = Directory::for_loopback_fixture();
        for seed in 1..=64 {
            remember(&directory, relay(seed));
        }
        directory
            .set_guards(vec![[3; 32], [2; 32], [1; 32]])
            .unwrap();
        directory
            .set_own_services((100..108).map(|n| (relay(n).addr, [n; 32])).collect())
            .unwrap();
        let bytes = directory.encode_private().unwrap();
        assert_eq!(bytes.len(), MAX_PRIVATE_BYTES);
        let restored = restore(&bytes, NOW + 101).unwrap();
        assert_eq!(restored.encode_private().unwrap(), bytes);
        assert_eq!(restored.guards(), vec![[3; 32], [2; 32], [1; 32]]);
        assert!(restored.eligible(&[], NOW + 101).unwrap().is_empty());
        assert_eq!(restored.reentry_candidates()[0].reentry_cap, [201; 32]);
        assert!(restored.reentry_candidates()[0].entry(NOW + 101).is_err());
        assert!(Directory::restore_private(&bytes, NOW).is_err()); // loopback isn't production
        assert!(restore(&bytes, 0).is_err()); // no lifetime expansion on clock rollback
        assert_eq!(
            restore(&bytes, u64::MAX).unwrap().encode_private().unwrap(),
            bytes
        );
    }
    #[test]
    fn private_decoder_rejects_truncation_duplicate_records_and_invalid_guards() {
        let directory = Directory::for_loopback_fixture();
        remember(&directory, relay(1));
        remember(&directory, relay(2));
        directory.set_guards(vec![[1; 32], [2; 32]]).unwrap();
        directory
            .set_own_services(vec![(relay(3).addr, [3; 32])])
            .unwrap();
        let bytes = directory.encode_private().unwrap();
        for length in 0..bytes.len() {
            assert!(restore(&bytes[..length], NOW).is_err(), "{length}");
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(restore(&trailing, NOW).is_err());
        let guard_count = 6 + 2 * INTRODUCTION_BYTES;
        let own_count = guard_count + 1 + 64;
        for (offset, value) in [(4, 1), (5, 65), (guard_count, 4), (own_count, 9)] {
            let mut bad = bytes.to_vec();
            bad[offset] = value;
            assert!(restore(&bad, NOW).is_err());
        }
        let mut bad = bytes.to_vec();
        bad.copy_within(6..6 + INTRODUCTION_BYTES, 6 + INTRODUCTION_BYTES);
        assert!(restore(&bad, NOW).is_err());
        for pin in [[1; 32], [99; 32]] {
            let mut bad = bytes.to_vec();
            bad[guard_count + 33..guard_count + 65].copy_from_slice(&pin);
            assert!(restore(&bad, NOW).is_err());
        }
        let mut bad = bytes.to_vec();
        bad[own_count + 1..own_count + 20].copy_from_slice(&encode_address(relay(1).addr));
        assert!(restore(&bad, NOW).is_err()); // own-IP overlap with a retained guard
        let mut bad = bytes.to_vec();
        bad[own_count + 20..own_count + 52].fill(0);
        assert!(restore(&bad, NOW).is_err());
    }
    #[test]
    fn checkpoint_failure_never_publishes_new_authority_or_guard_changes() {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        };
        let fail = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let saved = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
        let sink = saved.clone();
        let reject = fail.clone();
        let count = writes.clone();
        let directory = Directory::for_loopback_fixture()
            .with_checkpoint(Arc::new(move |bytes| {
                if reject.load(Ordering::SeqCst) {
                    return Err("fixture disk unavailable".into());
                }
                restore(bytes, NOW)?;
                *sink.lock().unwrap() = Zeroizing::new(bytes.to_vec());
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }))
            .unwrap();
        remember(&directory, relay(1));
        remember(&directory, relay(2));
        assert!(directory.retain_guard([1; 32]).unwrap());
        let before = directory.encode_private().unwrap();
        let count = writes.load(Ordering::SeqCst);
        fail.store(true, Ordering::SeqCst);
        assert!(directory.retain_guard([2; 32]).is_err());
        assert!(directory.set_guards(vec![[2; 32]]).is_err());
        assert!(directory
            .set_own_services(vec![(relay(1).addr, [99; 32])])
            .is_err());
        let mut renewed = relay(1);
        renewed.expires_at += 100;
        renewed.entry_cap = [204; 32];
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![renewed]
                },
                NOW
            )
            .is_err());
        assert!(directory.encode_private().is_err());
        assert_eq!(*saved.lock().unwrap(), before);
        // Even unchanged state is unsafe after an ambiguous checkpoint error.
        assert!(directory.set_guards(vec![[1; 32]]).is_err());
        assert!(directory.retain_guard([1; 32]).is_err());
        assert!(directory.eligible(&[], NOW).is_err());
        assert!(directory.guards().is_empty());
        assert!(directory.reentry_candidates().is_empty());
        assert_eq!(writes.load(Ordering::SeqCst), count);
        fail.store(false, Ordering::SeqCst);
        assert!(directory.retain_guard([2; 32]).is_err());
        let restarted = restore(&saved.lock().unwrap(), NOW).unwrap();
        assert_eq!(restarted.guards(), vec![[1; 32]]);
        assert!(restarted.retain_guard([2; 32]).unwrap());
        assert!(Directory::for_loopback_fixture()
            .with_checkpoint(Arc::new(|_| Err("disk failed".into())))
            .is_err());
    }
    #[test]
    fn checkpoint_written_then_error_requires_reload_of_new_authority() {
        use std::sync::Mutex;
        let fail = Arc::new(AtomicBool::new(false));
        let saved = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
        let sink = saved.clone();
        let reject = fail.clone();
        let directory = Directory::for_loopback_fixture()
            .with_checkpoint(Arc::new(move |bytes| {
                *sink.lock().unwrap() = Zeroizing::new(bytes.to_vec());
                if reject.load(Ordering::SeqCst) {
                    return Err("fixture rename succeeded but directory fsync failed".into());
                }
                Ok(())
            }))
            .unwrap();
        remember(&directory, relay(1));
        directory.retain_guard([1; 32]).unwrap();
        let mut renewed = relay(1);
        renewed.entry_cap = [204; 32];
        renewed.expires_at += 100;
        fail.store(true, Ordering::SeqCst);
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![renewed.clone()]
                },
                NOW
            )
            .is_err());
        let on_disk = saved.lock().unwrap().clone();
        fail.store(false, Ordering::SeqCst);
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![relay(1)]
                },
                NOW
            )
            .is_err());
        assert!(directory.retain_guard([1; 32]).is_err());
        assert!(directory.eligible(&[], NOW).is_err());
        assert!(directory.encode_private().is_err());
        assert_eq!(*saved.lock().unwrap(), on_disk);
        let restarted = restore(&on_disk, NOW).unwrap();
        assert_eq!(restarted.guards(), vec![[1; 32]]);
        assert_eq!(restarted.eligible(&[], NOW).unwrap(), vec![renewed]);
    }
    #[test]
    fn bundle_is_bounded_canonical_and_version_separated() {
        let bundle = BootstrapBundle {
            relays: (1..=8).map(relay).collect(),
        };
        let bytes = bundle.encode().unwrap();
        assert_eq!(bytes.len(), MAX_BUNDLE_BYTES);
        assert_eq!(
            BootstrapBundle::decode(&bytes).unwrap().encode().unwrap(),
            bytes
        );
        assert!(BootstrapBundle::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(BootstrapBundle::decode(&trailing).is_err());
        let mut wrong = bytes.to_vec();
        wrong[4] = 1;
        assert!(BootstrapBundle::decode(&wrong).is_err());
        wrong = bytes.to_vec();
        wrong[5] = 0;
        assert!(BootstrapBundle::decode(&wrong).is_err());
        assert!(BootstrapBundle {
            relays: vec![relay(1), relay(1)]
        }
        .encode()
        .is_err());
        assert!(BootstrapBundle {
            relays: (1..=9).map(relay).collect()
        }
        .encode()
        .is_err());
        let mut value = relay(1);
        value.entry_cap = value.reentry_cap;
        assert!(value.encode().is_err());
        value = relay(1);
        value.transit_cap = [0; 32];
        assert!(value.encode().is_err());
        let private = relay(1);
        assert!(!format!("{private:?}").contains("201"));
        assert_eq!(private.encode().unwrap().len(), INTRODUCTION_BYTES);
    }
    #[test]
    fn expiry_preserves_reentry_without_reviving_circuit_authority() {
        let directory = Directory::for_loopback_fixture();
        let mut stale = relay(1);
        stale.expires_at = NOW;
        assert!(stale.entry(NOW).is_err());
        assert!(stale.transit(NOW).is_err());
        assert_eq!(
            directory
                .remember(
                    &BootstrapBundle {
                        relays: vec![stale]
                    },
                    NOW
                )
                .unwrap(),
            0
        );
        assert!(directory.eligible(&[], NOW).unwrap().is_empty());
        let seed = &directory.reentry_candidates()[0];
        assert_eq!(seed.expires_at, NOW);
        assert_eq!(seed.reentry_cap, [201; 32]);
        let mut fresh = relay(1);
        fresh.expires_at = NOW + 200;
        fresh.entry_cap = [211; 32];
        remember(&directory, fresh);
        remember(&directory, relay(1));
        let current = &directory.eligible(&[], NOW).unwrap()[0];
        assert_eq!(current.entry_cap, [211; 32]);
        assert_eq!(current.entry(NOW).unwrap().expires_at, NOW + 200);
        assert_eq!(current.transit(NOW).unwrap().expires_at, NOW + 200);
    }
    #[test]
    fn referral_authority_change_requires_explicit_migration() {
        let directory = Directory::for_loopback_fixture();
        remember(&directory, relay(1));
        directory.set_guards(vec![[1; 32]]).unwrap();
        let mut replaced = relay(1);
        replaced.reentry_cap = [211; 32];
        replaced.expires_at = NOW + 200;
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![relay(2), replaced]
                },
                NOW
            )
            .is_err());
        assert_eq!(directory.eligible(&[], NOW).unwrap().len(), 1);
        assert_eq!(directory.reentry_candidates()[0].reentry_cap, [201; 32]);
        assert_eq!(directory.guards(), vec![[1; 32]]);
    }
    #[test]
    fn complete_bundle_is_validated_before_directory_mutation() {
        let directory = Directory::new();
        let mut public = relay(1);
        public.addr = "8.8.8.1:443".parse().unwrap();
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![public, relay(2)]
                },
                NOW
            )
            .is_err());
        assert!(directory.reentry_candidates().is_empty());
        let directory = Directory::for_loopback_fixture();
        let mut far = relay(2);
        far.expires_at = NOW + MAX_ADVERTISEMENT_AGE + 1;
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![relay(1), far]
                },
                NOW
            )
            .is_err());
        assert!(directory.reentry_candidates().is_empty());
    }
    #[test]
    fn capacity_preserves_guards_and_excludes_owned_and_terminal_services() {
        let directory = Directory::for_loopback_fixture();
        for seed in 1..=3 {
            remember(&directory, relay(seed));
        }
        directory
            .set_guards(vec![[1; 32], [2; 32], [3; 32]])
            .unwrap();
        for seed in 4..=100 {
            remember(&directory, relay(seed));
        }
        let eligible = directory.eligible(&[], NOW).unwrap();
        assert_eq!(eligible.len(), MAX_RELAYS);
        assert!((1..=3).all(|seed| eligible.iter().any(|relay| relay.service_id == [seed; 32])));
        assert_eq!(directory.reentry_candidates().len(), MAX_INTRODUCTIONS);
        assert_eq!(directory.reentry_candidates()[0].service_id, [1; 32]);
        directory
            .set_own_services(vec![(relay(1).addr, [99; 32])])
            .unwrap();
        assert_eq!(directory.guards(), vec![[2; 32], [3; 32]]);
        let excluded = [
            (relay(2).addr, [98; 32]),
            ("127.0.0.120:443".parse().unwrap(), [3; 32]),
        ];
        assert!(directory
            .eligible(&excluded, NOW)
            .unwrap()
            .iter()
            .all(|r| r.addr.ip() != relay(1).addr.ip()
                && r.service_id != [2; 32]
                && r.service_id != [3; 32]
                && r.service_id != [99; 32]));
        assert!(directory.eligible(&[excluded[0]; 65], NOW).is_err());
        assert!(directory.set_guards(vec![[1; 32]]).is_err());
    }
    #[test]
    fn address_updates_cannot_turn_retained_guards_into_one_hop() {
        let directory = Directory::for_loopback_fixture();
        remember(&directory, relay(1));
        remember(&directory, relay(2));
        directory.set_guards(vec![[1; 32], [2; 32]]).unwrap();
        let mut moved = relay(2);
        moved.addr = relay(1).addr;
        remember(&directory, moved);
        assert_eq!(directory.guards(), vec![[1; 32]]);
        assert!(directory.set_guards(vec![[1; 32], [2; 32]]).is_err());
        assert_eq!(directory.guards(), vec![[1; 32]]);
    }
}
