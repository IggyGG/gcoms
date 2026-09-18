//! Private GC/2 state is distinct from GC/1. The host owns encryption and atomic
//! durable replacement; a failed commit must never publish a new guard or cap.
use super::*;

pub const MAX_PRIVATE_BYTES: usize = 7 + MAX_RELAYS * INTRODUCTION_BYTES + MAX_GUARDS * 32;

/// Authenticated encrypted storage, committed before new state becomes visible.
/// The sink runs under the directory write lock and must not reenter it. It must
/// atomically replace complete snapshots and report success only after durability.
/// An error may mean either snapshot reached disk: this directory then refuses
/// further routing until the host reloads authenticated storage into a new one.
/// Plaintext must not be logged.
pub type PrivateStateSink = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

fn encode(view: &View) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(b"GCRD\x02".to_vec());
    bytes.push(view.relays.len() as u8);
    bytes.push(view.guards.len() as u8);
    for relay in &view.relays {
        bytes.extend_from_slice(relay.encode()?.as_ref());
    }
    for guard in &view.guards {
        bytes.extend_from_slice(guard);
    }
    Ok(bytes)
}

impl Directory {
    /// Attach storage before sharing this directory or starting its entry owner.
    /// The initial snapshot must commit too; failure prevents construction.
    pub fn with_persistence(mut self, sink: PrivateStateSink) -> Result<Self> {
        sink(&self.encode_private()?)?;
        self.persist = Some(sink);
        Ok(self)
    }

    /// Only the caller's authenticated, encrypted private storage may retain this
    /// material. Own listener exclusions are installed anew before owner startup.
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        encode(&self.view.read().unwrap_or_else(|p| p.into_inner()))
    }

    pub fn restore_private(bytes: &[u8], now: u64) -> Result<Self> {
        Self::new().restore(bytes, now)
    }

    /// Explicit local-fixture policy; never inferred from persisted addresses.
    pub fn restore_private_for_loopback_fixture(bytes: &[u8], now: u64) -> Result<Self> {
        Self::for_loopback_fixture().restore(bytes, now)
    }

    fn restore(self, bytes: &[u8], now: u64) -> Result<Self> {
        if !(7..=MAX_PRIVATE_BYTES).contains(&bytes.len()) || &bytes[..5] != b"GCRD\x02" {
            return Err("GC/2 private routing state required".into());
        }
        let count = bytes[5] as usize;
        let guard_count = bytes[6] as usize;
        let end = 7 + count * INTRODUCTION_BYTES;
        if count > MAX_RELAYS || guard_count > MAX_GUARDS || bytes.len() != end + guard_count * 32 {
            return Err("GC/2 private routing state exceeds bounds".into());
        }
        let mut restored = View::default();
        for raw in bytes[7..end].as_chunks::<INTRODUCTION_BYTES>().0 {
            let relay = Introduction::decode(raw)?;
            self.admissible(&relay, now)?;
            if restored
                .relays
                .iter()
                .any(|old| old.service_id == relay.service_id)
            {
                return Err("duplicate GC/2 private relay".into());
            }
            restored.relays.push(relay);
        }
        let guards = bytes[end..].as_chunks::<32>().0.to_vec();
        *self.view.write().unwrap_or_else(|p| p.into_inner()) = restored;
        // Validates known pins, duplicates and independent guard IPs. Nothing
        // escapes this constructor on failure and no expiry is extended.
        self.set_guards(guards)?;
        Ok(self)
    }

    pub(super) fn commit_view(&self, view: &mut View, next: View) -> Result<()> {
        self.check_persistence()?;
        if let Some(sink) = &self.persist {
            let bytes = encode(&next)?;
            if bytes != encode(view)? {
                if let Err(error) = sink(&bytes) {
                    self.persistence_failed.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
        *view = next;
        Ok(())
    }

    pub(crate) fn check_persistence(&self) -> Result<()> {
        if self.persistence_failed.load(Ordering::Acquire) {
            Err(
                "GC/2 routing storage failed; reload authenticated state before reconnecting"
                    .into(),
            )
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };

    const NOW: u64 = 10_000;
    fn relay(index: u8) -> Introduction {
        Introduction {
            addr: format!("127.0.0.{index}:443").parse().unwrap(),
            service_id: [index; 32],
            reentry_cap: [100; 32],
            entry_cap: [101; 32],
            transit_cap: [102; 32],
            expires_at: NOW + 100,
        }
    }
    fn directory() -> Directory {
        let directory = Directory::for_loopback_fixture();
        directory
            .remember(
                &BootstrapBundle {
                    relays: vec![relay(1), relay(2), relay(3)],
                },
                NOW,
            )
            .unwrap();
        directory.set_guards(vec![[2; 32], [1; 32]]).unwrap();
        directory
    }
    #[test]
    fn restart_retains_guard_order_and_expired_reentry_without_extending_authority() {
        let bytes = directory().encode_private().unwrap();
        let restored = Directory::restore_private_for_loopback_fixture(&bytes, NOW + 101).unwrap();
        assert_eq!(restored.guards(), vec![[2; 32], [1; 32]]);
        assert_eq!(restored.encode_private().unwrap(), bytes);
        assert!(restored.eligible(&[], NOW + 101).unwrap().is_empty());
        assert_eq!(restored.reentry_candidates().len(), 3);
        assert!(restored
            .reentry_candidates()
            .iter()
            .all(|relay| relay.expires_at == NOW + 100));
        // A local archive is not allowed to weaken the production address policy.
        assert!(Directory::restore_private(&bytes, NOW).is_err());
    }
    #[test]
    fn corrupt_noncanonical_and_other_version_archives_are_rejected() {
        let bytes = directory().encode_private().unwrap();
        for end in 0..bytes.len() {
            assert!(Directory::restore_private_for_loopback_fixture(&bytes[..end], NOW).is_err());
        }
        let mut variants = Vec::new();
        let mut wrong = bytes.to_vec();
        wrong[4] = 1;
        variants.push(wrong);
        let mut wrong = bytes.to_vec();
        wrong.push(0);
        variants.push(wrong);
        let mut wrong = bytes.to_vec();
        wrong[5] = 65;
        variants.push(wrong);
        let mut wrong = bytes.to_vec();
        wrong[6] = 4;
        variants.push(wrong);
        let mut wrong = bytes.to_vec();
        wrong[7 + INTRODUCTION_BYTES..7 + 2 * INTRODUCTION_BYTES]
            .copy_from_slice(&bytes[7..7 + INTRODUCTION_BYTES]);
        variants.push(wrong);
        let end = bytes.len();
        let mut wrong = bytes.to_vec();
        wrong[end - 32..].fill(99);
        variants.push(wrong);
        let mut wrong = bytes.to_vec();
        wrong[end - 32..].copy_from_slice(&bytes[end - 64..end - 32]);
        variants.push(wrong);
        for wrong in variants {
            assert!(Directory::restore_private_for_loopback_fixture(&wrong, NOW).is_err());
        }
        let mut future = bytes.to_vec();
        future[7 + 147..7 + INTRODUCTION_BYTES]
            .copy_from_slice(&(NOW + MAX_ADVERTISEMENT_AGE + 1).to_be_bytes());
        assert!(Directory::restore_private_for_loopback_fixture(&future, NOW).is_err());
    }

    #[test]
    fn full_private_view_roundtrips_under_production_policy_with_exact_bounds() {
        let directory = Directory::new();
        for chunk in (1..=MAX_RELAYS as u8)
            .collect::<Vec<_>>()
            .chunks(MAX_INTRODUCTIONS)
        {
            let relays = chunk
                .iter()
                .map(|index| {
                    let mut intro = relay(*index);
                    intro.addr = format!("8.8.8.{index}:443").parse().unwrap();
                    intro
                })
                .collect();
            directory
                .remember(&BootstrapBundle { relays }, NOW)
                .unwrap();
        }
        directory
            .set_guards(vec![[1; 32], [32; 32], [64; 32]])
            .unwrap();
        let bytes = directory.encode_private().unwrap();
        assert_eq!(bytes.len(), MAX_PRIVATE_BYTES);
        let restored = Directory::restore_private(&bytes, NOW).unwrap();
        assert_eq!(restored.guards(), directory.guards());
        assert_eq!(restored.encode_private().unwrap(), bytes);
        assert_eq!(restored.eligible(&[], NOW).unwrap().len(), MAX_RELAYS);
    }
    #[test]
    fn failed_durable_commit_cannot_publish_new_guard_authority_or_own_exclusion() {
        let saved = Arc::new(Mutex::new(Vec::new()));
        let reject = Arc::new(AtomicBool::new(false));
        let snapshot = saved.clone();
        let failure = reject.clone();
        let directory = directory()
            .with_persistence(Arc::new(move |bytes| {
                if failure.load(Ordering::SeqCst) {
                    return Err("injected durable failure".into());
                }
                *snapshot.lock().unwrap() = bytes.to_vec();
                Ok(())
            }))
            .unwrap();
        let before = directory.encode_private().unwrap();
        assert_eq!(*saved.lock().unwrap(), *before);
        reject.store(true, Ordering::SeqCst);
        assert!(directory.set_guards(vec![[3; 32]]).is_err());
        assert!(directory.retain_guards(&[[3; 32]]).is_err());
        let mut renewed = relay(2);
        renewed.entry_cap = [111; 32];
        renewed.expires_at += 1;
        assert!(directory
            .remember(
                &BootstrapBundle {
                    relays: vec![renewed]
                },
                NOW
            )
            .is_err());
        assert!(directory
            .set_own_services(vec![(relay(2).addr, [55; 32])])
            .is_err());
        assert_eq!(directory.encode_private().unwrap(), before);
        assert_eq!(*saved.lock().unwrap(), *before);
        assert!(directory.eligible(&[], NOW).is_err());
        assert!(directory.reentry_candidates().is_empty());
        assert!(directory.set_guards(vec![[2; 32], [1; 32]]).is_err());
        reject.store(false, Ordering::SeqCst);
        // Recovery must reconcile the actual saved state, not silently clear a
        // failure flag in a directory whose disk outcome may be uncertain.
        let reopened =
            Directory::restore_private_for_loopback_fixture(&saved.lock().unwrap(), NOW).unwrap();
        assert_eq!(reopened.guards(), vec![[2; 32], [1; 32]]);
        assert!(directory.set_guards(vec![[3; 32]]).is_err());
    }

    #[test]
    fn ambiguous_atomic_replace_cannot_resume_from_the_stale_memory_snapshot() {
        let saved = Arc::new(Mutex::new(Vec::new()));
        let reject = Arc::new(AtomicBool::new(false));
        let snapshot = saved.clone();
        let failure = reject.clone();
        let directory = directory()
            .with_persistence(Arc::new(move |bytes| {
                *snapshot.lock().unwrap() = bytes.to_vec();
                if failure.load(Ordering::SeqCst) {
                    return Err("flush failed after atomic replace".into());
                }
                Ok(())
            }))
            .unwrap();
        reject.store(true, Ordering::SeqCst);
        assert!(directory.set_guards(vec![[3; 32]]).is_err());
        assert_eq!(directory.guards(), vec![[2; 32], [1; 32]]);
        assert!(directory.set_guards(vec![[2; 32], [1; 32]]).is_err());
        assert!(directory.eligible(&[], NOW).is_err());
        assert!(directory.reentry_candidates().is_empty());
        let restored =
            Directory::restore_private_for_loopback_fixture(&saved.lock().unwrap(), NOW).unwrap();
        assert_eq!(restored.guards(), vec![[3; 32]]);
    }
}
