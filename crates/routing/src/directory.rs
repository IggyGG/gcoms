//! A private, bounded view of relay services, never of people or channels.
use crate::{
    wire::{decode_address, encode_address},
    Result,
};
use rand::seq::SliceRandom;
use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::RwLock,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

pub const MAX_RELAYS: usize = 64;
pub const MAX_GUARDS: usize = 3;
pub const MAX_ADVERTISEMENT_AGE: u64 = 24 * 60 * 60;
pub const RELAY_BYTES: usize = 123;

#[derive(Clone)]
pub struct Relay {
    pub addr: SocketAddr,
    pub service_id: [u8; 32],
    /// Durable private re-entry capability, independent of the fresh circuit cap.
    pub reentry_cap: [u8; 32],
    pub circuit_cap: [u8; 32],
    pub expires_at: u64,
}

impl fmt::Debug for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relay")
            .field("addr", &self.addr)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.reentry_cap.zeroize();
        self.circuit_cap.zeroize();
    }
}

impl Relay {
    pub fn validate(&self) -> Result<()> {
        decode_address(&encode_address(self.addr))?;
        if self.service_id == [0; 32]
            || self.reentry_cap == [0; 32]
            || self.circuit_cap == [0; 32]
            || self.circuit_cap == self.reentry_cap
            || self.expires_at == 0
        {
            return Err("incomplete relay introduction".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; RELAY_BYTES]> {
        self.validate()?;
        let mut out = [0; RELAY_BYTES];
        out[..19].copy_from_slice(&encode_address(self.addr));
        out[19..51].copy_from_slice(&self.service_id);
        out[51..83].copy_from_slice(&self.reentry_cap);
        out[83..115].copy_from_slice(&self.circuit_cap);
        out[115..].copy_from_slice(&self.expires_at.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RELAY_BYTES {
            return Err("invalid introduction size".into());
        }
        let relay = Self {
            addr: decode_address(&bytes[..19])?,
            service_id: bytes[19..51].try_into()?,
            reentry_cap: bytes[51..83].try_into()?,
            circuit_cap: bytes[83..115].try_into()?,
            expires_at: u64::from_be_bytes(bytes[115..].try_into()?),
        };
        relay.validate()?;
        Ok(relay)
    }

    pub fn conflicts(&self, addr: SocketAddr, pin: [u8; 32]) -> bool {
        self.service_id == pin || self.addr.ip() == addr.ip()
    }
}

#[derive(Default)]
struct View {
    relays: Vec<Relay>,
    guards: Vec<[u8; 32]>,
    failures: HashMap<[u8; 32], (u32, Instant)>,
    own: Vec<(SocketAddr, [u8; 32])>,
}

#[derive(Default)]
pub struct Directory(RwLock<View>);

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Own listeners are exclusions, never implicit bootstrap or inbox fallbacks.
    pub fn set_own_services(&self, services: Vec<(SocketAddr, [u8; 32])>) -> Result<()> {
        if services.len() > 8 {
            return Err("too many own relay services".into());
        }
        self.0.write().unwrap_or_else(|p| p.into_inner()).own = services;
        Ok(())
    }

    pub fn install(&self, relay: Relay, now: u64) -> Result<()> {
        relay.validate()?;
        if relay.expires_at <= now || relay.expires_at.saturating_sub(now) > MAX_ADVERTISEMENT_AGE {
            return Err("relay advertisement outside freshness window".into());
        }
        self.remember(relay, now)
    }

    /// Keep long-lived re-entry credentials even when an advertisement expired.
    /// Path selection still requires a fresh advertisement, without extending it.
    pub fn remember(&self, relay: Relay, now: u64) -> Result<()> {
        relay.validate()?;
        if relay.expires_at.saturating_sub(now) > MAX_ADVERTISEMENT_AGE {
            return Err("relay advertisement outside freshness window".into());
        }
        let mut view = self.0.write().unwrap_or_else(|p| p.into_inner());
        if let Some(index) = view
            .relays
            .iter()
            .position(|r| r.service_id == relay.service_id)
        {
            if view.relays[index].expires_at > relay.expires_at {
                return Ok(()); // retained newer credentials take precedence
            }
            view.relays[index] = relay;
        } else {
            if view.relays.len() >= MAX_RELAYS {
                let victim = view
                    .relays
                    .iter()
                    .position(|r| r.expires_at <= now && !view.guards.contains(&r.service_id))
                    .or_else(|| {
                        view.relays
                            .iter()
                            .enumerate()
                            .filter(|(_, r)| !view.guards.contains(&r.service_id))
                            .min_by_key(|(_, r)| r.expires_at)
                            .map(|(index, _)| index)
                    })
                    .ok_or("relay view is full")?;
                let old = view.relays.remove(victim);
                view.failures.remove(&old.service_id);
            }
            view.relays.push(relay);
        }
        Ok(())
    }

    pub fn introductions(&self) -> Vec<Relay> {
        self.0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .relays
            .clone()
    }

    pub fn is_own(&self, addr: SocketAddr, pin: [u8; 32]) -> bool {
        self.0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .own
            .iter()
            .any(|(own_addr, own_pin)| *own_pin == pin || own_addr.ip() == addr.ip())
    }

    /// Bootstrap touches retained guards first. At most eight distinct services
    /// are tried in one recovery round; failed services keep their cooldown.
    pub fn reentry_candidates(&self) -> Vec<Relay> {
        let view = self.0.read().unwrap_or_else(|p| p.into_inner());
        let mut candidates: Vec<_> = view
            .relays
            .iter()
            .filter(|r| {
                !view.own.iter().any(|(addr, pin)| r.conflicts(*addr, *pin))
                    && !view
                        .failures
                        .get(&r.service_id)
                        .is_some_and(|(_, until)| *until > Instant::now())
            })
            .cloned()
            .collect();
        candidates.shuffle(&mut rand::thread_rng());
        candidates.sort_by_key(|r| {
            view.guards
                .iter()
                .position(|pin| pin == &r.service_id)
                .unwrap_or(MAX_GUARDS)
        });
        candidates.truncate(8);
        candidates
    }

    /// Keep one preferred entry and two alternatives. Reuse a healthy entry;
    /// only the middle is selected for each newly constructed circuit.
    pub fn path(&self, excluded: &[(SocketAddr, [u8; 32])], now: u64) -> Result<[Relay; 2]> {
        if excluded.len() > MAX_RELAYS {
            return Err("too many terminal exclusions".into());
        }
        let mut view = self.0.write().unwrap_or_else(|p| p.into_inner());
        let eligible: Vec<_> = view
            .relays
            .iter()
            .filter(|r| {
                r.expires_at > now
                    && r.expires_at.saturating_sub(now) <= MAX_ADVERTISEMENT_AGE
                    && !view
                        .own
                        .iter()
                        .chain(excluded)
                        .any(|(addr, pin)| r.conflicts(*addr, *pin))
                    && !view
                        .failures
                        .get(&r.service_id)
                        .is_some_and(|(_, until)| *until > Instant::now())
            })
            .cloned()
            .collect();
        let mut candidates: Vec<_> = eligible
            .iter()
            .filter(|r| !view.guards.contains(&r.service_id))
            .collect();
        candidates.shuffle(&mut rand::thread_rng());
        // Remove entries only when they are absent from the retained private
        // view. An outage, stale descriptor or target exclusion is not erasure.
        let retained: Vec<_> = view.relays.iter().map(|r| r.service_id).collect();
        view.guards.retain(|pin| retained.contains(pin));
        for relay in candidates {
            if view.guards.len() == MAX_GUARDS {
                break;
            }
            if view.guards.iter().any(|pin| {
                view.relays
                    .iter()
                    .any(|r| &r.service_id == pin && r.addr.ip() == relay.addr.ip())
            }) {
                continue;
            }
            view.guards.push(relay.service_id);
        }
        // Retiring the original guard set must not strand a retained volunteer
        // view. Replace only an unusable alternative, preserving the preferred
        // guard and avoiding entry churn while any retained guard is usable.
        if !view
            .guards
            .iter()
            .any(|pin| eligible.iter().any(|r| &r.service_id == pin))
        {
            let replacements: Vec<_> = eligible
                .iter()
                .filter(|entry| {
                    eligible
                        .iter()
                        .any(|middle| !middle.conflicts(entry.addr, entry.service_id))
                })
                .collect();
            if let Some(replacement) = replacements.choose(&mut rand::thread_rng()) {
                if view.guards.len() == MAX_GUARDS {
                    view.guards.pop();
                }
                view.guards.push(replacement.service_id);
            }
        }
        for pin in &view.guards {
            let Some(entry) = eligible.iter().find(|r| &r.service_id == pin) else {
                continue;
            };
            let middles: Vec<_> = eligible
                .iter()
                .filter(|r| !r.conflicts(entry.addr, entry.service_id))
                .collect();
            if let Some(middle) = middles.choose(&mut rand::thread_rng()) {
                return Ok([entry.clone(), (*middle).clone()]);
            }
        }
        Err("no complete distinct relay path is available".into())
    }

    pub fn failed(&self, pin: [u8; 32]) {
        let mut view = self.0.write().unwrap_or_else(|p| p.into_inner());
        if !view.relays.iter().any(|r| r.service_id == pin) {
            return;
        }
        let count = view
            .failures
            .get(&pin)
            .map_or(1, |(n, _)| n.saturating_add(1));
        let delay = Duration::from_secs(1 << count.min(6));
        view.failures.insert(pin, (count, Instant::now() + delay));
    }

    pub fn healthy(&self, pin: [u8; 32]) {
        self.0
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .failures
            .remove(&pin);
    }

    /// The caller must place these private bytes inside its authenticated,
    /// encrypted archive. Freshness is checked again when selecting a circuit.
    pub fn encode_private(&self) -> Result<Vec<u8>> {
        let view = self.0.read().unwrap_or_else(|p| p.into_inner());
        let mut bytes = b"GCRD\x01".to_vec();
        bytes.push(view.relays.len() as u8);
        bytes.push(view.guards.len() as u8);
        for relay in &view.relays {
            bytes.extend_from_slice(&relay.encode()?);
        }
        for guard in &view.guards {
            bytes.extend_from_slice(guard);
        }
        Ok(bytes)
    }

    pub fn restore_private(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 7 || &bytes[..5] != b"GCRD\x01" {
            return Err("invalid relay archive".into());
        }
        let count = bytes[5] as usize;
        let guard_count = bytes[6] as usize;
        if count > MAX_RELAYS
            || guard_count > MAX_GUARDS
            || bytes.len() != 7 + count * RELAY_BYTES + guard_count * 32
        {
            return Err("relay archive exceeds bounds".into());
        }
        let mut view = View::default();
        for raw in bytes[7..7 + count * RELAY_BYTES]
            .as_chunks::<RELAY_BYTES>()
            .0
        {
            let relay = Relay::decode(raw)?;
            if view.relays.iter().any(|r| r.service_id == relay.service_id) {
                return Err("duplicate relay identity".into());
            }
            view.relays.push(relay);
        }
        for raw in bytes[7 + count * RELAY_BYTES..].as_chunks::<32>().0 {
            let pin = *raw;
            if view.guards.contains(&pin) || !view.relays.iter().any(|r| r.service_id == pin) {
                return Err("invalid retained guard".into());
            }
            view.guards.push(pin);
        }
        Ok(Self(RwLock::new(view)))
    }
}
