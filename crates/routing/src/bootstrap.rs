//! Bounded private introductions shared by invites and endpoint packaging.
use crate::{directory::RELAY_BYTES, Directory, Relay, Result};

pub const MAX_INTRODUCTIONS: usize = 8;
pub const MAX_BUNDLE_BYTES: usize = 6 + MAX_INTRODUCTIONS * RELAY_BYTES;

#[derive(Clone, Debug)]
pub struct BootstrapBundle {
    pub relays: Vec<Relay>,
}

impl BootstrapBundle {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = b"GCRB\x01".to_vec();
        bytes.push(self.relays.len() as u8);
        for relay in &self.relays {
            bytes.extend_from_slice(&relay.encode()?);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 6 || bytes.len() > MAX_BUNDLE_BYTES || &bytes[..5] != b"GCRB\x01" {
            return Err("invalid routing bootstrap bundle".into());
        }
        let count = bytes[5] as usize;
        if count == 0 || count > MAX_INTRODUCTIONS || bytes.len() != 6 + count * RELAY_BYTES {
            return Err("routing bootstrap bundle exceeds bounds".into());
        }
        let mut relays = Vec::with_capacity(count);
        for raw in bytes[6..].as_chunks::<RELAY_BYTES>().0 {
            relays.push(Relay::decode(raw)?);
        }
        let bundle = Self { relays };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<()> {
        if self.relays.is_empty() || self.relays.len() > MAX_INTRODUCTIONS {
            return Err("routing bootstrap bundle exceeds bounds".into());
        }
        for (index, relay) in self.relays.iter().enumerate() {
            relay.validate()?;
            if self.relays[..index]
                .iter()
                .any(|r| r.service_id == relay.service_id)
            {
                return Err("duplicate bootstrap service identity".into());
            }
        }
        Ok(())
    }

    /// Stale descriptors are retained only as re-entry material. Do not widen
    /// their expiry to turn them into fresh circuit credentials.
    pub fn install_fresh(&self, directory: &Directory, now: u64) -> Result<usize> {
        self.validate()?;
        let mut installed = 0;
        for relay in &self.relays {
            directory.remember(relay.clone(), now)?;
            if relay.expires_at > now {
                installed += 1;
            }
        }
        Ok(installed)
    }
}
