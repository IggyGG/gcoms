//! Optional owner-authorized wake-up bindings. No provider SDKs or device tokens.
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub use gcoms_core::lease::OP_BIND_NOTIFICATION;
pub use gcoms_core::lease::OP_PUSH_REGISTRATION;
mod tickets;
#[cfg(feature = "push-gateway")]
pub(crate) use tickets::TicketIssuer;
pub(crate) use tickets::TicketRequest;
pub use tickets::{PushPlatform, PushRegistrationRequest, PushRegistrationTicket};
const DOMAIN: &[u8] = b"GC/PUSH-BIND/v1\0";
const BODY: usize = 106;
pub const WIRE_BYTES: usize = BODY + 32;

/// Revision is monotonically increasing per owned queue. Zero reference unbinds.
/// Persist the revision in the host app before submitting; retries reuse it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub queue: [u8; 32],
    pub epoch: u64,
    pub revision: u64,
    pub expires: u64,
    pub nonce: [u8; 16],
    pub reference: [u8; 32],
}
impl Binding {
    pub fn encode(&self, admin: &[u8; 32], service: &[u8; 32]) -> Result<Vec<u8>, String> {
        if self.revision == 0 || self.nonce == [0; 16] {
            return Err("invalid notification binding".into());
        }
        let mut wire = Vec::with_capacity(WIRE_BYTES);
        wire.extend_from_slice(&[1, OP_BIND_NOTIFICATION]);
        wire.extend_from_slice(&self.queue);
        wire.extend_from_slice(&self.epoch.to_be_bytes());
        wire.extend_from_slice(&self.revision.to_be_bytes());
        wire.extend_from_slice(&self.expires.to_be_bytes());
        wire.extend_from_slice(&self.nonce);
        wire.extend_from_slice(&self.reference);
        let mut mac = Hmac::<Sha256>::new_from_slice(admin).map_err(|_| "invalid admin key")?;
        mac.update(DOMAIN);
        mac.update(service);
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }
    pub fn verify(
        wire: &[u8],
        admin: &[u8; 32],
        service: &[u8; 32],
        now: u64,
    ) -> Result<Self, String> {
        if wire.len() != WIRE_BYTES || wire[..2] != [1, OP_BIND_NOTIFICATION] {
            return Err("invalid notification binding".into());
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(admin).map_err(|_| "invalid admin key")?;
        mac.update(DOMAIN);
        mac.update(service);
        mac.update(&wire[..BODY]);
        mac.verify_slice(&wire[BODY..])
            .map_err(|_| "unauthorized notification binding")?;
        let value = Self {
            queue: wire[2..34].try_into().map_err(|_| "queue")?,
            epoch: u64::from_be_bytes(wire[34..42].try_into().map_err(|_| "epoch")?),
            revision: u64::from_be_bytes(wire[42..50].try_into().map_err(|_| "revision")?),
            expires: u64::from_be_bytes(wire[50..58].try_into().map_err(|_| "expiry")?),
            nonce: wire[58..74].try_into().map_err(|_| "nonce")?,
            reference: wire[74..106].try_into().map_err(|_| "reference")?,
        };
        if value.revision == 0
            || value.nonce == [0; 16]
            || value.expires <= now
            || value.expires > now.saturating_add(86400)
        {
            return Err("invalid notification binding lifetime".into());
        }
        Ok(value)
    }
}

#[cfg(feature = "push-gateway")]
mod gateway;
#[cfg(feature = "push-gateway")]
pub(crate) use gateway::worker;
#[cfg(feature = "push-gateway")]
pub use gateway::GatewayConfig;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binding_requires_admin_and_binds_relay_epoch_reference_and_expiry() {
        let binding = Binding {
            queue: [1; 32],
            epoch: 2,
            revision: 3,
            expires: 200,
            nonce: [4; 16],
            reference: [5; 32],
        };
        let wire = binding.encode(&[6; 32], &[7; 32]).unwrap();
        assert_eq!(
            Binding::verify(&wire, &[6; 32], &[7; 32], 100).unwrap(),
            binding
        );
        assert!(Binding::verify(&wire, &[8; 32], &[7; 32], 100).is_err());
        assert!(Binding::verify(&wire, &[6; 32], &[8; 32], 100).is_err());
        assert!(Binding::verify(&wire, &[6; 32], &[7; 32], 200).is_err());
        for offset in [2, 34, 42, 50, 58, 74, 106] {
            let mut changed = wire.clone();
            changed[offset] ^= 1;
            assert!(Binding::verify(&changed, &[6; 32], &[7; 32], 100).is_err());
        }
    }
}
