//! Volatile D13 contact exchange for an already authorized durable delivery.
//! This codec grants no authority. Callers must match a current signed attempt
//! before using it, and send it only via the reserved volatile GC application API.
use crate::file_stream::{FileContact, FILE_CONTACT_LEN};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 7] = b"GCPAYC1";
pub const PAYLOAD_CONTACT_BYTES: usize = MAGIC.len() + 16 + 32 + FILE_CONTACT_LEN;

/// No Debug/serde/filesystem interface: the one-use capability is not a journal
/// entry. Only its digest may be recorded in a durable attempt.
pub struct PayloadContact {
    delivery_id: [u8; 16],
    receiver_descriptor_sha256: [u8; 32],
    contact: FileContact,
}

/// Values taken from the independently verified current negotiation, never
/// copied from an untrusted volatile packet to make that packet match itself.
#[derive(Clone)]
pub struct ExpectedAttempt {
    pub delivery_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub receiver_descriptor_sha256: [u8; 32],
    pub contact_sha256: [u8; 32],
    pub size_bytes: u64,
    pub expires_at_unix: u64,
}

impl PayloadContact {
    pub fn new(
        delivery_id: [u8; 16],
        receiver_descriptor_sha256: [u8; 32],
        contact: FileContact,
        now: u64,
    ) -> Result<Self, &'static str> {
        if delivery_id == [0; 16] || receiver_descriptor_sha256 == [0; 32] {
            return Err("invalid payload contact identity");
        }
        contact
            .validate(now)
            .map_err(|_| "invalid or expired file contact")?;
        Ok(Self {
            delivery_id,
            receiver_descriptor_sha256,
            contact,
        })
    }

    pub fn encode(&self, now: u64) -> Result<Vec<u8>, &'static str> {
        self.contact
            .validate(now)
            .map_err(|_| "invalid or expired file contact")?;
        let mut wire = Vec::with_capacity(PAYLOAD_CONTACT_BYTES);
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&self.delivery_id);
        wire.extend_from_slice(&self.receiver_descriptor_sha256);
        wire.extend_from_slice(&self.contact.encode().map_err(|_| "invalid file contact")?);
        Ok(wire)
    }

    pub fn decode(wire: &[u8], now: u64) -> Result<Self, &'static str> {
        if wire.len() != PAYLOAD_CONTACT_BYTES || &wire[..MAGIC.len()] != MAGIC {
            return Err("invalid payload contact framing");
        }
        let delivery_id = wire[7..23].try_into().map_err(|_| "invalid delivery ID")?;
        let descriptor = wire[23..55]
            .try_into()
            .map_err(|_| "invalid descriptor hash")?;
        let contact = FileContact::decode(&wire[55..], now).map_err(|_| "invalid file contact")?;
        Self::new(delivery_id, descriptor, contact, now)
    }

    /// Untrusted public routing metadata for an independent authorization lookup.
    /// These IDs grant no permission; use `verify_for` before opening D13.
    pub fn routing_ids(&self) -> ([u8; 16], [u8; 16]) {
        (self.delivery_id, self.contact.transfer_id)
    }

    /// Untrusted public proposal metadata. The controller bounds this value by
    /// its signed queued job before requesting durable Begin admission.
    pub fn proposed_expires_at_unix(&self) -> u64 {
        self.contact.contact_expiry
    }

    pub fn contact_sha256(&self) -> Result<[u8; 32], &'static str> {
        Ok(Sha256::digest(self.contact.encode().map_err(|_| "invalid file contact")?).into())
    }

    /// Borrow the contact only after it matches every independently trusted
    /// attempt field. D13 transfer_id is exactly the fresh delivery attempt ID.
    pub fn verify_for(
        &self,
        expected: &ExpectedAttempt,
        now: u64,
    ) -> Result<&FileContact, &'static str> {
        self.contact
            .validate(now)
            .map_err(|_| "invalid or expired file contact")?;
        if self.delivery_id != expected.delivery_id
            || self.contact.transfer_id != expected.attempt_id
            || self.receiver_descriptor_sha256 != expected.receiver_descriptor_sha256
            || self.contact_sha256()? != expected.contact_sha256
            || expected.size_bytes == 0
            || self.contact.max_file_size != expected.size_bytes
            || self.contact.contact_expiry != expected.expires_at_unix
        {
            return Err("payload contact does not match the current attempt");
        }
        Ok(&self.contact)
    }
}

impl Drop for PayloadContact {
    fn drop(&mut self) {
        self.contact.file_cap.fill(0);
        self.contact.recipient_contact.push_cap.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_stream::{Contact, PROFILE_VERSION_V2};
    fn fixture() -> (PayloadContact, ExpectedAttempt) {
        let contact = FileContact {
            profile_version: PROFILE_VERSION_V2,
            transfer_id: [2; 16],
            recipient_contact: Contact {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [3; 32],
                queue_id: [4; 32],
                epoch: 1,
                push_cap: [5; 32],
                lease_expiry: 2000,
            },
            file_cap: [6; 32],
            contact_expiry: 1900,
            max_file_size: 123,
            max_chunk_size: 4096,
            max_inflight_bytes: 8192,
        };
        let value = PayloadContact::new([1; 16], [7; 32], contact, 1000).unwrap();
        let expected = ExpectedAttempt {
            delivery_id: [1; 16],
            attempt_id: [2; 16],
            receiver_descriptor_sha256: [7; 32],
            contact_sha256: value.contact_sha256().unwrap(),
            size_bytes: 123,
            expires_at_unix: 1900,
        };
        (value, expected)
    }
    #[test]
    fn exact_bounded_wire_matches_the_current_authorized_attempt() {
        let (value, expected) = fixture();
        let wire = value.encode(1000).unwrap();
        assert_eq!(
            value.routing_ids(),
            (expected.delivery_id, expected.attempt_id)
        );
        assert_eq!(wire.len(), 268);
        assert_eq!(value.proposed_expires_at_unix(), expected.expires_at_unix);
        let decoded = PayloadContact::decode(&wire, 1000).unwrap();
        assert_eq!(
            decoded.verify_for(&expected, 1000).unwrap().transfer_id,
            expected.attempt_id
        );
        for length in 0..wire.len() {
            assert!(PayloadContact::decode(&wire[..length], 1000).is_err());
        }
        let mut extended = wire;
        extended.push(0);
        assert!(PayloadContact::decode(&extended, 1000).is_err());
        assert!(value.verify_for(&expected, 2001).is_err());
    }
    #[test]
    fn job_fields_and_contact_bytes_cannot_be_substituted() {
        let (value, _) = fixture();
        for field in 0..6 {
            let (_, mut expected) = fixture();
            match field {
                0 => expected.delivery_id[0] ^= 1,
                1 => expected.attempt_id[0] ^= 1,
                2 => expected.receiver_descriptor_sha256[0] ^= 1,
                3 => expected.contact_sha256[0] ^= 1,
                4 => expected.size_bytes += 1,
                _ => expected.expires_at_unix += 1,
            }
            assert!(value.verify_for(&expected, 1000).is_err());
        }
        let (_, expected) = fixture();
        let mut wire = value.encode(1000).unwrap();
        // Change a capability while preserving the syntactic file contact.
        wire[55 + 1 + 16 + 132] ^= 1;
        let changed = PayloadContact::decode(&wire, 1000).unwrap();
        assert!(changed.verify_for(&expected, 1000).is_err());
    }
}
