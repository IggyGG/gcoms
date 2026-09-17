use crate::lease::{Capabilities, LeaseLimits};
use crate::relay::{HopKey, RelayTarget};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use gcoms_core::Cell;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasContact {
    pub target: RelayTarget,
    pub queue_id: [u8; 32],
    pub epoch: u64,
    pub push_cap: [u8; 32],
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedAlias {
    pub contact: AliasContact,
    pub capabilities: Capabilities,
    pub limits: LeaseLimits,
    pub create_path: String,
    pub lease_create: Cell,
}

impl OwnedAlias {
    pub fn zeroize(&mut self) {
        self.capabilities.push.fill(0);
        self.capabilities.sub.fill(0);
        self.capabilities.admin.fill(0);
        self.lease_create.payload.fill(0);
        self.create_path.clear();
    }
}

impl Drop for OwnedAlias {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayProvision {
    pub aliases: Vec<OwnedAlias>,
    pub frwd_path: String,
    pub hop_key: HopKey,
}

impl RelayProvision {
    pub fn alias(&self, index: usize) -> Option<&OwnedAlias> {
        self.aliases.get(index)
    }

    /// The forwarding authority this provision carries, as a grant that can
    /// be handed to a peer.
    pub fn forward_grant(&self, expires_at: u64, issued_by: Vec<u8>) -> Option<ForwardGrant> {
        let target = self.aliases.first()?.contact.target.clone();
        Some(ForwardGrant {
            target,
            frwd_path: self.frwd_path.clone(),
            hop_key: self.hop_key,
            expires_at,
            issued_by,
        })
    }
}

/// Authority to use one relay as a FRWD intermediary (SPEC §11.1, §12).
///
/// A grant is a private bearer: `hop_key` MACs every FRWD toward `target`
/// on `frwd_path`. Grants travel only inside E2E-encrypted direct records
/// and are never exposed on a public endpoint (that would be a §5.3 oracle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardGrant {
    pub target: RelayTarget,
    pub frwd_path: String,
    pub hop_key: HopKey,
    pub expires_at: u64,
    /// Identity key of the peer that issued this grant, so a sender can
    /// exclude grants issued by the message's own receiver.
    pub issued_by: Vec<u8>,
}

impl ForwardGrant {
    pub const MAX_ENCODED: usize = 4 * 1024;

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128 + self.issued_by.len());
        v.push(1); // version
        v.extend_from_slice(&self.target.encode_public());
        v.extend_from_slice(&(self.frwd_path.len() as u16).to_be_bytes());
        v.extend_from_slice(self.frwd_path.as_bytes());
        v.extend_from_slice(&self.hop_key);
        v.extend_from_slice(&self.expires_at.to_be_bytes());
        v.extend_from_slice(&(self.issued_by.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.issued_by);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() > Self::MAX_ENCODED || *buf.first()? != 1 {
            return None;
        }
        let mut p = 1usize;
        let target = RelayTarget::decode_public(buf.get(p..p + 51)?)?;
        p += 51;
        let len = u16::from_be_bytes(buf.get(p..p + 2)?.try_into().ok()?) as usize;
        p += 2;
        let frwd_path = core::str::from_utf8(buf.get(p..p + len)?).ok()?.to_string();
        p += len;
        if frwd_path.is_empty() || frwd_path.len() > 64 {
            return None;
        }
        let hop_key: HopKey = buf.get(p..p + 32)?.try_into().ok()?;
        p += 32;
        if hop_key == [0; 32] {
            return None;
        }
        let expires_at = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
        p += 8;
        let len = u16::from_be_bytes(buf.get(p..p + 2)?.try_into().ok()?) as usize;
        p += 2;
        let issued_by = buf.get(p..p + len)?.to_vec();
        p += len;
        if p != buf.len() {
            return None;
        }
        Some(Self {
            target,
            frwd_path,
            hop_key,
            expires_at,
            issued_by,
        })
    }

    pub fn zeroize(&mut self) {
        self.hop_key.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_alias_zeroize_clears_all_private_authority() {
        let target = RelayTarget {
            address: "192.0.2.1:443".parse().unwrap(),
            relay_service_id: [1; 32],
        };
        let mut alias = OwnedAlias {
            contact: AliasContact {
                target,
                queue_id: [2; 32],
                epoch: 3,
                push_cap: [4; 32],
                expiry: 5,
            },
            capabilities: Capabilities {
                push: [6; 32],
                sub: [7; 32],
                admin: [8; 32],
            },
            limits: LeaseLimits {
                max_queue_cells: 1,
                max_queue_bytes: 1,
            },
            create_path: "private-admin-token".into(),
            lease_create: Cell::new(gcoms_core::CellType::RelaySub, 0, 0, vec![9; 32]),
        };

        alias.zeroize();

        assert_eq!(alias.capabilities.push, [0; 32]);
        assert_eq!(alias.capabilities.sub, [0; 32]);
        assert_eq!(alias.capabilities.admin, [0; 32]);
        assert!(alias.create_path.is_empty());
        assert!(alias.lease_create.payload.iter().all(|byte| *byte == 0));
    }
}
