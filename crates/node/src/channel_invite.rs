//! Single-use invite links for private channels.
//!
//! An invite is a high-entropy bearer token the owner mints and shares once. A
//! friend redeems it by pushing their MLS key package to the owner's rendezvous
//! queue (whose coordinates the invite carries) together with the invite id and
//! secret; the owner enforces single-use atomically (see
//! `node::channels::redeem_invite`) and pushes back an MLS Welcome.
//!
//! The invite carries no low-entropy material, so no PAKE is needed: the 32-byte
//! `secret` is itself the shared secret. It is NOT a capability to the channel —
//! redemption still runs the owner's MLS add against a live key package, and the
//! secret is single-use with a TTL.

use crate::proto::NodeInfo;
use gcoms_transport::{decode_b64url, encode_b64url};

/// Wire/format version. Bump on any breaking change to the layout below.
pub const INVITE_VERSION: u8 = 1;
pub const BOOTSTRAP_INVITE_VERSION: u8 = 2;
/// Bound decoding before allocating the base64 body. Existing v1 format stays
/// readable; v2 wraps it without adding fields to `ChannelInvite`.
const MAX_INVITE_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct InviteEnvelope {
    pub invite: ChannelInvite,
    pub bootstrap: Option<gcoms_routing::bootstrap::BootstrapBundle>,
}

/// A decoded invite link. `owner` is the owner's public contact card (identity
/// key + bundle + relay aliases) the friend uses to open a sealed session and
/// send the redeem request; `channel` is the human channel name the friend
/// joins; `id`/`secret` identify and authorize the single redemption; `expiry`
/// is an absolute unix time after which the owner refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInvite {
    pub owner: NodeInfo,
    pub channel: String,
    pub id: [u8; 16],
    pub secret: [u8; 32],
    pub expiry: u64,
}

impl ChannelInvite {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.channel.len() > u16::MAX as usize {
            return None;
        }
        // The owner's PUBLIC card only: never leak private relay provisioning
        // into a shareable link.
        let owner = self.owner.public().encode();
        if owner.len() > u32::MAX as usize {
            return None;
        }
        let mut v = Vec::with_capacity(64 + owner.len());
        v.push(INVITE_VERSION);
        v.extend_from_slice(&(owner.len() as u32).to_be_bytes());
        v.extend_from_slice(&owner);
        v.extend_from_slice(&(self.channel.len() as u16).to_be_bytes());
        v.extend_from_slice(self.channel.as_bytes());
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.secret);
        v.extend_from_slice(&self.expiry.to_be_bytes());
        Some(v)
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() > MAX_INVITE_BYTES {
            return None;
        }
        if buf.first() == Some(&BOOTSTRAP_INVITE_VERSION) {
            return InviteEnvelope::decode(buf).map(|envelope| envelope.invite);
        }
        let mut p = 0usize;
        if *buf.get(p)? != INVITE_VERSION {
            return None;
        }
        p += 1;
        let olen = u32::from_be_bytes(buf.get(p..p + 4)?.try_into().ok()?) as usize;
        p += 4;
        let owner_end = p.checked_add(olen)?;
        let owner = NodeInfo::decode(buf.get(p..owner_end)?)?;
        p = owner_end;
        let clen = u16::from_be_bytes(buf.get(p..p + 2)?.try_into().ok()?) as usize;
        p += 2;
        let channel_end = p.checked_add(clen)?;
        let channel = String::from_utf8(buf.get(p..channel_end)?.to_vec()).ok()?;
        p = channel_end;
        let id: [u8; 16] = buf.get(p..p + 16)?.try_into().ok()?;
        p += 16;
        let secret: [u8; 32] = buf.get(p..p + 32)?.try_into().ok()?;
        p += 32;
        let expiry = u64::from_be_bytes(buf.get(p..p + 8)?.try_into().ok()?);
        p += 8;
        if p != buf.len() {
            return None;
        }
        Some(ChannelInvite {
            owner,
            channel,
            id,
            secret,
            expiry,
        })
    }

    /// The paste-able / QR-able string form.
    pub fn to_link(&self) -> Option<String> {
        Some(encode_b64url(&self.encode()?))
    }

    pub fn from_link(link: &str) -> Option<Self> {
        if link.trim().len() > MAX_INVITE_BYTES * 4 / 3 + 4 {
            return None;
        }
        Self::decode(&decode_b64url(link.trim())?)
    }

    pub fn to_link_with_bootstrap(
        &self,
        bootstrap: gcoms_routing::bootstrap::BootstrapBundle,
    ) -> Option<String> {
        InviteEnvelope {
            invite: self.clone(),
            bootstrap: Some(bootstrap),
        }
        .to_link()
    }
}

impl InviteEnvelope {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_INVITE_BYTES {
            return None;
        }
        if bytes.first() == Some(&INVITE_VERSION) {
            return Some(Self {
                invite: ChannelInvite::decode(bytes)?,
                bootstrap: None,
            });
        }
        if bytes.first() != Some(&BOOTSTRAP_INVITE_VERSION) {
            return None;
        }
        let invite_len = u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?) as usize;
        let invite_end = 5usize.checked_add(invite_len)?;
        let inner = bytes.get(5..invite_end)?;
        // A v2 envelope must contain v1, never another recursively nested v2.
        if inner.first() != Some(&INVITE_VERSION) {
            return None;
        }
        let invite = ChannelInvite::decode(inner)?;
        let bundle_len =
            u16::from_be_bytes(bytes.get(invite_end..invite_end + 2)?.try_into().ok()?) as usize;
        let bundle_start = invite_end.checked_add(2)?;
        if bytes.len() != bundle_start.checked_add(bundle_len)? {
            return None;
        }
        let bootstrap =
            gcoms_routing::bootstrap::BootstrapBundle::decode(bytes.get(bundle_start..)?).ok()?;
        Some(Self {
            invite,
            bootstrap: Some(bootstrap),
        })
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        let inner = self.invite.encode()?;
        let Some(bootstrap) = &self.bootstrap else {
            return Some(inner);
        };
        let bundle = bootstrap.encode().ok()?;
        let total = 7usize.checked_add(inner.len())?.checked_add(bundle.len())?;
        if total > MAX_INVITE_BYTES {
            return None;
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.push(BOOTSTRAP_INVITE_VERSION);
        bytes.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&inner);
        bytes.extend_from_slice(&(bundle.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&bundle);
        Some(bytes)
    }

    pub fn from_link(link: &str) -> Option<Self> {
        if link.trim().len() > MAX_INVITE_BYTES * 4 / 3 + 4 {
            return None;
        }
        Self::decode(&decode_b64url(link.trim())?)
    }

    pub fn to_link(&self) -> Option<String> {
        Some(encode_b64url(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::AliasContact;
    use crate::relay::RelayTarget;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn contact(port: u16, ip: IpAddr) -> AliasContact {
        AliasContact {
            target: RelayTarget {
                address: SocketAddr::new(ip, port),
                relay_service_id: [7u8; 32],
            },
            queue_id: [9u8; 32],
            epoch: 0x0102_0304_0506_0708,
            push_cap: [0x5a; 32],
            expiry: 1_800_000_000,
        }
    }

    fn owner(ip: IpAddr) -> NodeInfo {
        NodeInfo {
            identity_pk: vec![0xa1; 48],
            bundle: vec![0xb2; 96],
            aliases: vec![contact(30443, ip), contact(30444, ip)],
            provisioning: None,
        }
    }

    fn sample(ip: IpAddr) -> ChannelInvite {
        ChannelInvite {
            owner: owner(ip),
            channel: "friends".into(),
            id: [0x22; 16],
            secret: [0x33; 32],
            expiry: 1_800_000_300,
        }
    }

    #[test]
    fn roundtrips_via_bytes_and_link() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(157, 90, 35, 101)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let invite = sample(ip);
            assert_eq!(
                ChannelInvite::decode(&invite.encode().unwrap()),
                Some(invite.clone())
            );
            assert_eq!(
                ChannelInvite::from_link(&invite.to_link().unwrap()),
                Some(invite)
            );
        }
    }

    #[test]
    fn link_is_url_safe_and_parses_with_whitespace() {
        let link = sample(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .to_link()
            .unwrap();
        assert!(link
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let padded = format!("  {link}\n");
        assert!(ChannelInvite::from_link(&padded).is_some());
    }

    #[test]
    fn rejects_truncated_tampered_and_wrong_version() {
        let invite = sample(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        let good = invite.encode().unwrap();
        // Truncation at every boundary yields None, never a partial parse.
        for cut in 0..good.len() {
            assert_eq!(ChannelInvite::decode(&good[..cut]), None, "cut at {cut}");
        }
        // Trailing garbage is rejected (exact-length parse).
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(ChannelInvite::decode(&extra), None);
        // Wrong version byte is rejected.
        let mut bad_version = good.clone();
        bad_version[0] = INVITE_VERSION + 1;
        assert_eq!(ChannelInvite::decode(&bad_version), None);
        // A non-b64url link is rejected without panicking.
        assert_eq!(ChannelInvite::from_link("!!!not base64!!!"), None);
    }

    #[test]
    fn bootstrap_envelope_keeps_v1_bytes_and_public_owner() {
        let invite = sample(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        let legacy = invite.encode().unwrap();
        let bundle = gcoms_routing::bootstrap::BootstrapBundle {
            relays: vec![gcoms_routing::Relay {
                addr: "192.0.2.10:443".parse().unwrap(),
                service_id: [0x10; 32],
                reentry_cap: [0x11; 32],
                circuit_cap: [0x12; 32],
                expires_at: 1_800_000_000,
            }],
        };
        let link = invite.to_link_with_bootstrap(bundle).unwrap();
        let raw = decode_b64url(&link).unwrap();
        assert_eq!(raw[0], 2);
        assert_eq!(&raw[5..5 + legacy.len()], &legacy);
        assert_eq!(ChannelInvite::from_link(&link), Some(invite.clone()));
        let envelope = InviteEnvelope::from_link(&link).unwrap();
        assert!(envelope.invite.owner.provisioning.is_none());
        assert_eq!(envelope.bootstrap.unwrap().relays.len(), 1);
        assert!(InviteEnvelope::from_link(&invite.to_link().unwrap())
            .unwrap()
            .bootstrap
            .is_none());
        for n in 0..raw.len() {
            assert!(InviteEnvelope::decode(&raw[..n]).is_none());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(InviteEnvelope::decode(&trailing).is_none());
        let mut nested = raw.clone();
        nested[5] = BOOTSTRAP_INVITE_VERSION;
        assert!(InviteEnvelope::decode(&nested).is_none());
        let mut overflow = raw;
        overflow[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(InviteEnvelope::decode(&overflow).is_none());
    }
}
