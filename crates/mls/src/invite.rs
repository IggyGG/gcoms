use gcoms_crypto::{verify_signature, IdentityKeypair};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub post: bool,
    pub invite: bool,
    pub admin: bool,
}

impl Caps {
    pub const fn member() -> Self {
        Caps {
            post: true,
            invite: false,
            admin: false,
        }
    }

    pub const fn admin() -> Self {
        Caps {
            post: true,
            invite: true,
            admin: false,
        }
    }

    pub const fn owner() -> Self {
        Caps {
            post: true,
            invite: true,
            admin: true,
        }
    }

    pub fn encode(&self) -> u8 {
        (self.post as u8) | ((self.invite as u8) << 1) | ((self.admin as u8) << 2)
    }

    pub fn decode(b: u8) -> Self {
        Caps {
            post: b & 1 != 0,
            invite: b & 2 != 0,
            admin: b & 4 != 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub channel: Vec<u8>,
    pub leaf: [u8; 32],
    pub name: String,
    pub caps: Caps,
    pub expiry: u64,
    pub sig: Vec<u8>,
}

impl Invite {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"gc1/invite");
        v.extend_from_slice(&self.channel);
        v.extend_from_slice(&self.leaf);
        v.extend_from_slice(self.name.as_bytes());
        v.push(self.caps.encode());
        v.extend_from_slice(&self.expiry.to_be_bytes());
        v
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(self.channel.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.channel);
        v.extend_from_slice(&self.leaf);
        v.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        v.extend_from_slice(self.name.as_bytes());
        v.push(self.caps.encode());
        v.extend_from_slice(&self.expiry.to_be_bytes());
        v.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        fn take(buf: &[u8], p: &mut usize, n: usize) -> Option<Vec<u8>> {
            if buf.len() < *p + n {
                return None;
            }
            let out = buf[*p..*p + n].to_vec();
            *p += n;
            Some(out)
        }
        let mut p = 0;
        let clen = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
        p += 2;
        let channel = take(buf, &mut p, clen)?;
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&take(buf, &mut p, 32)?);
        let nlen = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
        p += 2;
        let name = String::from_utf8(take(buf, &mut p, nlen)?).ok()?;
        let caps = Caps::decode(*buf.get(p)?);
        p += 1;
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&take(buf, &mut p, 8)?);
        let expiry = u64::from_be_bytes(expiry);
        let slen = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
        p += 2;
        let sig = take(buf, &mut p, slen)?;
        Some(Invite {
            channel,
            leaf,
            name,
            caps,
            expiry,
            sig,
        })
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn sign_invite(
    identity: &IdentityKeypair,
    leaf: &[u8; 32],
    name: &str,
    caps: Caps,
    ttl_secs: u64,
) -> Invite {
    let unsigned = Invite {
        channel: identity.public_bytes(),
        leaf: *leaf,
        name: name.to_string(),
        caps,
        expiry: now_unix().saturating_add(ttl_secs),
        sig: Vec::new(),
    };
    let sig = identity.sign(&unsigned.signing_payload());
    Invite { sig, ..unsigned }
}

pub fn verify_invite(invite: &Invite) -> Result<(), &'static str> {
    if invite.expiry <= now_unix() {
        return Err("expired");
    }
    if !verify_signature(&invite.channel, &invite.signing_payload(), &invite.sig) {
        return Err("signature");
    }
    Ok(())
}

pub fn leaf_hash(key_package_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"gc1/leaf");
    h.update(key_package_bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_roundtrip() {
        for caps in [Caps::member(), Caps::admin(), Caps::owner()] {
            assert_eq!(Caps::decode(caps.encode()), caps);
        }
    }

    #[test]
    fn invite_signs_and_verifies() {
        let owner = IdentityKeypair::from_seed([0x0F; 32]);
        let leaf = [9u8; 32];
        let invite = sign_invite(&owner, &leaf, "redwing", Caps::member(), 3600);
        assert!(verify_invite(&invite).is_ok());
    }

    #[test]
    fn invite_expiry_rejected() {
        let owner = IdentityKeypair::from_seed([0x0F; 32]);
        let mut invite = sign_invite(&owner, &[9u8; 32], "x", Caps::member(), 0);
        invite.expiry = now_unix() + 3600;
        invite.expiry -= 7200;
        assert_eq!(verify_invite(&invite), Err("expired"));
    }

    #[test]
    fn invite_tamper_rejected() {
        let owner = IdentityKeypair::from_seed([0x0F; 32]);
        let mut invite = sign_invite(&owner, &[9u8; 32], "x", Caps::member(), 3600);
        invite.name.push('!');
        assert_eq!(verify_invite(&invite), Err("signature"));
    }

    #[test]
    fn invite_encoding_roundtrip() {
        let owner = IdentityKeypair::from_seed([0x0F; 32]);
        let invite = sign_invite(&owner, &[7u8; 32], "nest", Caps::admin(), 99);
        let dec = Invite::decode(&invite.encode()).unwrap();
        assert_eq!(dec, invite);
    }
}
