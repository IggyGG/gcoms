//! Compact bearer invitations and short-lived, owner-signed encrypted locators.
//! A provider stores ciphertext and cannot admit a member or extend a relay lease.
use super::*;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const PREFIX: &str = "GCIR1-";
pub const LINK_PREFIX: &str = "gcoms://join#GCIR1-";
pub const MAX_DESCRIPTOR_BYTES: usize = 512 * 1024;
pub const MAX_LIFETIME: u64 = 300;
const DOMAIN: &[u8] = b"gcoms/invitation-descriptor/v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub version: u8,
    pub network_id: String,
    pub network_key_hash: String,
    pub issuer_key_hash: String,
    pub channel_id: String,
    pub providers: Vec<String>,
    pub id: String,
    pub secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Reference, ResolvedInvitation, IdentityKeypair) {
        let root = IdentityKeypair::from_seed([61; 32]);
        let issuer = IdentityKeypair::from_seed([62; 32]);
        let network = NetworkIdentity {
            trusted_key_b64: URL_SAFE_NO_PAD.encode(root.public_bytes()),
            signed_defaults: SignedNetworkDefaults::sign(crate::tests::defaults(), &root, vec![])
                .unwrap(),
        };
        let reference =
            Reference::new(&network, &issuer.public_bytes(), [3; 32], [4; 16], [5; 32]).unwrap();
        let value = ResolvedInvitation {
            network,
            channel_id: reference.channel_id.clone(),
            channel_invitation: "private admission and route bytes".into(),
        };
        (reference, value, issuer)
    }
    #[test]
    fn compact_locator_pins_every_authority_and_never_contains_plaintext() {
        let (reference, value, issuer) = fixture();
        let link = reference.encode().unwrap();
        assert!(link.len() < 2048);
        let reference = Reference::decode(&link).unwrap();
        let descriptor = Descriptor::seal(&reference, &value, &issuer, 7, 200, 500).unwrap();
        let stored = serde_json::to_string(&descriptor).unwrap();
        assert!(!stored.contains(&reference.secret));
        assert!(!stored.contains(&value.channel_invitation));
        assert_eq!(
            descriptor
                .open(&reference, 201, 7)
                .unwrap()
                .channel_invitation,
            value.channel_invitation
        );
        assert!(descriptor.open(&reference, 201, 8).is_err());
        assert!(descriptor.open(&reference, 500, 0).is_err());
        for field in [
            "secret",
            "network_key_hash",
            "issuer_key_hash",
            "channel_id",
        ] {
            let mut other = reference.clone();
            let wrong = URL_SAFE_NO_PAD.encode([9; 32]);
            match field {
                "secret" => other.secret = wrong,
                "network_key_hash" => other.network_key_hash = wrong,
                "issuer_key_hash" => other.issuer_key_hash = wrong,
                _ => other.channel_id = wrong,
            }
            assert!(descriptor.open(&other, 201, 0).is_err(), "{field}");
        }
        let mut forged = descriptor.clone();
        forged.body.sequence += 1;
        assert!(forged.open(&reference, 201, 0).is_err());
        assert!(Descriptor::seal(&reference, &value, &issuer, 8, 200, 501).is_err());
        assert!(Reference::decode(&format!("{link}?secret=x")).is_err());
    }
}
impl Drop for Reference {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl Reference {
    pub fn new(
        network: &NetworkIdentity,
        issuer: &[u8],
        channel_id: [u8; 32],
        id: [u8; 16],
        secret: [u8; 32],
    ) -> Result<Self> {
        let value = Self {
            version: 1,
            network_id: network.signed_defaults.defaults.network_id.clone(),
            network_key_hash: URL_SAFE_NO_PAD
                .encode(Sha256::digest(decode(&network.trusted_key_b64)?)),
            issuer_key_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(issuer)),
            channel_id: URL_SAFE_NO_PAD.encode(channel_id),
            providers: network.signed_defaults.defaults.provider_urls.clone(),
            id: URL_SAFE_NO_PAD.encode(id),
            secret: URL_SAFE_NO_PAD.encode(secret),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.network_id.is_empty()
            || self.network_id.len() > 128
            || decode(&self.network_key_hash)?.len() != 32
            || decode(&self.issuer_key_hash)?.len() != 32
            || decode(&self.channel_id)?.len() != 32
            || decode(&self.id)?.len() != 16
            || decode(&self.secret)?.len() != 32
        {
            return Err("invalid reusable invitation".into());
        }
        validate_provider_urls(&self.providers)
    }
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| "invalid invitation")?);
        let code = format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(&bytes));
        if code.len() > 2048 {
            return Err("compact invitation is too large".into());
        }
        Ok(code)
    }
    pub fn decode(code: &str) -> Result<Self> {
        let code = code.trim();
        if code.len() > 2048 {
            return Err("compact invitation is too large".into());
        }
        let raw = code
            .strip_prefix(LINK_PREFIX)
            .or_else(|| code.strip_prefix(PREFIX))
            .ok_or("not a reusable invitation")?;
        let bytes = Zeroizing::new(decode(raw)?);
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid reusable invitation")?;
        value.validate()?;
        Ok(value)
    }
    pub fn is_reference(code: &str) -> bool {
        code.trim().starts_with(PREFIX) || code.trim().starts_with(LINK_PREFIX)
    }
    fn key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let secret = Zeroizing::new(decode(&self.secret)?);
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(Some(self.id.as_bytes()), &secret)
            .expand(DOMAIN, key.as_mut())
            .map_err(|_| "invitation key derivation failed")?;
        Ok(key)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorBody {
    pub version: u8,
    pub network_id: String,
    pub id: String,
    pub issuer_key: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub ciphertext: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub body: DescriptorBody,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedInvitation {
    pub network: NetworkIdentity,
    pub channel_id: String,
    pub channel_invitation: String,
}
impl Drop for ResolvedInvitation {
    fn drop(&mut self) {
        self.channel_invitation.zeroize();
    }
}
impl Descriptor {
    pub fn verify(&self, now: u64) -> Result<()> {
        let b = &self.body;
        if b.version != 1
            || b.sequence == 0
            || b.network_id.is_empty()
            || b.network_id.len() > 128
            || b.issued_at > now.saturating_add(30)
            || b.expires_at <= now
            || b.expires_at <= b.issued_at
            || b.expires_at - b.issued_at > MAX_LIFETIME
            || decode(&b.id)?.len() != 16
            || b.ciphertext.len() > MAX_DESCRIPTOR_BYTES * 2 / 3
        {
            return Err("invalid or expired invitation descriptor".into());
        }
        let key = decode(&b.issuer_key)?;
        if !verify_signature(&key, &signed_bytes(DOMAIN, b)?, &decode(&self.signature)?) {
            return Err("invitation owner signature mismatch".into());
        }
        Ok(())
    }
    pub fn seal(
        reference: &Reference,
        value: &ResolvedInvitation,
        issuer: &IdentityKeypair,
        sequence: u64,
        now: u64,
        expires_at: u64,
    ) -> Result<Self> {
        reference.validate()?;
        if reference.issuer_key_hash
            != URL_SAFE_NO_PAD.encode(Sha256::digest(issuer.public_bytes()))
        {
            return Err("invitation issuer mismatch".into());
        }
        let plain =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| "invalid invitation descriptor")?);
        if plain.len() > MAX_DOCUMENT_BYTES {
            return Err("invitation descriptor too large".into());
        }
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let key = reference.key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| "invalid key")?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: reference.id.as_bytes(),
                },
            )
            .map_err(|_| "invitation encryption failed")?;
        let mut ciphertext = nonce.to_vec();
        ciphertext.extend(cipher);
        let body = DescriptorBody {
            version: 1,
            network_id: reference.network_id.clone(),
            id: reference.id.clone(),
            issuer_key: URL_SAFE_NO_PAD.encode(issuer.public_bytes()),
            sequence,
            issued_at: now,
            expires_at,
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let signature = URL_SAFE_NO_PAD.encode(issuer.sign(&signed_bytes(DOMAIN, &body)?));
        let result = Self { body, signature };
        result.verify(now)?;
        Ok(result)
    }
    pub fn open(
        &self,
        reference: &Reference,
        now: u64,
        minimum_sequence: u64,
    ) -> Result<ResolvedInvitation> {
        reference.validate()?;
        self.verify(now)?;
        let b = &self.body;
        if b.id != reference.id
            || b.network_id != reference.network_id
            || b.sequence < minimum_sequence
            || URL_SAFE_NO_PAD.encode(Sha256::digest(decode(&b.issuer_key)?))
                != reference.issuer_key_hash
        {
            return Err("invitation descriptor binding or sequence mismatch".into());
        }
        let ciphertext = decode(&b.ciphertext)?;
        if ciphertext.len() < 28 {
            return Err("invalid invitation ciphertext".into());
        }
        let key = reference.key()?;
        let plain = Zeroizing::new(
            Aes256Gcm::new_from_slice(key.as_ref())
                .map_err(|_| "invalid key")?
                .decrypt(
                    Nonce::from_slice(&ciphertext[..12]),
                    Payload {
                        msg: &ciphertext[12..],
                        aad: b.id.as_bytes(),
                    },
                )
                .map_err(|_| "invitation cannot be decrypted")?,
        );
        if plain.len() > MAX_DOCUMENT_BYTES {
            return Err("invitation descriptor too large".into());
        }
        let value: ResolvedInvitation =
            serde_json::from_slice(&plain).map_err(|_| "invalid invitation descriptor")?;
        if value.channel_id != reference.channel_id
            || value.network.signed_defaults.defaults.network_id != reference.network_id
            || URL_SAFE_NO_PAD.encode(Sha256::digest(decode(&value.network.trusted_key_b64)?))
                != reference.network_key_hash
        {
            return Err("invitation network pin mismatch".into());
        }
        value.network.verify_at(now, 0)?;
        Ok(value)
    }
}
