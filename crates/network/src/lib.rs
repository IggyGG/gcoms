//! Public configuration is independently signed. Invitations carry only a scoped
//! network grant and never replace a GC identity, channel invitation, or profile.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_crypto::{verify_signature, IdentityKeypair};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

mod invitation;
pub use invitation::{JoinInvitation, NetworkIdentity, JOIN_INVITATION_PREFIX};

pub const INVITATION_PREFIX: &str = "GCNI1-";
pub const MAX_DOCUMENT_BYTES: usize = 128 * 1024;
const DEFAULTS_DOMAIN: &[u8] = b"gc/network/defaults/v1\0";
const ROTATION_DOMAIN: &[u8] = b"gc/network/signing-key/v1\0";
pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Founder {
    pub name: String,
    pub service_id: [u8; 32],
    pub address_hints: Vec<SocketAddr>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDefaults {
    pub version: u8,
    pub network_id: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub provider_urls: Vec<String>,
    pub founders: Vec<Founder>,
    pub dns_domain: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyTransition {
    pub new_key_b64: String,
    pub network_id: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub signature_b64: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkDefaults {
    pub defaults: NetworkDefaults,
    #[serde(default)]
    pub key_transitions: Vec<SigningKeyTransition>,
    pub signature_b64: String,
}
/// No Debug implementation: printing an invitation must not expose the grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInvitation {
    pub version: u8,
    pub network_id: String,
    pub provider_urls: Vec<String>,
    pub grant: String,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterNameRequest {
    pub request_id: String,
    pub credential_b64: String,
    /// GCRB1 containing exactly the listener being registered. Private, HTTPS only.
    pub routing_bundle_b64: String,
    pub server_label: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateNameRequest {
    pub sequence: u64,
    pub routing_bundle_b64: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveNameRequest {
    pub sequence: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameResponse {
    pub node_handle: String,
    pub fqdn: String,
    pub sequence: u64,
    pub lease_expires_at: u64,
    pub published: bool,
}
fn signed_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|_| "invalid document")?);
    Ok(bytes)
}
fn decode(text: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| "invalid base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err("noncanonical base64url".into());
    }
    Ok(bytes)
}
pub fn validate_provider_urls(urls: &[String]) -> Result<()> {
    if urls.is_empty() || urls.len() > 8 {
        return Err("one to eight HTTPS providers required".into());
    }
    for raw in urls {
        let url = url::Url::parse(raw).map_err(|_| "invalid provider URL")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.port_or_known_default() != Some(443)
        {
            return Err("providers must be HTTPS origins on port 443".into());
        }
    }
    Ok(())
}
impl NetworkDefaults {
    pub fn validate_at(&self, now: u64, minimum_sequence: u64) -> Result<()> {
        if self.version != 1
            || self.network_id.is_empty()
            || self.network_id.len() > 128
            || self.sequence < minimum_sequence
            || self.issued_at > now.saturating_add(300)
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.dns_domain != self.network_id
            || self.founders.is_empty()
            || self.founders.len() > 8
        {
            return Err("invalid, stale or expired network defaults".into());
        }
        validate_provider_urls(&self.provider_urls)?;
        for (index, founder) in self.founders.iter().enumerate() {
            if founder.name != format!("r{}.relays.{}", index + 1, self.dns_domain)
                || founder.service_id == [0; 32]
                || founder.address_hints.is_empty()
                || founder.address_hints.len() > 2
                || founder.address_hints.iter().any(|addr| addr.port() == 0)
                || self.founders[..index]
                    .iter()
                    .any(|old| old.service_id == founder.service_id)
            {
                return Err("invalid founder public identity or address hints".into());
            }
        }
        Ok(())
    }
}
impl SigningKeyTransition {
    pub fn sign(
        network_id: String,
        not_before: u64,
        expires_at: u64,
        new_key: &[u8],
        old: &IdentityKeypair,
    ) -> Result<Self> {
        let mut value = Self {
            new_key_b64: URL_SAFE_NO_PAD.encode(new_key),
            network_id,
            not_before,
            expires_at,
            signature_b64: String::new(),
        };
        value.signature_b64 = URL_SAFE_NO_PAD.encode(old.sign(&value.message()?));
        Ok(value)
    }
    fn message(&self) -> Result<Vec<u8>> {
        signed_bytes(
            ROTATION_DOMAIN,
            &(
                &self.network_id,
                self.not_before,
                self.expires_at,
                &self.new_key_b64,
            ),
        )
    }
}
impl SignedNetworkDefaults {
    pub fn sign(
        defaults: NetworkDefaults,
        signer: &IdentityKeypair,
        key_transitions: Vec<SigningKeyTransition>,
    ) -> Result<Self> {
        let signature_b64 =
            URL_SAFE_NO_PAD.encode(signer.sign(&signed_bytes(DEFAULTS_DOMAIN, &defaults)?));
        Ok(Self {
            defaults,
            key_transitions,
            signature_b64,
        })
    }
    /// `trusted_key` comes from the installer/profile, never this document or DNS.
    /// Persist the returned sequence alongside the existing profile to prevent rollback.
    pub fn verify_at(
        &self,
        trusted_key: &[u8],
        network_id: &str,
        now: u64,
        minimum_sequence: u64,
    ) -> Result<NetworkDefaults> {
        if self.defaults.network_id != network_id || self.key_transitions.len() > 8 {
            return Err("network trust mismatch".into());
        }
        self.defaults.validate_at(now, minimum_sequence)?;
        let mut key = trusted_key.to_vec();
        for transition in &self.key_transitions {
            if transition.network_id != network_id
                || transition.not_before > now
                || transition.expires_at <= now
                || !verify_signature(
                    &key,
                    &transition.message()?,
                    &decode(&transition.signature_b64)?,
                )
            {
                return Err("invalid network signing key transition".into());
            }
            key = decode(&transition.new_key_b64)?;
        }
        if !verify_signature(
            &key,
            &signed_bytes(DEFAULTS_DOMAIN, &self.defaults)?,
            &decode(&self.signature_b64)?,
        ) {
            return Err("invalid network defaults signature".into());
        }
        Ok(self.defaults.clone())
    }
}
impl NetworkInvitation {
    pub fn encode(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self).map_err(|_| "invalid invitation")?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err("invitation too large".into());
        }
        Ok(format!(
            "{INVITATION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    }
    pub fn decode_at(code: &str, now: u64) -> Result<Self> {
        if code.len() > MAX_DOCUMENT_BYTES * 4 / 3 + 16 {
            return Err("invitation too large".into());
        }
        let bytes = decode(
            code.strip_prefix(INVITATION_PREFIX)
                .ok_or("not a network invitation")?,
        )?;
        let invitation: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid invitation envelope")?;
        if invitation.version != 1
            || invitation.network_id.is_empty()
            || invitation.network_id.len() > 128
            || invitation.expires_at <= now
            || decode(&invitation.grant)?.len() != 32
        {
            return Err("invalid or expired network invitation".into());
        }
        validate_provider_urls(&invitation.provider_urls)?;
        Ok(invitation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn defaults() -> NetworkDefaults {
        NetworkDefaults {
            version: 1,
            network_id: "gchat.boo".into(),
            sequence: 4,
            issued_at: 100,
            expires_at: 1000,
            provider_urls: vec!["https://bootstrap-hel.gchat.boo/".into()],
            founders: vec![Founder {
                name: "r1.relays.gchat.boo".into(),
                service_id: [1; 32],
                address_hints: vec!["8.8.8.8:4433".parse().unwrap()],
            }],
            dns_domain: "gchat.boo".into(),
        }
    }
    #[test]
    fn independent_trust_rotation_tamper_and_rollback() {
        let root = IdentityKeypair::from_seed([1; 32]);
        let next = IdentityKeypair::from_seed([2; 32]);
        let transition =
            SigningKeyTransition::sign("gchat.boo".into(), 100, 1000, &next.public_bytes(), &root)
                .unwrap();
        let signed = SignedNetworkDefaults::sign(defaults(), &next, vec![transition]).unwrap();
        assert!(signed
            .verify_at(&root.public_bytes(), "gchat.boo", 200, 4)
            .is_ok());
        assert!(signed
            .verify_at(&next.public_bytes(), "gchat.boo", 200, 4)
            .is_err());
        assert!(signed
            .verify_at(&root.public_bytes(), "gchat.boo", 200, 5)
            .is_err());
        assert!(signed
            .verify_at(&root.public_bytes(), "gchat.boo", 1000, 4)
            .is_err());
        let mut altered = signed;
        altered.defaults.provider_urls[0] = "https://attacker.example/".into();
        assert!(altered
            .verify_at(&root.public_bytes(), "gchat.boo", 200, 4)
            .is_err());
    }
    #[test]
    fn network_envelope_is_distinct_and_bounded() {
        let invite = NetworkInvitation {
            version: 1,
            network_id: "gchat.boo".into(),
            provider_urls: defaults().provider_urls,
            grant: URL_SAFE_NO_PAD.encode([3; 32]),
            expires_at: 1000,
        };
        let code = invite.encode().unwrap();
        assert!(NetworkInvitation::decode_at(&code, 200).is_ok());
        assert!(NetworkInvitation::decode_at(&code, 1000).is_err());
        assert!(NetworkInvitation::decode_at("GCRB1anything", 200).is_err());
        assert!(NetworkInvitation::decode_at(&format!("{code}="), 200).is_err());
    }
}
