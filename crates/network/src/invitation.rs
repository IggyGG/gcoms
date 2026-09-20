//! Shareable network identity and optional channel access. Accepting an unknown
//! root is an explicit user decision; self-consistent signatures alone do not
//! make an invitation trusted. No Debug implementation may expose bearer tokens.
use super::*;

pub const JOIN_INVITATION_PREFIX: &str = "GCI1-";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub trusted_key_b64: String,
    pub signed_defaults: SignedNetworkDefaults,
}

impl NetworkIdentity {
    pub fn verify_at(&self, now: u64, minimum_sequence: u64) -> Result<NetworkDefaults> {
        self.signed_defaults.verify_at(
            &decode(&self.trusted_key_b64)?,
            &self.signed_defaults.defaults.network_id,
            now,
            minimum_sequence,
        )
    }

    /// Compare trust anchors, not names or mutable provider/relay addresses.
    pub fn same_network(&self, other: &Self) -> bool {
        self.trusted_key_b64 == other.trusted_key_b64
            && self.signed_defaults.defaults.network_id == other.signed_defaults.defaults.network_id
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinInvitation {
    pub version: u8,
    pub network: NetworkIdentity,
    /// An independently issued recipient grant, never the sender's saved grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_invitation: Option<String>,
    /// The node validates the typed channel envelope and its bootstrap authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_invitation: Option<String>,
}

impl JoinInvitation {
    pub fn validate_at(&self, now: u64) -> Result<()> {
        if self.version != 1 {
            return Err("unsupported combined invitation version".into());
        }
        let defaults = self.network.verify_at(now, 0)?;
        if self.network_invitation.is_none() && self.channel_invitation.is_none() {
            return Err("invitation contains no network or channel access".into());
        }
        if let Some(code) = &self.network_invitation {
            let invitation = NetworkInvitation::decode_at(code, now)?;
            if invitation.network_id != defaults.network_id
                || invitation.provider_urls != defaults.provider_urls
            {
                return Err("network grant belongs to different network configuration".into());
            }
        }
        if self
            .channel_invitation
            .as_ref()
            .is_some_and(|code| code.is_empty() || code.len() > MAX_DOCUMENT_BYTES * 4 / 3 + 16)
        {
            return Err("invalid channel invitation size".into());
        }
        Ok(())
    }

    pub fn encode_at(&self, now: u64) -> Result<String> {
        self.validate_at(now)?;
        let bytes = serde_json::to_vec(self).map_err(|_| "invitation encoding failed")?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err("invitation too large".into());
        }
        Ok(format!(
            "{JOIN_INVITATION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    pub fn decode_at(code: &str, now: u64) -> Result<Self> {
        if code.len() > MAX_DOCUMENT_BYTES * 4 / 3 + 16 {
            return Err("invitation too large".into());
        }
        let bytes = decode(
            code.strip_prefix(JOIN_INVITATION_PREFIX)
                .ok_or("not a combined invitation")?,
        )?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err("invitation too large".into());
        }
        let invitation: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid combined invitation")?;
        invitation.validate_at(now)?;
        Ok(invitation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invitation() -> JoinInvitation {
        let key = IdentityKeypair::from_seed([91; 32]);
        JoinInvitation {
            version: 1,
            network: NetworkIdentity {
                trusted_key_b64: URL_SAFE_NO_PAD.encode(key.public_bytes()),
                signed_defaults: SignedNetworkDefaults::sign(
                    super::super::tests::defaults(),
                    &key,
                    vec![],
                )
                .unwrap(),
            },
            network_invitation: None,
            channel_invitation: Some("opaque-channel-envelope".into()),
        }
    }

    #[test]
    fn combined_invite_binds_trust_and_preserves_opaque_channel() {
        let invitation = invitation();
        let encoded = invitation.encode_at(200).unwrap();
        let decoded = JoinInvitation::decode_at(&encoded, 200).unwrap();
        assert!(decoded.network.same_network(&invitation.network));
        assert_eq!(decoded.channel_invitation, invitation.channel_invitation);
        assert!(decoded.network_invitation.is_none());
        assert!(JoinInvitation::decode_at(&encoded, 1000).is_err());
        assert!(JoinInvitation::decode_at(&format!("{encoded}="), 200).is_err());
        let mut tampered = invitation.clone();
        tampered.network.signed_defaults.defaults.provider_urls[0] =
            "https://attacker.example/".into();
        assert!(tampered.encode_at(200).is_err());
        let mut other = invitation.network.clone();
        other.trusted_key_b64 =
            URL_SAFE_NO_PAD.encode(IdentityKeypair::from_seed([92; 32]).public_bytes());
        assert!(!other.same_network(&invitation.network));
        assert!(other.verify_at(200, 0).is_err());
    }

    #[test]
    fn combined_invite_rejects_cross_network_grants_and_empty_access() {
        let mut invitation = invitation();
        invitation.channel_invitation = None;
        assert!(invitation.encode_at(200).is_err());
        let mut grant = NetworkInvitation {
            version: 1,
            network_id: "elsewhere.example".into(),
            provider_urls: invitation
                .network
                .signed_defaults
                .defaults
                .provider_urls
                .clone(),
            grant: URL_SAFE_NO_PAD.encode([42; 32]),
            expires_at: 900,
        };
        invitation.network_invitation = Some(grant.encode().unwrap());
        assert!(invitation.encode_at(200).is_err());
        grant.network_id = invitation
            .network
            .signed_defaults
            .defaults
            .network_id
            .clone();
        invitation.network_invitation = Some(grant.encode().unwrap());
        assert!(invitation.encode_at(200).is_ok());
        assert!(invitation.encode_at(900).is_err());
    }
}
