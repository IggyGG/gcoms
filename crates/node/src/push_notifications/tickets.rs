//! Registration authority is independent from notification event authentication.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REQUEST_DOMAIN: &[u8] = b"GCOMS-PUSH-REGISTER-REQUEST-v2\0";
const ADMIN_DOMAIN: &[u8] = b"GCOMS-PUSH-REGISTER-ADMIN-v2\0";
const INSTALLATION_DOMAIN: &[u8] = b"GCOMS-PUSH-INSTALLATION-v2\0";
#[cfg(feature = "push-gateway")]
const TICKET_DOMAIN: &[u8] = b"GCOMS-PUSH-RELAY-TICKET-v2\0";
const MAX_REQUEST: usize = 12 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    Apns,
    Fcm,
}

/// Persist a random nonce per installation and increment revision before each
/// new registration. Tokens are hashed before entering relay control traffic.
#[derive(Clone)]
pub struct PushRegistrationRequest {
    pub app_id: String,
    pub installation_nonce: [u8; 32],
    pub platform: PushPlatform,
    pub token: String,
    pub revision: u64,
    pub visible: bool,
}

/// Use this one-use ticket at `gateway_origin + "/v1/register"`, or at
/// `/v1/unregister` when obtained through `request_push_revocation`.
/// An ambiguous HTTP result requires a new durably incremented revision.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationTicket {
    pub ticket: String,
    pub gateway_origin: String,
    pub installation: String,
    pub expires: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TicketPurpose {
    Register,
    Unregister,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TicketRequest {
    pub purpose: TicketPurpose,
    pub app: String,
    pub installation_nonce: [u8; 32],
    pub platform: PushPlatform,
    pub token_sha256: [u8; 32],
    pub revision: u64,
    pub visible: bool,
    pub expires: u64,
    pub nonce: [u8; 16],
    pub identity: String,
    pub signature: String,
}

pub(crate) fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl TicketRequest {
    pub(crate) fn new(
        request: PushRegistrationRequest,
        identity: &[u8],
        expires: u64,
        nonce: [u8; 16],
    ) -> Result<Self, String> {
        if !valid_name(&request.app_id)
            || request.installation_nonce == [0; 32]
            || request.revision == 0
            || request.revision > i64::MAX as u64
            || request.token.is_empty()
            || request.token.len() > 4096
            || !request.token.bytes().all(|b| (33..=126).contains(&b))
            || (request.platform == PushPlatform::Apns
                && (request.token.len() < 32
                    || request.token.len() > 256
                    || !request.token.len().is_multiple_of(2)
                    || !request.token.bytes().all(|b| b.is_ascii_hexdigit())))
        {
            return Err("invalid push registration scope".into());
        }
        Ok(Self {
            purpose: TicketPurpose::Register,
            app: request.app_id,
            installation_nonce: request.installation_nonce,
            platform: request.platform,
            token_sha256: Sha256::digest(request.token.as_bytes()).into(),
            revision: request.revision,
            visible: request.visible,
            expires,
            nonce,
            identity: gcoms_transport::encode_b64url(identity),
            signature: String::new(),
        })
    }
    pub(crate) fn revoke(&mut self) -> Result<(), String> {
        if self.visible {
            return Err("push revocation cannot request an alert".into());
        }
        self.purpose = TicketPurpose::Unregister;
        Ok(())
    }
    pub(crate) fn digest(
        &self,
        queue: &[u8; 32],
        epoch: u64,
        service: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let body = serde_json::to_vec(&unsigned).map_err(|_| "invalid push request")?;
        let mut digest = Sha256::new();
        digest.update(REQUEST_DOMAIN);
        digest.update(service);
        digest.update(queue);
        digest.update(epoch.to_be_bytes());
        digest.update(body);
        Ok(digest.finalize().into())
    }
    pub(crate) fn installation(&self) -> Result<String, String> {
        let identity = gcoms_transport::decode_b64url(&self.identity).ok_or("invalid identity")?;
        let mut hash = Sha256::new();
        hash.update(INSTALLATION_DOMAIN);
        hash.update((self.app.len() as u32).to_be_bytes());
        hash.update(self.app.as_bytes());
        hash.update(identity);
        hash.update(self.installation_nonce);
        Ok(hex(&hash.finalize()))
    }
    pub(crate) fn encode(
        &self,
        queue: &[u8; 32],
        epoch: u64,
        admin: &[u8; 32],
        service: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let mut wire = vec![1, super::OP_PUSH_REGISTRATION];
        wire.extend_from_slice(queue);
        wire.extend_from_slice(&epoch.to_be_bytes());
        wire.extend_from_slice(&serde_json::to_vec(self).map_err(|_| "invalid push request")?);
        let mut mac = Hmac::<Sha256>::new_from_slice(admin).map_err(|_| "invalid admin key")?;
        mac.update(ADMIN_DOMAIN);
        mac.update(service);
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        if wire.len() > MAX_REQUEST {
            return Err("push request exceeds control bound".into());
        }
        Ok(wire)
    }
    #[cfg(any(test, feature = "push-gateway"))]
    pub(crate) fn authenticate(
        wire: &[u8],
        epoch: u64,
        admin: &[u8; 32],
        service: &[u8; 32],
        now: u64,
    ) -> Result<Self, String> {
        if !(75..=MAX_REQUEST).contains(&wire.len())
            || wire[..2] != [1, super::OP_PUSH_REGISTRATION]
            || wire[34..42] != epoch.to_be_bytes()
        {
            return Err("invalid push request".into());
        }
        let end = wire.len() - 32;
        let mut mac = Hmac::<Sha256>::new_from_slice(admin).map_err(|_| "invalid admin key")?;
        mac.update(ADMIN_DOMAIN);
        mac.update(service);
        mac.update(&wire[..end]);
        mac.verify_slice(&wire[end..])
            .map_err(|_| "unauthorized push request")?;
        let value: Self =
            serde_json::from_slice(&wire[42..end]).map_err(|_| "invalid push request")?;
        if (value.purpose == TicketPurpose::Unregister && value.visible)
            || !valid_name(&value.app)
            || value.installation_nonce == [0; 32]
            || value.nonce == [0; 16]
            || value.revision == 0
            || value.revision > i64::MAX as u64
            || value.expires <= now
            || value.expires > now.saturating_add(300)
        {
            return Err("invalid push request scope or expiry".into());
        }
        Ok(value)
    }
    #[cfg(any(test, feature = "push-gateway"))]
    pub(crate) fn verify_identity(
        &self,
        queue: &[u8; 32],
        epoch: u64,
        service: &[u8; 32],
    ) -> Result<(), String> {
        let identity = gcoms_transport::decode_b64url(&self.identity).ok_or("invalid identity")?;
        let signature =
            gcoms_transport::decode_b64url(&self.signature).ok_or("invalid identity proof")?;
        let digest = self.digest(queue, epoch, service)?;
        if !gcoms_crypto::identity::verify_signature(
            &identity,
            &gcoms_core::identity_digest_signature_payload(&digest),
            &signature,
        ) {
            return Err("invalid push identity proof".into());
        }
        Ok(())
    }
    #[cfg(test)]
    fn verify(
        wire: &[u8],
        epoch: u64,
        admin: &[u8; 32],
        service: &[u8; 32],
        now: u64,
    ) -> Result<Self, String> {
        let value = Self::authenticate(wire, epoch, admin, service, now)?;
        let queue = wire[2..34].try_into().map_err(|_| "invalid queue")?;
        value.verify_identity(&queue, epoch, service)?;
        Ok(value)
    }
}

#[cfg(feature = "push-gateway")]
pub(crate) struct TicketIssuer {
    pub origin: String,
    pub relay_id: String,
    pub apps: Vec<String>,
    pub key: [u8; 32],
}
#[cfg(feature = "push-gateway")]
impl Drop for TicketIssuer {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
#[cfg(feature = "push-gateway")]
impl TicketIssuer {
    pub(crate) fn issue(
        &self,
        request: &TicketRequest,
        now: u64,
    ) -> Result<PushRegistrationTicket, String> {
        if !self.apps.contains(&request.app) {
            return Err("push application is not configured".into());
        }
        let installation = request.installation()?;
        let body = serde_json::to_vec(&serde_json::json!({
            "version": 2, "purpose": request.purpose, "issuer": self.relay_id, "app": request.app,
            "installation": installation, "issued": now, "expires": request.expires,
            "nonce": hex(&request.nonce), "revision": request.revision,
            "platform": request.platform, "token_sha256": hex(&request.token_sha256),
            "gateway_origin": self.origin, "visible": request.visible,
        }))
        .map_err(|_| "push ticket encoding failed")?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| "invalid gateway key")?;
        mac.update(TICKET_DOMAIN);
        mac.update(&body);
        Ok(PushRegistrationTicket {
            ticket: format!(
                "{}.{}",
                gcoms_transport::encode_b64url(&body),
                hex(&mac.finalize().into_bytes())
            ),
            gateway_origin: self.origin.clone(),
            installation,
            expires: request.expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn signed(nonce: u8) -> TicketRequest {
        let identity = gcoms_crypto::identity::IdentityKeypair::from_seed([8; 32]);
        let mut request = TicketRequest::new(
            PushRegistrationRequest {
                app_id: "boo.gchat.app".into(),
                installation_nonce: [7; 32],
                platform: PushPlatform::Fcm,
                token: "private-token".into(),
                revision: 1,
                visible: true,
            },
            &identity.public_bytes(),
            1200,
            [nonce; 16],
        )
        .unwrap();
        let digest = request.digest(&[1; 32], 1, &[9; 32]).unwrap();
        request.signature = gcoms_transport::encode_b64url(
            &identity.sign(&gcoms_core::identity_digest_signature_payload(&digest)),
        );
        request
    }
    #[test]
    fn ticket_request_requires_lease_admin_and_identity_and_fits_existing_cell() {
        let request = signed(3);
        let wire = request.encode(&[1; 32], 1, &[7; 32], &[9; 32]).unwrap();
        let cell = gcoms_core::Cell::new(gcoms_core::CellType::RelaySub, 0, 0, wire.clone());
        assert!(cell.encode_wire().is_ok());
        assert!(wire.len() < MAX_REQUEST);
        assert!(!wire.windows(13).any(|part| part == b"private-token"));
        TicketRequest::verify(&wire, 1, &[7; 32], &[9; 32], 1000).unwrap();
        for (epoch, admin, service, now) in [
            (2, [7; 32], [9; 32], 1000),
            (1, [5; 32], [9; 32], 1000),
            (1, [7; 32], [8; 32], 1000),
            (1, [7; 32], [9; 32], 1200),
        ] {
            assert!(TicketRequest::verify(&wire, epoch, &admin, &service, now).is_err());
        }
        let mut changed = request.clone();
        changed.visible = false;
        let forged = changed.encode(&[1; 32], 1, &[7; 32], &[9; 32]).unwrap();
        assert!(TicketRequest::verify(&forged, 1, &[7; 32], &[9; 32], 1000).is_err());
        changed = request.clone();
        changed.purpose = TicketPurpose::Unregister;
        changed.visible = false;
        assert!(TicketRequest::verify(
            &changed.encode(&[1; 32], 1, &[7; 32], &[9; 32]).unwrap(),
            1,
            &[7; 32],
            &[9; 32],
            1000
        )
        .is_err());
        changed = request.clone();
        changed.identity = gcoms_transport::encode_b64url(
            &gcoms_crypto::identity::IdentityKeypair::from_seed([2; 32]).public_bytes(),
        );
        assert_ne!(
            changed.installation().unwrap(),
            request.installation().unwrap()
        );
        assert!(TicketRequest::verify(
            &changed.encode(&[1; 32], 1, &[7; 32], &[9; 32]).unwrap(),
            1,
            &[7; 32],
            &[9; 32],
            1000
        )
        .is_err());
    }
    #[cfg(feature = "push-gateway")]
    #[test]
    fn ticket_matches_gateway_interoperability_vector() {
        let request = TicketRequest::new(
            PushRegistrationRequest {
                app_id: "boo.gchat.app".into(),
                installation_nonce: [7; 32],
                platform: PushPlatform::Fcm,
                token: "private-token".into(),
                revision: 1,
                visible: true,
            },
            &[1; 1952],
            1200,
            [3; 16],
        )
        .unwrap();
        let issuer = TicketIssuer {
            origin: "https://push.example".into(),
            relay_id: "r1".into(),
            apps: vec!["boo.gchat.app".into()],
            key: [90; 32],
        };
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("relay-ticket-v2-vector.json")).unwrap();
        assert_eq!(
            issuer.issue(&request, 1000).unwrap().ticket,
            vector["ticket"]
        );
    }
}
