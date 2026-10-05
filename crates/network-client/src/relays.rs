//! Idempotent public relay heartbeats, scoped to installed provider trust.
use super::*;
use gcoms_network::{RelayRegistrationRequest, RelayRegistrationResponse};
use gcoms_routing::gc2::directory::{BootstrapBundle as Gc2Bundle, Introduction};

impl NetworkClient {
    fn relay_authority(&self) -> Result<(NetworkDefaults, NetworkInvitation)> {
        self.transaction(|state| {
            let defaults = self.selected_defaults(state, now_unix())?;
            let invitation = state
                .invitation
                .clone()
                .ok_or("Enter a network invitation to contribute a relay.")?;
            validate_retained_invitation(&invitation, &defaults, now_unix())?;
            Ok((defaults, invitation))
        })
    }

    /// Prepare a claim without exporting the membership bearer to the relay.
    pub fn relay_registration(
        &self,
        introduction: &Introduction,
    ) -> Result<RelayRegistrationRequest> {
        let (defaults, invitation) = self.relay_authority()?;
        let mut hash = Sha256::new();
        hash.update(b"gc/network/grant/v1\0");
        hash.update(canonical_b64(&invitation.grant)?);
        Ok(RelayRegistrationRequest {
            network_id: defaults.network_id,
            grant_id: URL_SAFE_NO_PAD.encode(hash.finalize()),
            expires_at: now_unix().saturating_add(30).min(introduction.expires_at),
            routing_bundle_b64: URL_SAFE_NO_PAD.encode(
                Gc2Bundle {
                    relays: vec![introduction.clone()],
                }
                .encode()
                .map_err(|e| e.to_string())?,
            ),
            certificate_b64: String::new(),
            signature_scheme: 0,
            signature_b64: String::new(),
        })
    }

    /// Renew only this service's independently verified public listener. No DNS
    /// record, private contact or entry guard is sent to the provider.
    pub async fn register_relay(
        &self,
        introduction: &Introduction,
        body: &RelayRegistrationRequest,
        deadline: Instant,
    ) -> Result<u64> {
        introduction.entry(now_unix()).map_err(|e| e.to_string())?;
        let (defaults, invitation) = self.relay_authority()?;
        let expected = self.relay_registration(introduction)?;
        if body.network_id != expected.network_id
            || body.grant_id != expected.grant_id
            || body.routing_bundle_b64 != expected.routing_bundle_b64
            || body.expires_at <= now_unix()
            || body.expires_at > now_unix() + 60
            || body.certificate_b64.is_empty()
            || body.signature_b64.is_empty()
        {
            return Err("relay registration proof is missing or changed its binding".into());
        }
        let mut expiry = None;
        let providers = defaults.provider_urls.len();
        for (index, base) in defaults.provider_urls.into_iter().enumerate() {
            let result =
                tokio::time::timeout_at(provider_deadline(deadline, providers - index), async {
                    let response = self
                        .http
                        .post(format!("{}v1/relays", base))
                        .bearer_auth(&invitation.grant)
                        .json(body)
                        .send()
                        .await
                        .map_err(|_| "relay contribution provider unreachable")?;
                    if !response.status().is_success() {
                        return Err("relay contribution refused".to_string());
                    }
                    let response: RelayRegistrationResponse =
                        serde_json::from_slice(&bounded_body(response).await?)
                            .map_err(|_| "invalid relay contribution receipt")?;
                    if response.service_id != introduction.service_id
                        || response.lease_expires_at <= now_unix()
                        || response.lease_expires_at > now_unix().saturating_add(300)
                        || response.lease_expires_at
                            > introduction.expires_at.min(invitation.expires_at)
                    {
                        return Err("relay contribution receipt changed its authority".to_string());
                    }
                    Ok(response.lease_expires_at)
                })
                .await;
            if let Ok(Ok(until)) = result {
                expiry = Some(expiry.map_or(until, |old: u64| old.min(until)));
            }
        }
        expiry.ok_or_else(|| "relay contribution providers unavailable".into())
    }

    pub async fn remove_relay(&self, service_id: [u8; 32], deadline: Instant) -> Result<()> {
        let (defaults, invitation) = self.relay_authority()?;
        let handle = URL_SAFE_NO_PAD.encode(service_id);
        let mut complete = true;
        let providers = defaults.provider_urls.len();
        for (index, base) in defaults.provider_urls.into_iter().enumerate() {
            let result =
                tokio::time::timeout_at(provider_deadline(deadline, providers - index), async {
                    let response = self
                        .http
                        .delete(format!("{}v1/relays/{handle}", base))
                        .bearer_auth(&invitation.grant)
                        .send()
                        .await
                        .map_err(|_| "relay withdrawal unreachable")?;
                    if !response.status().is_success() {
                        return Err("relay withdrawal refused".to_string());
                    }
                    let response: serde_json::Value =
                        serde_json::from_slice(&bounded_body(response).await?)
                            .map_err(|_| "invalid relay withdrawal receipt")?;
                    if response.get("removed").and_then(serde_json::Value::as_bool) != Some(true) {
                        return Err("relay withdrawal not confirmed".to_string());
                    }
                    Ok(())
                })
                .await;
            complete &= matches!(result, Ok(Ok(())));
        }
        if complete {
            Ok(())
        } else {
            Err("relay withdrawal pending; leases expire automatically".into())
        }
    }
}
