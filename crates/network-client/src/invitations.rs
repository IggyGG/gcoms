//! HTTPS rendezvous for encrypted owner descriptors. The bearer invitation
//! secret is used locally only, never in a URL, header, request or diagnostic.
use super::*;
use gcoms_network::channel_invitation::{
    Descriptor, Reference, ResolvedInvitation, MAX_DESCRIPTOR_BYTES,
};

async fn descriptor_body(response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_DESCRIPTOR_BYTES as u64)
    {
        return Err("invitation descriptor too large".into());
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "invitation response interrupted")?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|n| n > MAX_DESCRIPTOR_BYTES)
        {
            return Err("invitation descriptor too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "invitation HTTPS unavailable".into())
}
/// Resolve only user-supplied, explicitly accepted references. TLS authenticates
/// each locator; the pinned issuer and network root authenticate its contents.
pub async fn resolve(
    reference: &Reference,
    minimum: u64,
    previous_digest: Option<[u8; 32]>,
    deadline: Instant,
) -> Result<(ResolvedInvitation, Descriptor)> {
    reference.validate()?;
    resolve_with(&http()?, reference, minimum, previous_digest, deadline).await
}
pub(super) async fn resolve_with(
    client: &reqwest::Client,
    reference: &Reference,
    minimum: u64,
    previous_digest: Option<[u8; 32]>,
    deadline: Instant,
) -> Result<(ResolvedInvitation, Descriptor)> {
    let mut last = "invitation owner or providers unavailable".to_string();
    for (index, provider) in reference.providers.iter().enumerate() {
        let attempt = async {
            let response = client
                .get(format!("{provider}v1/invitations/{}", reference.id))
                .send()
                .await
                .map_err(|_| "invitation provider unreachable")?;
            if !response.status().is_success() {
                return Err("invitation owner has no current route; retrying".into());
            }
            let bytes = descriptor_body(response).await?;
            let descriptor: Descriptor = serde_json::from_slice(&bytes)
                .map_err(|_| "invalid invitation descriptor response")?;
            let value = descriptor.open(reference, now_unix(), minimum)?;
            let digest: [u8; 32] =
                Sha256::digest(serde_json::to_vec(&descriptor).map_err(|_| "invalid descriptor")?)
                    .into();
            if descriptor.body.sequence == minimum
                && previous_digest.is_some_and(|previous| previous != digest)
            {
                return Err("invitation descriptor equivocation".into());
            }
            Ok((value, descriptor))
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(
            remaining / (reference.providers.len() - index) as u32,
            attempt,
        )
        .await
        {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) => last = error,
            Err(_) => last = "invitation provider timed out".into(),
        }
    }
    Err(last)
}
impl NetworkClient {
    pub async fn publish_invitation(
        &self,
        descriptor: &Descriptor,
        deadline: Instant,
    ) -> Result<()> {
        descriptor.verify(now_unix())?;
        let (defaults, grant) = self.transaction(|state| {
            let defaults = self.selected_defaults(state, now_unix())?;
            let invitation = state
                .invitation
                .as_ref()
                .ok_or("publishing invitations requires an invitation-publication network grant")?;
            validate_invitation(invitation, &defaults, now_unix())?;
            if descriptor.body.network_id != defaults.network_id {
                return Err("invitation network mismatch".into());
            }
            Ok((defaults, Zeroizing::new(invitation.grant.clone())))
        })?;
        let mut success = false;
        for (index, provider) in defaults.provider_urls.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let attempt = async {
                self.http
                    .put(format!("{provider}v1/invitations/{}", descriptor.body.id))
                    .bearer_auth(grant.as_str())
                    .json(descriptor)
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            };
            success |= tokio::time::timeout(
                remaining / (defaults.provider_urls.len() - index) as u32,
                attempt,
            )
            .await
            .unwrap_or(false);
        }
        if success {
            Ok(())
        } else {
            Err("invitation publication refused or unavailable; check the network grant's invitations scope".into())
        }
    }
}
