//! Owner publication of short-lived encrypted routing descriptors. Sequence and
//! ciphertext are checkpointed before HTTPS publication, so retries are exact.
use super::*;
use gcoms_network::channel_invitation::{Descriptor, Reference, ResolvedInvitation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(all(test, feature = "client-persist"))]
#[path = "invitation_publication_tests.rs"]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Publication {
    pub reference: Reference,
    pub descriptor: Descriptor,
    route_digest: [u8; 32],
    pub published_until: Option<u64>,
    pub last_error: Option<String>,
}
impl NodeHandle {
    /// A host supplies its already pinned, profile-owned network client. This
    /// does not authorize publication without the provider's invitations scope.
    pub fn configure_invitation_directory(
        &self,
        network: gcoms_network_client::NetworkClient,
    ) -> Result<(), String> {
        let state = self.state.upgrade().ok_or("node closed")?;
        state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .invitation_network = Some(network);
        Ok(())
    }
    pub async fn share_reusable_invitation(
        &self,
        channel: &str,
        id: [u8; 16],
    ) -> Result<String, String> {
        publish(self, channel, id).await?;
        let state = self.state.upgrade().ok_or("node closed")?;
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.channels
            .get(channel)
            .and_then(|cs| cs.invitations.records.iter().find(|r| r.id == id))
            .and_then(|r| r.publication.as_ref())
            .ok_or("invitation publication missing")?
            .reference
            .encode()
    }
    pub async fn resolve_reusable_invitation(&self, link: &str) -> Result<String, String> {
        let reference = Reference::decode(link)?;
        let (resolved, _) = gcoms_network_client::invitations::resolve(
            &reference,
            0,
            None,
            tokio::time::Instant::now() + std::time::Duration::from_secs(20),
        )
        .await?;
        validate_resolved(&reference, &resolved)?;
        Ok(resolved.channel_invitation.clone())
    }
}
pub fn validate_resolved(
    reference: &Reference,
    resolved: &ResolvedInvitation,
) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let envelope = crate::channel_invite::InviteEnvelope::from_link(&resolved.channel_invitation)
        .ok_or("invalid resolved channel invitation")?;
    if envelope.policy.is_none()
        || URL_SAFE_NO_PAD.encode(envelope.invite.id) != reference.id
        || URL_SAFE_NO_PAD.encode(envelope.invite.secret) != reference.secret
        || URL_SAFE_NO_PAD.encode(Sha256::digest(&envelope.invite.owner.identity_pk))
            != reference.issuer_key_hash
    {
        return Err("resolved invitation does not match its reference".into());
    }
    Ok(())
}
async fn publish(handle: &NodeHandle, channel: &str, id: [u8; 16]) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let state = handle.state.upgrade().ok_or("node closed")?;
    let (network, record, channel_id, seed) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        invitations::require_durable(&st)?;
        let cs = st.channels.get(channel).ok_or("no channel")?;
        if !cs.role.is_owner() || crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
            return Err("invitation owner unavailable".into());
        }
        let record = cs
            .invitations
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or("invite not found")?;
        (st.invitation_network.clone().ok_or("configure an invitation-publication network grant before sharing reusable invitations")?,record.clone(),cs.id.0,st.identity_seed)
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    if network.shareable_identity().is_err() {
        network.refresh_defaults(deadline).await?;
    }
    let identity = network.shareable_identity()?;
    let info = handle.current_info().await?;
    let now = now_unix();
    let expiry = info
        .aliases
        .iter()
        .map(|a| a.expiry)
        .min()
        .unwrap_or(0)
        .min(now.saturating_add(300));
    if expiry <= now.saturating_add(30) {
        return Err("owner route is renewing; invitation publication will retry".into());
    }
    let invite = crate::channel_invite::ChannelInvite {
        owner: info,
        channel: channel.into(),
        id,
        secret: record.secret,
        expiry: record.policy.expires_at.unwrap_or(u64::MAX),
    };
    let mut envelope =
        crate::channel_invite::InviteEnvelope::from_link(&handle.channel_invite_link(&invite)?)
            .ok_or("invalid routed invitation")?;
    envelope.policy = Some(record.policy);
    let resolved = ResolvedInvitation {
        network: identity.clone(),
        channel_id: URL_SAFE_NO_PAD.encode(channel_id),
        channel_invitation: envelope.to_link().ok_or("invitation too large")?,
    };
    let digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&resolved).map_err(|_| "invalid invitation descriptor")?)
            .into();
    // The maintenance tick checks for renewed routes; it must not upload the
    // same ciphertext repeatedly while the confirmed publication is fresh.
    if record.publication.as_ref().is_some_and(|old| {
        old.route_digest == digest
            && old.published_until == Some(old.descriptor.body.expires_at)
            && old.descriptor.body.expires_at > now.saturating_add(90)
    }) {
        return Ok(());
    }
    let publication = if let Some(old) = record.publication.as_ref().filter(|old| {
        old.route_digest == digest && old.descriptor.body.expires_at > now.saturating_add(90)
    }) {
        old.clone()
    } else {
        let issuer = IdentityKeypair::from_seed(seed);
        let reference = match &record.publication {
            Some(old) => old.reference.clone(),
            None => Reference::new(
                &identity,
                &issuer.public_bytes(),
                channel_id,
                id,
                record.secret,
            )?,
        };
        let sequence = record
            .publication
            .as_ref()
            .map_or(Some(1), |old| old.descriptor.body.sequence.checked_add(1))
            .ok_or("invitation descriptor sequence exhausted")?;
        Publication {
            descriptor: Descriptor::seal(&reference, &resolved, &issuer, sequence, now, expiry)?,
            reference,
            route_digest: digest,
            published_until: None,
            last_error: None,
        }
    };
    {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        stage_publication(&mut st, channel, &record, &publication)?;
    }
    let result = network
        .publish_invitation(&publication.descriptor, deadline)
        .await;
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    finish_publication(&mut st, channel, id, &publication.descriptor, &result)?;
    result
}

fn stage_publication(
    st: &mut NodeState,
    channel: &str,
    record: &crate::channel_invite::policy::InvitationRecord,
    publication: &Publication,
) -> Result<(), String> {
    let current = st
        .channels
        .get_mut(channel)
        .ok_or("no channel")?
        .invitations
        .records
        .iter_mut()
        .find(|r| r.id == record.id)
        .ok_or("invite not found")?;
    if current.revision != record.revision
        || current
            .publication
            .as_ref()
            .map(|p| p.descriptor.body.sequence)
            != record
                .publication
                .as_ref()
                .map(|p| p.descriptor.body.sequence)
    {
        return Err("invitation changed during publication; retry".into());
    }
    // A retry uses the exact ciphertext already behind the durable barrier.
    // Rewriting the entire profile adds no durability and amplifies outages.
    if current
        .publication
        .as_ref()
        .is_some_and(|old| old.descriptor == publication.descriptor)
    {
        return Ok(());
    }
    let old = current.publication.replace(publication.clone());
    if let Err(error) = persist_current_direct_state(st) {
        st.channels
            .get_mut(channel)
            .unwrap()
            .invitations
            .records
            .iter_mut()
            .find(|r| r.id == record.id)
            .unwrap()
            .publication = old;
        return Err(error);
    }
    Ok(())
}

fn finish_publication(
    st: &mut NodeState,
    channel: &str,
    id: [u8; 16],
    descriptor: &Descriptor,
    result: &Result<(), String>,
) -> Result<(), String> {
    if let Some(current) = st
        .channels
        .get_mut(channel)
        .and_then(|cs| cs.invitations.records.iter_mut().find(|r| r.id == id))
    {
        if current
            .publication
            .as_ref()
            .is_some_and(|p| p.descriptor == *descriptor)
        {
            let publication = current.publication.as_mut().unwrap();
            // Retry errors are diagnostic, not new protocol authority. Leave a
            // concurrent confirmed publication intact and let ordinary saves
            // retain the latest error without forcing another profile fsync.
            if publication.published_until == Some(descriptor.body.expires_at) {
                return Ok(());
            }
            if let Err(error) = result {
                publication.last_error = Some(error.clone());
                return Ok(());
            }
            let previous = publication.clone();
            publication.published_until = Some(descriptor.body.expires_at);
            publication.last_error = None;
            if let Err(error) = persist_current_direct_state(st) {
                st.channels
                    .get_mut(channel)
                    .unwrap()
                    .invitations
                    .records
                    .iter_mut()
                    .find(|r| r.id == id)
                    .unwrap()
                    .publication = Some(previous);
                return Err(error);
            }
        }
    }
    Ok(())
}

struct Retry {
    failures: u32,
    next_attempt: tokio::time::Instant,
}

impl Retry {
    fn failed(&mut self, now: tokio::time::Instant) {
        self.failures = self.failures.saturating_add(1);
        let seconds = (30u64 << self.failures.saturating_sub(1).min(4)).min(300);
        let delay = jittered(std::time::Duration::from_secs(seconds)).clamp(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        );
        self.next_attempt = now + delay;
    }
}

pub(crate) async fn run(handle: NodeHandle) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Scheduling is process-local: connectivity failures must not themselves
    // dirty every retained invitation. Entries disappear with their jobs.
    let mut retries = HashMap::<(String, [u8; 16]), Retry>::new();
    loop {
        interval.tick().await;
        let Some(state) = handle.state.upgrade() else {
            break;
        };
        let jobs = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            if st.invitation_network.is_none() {
                continue;
            }
            st.channels
                .iter()
                .filter(|(_, cs)| cs.role.is_owner())
                .flat_map(|(name, cs)| {
                    cs.invitations
                        .records
                        .iter()
                        .filter(|r| {
                            r.publication.is_some()
                                && ((r.revoked_at.is_none()
                                    && r.policy
                                        .expires_at
                                        .is_none_or(|expiry| expiry > now_unix())
                                    && r.policy
                                        .max_admissions
                                        .is_none_or(|limit| r.admissions < limit))
                                    || r.redemptions.iter().any(|redemption| {
                                        !redemption.confirmed && !redemption.removed
                                    }))
                        })
                        .map(|r| (name.clone(), r.id))
                })
                .collect::<Vec<_>>()
        };
        let live: HashSet<_> = jobs.iter().cloned().collect();
        retries.retain(|key, _| live.contains(key));
        let now = tokio::time::Instant::now();
        use futures_util::{stream, StreamExt};
        let results = stream::iter(jobs.into_iter().filter(|key| {
            retries
                .get(key)
                .is_none_or(|retry| retry.next_attempt <= now)
        }))
        .map(|(name, id)| {
            let handle = &handle;
            async move {
                let success = publish(handle, &name, id).await.is_ok();
                ((name, id), success)
            }
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
        for (key, success) in results {
            if success {
                retries.remove(&key);
            } else {
                let now = tokio::time::Instant::now();
                retries
                    .entry(key)
                    .or_insert(Retry {
                        failures: 0,
                        next_attempt: now,
                    })
                    .failed(now);
            }
        }
    }
}
