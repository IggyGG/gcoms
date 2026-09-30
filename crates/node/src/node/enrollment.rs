//! Profile-owned enrollment operations. Timeouts release an attempt, never the
//! MLS preparation. The node owns the worker and stops it during shutdown.
use super::*;
use crate::channel_invite::{proof, InviteEnvelope};
use gcoms_core::invitation::{EnrollmentPhase, EnrollmentStatus};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: usize = 64;
const BYTES: usize = 32 * 1024 * 1024;

#[cfg(test)]
pub(crate) type TestResolver = Arc<
    dyn Fn(
            &gcoms_network::channel_invitation::Reference,
            u64,
            Option<[u8; 32]>,
        ) -> Result<
            (
                gcoms_network::channel_invitation::ResolvedInvitation,
                gcoms_network::channel_invitation::Descriptor,
            ),
            String,
        > + Send
        + Sync,
>;

#[cfg(feature = "client-persist")]
async fn resolve(
    state: &Arc<Mutex<NodeState>>,
    reference: &gcoms_network::channel_invitation::Reference,
    sequence: u64,
    digest: Option<[u8; 32]>,
    deadline: tokio::time::Instant,
) -> Result<
    (
        gcoms_network::channel_invitation::ResolvedInvitation,
        gcoms_network::channel_invitation::Descriptor,
    ),
    String,
> {
    #[cfg(test)]
    {
        let resolver = state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .invitation_resolver
            .clone();
        if let Some(resolver) = resolver {
            return resolver(reference, sequence, digest);
        }
    }
    let _ = state;
    gcoms_network_client::invitations::resolve(reference, sequence, digest, deadline).await
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operation {
    pub status: EnrollmentStatus,
    link: String,
    prepared: Vec<u8>,
    pub prepared_id: Option<u64>,
    proof_submitted: bool,
    result: Option<Vec<u8>>,
    next_attempt: u64,
    descriptor_sequence: u64,
    network_sequence: u64,
    descriptor_digest: Option<[u8; 32]>,
    resolved_link: Option<String>,
    pub expected_channel_id: Option<[u8; 32]>,
}
impl Operation {
    pub(crate) fn joined(&mut self) {
        self.status.phase = EnrollmentPhase::Joined;
        self.status.last_error = None;
        self.prepared_id = None;
        self.link.zeroize();
        self.prepared.zeroize();
        self.result.zeroize();
        self.result = None;
        self.resolved_link.zeroize();
        self.resolved_link = None;
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.link.zeroize();
        self.prepared.zeroize();
        self.result.zeroize();
        self.resolved_link.zeroize();
    }
}

pub(crate) fn encode(operations: &[Operation]) -> Result<Vec<u8>, String> {
    validate(operations)?;
    let bytes =
        Zeroizing::new(serde_json::to_vec(operations).map_err(|_| "cannot encode enrollments")?);
    if bytes.len() > BYTES {
        return Err("enrollment profile limit reached".into());
    }
    Ok(bytes.to_vec())
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<Operation>, String> {
    if bytes.len() > BYTES {
        return Err("enrollment profile limit reached".into());
    }
    let operations: Vec<Operation> =
        serde_json::from_slice(bytes).map_err(|_| "invalid enrollment archive")?;
    validate(&operations)?;
    Ok(operations)
}
fn validate(operations: &[Operation]) -> Result<(), String> {
    if operations.len() > LIMIT {
        return Err("enrollment operation limit reached".into());
    }
    let mut ids = HashSet::new();
    for op in operations {
        if !ids.insert(op.status.id)
            || op.status.channel.len() > 1024
            || op.status.display.len() > 1024
            || op.prepared.len() > 1024 * 1024
            || op
                .result
                .as_ref()
                .is_some_and(|r| r.len() > crate::channel_invite::welcome::MAX_BYTES)
            || op
                .status
                .last_error
                .as_ref()
                .is_some_and(|e| e.len() > 2048)
        {
            return Err("invalid enrollment operation".into());
        }
        if !matches!(
            op.status.phase,
            EnrollmentPhase::Joined | EnrollmentPhase::Cancelled
        ) {
            if gcoms_network::channel_invitation::Reference::is_reference(&op.link) {
                let reference = gcoms_network::channel_invitation::Reference::decode(&op.link)?;
                if op
                    .expected_channel_id
                    .map(|id| gcoms_transport::encode_b64url(&id))
                    .as_ref()
                    != Some(&reference.channel_id)
                {
                    return Err("invalid retained channel pin".into());
                }
            } else {
                let envelope = InviteEnvelope::from_link(&op.link)
                    .ok_or("invalid retained enrollment invitation")?;
                if envelope.policy.is_none() || envelope.invite.channel != op.status.channel {
                    return Err("invalid retained enrollment identity".into());
                }
            }
            if op.prepared.is_empty() {
                return Err("missing retained enrollment identity".into());
            }
        }
    }
    Ok(())
}

impl NodeHandle {
    pub async fn list_enrollments(&self) -> Result<Vec<EnrollmentStatus>, String> {
        let state = self.state.upgrade().ok_or("node closed")?;
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        Ok(st.enrollments.iter().map(|op| op.status.clone()).collect())
    }
    pub async fn retire_enrollment(&self, id: [u8; 16]) -> Result<(), String> {
        let state = self.state.upgrade().ok_or("node closed")?;
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let index = st
            .enrollments
            .iter()
            .position(|op| op.status.id == id)
            .ok_or("enrollment not found")?;
        if !matches!(
            st.enrollments[index].status.phase,
            EnrollmentPhase::Joined | EnrollmentPhase::Cancelled
        ) {
            return Err("complete or cancel enrollment before retiring it".into());
        }
        let op = st.enrollments.remove(index);
        if let Err(error) = persist_current_direct_state(&st) {
            st.enrollments.insert(index, op);
            return Err(error);
        }
        Ok(())
    }
    pub async fn start_enrollment(
        &self,
        link: &str,
        display: &str,
    ) -> Result<EnrollmentStatus, String> {
        #[cfg(not(feature = "client-persist"))]
        {
            let _ = (link, display);
            Err("enrollment requires client persistence".into())
        }
        #[cfg(feature = "client-persist")]
        {
            if display.is_empty() || display.len() > 1024 {
                return Err("invalid member name".into());
            }
            let link = link.trim();
            let (channel, expected_channel_id) =
                if gcoms_network::channel_invitation::Reference::is_reference(link) {
                    let reference = gcoms_network::channel_invitation::Reference::decode(link)?;
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                    (
                        String::new(),
                        Some(
                            URL_SAFE_NO_PAD
                                .decode(&reference.channel_id)
                                .map_err(|_| "invalid channel pin")?
                                .try_into()
                                .map_err(|_| "invalid channel pin")?,
                        ),
                    )
                } else {
                    let envelope =
                        InviteEnvelope::from_link(link).ok_or("invalid channel invitation")?;
                    if envelope.policy.is_none() {
                        return Err("this invitation uses the single-use join flow".into());
                    }
                    (envelope.invite.channel, None)
                };
            let state = self.state.upgrade().ok_or("node closed")?;
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            invitations::require_durable(&st)?;
            if let Some(pin) = expected_channel_id {
                if st.channels.values().any(|cs| cs.id.0 == pin) {
                    if let Some(op) = st.enrollments.iter().find(|op| {
                        op.expected_channel_id == Some(pin)
                            && op.status.phase == EnrollmentPhase::Joined
                    }) {
                        return Ok(op.status.clone());
                    }
                    return Err("already a member of this channel".into());
                }
            }
            if let Some(op) = st.enrollments.iter().find(|op| {
                op.link == link
                    && op.status.display == display
                    && op.status.phase != EnrollmentPhase::Cancelled
            }) {
                return Ok(op.status.clone());
            }
            if st.channels.contains_key(&channel) {
                return Err("already a member of this channel".into());
            }
            if st.enrollments.len() >= LIMIT {
                return Err("enrollment operation limit reached".into());
            }
            let mls = gcoms_mls::ChannelMember::prepare(display).map_err(|e| e.to_string())?;
            let prepared = mls
                .persist(&channel_archive_key(&st.identity_seed))
                .map_err(|e| e.to_string())?;
            let status = EnrollmentStatus {
                id: fresh_msg_id(),
                channel,
                display: display.into(),
                phase: EnrollmentPhase::WaitingNetwork,
                attempts: 0,
                last_error: None,
            };
            st.enrollments.push(Operation {
                status: status.clone(),
                link: link.into(),
                prepared,
                prepared_id: None,
                proof_submitted: false,
                result: None,
                next_attempt: 0,
                descriptor_sequence: 0,
                network_sequence: 0,
                descriptor_digest: None,
                resolved_link: None,
                expected_channel_id,
            });
            if let Err(error) = persist_current_direct_state(&st) {
                st.enrollments.pop();
                return Err(error);
            }
            Ok(status)
        }
    }
    pub async fn enrollment_status(&self, id: [u8; 16]) -> Result<EnrollmentStatus, String> {
        let state = self.state.upgrade().ok_or("node closed")?;
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.enrollments
            .iter()
            .find(|op| op.status.id == id)
            .map(|op| op.status.clone())
            .ok_or_else(|| "enrollment not found".into())
    }
    pub async fn resume_enrollment(&self, id: [u8; 16]) -> Result<EnrollmentStatus, String> {
        self.update_enrollment(id, |op| {
            if op.status.phase == EnrollmentPhase::Cancelled {
                return Err("enrollment was cancelled".into());
            }
            op.next_attempt = 0;
            Ok(())
        })
    }
    pub async fn cancel_enrollment(&self, id: [u8; 16]) -> Result<EnrollmentStatus, String> {
        self.update_enrollment(id, |op| {
            if op.status.phase == EnrollmentPhase::Joined { return Err("already joined; leave the channel to remove membership".into()); }
            if op.proof_submitted { return Err("admission may already be committed; resume to confirm membership before leaving".into()); }
            op.status.phase = EnrollmentPhase::Cancelled;
            op.link.zeroize(); op.prepared.zeroize(); op.result.zeroize();
            Ok(())
        })
    }
    fn update_enrollment(
        &self,
        id: [u8; 16],
        update: impl FnOnce(&mut Operation) -> Result<(), String>,
    ) -> Result<EnrollmentStatus, String> {
        let state = self.state.upgrade().ok_or("node closed")?;
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let index = st
            .enrollments
            .iter()
            .position(|op| op.status.id == id)
            .ok_or("enrollment not found")?;
        let prior = st.enrollments[index].clone();
        if prior.status.phase == EnrollmentPhase::Cancelled {
            return Err("enrollment was cancelled".into());
        }
        if let Err(error) = update(&mut st.enrollments[index]) {
            st.enrollments[index] = prior;
            return Err(error);
        }
        let released = if st.enrollments[index].status.phase == EnrollmentPhase::Cancelled {
            st.enrollments[index]
                .prepared_id
                .take()
                .and_then(|id| st.prepared.remove(&id).map(|prepared| (id, prepared)))
        } else {
            None
        };
        if let Err(error) = persist_current_direct_state(&st) {
            st.enrollments[index] = prior;
            if let Some((id, prepared)) = released {
                st.prepared.insert(id, prepared);
            }
            return Err(error);
        }
        if let Some((_, prepared)) = released {
            close_route_lanes(&st.scheduler, &prepared.route);
        }
        Ok(st.enrollments[index].status.clone())
    }
}

pub(crate) async fn run(handle: NodeHandle) {
    use futures_util::{stream, StreamExt};
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(state) = handle.state.upgrade() else {
            break;
        };
        let due = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            st.enrollments
                .iter()
                .filter(|op| {
                    !matches!(
                        op.status.phase,
                        EnrollmentPhase::Joined | EnrollmentPhase::Cancelled
                    ) && op.next_attempt <= now_unix()
                })
                .take(4)
                .map(|op| op.status.id)
                .collect::<Vec<_>>()
        };
        stream::iter(due)
            .for_each_concurrent(4, |id| {
                let handle = &handle;
                async move {
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                    let result = tokio::time::timeout_at(deadline, attempt(handle, id, deadline))
                        .await
                        .unwrap_or_else(|_| {
                            Err(
                                "Still waiting for the owner; the saved enrollment will retry"
                                    .into(),
                            )
                        });
                    if let Err(error) = result {
                        let _ = handle.update_enrollment(id, |op| {
                            if !matches!(
                                op.status.phase,
                                EnrollmentPhase::Joined | EnrollmentPhase::Cancelled
                            ) {
                                op.status.last_error = Some(error.chars().take(500).collect());
                                op.next_attempt = now_unix().saturating_add(10);
                                if op.status.phase != EnrollmentPhase::ApplyingMembership {
                                    op.status.phase = EnrollmentPhase::WaitingOwner;
                                }
                            }
                            Ok(())
                        });
                    }
                }
            })
            .await;
    }
}

#[cfg(not(feature = "client-persist"))]
async fn attempt(
    _handle: &NodeHandle,
    _id: [u8; 16],
    _deadline: tokio::time::Instant,
) -> Result<(), String> {
    Err("enrollment requires client persistence".into())
}

#[cfg(feature = "client-persist")]
async fn attempt(
    handle: &NodeHandle,
    id: [u8; 16],
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    let state = handle.state.upgrade().ok_or("node closed")?;
    let operation = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.enrollments
            .iter()
            .find(|op| op.status.id == id)
            .ok_or("enrollment not found")?
            .clone()
    };
    if matches!(
        operation.status.phase,
        EnrollmentPhase::Joined | EnrollmentPhase::Cancelled
    ) {
        return Ok(());
    }
    let resolved_link =
        if gcoms_network::channel_invitation::Reference::is_reference(&operation.link) {
            if operation.result.is_some() && operation.resolved_link.is_some() {
                operation
                    .resolved_link
                    .clone()
                    .expect("checked retained result")
            } else {
                let reference =
                    gcoms_network::channel_invitation::Reference::decode(&operation.link)?;
                let (resolved, descriptor) = resolve(
                    &state,
                    &reference,
                    operation.descriptor_sequence,
                    operation.descriptor_digest,
                    deadline,
                )
                .await?;
                super::invitation_directory::validate_resolved(&reference, &resolved)?;
                resolved
                    .network
                    .verify_at(now_unix(), operation.network_sequence)?;
                let inner = InviteEnvelope::from_link(&resolved.channel_invitation)
                    .ok_or("invalid resolved invitation")?;
                let digest = Sha256::digest(
                    serde_json::to_vec(&descriptor).map_err(|_| "invalid descriptor")?,
                )
                .into();
                handle.update_enrollment(id, |op| {
                    if !op.status.channel.is_empty() && op.status.channel != inner.invite.channel {
                        return Err("invitation channel changed".into());
                    }
                    op.status.channel = inner.invite.channel.clone();
                    op.network_sequence = resolved.network.signed_defaults.defaults.sequence;
                    op.descriptor_sequence = descriptor.body.sequence;
                    op.descriptor_digest = Some(digest);
                    op.resolved_link = Some(resolved.channel_invitation.clone());
                    Ok(())
                })?;
                resolved.channel_invitation.clone()
            }
        } else {
            operation.link.clone()
        };
    let envelope =
        InviteEnvelope::from_link(&resolved_link).ok_or("invalid retained invitation")?;
    handle.update_enrollment(id, |op| {
        op.status.attempts = op.status.attempts.saturating_add(1);
        op.status.last_error = None;
        Ok(())
    })?;
    handle.install_invite_bootstrap(&envelope).await?;
    handle.wait_for_inbox(deadline).await?;
    let prepared_id = prepare(&state, &handle.scheduler, id).await?;
    let package = handle.channel_key_package(prepared_id).await?;
    let result = if let Some(result) = &operation.result {
        result.clone()
    } else {
        handle.update_enrollment(id, |op| {
            op.status.phase = EnrollmentPhase::VerifyingReturnRoute;
            Ok(())
        })?;
        let probe = proof::request(&package, None).ok_or("enrollment package too large")?;
        let challenge = handle
            .redeem_invite_remote(
                envelope.invite.owner.clone(),
                &envelope.invite.channel,
                &operation.status.display,
                &probe,
                envelope.invite.id,
                envelope.invite.secret,
                remaining(deadline)?,
            )
            .await?;
        let challenge = proof::decode_challenge(&challenge)
            .ok_or("owner does not support return-path verification")?;
        let proven =
            proof::request(&package, Some(challenge)).ok_or("enrollment package too large")?;
        handle.update_enrollment(id, |op| {
            if op.status.phase == EnrollmentPhase::Cancelled {
                return Err("enrollment cancelled".into());
            }
            op.proof_submitted = true;
            op.status.phase = EnrollmentPhase::AwaitingAdmission;
            Ok(())
        })?;
        handle
            .redeem_invite_remote(
                envelope.invite.owner.clone(),
                &envelope.invite.channel,
                &operation.status.display,
                &proven,
                envelope.invite.id,
                envelope.invite.secret,
                remaining(deadline)?,
            )
            .await?
    };
    handle.update_enrollment(id, |op| {
        op.result = Some(result.clone());
        op.status.phase = EnrollmentPhase::ApplyingMembership;
        Ok(())
    })?;
    handle
        .join_channel(
            prepared_id,
            &envelope.invite.channel,
            crate::channel::ChannelVisibility::Private,
            &result,
        )
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "client-persist", feature = "relay-host"))]
#[path = "enrollment_restart_tests.rs"]
mod restart_tests;

#[cfg(feature = "client-persist")]
fn remaining(deadline: tokio::time::Instant) -> Result<u64, String> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        Err("enrollment attempt deadline elapsed".into())
    } else {
        Ok(remaining.as_secs().clamp(1, 600))
    }
}

#[cfg(feature = "client-persist")]
async fn prepare(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    id: [u8; 16],
) -> Result<u64, String> {
    let (op, relay, seed) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let op = st
            .enrollments
            .iter()
            .find(|op| op.status.id == id)
            .ok_or("enrollment not found")?;
        if op.status.phase == EnrollmentPhase::Cancelled {
            return Err("enrollment cancelled".into());
        }
        if let Some(prepared_id) = op.prepared_id {
            if st.prepared.get(&prepared_id).is_some_and(|p| {
                p.route.aliases.len() == 2
                    && p.route
                        .aliases
                        .iter()
                        .all(|a| a.contact.expiry > now_unix() + 60)
            }) {
                return Ok(prepared_id);
            }
        }
        (op.clone(), st.client_relay.clone(), st.identity_seed)
    };
    let mls = gcoms_mls::PreparedJoin::restore(&channel_archive_key(&seed), &op.prepared)
        .map_err(|e| e.to_string())?;
    let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&mls);
    let route = provision_channel_route(
        scheduler,
        &relay,
        pseudonym,
        channel_direct_secret(&seed, &pseudonym),
    )
    .await?;
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    let index = st
        .enrollments
        .iter()
        .position(|op| op.status.id == id)
        .ok_or("enrollment not found")?;
    if st.enrollments[index].status.phase == EnrollmentPhase::Cancelled {
        close_route_lanes(scheduler, &route);
        return Err("enrollment cancelled".into());
    }
    let previous_next = st.next_prep_id;
    let prepared_id = match op.prepared_id {
        Some(id) => id,
        None => {
            let next = st.next_prep_id;
            st.next_prep_id = next.checked_add(1).ok_or("join id exhausted")?;
            next
        }
    };
    let old = st.prepared.insert(
        prepared_id,
        PreparedChannelJoin {
            mls,
            route,
            display: op.status.display.clone(),
        },
    );
    st.enrollments[index].prepared_id = Some(prepared_id);
    if let Err(error) = persist_current_direct_state(&st) {
        if let Some(new) = st.prepared.remove(&prepared_id) {
            close_route_lanes(scheduler, &new.route);
        }
        if let Some(old) = old {
            st.prepared.insert(prepared_id, old);
        }
        st.enrollments[index].prepared_id = op.prepared_id;
        st.next_prep_id = previous_next;
        return Err(error);
    }
    if let Some(old) = old {
        close_route_lanes(scheduler, &old.route);
    }
    open_route_lanes(scheduler, &st.prepared[&prepared_id].route);
    Ok(prepared_id)
}
