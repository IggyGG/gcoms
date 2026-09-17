//! Opt-in public service naming. DNS errors never mutate private GC routing.
//! Each HTTP mutation is journaled with its original credential and exact body
//! before sending, so lost replies and process restarts reuse one operation.
use crate::{
    bounded_body, canonical_b64, now_unix, validate_retained_invitation, NetworkClient, Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_network::{
    NameResponse, NetworkDefaults, RegisterNameRequest, RemoveNameRequest, UpdateNameRequest,
};
use gcoms_routing::bootstrap::BootstrapBundle;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::time::Instant;

const MAX_NAME_LEASE: u64 = 86400;
const RENEW_BEFORE: u64 = 300;
/// Public status only: never contains the per-record credential or invitation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NameStatus {
    pub opted_in: bool,
    pub server_label: Option<String>,
    pub pending: bool,
    pub removed: bool,
    pub registration: Option<NameResponse>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameState {
    opted_in: bool,
    #[serde(default)]
    server_label: Option<String>,
    credential_b64: Option<String>,
    registration: Option<Registration>,
    pending: Option<Pending>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    authority: String,
    service_id: [u8; 32],
    address: SocketAddr,
    response: NameResponse,
    removed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    id: String,
    authority: String,
    authorization: String,
    operation: Operation,
    service_id: [u8; 32],
    address: SocketAddr,
    /// A cap on the response lease, signed/protected by the request's inputs.
    maximum_lease: u64,
    proof_expires_at: u64,
    grant_expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Operation {
    Register(RegisterNameRequest),
    Update {
        handle: String,
        body: UpdateNameRequest,
    },
    Remove {
        handle: String,
        body: RemoveNameRequest,
    },
}
impl NameState {
    fn status(&self) -> NameStatus {
        NameStatus {
            opted_in: self.opted_in,
            server_label: self.server_label.clone(),
            pending: self.pending.is_some()
                || (!self.opted_in && self.registration.as_ref().is_some_and(|r| !r.removed)),
            removed: self.registration.as_ref().is_some_and(|r| r.removed),
            registration: self.registration.as_ref().map(|r| r.response.clone()),
        }
    }
}
impl Pending {
    fn sequence(&self) -> u64 {
        match &self.operation {
            Operation::Register(_) => 1,
            Operation::Update { body, .. } => body.sequence,
            Operation::Remove { body, .. } => body.sequence,
        }
    }
    fn handle(&self) -> Option<&str> {
        match &self.operation {
            Operation::Register(_) => None,
            Operation::Update { handle, .. } | Operation::Remove { handle, .. } => Some(handle),
        }
    }
    fn response(&self, response: &NameResponse, defaults: &NetworkDefaults) -> Result<()> {
        if response.node_handle.len() != 32
            || !response
                .node_handle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || response.sequence != self.sequence()
            || response.lease_expires_at
                > if matches!(self.operation, Operation::Remove { .. }) {
                    now_unix().saturating_add(300)
                } else {
                    self.maximum_lease
                }
            || self
                .handle()
                .is_some_and(|handle| handle != response.node_handle)
        {
            return Err("invalid DNS registration response".into());
        }
        let expected =
            match &self.operation {
                Operation::Register(RegisterNameRequest {
                    server_label: Some(label),
                    ..
                }) => {
                    let name = format!("{label}.relays.{}", defaults.dns_domain);
                    if !defaults.founders.iter().any(|founder| {
                        founder.name == name && founder.service_id == self.service_id
                    }) {
                        return Err("DNS founder pin mismatch".into());
                    }
                    name
                }
                Operation::Register(_) => {
                    format!("{}.nodes.{}", response.node_handle, defaults.dns_domain)
                }
                _ => String::new(),
            };
        if !expected.is_empty() && response.fqdn != expected {
            return Err("DNS response named a different service".into());
        }
        Ok(())
    }
}
impl NetworkClient {
    /// Persist consent first. Call `flush_name` after disabling and on later
    /// worker ticks, including while the node has no published listener.
    pub fn configure_opt_in(&self, enabled: bool) -> Result<()> {
        self.transaction(|state| {
            state.names.opted_in = enabled;
            Ok(())
        })
    }
    /// Choose a founder name before the first registration attempt. `None`
    /// keeps ordinary clients on random node names; existing bindings are fixed.
    pub fn configure_server_label(&self, label: Option<&str>) -> Result<()> {
        if label.is_some_and(|value| !(1..=8).any(|n| value == format!("r{n}"))) {
            return Err("DNS server label must be r1 through r8".into());
        }
        self.transaction(|state| {
            let selected = label.map(str::to_owned);
            if state.names.server_label != selected
                && (state.names.credential_b64.is_some()
                    || state.names.registration.is_some()
                    || state.names.pending.is_some())
            {
                return Err("DNS name kind and server label are already bound".into());
            }
            state.names.server_label = selected;
            Ok(())
        })
    }
    pub fn name_status(&self) -> Result<NameStatus> {
        self.transaction(|state| Ok(state.names.status()))
    }
    /// Only call with the node's independently published, single public listener.
    /// Returned errors concern DNS only; retain the existing private GC session.
    pub async fn update_listener(
        &self,
        bundle: &BootstrapBundle,
        deadline: Instant,
    ) -> Result<Option<NameResponse>> {
        if !self.name_status()?.opted_in {
            return self.flush_name(deadline).await;
        }
        bundle
            .validate()
            .map_err(|_| "invalid DNS listener introduction")?;
        if bundle.relays.len() != 1 {
            return Err("DNS registration requires exactly one listener".into());
        }
        let relay = &bundle.relays[0];
        if !gcoms_routing::service::public_ip(relay.addr.ip()) || relay.expires_at <= now_unix() {
            return Err("DNS listener must be current and public".into());
        }
        self.flush_name(deadline).await?;
        if Instant::now() >= deadline {
            return Err("DNS update deadline elapsed".into());
        }
        self.transaction(|state| {
            if !state.names.opted_in || state.names.pending.is_some() {
                return Ok(());
            }
            let defaults = self.selected_defaults(state, now_unix())?;
            if let Some(registration) = &state.names.registration {
                if registration.service_id != relay.service_id {
                    return Err("DNS name belongs to a different service pin".into());
                }
                if !registration.removed
                    && registration.address == relay.addr
                    && registration.response.lease_expires_at
                        > now_unix().saturating_add(RENEW_BEFORE)
                {
                    return Ok(());
                }
                let credential = state
                    .names
                    .credential_b64
                    .as_ref()
                    .ok_or("DNS record credential missing")?;
                if !defaults.provider_urls.contains(&registration.authority) {
                    return Err("DNS authority absent from current signed defaults".into());
                }
                state.names.pending = Some(Pending {
                    id: random_id(),
                    authority: registration.authority.clone(),
                    authorization: credential.clone(),
                    operation: Operation::Update {
                        handle: registration.response.node_handle.clone(),
                        body: UpdateNameRequest {
                            sequence: registration
                                .response
                                .sequence
                                .checked_add(1)
                                .ok_or("DNS sequence exhausted")?,
                            routing_bundle_b64: encoded(bundle)?,
                        },
                    },
                    service_id: relay.service_id,
                    address: relay.addr,
                    maximum_lease: relay
                        .expires_at
                        .min(now_unix().saturating_add(MAX_NAME_LEASE)),
                    proof_expires_at: relay.expires_at,
                    grant_expires_at: 0,
                });
            } else {
                let invitation = state
                    .invitation
                    .as_ref()
                    .ok_or("A network invitation is required for DNS registration.")?;
                validate_retained_invitation(invitation, &defaults, now_unix())?;
                let credential = state
                    .names
                    .credential_b64
                    .get_or_insert_with(|| URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()))
                    .clone();
                if credential == invitation.grant {
                    return Err("DNS credential must be independent".into());
                }
                let server_label = state.names.server_label.clone();
                if let Some(label) = &server_label {
                    let name = format!("{label}.relays.{}", defaults.dns_domain);
                    if !defaults.founders.iter().any(|founder| {
                        founder.name == name && founder.service_id == relay.service_id
                    }) {
                        return Err("DNS server label does not match the signed founder pin".into());
                    }
                }
                state.names.pending = Some(Pending {
                    id: random_id(),
                    authority: defaults.provider_urls[0].clone(),
                    authorization: invitation.grant.clone(),
                    operation: Operation::Register(RegisterNameRequest {
                        request_id: random_id(),
                        credential_b64: credential,
                        routing_bundle_b64: encoded(bundle)?,
                        server_label,
                    }),
                    service_id: relay.service_id,
                    address: relay.addr,
                    maximum_lease: relay
                        .expires_at
                        .min(invitation.expires_at)
                        .min(now_unix().saturating_add(MAX_NAME_LEASE)),
                    proof_expires_at: relay.expires_at,
                    grant_expires_at: invitation.expires_at,
                });
            }
            Ok(())
        })?;
        self.flush_name(deadline).await
    }
    /// Replay durable work without needing a listener. This is also the opt-out
    /// cleanup path after an ambiguous registration or update response.
    pub async fn flush_name(&self, deadline: Instant) -> Result<Option<NameResponse>> {
        // At most one replay and one cleanup request per call; the third pass
        // observes convergence. All attempts share the caller's original budget.
        for _ in 0..3 {
            let operation = self.transaction(|state| {
                let defaults = self.selected_defaults(state, now_unix())?;
                if let Some(pending) = &state.names.pending {
                    if matches!(pending.operation, Operation::Register(_))
                        && pending.grant_expires_at <= now_unix()
                    {
                        // Server leases cannot outlive this grant. Retain no
                        // expired registration operation that could re-enable DNS.
                        state.names.pending = None;
                    }
                }
                if state.names.pending.is_none() && !state.names.opted_in {
                    if let Some(registration) = &state.names.registration {
                        if !registration.removed {
                            let credential = state
                                .names
                                .credential_b64
                                .as_ref()
                                .ok_or("DNS record credential missing")?;
                            state.names.pending = Some(Pending {
                                id: random_id(),
                                authority: registration.authority.clone(),
                                authorization: credential.clone(),
                                operation: Operation::Remove {
                                    handle: registration.response.node_handle.clone(),
                                    body: RemoveNameRequest {
                                        sequence: registration
                                            .response
                                            .sequence
                                            .checked_add(1)
                                            .ok_or("DNS sequence exhausted")?,
                                    },
                                },
                                service_id: registration.service_id,
                                address: registration.address,
                                maximum_lease: now_unix().saturating_add(300),
                                proof_expires_at: 0,
                                grant_expires_at: 0,
                            });
                        }
                    }
                }
                let pending = state.names.pending.clone();
                if let Some(pending) = &pending {
                    if !defaults.provider_urls.contains(&pending.authority) {
                        return Err("DNS authority absent from current signed defaults".into());
                    }
                    if canonical_b64(&pending.authorization)?.len() != 32 {
                        return Err("invalid retained DNS credential".into());
                    }
                }
                Ok(pending)
            })?;
            let Some(pending) = operation else {
                return self.transaction(|state| {
                    Ok(state
                        .names
                        .registration
                        .as_ref()
                        .filter(|r| !r.removed)
                        .map(|r| r.response.clone()))
                });
            };
            if Instant::now() >= deadline {
                return Err("DNS update deadline elapsed".into());
            }
            let attempt = async {
                let request = match &pending.operation {
                    Operation::Register(body) => self
                        .http
                        .post(format!("{}v1/names", pending.authority))
                        .json(body),
                    Operation::Update { handle, body } => self
                        .http
                        .put(format!("{}v1/names/{handle}", pending.authority))
                        .json(body),
                    Operation::Remove { handle, body } => self
                        .http
                        .delete(format!("{}v1/names/{handle}", pending.authority))
                        .json(body),
                };
                let response = request
                    .bearer_auth(&pending.authorization)
                    .send()
                    .await
                    .map_err(|_| "DNS naming service unreachable")?;
                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    // An explicit rejection of an expired proof after the
                    // backend's bounded probe window establishes non-application.
                    // Exact replays of an applied request succeed before probing.
                    if matches!(status, 400 | 422)
                        && pending.proof_expires_at != 0
                        && now_unix() > pending.proof_expires_at.saturating_add(40)
                    {
                        self.transaction(|state| {
                            if state
                                .names
                                .pending
                                .as_ref()
                                .is_some_and(|p| p.id == pending.id)
                            {
                                state.names.pending = None;
                            }
                            Ok(())
                        })?;
                    }
                    return Err(format!("DNS naming service refused ({status})"));
                }
                let response: NameResponse = serde_json::from_slice(&bounded_body(response).await?)
                    .map_err(|_| "invalid DNS naming response")?;
                self.transaction(|state| {
                    let defaults = self.selected_defaults(state, now_unix())?;
                    pending.response(&response, &defaults)?;
                    if !state
                        .names
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.id == pending.id)
                    {
                        return Ok(());
                    }
                    if let Some(old) = &state.names.registration {
                        if old.response.node_handle != response.node_handle
                            || old.response.fqdn != response.fqdn
                            || old.service_id != pending.service_id
                        {
                            return Err("DNS response changed retained name identity".into());
                        }
                    }
                    state.names.registration = Some(Registration {
                        authority: pending.authority.clone(),
                        service_id: pending.service_id,
                        address: pending.address,
                        response,
                        removed: matches!(pending.operation, Operation::Remove { .. }),
                    });
                    state.names.pending = None;
                    Ok(())
                })
            };
            tokio::time::timeout_at(deadline, attempt)
                .await
                .map_err(|_| "DNS update deadline elapsed")??;
        }
        self.transaction(|state| {
            Ok(state
                .names
                .registration
                .as_ref()
                .filter(|r| !r.removed)
                .map(|r| r.response.clone()))
        })
    }
}
fn random_id() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}
fn encoded(bundle: &BootstrapBundle) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(
        bundle
            .encode()
            .map_err(|_| "invalid DNS listener introduction")?,
    ))
}
