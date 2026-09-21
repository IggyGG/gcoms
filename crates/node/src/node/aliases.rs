// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;
use std::time::Duration;

pub(crate) async fn consume_provision(
    scheduler: &RelayScheduler,
    info: &NodeInfo,
) -> Result<RelayProvision, String> {
    let provision = info
        .provisioning
        .as_ref()
        .ok_or("relay card has no private provisioning fields")?;
    for owned in &provision.aliases {
        scheduler
            .admin_post(
                owned.contact.target.clone(),
                owned.create_path.clone(),
                owned.lease_create.clone(),
            )
            .map_err(|e| e.to_string())?
            .completion()
            .await
            .accepted()?;
    }
    Ok(provision.clone())
}

pub(crate) async fn create_contact_alias(
    scheduler: &RelayScheduler,
    authority: &OwnedAlias,
) -> Result<OwnedAlias, String> {
    provision_contact_alias(scheduler, authority, None).await
}

/// Restore an owned queue without changing the public address in an MLS package.
/// An authenticated cover deposit checks an existing queue without consuming data.
pub(crate) async fn restore_contact_alias(
    scheduler: &RelayScheduler,
    authority: &OwnedAlias,
    saved: &OwnedAlias,
) -> Result<OwnedAlias, String> {
    if saved.contact.expiry <= now_unix() {
        return Err("prepared channel route expired".into());
    }
    #[cfg(feature = "experimental-gc2")]
    if scheduler.is_gc2() {
        use gcoms_protocol::relay::gc2::{Forward, Push, UnverifiedPush};
        let expiry = now_unix().saturating_add(60).min(saved.contact.expiry);
        let push = Push {
            class: gcoms_core::TrafficClass::Interactive,
            queue_id: saved.contact.queue_id,
            epoch: saved.contact.epoch,
            nonce: random_nonzero(),
            expiry,
            msg: None,
        }
        .encode(
            &saved.capabilities.push,
            &saved.contact.target.relay_service_id,
        )
        .map_err(|e| e.to_string())?;
        let result = scheduler
            .forward_gc2(Forward {
                class: gcoms_core::TrafficClass::Interactive,
                target: saved.contact.target.clone(),
                expiry,
                nonce: random_nonzero(),
                push: Some(UnverifiedPush::parse(push).map_err(|e| e.to_string())?),
            })
            .map_err(|e| e.to_string())?
            .completion()
            .await
            .accepted();
        if result.is_ok() {
            return Ok(saved.clone());
        }
        if saved.contact.target != authority.contact.target {
            return Err("prepared channel relay is unavailable".into());
        }
        return provision_contact_alias(scheduler, authority, Some(saved)).await;
    }
    let cover = crate::relay::RelayPush::cover(
        saved.contact.queue_id,
        saved.contact.epoch,
        random_nonzero(),
        now_unix().saturating_add(60).min(saved.contact.expiry),
    )
    .encode_into_cell(
        &saved.capabilities.push,
        &saved.contact.target.relay_service_id,
    )
    .map_err(|error| error.to_string())?;
    if scheduler
        .admin_post(
            saved.contact.target.clone(),
            encode_b64url(&saved.contact.queue_id),
            cover,
        )
        .map_err(|error| error.to_string())?
        .completion()
        .await
        .accepted()
        .is_ok()
    {
        return Ok(saved.clone());
    }
    if saved.contact.target != authority.contact.target {
        return Err("prepared channel relay is unavailable".into());
    }
    provision_contact_alias(scheduler, authority, Some(saved)).await
}

async fn provision_contact_alias(
    scheduler: &RelayScheduler,
    authority: &OwnedAlias,
    saved: Option<&OwnedAlias>,
) -> Result<OwnedAlias, String> {
    let now = now_unix();
    let queue_id = saved.map_or_else(random_nonzero, |alias| alias.contact.queue_id);
    let epoch = saved.map_or_else(
        || u64::from_be_bytes(random_nonzero()),
        |alias| alias.contact.epoch,
    );
    let limits = saved.map_or(
        LeaseLimits {
            max_queue_cells: crate::lease::DEFAULT_QUEUE_CELLS,
            max_queue_bytes: crate::lease::DEFAULT_QUEUE_BYTES,
        },
        |alias| alias.limits,
    );
    let request = DynamicGrantRequest {
        authority_queue_id: authority.contact.queue_id,
        authority_epoch: authority.contact.epoch,
        queue_id,
        epoch,
        limits,
        nonce: random_nonzero(),
        expiry: now.saturating_add(60),
    };
    let request_wire = request
        .encode(
            &authority.capabilities.admin,
            &authority.contact.target.relay_service_id,
        )
        .map_err(|error| error.to_string())?;
    let response = scheduler
        .admin_post(
            authority.contact.target.clone(),
            authority.create_path.clone(),
            Cell::new(CellType::RelaySub, 0, 0, request_wire.to_vec()),
        )
        .map_err(|error| error.to_string())?
        .completion()
        .await
        .accepted()?;
    let reply = gcoms_core::decode(&response).map_err(|_| "malformed contact grant response")?;
    if reply.cell_type() != Some(CellType::Ack)
        || reply.payload.len() != crate::lease::ADMISSION_GRANT_LEN
    {
        return Err("malformed contact grant response".into());
    }
    let grant: [u8; crate::lease::ADMISSION_GRANT_LEN] = reply
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| "malformed contact grant response")?;
    let grant_cap: [u8; 32] = grant[49..81]
        .try_into()
        .map_err(|_| "malformed contact grant response")?;
    let capabilities = saved.map_or_else(
        || Capabilities {
            push: random_nonzero(),
            sub: random_nonzero(),
            admin: random_nonzero(),
        },
        |alias| alias.capabilities,
    );
    let expiry = saved.map_or_else(
        || now.saturating_add(24 * 60 * 60),
        |alias| alias.contact.expiry,
    );
    let create = LeaseCreate {
        queue_id,
        epoch,
        lease_expiry: expiry,
        queue_cells: limits.max_queue_cells,
        queue_bytes: limits.max_queue_bytes,
        capabilities,
        nonce: random_nonzero(),
        grant,
    };
    let create_wire = create
        .encode(&authority.contact.target.relay_service_id)
        .map_err(|error| error.to_string())?;
    let create_path = encode_b64url(&grant_cap);
    let lease_create = Cell::new(CellType::RelaySub, 0, 0, create_wire.to_vec());
    scheduler
        .admin_post(
            authority.contact.target.clone(),
            create_path.clone(),
            lease_create.clone(),
        )
        .map_err(|error| error.to_string())?
        .completion()
        .await
        .accepted()?;
    Ok(OwnedAlias {
        contact: AliasContact {
            target: authority.contact.target.clone(),
            queue_id,
            epoch,
            push_cap: capabilities.push,
            expiry,
        },
        capabilities,
        limits,
        create_path,
        lease_create,
    })
}

pub(crate) async fn revoke_contact_alias(
    scheduler: &RelayScheduler,
    alias: &OwnedAlias,
) -> Result<(), String> {
    revoke_contact_alias_until(
        scheduler,
        alias,
        now_unix().saturating_add(60).min(alias.contact.expiry),
    )
    .await
}

async fn revoke_contact_alias_until(
    scheduler: &RelayScheduler,
    alias: &OwnedAlias,
    expires: u64,
) -> Result<(), String> {
    if expires <= now_unix() {
        return Err("alias cleanup authority expired".into());
    }
    let revoke = LeaseRevoke {
        queue_id: alias.contact.queue_id,
        epoch: alias.contact.epoch,
        operation_expiry: expires,
        nonce: random_nonzero(),
    };
    let wire = revoke
        .encode(
            &alias.capabilities.admin,
            &alias.contact.target.relay_service_id,
        )
        .map_err(|error| error.to_string())?;
    scheduler
        .admin_post(
            alias.contact.target.clone(),
            alias.create_path.clone(),
            Cell::new(CellType::RelaySub, 0, 0, wire.to_vec()),
        )
        .map_err(|error| error.to_string())?
        .completion()
        .await
        .accepted()?;
    Ok(())
}

pub(crate) async fn provision_channel_route(
    scheduler: &RelayScheduler,
    relay: &RelayProvision,
    pseudonym: [u8; 32],
    direct_secret: [u8; 32],
) -> Result<crate::channel::OwnedChannelRoute, String> {
    let authority = relay
        .aliases
        .first()
        .ok_or("relay provision has no admin authority")?;
    let mut aliases = Vec::with_capacity(2);
    for _ in 0..2 {
        let now = now_unix();
        let queue_id = random_nonzero();
        let epoch = u64::from_be_bytes(random_nonzero());
        let limits = LeaseLimits {
            max_queue_cells: crate::lease::DEFAULT_QUEUE_CELLS,
            max_queue_bytes: crate::lease::DEFAULT_QUEUE_BYTES,
        };
        let request = DynamicGrantRequest {
            authority_queue_id: authority.contact.queue_id,
            authority_epoch: authority.contact.epoch,
            queue_id,
            epoch,
            limits,
            nonce: random_nonzero(),
            expiry: now.saturating_add(60),
        };
        let request_wire = request
            .encode(
                &authority.capabilities.admin,
                &authority.contact.target.relay_service_id,
            )
            .map_err(|error| error.to_string())?;
        let cell = Cell::new(CellType::RelaySub, 0, 0, request_wire.to_vec());
        let response = scheduler
            .admin_post(
                authority.contact.target.clone(),
                authority.create_path.clone(),
                cell,
            )
            .map_err(|error| error.to_string())?
            .completion()
            .await
            .accepted()?;
        let reply =
            gcoms_core::decode(&response).map_err(|_| "malformed channel grant response")?;
        if reply.cell_type() != Some(CellType::Ack)
            || reply.payload.len() != crate::lease::ADMISSION_GRANT_LEN
        {
            return Err("malformed channel grant response".into());
        }
        let grant: [u8; crate::lease::ADMISSION_GRANT_LEN] = reply
            .payload
            .as_slice()
            .try_into()
            .map_err(|_| "malformed channel grant response")?;
        let grant_cap: [u8; 32] = grant[49..81]
            .try_into()
            .map_err(|_| "malformed channel grant response")?;
        let capabilities = Capabilities {
            push: random_nonzero(),
            sub: random_nonzero(),
            admin: random_nonzero(),
        };
        let lease_expiry = now.saturating_add(60 * 60);
        let create = LeaseCreate {
            queue_id,
            epoch,
            lease_expiry,
            queue_cells: limits.max_queue_cells,
            queue_bytes: limits.max_queue_bytes,
            capabilities,
            nonce: random_nonzero(),
            grant,
        };
        let create_wire = create
            .encode(&authority.contact.target.relay_service_id)
            .map_err(|error| error.to_string())?;
        let cell = Cell::new(CellType::RelaySub, 0, 0, create_wire.to_vec());
        let create_path = encode_b64url(&grant_cap);
        scheduler
            .admin_post(
                authority.contact.target.clone(),
                create_path.clone(),
                cell.clone(),
            )
            .map_err(|error| error.to_string())?
            .completion()
            .await
            .accepted()?;
        aliases.push(OwnedAlias {
            contact: AliasContact {
                target: authority.contact.target.clone(),
                queue_id,
                epoch,
                push_cap: capabilities.push,
                expiry: lease_expiry,
            },
            capabilities,
            limits,
            create_path,
            lease_create: cell,
        });
    }
    let public = crate::channel::ChannelRoute {
        pseudonym,
        direct_public: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            direct_secret,
        ))
        .to_bytes(),
        data: aliases[0].contact.clone(),
        control: aliases[1].contact.clone(),
    };
    if !public.is_valid() {
        return Err("relay returned non-independent channel route capabilities".into());
    }
    Ok(crate::channel::OwnedChannelRoute {
        public,
        direct_secret,
        aliases,
    })
}

pub(crate) async fn renew_contact_aliases(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
    force: bool,
) -> Result<(), String> {
    let now = now_unix();
    let aliases = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .client_relay
        .aliases
        .clone();
    let mut changed = false;
    for alias in aliases {
        if !force && alias.contact.expiry.saturating_sub(now) > 12 * 60 * 60 {
            continue;
        }
        // A lease created this second is already at the relay's 24-hour
        // limit. Adding one to it would be rejected even with a valid MAC.
        // Give an explicit renewal one clock tick, then revalidate ownership
        // and its original deadline before constructing the request.
        if force && now_unix().saturating_add(24 * 60 * 60) <= alias.contact.expiry {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let expiry = now_unix().saturating_add(24 * 60 * 60);
        if expiry <= alias.contact.expiry {
            if force {
                return Err("contact lease is not yet eligible for extension".into());
            }
            continue;
        }
        let budget = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            if !owner_alias_available(&st, &alias) {
                return Err("owner alias unavailable for renewal".into());
            }
            #[cfg(feature = "client-persist")]
            let budget = {
                let (effective, deadline) =
                    super::persist::owner_aliases::alias_deadline(&st, &alias)?;
                Duration::from_millis(deadline.saturating_sub(effective))
            };
            #[cfg(not(feature = "client-persist"))]
            let budget = Duration::from_secs(alias.contact.expiry.saturating_sub(now_unix()));
            budget
        };
        let renew = LeaseRenew {
            queue_id: alias.contact.queue_id,
            epoch: alias.contact.epoch,
            lease_expiry: expiry,
            nonce: random_nonzero(),
        };
        let wire = renew
            .encode(
                &alias.capabilities.admin,
                &alias.contact.target.relay_service_id,
            )
            .map_err(|e| e.to_string())?;
        let cell = Cell::new(CellType::RelaySub, 0, 0, wire.to_vec());
        let renewed = match scheduler.admin_post(
            alias.contact.target.clone(),
            alias.create_path.clone(),
            cell,
        ) {
            Ok(receipt) => tokio::time::timeout(budget, receipt.completion())
                .await
                .is_ok_and(|result| result.accepted().is_ok()),
            Err(_) => false,
        };
        if renewed {
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            apply_accepted_owner_renewal(&mut st, &alias, expiry, &wire)?;
            changed = true;
        }
        metrics::log_event("lease_renew", &[("ok", renewed.to_string())]);
    }
    if !changed {
        return Ok(());
    }
    let (generation, info, deliveries, policy, natural) = {
        let mut st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let deliveries = queue_contact_updates(&mut st)?;
        (
            st.local_contact_generation,
            st.info.clone(),
            deliveries,
            st.frwd_target_policy.clone(),
            natural_client(&st),
        )
    };
    let _ = events.send(Ev::IdentityUpdated { info, generation });
    for delivery in deliveries {
        let _ = deliver_direct(
            scheduler,
            &delivery,
            &policy,
            gcoms_core::TrafficClass::Interactive,
            natural.as_ref(),
        )
        .await;
    }
    Ok(())
}

/// Serialize an owner lifecycle candidate in the complete archive before any
/// observer can obtain its new contact. The caller holds the state mutex.
/// Only called after the existing scheduler reports authenticated acceptance.
/// The retained wire is owner-sealed provenance, never a replacement grant.
pub(super) fn apply_accepted_owner_renewal(
    st: &mut NodeState,
    prior: &OwnedAlias,
    expiry: u64,
    wire: &[u8],
) -> Result<(), String> {
    if !owner_alias_available(st, prior) {
        return Err("owner alias expired before renewal publication".into());
    }
    let index = st
        .client_relay
        .aliases
        .iter()
        .position(|a| a == prior)
        .ok_or("owner alias changed during renewal")?;
    #[cfg(feature = "client-persist")]
    {
        let mut accepted = prior.clone();
        accepted.contact.expiry = expiry;
        crate::lease::validate_retained_alias_renewal(&accepted, Some(wire))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(feature = "client-persist"))]
    let _ = wire;
    owner_transition(st, |st| {
        #[cfg(feature = "client-persist")]
        {
            st.owner_alias_origins
                .entry(prior.contact.queue_id)
                .or_insert_with(|| prior.clone());
            st.owner_alias_renewals
                .insert(prior.contact.queue_id, wire.to_vec());
        }
        st.client_relay.aliases[index].contact.expiry = expiry;
        st.info.aliases[index].expiry = expiry;
        Ok(())
    })
}

pub(super) fn owner_transition(
    st: &mut NodeState,
    change: impl FnOnce(&mut NodeState) -> Result<(), String>,
) -> Result<(), String> {
    if st.owner_transition_failed {
        return Err("owner lifecycle persistence outcome is unconfirmed".into());
    }
    #[cfg(feature = "client-persist")]
    let old_clock = st
        .owner_clock
        .lock()
        .map_err(|_| "owner clock poisoned")?
        .clone();
    #[cfg(feature = "client-persist")]
    let old_operations = (
        st.owner_alias_origins.clone(),
        st.owner_alias_renewals.clone(),
    );
    let old = (
        st.client_relay.clone(),
        st.info.clone(),
        st.contact_aliases_activated,
        st.staged_contact_aliases.clone(),
        st.unannounced_old_contact_aliases.clone(),
        st.unannounced_contact_deadlines,
        st.draining_contact_aliases.clone(),
    );
    let changed = change(st);
    let result = changed.and_then(|()| persist_current_direct_state(st));
    #[cfg(feature = "client-persist")]
    let result = result.and_then(|()| super::persist::owner_aliases::validate_current_live(st));
    if result.is_err() {
        (
            st.client_relay,
            st.info,
            st.contact_aliases_activated,
            st.staged_contact_aliases,
            st.unannounced_old_contact_aliases,
            st.unannounced_contact_deadlines,
            st.draining_contact_aliases,
        ) = old;
        // A sink may have committed before returning an error. Never retry with
        // a new schedule or overwrite that uncertain durable candidate in-process.
        #[cfg(feature = "client-persist")]
        {
            st.owner_clock = Mutex::new(old_clock);
            (st.owner_alias_origins, st.owner_alias_renewals) = old_operations;
        }
        st.pause_failed_owner_transition();
    }
    result
}

fn promote_staged_contact_aliases(
    st: &mut NodeState,
    now: std::time::Instant,
    timing: AliasLifecycleConfig,
) -> Result<bool, String> {
    let ready = st.staged_contact_aliases.as_ref().is_some_and(|aliases| {
        aliases.len() == 2
            && aliases.iter().all(|alias| {
                st.subscribed_contact_aliases
                    .contains(&alias.contact.queue_id)
            })
    });
    if !ready {
        return Ok(false);
    }
    let receive_until = now
        .checked_add(timing.alias_drain)
        .ok_or("alias drain overflow")?;
    let abandon_at = receive_until
        .checked_add(timing.revoke_timeout)
        .ok_or("alias abandon overflow")?;
    owner_transition(st, |st| {
        let next = st
            .staged_contact_aliases
            .take()
            .ok_or("missing staged aliases")?;
        let old = std::mem::replace(&mut st.client_relay.aliases, next);
        st.info.aliases = st
            .client_relay
            .aliases
            .iter()
            .map(|a| a.contact.clone())
            .collect();
        st.contact_aliases_activated = now;
        st.unannounced_old_contact_aliases = Some(old);
        st.unannounced_contact_deadlines = Some((receive_until, abandon_at));
        Ok(())
    })?;
    Ok(true)
}

pub(crate) fn owner_alias_available(st: &NodeState, alias: &OwnedAlias) -> bool {
    #[cfg(feature = "client-persist")]
    {
        matches!(super::persist::owner_aliases::alias_deadline(st, alias), Ok((now, until)) if now < until)
    }
    #[cfg(not(feature = "client-persist"))]
    {
        let _ = st;
        alias.contact.expiry > now_unix()
    }
}

pub(crate) fn owner_alias_receiving(st: &NodeState, alias: &OwnedAlias) -> bool {
    if st.owner_transition_failed {
        return false;
    }
    let now = std::time::Instant::now();
    let matches = |candidate: &OwnedAlias| {
        candidate.contact.queue_id == alias.contact.queue_id
            && candidate.contact.epoch == alias.contact.epoch
    };
    let present = st.client_relay.aliases.iter().any(matches)
        || st.staged_contact_aliases.iter().flatten().any(matches)
        || (st
            .unannounced_contact_deadlines
            .is_some_and(|(receive, abandon)| receive > now && abandon > now)
            && st
                .unannounced_old_contact_aliases
                .iter()
                .flatten()
                .any(matches))
        || st
            .draining_contact_aliases
            .iter()
            .any(|g| g.receive_until > now && g.abandon_at > now && g.aliases.iter().any(matches));
    if !present {
        return false;
    }
    #[cfg(feature = "client-persist")]
    {
        matches!(super::persist::owner_aliases::receive_deadline(st, alias), Ok((now, until)) if now < until)
    }
    #[cfg(not(feature = "client-persist"))]
    {
        alias.contact.expiry > now_unix()
    }
}

fn retire_expired_owner_roles(st: &mut NodeState, now: std::time::Instant) -> Result<(), String> {
    let staged_expired = st
        .staged_contact_aliases
        .as_ref()
        .is_some_and(|aliases| aliases.iter().any(|a| !owner_alias_available(st, a)));
    let old_expired = st
        .unannounced_old_contact_aliases
        .as_ref()
        .is_some_and(|aliases| {
            st.unannounced_contact_deadlines
                .is_none_or(|(_, until)| until <= now)
                || aliases.iter().any(|a| !owner_alias_available(st, a))
        });
    let draining = st
        .draining_contact_aliases
        .iter()
        .filter_map(|group| {
            if group.abandon_at <= now {
                return None;
            }
            let mut group = group.clone();
            group.aliases.retain(|a| owner_alias_available(st, a));
            (!group.aliases.is_empty()).then_some(group)
        })
        .collect::<Vec<_>>();
    let draining_changed = draining.len() != st.draining_contact_aliases.len()
        || draining
            .iter()
            .zip(&st.draining_contact_aliases)
            .any(|(a, b)| a.aliases != b.aliases);
    if staged_expired || old_expired || draining_changed {
        owner_transition(st, |st| {
            if staged_expired {
                st.staged_contact_aliases = None;
            }
            if old_expired {
                st.unannounced_old_contact_aliases = None;
                st.unannounced_contact_deadlines = None;
            }
            st.draining_contact_aliases = draining;
            Ok(())
        })?;
    }
    Ok(())
}

pub(crate) async fn contact_alias_lifecycle_tick(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
    timing: AliasLifecycleConfig,
) {
    let now = std::time::Instant::now();
    if state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .owner_transition_failed
    {
        return;
    }
    {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(error) = retire_expired_owner_roles(&mut st, now) {
            metrics::log_event("alias_expired_retirement_error", &[("e", error)]);
            return;
        }
    }
    let authority = {
        let st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        #[cfg(feature = "client-persist")]
        let due = match super::persist::owner_aliases::rotation_due(&st, timing) {
            Ok(due) => due,
            Err(error) => {
                metrics::log_event("alias_clock_error", &[("e", error)]);
                return;
            }
        };
        #[cfg(not(feature = "client-persist"))]
        let due = now.duration_since(st.contact_aliases_activated) >= timing.alias_ttl;
        (st.staged_contact_aliases.is_none()
            && st.unannounced_old_contact_aliases.is_none()
            && st.draining_contact_aliases.is_empty()
            && due)
            .then(|| {
                st.client_relay
                    .aliases
                    .first()
                    .filter(|alias| owner_alias_available(&st, alias))
                    .cloned()
            })
            .flatten()
    };
    if let Some(authority) = authority {
        let staged = match create_contact_alias(scheduler, &authority).await {
            Ok(first) => match create_contact_alias(scheduler, &authority).await {
                Ok(second) => Some(vec![first, second]),
                Err(error) => {
                    let _ = revoke_contact_alias(scheduler, &first).await;
                    metrics::log_event("alias_create_error", &[("e", error)]);
                    None
                }
            },
            Err(error) => {
                metrics::log_event("alias_create_error", &[("e", error)]);
                None
            }
        };
        if let Some(staged) = staged {
            let mut st = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if st.staged_contact_aliases.is_none()
                && st.unannounced_old_contact_aliases.is_none()
                && st.draining_contact_aliases.is_empty()
            {
                if let Err(error) = owner_transition(&mut st, |st| {
                    st.staged_contact_aliases = Some(staged);
                    Ok(())
                }) {
                    metrics::log_event("alias_stage_persist_error", &[("e", error)]);
                    return;
                }
            }
        }
    }

    {
        let mut st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) = promote_staged_contact_aliases(&mut st, now, timing) {
            metrics::log_event("alias_promotion_persist_error", &[("e", error)]);
            return;
        }
    }

    let announcement = {
        let mut st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if st.unannounced_old_contact_aliases.is_some() {
            match queue_contact_updates(&mut st) {
                Ok(deliveries) => {
                    let committed = owner_transition(&mut st, |st| {
                        let aliases = st
                            .unannounced_old_contact_aliases
                            .take()
                            .ok_or("missing announcement aliases")?;
                        let (receive_until, abandon_at) =
                            st.unannounced_contact_deadlines
                                .take()
                                .ok_or("missing announcement deadlines")?;
                        st.draining_contact_aliases.push(DrainingContactAliases {
                            aliases,
                            receive_until,
                            abandon_at,
                            next_revoke: receive_until,
                        });
                        Ok(())
                    });
                    if let Err(error) = committed {
                        metrics::log_event("alias_announcement_persist_error", &[("e", error)]);
                        None
                    } else {
                        Some((
                            st.local_contact_generation,
                            st.info.clone(),
                            deliveries,
                            st.frwd_target_policy.clone(),
                            natural_client(&st),
                        ))
                    }
                }
                Err(error) => {
                    metrics::log_event("contact_update_error", &[("e", error)]);
                    None
                }
            }
        } else {
            None
        }
    };
    if let Some((generation, info, deliveries, policy, natural)) = announcement {
        let _ = events.send(Ev::IdentityUpdated { info, generation });
        for delivery in deliveries {
            let _ = deliver_direct(
                scheduler,
                &delivery,
                &policy,
                gcoms_core::TrafficClass::Interactive,
                natural.as_ref(),
            )
            .await;
        }
    }

    let revoke_candidates = {
        let st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        st.draining_contact_aliases
            .iter()
            .filter(|draining| draining.next_revoke <= now && draining.abandon_at > now)
            .flat_map(|draining| {
                draining
                    .aliases
                    .iter()
                    .filter(|alias| owner_alias_available(&st, alias))
                    .cloned()
                    .map(|alias| (alias, draining.abandon_at))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    for (alias, abandon_at) in revoke_candidates {
        let queue_id = alias.contact.queue_id;
        let remaining = abandon_at.saturating_duration_since(std::time::Instant::now());
        #[cfg(feature = "client-persist")]
        let remaining = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            match super::persist::owner_aliases::alias_deadline(&st, &alias) {
                Ok((now_ms, until_ms)) => remaining.min(std::time::Duration::from_millis(
                    until_ms.saturating_sub(now_ms),
                )),
                Err(error) => {
                    metrics::log_event("alias_cleanup_clock_error", &[("e", error)]);
                    return;
                }
            }
        };
        let expires = now_unix()
            .saturating_add(remaining.as_secs().min(60))
            .min(alias.contact.expiry);
        let revoked = if remaining.is_zero() {
            false
        } else {
            matches!(
                tokio::time::timeout(
                    remaining,
                    revoke_contact_alias_until(scheduler, &alias, expires)
                )
                .await,
                Ok(Ok(()))
            )
        };
        let now = std::time::Instant::now();
        let mut st = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) = owner_transition(&mut st, |st| {
            for draining in &mut st.draining_contact_aliases {
                if revoked || now >= draining.abandon_at {
                    draining
                        .aliases
                        .retain(|candidate| candidate.contact.queue_id != queue_id);
                } else if draining
                    .aliases
                    .iter()
                    .any(|candidate| candidate.contact.queue_id == queue_id)
                {
                    draining.next_revoke = now
                        .checked_add(timing.revoke_retry)
                        .ok_or("alias retry overflow")?
                        .min(draining.abandon_at);
                }
            }
            st.draining_contact_aliases
                .retain(|draining| !draining.aliases.is_empty());
            Ok(())
        }) {
            metrics::log_event("alias_retirement_persist_error", &[("e", error)]);
            return;
        }
        metrics::log_event("alias_revoke", &[("ok", revoked.to_string())]);
    }
}

pub(crate) fn contact_update_message_id(identity: &[u8], peer: &[u8], generation: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"gc1/contact-update/message-id/v1\0");
    digest.update(identity);
    digest.update(peer);
    digest.update(generation.to_be_bytes());
    digest.finalize()[..16].try_into().expect("SHA-256 prefix")
}

pub(crate) fn queue_contact_updates(st: &mut NodeState) -> Result<Vec<DirectDelivery>, String> {
    st.local_contact_generation = st
        .local_contact_generation
        .checked_add(1)
        .ok_or("contact generation exhausted")?;
    let issued_at = now_unix();
    let bundle = Bundle::decode(&st.info.bundle).ok_or("local bundle is invalid")?;
    if issued_at.saturating_sub(bundle.created) > crate::proto::MAX_BUNDLE_AGE_SECS / 2 {
        let identity = IdentityKeypair::from_seed(st.identity_seed);
        let (bundle, secrets) = identity.issue_bundle();
        st.info.bundle = bundle.encode();
        st.secrets = Arc::new(secrets);
        for session in st.sessions.values_mut() {
            session.provide_local_secrets(&st.secrets);
        }
    }
    let expires_at = st
        .info
        .aliases
        .iter()
        .map(|alias| alias.expiry)
        .min()
        .ok_or("local identity has no aliases")?;
    let identity = IdentityKeypair::from_seed(st.identity_seed);
    let update = ContactUpdate::sign(
        st.local_contact_generation,
        issued_at,
        expires_at,
        st.info.clone(),
        &identity,
    )
    .ok_or("contact update exceeds encoding limit")?;
    if !update.verify(&st.info.identity_pk, issued_at) {
        return Err("local contact update is invalid".into());
    }
    // An initiator may restart after its first frame was received but before
    // committing the reply. It already disclosed its route in that first move;
    // refreshing it must not wait for a reply addressed to the now-dead route.
    let peers = st.sessions.keys().cloned().collect::<Vec<_>>();
    let mut deliveries = Vec::new();
    for peer in peers {
        if st.pending_1to1.len() >= 1024 {
            break;
        }
        if !st.peer_routes.contains_key(&peer) {
            continue;
        }
        let message_id = contact_update_message_id(&st.info.identity_pk, &peer, update.generation);
        if st.pending_1to1.contains_key(&message_id) {
            continue;
        }
        let record = encode_contact_update(message_id, &update)
            .ok_or("contact update exceeds direct record limit")?;
        let lifetime = std::time::Duration::from_secs(expires_at.saturating_sub(issued_at).max(1));
        if let Some(delivery) = queue_session_control(
            st,
            &peer,
            message_id,
            record,
            lifetime,
            std::time::Duration::from_secs(60),
        )? {
            deliveries.push(delivery);
        }
        // Renewals also refresh the peer's authority to route through us.
        if let Ok(Some(grant_delivery)) = queue_forward_grant(st, &peer) {
            deliveries.push(grant_delivery);
        }
    }
    if deliveries.is_empty() {
        persist_current_direct_state(st)?;
    }
    Ok(deliveries)
}

struct InboxReplacement {
    activated: std::time::Instant,
    receive_until: std::time::Instant,
    abandon_at: std::time::Instant,
    staged_abandon_at: std::time::Instant,
}

fn preflight_inbox_replacement(st: &NodeState) -> Result<InboxReplacement, String> {
    if st.owner_transition_failed {
        return Err("owner transition requires recovery".into());
    }
    if st.routing.is_none()
        && (st.staged_contact_aliases.is_some() || st.unannounced_old_contact_aliases.is_some())
    {
        return Err("alias transition pending".into());
    }
    let activated = std::time::Instant::now();
    if st.routing.is_some() {
        let retained = st
            .draining_contact_aliases
            .iter()
            .filter(|group| group.abandon_at > activated)
            .count()
            + usize::from(st.unannounced_old_contact_aliases.is_some())
            + usize::from(st.staged_contact_aliases.is_some());
        if retained > 5 {
            return Err("retained inbox cleanup capacity reached".into());
        }
        if st.unannounced_old_contact_aliases.is_some()
            && st.unannounced_contact_deadlines.is_none()
        {
            return Err("missing retained cleanup deadlines".into());
        }
    }
    let receive_until = activated
        .checked_add(st.alias_lifecycle_timing.alias_drain)
        .ok_or("alias drain overflow")?;
    let abandon_at = receive_until
        .checked_add(st.alias_lifecycle_timing.revoke_timeout)
        .ok_or("alias abandon overflow")?;
    let staged_abandon_at = activated
        .checked_add(st.alias_lifecycle_timing.revoke_timeout)
        .ok_or("alias cleanup overflow")?;
    Ok(InboxReplacement {
        activated,
        receive_until,
        abandon_at,
        staged_abandon_at,
    })
}

/// Replace an unavailable inbox after trusted remote provisioning succeeds.
pub(crate) async fn install_inbox_relay(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
    card: &NodeInfo,
) -> Result<(), String> {
    {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        preflight_inbox_replacement(&st)?;
        if let Some(runtime) = &st.routing {
            if let Some(own) = runtime.own_introduction() {
                if card
                    .aliases
                    .iter()
                    .any(|a| own.conflicts(a.target.address, a.target.relay_service_id))
                {
                    return Err("a node cannot publish its own listener as its inbox".into());
                }
            }
        }
    }
    if card.provisioning.as_ref().map(|p| p.aliases.len()) != Some(2) {
        return Err("relay requires normal and control aliases".into());
    }
    let provision = consume_provision(scheduler, card).await?;
    let (info, generation, deliveries, policy, natural) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        // Provisioning awaits the network; recheck capacity before mutating the
        // owner record. A routine capacity refusal must not pause the owner.
        let timing = preflight_inbox_replacement(&st)?;
        owner_transition(&mut st, |st| {
            // A failed active relay may be replaced during an earlier route
            // announcement. Retain those cleanup groups at their old deadlines.
            if st.routing.is_some() {
                let now = timing.activated;
                st.draining_contact_aliases.retain(|g| g.abandon_at > now);
                if let Some(aliases) = st.unannounced_old_contact_aliases.take() {
                    let (receive_until, abandon_at) = st
                        .unannounced_contact_deadlines
                        .take()
                        .expect("preflight checked retained cleanup deadlines");
                    st.draining_contact_aliases.push(DrainingContactAliases {
                        aliases,
                        receive_until,
                        abandon_at,
                        next_revoke: receive_until,
                    });
                }
                if let Some(aliases) = st.staged_contact_aliases.take() {
                    st.draining_contact_aliases.push(DrainingContactAliases {
                        aliases,
                        receive_until: now,
                        next_revoke: now,
                        abandon_at: timing.staged_abandon_at,
                    });
                }
            }
            let old = std::mem::replace(&mut st.client_relay, provision);
            st.info.aliases = st
                .client_relay
                .aliases
                .iter()
                .map(|a| a.contact.clone())
                .collect();
            st.contact_aliases_activated = timing.activated;
            if old.aliases.is_empty() {
                return Ok(());
            }
            st.unannounced_old_contact_aliases = Some(old.aliases);
            st.unannounced_contact_deadlines = Some((timing.receive_until, timing.abandon_at));
            Ok(())
        })?;
        let deliveries = queue_contact_updates(&mut st)?;
        (
            st.info.clone(),
            st.local_contact_generation,
            deliveries,
            st.frwd_target_policy.clone(),
            natural_client(&st),
        )
    };
    let _ = events.send(Ev::IdentityUpdated { info, generation });
    for delivery in deliveries {
        let _ = deliver_direct(
            scheduler,
            &delivery,
            &policy,
            gcoms_core::TrafficClass::Interactive,
            natural.as_ref(),
        )
        .await;
    }
    Ok(())
}
