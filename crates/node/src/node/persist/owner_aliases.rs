//! Bounded, seed-authenticated owner route record. This codec is deliberately
//! separate from archive-version selection and authenticated relay admission.
use super::*;
use std::time::{Duration, Instant};

const MAX_GROUPS: usize = 16;
const MAX_RECORD_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum Role {
    Active = 1,
    Staged = 2,
    Unannounced = 3,
    Draining = 4,
}

#[derive(Clone)]
pub(in crate::node) struct Group {
    pub role: Role,
    pub provision: RelayProvision,
    /// The first sealed operation for each queue, retained across current
    /// authenticated re-admission. Never itself treated as a current grant.
    pub origins: Vec<OwnedAlias>,
    /// Original absolute role lifetime, capped by every alias lease expiry.
    pub deadline_ms: u64,
    /// Active rotation or old-alias revoke boundary; zero only for staging.
    pub action_ms: u64,
    pub receive_until_ms: u64,
}

#[derive(Clone)]
pub(in crate::node) struct Record {
    pub captured_ms: u64,
    pub activated_ms: u64,
    pub groups: Vec<Group>,
    pub renewals: HashMap<[u8; 32], Vec<u8>>,
}

/// Host-clock observations are authenticated local evidence, not external time.
/// Restoring time can only consume a sealed budget. Regression is a refusal.
#[derive(Clone)]
pub(in crate::node) struct RestoreClock {
    start: Instant,
    wall_start_ms: u64,
    last_wall_ms: u64,
    last_instant: Instant,
    last_effective_ms: u64,
    limits: HashMap<[u8; 32], (Role, u64, u64, u64)>,
    activation: Option<(Vec<[u8; 32]>, u64)>,
}

impl RestoreClock {
    pub fn fresh() -> Result<Self, String> {
        let wall = now_ms();
        Self::new(wall, wall, Instant::now())
    }

    pub fn new(captured_ms: u64, wall_ms: u64, start: Instant) -> Result<Self, String> {
        if captured_ms == 0 || wall_ms < captured_ms {
            return Err("owner alias clock precedes saved observation".into());
        }
        Ok(Self {
            start,
            wall_start_ms: wall_ms,
            last_wall_ms: wall_ms,
            last_instant: start,
            last_effective_ms: wall_ms,
            limits: HashMap::new(),
            activation: None,
        })
    }

    pub fn observe(&mut self, wall_ms: u64, now: Instant) -> Result<u64, String> {
        if wall_ms < self.last_wall_ms || now < self.last_instant {
            return Err("owner alias clock regressed".into());
        }
        let elapsed = now.duration_since(self.start);
        // Round elapsed UP, so sub-millisecond work cannot replenish a budget.
        let elapsed_ms = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000))
            .map_err(|_| "owner alias elapsed time overflow")?;
        let monotonic_ms = self
            .wall_start_ms
            .checked_add(elapsed_ms)
            .ok_or("owner alias elapsed time overflow")?;
        let effective = wall_ms.max(monotonic_ms);
        if effective < self.last_effective_ms {
            return Err("owner alias effective clock regressed".into());
        }
        self.last_wall_ms = wall_ms;
        self.last_instant = now;
        self.last_effective_ms = effective;
        Ok(effective)
    }
    fn retain_limits(&mut self, record: &mut Record) {
        let active = record
            .groups
            .iter()
            .find(|g| g.role == Role::Active)
            .map(|g| {
                g.provision
                    .aliases
                    .iter()
                    .map(|a| a.contact.queue_id)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some((ids, activated)) = &self.activation {
            if *ids == active {
                record.activated_ms = record.activated_ms.min(*activated);
            }
        }
        for group in &mut record.groups {
            for alias in &group.provision.aliases {
                if let Some((prior_role, deadline, action, receive_until)) =
                    self.limits.get(&alias.contact.queue_id)
                {
                    group.deadline_ms = group.deadline_ms.min(*deadline);
                    if group.role == Role::Active && *prior_role == Role::Active {
                        group.action_ms = group.action_ms.min(*action);
                    }
                    if matches!(group.role, Role::Unannounced | Role::Draining)
                        && matches!(prior_role, Role::Unannounced | Role::Draining)
                    {
                        group.receive_until_ms = group.receive_until_ms.min(*receive_until);
                    }
                }
            }
            group.action_ms = group.action_ms.min(group.deadline_ms);
            group.receive_until_ms = group.receive_until_ms.min(group.action_ms);
        }
        self.activation = Some((active, record.activated_ms));
        self.limits = record
            .groups
            .iter()
            .flat_map(|g| {
                g.provision.aliases.iter().map(move |a| {
                    (
                        a.contact.queue_id,
                        (g.role, g.deadline_ms, g.action_ms, g.receive_until_ms),
                    )
                })
            })
            .collect();
    }
}

impl Record {
    /// Validate the sealed record structure. This is not relay admission proof;
    /// the existing authenticated restore operation remains mandatory.
    pub fn validate(&self, target: &RelayTarget) -> Result<(), String> {
        if self.captured_ms == 0
            || self.activated_ms > self.captured_ms
            || self.groups.is_empty()
            || self.groups.len() > MAX_GROUPS
        {
            return Err("invalid owner alias time or group count".into());
        }
        let mut queues = HashSet::new();
        let mut roles = [0usize; 4];
        for group in &self.groups {
            roles[group.role as usize - 1] += 1;
            if group.provision.aliases.is_empty()
                || group.provision.aliases.len() > 2
                || group.provision.frwd_path.is_empty()
                || group.provision.frwd_path.len() > 256
                || group.provision.hop_key == [0; 32]
                || group.deadline_ms == 0
                || group.action_ms > group.deadline_ms
                || group.receive_until_ms > group.action_ms
                || (matches!(group.role, Role::Active | Role::Staged)
                    && group.receive_until_ms != 0)
                || (matches!(group.role, Role::Unannounced | Role::Draining)
                    && group.receive_until_ms == 0)
                || (group.role == Role::Staged && group.action_ms != 0)
                || (group.role != Role::Staged && group.action_ms == 0)
            {
                return Err("invalid owner alias lifecycle group".into());
            }
            if matches!(group.role, Role::Active | Role::Staged)
                && group.provision.aliases.len() != 2
            {
                return Err("invalid owner active or staged alias count".into());
            }
            let mut public_values = HashSet::new();
            for alias in &group.provision.aliases {
                if !public_values.insert(alias.contact.queue_id)
                    || !public_values.insert(alias.contact.push_cap)
                {
                    return Err("owner alias public capabilities overlap".into());
                }
            }
            if group.origins.len() != group.provision.aliases.len() {
                return Err("missing original owner alias operation".into());
            }
            for (alias, origin) in group.provision.aliases.iter().zip(&group.origins) {
                crate::lease::validate_retained_alias(origin).map_err(|error| error.to_string())?;
                let renewal = self
                    .renewals
                    .get(&alias.contact.queue_id)
                    .map(Vec::as_slice);
                let mut renewed_origin = origin.clone();
                renewed_origin.contact.expiry = alias.contact.expiry;
                crate::lease::validate_retained_alias_renewal(&renewed_origin, renewal)
                    .map_err(|error| error.to_string())?;
                let mut original_contact = origin.contact.clone();
                original_contact.expiry = alias.contact.expiry;
                if original_contact != alias.contact
                    || origin.capabilities != alias.capabilities
                    || origin.limits != alias.limits
                {
                    return Err("original owner alias authority mismatch".into());
                }
                crate::lease::validate_retained_alias_renewal(alias, renewal)
                    .map_err(|error| error.to_string())?;
                let lease_ms = alias
                    .contact
                    .expiry
                    .checked_mul(1000)
                    .ok_or("owner alias expiry overflow")?;
                if (group.role == Role::Active && alias.contact.target != *target)
                    || alias.contact.target.address.port() == 0
                    || alias.contact.target.address.ip().is_unspecified()
                    || alias.contact.target.relay_service_id == [0; 32]
                    || alias.contact.queue_id == [0; 32]
                    || alias.contact.epoch == 0
                    || !queues.insert(alias.contact.queue_id)
                    || alias.contact.push_cap != alias.capabilities.push
                    || alias.capabilities.push == [0; 32]
                    || alias.capabilities.sub == [0; 32]
                    || alias.capabilities.admin == [0; 32]
                    || alias.limits.max_queue_cells == 0
                    || alias.limits.max_queue_bytes == 0
                    || alias.create_path.is_empty()
                    || alias.create_path.len() > 256
                    || alias.lease_create.cell_type() != Some(CellType::RelaySub)
                    || alias.lease_create.payload.len() != crate::lease::LEASE_CREATE_LEN
                    || group.deadline_ms > lease_ms
                    || group.deadline_ms
                        > origin
                            .contact
                            .expiry
                            .checked_mul(1000)
                            .ok_or("original owner alias expiry overflow")?
                {
                    return Err("invalid owner alias binding or duplicate queue".into());
                }
            }
        }
        if self.renewals.keys().any(|q| !queues.contains(q)) {
            return Err("orphan owner renewal operation".into());
        }
        if roles[0] != 1 || roles[1] > 1 || roles[2] > 1 {
            return Err("invalid owner alias role multiplicity".into());
        }
        Ok(())
    }

    pub fn active_age(&self, effective_ms: u64) -> Result<Duration, String> {
        effective_ms
            .checked_sub(self.activated_ms)
            .map(Duration::from_millis)
            .ok_or_else(|| "owner alias activation is in the future".into())
    }

    /// A due cleanup role is not permission to recreate its receive queue.
    pub fn may_restore(group: &Group, effective_ms: u64) -> Result<bool, String> {
        if effective_ms >= group.deadline_ms {
            if group.role == Role::Active {
                return Err("active owner alias expired".into());
            }
            return Ok(false);
        }
        Ok(!matches!(group.role, Role::Unannounced | Role::Draining)
            || effective_ms < group.receive_until_ms)
    }
}

fn context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"owner-aliases",
        b"lifecycle",
        b"gc1/owner-aliases/v1",
    )
    .map_err(|error| error.to_string())
}

pub(in crate::node) fn seal(
    record: &Record,
    target: &RelayTarget,
    seed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    record.validate(target)?;
    let identity = IdentityKeypair::from_seed(*seed).public_bytes();
    let mut plain = SecretBuffer(vec![1]);
    plain.extend_from_slice(&record.captured_ms.to_be_bytes());
    plain.extend_from_slice(&record.activated_ms.to_be_bytes());
    put_count(&mut plain, record.groups.len())?;
    for group in &record.groups {
        plain.push(group.role as u8);
        plain.extend_from_slice(&group.deadline_ms.to_be_bytes());
        plain.extend_from_slice(&group.action_ms.to_be_bytes());
        plain.extend_from_slice(&group.receive_until_ms.to_be_bytes());
        let info = NodeInfo {
            identity_pk: identity.clone(),
            bundle: Vec::new(),
            aliases: group
                .provision
                .aliases
                .iter()
                .map(|alias| alias.contact.clone())
                .collect(),
            provisioning: Some(group.provision.clone()),
        };
        put_sensitive(
            &mut plain,
            info.encode_private()
                .ok_or("invalid private owner alias record")?,
        )?;
        let original = NodeInfo {
            aliases: group.origins.iter().map(|a| a.contact.clone()).collect(),
            provisioning: Some(RelayProvision {
                aliases: group.origins.clone(),
                frwd_path: group.provision.frwd_path.clone(),
                hop_key: group.provision.hop_key,
            }),
            ..info
        };
        put_sensitive(
            &mut plain,
            original
                .encode_private()
                .ok_or("invalid original owner operation")?,
        )?;
    }
    put_count(&mut plain, record.renewals.len())?;
    let mut renewals: Vec<_> = record.renewals.iter().collect();
    renewals.sort_by_key(|(queue, _)| **queue);
    for (queue, wire) in renewals {
        plain.extend_from_slice(queue);
        put_sensitive(&mut plain, wire.clone())?;
    }
    if plain.len() > MAX_RECORD_BYTES {
        return Err("owner alias record too large".into());
    }
    seal_bytes(&channel_archive_key(seed), &context(seed)?, &plain)
}

pub(in crate::node) fn open_unbound(bytes: &[u8], seed: &[u8; 32]) -> Result<Record, String> {
    if bytes.len() > MAX_RECORD_BYTES + 64 {
        return Err("owner alias record too large".into());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &context(seed)?,
        bytes,
    )?);
    let mut pos = 0;
    if take_u8(&plain, &mut pos)? != 1 {
        return Err(malformed());
    }
    let captured_ms = take_u64(&plain, &mut pos)?;
    let activated_ms = take_u64(&plain, &mut pos)?;
    let count = take_count(&plain, &mut pos, MAX_GROUPS)?;
    let identity = IdentityKeypair::from_seed(*seed).public_bytes();
    let mut groups = Vec::with_capacity(count);
    for _ in 0..count {
        let role = match take_u8(&plain, &mut pos)? {
            1 => Role::Active,
            2 => Role::Staged,
            3 => Role::Unannounced,
            4 => Role::Draining,
            _ => return Err(malformed()),
        };
        let deadline_ms = take_u64(&plain, &mut pos)?;
        let action_ms = take_u64(&plain, &mut pos)?;
        let receive_until_ms = take_u64(&plain, &mut pos)?;
        let info = NodeInfo::decode_private(take32(&plain, &mut pos)?).ok_or_else(malformed)?;
        if info.identity_pk != identity || !info.bundle.is_empty() {
            return Err(malformed());
        }
        let provision = info.provisioning.ok_or_else(malformed)?;
        if info.aliases
            != provision
                .aliases
                .iter()
                .map(|alias| alias.contact.clone())
                .collect::<Vec<_>>()
        {
            return Err(malformed());
        }
        let original = NodeInfo::decode_private(take32(&plain, &mut pos)?).ok_or_else(malformed)?;
        if original.identity_pk != identity || !original.bundle.is_empty() {
            return Err(malformed());
        }
        let original_provision = original.provisioning.ok_or_else(malformed)?;
        if original.aliases
            != original_provision
                .aliases
                .iter()
                .map(|a| a.contact.clone())
                .collect::<Vec<_>>()
            || original_provision.frwd_path != provision.frwd_path
            || original_provision.hop_key != provision.hop_key
        {
            return Err(malformed());
        }
        groups.push(Group {
            role,
            origins: original_provision.aliases,
            provision,
            deadline_ms,
            action_ms,
            receive_until_ms,
        });
    }
    let renewal_count = take_count(&plain, &mut pos, MAX_GROUPS * 2)?;
    let mut renewals = HashMap::new();
    for _ in 0..renewal_count {
        let queue: [u8; 32] = take(&plain, &mut pos, 32)?
            .try_into()
            .map_err(|_| malformed())?;
        let wire = take32(&plain, &mut pos)?;
        if wire.len() != crate::lease::LEASE_RENEW_LEN
            || renewals.insert(queue, wire.to_vec()).is_some()
        {
            return Err(malformed());
        }
    }
    if pos != plain.len() {
        return Err(malformed());
    }
    let record = Record {
        captured_ms,
        activated_ms,
        groups,
        renewals,
    };
    let target = record.active_target()?;
    record.validate(target)?;
    Ok(record)
}

#[cfg(test)]
fn open(bytes: &[u8], target: &RelayTarget, seed: &[u8; 32]) -> Result<Record, String> {
    let record = open_unbound(bytes, seed)?;
    record.validate(target)?;
    Ok(record)
}

fn alias_expiry(aliases: &[OwnedAlias]) -> Result<u64, String> {
    aliases
        .iter()
        .map(|a| {
            a.contact
                .expiry
                .checked_mul(1000)
                .ok_or_else(|| "owner alias expiry overflow".into())
        })
        .collect::<Result<Vec<_>, String>>()?
        .into_iter()
        .min()
        .ok_or_else(|| "owner alias set is empty".into())
}

fn absolute(deadline: Instant, now: Instant, effective_ms: u64) -> Result<u64, String> {
    if deadline >= now {
        let remaining = u64::try_from(deadline.duration_since(now).as_millis())
            .map_err(|_| "owner alias deadline overflow")?;
        effective_ms
            .checked_add(remaining)
            .ok_or_else(|| "owner alias deadline overflow".into())
    } else {
        let elapsed = u64::try_from(now.duration_since(deadline).as_nanos().div_ceil(1_000_000))
            .map_err(|_| "owner alias age overflow")?;
        effective_ms
            .checked_sub(elapsed)
            .ok_or_else(|| "owner alias age cannot be related to wall time".into())
    }
}

pub(in crate::node) fn seal_current(st: &NodeState) -> Result<Vec<u8>, String> {
    let now = Instant::now();
    let captured_ms = st
        .owner_clock
        .lock()
        .map_err(|_| "owner clock poisoned")?
        .observe(now_ms(), now)?;
    let activated_ms = absolute(st.contact_aliases_activated, now, captured_ms)?;
    let expiry = alias_expiry(&st.client_relay.aliases)?;
    let rotation = st
        .contact_aliases_activated
        .checked_add(st.alias_lifecycle_timing.alias_ttl)
        .ok_or("owner rotation overflow")?;
    let mut groups = vec![Group {
        role: Role::Active,
        provision: st.client_relay.clone(),
        origins: st
            .client_relay
            .aliases
            .iter()
            .map(|a| {
                st.owner_alias_origins
                    .get(&a.contact.queue_id)
                    .unwrap_or(a)
                    .clone()
            })
            .collect(),
        deadline_ms: expiry,
        action_ms: absolute(rotation, now, captured_ms)?.min(expiry),
        receive_until_ms: 0,
    }];
    let origins = |aliases: &[OwnedAlias]| {
        aliases
            .iter()
            .map(|a| {
                st.owner_alias_origins
                    .get(&a.contact.queue_id)
                    .unwrap_or(a)
                    .clone()
            })
            .collect()
    };
    let provision = |aliases: &[OwnedAlias]| RelayProvision {
        aliases: aliases.to_vec(),
        frwd_path: st.client_relay.frwd_path.clone(),
        hop_key: st.client_relay.hop_key,
    };
    if let Some(aliases) = &st.staged_contact_aliases {
        groups.push(Group {
            role: Role::Staged,
            provision: provision(aliases),
            origins: origins(aliases),
            deadline_ms: alias_expiry(aliases)?,
            action_ms: 0,
            receive_until_ms: 0,
        });
    }
    if let Some(aliases) = &st.unannounced_old_contact_aliases {
        let (receive_until, abandon_at) = st
            .unannounced_contact_deadlines
            .ok_or("missing original announcement deadlines")?;
        let expiry = alias_expiry(aliases)?;
        groups.push(Group {
            role: Role::Unannounced,
            provision: provision(aliases),
            origins: origins(aliases),
            deadline_ms: absolute(abandon_at, now, captured_ms)?.min(expiry),
            action_ms: absolute(receive_until, now, captured_ms)?.min(expiry),
            receive_until_ms: absolute(receive_until, now, captured_ms)?.min(expiry),
        });
    } else if st.unannounced_contact_deadlines.is_some() {
        return Err("orphan announcement deadlines".into());
    }
    for draining in &st.draining_contact_aliases {
        if draining.aliases.is_empty() {
            continue;
        }
        let expiry = alias_expiry(&draining.aliases)?;
        let deadline_ms = absolute(draining.abandon_at, now, captured_ms)?.min(expiry);
        groups.push(Group {
            role: Role::Draining,
            provision: provision(&draining.aliases),
            origins: origins(&draining.aliases),
            deadline_ms,
            action_ms: absolute(draining.next_revoke, now, captured_ms)?.min(deadline_ms),
            receive_until_ms: absolute(draining.receive_until, now, captured_ms)?.min(deadline_ms),
        });
    }
    for group in &mut groups {
        group.deadline_ms = group.deadline_ms.min(alias_expiry(&group.origins)?);
        group.action_ms = group.action_ms.min(group.deadline_ms);
        group.receive_until_ms = group.receive_until_ms.min(group.action_ms);
    }
    let queues: HashSet<_> = groups
        .iter()
        .flat_map(|g| g.provision.aliases.iter().map(|a| a.contact.queue_id))
        .collect();
    let renewals = st
        .owner_alias_renewals
        .iter()
        .filter(|(q, _)| queues.contains(*q))
        .map(|(q, wire)| (*q, wire.clone()))
        .collect();
    let mut record = Record {
        captured_ms,
        activated_ms,
        groups,
        renewals,
    };
    st.owner_clock
        .lock()
        .map_err(|_| "owner clock poisoned")?
        .retain_limits(&mut record);
    if st.routing.is_none() {
        record.validate_live(captured_ms)?;
    }
    seal(&record, record.active_target()?, &st.identity_seed)
}

impl Record {
    pub fn active_target(&self) -> Result<&RelayTarget, String> {
        self.groups
            .iter()
            .find(|g| g.role == Role::Active)
            .and_then(|g| g.provision.aliases.first())
            .map(|a| &a.contact.target)
            .ok_or_else(|| "missing active owner aliases".into())
    }
    pub fn validate_live(&self, effective_ms: u64) -> Result<(), String> {
        if effective_ms < self.captured_ms {
            return Err("owner clock precedes captured state".into());
        }
        for group in &self.groups {
            Self::may_restore(group, effective_ms)?;
        }
        Ok(())
    }
}

impl Record {
    pub async fn restore_for_constructor(
        &self,
        scheduler: &RelayScheduler,
        current: &RelayProvision,
        clock: &mut RestoreClock,
    ) -> Result<Self, String> {
        let authority = current
            .aliases
            .first()
            .ok_or("no current owner admission route")?;
        self.validate(&authority.contact.target)?;
        self.validate_live(clock.observe(now_ms(), Instant::now())?)?;
        let mut restored = self.clone();
        for group in &mut restored.groups {
            let effective = clock.observe(now_ms(), Instant::now())?;
            if !Self::may_restore(group, effective)? {
                continue;
            }
            for alias in &mut group.provision.aliases {
                let effective = clock.observe(now_ms(), Instant::now())?;
                let boundary = if matches!(group.role, Role::Unannounced | Role::Draining) {
                    group.deadline_ms.min(group.receive_until_ms)
                } else {
                    group.deadline_ms
                };
                let remaining = boundary
                    .checked_sub(effective)
                    .filter(|v| *v != 0)
                    .ok_or("owner alias expired during restoration")?;
                let admitted = tokio::time::timeout(
                    Duration::from_millis(remaining),
                    restore_contact_alias(scheduler, authority, alias),
                )
                .await
                .map_err(|_| "owner alias restore exceeded original lifetime")??;
                // Existing authenticated re-admission may replace only its operation
                // grant/create path, never the retained public identity or limits.
                if admitted.contact != alias.contact
                    || admitted.capabilities != alias.capabilities
                    || admitted.limits != alias.limits
                {
                    return Err("owner alias restore changed retained authority".into());
                }
                *alias = admitted;
                let effective = clock.observe(now_ms(), Instant::now())?;
                if effective >= boundary {
                    return Err("owner alias expired during restoration".into());
                }
            }
        }
        restored.validate_live(clock.observe(now_ms(), Instant::now())?)?;
        Ok(restored)
    }

    #[cfg(test)]
    pub fn apply(&self, st: &mut NodeState, clock: RestoreClock) -> Result<(), String> {
        self.apply_retained(st, clock, false)
    }

    /// Offline construction retains authority and its original deadlines. It
    /// does not assert relay admission or publish an expired receive address.
    pub fn apply_retained(
        &self,
        st: &mut NodeState,
        clock: RestoreClock,
        offline: bool,
    ) -> Result<(), String> {
        let mut clock = clock;
        let now = Instant::now();
        let effective = clock.observe(now_ms(), now)?;
        if !offline {
            self.validate_live(effective)?;
        }
        let deadline = |ms: u64| {
            now.checked_add(Duration::from_millis(ms.saturating_sub(effective)))
                .ok_or("owner alias deadline is unrepresentable")
        };
        st.contact_aliases_activated = now
            .checked_sub(self.active_age(effective)?)
            .ok_or("owner alias active age is unrepresentable")?;
        // This is a complete retained record. Runtime recovery also calls this
        // on populated state; appending would duplicate draining queue IDs and
        // fail the next durable checkpoint. Roles absent or expired in the
        // record must not survive from the previous in-memory collections.
        st.staged_contact_aliases = None;
        st.unannounced_old_contact_aliases = None;
        st.unannounced_contact_deadlines = None;
        st.draining_contact_aliases.clear();
        for group in &self.groups {
            if group.role != Role::Active && group.deadline_ms <= effective {
                continue;
            }
            match group.role {
                Role::Active => st.client_relay.aliases = group.provision.aliases.clone(),
                Role::Staged => st.staged_contact_aliases = Some(group.provision.aliases.clone()),
                Role::Unannounced if effective < group.receive_until_ms => {
                    st.unannounced_old_contact_aliases = Some(group.provision.aliases.clone());
                    st.unannounced_contact_deadlines = Some((
                        deadline(group.receive_until_ms)?,
                        deadline(group.deadline_ms)?,
                    ));
                }
                Role::Unannounced | Role::Draining => {
                    st.draining_contact_aliases.push(DrainingContactAliases {
                        aliases: group.provision.aliases.clone(),
                        receive_until: deadline(group.receive_until_ms)?,
                        next_revoke: deadline(group.action_ms)?,
                        abandon_at: deadline(group.deadline_ms)?,
                    })
                }
            }
        }
        st.owner_alias_renewals = self.renewals.clone();
        st.owner_alias_origins = self
            .groups
            .iter()
            .flat_map(|g| g.origins.iter().map(|a| (a.contact.queue_id, a.clone())))
            .collect();
        st.info.aliases = st
            .client_relay
            .aliases
            .iter()
            .map(|a| a.contact.clone())
            .collect();
        clock.retain_limits(&mut self.clone());
        st.owner_clock = Mutex::new(clock);
        super::super::routing::refresh_public_info(st);
        Ok(())
    }
}

pub(in crate::node) fn alias_deadline(
    st: &NodeState,
    alias: &OwnedAlias,
) -> Result<(u64, u64), String> {
    let mut clock = st.owner_clock.lock().map_err(|_| "owner clock poisoned")?;
    let effective = clock.observe(now_ms(), Instant::now())?;
    let lease = alias
        .contact
        .expiry
        .checked_mul(1000)
        .ok_or("owner alias expiry overflow")?;
    let deadline = clock
        .limits
        .get(&alias.contact.queue_id)
        .map_or(lease, |(_, deadline, _, _)| lease.min(*deadline));
    Ok((effective, deadline))
}

pub(in crate::node) fn receive_deadline(
    st: &NodeState,
    alias: &OwnedAlias,
) -> Result<(u64, u64), String> {
    let mut clock = st.owner_clock.lock().map_err(|_| "owner clock poisoned")?;
    let effective = clock.observe(now_ms(), Instant::now())?;
    let lease = alias
        .contact
        .expiry
        .checked_mul(1000)
        .ok_or("owner alias expiry overflow")?;
    let deadline =
        clock
            .limits
            .get(&alias.contact.queue_id)
            .map_or(lease, |(role, deadline, _, receive)| {
                if matches!(role, Role::Unannounced | Role::Draining) {
                    lease.min(*deadline).min(*receive)
                } else {
                    lease.min(*deadline)
                }
            });
    Ok((effective, deadline))
}

pub(in crate::node) fn validate_current_live(st: &NodeState) -> Result<(), String> {
    for alias in &st.client_relay.aliases {
        if st.routing.is_some() && !st.info.aliases.contains(&alias.contact) {
            continue;
        }
        let (effective, deadline) = alias_deadline(st, alias)?;
        if deadline <= effective {
            return Err("active owner alias expired before publication".into());
        }
    }
    Ok(())
}

pub(in crate::node) fn rotation_due(
    st: &NodeState,
    timing: AliasLifecycleConfig,
) -> Result<bool, String> {
    let mut clock = st.owner_clock.lock().map_err(|_| "owner clock poisoned")?;
    let now = Instant::now();
    let effective = clock.observe(now_ms(), now)?;
    let saved_due = st.client_relay.aliases.iter().any(|alias| {
        clock
            .limits
            .get(&alias.contact.queue_id)
            .is_some_and(|(role, _, action, _)| *role == Role::Active && *action <= effective)
    });
    Ok(saved_due || now.duration_since(st.contact_aliases_activated) >= timing.alias_ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Record, RelayTarget) {
        let target = RelayTarget {
            address: "127.0.0.1:4444".parse().unwrap(),
            relay_service_id: [9; 32],
        };
        let aliases: Vec<OwnedAlias> = (1u8..=2)
            .map(|n| {
                let capabilities = Capabilities {
                    push: [n + 2; 32],
                    sub: [n + 4; 32],
                    admin: [n + 6; 32],
                };
                let create = LeaseCreate {
                    queue_id: [n; 32],
                    epoch: u64::from(n),
                    lease_expiry: 20,
                    queue_cells: 8,
                    queue_bytes: 4096,
                    capabilities,
                    nonce: [n + 8; 16],
                    grant: crate::lease::AdmissionGrant {
                        relay_service_id: target.relay_service_id,
                        grant_id: [n + 10; 16],
                        grant_cap: [n + 12; 32],
                        queue_id: [n; 32],
                        epoch: u64::from(n),
                        not_before: 1,
                        expiry: 5,
                        max_queue_cells: 8,
                        max_queue_bytes: 4096,
                    }
                    .encode(&[99; 32])
                    .unwrap(),
                };
                OwnedAlias {
                    contact: AliasContact {
                        target: target.clone(),
                        queue_id: create.queue_id,
                        epoch: create.epoch,
                        push_cap: capabilities.push,
                        expiry: create.lease_expiry,
                    },
                    capabilities,
                    limits: LeaseLimits {
                        max_queue_cells: 8,
                        max_queue_bytes: 4096,
                    },
                    create_path: encode_b64url(&create.grant[49..81]),
                    lease_create: Cell::new(
                        CellType::RelaySub,
                        0,
                        0,
                        create.encode(&target.relay_service_id).unwrap().to_vec(),
                    ),
                }
            })
            .collect();
        (
            Record {
                captured_ms: 10_000,
                activated_ms: 2_000,
                renewals: HashMap::new(),
                groups: vec![Group {
                    role: Role::Active,
                    origins: aliases.clone(),
                    provision: RelayProvision {
                        aliases,
                        frwd_path: "retained-forward".into(),
                        hop_key: [8; 32],
                    },
                    deadline_ms: 20_000,
                    action_ms: 18_000,
                    receive_until_ms: 0,
                }],
            },
            target,
        )
    }

    #[test]
    fn owner_record_roundtrip_preserves_all_roles_and_private_material() {
        let (mut record, target) = fixture();
        for (i, role) in [Role::Staged, Role::Unannounced, Role::Draining]
            .into_iter()
            .enumerate()
        {
            let mut group = record.groups[0].clone();
            group.role = role;
            group.receive_until_ms = if matches!(role, Role::Unannounced | Role::Draining) {
                group.action_ms
            } else {
                0
            };
            if role == Role::Staged {
                group.action_ms = 0;
            }
            for alias in &mut group.provision.aliases {
                // Codec test: retained opaque LeaseCreate bytes are not admission proof.
                alias.contact.queue_id[0] += (i as u8 + 1) * 10;
                let create = LeaseCreate {
                    queue_id: alias.contact.queue_id,
                    epoch: alias.contact.epoch,
                    lease_expiry: alias.contact.expiry,
                    queue_cells: alias.limits.max_queue_cells,
                    queue_bytes: alias.limits.max_queue_bytes,
                    capabilities: alias.capabilities,
                    nonce: [17; 16],
                    grant: crate::lease::AdmissionGrant {
                        relay_service_id: target.relay_service_id,
                        grant_id: [17 + i as u8; 16],
                        grant_cap: [20 + i as u8; 32],
                        queue_id: alias.contact.queue_id,
                        epoch: alias.contact.epoch,
                        not_before: 1,
                        expiry: 5,
                        max_queue_cells: alias.limits.max_queue_cells,
                        max_queue_bytes: alias.limits.max_queue_bytes,
                    }
                    .encode(&[99; 32])
                    .unwrap(),
                };
                alias.create_path = encode_b64url(&create.grant[49..81]);
                alias.lease_create.payload =
                    create.encode(&target.relay_service_id).unwrap().to_vec();
            }
            group.origins = group.provision.aliases.clone();
            record.groups.push(group);
        }
        let sealed = seal(&record, &target, &[42; 32]).unwrap();
        let restored = open(&sealed, &target, &[42; 32]).unwrap();
        assert_eq!(restored.captured_ms, record.captured_ms);
        assert_eq!(restored.activated_ms, record.activated_ms);
        for (a, b) in restored.groups.iter().zip(record.groups.iter()) {
            assert_eq!(a.role, b.role);
            assert_eq!(a.provision, b.provision);
            assert_eq!(a.origins, b.origins);
            assert_eq!(a.deadline_ms, b.deadline_ms);
            assert_eq!(a.action_ms, b.action_ms);
        }
        assert!(open(&sealed, &target, &[43; 32]).is_err());
        let mut damaged = sealed;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(open(&damaged, &target, &[42; 32]).is_err());
    }

    #[test]
    fn owner_record_rejects_queue_collision_across_roles_even_different_epoch() {
        let (mut record, target) = fixture();
        let mut group = record.groups[0].clone();
        group.role = Role::Draining;
        group.receive_until_ms = group.action_ms;
        let alias = &mut group.provision.aliases[0];
        alias.contact.epoch += 1;
        let grant = crate::lease::AdmissionGrant {
            relay_service_id: target.relay_service_id,
            grant_id: [51; 16],
            grant_cap: [52; 32],
            queue_id: alias.contact.queue_id,
            epoch: alias.contact.epoch,
            not_before: 1,
            expiry: 5,
            max_queue_cells: alias.limits.max_queue_cells,
            max_queue_bytes: alias.limits.max_queue_bytes,
        }
        .encode(&[99; 32])
        .unwrap();
        let create = LeaseCreate {
            queue_id: alias.contact.queue_id,
            epoch: alias.contact.epoch,
            lease_expiry: alias.contact.expiry,
            queue_cells: alias.limits.max_queue_cells,
            queue_bytes: alias.limits.max_queue_bytes,
            capabilities: alias.capabilities,
            nonce: [53; 16],
            grant,
        };
        alias.create_path = encode_b64url(&grant[49..81]);
        alias.lease_create.payload = create.encode(&target.relay_service_id).unwrap().to_vec();
        group.origins = group.provision.aliases.clone();
        record.groups.push(group);
        assert!(record.validate(&target).is_err());
    }

    #[test]
    fn owner_record_rejects_target_caps_deadline_and_malformed_record() {
        let (record, target) = fixture();
        let sealed = seal(&record, &target, &[42; 32]).unwrap();
        let mut wrong_target = target.clone();
        wrong_target.relay_service_id[0] ^= 1;
        assert!(open(&sealed, &wrong_target, &[42; 32]).is_err());
        let mut wrong = record.clone();
        wrong.groups[0].provision.aliases[0].contact.push_cap = [99; 32];
        assert!(wrong.validate(&target).is_err());
        let mut wrong = record;
        wrong.groups[0].deadline_ms = 20_001;
        assert!(wrong.validate(&target).is_err());
        assert!(open(&[], &target, &[42; 32]).is_err());
        assert!(open(&vec![0; MAX_RECORD_BYTES + 65], &target, &[42; 32]).is_err());
    }

    #[test]
    fn owner_renewal_preserves_original_operation_and_budget() {
        let (mut record, target) = fixture();
        let prior = record.groups[0].provision.aliases[0].clone();
        let expiry = prior.contact.expiry + 100;
        let wire = LeaseRenew {
            queue_id: prior.contact.queue_id,
            epoch: prior.contact.epoch,
            lease_expiry: expiry,
            nonce: [61; 16],
        }
        .encode(&prior.capabilities.admin, &target.relay_service_id)
        .unwrap()
        .to_vec();
        record.groups[0].provision.aliases[0].contact.expiry = expiry;
        assert!(record.validate(&target).is_err());
        record.renewals.insert(prior.contact.queue_id, wire.clone());
        let sealed = seal(&record, &target, &[42; 32]).unwrap();
        let restored = open(&sealed, &target, &[42; 32]).unwrap();
        assert_eq!(restored.groups[0].origins[0], prior);
        assert_eq!(restored.groups[0].deadline_ms, record.groups[0].deadline_ms);
        assert_eq!(restored.renewals[&prior.contact.queue_id], wire);
        let mut wrong = record.clone();
        wrong.renewals.get_mut(&prior.contact.queue_id).unwrap()[10] ^= 1;
        assert!(wrong.validate(&target).is_err());
        let mut wrong = record.clone();
        wrong.groups[0].deadline_ms = expiry * 1000;
        assert!(wrong.validate(&target).is_err());
        let mut wrong = record;
        wrong.groups[0].provision.aliases[0].contact.target.address = "0.0.0.0:0".parse().unwrap();
        wrong.groups[0].origins[0].contact.target.address = "0.0.0.0:0".parse().unwrap();
        wrong.groups[0].role = Role::Draining;
        wrong.groups[0].receive_until_ms = wrong.groups[0].action_ms;
        assert!(wrong.validate(&target).is_err());
    }

    #[test]
    fn owner_clock_refuses_decreasing_monotonic_observation_after_start() {
        let start = Instant::now();
        let mut clock = RestoreClock::new(100, 100, start).unwrap();
        assert_eq!(
            clock
                .observe(100, start + Duration::from_millis(20))
                .unwrap(),
            120
        );
        assert!(clock
            .observe(100, start + Duration::from_millis(19))
            .is_err());
    }

    #[test]
    fn owner_clock_counts_offline_restore_and_active_age_without_rounding_up_budget() {
        let (record, _) = fixture();
        let start = Instant::now();
        let mut clock = RestoreClock::new(record.captured_ms, 15_000, start).unwrap();
        let effective = clock
            .observe(15_000, start + Duration::from_micros(1_500))
            .unwrap();
        assert_eq!(effective, 15_002);
        assert_eq!(
            record.active_age(effective).unwrap(),
            Duration::from_millis(13_002)
        );
        assert!(Record::may_restore(&record.groups[0], effective).unwrap());
        let effective = clock
            .observe(15_000, start + Duration::from_secs(5))
            .unwrap();
        assert_eq!(effective, 20_000);
        assert!(Record::may_restore(&record.groups[0], effective).is_err());
    }

    #[test]
    fn owner_clock_regression_and_due_cleanup_refuse_recreation() {
        let (mut record, _) = fixture();
        let start = Instant::now();
        assert!(RestoreClock::new(record.captured_ms, 9_999, start).is_err());
        let mut clock = RestoreClock::new(record.captured_ms, 15_000, start).unwrap();
        clock.observe(16_000, start).unwrap();
        assert!(clock
            .observe(15_999, start + Duration::from_secs(1))
            .is_err());
        record.groups[0].role = Role::Draining;
        record.groups[0].receive_until_ms = record.groups[0].action_ms;
        assert!(!Record::may_restore(&record.groups[0], 18_000).unwrap());
        assert!(!Record::may_restore(&record.groups[0], 20_000).unwrap());
    }
    #[test]
    fn owner_record_refuses_mismatched_leasecreate_and_nonactive_expiry_before_use() {
        let (record, target) = fixture();
        let mut wrong = record.clone();
        wrong.groups[0].provision.aliases[0].contact.epoch += 1;
        assert!(seal(&wrong, &target, &[42; 32]).is_err());
        let mut wrong = record.clone();
        wrong.groups[0].provision.aliases[0].lease_create.payload[50] ^= 1;
        assert!(seal(&wrong, &target, &[42; 32]).is_err());
        let mut wrong = record.clone();
        wrong.groups[0].provision.aliases[0].create_path = "unrelated-grant".into();
        assert!(seal(&wrong, &target, &[42; 32]).is_err());
        let mut expired = record.groups[0].clone();
        expired.role = Role::Staged;
        expired.action_ms = 0;
        assert!(!Record::may_restore(&expired, expired.deadline_ms).unwrap());
        assert!(record.validate_live(20_000).is_err());
    }
}
