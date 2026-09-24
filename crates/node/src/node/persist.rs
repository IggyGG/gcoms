// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

// (client-persist) export/import of recoverable node state. See SPEC R1 notes in mod.rs.

use super::*;

pub(super) mod owner_aliases;
use crate::channel::{
    CachedAdmission, ChannelMessageOutbox, ChannelRole, ChannelState, MembershipOutbox,
};

const MAGIC_V1: &[u8; 6] = b"GCNST1";
const MAGIC_V2: &[u8; 6] = b"GCNST2";
const MAGIC_V3: &[u8; 6] = b"GCNST3";
const MAGIC_V4: &[u8; 6] = b"GCNST4";
const MAGIC_V5: &[u8; 6] = b"GCNST5";
const MAGIC_V6: &[u8; 6] = b"GCNST6";
const MAGIC_V7: &[u8; 6] = b"GCNST7";
const MAGIC_V8: &[u8; 6] = b"GCNST8";
/// v9 adds the sealed forward-grant pool (SPEC §11.1 intermediary set).
const MAGIC_V9: &[u8; 6] = b"GCNST9";
/// v10 adds the per-channel single-use invite ledger so that a minted invite
/// stays spent across an owner restart.
const MAGIC_V10: &[u8; 6] = b"GCNSTA";
/// v11 seals the durable application inbox and its monotonic cursor.
const MAGIC_V11: &[u8; 6] = b"GCNSTB";
/// v12 seals pending MLS joins and preserves their request identifiers.
const MAGIC_V12: &[u8; 6] = b"GCNSTC";
/// v13 seals the stable relay TLS identity across backend restarts.
const MAGIC_V13: &[u8; 6] = b"GCNSTD";
/// v14 seals central endpoint ownership and its canonical policy commitment.
const MAGIC_V14: &[u8; 6] = b"GCNSTE";
/// v15 seals the owner receive-route lifecycle separately from peer authority.
const MAGIC_V15: &[u8; 6] = b"GCNSTF";
/// Historical v16 has two independently deployed grammars: machine scope and
/// P2 routing recovery. Their domain-separated sealed trailers distinguish them.
const MAGIC_V16: &[u8; 6] = b"GCNSTG";
/// Retained command profiles: inline established channel grants.
const MAGIC_V17: &[u8; 6] = b"GCNSTH";
/// Unified machine scope, routing recovery and named current/previous grants.
const MAGIC_V18: &[u8; 6] = b"GCNSTI";
/// v19 permits durable logical records to wait behind a known session's
/// readiness/flow barrier, including when no routing-recovery directory exists.
const MAGIC_V19: &[u8; 6] = b"GCNSTJ";
/// v20 carries explicitly selected GC/2 sessions, including encrypted counter
/// credit and deferred logical records from simultaneous initiation.
const MAGIC_V20: &[u8; 6] = b"GCNSTK";
/// v21 seals bounded logical receipt history across authenticated GC/2 recovery.
const MAGIC_V21: &[u8; 6] = b"GCNSTL";
const ROLE_OWNER: u8 = 1;
const ROLE_MEMBER: u8 = 2;
const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_SESSIONS: usize = 8192;
const MAX_DIRECT: usize = 8192;
const MAX_CHANNEL_ITEMS: usize = 1024;

struct SecretBuffer(Vec<u8>);

impl std::ops::Deref for SecretBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SecretBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl SecretBuffer {
    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

type ArchivedPendingDirect = (
    [u8; 16],
    DirectDelivery,
    Option<Vec<u8>>,
    u64,
    u64,
    u64,
    bool,
);

struct Archive {
    routing_directory: Option<gcoms_routing::Directory>,
    channel_routes: HashMap<String, crate::channel::OwnedChannelRoute>,
    previous_channel_routes: HashMap<String, crate::channel::OwnedChannelRoute>,
    #[cfg(test)]
    layout: ArchiveLayout,
    owner_aliases: Option<owner_aliases::Record>,
    tls_identity: Option<TlsIdentity>,
    exported_ms: u64,
    next_direct_sequence: u64,
    application_inbox: application_inbox::ApplicationInbox,
    #[cfg(feature = "experimental-gc2")]
    gc2_receipts: Option<gc2_receipts::Ledger>,
    local_contact_generation: u64,
    sessions: Vec<(Vec<u8>, ArchivedSession, ArchivedSessionState)>,
    peer_routes: Vec<(Vec<u8>, NodeInfo, u64)>,
    pending_direct: Vec<ArchivedPendingDirect>,
    direct_acks: Vec<DirectDelivery>,
    processed_direct: Vec<((Vec<u8>, u64), ProcessedDirect)>,
    channels: Vec<ArchivedChannel>,
    direct_presence_opt_in: HashSet<Vec<u8>>,
    channel_presence_opt_in: HashSet<String>,
    forward_grants: Vec<crate::alias::ForwardGrant>,
    prepared: Vec<(
        u64,
        String,
        gcoms_mls::PreparedJoin,
        crate::channel::OwnedChannelRoute,
    )>,
    next_prep_id: u64,
}

enum ArchivedSession {
    Legacy(Box<Session>),
    Sealed(SealedSession),
    #[cfg(feature = "experimental-gc2")]
    Credited(gcoms_protocol::gc2_session::SealedState),
}

enum ArchivedSessionState {
    InitiatedUnconfirmed { remaining_ms: u64 },
    Established,
}

struct ArchivedChannel {
    name: String,
    visibility: crate::channel::ChannelVisibility,
    role: ChannelRole,
    own_name: Option<String>,
    directory: HashMap<String, crate::channel::ChannelRoute>,
    message_outbox: Vec<([u8; 16], ChannelMessageOutbox)>,
    membership_outbox: Option<MembershipOutbox>,
    pending_control: Vec<(crate::channel::ChannelRoute, Vec<u8>)>,
    admissions: Vec<([u8; 32], CachedAdmission)>,
    invites: Vec<([u8; 16], crate::channel::InviteRecord)>,
    completed_removals: Vec<String>,
    commit_acks: Vec<([u8; 16], crate::channel::ChannelRoute, Vec<u8>)>,
    unrouted_acks: Vec<(crate::channel::UnroutedAckKey, Vec<u8>)>,
}

fn malformed() -> String {
    "malformed node state export".to_string()
}

fn put_count(v: &mut Vec<u8>, count: usize) -> Result<(), String> {
    let count = u32::try_from(count).map_err(|_| "node state export too large")?;
    v.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn put16(v: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len = u16::try_from(bytes.len()).map_err(|_| "node state field too large")?;
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(bytes);
    Ok(())
}

fn put32(v: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len()).map_err(|_| "node state field too large")?;
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(bytes);
    Ok(())
}

fn put_sensitive(v: &mut Vec<u8>, mut bytes: Vec<u8>) -> Result<(), String> {
    let result = put32(v, &bytes);
    bytes.fill(0);
    result
}

fn take<'a>(buf: &'a [u8], position: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = position.checked_add(len).ok_or_else(malformed)?;
    let value = buf.get(*position..end).ok_or_else(malformed)?;
    *position = end;
    Ok(value)
}

fn take_u8(buf: &[u8], position: &mut usize) -> Result<u8, String> {
    Ok(take(buf, position, 1)?[0])
}

fn take_u16(buf: &[u8], position: &mut usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes(
        take(buf, position, 2)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}

fn take_u32(buf: &[u8], position: &mut usize) -> Result<u32, String> {
    Ok(u32::from_be_bytes(
        take(buf, position, 4)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}

fn take_u64(buf: &[u8], position: &mut usize) -> Result<u64, String> {
    Ok(u64::from_be_bytes(
        take(buf, position, 8)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}

fn take16<'a>(buf: &'a [u8], position: &mut usize) -> Result<&'a [u8], String> {
    let len = usize::from(take_u16(buf, position)?);
    take(buf, position, len)
}

fn take32<'a>(buf: &'a [u8], position: &mut usize) -> Result<&'a [u8], String> {
    let len = usize::try_from(take_u32(buf, position)?).map_err(|_| malformed())?;
    take(buf, position, len)
}

fn take_count(buf: &[u8], position: &mut usize, maximum: usize) -> Result<usize, String> {
    let count = usize::try_from(take_u32(buf, position)?).map_err(|_| malformed())?;
    (count <= maximum).then_some(count).ok_or_else(malformed)
}

fn take_array<const N: usize>(buf: &[u8], position: &mut usize) -> Result<[u8; N], String> {
    take(buf, position, N)?.try_into().map_err(|_| malformed())
}

fn take_string16(buf: &[u8], position: &mut usize) -> Result<String, String> {
    String::from_utf8(take16(buf, position)?.to_vec()).map_err(|_| malformed())
}

fn encode_cell(v: &mut Vec<u8>, cell: &Cell) -> Result<(), String> {
    cell.encode_auto().map_err(|error| error.to_string())?;
    v.extend_from_slice(&[cell.version, cell.raw_type, cell.flags]);
    v.extend_from_slice(&cell.round_ctr.to_be_bytes());
    put32(v, &cell.payload)
}

fn decode_cell(buf: &[u8], position: &mut usize) -> Result<Cell, String> {
    let cell = Cell {
        version: take_u8(buf, position)?,
        raw_type: take_u8(buf, position)?,
        flags: take_u8(buf, position)?,
        round_ctr: take_u16(buf, position)?,
        payload: take32(buf, position)?.to_vec(),
    };
    cell.encode_auto().map_err(|_| malformed())?;
    Ok(cell)
}

fn encode_route(v: &mut Vec<u8>, route: &crate::channel::ChannelRoute) -> Result<(), String> {
    put32(v, &route.encode())
}

fn decode_route(buf: &[u8], position: &mut usize) -> Result<crate::channel::ChannelRoute, String> {
    crate::channel::ChannelRoute::decode(take32(buf, position)?).ok_or_else(malformed)
}

fn prepared_route_context(seed: &[u8; 32], pseudonym: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"pending-join",
        pseudonym,
        b"gc1/prepared-route/v1",
    )
    .map_err(|e| e.to_string())
}
fn seal_prepared_route(
    route: &crate::channel::OwnedChannelRoute,
    seed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let plain = encode_owned_route(route)?;
    seal_bytes(
        &channel_archive_key(seed),
        &prepared_route_context(seed, &route.public.pseudonym)?,
        &plain,
    )
}

fn encode_owned_route(route: &crate::channel::OwnedChannelRoute) -> Result<SecretBuffer, String> {
    if route.aliases.len() != 2 {
        return Err(malformed());
    }
    let mut plain = SecretBuffer(Vec::new());
    encode_route(&mut plain, &route.public)?;
    for alias in &route.aliases {
        plain.extend_from_slice(&alias.capabilities.push);
        plain.extend_from_slice(&alias.capabilities.sub);
        plain.extend_from_slice(&alias.capabilities.admin);
        plain.extend_from_slice(&alias.limits.max_queue_cells.to_be_bytes());
        plain.extend_from_slice(&alias.limits.max_queue_bytes.to_be_bytes());
        put16(&mut plain, alias.create_path.as_bytes())?;
        encode_cell(&mut plain, &alias.lease_create)?;
    }
    Ok(plain)
}
fn open_prepared_route(
    sealed: &[u8],
    seed: &[u8; 32],
    pseudonym: [u8; 32],
) -> Result<crate::channel::OwnedChannelRoute, String> {
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &prepared_route_context(seed, &pseudonym)?,
        sealed,
    )?);
    decode_owned_route(&plain, pseudonym, channel_direct_secret(seed, &pseudonym))
}

fn decode_owned_route(
    plain: &[u8],
    pseudonym: [u8; 32],
    direct_secret: [u8; 32],
) -> Result<crate::channel::OwnedChannelRoute, String> {
    let mut position = 0;
    let public = decode_route(plain, &mut position)?;
    if public.pseudonym != pseudonym {
        return Err(malformed());
    }
    let mut aliases = Vec::new();
    for contact in [&public.data, &public.control] {
        let push = take(plain, &mut position, 32)?
            .try_into()
            .map_err(|_| malformed())?;
        let sub = take(plain, &mut position, 32)?
            .try_into()
            .map_err(|_| malformed())?;
        let admin = take(plain, &mut position, 32)?
            .try_into()
            .map_err(|_| malformed())?;
        let max_queue_cells = u16::from_be_bytes(
            take(plain, &mut position, 2)?
                .try_into()
                .map_err(|_| malformed())?,
        );
        let max_queue_bytes = take_u64(plain, &mut position)?;
        let create_path = std::str::from_utf8(take16(plain, &mut position)?)
            .map_err(|_| malformed())?
            .to_string();
        let lease_create = decode_cell(plain, &mut position)?;
        if push != contact.push_cap {
            return Err(malformed());
        }
        aliases.push(OwnedAlias {
            contact: contact.clone(),
            capabilities: crate::lease::Capabilities { push, sub, admin },
            limits: crate::lease::LeaseLimits {
                max_queue_cells,
                max_queue_bytes,
            },
            create_path,
            lease_create,
        });
    }
    if position != plain.len() {
        return Err(malformed());
    }
    Ok(crate::channel::OwnedChannelRoute {
        public,
        direct_secret,
        aliases,
    })
}

fn established_route_context(
    seed: &[u8; 32],
    role: &ChannelRole,
) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"gc1/established-channel-route/v1",
        role.own_pseudonym(),
        role.channel_id().0,
    )
    .map_err(|error| error.to_string())
}

fn previous_route_context(seed: &[u8; 32], role: &ChannelRole) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"gc1/previous-channel-route/v1",
        role.own_pseudonym(),
        role.channel_id().0,
    )
    .map_err(|error| error.to_string())
}

pub(super) fn established_route_secret(
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> [u8; 32] {
    match role {
        ChannelRole::Owner(_) => {
            channel_direct_secret(&channel_seed_from(seed, name), &role.own_pseudonym())
        }
        ChannelRole::Member(_) => channel_direct_secret(seed, &role.own_pseudonym()),
    }
}

fn validate_established_route(
    route: &crate::channel::OwnedChannelRoute,
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> Result<(), String> {
    validate_owned_route(route, established_route_secret(seed, name, role), role)
}

fn validate_owned_route(
    route: &crate::channel::OwnedChannelRoute,
    secret: [u8; 32],
    role: &ChannelRole,
) -> Result<(), String> {
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    if route.public.pseudonym != role.own_pseudonym()
        || !route.public.is_valid()
        || route.direct_secret != secret
        || route.public.direct_public != public.to_bytes()
        || route.aliases.len() != 2
    {
        return Err("invalid established channel route".into());
    }
    for (alias, contact) in route
        .aliases
        .iter()
        .zip([&route.public.data, &route.public.control])
    {
        let capabilities = [
            alias.capabilities.push,
            alias.capabilities.sub,
            alias.capabilities.admin,
        ];
        if &alias.contact != contact
            || alias.capabilities.push != contact.push_cap
            || capabilities
                .iter()
                .any(|cap| *cap == [0; 32] || *cap == contact.queue_id)
            || capabilities[0] == capabilities[1]
            || capabilities[0] == capabilities[2]
            || capabilities[1] == capabilities[2]
            || alias.limits.max_queue_cells == 0
            || alias.limits.max_queue_bytes == 0
            || alias.create_path.is_empty()
            || alias.create_path.len() > 256
            || alias.lease_create.cell_type() != Some(CellType::RelaySub)
            || alias.lease_create.payload.len() != crate::lease::LEASE_CREATE_LEN
        {
            return Err("invalid established channel alias".into());
        }
    }
    Ok(())
}

#[cfg(test)]
fn seal_established_route(
    route: &crate::channel::OwnedChannelRoute,
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> Result<Vec<u8>, String> {
    validate_established_route(route, seed, name, role)?;
    let plain = encode_owned_route(route)?;
    seal_bytes(
        &channel_archive_key(seed),
        &established_route_context(seed, role)?,
        &plain,
    )
}

fn open_established_route(
    sealed: &[u8],
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> Result<crate::channel::OwnedChannelRoute, String> {
    if sealed.len() > 64 * 1024 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &established_route_context(seed, role)?,
        sealed,
    )?);
    let route = decode_owned_route(
        &plain,
        role.own_pseudonym(),
        established_route_secret(seed, name, role),
    )?;
    validate_established_route(&route, seed, name, role)?;
    Ok(route)
}

#[cfg(test)]
fn seal_previous_route(
    route: &crate::channel::OwnedChannelRoute,
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> Result<Vec<u8>, String> {
    validate_established_route(route, seed, name, role)?;
    let plain = encode_owned_route(route)?;
    seal_bytes(
        &channel_archive_key(seed),
        &previous_route_context(seed, role)?,
        &plain,
    )
}

fn open_previous_route(
    sealed: &[u8],
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> Result<crate::channel::OwnedChannelRoute, String> {
    if sealed.len() > 64 * 1024 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &previous_route_context(seed, role)?,
        sealed,
    )?);
    let route = decode_owned_route(
        &plain,
        role.own_pseudonym(),
        established_route_secret(seed, name, role),
    )?;
    validate_established_route(&route, seed, name, role)?;
    Ok(route)
}

fn validate_unified_route(
    route: &crate::channel::OwnedChannelRoute,
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
) -> Result<(), String> {
    let secret = routing::retained_channel_direct_secret(
        seed,
        name,
        &role.own_pseudonym(),
        &route.public.direct_public,
    )?;
    if route.direct_secret != secret {
        return Err("invalid retained channel direct secret".into());
    }
    validate_owned_route(route, secret, role)
}

fn seal_unified_route(
    route: &crate::channel::OwnedChannelRoute,
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
    previous: bool,
) -> Result<Vec<u8>, String> {
    validate_unified_route(route, seed, name, role)?;
    let context = if previous {
        previous_route_context(seed, role)?
    } else {
        established_route_context(seed, role)?
    };
    seal_bytes(
        &channel_archive_key(seed),
        &context,
        &encode_owned_route(route)?,
    )
}

fn open_unified_route(
    sealed: &[u8],
    seed: &[u8; 32],
    name: &str,
    role: &ChannelRole,
    previous: bool,
) -> Result<crate::channel::OwnedChannelRoute, String> {
    if sealed.len() > 64 * 1024 {
        return Err(malformed());
    }
    let context = if previous {
        previous_route_context(seed, role)?
    } else {
        established_route_context(seed, role)?
    };
    let plain = SecretBuffer(open_bytes(&channel_archive_key(seed), &context, sealed)?);
    let mut route = decode_owned_route(&plain, role.own_pseudonym(), [0; 32])?;
    route.direct_secret = routing::retained_channel_direct_secret(
        seed,
        name,
        &role.own_pseudonym(),
        &route.public.direct_public,
    )?;
    validate_unified_route(&route, seed, name, role)?;
    Ok(route)
}

fn encode_delivery(v: &mut Vec<u8>, delivery: &DirectDelivery) -> Result<(), String> {
    put_sensitive(v, delivery.peer.public().encode())?;
    put_count(v, delivery.cells.len())?;
    for cell in &delivery.cells {
        encode_cell(v, cell)?;
    }
    Ok(())
}

fn decode_delivery(
    buf: &[u8],
    position: &mut usize,
    has_private_relay: bool,
    allow_deferred: bool,
) -> Result<DirectDelivery, String> {
    let peer = NodeInfo::decode(take32(buf, position)?).ok_or_else(malformed)?;
    if peer.identity_pk.is_empty() || peer.primary().is_none() {
        return Err(malformed());
    }
    let relay = if has_private_relay {
        let relay_card = NodeInfo::decode_private(take32(buf, position)?).ok_or_else(malformed)?;
        let relay = relay_card.provisioning.ok_or_else(malformed)?;
        if relay.aliases.is_empty() || relay.frwd_path.is_empty() {
            return Err(malformed());
        }
        relay
    } else {
        RelayProvision {
            aliases: Vec::new(),
            frwd_path: String::new(),
            hop_key: [0; 32],
        }
    };
    let count = take_count(buf, position, 2)?;
    if count == 0 && !allow_deferred {
        return Err(malformed());
    }
    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        cells.push(decode_cell(buf, position)?);
    }
    Ok(DirectDelivery { peer, relay, cells })
}

fn encode_expected(
    v: &mut Vec<u8>,
    expected: &HashMap<[u8; 32], crate::channel::ChannelRoute>,
    acknowledged: &std::collections::HashSet<[u8; 32]>,
) -> Result<(), String> {
    if !acknowledged
        .iter()
        .all(|identity| expected.contains_key(identity))
    {
        return Err("invalid acknowledged recipient in node state".into());
    }
    put_count(v, expected.len())?;
    for (identity, route) in expected {
        if identity != &route.pseudonym {
            return Err("invalid expected recipient in node state".into());
        }
        v.extend_from_slice(identity);
        encode_route(v, route)?;
    }
    put_count(v, acknowledged.len())?;
    for identity in acknowledged {
        v.extend_from_slice(identity);
    }
    Ok(())
}

type ExpectedRecipients = (
    HashMap<[u8; 32], crate::channel::ChannelRoute>,
    std::collections::HashSet<[u8; 32]>,
);

fn decode_expected(buf: &[u8], position: &mut usize) -> Result<ExpectedRecipients, String> {
    let count = take_count(buf, position, MAX_CHANNEL_ITEMS)?;
    let mut expected = HashMap::with_capacity(count);
    for _ in 0..count {
        let identity = take_array(buf, position)?;
        let route = decode_route(buf, position)?;
        if identity != route.pseudonym || expected.insert(identity, route).is_some() {
            return Err(malformed());
        }
    }
    let count = take_count(buf, position, MAX_CHANNEL_ITEMS)?;
    let mut acknowledged = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let identity = take_array(buf, position)?;
        if !expected.contains_key(&identity) || !acknowledged.insert(identity) {
            return Err(malformed());
        }
    }
    Ok((expected, acknowledged))
}

fn remaining_ms(deadline: std::time::Instant, now: std::time::Instant) -> u64 {
    deadline
        .saturating_duration_since(now)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub fn encode_state(st: &NodeState) -> Result<Vec<u8>, String> {
    encode_state_inner(st, None)
}

pub fn encode_state_with_session(
    st: &NodeState,
    override_peer: &[u8],
    override_state: &peer_session::Snapshot,
) -> Result<Vec<u8>, String> {
    encode_state_inner(st, Some((override_peer, override_state)))
}

fn encode_state_inner(
    st: &NodeState,
    session_override: Option<(&[u8], &peer_session::Snapshot)>,
) -> Result<Vec<u8>, String> {
    if st.owner_transition_failed {
        return Err("owner lifecycle persistence outcome is unconfirmed".into());
    }
    let mut v = SecretBuffer(Vec::with_capacity(8192));
    let credited = st.sessions.values().any(|s| s.tag().is_some())
        || session_override.is_some_and(|(_, s)| s.tag().is_some());
    #[cfg(feature = "experimental-gc2")]
    let credited = credited || st.gc2_sessions;
    v.extend_from_slice(if credited { MAGIC_V21 } else { MAGIC_V19 });
    v.extend_from_slice(&now_ms().to_be_bytes());
    v.extend_from_slice(&st.next_direct_sequence.to_be_bytes());
    v.extend_from_slice(&st.local_contact_generation.to_be_bytes());
    put_count(&mut v, st.sessions.len())?;
    for (peer, session) in &st.sessions {
        put16(&mut v, peer)?;
        match st
            .session_states
            .get(peer)
            .copied()
            .unwrap_or(DirectSessionState::Established)
        {
            DirectSessionState::InitiatedUnconfirmed { expires } => {
                v.push(1);
                v.extend_from_slice(
                    &remaining_ms(expires, std::time::Instant::now()).to_be_bytes(),
                );
            }
            DirectSessionState::Established => v.push(2),
        }
        if let Some((override_peer, sealed)) =
            session_override.filter(|(override_peer, _)| *override_peer == peer.as_slice())
        {
            let _ = override_peer;
            put32(&mut v, sealed.as_bytes())?;
        } else {
            let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
            let context = direct_session_context(st, peer)?;
            let sealed = session
                .seal_state(&wrapping_key, &context)
                .map_err(|error| error.to_string())?;
            wrapping_key.fill(0);
            put32(&mut v, sealed.as_bytes())?;
        }
    }
    put_count(&mut v, st.peer_routes.len())?;
    for (peer, route) in &st.peer_routes {
        if peer != &route.identity_pk {
            return Err("invalid peer route in node state".into());
        }
        put16(&mut v, peer)?;
        put_sensitive(&mut v, route.public().encode())?;
        v.extend_from_slice(
            &st.peer_route_generations
                .get(peer)
                .copied()
                .unwrap_or(0)
                .to_be_bytes(),
        );
    }
    let instant_now = std::time::Instant::now();
    let retained: Vec<_> = st
        .pending_1to1
        .iter()
        .filter(|(_, pending)| {
            !pending
                .logical_record
                .as_deref()
                .is_some_and(crate::proto::is_volatile_application)
        })
        .collect();
    put_count(&mut v, retained.len())?;
    for (message_id, pending) in retained {
        v.extend_from_slice(message_id);
        v.extend_from_slice(&remaining_ms(pending.next_attempt, instant_now).to_be_bytes());
        v.extend_from_slice(&remaining_ms(pending.expires, instant_now).to_be_bytes());
        v.extend_from_slice(&pending.sequence.to_be_bytes());
        match &pending.logical_record {
            Some(record) => {
                v.push(1);
                put32(&mut v, record)?;
            }
            None => v.push(0),
        }
        v.push(u8::from(pending.application_event));
        encode_delivery(&mut v, &pending.delivery)?;
    }
    put_count(&mut v, st.direct_ack_outbox.len())?;
    for delivery in &st.direct_ack_outbox {
        encode_delivery(&mut v, delivery)?;
    }
    put_count(&mut v, st.processed_direct_order.len())?;
    for key in &st.processed_direct_order {
        let processed = st
            .processed_direct
            .get(key)
            .ok_or("invalid processed direct order")?;
        put16(&mut v, &key.0)?;
        v.extend_from_slice(&key.1.to_be_bytes());
        v.extend_from_slice(&processed.frame_hash);
        encode_delivery(&mut v, &processed.delivery)?;
    }
    put_count(&mut v, st.channels.len())?;
    for (name, channel) in &st.channels {
        put16(&mut v, name.as_bytes())?;
        v.push(match channel.visibility {
            crate::channel::ChannelVisibility::Public => 1,
            crate::channel::ChannelVisibility::Private => 2,
        });
        let archive_key = channel_archive_key(&st.identity_seed);
        let (role, mut blob) = match &channel.role {
            ChannelRole::Owner(owner) => (
                ROLE_OWNER,
                owner
                    .persist(&archive_key)
                    .map_err(|error| error.to_string())?,
            ),
            ChannelRole::Member(member) => (
                ROLE_MEMBER,
                member
                    .persist(&archive_key)
                    .map_err(|error| error.to_string())?,
            ),
        };
        v.push(role);
        put32(&mut v, &blob)?;
        blob.fill(0);
        let own_pseudonym = channel.role.own_pseudonym();
        let own_name = channel
            .directory
            .iter()
            .find(|(_, route)| route.pseudonym == own_pseudonym)
            .map(|(member, _)| member);
        match own_name {
            Some(member) => {
                v.push(1);
                put16(&mut v, member.as_bytes())?;
            }
            None => v.push(0),
        }
        put_count(
            &mut v,
            channel
                .directory
                .values()
                .filter(|route| route.pseudonym != own_pseudonym)
                .count(),
        )?;
        for (member, route) in &channel.directory {
            if route.pseudonym == own_pseudonym {
                continue;
            }
            put16(&mut v, member.as_bytes())?;
            encode_route(&mut v, route)?;
        }
        put_count(&mut v, channel.message_outbox.len())?;
        for (message_id, outbox) in &channel.message_outbox {
            if message_id != &crate::channel::msg_id(name, &outbox.wire) {
                return Err("invalid channel message journal".into());
            }
            v.extend_from_slice(message_id);
            put32(&mut v, &outbox.wire)?;
            encode_expected(&mut v, &outbox.expected, &outbox.acknowledged)?;
        }
        match &channel.membership_outbox {
            Some(outbox) => {
                v.push(1);
                if outbox.commit_id != crate::channel::msg_id(name, &outbox.commit) {
                    return Err("invalid membership journal".into());
                }
                v.extend_from_slice(&outbox.commit_id);
                v.extend_from_slice(&outbox.epoch.to_be_bytes());
                put32(&mut v, &outbox.commit)?;
                encode_expected(&mut v, &outbox.expected, &outbox.acknowledged)?;
            }
            None => v.push(0),
        }
        put_count(&mut v, channel.pending_control.len())?;
        for (route, wire) in &channel.pending_control {
            encode_route(&mut v, route)?;
            put32(&mut v, wire)?;
        }
        if channel.admission_cache.len() != channel.admission_cache_order.len() {
            return Err("invalid admission cache order".into());
        }
        put_count(&mut v, channel.admission_cache_order.len())?;
        for request_id in &channel.admission_cache_order {
            let admission = channel
                .admission_cache
                .get(request_id)
                .ok_or("invalid admission cache order")?;
            v.extend_from_slice(request_id);
            put16(&mut v, admission.name.as_bytes())?;
            v.extend_from_slice(&admission.pseudonym);
            put32(&mut v, &admission.welcome)?;
        }
        put_count(&mut v, channel.completed_removals.len())?;
        for member in &channel.completed_removals {
            if !valid_completed_removal_key(member) {
                return Err("invalid completed removal key".into());
            }
            put16(&mut v, member.as_bytes())?;
        }
        if channel.commit_ack_cache.len() != channel.commit_ack_order.len() {
            return Err("invalid control ACK cache order".into());
        }
        put_count(&mut v, channel.commit_ack_order.len())?;
        for message_id in &channel.commit_ack_order {
            let (route, wire) = channel
                .commit_ack_cache
                .get(message_id)
                .ok_or("invalid control ACK cache order")?;
            v.extend_from_slice(message_id);
            encode_route(&mut v, route)?;
            put32(&mut v, wire)?;
        }
        if channel.unrouted_ack_journal.len() != channel.unrouted_ack_order.len()
            || channel.unrouted_ack_order.len() > crate::channel::CHANNEL_ACK_LIMIT
        {
            return Err("invalid unrouted ACK journal order".into());
        }
        put_count(&mut v, channel.unrouted_ack_order.len())?;
        for key in &channel.unrouted_ack_order {
            let wire = channel
                .unrouted_ack_journal
                .get(key)
                .ok_or("invalid unrouted ACK journal order")?;
            if key.sender_pseudonym == channel.role.own_pseudonym()
                || !channel.role.roster().iter().any(|(_, name)| {
                    channel.role.pseudonym_for_name(name) == Some(key.sender_pseudonym)
                })
                || wire.is_empty()
            {
                return Err("invalid unrouted ACK journal".into());
            }
            v.extend_from_slice(&key.original_id);
            v.extend_from_slice(&key.sender_pseudonym);
            put32(&mut v, wire)?;
        }
        // v10: the single-use invite ledger, appended at the end of the channel
        // record (append-only, so older readers simply stop before it). FIFO
        // order preserved; `consumed` is a 1-byte present flag optionally
        // followed by the 32-byte redeemer pseudonym.
        if channel.invites.len() != channel.invite_order.len() {
            return Err("invalid invite order".into());
        }
        put_count(&mut v, channel.invite_order.len())?;
        for invite_id in &channel.invite_order {
            let invite = channel
                .invites
                .get(invite_id)
                .ok_or("invalid invite order")?;
            v.extend_from_slice(invite_id);
            v.extend_from_slice(&invite.secret);
            v.extend_from_slice(&invite.expiry.to_be_bytes());
            match invite.consumed {
                Some(pseudonym) => {
                    v.push(1);
                    v.extend_from_slice(&pseudonym);
                }
                None => v.push(0),
            }
        }
    }
    put_count(&mut v, st.direct_presence_opt_in.len())?;
    for peer in &st.direct_presence_opt_in {
        if peer.is_empty() {
            return Err("invalid direct presence policy".into());
        }
        put16(&mut v, peer)?;
    }
    put_count(&mut v, st.channel_presence_opt_in.len())?;
    for channel in &st.channel_presence_opt_in {
        if !st.channels.contains_key(channel) {
            return Err("invalid channel presence policy".into());
        }
        put16(&mut v, channel.as_bytes())?;
    }
    // Forward grants are private bearers: sealed under the node's direct
    // wrapping key with a grant-specific context.
    put_count(&mut v, st.forward_grants.len())?;
    {
        let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
        let context = forward_grant_context(&st.info.identity_pk)?;
        for grant in st.forward_grants.values() {
            let sealed = seal_bytes(&wrapping_key, &context, &grant.encode())?;
            put_sensitive(&mut v, sealed)?;
        }
        wrapping_key.fill(0);
    }
    put_sensitive(
        &mut v,
        seal_application_inbox(&st.application_inbox, &st.identity_seed)?,
    )?;
    v.extend_from_slice(&st.next_prep_id.to_be_bytes());
    put_count(&mut v, st.prepared.len())?;
    for (id, prepared) in &st.prepared {
        v.extend_from_slice(&id.to_be_bytes());
        put16(&mut v, prepared.display.as_bytes())?;
        put_sensitive(
            &mut v,
            prepared
                .mls
                .persist(&channel_archive_key(&st.identity_seed))
                .map_err(|e| e.to_string())?,
        )?;
        put_sensitive(
            &mut v,
            seal_prepared_route(&prepared.route, &st.identity_seed)?,
        )?;
    }
    put32(&mut v, &st.sealed_tls_identity)?;
    put_sensitive(
        &mut v,
        seal_central_ownership(&st.application_inbox.central_ownership, &st.identity_seed)?,
    )?;
    put_sensitive(
        &mut v,
        seal_machine_ownership(st.application_inbox.machine_owned, &st.identity_seed)?,
    )?;
    if st.routing.is_some() && st.client_relay.aliases.is_empty() {
        put32(&mut v, &[])?;
    } else {
        put_sensitive(&mut v, owner_aliases::seal_current(st)?)?;
    }
    if let Some(runtime) = &st.routing {
        let plain = SecretBuffer(
            runtime
                .discovery
                .directory
                .encode_private()
                .map_err(|e| e.to_string())?,
        );
        put_sensitive(
            &mut v,
            seal_bytes(
                &channel_archive_key(&st.identity_seed),
                &routing_context(&st.identity_seed)?,
                &plain,
            )?,
        )?;
    } else {
        put32(&mut v, &[])?;
    }
    let routes: Vec<_> = st
        .channels
        .iter()
        .filter(|(_, channel)| {
            !channel.own_route.aliases.is_empty() || channel.previous_own_route.is_some()
        })
        .collect();
    put_count(&mut v, routes.len())?;
    for (name, channel) in routes {
        put16(&mut v, name.as_bytes())?;
        for (route, previous) in [
            (
                (!channel.own_route.aliases.is_empty()).then_some(&channel.own_route),
                false,
            ),
            (channel.previous_own_route.as_ref(), true),
        ] {
            match route {
                Some(route) => {
                    v.push(1);
                    put_sensitive(
                        &mut v,
                        seal_unified_route(
                            route,
                            &st.identity_seed,
                            name,
                            &channel.role,
                            previous,
                        )?,
                    )?;
                }
                None => v.push(0),
            }
        }
    }
    #[cfg(feature = "experimental-gc2")]
    if credited {
        let plain = zeroize::Zeroizing::new(st.gc2_receipts.encode());
        put_sensitive(
            &mut v,
            seal_bytes(
                &channel_archive_key(&st.identity_seed),
                &gc2_receipts_context(&st.identity_seed)?,
                &plain,
            )?,
        )?;
    }
    if v.len() > MAX_ARCHIVE_BYTES {
        v.fill(0);
        return Err("node state export too large".into());
    }
    Ok(v.into_vec())
}

fn decode_v2(buf: &[u8], identity_seed: &[u8; 32]) -> Result<Archive, String> {
    let archive_key = channel_archive_key(identity_seed);
    if buf.len() > MAX_ARCHIVE_BYTES
        || !matches!(buf.get(..6), Some(magic) if magic == MAGIC_V2 || magic == MAGIC_V3 || magic == MAGIC_V4 || magic == MAGIC_V5 || magic == MAGIC_V6 || magic == MAGIC_V7 || magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21)
    {
        return Err("not a gc node state export".into());
    }
    let has_channel_metadata = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V3 || magic == MAGIC_V4 || magic == MAGIC_V5 || magic == MAGIC_V6 || magic == MAGIC_V7 || magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let sessions_are_sealed = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V4 || magic == MAGIC_V5 || magic == MAGIC_V6 || magic == MAGIC_V7 || magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_collision_state = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V5 || magic == MAGIC_V6 || magic == MAGIC_V7 || magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_contact_updates = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V6 || magic == MAGIC_V7 || magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_presence_policy = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V7 || magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_typed_removals = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V8 || magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_forward_grants = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V9 || magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_invites = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V10 || magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let has_application_inbox = matches!(buf.get(..6), Some(magic) if magic == MAGIC_V11 || magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21);
    let mut position = 6;
    let exported_ms = take_u64(buf, &mut position)?;
    let mut next_direct_sequence = if has_collision_state {
        take_u64(buf, &mut position)?
    } else {
        1
    };
    let local_contact_generation = if has_contact_updates {
        take_u64(buf, &mut position)?
    } else {
        1
    };
    if local_contact_generation == 0 {
        return Err(malformed());
    }
    let count = take_count(buf, &mut position, MAX_SESSIONS)?;
    let mut sessions = Vec::with_capacity(count);
    let mut session_keys = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let peer = take16(buf, &mut position)?.to_vec();
        if peer.is_empty() || !session_keys.insert(peer.clone()) {
            return Err(malformed());
        }
        let state = if has_collision_state {
            match take_u8(buf, &mut position)? {
                1 => ArchivedSessionState::InitiatedUnconfirmed {
                    remaining_ms: take_u64(buf, &mut position)?,
                },
                2 => ArchivedSessionState::Established,
                _ => return Err(malformed()),
            }
        } else {
            ArchivedSessionState::Established
        };
        let encoded = take32(buf, &mut position)?;
        let session = if sessions_are_sealed {
            match peer_session::Snapshot::from_bytes(encoded.to_vec()).map_err(|_| malformed())? {
                peer_session::Snapshot::Legacy(sealed) => ArchivedSession::Sealed(sealed),
                #[cfg(feature = "experimental-gc2")]
                peer_session::Snapshot::Credited(sealed, _) if matches!(buf.get(..6), Some(magic) if magic == MAGIC_V20 || magic == MAGIC_V21) => {
                    ArchivedSession::Credited(sealed)
                }
                #[cfg(feature = "experimental-gc2")]
                _ => return Err(malformed()),
            }
        } else {
            ArchivedSession::Legacy(Box::new(Session::decode(encoded).ok_or_else(malformed)?))
        };
        sessions.push((peer, session, state));
    }
    let count = take_count(buf, &mut position, MAX_SESSIONS)?;
    let mut peer_routes = Vec::with_capacity(count);
    let mut route_keys = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let peer = take16(buf, &mut position)?.to_vec();
        let route = NodeInfo::decode(take32(buf, &mut position)?).ok_or_else(malformed)?;
        let generation = if has_contact_updates {
            take_u64(buf, &mut position)?
        } else {
            0
        };
        if peer.is_empty()
            || peer != route.identity_pk
            || route.primary().is_none()
            || !route_keys.insert(peer.clone())
        {
            return Err(malformed());
        }
        peer_routes.push((peer, route, generation));
    }
    let count = take_count(buf, &mut position, MAX_DIRECT)?;
    let mut pending_direct = Vec::with_capacity(count);
    let mut pending_ids = std::collections::HashSet::with_capacity(count);
    let mut pending_sequences = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let message_id = take_array(buf, &mut position)?;
        let retry_ms = take_u64(buf, &mut position)?;
        let expiry_ms = take_u64(buf, &mut position)?;
        let sequence = if has_collision_state {
            take_u64(buf, &mut position)?
        } else {
            let sequence = next_direct_sequence;
            next_direct_sequence = next_direct_sequence.saturating_add(1);
            sequence
        };
        let logical_record = if has_collision_state {
            match take_u8(buf, &mut position)? {
                0 => None,
                1 => Some(take32(buf, &mut position)?.to_vec()),
                _ => return Err(malformed()),
            }
        } else {
            None
        };
        if logical_record
            .as_deref()
            .is_some_and(crate::proto::is_volatile_application)
        {
            return Err(malformed());
        }
        let application_event = if has_contact_updates {
            match take_u8(buf, &mut position)? {
                0 => false,
                1 => true,
                _ => return Err(malformed()),
            }
        } else {
            true
        };
        if expiry_ms == 0
            || sequence == 0
            || !pending_ids.insert(message_id)
            || !pending_sequences.insert(sequence)
        {
            return Err(malformed());
        }
        pending_direct.push((
            message_id,
            decode_delivery(
                buf,
                &mut position,
                !has_contact_updates,
                matches!(buf.get(..6), Some(magic) if magic == MAGIC_V16 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21),
            )?,
            logical_record,
            sequence,
            retry_ms,
            expiry_ms,
            application_event,
        ));
    }
    if has_collision_state
        && (next_direct_sequence == 0
            || pending_sequences
                .iter()
                .any(|sequence| *sequence >= next_direct_sequence))
    {
        return Err(malformed());
    }
    let count = take_count(buf, &mut position, MAX_DIRECT)?;
    let mut direct_acks = Vec::with_capacity(count);
    for _ in 0..count {
        direct_acks.push(decode_delivery(
            buf,
            &mut position,
            !has_contact_updates,
            false,
        )?);
    }
    let count = take_count(buf, &mut position, MAX_DIRECT)?;
    let mut processed_direct = Vec::with_capacity(count);
    let mut processed_keys = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let peer = take16(buf, &mut position)?.to_vec();
        let counter = take_u64(buf, &mut position)?;
        let frame_hash = take_array(buf, &mut position)?;
        let delivery = decode_delivery(buf, &mut position, !has_contact_updates, false)?;
        let key = (peer, counter);
        if !processed_keys.insert(key.clone()) {
            return Err(malformed());
        }
        processed_direct.push((
            key,
            ProcessedDirect {
                frame_hash,
                delivery,
            },
        ));
    }
    let mut channel_routes = HashMap::new();
    let mut previous_channel_routes = HashMap::new();
    #[cfg(test)]
    let mut layout = ArchiveLayout::default();
    let count = take_count(buf, &mut position, gcoms_mls::CHANNEL_MAX)?;
    let mut channels = Vec::with_capacity(count);
    let mut channel_names = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        let name = take_string16(buf, &mut position)?;
        if name.is_empty() || !channel_names.insert(name.clone()) {
            return Err(malformed());
        }
        let visibility = if has_channel_metadata {
            match take_u8(buf, &mut position)? {
                1 => crate::channel::ChannelVisibility::Public,
                2 => crate::channel::ChannelVisibility::Private,
                _ => return Err(malformed()),
            }
        } else {
            crate::channel::ChannelVisibility::Private
        };
        let kind = take_u8(buf, &mut position)?;
        let blob = take32(buf, &mut position)?;
        let role = match kind {
            ROLE_OWNER => {
                let owner_seed = channel_seed_from(identity_seed, &name);
                ChannelRole::Owner(
                    gcoms_mls::OwnerSession::restore(
                        &archive_key,
                        blob,
                        IdentityKeypair::from_seed(owner_seed),
                    )
                    .map_err(|_| malformed())?,
                )
            }
            ROLE_MEMBER => ChannelRole::Member(
                gcoms_mls::ChannelMember::restore(&archive_key, blob).map_err(|_| malformed())?,
            ),
            _ => return Err(malformed()),
        };
        #[cfg(test)]
        layout.channel_insertions.push((name.clone(), position));
        if buf.get(..6) == Some(MAGIC_V17) {
            let route =
                open_established_route(take32(buf, &mut position)?, identity_seed, &name, &role)?;
            channel_routes.insert(name.clone(), route);
            match take_u8(buf, &mut position)? {
                0 => {}
                1 => {
                    let previous = open_previous_route(
                        take32(buf, &mut position)?,
                        identity_seed,
                        &name,
                        &role,
                    )?;
                    previous_channel_routes.insert(name.clone(), previous);
                }
                _ => return Err(malformed()),
            }
        }
        let own_name = match take_u8(buf, &mut position)? {
            0 => None,
            1 => {
                let own_name = take_string16(buf, &mut position)?;
                if own_name.is_empty()
                    || role.pseudonym_for_name(&own_name) != Some(role.own_pseudonym())
                {
                    return Err(malformed());
                }
                Some(own_name)
            }
            _ => return Err(malformed()),
        };
        let directory_count = take_count(buf, &mut position, MAX_CHANNEL_ITEMS)?;
        let mut directory = HashMap::with_capacity(directory_count);
        let mut directory_names = HashSet::with_capacity(directory_count);
        for _ in 0..directory_count {
            let member = take_string16(buf, &mut position)?;
            let route = decode_route(buf, &mut position)?;
            if member.is_empty()
                || route.pseudonym == role.own_pseudonym()
                || !directory_names.insert(member.clone())
            {
                return Err(malformed());
            }
            // Retained writers could leave a public route after Remove/Add.
            // The authenticated MLS role remains the membership authority.
            if role.pseudonym_for_name(&member) == Some(route.pseudonym) {
                directory.insert(member, route);
            }
        }
        let message_count = take_count(buf, &mut position, 64)?;
        let mut message_outbox = Vec::with_capacity(message_count);
        let mut message_ids = std::collections::HashSet::with_capacity(message_count);
        for _ in 0..message_count {
            let message_id = take_array(buf, &mut position)?;
            let wire = take32(buf, &mut position)?.to_vec();
            let (expected, acknowledged) = decode_expected(buf, &mut position)?;
            if message_id != crate::channel::msg_id(&name, &wire)
                || expected.is_empty()
                || acknowledged.len() == expected.len()
                || !message_ids.insert(message_id)
            {
                return Err(malformed());
            }
            message_outbox.push((
                message_id,
                ChannelMessageOutbox {
                    wire,
                    expected,
                    acknowledged,
                },
            ));
        }
        let membership_outbox = match take_u8(buf, &mut position)? {
            0 => None,
            1 => {
                let commit_id = take_array(buf, &mut position)?;
                let epoch = take_u64(buf, &mut position)?;
                let commit = take32(buf, &mut position)?.to_vec();
                let (expected, acknowledged) = decode_expected(buf, &mut position)?;
                if commit_id != crate::channel::msg_id(&name, &commit)
                    || expected.is_empty()
                    || acknowledged.len() == expected.len()
                {
                    return Err(malformed());
                }
                Some(MembershipOutbox {
                    commit_id,
                    epoch,
                    commit,
                    expected,
                    acknowledged,
                })
            }
            _ => return Err(malformed()),
        };
        let control_count = take_count(buf, &mut position, 64)?;
        let mut pending_control = Vec::with_capacity(control_count);
        for _ in 0..control_count {
            pending_control.push((
                decode_route(buf, &mut position)?,
                take32(buf, &mut position)?.to_vec(),
            ));
        }
        let admission_count = take_count(buf, &mut position, 64)?;
        let mut admissions = Vec::with_capacity(admission_count);
        let mut admission_ids = std::collections::HashSet::with_capacity(admission_count);
        for _ in 0..admission_count {
            let request_id = take_array(buf, &mut position)?;
            let admission = CachedAdmission {
                name: take_string16(buf, &mut position)?,
                pseudonym: take_array(buf, &mut position)?,
                welcome: take32(buf, &mut position)?.to_vec(),
            };
            if admission.name.is_empty()
                || admission.welcome.is_empty()
                || !admission_ids.insert(request_id)
            {
                return Err(malformed());
            }
            admissions.push((request_id, admission));
        }
        let removal_count = take_count(buf, &mut position, MAX_CHANNEL_ITEMS)?;
        let mut completed_removals = Vec::with_capacity(removal_count);
        let mut removal_names = std::collections::HashSet::with_capacity(removal_count);
        for _ in 0..removal_count {
            let stored = take_string16(buf, &mut position)?;
            if stored.is_empty() {
                return Err(malformed());
            }
            let member = if has_typed_removals {
                if !valid_completed_removal_key(&stored) {
                    return Err(malformed());
                }
                stored
            } else {
                completed_legacy_removal_key(&stored)
            };
            if !removal_names.insert(member.clone()) {
                return Err(malformed());
            }
            completed_removals.push(member);
        }
        let ack_count = take_count(buf, &mut position, 64)?;
        let mut commit_acks = Vec::with_capacity(ack_count);
        let mut ack_ids = std::collections::HashSet::with_capacity(ack_count);
        for _ in 0..ack_count {
            let message_id = take_array(buf, &mut position)?;
            let route = decode_route(buf, &mut position)?;
            let wire = take32(buf, &mut position)?.to_vec();
            if wire.is_empty() || !ack_ids.insert(message_id) {
                return Err(malformed());
            }
            commit_acks.push((message_id, route, wire));
        }
        let unrouted_count = take_count(buf, &mut position, crate::channel::CHANNEL_ACK_LIMIT)?;
        let mut unrouted_acks = Vec::with_capacity(unrouted_count);
        let mut unrouted_keys = std::collections::HashSet::with_capacity(unrouted_count);
        for _ in 0..unrouted_count {
            let key = crate::channel::UnroutedAckKey {
                original_id: take_array(buf, &mut position)?,
                sender_pseudonym: take_array(buf, &mut position)?,
            };
            let wire = take32(buf, &mut position)?.to_vec();
            let sender_is_member = role
                .roster()
                .iter()
                .any(|(_, member)| role.pseudonym_for_name(member) == Some(key.sender_pseudonym));
            if key.sender_pseudonym == role.own_pseudonym()
                || !sender_is_member
                || wire.is_empty()
                || !unrouted_keys.insert(key)
            {
                return Err(malformed());
            }
            unrouted_acks.push((key, wire));
        }
        // v10: invite ledger, appended at the end of each channel record.
        let mut invites = Vec::new();
        if has_invites {
            let invite_count = take_count(buf, &mut position, 64)?;
            invites.reserve(invite_count);
            let mut invite_ids = std::collections::HashSet::with_capacity(invite_count);
            for _ in 0..invite_count {
                let invite_id: [u8; 16] = take_array(buf, &mut position)?;
                let secret: [u8; 32] = take_array(buf, &mut position)?;
                let expiry = take_u64(buf, &mut position)?;
                let consumed = match take_u8(buf, &mut position)? {
                    0 => None,
                    1 => Some(take_array::<32>(buf, &mut position)?),
                    _ => return Err(malformed()),
                };
                if !invite_ids.insert(invite_id) {
                    return Err(malformed());
                }
                invites.push((
                    invite_id,
                    crate::channel::InviteRecord {
                        secret,
                        expiry,
                        consumed,
                    },
                ));
            }
        }
        channels.push(ArchivedChannel {
            name,
            visibility,
            role,
            own_name,
            directory,
            message_outbox,
            membership_outbox,
            pending_control,
            admissions,
            invites,
            completed_removals,
            commit_acks,
            unrouted_acks,
        });
    }
    let mut direct_presence_opt_in = HashSet::new();
    let mut channel_presence_opt_in = HashSet::new();
    if has_presence_policy {
        let count = take_count(buf, &mut position, MAX_DIRECT)?;
        for _ in 0..count {
            let peer = take16(buf, &mut position)?.to_vec();
            if peer.is_empty() || !direct_presence_opt_in.insert(peer) {
                return Err(malformed());
            }
        }
        let count = take_count(buf, &mut position, gcoms_mls::CHANNEL_MAX)?;
        for _ in 0..count {
            let channel = take_string16(buf, &mut position)?;
            if !channel_names.contains(&channel) || !channel_presence_opt_in.insert(channel) {
                return Err(malformed());
            }
        }
    }
    let mut forward_grants = Vec::new();
    if has_forward_grants {
        let count = take_count(buf, &mut position, MAX_FORWARD_GRANTS)?;
        for _ in 0..count {
            // Sealed; opened in `decode_state` where the node key is known.
            let sealed = take32(buf, &mut position)?.to_vec();
            forward_grants.push(crate::alias::ForwardGrant {
                target: RelayTarget {
                    address: "0.0.0.0:0".parse().expect("static"),
                    relay_service_id: [0; 32],
                },
                frwd_path: String::new(),
                hop_key: [0; 32],
                expires_at: 0,
                issued_by: sealed,
            });
        }
    }
    let mut application_inbox = if has_application_inbox {
        open_application_inbox(take32(buf, &mut position)?, identity_seed)?
    } else {
        application_inbox::ApplicationInbox::default()
    };
    let mut prepared = Vec::new();
    let next_prep_id = if matches!(buf.get(..6), Some(magic) if magic == MAGIC_V12 || magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21)
    {
        let next = take_u64(buf, &mut position)?;
        let count = take_count(buf, &mut position, 64)?;
        let mut ids = HashSet::new();
        for _ in 0..count {
            let id = take_u64(buf, &mut position)?;
            let display = std::str::from_utf8(take16(buf, &mut position)?)
                .map_err(|_| malformed())?
                .to_string();
            if id == 0 || id >= next || !ids.insert(id) {
                return Err(malformed());
            }
            let mls = gcoms_mls::PreparedJoin::restore(&archive_key, take32(buf, &mut position)?)
                .map_err(|_| malformed())?;
            let route = open_prepared_route(
                take32(buf, &mut position)?,
                identity_seed,
                gcoms_mls::ChannelMember::prepared_pseudonym(&mls),
            )?;
            prepared.push((id, display, mls, route));
        }
        if next == 0 {
            return Err(malformed());
        }
        next
    } else {
        1
    };
    let tls_identity = if matches!(buf.get(..6), Some(magic) if magic == MAGIC_V13 || magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21)
    {
        let sealed = take32(buf, &mut position)?;
        if sealed.is_empty() {
            None
        } else {
            if sealed.len() > 64 * 1024 {
                return Err(malformed());
            }
            let plain = SecretBuffer(open_bytes(
                &channel_archive_key(identity_seed),
                &tls_identity_context(identity_seed)?,
                sealed,
            )?);
            Some(TlsIdentity::decode(&plain).map_err(|e| e.to_string())?)
        }
    } else {
        None
    };
    if matches!(buf.get(..6), Some(magic) if magic == MAGIC_V14 || magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21)
    {
        application_inbox.central_ownership =
            open_central_ownership(take32(buf, &mut position)?, identity_seed)?;
    }
    #[cfg(test)]
    {
        layout.trailer_start = position;
    }
    let magic = buf.get(..6);
    let mut routing_directory = None;
    let owner_aliases = if magic == Some(MAGIC_V16) {
        // Two deployed grammars share this prefix. Evaluate only their bounded
        // trailers without mutating state, require authentication and exact EOF,
        // and reject both failure and ambiguity instead of guessing authority.
        let retained = (|| -> Result<_, String> {
            let mut cursor = position;
            let machine = open_machine_ownership(take32(buf, &mut cursor)?, identity_seed)?;
            let owner = owner_aliases::open_unbound(take32(buf, &mut cursor)?, identity_seed)?;
            if cursor != buf.len() || (machine && application_inbox.central_ownership.is_some()) {
                return Err(malformed());
            }
            Ok((machine, Some(owner), None, HashMap::new()))
        })();
        let routed = (|| -> Result<_, String> {
            let mut cursor = position;
            let first = take32(buf, &mut cursor)?;
            let owner = if first.is_empty() {
                None
            } else {
                Some(owner_aliases::open_unbound(first, identity_seed)?)
            };
            let directory = open_routing_directory(take32(buf, &mut cursor)?, identity_seed)?;
            let count = take_count(buf, &mut cursor, MAX_CHANNEL_ITEMS)?;
            let mut routes = HashMap::with_capacity(count);
            for _ in 0..count {
                let name = take_string16(buf, &mut cursor)?;
                let channel = channels
                    .iter()
                    .find(|channel| channel.name == name)
                    .ok_or_else(malformed)?;
                let sealed = take32(buf, &mut cursor)?;
                if sealed.len() > 64 * 1024 {
                    return Err(malformed());
                }
                let mut route =
                    open_prepared_route(sealed, identity_seed, channel.role.own_pseudonym())?;
                route.direct_secret = routing::retained_channel_direct_secret(
                    identity_seed,
                    &name,
                    &route.public.pseudonym,
                    &route.public.direct_public,
                )?;
                validate_unified_route(&route, identity_seed, &name, &channel.role)?;
                if routes.insert(name, route).is_some() {
                    return Err(malformed());
                }
            }
            if cursor != buf.len() {
                return Err(malformed());
            }
            Ok((false, owner, Some(directory), routes))
        })();
        let (machine, owner, directory, routes) = match (retained, routed) {
            (Ok(value), Err(_)) | (Err(_), Ok(value)) => value,
            _ => return Err("invalid or ambiguous v16 archive trailer".into()),
        };
        application_inbox.machine_owned = machine;
        routing_directory = directory;
        channel_routes = routes;
        position = buf.len();
        owner
    } else if magic == Some(MAGIC_V17)
        || (magic == Some(MAGIC_V18)
            || (magic == Some(MAGIC_V19) || magic == Some(MAGIC_V20) || magic == Some(MAGIC_V21)))
    {
        application_inbox.machine_owned =
            open_machine_ownership(take32(buf, &mut position)?, identity_seed)?;
        let sealed = take32(buf, &mut position)?;
        let owner = if sealed.is_empty()
            && (magic == Some(MAGIC_V18)
                || (magic == Some(MAGIC_V19)
                    || magic == Some(MAGIC_V20)
                    || magic == Some(MAGIC_V21)))
        {
            None
        } else {
            Some(owner_aliases::open_unbound(sealed, identity_seed)?)
        };
        if magic == Some(MAGIC_V18)
            || (magic == Some(MAGIC_V19) || magic == Some(MAGIC_V20) || magic == Some(MAGIC_V21))
        {
            let sealed = take32(buf, &mut position)?;
            if !sealed.is_empty() {
                routing_directory = Some(open_routing_directory(sealed, identity_seed)?);
            }
            if owner.is_none() && routing_directory.is_none() {
                return Err(malformed());
            }
            let count = take_count(buf, &mut position, MAX_CHANNEL_ITEMS)?;
            let mut names = HashSet::with_capacity(count);
            for _ in 0..count {
                let name = take_string16(buf, &mut position)?;
                if !names.insert(name.clone()) {
                    return Err(malformed());
                }
                let channel = channels
                    .iter()
                    .find(|channel| channel.name == name)
                    .ok_or_else(malformed)?;
                let mut present = false;
                for (routes, previous) in [
                    (&mut channel_routes, false),
                    (&mut previous_channel_routes, true),
                ] {
                    match take_u8(buf, &mut position)? {
                        0 => {}
                        1 => {
                            let route = open_unified_route(
                                take32(buf, &mut position)?,
                                identity_seed,
                                &name,
                                &channel.role,
                                previous,
                            )?;
                            routes.insert(name.clone(), route);
                            present = true;
                        }
                        _ => return Err(malformed()),
                    }
                }
                if !present {
                    return Err(malformed());
                }
            }
        }
        owner
    } else if magic == Some(MAGIC_V15) {
        Some(owner_aliases::open_unbound(
            take32(buf, &mut position)?,
            identity_seed,
        )?)
    } else {
        None
    };
    if application_inbox.machine_owned && application_inbox.central_ownership.is_some() {
        return Err(malformed());
    }
    for (_, delivery, logical, _, _, _, _) in &pending_direct {
        #[cfg(feature = "experimental-gc2")]
        if (magic == Some(MAGIC_V20) || magic == Some(MAGIC_V21))
            && sessions.iter().any(|(peer, s, _)| {
                *peer == delivery.peer.identity_pk && matches!(s, ArchivedSession::Credited(_))
            })
            && logical
                .as_deref()
                .is_some_and(|record| decode_direct_record(record).is_some())
        {
            continue;
        }
        if delivery.cells.is_empty()
            && ((routing_directory.is_none()
                && !((magic == Some(MAGIC_V19)
                    || magic == Some(MAGIC_V20)
                    || magic == Some(MAGIC_V21))
                    && session_keys.contains(&delivery.peer.identity_pk)))
                || !logical
                    .as_deref()
                    .is_some_and(crate::proto::is_durable_direct_data))
        {
            return Err(malformed());
        }
    }
    #[cfg(feature = "experimental-gc2")]
    let gc2_receipts = if magic == Some(MAGIC_V21) {
        let sealed = take32(buf, &mut position)?;
        if sealed.len() > gc2_receipts::MAX_ENCODED + 28 {
            return Err(malformed());
        }
        let plain = zeroize::Zeroizing::new(open_bytes(
            &archive_key,
            &gc2_receipts_context(identity_seed)?,
            sealed,
        )?);
        Some(gc2_receipts::Ledger::decode(&plain)?)
    } else {
        None
    };
    if position != buf.len() {
        return Err(malformed());
    }
    Ok(Archive {
        #[cfg(test)]
        layout,
        previous_channel_routes,
        routing_directory,
        channel_routes,
        owner_aliases,
        tls_identity,
        prepared,
        next_prep_id,
        exported_ms,
        next_direct_sequence,
        application_inbox,
        #[cfg(feature = "experimental-gc2")]
        gc2_receipts,
        local_contact_generation,
        sessions,
        peer_routes,
        pending_direct,
        direct_acks,
        processed_direct,
        channels,
        direct_presence_opt_in,
        channel_presence_opt_in,
        forward_grants,
    })
}

#[cfg(test)]
#[derive(Default)]
struct ArchiveLayout {
    trailer_start: usize,
    channel_insertions: Vec<(String, usize)>,
}

fn open_routing_directory(
    sealed: &[u8],
    seed: &[u8; 32],
) -> Result<gcoms_routing::Directory, String> {
    if sealed.len() > 16 * 1024 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &routing_context(seed)?,
        sealed,
    )?);
    gcoms_routing::Directory::restore_private(&plain).map_err(|e| e.to_string())
}

fn routing_context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"network",
        b"relay-view",
        b"gc1/routing/v1",
    )
    .map_err(|e| e.to_string())
}

pub(super) fn restore_routing_directory(
    buf: &[u8],
    seed: &[u8; 32],
) -> Result<gcoms_routing::Directory, String> {
    if buf.get(..6) == Some(MAGIC_V1) {
        return Ok(gcoms_routing::Directory::new());
    }
    Ok(decode_v2(buf, seed)?.routing_directory.unwrap_or_default())
}

pub(super) fn restore_owner_aliases(
    buf: &[u8],
    seed: &[u8; 32],
    offline: bool,
) -> Result<Option<owner_aliases::Record>, String> {
    if buf.get(..6) == Some(MAGIC_V1) {
        return Ok(None);
    }
    let record = decode_v2(buf, seed)?.owner_aliases;
    if let Some(record) = &record {
        let mut clock = owner_aliases::RestoreClock::new(
            record.captured_ms,
            now_ms(),
            std::time::Instant::now(),
        )?;
        let effective = clock.observe(now_ms(), std::time::Instant::now())?;
        if !offline {
            record.validate_live(effective)?;
        }
    }
    Ok(record)
}

fn tls_identity_context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"relay-tls",
        b"identity",
        b"gc1/relay-tls/v1",
    )
    .map_err(|e| e.to_string())
}

pub(super) fn seal_tls_identity(
    identity: &TlsIdentity,
    seed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let plain = SecretBuffer(identity.encode().map_err(|e| e.to_string())?);
    seal_bytes(
        &channel_archive_key(seed),
        &tls_identity_context(seed)?,
        &plain,
    )
}

pub(super) fn restore_tls_identity(
    buf: &[u8],
    seed: &[u8; 32],
) -> Result<Option<TlsIdentity>, String> {
    if buf.get(..6) == Some(MAGIC_V1) {
        return Ok(None);
    }
    Ok(decode_v2(buf, seed)?.tls_identity)
}

fn machine_ownership_context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"machine-ownership",
        b"scope",
        b"gc1/machine-ownership/v1",
    )
    .map_err(|e| e.to_string())
}
fn seal_machine_ownership(value: bool, seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    seal_bytes(
        &channel_archive_key(seed),
        &machine_ownership_context(seed)?,
        &[u8::from(value)],
    )
}
fn open_machine_ownership(bytes: &[u8], seed: &[u8; 32]) -> Result<bool, String> {
    if bytes.len() > 128 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &machine_ownership_context(seed)?,
        bytes,
    )?);
    match plain.as_slice() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(malformed()),
    }
}

fn central_ownership_context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"central-ownership",
        b"partition",
        b"gc1/central-ownership/v1",
    )
    .map_err(|e| e.to_string())
}
fn seal_central_ownership(
    value: &Option<application_inbox::CentralOwnership>,
    seed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut plain = SecretBuffer(vec![u8::from(value.is_some())]);
    if let Some(value) = value {
        value.validate()?;
        for ids in [&value.primary, &value.scoped] {
            put_count(&mut plain, ids.len())?;
            for id in ids {
                plain.extend_from_slice(id);
            }
        }
        plain.extend_from_slice(&value.policy_hash);
    }
    seal_bytes(
        &channel_archive_key(seed),
        &central_ownership_context(seed)?,
        &plain,
    )
}
fn open_central_ownership(
    bytes: &[u8],
    seed: &[u8; 32],
) -> Result<Option<application_inbox::CentralOwnership>, String> {
    if bytes.len() > 2048 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &central_ownership_context(seed)?,
        bytes,
    )?);
    if plain.as_slice() == [0] {
        return Ok(None);
    }
    if plain.first() != Some(&1) {
        return Err(malformed());
    }
    let mut pos = 1;
    let mut read_ids = || -> Result<Vec<[u8; 16]>, String> {
        let count = take_count(&plain, &mut pos, 64)?;
        (0..count).map(|_| take_array(&plain, &mut pos)).collect()
    };
    let primary = read_ids()?;
    let scoped = read_ids()?;
    let policy_hash = take_array(&plain, &mut pos)?;
    let value = application_inbox::CentralOwnership {
        primary,
        scoped,
        policy_hash,
    };
    value.validate()?;
    if pos != plain.len() {
        return Err(malformed());
    }
    Ok(Some(value))
}

#[cfg(feature = "experimental-gc2")]
fn gc2_receipts_context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"gc2-logical-receipts",
        b"scope",
        b"gc2/logical-receipts/v1",
    )
    .map_err(|e| e.to_string())
}

fn application_inbox_context(seed: &[u8; 32]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"application-inbox",
        b"pending",
        b"gc1/application-inbox/v1",
    )
    .map_err(|e| e.to_string())
}

fn seal_application_inbox(
    inbox: &application_inbox::ApplicationInbox,
    seed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut plain = SecretBuffer(Vec::new());
    plain.extend_from_slice(&inbox.next_sequence.to_be_bytes());
    put_count(&mut plain, inbox.entries.len())?;
    for entry in &inbox.entries {
        plain.extend_from_slice(&entry.sequence.to_be_bytes());
        put16(&mut plain, &entry.peer_identity)?;
        plain.extend_from_slice(&entry.message_id);
        plain.extend_from_slice(&entry.received_at_unix.to_be_bytes());
        put32(&mut plain, &entry.body)?;
    }
    let mut key = direct_session_wrapping_key(seed);
    let result = seal_bytes(&key, &application_inbox_context(seed)?, &plain);
    key.fill(0);
    result
}

fn open_application_inbox(
    sealed: &[u8],
    seed: &[u8; 32],
) -> Result<application_inbox::ApplicationInbox, String> {
    // An inbox is at most 256 (12 KiB body + 1952-byte identity) entries.
    if sealed.len() > 4 * 1024 * 1024 {
        return Err(malformed());
    }
    let mut key = direct_session_wrapping_key(seed);
    let result = open_bytes(&key, &application_inbox_context(seed)?, sealed);
    key.fill(0);
    let plain = SecretBuffer(result?);
    let mut position = 0;
    let next_sequence = take_u64(&plain, &mut position)?;
    if next_sequence == 0 || next_sequence > 9_007_199_254_740_991 {
        return Err(malformed());
    }
    let count = take_count(
        &plain,
        &mut position,
        application_inbox::APPLICATION_INBOX_LIMIT,
    )?;
    let mut inbox = application_inbox::ApplicationInbox::default();
    let mut previous = 0;
    for _ in 0..count {
        let sequence = take_u64(&plain, &mut position)?;
        if sequence <= previous || sequence >= next_sequence {
            return Err(malformed());
        }
        let peer = take16(&plain, &mut position)?;
        let message_id = take_array(&plain, &mut position)?;
        let received = take_u64(&plain, &mut position)?;
        let body = take32(&plain, &mut position)?;
        let prior_len = inbox.entries.len();
        inbox.stage(peer, message_id, received, body)?;
        if inbox.entries.len() != prior_len + 1 {
            return Err(malformed());
        }
        inbox.entries.back_mut().expect("staged above").sequence = sequence;
        inbox.next_sequence = sequence + 1;
        previous = sequence;
    }
    if position != plain.len() {
        return Err(malformed());
    }
    inbox.next_sequence = next_sequence;
    Ok(inbox)
}

fn forward_grant_context(identity_pk: &[u8]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(identity_pk),
        b"forward-grant",
        b"pool",
        b"gc1/forward-grant/v1",
    )
    .map_err(|error| error.to_string())
}

fn seal_bytes(
    wrapping_key: &[u8; 32],
    context: &SessionContext,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, Payload};
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = Aes256Gcm::new_from_slice(wrapping_key)
        .expect("AES-256 key")
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &context_aad(context),
            },
        )
        .map_err(|_| "seal failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_bytes(
    wrapping_key: &[u8; 32],
    context: &SessionContext,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, Payload};
    if sealed.len() < 12 + 16 {
        return Err(malformed());
    }
    Aes256Gcm::new_from_slice(wrapping_key)
        .expect("AES-256 key")
        .decrypt(
            Nonce::from_slice(&sealed[..12]),
            Payload {
                msg: &sealed[12..],
                aad: &context_aad(context),
            },
        )
        .map_err(|_| "forward grant archive authentication failed".to_string())
}

fn context_aad(context: &SessionContext) -> Vec<u8> {
    // The SessionContext AAD is private to gc-crypto; bind the same fields
    // through its Debug-stable encoding.
    format!("gc1/forward-grant-aad/v1{context:?}").into_bytes()
}

pub async fn decode_state(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    buf: &[u8],
) -> Result<(), String> {
    {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.application_inbox.machine_owned
            || st.application_inbox.central_ownership.is_some()
            || st.application_inbox.local_routing_policy.is_some()
        {
            return Err("cannot replace initialized central ownership".into());
        }
    }
    if matches!(buf.get(..6), Some(magic) if magic == MAGIC_V15 || magic == MAGIC_V16 || magic == MAGIC_V17 || magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21)
    {
        return Err("owner alias archives require constructor restoration".into());
    }
    decode_state_at_startup(state, scheduler, buf).await
}

pub(super) async fn decode_state_at_startup(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    buf: &[u8],
) -> Result<(), String> {
    if buf.len() > MAX_ARCHIVE_BYTES {
        return Err("node state export too large".into());
    }
    if matches!(buf.get(..6), Some(magic) if magic == MAGIC_V20 || magic == MAGIC_V21) {
        #[cfg(feature = "experimental-gc2")]
        if !state.lock().unwrap_or_else(|p| p.into_inner()).gc2_sessions {
            return Err("GC/2 archive requires explicit GC/2 session selection".into());
        }
        #[cfg(not(feature = "experimental-gc2"))]
        return Err("GC/2 archive is not supported by this build".into());
    }
    {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.application_inbox.machine_owned
            || st.application_inbox.central_ownership.is_some()
            || st.application_inbox.local_routing_policy.is_some()
        {
            return Err("cannot replace initialized central ownership".into());
        }
    }
    if buf.get(..6) == Some(MAGIC_V1) {
        return super::persist_legacy::decode_state(state, scheduler, buf).await;
    }
    let (relay, identity_seed, offline) = {
        let state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            state.client_relay.clone(),
            state.identity_seed,
            state.routing.is_some(),
        )
    };
    let mut archive = decode_v2(buf, &identity_seed)?;
    #[cfg(feature = "experimental-gc2")]
    if state.lock().unwrap_or_else(|p| p.into_inner()).gc2_sessions
        && archive
            .sessions
            .iter()
            .any(|(_, s, _)| !matches!(s, ArchivedSession::Credited(_)))
    {
        return Err(
            "GC/1 sessions require explicit authenticated migration before GC/2 selection".into(),
        );
    }

    let mut restored_prepared = Vec::new();
    for (id, display, mls, mut route) in archive.prepared {
        if route
            .aliases
            .iter()
            .any(|alias| alias.contact.expiry <= now_unix())
        {
            continue;
        }
        if !offline {
            let authority = relay
                .aliases
                .first()
                .ok_or("relay has no channel authority")?;
            for alias in &mut route.aliases {
                *alias = restore_contact_alias(scheduler, authority, alias).await?;
            }
            open_route_lanes(scheduler, &route);
        }
        restored_prepared.push((
            id,
            PreparedChannelJoin {
                mls,
                route,
                display,
            },
        ));
    }
    let mut restored_channels = Vec::with_capacity(archive.channels.len());
    for archived in archive.channels {
        let pseudonym = archived.role.own_pseudonym();
        let mut previous_own_route = archive.previous_channel_routes.remove(&archived.name);
        let retained = archive.channel_routes.remove(&archived.name);
        let own_route = if offline {
            match retained {
                Some(route) => route,
                None => routing::pending_channel_route(
                    &identity_seed,
                    &archived.name,
                    pseudonym,
                    archived
                        .directory
                        .values()
                        .find(|r| r.pseudonym == pseudonym)
                        .cloned(),
                )?,
            }
        } else if let Some(mut route) = retained {
            if route
                .aliases
                .iter()
                .any(|alias| alias.contact.expiry <= now_unix())
            {
                let replacement =
                    provision_channel_route(scheduler, &relay, pseudonym, route.direct_secret)
                        .await?;
                previous_own_route = Some(route);
                replacement
            } else {
                let authority = relay
                    .aliases
                    .first()
                    .ok_or("relay has no channel authority")?;
                for alias in &mut route.aliases {
                    *alias = restore_contact_alias(scheduler, authority, alias).await?;
                }
                validate_unified_route(&route, &identity_seed, &archived.name, &archived.role)?;
                route
            }
        } else {
            provision_channel_route(
                scheduler,
                &relay,
                pseudonym,
                established_route_secret(&identity_seed, &archived.name, &archived.role),
            )
            .await?
        };
        if !offline {
            open_route_lanes(scheduler, &own_route);
        }
        // Fresh entropy for the overlay eviction RNG (T12): the seed is
        // never persisted or sent, so restoring with new randomness is safe
        // and keeps eviction unpredictable across restarts.
        let seed = rand::thread_rng().next_u64();
        let mut directory = archived.directory;
        if let Some(own_name) = archived.own_name {
            if own_route.public.is_valid() {
                directory.insert(own_name, own_route.public.clone());
            }
        }
        let mut channel = ChannelState::new(
            archived.role,
            own_route,
            seed,
            archived.name.clone(),
            archived.visibility,
        );
        channel.previous_own_route = previous_own_route;
        for route in directory.values() {
            channel.learn(route);
        }
        channel.directory = directory;
        for (message_id, outbox) in archived.message_outbox {
            channel.overlay.first_sighting(message_id);
            channel.message_outbox.insert(message_id, outbox);
        }
        if let Some(outbox) = archived.membership_outbox {
            channel.overlay.first_sighting(outbox.commit_id);
            channel.membership_outbox = Some(outbox);
        }
        channel.pending_control = archived.pending_control.into();
        for (request_id, admission) in archived.admissions {
            channel.admission_cache_order.push_back(request_id);
            channel.admission_cache.insert(request_id, admission);
        }
        for (invite_id, record) in archived.invites {
            channel.invite_order.push_back(invite_id);
            channel.invites.insert(invite_id, record);
        }
        channel.completed_removals = archived.completed_removals.into_iter().collect();
        for (message_id, route, wire) in archived.commit_acks {
            channel.overlay.first_sighting(message_id);
            channel.commit_ack_order.push_back(message_id);
            channel.commit_ack_cache.insert(message_id, (route, wire));
        }
        for (key, wire) in archived.unrouted_acks {
            channel.overlay.first_sighting(key.original_id);
            channel.unrouted_ack_order.push_back(key);
            channel.unrouted_ack_journal.insert(key, wire);
        }
        restored_channels.push((archived.name, channel));
    }
    let elapsed_ms = if now_ms() < archive.exported_ms {
        u64::MAX
    } else {
        now_ms().saturating_sub(archive.exported_ms)
    };
    let instant_now = std::time::Instant::now();
    let expired_unconfirmed = archive
        .sessions
        .iter()
        .filter(|(_peer, session, _state)| {
            #[cfg(feature = "experimental-gc2")]
            if matches!(session, ArchivedSession::Credited(_)) {
                return false;
            }
            let _ = session;
            true
        })
        .filter_map(|(peer, _, state)| match state {
            ArchivedSessionState::InitiatedUnconfirmed { remaining_ms }
                if remaining_ms.saturating_sub(elapsed_ms) == 0 =>
            {
                Some(peer.clone())
            }
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    let mut pending_direct = Vec::new();
    for (
        message_id,
        mut delivery,
        logical_record,
        sequence,
        retry_ms,
        expiry_ms,
        application_event,
    ) in archive.pending_direct
    {
        let remaining_expiry = expiry_ms.saturating_sub(elapsed_ms);
        if remaining_expiry == 0 || expired_unconfirmed.contains(&delivery.peer.identity_pk) {
            continue;
        }
        delivery.relay = relay.clone();
        let remaining_retry = retry_ms.saturating_sub(elapsed_ms).min(remaining_expiry);
        pending_direct.push((
            message_id,
            PendingDirect {
                delivery,
                logical_record,
                sequence,
                next_attempt: instant_now + std::time::Duration::from_millis(remaining_retry),
                expires: instant_now + std::time::Duration::from_millis(remaining_expiry),
                application_event,
            },
        ));
    }
    let direct_acks = archive
        .direct_acks
        .into_iter()
        .map(|mut delivery| {
            delivery.relay = relay.clone();
            delivery
        })
        .collect::<Vec<_>>();
    let processed_direct = archive
        .processed_direct
        .into_iter()
        .map(|(key, mut processed)| {
            processed.delivery.relay = relay.clone();
            (key, processed)
        })
        .collect::<Vec<_>>();
    let mut st = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if st.application_inbox.next_sequence != 1
        || st.application_inbox.machine_owned
        || st.application_inbox.central_ownership.is_some()
        || st.application_inbox.local_routing_policy.is_some()
    {
        return Err("cannot replace a live durable application inbox".into());
    }
    let mut restored_sessions = Vec::new();
    let mut restored_tags = HashSet::new();
    for (peer, archived, archived_state) in archive.sessions {
        if expired_unconfirmed.contains(&peer) {
            continue;
        }
        let session = match archived {
            ArchivedSession::Legacy(session) => PeerSession::from(*session),
            ArchivedSession::Sealed(sealed) => {
                let mut wrapping_key = direct_session_wrapping_key(&st.identity_seed);
                let context = direct_session_context(&st, &peer)?;
                let session = peer_session::Snapshot::Legacy(sealed)
                    .open(&wrapping_key, &context)
                    .map_err(|error| error.to_string())?;
                wrapping_key.fill(0);
                session
            }
            #[cfg(feature = "experimental-gc2")]
            ArchivedSession::Credited(sealed) => {
                let wrapping_key =
                    zeroize::Zeroizing::new(direct_session_wrapping_key(&st.identity_seed));
                let context = direct_session_context_for_tag(&st, &peer, Some(sealed.tag()))?;
                PeerSession::Credited(
                    sealed
                        .open(&wrapping_key, &context)
                        .map_err(|e| e.to_string())?,
                )
            }
        };
        let session_state = match archived_state {
            ArchivedSessionState::InitiatedUnconfirmed { remaining_ms } => {
                DirectSessionState::InitiatedUnconfirmed {
                    expires: instant_now
                        + std::time::Duration::from_millis(remaining_ms.saturating_sub(elapsed_ms)),
                }
            }
            ArchivedSessionState::Established => DirectSessionState::Established,
        };
        if session.tag().is_some_and(|tag| !restored_tags.insert(*tag)) {
            return Err("duplicate archived GC/2 session tag".into());
        }
        restored_sessions.push((peer, session, session_state));
    }
    #[cfg(feature = "experimental-gc2")]
    let restored_receipts = match archive.gc2_receipts {
        Some(receipts) => receipts,
        None => {
            let mut receipts = gc2_receipts::Ledger::default();
            for (peer, session, _) in &restored_sessions {
                if let PeerSession::Credited(session) = session {
                    if session.window().generation() != 1
                        || session.window().has_volatile_counters()
                    {
                        return Err(
                            "recovered or volatile GC/2 sessions require a v21 receipt archive"
                                .into(),
                        );
                    }
                    receipts.migrate(peer, session.window());
                }
            }
            receipts
        }
    };
    // Authenticate remaining fallible input before publishing sessions or
    // committing their shared resource account.
    let mut restored_grants = Vec::new();
    {
        let wrapping_key = zeroize::Zeroizing::new(direct_session_wrapping_key(&st.identity_seed));
        let context = forward_grant_context(&st.info.identity_pk)?;
        let now = now_unix();
        for sealed in archive.forward_grants {
            let plain =
                zeroize::Zeroizing::new(open_bytes(&wrapping_key, &context, &sealed.issued_by)?);
            let grant = crate::alias::ForwardGrant::decode(&plain).ok_or_else(malformed)?;
            if grant.expires_at > now && st.frwd_target_policy.permits(&grant.target) {
                restored_grants.push(grant);
            }
        }
    }
    #[cfg(feature = "experimental-gc2")]
    if st.gc2_sessions {
        if !st.sessions.is_empty()
            || !st.pending_1to1.is_empty()
            || !st.direct_ack_outbox.is_empty()
            || !st.processed_direct.is_empty()
        {
            return Err("cannot replace live GC/2 direct state".into());
        }
        let mut usage = crate::scheduler::PayloadUsage::default();
        for (_, session, _) in &restored_sessions {
            usage.add(session.retained_payload());
        }
        for (_, pending) in &pending_direct {
            usage.add(pending.retained_payload());
        }
        for ack in &direct_acks {
            usage.add(ack.retained_payload());
        }
        for (_, processed) in &processed_direct {
            usage.add(processed.delivery.retained_payload());
        }
        if let Some(update) = st.stage_retained_usage(usage, true)? {
            update.commit();
        }
    }
    #[cfg(feature = "experimental-gc2")]
    {
        st.gc2_receipts = restored_receipts;
    }
    for (peer, session, session_state) in restored_sessions {
        st.sessions.insert(peer.clone(), session);
        st.session_states.insert(peer, session_state);
    }
    st.next_direct_sequence = st
        .next_direct_sequence
        .max(archive.next_direct_sequence)
        .max(
            pending_direct
                .iter()
                .map(|(_, pending)| pending.sequence.saturating_add(1))
                .max()
                .unwrap_or(1),
        );
    st.local_contact_generation = st
        .local_contact_generation
        .max(archive.local_contact_generation);
    st.direct_presence.clear();
    st.direct_presence_counters.clear();
    st.channel_presence.clear();
    st.channel_presence_counters.clear();
    st.direct_presence_opt_in = archive.direct_presence_opt_in;
    st.channel_presence_opt_in = archive.channel_presence_opt_in;
    for grant in restored_grants {
        install_forward_grant(&mut st, grant);
    }
    for (peer, route, generation) in archive.peer_routes {
        st.peer_routes.insert(peer.clone(), route);
        st.peer_route_generations.insert(peer, generation);
    }
    for (message_id, pending) in pending_direct {
        st.pending_1to1.insert(message_id, pending);
    }
    st.direct_ack_outbox.extend(direct_acks.iter().cloned());
    for (key, processed) in processed_direct {
        st.processed_direct_order.push_back(key.clone());
        st.processed_direct.insert(key, processed);
    }
    for (name, channel) in restored_channels {
        st.channels.insert(name, channel);
    }
    st.prepared = restored_prepared.into_iter().collect();
    st.next_prep_id = archive.next_prep_id;
    st.application_inbox = archive.application_inbox;
    for delivery in direct_acks {
        if let Some(destination) = delivery.peer.primary().cloned() {
            for cell in &delivery.cells {
                let _ = scheduler.frwd(
                    ProducerClass::Direct,
                    delivery.relay.clone(),
                    destination.clone(),
                    cell.clone(),
                    st.frwd_target_policy.clone(),
                );
            }
        }
    }
    Ok(())
}

/// Owner identity seed of a channel, from the node seed and the channel name
/// (mirrors `channels::channel_seed` without needing a `NodeState`).
pub(super) fn channel_seed_from(identity_seed: &[u8; 32], channel: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(identity_seed), channel.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"gc1/channel-seed", &mut seed)
        .expect("32 bytes fit hkdf-sha256");
    seed
}

#[cfg(test)]
#[path = "channel_cold_route_tests.rs"]
mod channel_cold_route_tests;

#[cfg(test)]
fn replace_v18_owned_route(
    bytes: &[u8],
    seed: &[u8; 32],
    name: &str,
    route: &crate::channel::OwnedChannelRoute,
) -> Result<Vec<u8>, String> {
    if !matches!(bytes.get(..6), Some(magic) if magic == MAGIC_V18 || magic == MAGIC_V19 || magic == MAGIC_V20 || magic == MAGIC_V21)
    {
        return Err(malformed());
    }
    let archive = decode_v2(bytes, seed)?;
    let channel = archive
        .channels
        .iter()
        .find(|channel| channel.name == name)
        .ok_or_else(malformed)?;
    let mut position = archive.layout.trailer_start;
    for _ in 0..3 {
        take32(bytes, &mut position)?;
    }
    let count = take_count(bytes, &mut position, MAX_CHANNEL_ITEMS)?;
    for _ in 0..count {
        let entry = take_string16(bytes, &mut position)?;
        for previous in [false, true] {
            match take_u8(bytes, &mut position)? {
                0 => {}
                1 => {
                    let start = position;
                    take32(bytes, &mut position)?;
                    if entry == name && !previous {
                        let mut field = Vec::new();
                        put_sensitive(
                            &mut field,
                            seal_unified_route(route, seed, name, &channel.role, false)?,
                        )?;
                        let mut output = bytes.to_vec();
                        output.splice(start..position, field);
                        return Ok(output);
                    }
                }
                _ => return Err(malformed()),
            }
        }
    }
    Err("missing owned channel route".into())
}

#[cfg(test)]
pub(in crate::node) mod tests {
    use super::*;
    include!("persist/tracked_send_tests.rs");
    include!("persist/machine_scope_tests.rs");
    include!("persist/archive_compat_tests.rs");
    #[cfg(feature = "experimental-gc2")]
    include!("persist/gc2_session_tests.rs");
    #[cfg(feature = "experimental-gc2")]
    include!("persist/gc2_recovery_tests.rs");
    #[cfg(feature = "experimental-gc2")]
    include!("persist/gc2_volatile_tests.rs");
    #[cfg(feature = "experimental-gc2")]
    include!("persist/gc2_control_tests.rs");
    include!("persist/channel_directory_tests.rs");
    include!("persist/channel_pex_tests.rs");
    include!("persist/owner_reopen_tests.rs");

    fn contact(byte: u8) -> AliasContact {
        AliasContact {
            target: RelayTarget {
                address: format!("192.0.2.{byte}:443").parse().unwrap(),
                relay_service_id: [byte; 32],
            },
            queue_id: [byte.wrapping_add(1); 32],
            epoch: u64::from(byte) + 1,
            push_cap: [byte.wrapping_add(2); 32],
            expiry: 100_000,
        }
    }

    fn route(byte: u8, pseudonym: [u8; 32]) -> crate::channel::ChannelRoute {
        crate::channel::ChannelRoute {
            pseudonym,
            direct_public: [byte.wrapping_add(40); 32],
            data: contact(byte),
            control: contact(byte.wrapping_add(20)),
        }
    }

    fn owned_alias(byte: u8) -> crate::alias::OwnedAlias {
        let contact = contact(byte);
        valid_alias(contact, byte)
    }

    fn valid_alias(contact: AliasContact, byte: u8) -> crate::alias::OwnedAlias {
        let capabilities = Capabilities {
            push: contact.push_cap,
            sub: [byte.wrapping_add(4); 32],
            admin: [byte.wrapping_add(5); 32],
        };
        let grant = crate::lease::AdmissionGrant {
            relay_service_id: contact.target.relay_service_id,
            grant_id: [byte.wrapping_add(10); 16],
            grant_cap: [byte.wrapping_add(11); 32],
            queue_id: contact.queue_id,
            epoch: contact.epoch,
            not_before: now_unix().saturating_sub(1),
            expiry: now_unix() + 60,
            max_queue_cells: 32,
            max_queue_bytes: 65_536,
        }
        .encode(&[77; 32])
        .unwrap();
        let create = LeaseCreate {
            queue_id: contact.queue_id,
            epoch: contact.epoch,
            lease_expiry: contact.expiry,
            queue_cells: 32,
            queue_bytes: 65_536,
            capabilities,
            nonce: [byte.wrapping_add(9); 16],
            grant,
        };
        let wire = create.encode(&contact.target.relay_service_id).unwrap();
        crate::alias::OwnedAlias {
            contact,
            capabilities,
            limits: LeaseLimits {
                max_queue_cells: 32,
                max_queue_bytes: 65_536,
            },
            create_path: encode_b64url(&grant[49..81]),
            lease_create: Cell::new(CellType::RelaySub, 0, 0, wire.to_vec()),
        }
    }

    fn owner_relay() -> RelayProvision {
        let mut first = contact(50);
        first.expiry = now_unix() + 3600;
        let mut relay = RelayProvision {
            aliases: vec![valid_alias(first, 50)],
            frwd_path: "forward-50".into(),
            hop_key: [56; 32],
        };
        let mut second = contact(60);
        second.expiry = relay.aliases[0].contact.expiry;
        second.target = relay.aliases[0].contact.target.clone();
        relay.aliases.push(valid_alias(second, 60));
        relay
    }

    fn relay(byte: u8) -> RelayProvision {
        RelayProvision {
            aliases: vec![owned_alias(byte)],
            frwd_path: format!("forward-{byte}"),
            hop_key: [byte.wrapping_add(6); 32],
        }
    }

    fn peer(byte: u8) -> NodeInfo {
        NodeInfo {
            identity_pk: vec![byte; 32],
            bundle: vec![byte.wrapping_add(1); 64],
            aliases: vec![contact(byte), contact(byte.wrapping_add(20))],
            provisioning: None,
        }
    }

    /// A forward grant whose intermediary relay is `target_byte`, issued by
    /// the peer identified by `issuer_byte`, expiring at `expires_at`.
    fn grant(target_byte: u8, issuer_byte: u8, expires_at: u64) -> crate::alias::ForwardGrant {
        crate::alias::ForwardGrant {
            target: RelayTarget {
                address: format!("198.51.100.{target_byte}:443").parse().unwrap(),
                relay_service_id: [target_byte; 32],
            },
            frwd_path: format!("inbox-{target_byte}"),
            hop_key: [target_byte.wrapping_add(3); 32],
            expires_at,
            issued_by: vec![issuer_byte; 32],
        }
    }

    fn install(node: &mut NodeState, g: crate::alias::ForwardGrant) {
        let id = g.target.relay_service_id;
        node.active_intermediaries.push(id);
        node.forward_grants.insert(id, g);
    }

    // SPEC §11.1: the intermediary chosen for a delivery to `peer` must never
    // be the receiver's own relay, a grant the receiver issued, the node's own
    // relay, or an expired grant. This pins the hard exclusion invariant
    // deterministically (the integration test can only observe aggregate
    // counters, which also include incidental traffic to other peers).
    #[test]
    fn eligible_intermediaries_exclude_receiver_self_and_expired() {
        let now = 10_000u64;
        let mut node = state();
        // The node's own relay service id (from client_relay = relay(50)).
        let own_id = node.client_relay.aliases[0].contact.target.relay_service_id;

        // Receiver B: identity 0xB0, reachable via relays 0xB0 and 0xB0+20.
        let mut b = peer(0xB0);
        b.identity_pk = vec![0xB0; 32];

        // Grants in the active set:
        install(&mut node, grant(0x21, 0x21, now + 500)); // good intermediary
        install(&mut node, grant(0x22, 0x22, now + 500)); // good intermediary
        install(&mut node, grant(0xB0, 0x99, now + 500)); // B's OWN relay -> excluded
        install(&mut node, grant(0xC4, 0xB0, now + 500)); // issued BY B -> excluded
        install(&mut node, grant(own_id[0], 0x77, now + 500)); // node's own relay -> excluded
        install(&mut node, grant(0x25, 0x25, now - 1)); // expired -> excluded

        let eligible = super::eligible_intermediaries(&node, &b, now);
        let ids: std::collections::HashSet<[u8; 32]> =
            eligible.iter().map(|g| g.target.relay_service_id).collect();

        assert!(ids.contains(&[0x21; 32]));
        assert!(ids.contains(&[0x22; 32]));
        assert!(!ids.contains(&[0xB0; 32]), "receiver's own relay used");
        assert!(!ids.contains(&[0xC4; 32]), "grant issued by receiver used");
        assert!(!ids.contains(&own_id), "node's own relay used");
        assert!(!ids.contains(&[0x25; 32]), "expired grant used");
        assert_eq!(ids.len(), 2, "only the two good intermediaries remain");
    }

    const TEST_SEED: [u8; 32] = [0xA5; 32];

    pub(in crate::node) fn owned_channel_route(
        byte: u8,
        pseudonym: [u8; 32],
        direct_secret: [u8; 32],
    ) -> crate::channel::OwnedChannelRoute {
        let mut public = route(byte, pseudonym);
        public.direct_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(direct_secret))
                .to_bytes();
        let aliases = vec![
            valid_alias(public.data.clone(), byte),
            valid_alias(public.control.clone(), byte.wrapping_add(20)),
        ];
        crate::channel::OwnedChannelRoute {
            public,
            direct_secret,
            aliases,
        }
    }

    pub(in crate::node) fn established_owner_fixture(name: &str) -> ChannelState {
        let owner = gcoms_mls::OwnerSession::create(
            IdentityKeypair::from_seed(channel_seed_from(&TEST_SEED, name)),
            "owner",
            8,
        )
        .unwrap();
        let role = ChannelRole::Owner(owner);
        let own_route = owned_channel_route(
            61,
            role.own_pseudonym(),
            established_route_secret(&TEST_SEED, name, &role),
        );
        let public = own_route.public.clone();
        let mut channel = ChannelState::new(
            role,
            own_route,
            21,
            name.into(),
            crate::channel::ChannelVisibility::Private,
        );
        channel.directory.insert("owner".into(), public);
        channel
    }

    pub(in crate::node) fn state() -> NodeState {
        let identity = gcoms_crypto::IdentityKeypair::from_seed(TEST_SEED);
        let (bundle, secrets) = identity.issue_bundle();
        let info = NodeInfo {
            identity_pk: identity.public_bytes(),
            bundle: bundle.encode(),
            aliases: vec![contact(70), contact(90)],
            provisioning: None,
        };
        NodeState {
            #[cfg(feature = "experimental-gc2")]
            gc2_sessions: false,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_client: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_route: None,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_bulk_routes: Vec::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_bulk_cursor: 0,
            #[cfg(feature = "experimental-gc2")]
            gc2_carrier_directory: None,
            #[cfg(feature = "experimental-gc2")]
            retained_direct: std::sync::OnceLock::new(),
            #[cfg(feature = "experimental-gc2")]
            gc2_receipts: gc2_receipts::Ledger::default(),
            routing: None,
            secrets: Arc::new(secrets),
            identity_seed: [0xA5; 32],
            sealed_tls_identity: Vec::new(),
            info,
            sessions: HashMap::new(),
            session_states: HashMap::new(),
            peer_routes: HashMap::new(),
            peer_route_generations: HashMap::new(),
            local_contact_generation: 1,
            pending_1to1: HashMap::new(),
            next_direct_sequence: 1,
            durable_applications_enabled: false,
            application_inbox: application_inbox::ApplicationInbox::default(),
            direct_ack_outbox: VecDeque::new(),
            processed_direct: HashMap::new(),
            processed_direct_order: VecDeque::new(),
            direct_presence: HashMap::new(),
            direct_presence_counters: HashMap::new(),
            direct_presence_opt_in: HashSet::new(),
            channel_presence: HashMap::new(),
            channel_presence_counters: HashMap::new(),
            channel_presence_opt_in: HashSet::new(),
            parked: Vec::new(),
            accepted_first_moves: VecDeque::new(),
            channels: HashMap::new(),
            prepared: HashMap::new(),
            chan_parked: Vec::new(),
            channel_fragments: crate::proto::ChannelFragmentBuffer::default(),
            last_channel_send: None,
            pending_channel_direct: HashMap::new(),
            next_prep_id: 1,
            client_relay: owner_relay(),
            forward_grants: HashMap::new(),
            active_intermediaries: Vec::new(),
            last_intermediary_rotation: std::time::Instant::now(),
            intermediary_fallbacks: 0,
            staged_contact_aliases: None,
            unannounced_old_contact_aliases: None,
            unannounced_contact_deadlines: None,
            owner_transition_failed: false,
            alias_lifecycle_timing: AliasLifecycleConfig::default(),
            #[cfg(feature = "client-persist")]
            owner_clock: Mutex::new(persist::owner_aliases::RestoreClock::fresh().unwrap()),
            draining_contact_aliases: Vec::new(),
            subscribed_contact_aliases: HashSet::new(),
            subscribed_classes: HashSet::new(),
            #[cfg(feature = "client-persist")]
            owner_alias_origins: HashMap::new(),
            #[cfg(feature = "client-persist")]
            owner_alias_renewals: HashMap::new(),
            contact_aliases_activated: std::time::Instant::now(),
            frwd_target_policy: FrwdTargetPolicy::new(false),
            scheduler: RelayScheduler::new(Arc::new(Tp1Client::new().unwrap())),
            invite_redeem_inbox: VecDeque::new(),
            pending_invite_redemptions: HashMap::new(),
            durable_state_sink: None,
        }
    }

    fn delivery(byte: u8) -> DirectDelivery {
        DirectDelivery {
            peer: peer(byte),
            relay: relay(byte.wrapping_add(30)),
            cells: vec![Cell::new(
                CellType::Msg,
                3,
                0x1234,
                vec![byte.wrapping_add(9); 96],
            )],
        }
    }

    #[test]
    fn central_ownership_archive_upgrade_reload_and_failed_commit() {
        use gcoms_core::component::RoutingPolicy;
        let mut node = state();
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        let peer = node.info.identity_pk.clone();
        node.application_inbox
            .stage(&peer, [9; 16], 100, b"retained primary")
            .unwrap();
        let original = node.application_inbox.entries[0].clone();
        let policy = RoutingPolicy {
            bootstrap_listeners: Vec::new(),
            components: vec![[1; 16], [2; 16]],
            routes: vec![],
        };
        let configure = super::super::commands::configure_central_routes;
        node.durable_state_sink = Some(Arc::new(|_| Err("ownership failpoint".into())));
        assert!(configure(&mut node, policy.clone(), vec![[2; 16]]).is_err());
        assert!(node.application_inbox.central_ownership.is_none());
        assert!(node.application_inbox.local_routing_policy.is_none());
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        configure(&mut node, policy.clone(), vec![[2; 16]]).unwrap();
        let encoded = encode_state(&node).unwrap();
        assert_eq!(&encoded[..6], MAGIC_V19);
        let archive = decode_v2(&encoded, &TEST_SEED).unwrap();
        assert_eq!(
            archive.application_inbox.central_ownership,
            node.application_inbox.central_ownership
        );
        assert_eq!(archive.application_inbox.entries[0], original);
        assert!(archive.application_inbox.local_routing_policy.is_none());
        node.application_inbox = archive.application_inbox;
        assert!(configure(&mut node, policy.clone(), vec![[1; 16]]).is_err());
        configure(&mut node, policy, vec![[2; 16]]).unwrap();
        // Historical v13 has exactly the same prior fields, without the new trailer.
        let mut old = historical_archive(&node, HistoricalArchive::Machine16).unwrap();
        let sealed =
            seal_central_ownership(&node.application_inbox.central_ownership, &TEST_SEED).unwrap();
        let owner = owner_aliases::seal_current(&node).unwrap();
        old.truncate(
            old.len()
                - 4
                - owner.len()
                - 4
                - seal_machine_ownership(false, &TEST_SEED).unwrap().len()
                - 4
                - sealed.len(),
        );
        old[..6].copy_from_slice(MAGIC_V13);
        let prior = decode_v2(&old, &TEST_SEED).unwrap();
        assert!(prior.application_inbox.central_ownership.is_none());
        assert_eq!(prior.application_inbox.entries[0], original);
        let mut broken = encode_state(&node).unwrap();
        broken.pop();
        assert!(decode_v2(&broken, &TEST_SEED).is_err());
    }

    #[test]
    fn local_component_delivery_requires_routes_and_rolls_back_failed_persistence() {
        use gcoms_core::component::{RoutePermission, RoutedApplication, RoutingPolicy};
        let mut node = state();
        node.durable_applications_enabled = true;
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        let app = |kind: &str| {
            let mut v = b"GCAPP1".to_vec();
            v.extend_from_slice(&(kind.len() as u16).to_be_bytes());
            v.extend_from_slice(kind.as_bytes());
            v.extend_from_slice(b"signed request bytes");
            v
        };
        let wire = RoutedApplication {
            source: [1; 16],
            destination: [2; 16],
            application: app("test"),
        }
        .encode()
        .unwrap();
        let submit = super::super::commands::submit_local_component;
        assert!(submit(&mut node, &wire).is_err());
        let permission = |local, remote| RoutePermission {
            local: [local; 16],
            remote: [remote; 16],
            peer_identity: node.info.identity_pk.clone(),
            content_types: vec!["test".into()],
        };
        node.application_inbox.routing_policy = Some(RoutingPolicy {
            bootstrap_listeners: Vec::new(),
            components: vec![[1; 16], [2; 16]],
            routes: vec![permission(1, 2), permission(2, 1)],
        });
        let valid = node.application_inbox.routing_policy.clone().unwrap();
        for bad in 0..4 {
            let mut policy = valid.clone();
            match bad {
                0 => {
                    policy.routes.pop();
                }
                1 => {
                    policy.routes[0].peer_identity[0] ^= 1;
                }
                2 => {
                    policy.components.pop();
                }
                _ => {
                    policy.routes[0].content_types.clear();
                }
            }
            node.application_inbox.routing_policy = Some(policy);
            assert!(submit(&mut node, &wire).is_err());
            assert!(node.application_inbox.entries.is_empty());
        }
        node.application_inbox.routing_policy = Some(valid);
        node.durable_state_sink = Some(Arc::new(|_| Err("local persistence failpoint".into())));
        assert_eq!(
            submit(&mut node, &wire).unwrap_err(),
            "local persistence failpoint"
        );
        assert!(node.application_inbox.entries.is_empty());
        assert_eq!(node.application_inbox.next_sequence, 1);
        let saved = Arc::new(Mutex::new(Vec::new()));
        let sink = saved.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }));
        submit(&mut node, &wire).unwrap();
        let delivery = &node.application_inbox.entries[0];
        assert_eq!(delivery.peer_identity, node.info.identity_pk);
        assert_eq!(delivery.body, wire);
        assert_eq!(delivery.sequence, 1);
        assert!(!saved.lock().unwrap().is_empty());
        assert!(node.pending_1to1.is_empty());
        assert!(node.sessions.is_empty());
    }

    fn direct_fixture() -> (NodeState, Vec<u8>, Session) {
        let mut node = state();
        let alice_identity = IdentityKeypair::from_seed([0xD1; 32]);
        let (alice_bundle, _) = alice_identity.issue_bundle();
        let mut alice = peer(12);
        alice.identity_pk = alice_identity.public_bytes();
        alice.bundle = alice_bundle.encode();
        let bob_bundle = Bundle::decode(&node.info.bundle).unwrap();
        let (first_move, alice_session) = gcoms_crypto::initiate_authenticated(
            &alice_identity,
            &node.info.identity_pk,
            &bob_bundle,
            &alice.public().encode(),
        )
        .unwrap();
        let (_, bob_session) = node.secrets.accept(&first_move).unwrap();
        node.peer_routes
            .insert(alice.identity_pk.clone(), alice.clone());
        node.sessions
            .insert(alice.identity_pk.clone(), bob_session.into());
        node.session_states
            .insert(alice.identity_pk.clone(), DirectSessionState::Established);
        (node, alice.identity_pk, alice_session)
    }

    #[test]
    fn pending_presence_ack_requires_peer_persistence_and_fresh_frame() {
        let (mut node, alice, mut remote) = direct_fixture();
        let id = [0xA4; 16];
        let now = std::time::Instant::now();
        let mut packet = delivery(12);
        packet.peer = node.peer_routes[&alice].clone();
        node.pending_1to1.insert(
            id,
            PendingDirect {
                delivery: packet,
                logical_record: Some(
                    encode_direct_presence(id, 1, PresenceMode::RecentlyReachable, 30).unwrap(),
                ),
                sequence: 1,
                next_attempt: now,
                expires: now + std::time::Duration::from_secs(30),
                application_event: true,
            },
        );
        let (events, mut seen) = broadcast::channel(8);
        let ack = remote.send(&encode_direct_ack(id, false)).unwrap();
        // An authenticated different peer cannot consume this pending ACK.
        node.pending_1to1
            .get_mut(&id)
            .unwrap()
            .delivery
            .peer
            .identity_pk = vec![0; 1952];
        process_frame(&mut node, alice.clone(), ack, &events);
        assert!(node.pending_1to1.contains_key(&id));
        assert!(seen.try_recv().is_err());
        node.pending_1to1
            .get_mut(&id)
            .unwrap()
            .delivery
            .peer
            .identity_pk = alice.clone();
        let ack = remote.send(&encode_direct_ack(id, false)).unwrap();
        node.durable_state_sink = Some(Arc::new(|_| Err("ACK persistence failpoint".into())));
        process_frame(&mut node, alice.clone(), ack.clone(), &events);
        assert!(node.pending_1to1.contains_key(&id));
        assert!(seen.try_recv().is_err());
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        process_frame(&mut node, alice.clone(), ack.clone(), &events);
        assert!(!node.pending_1to1.contains_key(&id));
        assert!(
            matches!(seen.try_recv(), Ok(Ev::DirectDelivery { peer_pk, msg_id }) if peer_pk == alice && msg_id == id)
        );
        process_frame(&mut node, alice.clone(), ack, &events);
        assert!(
            seen.try_recv().is_err(),
            "replayed ACK is not a fresh observation"
        );
        let unsolicited = remote.send(&encode_direct_ack([0xB4; 16], false)).unwrap();
        process_frame(&mut node, alice, unsolicited, &events);
        assert!(
            seen.try_recv().is_err(),
            "unmatched ACK is not peer evidence"
        );
    }

    #[test]
    fn direct_presence_rejects_stale_counters_and_expires_to_unknown() {
        let mut node = state();
        let peer = vec![0x91; 32];
        let (events, mut receiver) = broadcast::channel(8);
        node.direct_presence_opt_in.insert(peer.clone());

        assert!(apply_direct_presence(
            &mut node,
            &peer,
            7,
            PresenceMode::Away,
            60,
            &events,
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(Ev::PresenceChanged {
                reachability: Reachability::Away,
                ..
            })
        ));
        assert!(!apply_direct_presence(
            &mut node,
            &peer,
            6,
            PresenceMode::RecentlyReachable,
            60,
            &events,
        ));
        assert_eq!(
            node.direct_presence.get(&peer).unwrap().reachability,
            Reachability::Away
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        node.direct_presence.get_mut(&peer).unwrap().expires =
            std::time::Instant::now() - std::time::Duration::from_millis(1);
        expire_direct_presence(&mut node, std::time::Instant::now(), &events);
        assert!(!node.direct_presence.contains_key(&peer));
        assert!(matches!(
            receiver.try_recv(),
            Ok(Ev::PresenceChanged {
                reachability: Reachability::Unknown,
                ..
            })
        ));
    }

    #[test]
    fn channel_presence_rejects_stale_leases_and_expires_to_unknown() {
        let mut node = state();
        let member_id = [0x92; 32];
        let key = ("ops".to_string(), member_id);
        let (events, mut receiver) = broadcast::channel(80);
        node.channel_presence_opt_in.insert("ops".into());

        for counter in 1..=65 {
            assert!(apply_channel_presence(
                &mut node,
                "ops",
                member_id,
                counter,
                PresenceMode::Away,
                60,
                &events,
            ));
        }
        assert_eq!(node.channel_presence_counters[&key], 65);
        assert!(!apply_channel_presence(
            &mut node,
            "ops",
            member_id,
            65,
            PresenceMode::RecentlyReachable,
            60,
            &events,
        ));
        assert_eq!(node.channel_presence[&key].reachability, Reachability::Away);

        assert!(apply_channel_presence(
            &mut node,
            "ops",
            member_id,
            66,
            PresenceMode::Invisible,
            0,
            &events,
        ));
        assert!(!node.channel_presence.contains_key(&key));
        assert!(!apply_channel_presence(
            &mut node,
            "ops",
            member_id,
            64,
            PresenceMode::Away,
            60,
            &events,
        ));
        assert!(!node.channel_presence.contains_key(&key));

        assert!(apply_channel_presence(
            &mut node,
            "ops",
            member_id,
            67,
            PresenceMode::Away,
            60,
            &events,
        ));

        node.channel_presence.get_mut(&key).unwrap().expires =
            std::time::Instant::now() - std::time::Duration::from_millis(1);
        expire_channel_presence(&mut node, std::time::Instant::now(), &events);
        assert!(!node.channel_presence.contains_key(&key));
        let mut expired = false;
        while let Ok(event) = receiver.try_recv() {
            expired |= matches!(
                event,
                Ev::ChannelPresenceChanged {
                    reachability: Reachability::Unknown,
                    ..
                }
            );
        }
        assert!(expired);
    }

    #[test]
    fn channel_member_revocation_clears_presence() {
        let mut node = state();
        let member_id = [0x93; 32];
        let key = ("ops".to_string(), member_id);
        let (events, mut receiver) = broadcast::channel(4);
        node.channel_presence_opt_in.insert("ops".into());
        assert!(apply_channel_presence(
            &mut node,
            "ops",
            member_id,
            1,
            PresenceMode::Away,
            60,
            &events,
        ));
        let _ = receiver.try_recv();

        withdraw_channel_presence(&mut node, "ops", member_id, &events);
        node.channel_presence_counters.remove(&key);

        assert!(!node.channel_presence.contains_key(&key));
        assert!(!node.channel_presence_counters.contains_key(&key));
        assert!(matches!(
            receiver.try_recv(),
            Ok(Ev::ChannelPresenceChanged {
                reachability: Reachability::Unknown,
                ..
            })
        ));
    }

    fn collision_fixture(
        remote_wins: bool,
    ) -> (NodeState, IdentityKeypair, NodeInfo, FirstMove, Session) {
        let mut node = state();
        let (remote_identity, remote_bundle) = (0u8..=u8::MAX)
            .find_map(|byte| {
                let identity = IdentityKeypair::from_seed([byte; 32]);
                let (bundle, _) = identity.issue_bundle();
                ((identity.public_bytes() < node.info.identity_pk) == remote_wins)
                    .then_some((identity, bundle))
            })
            .expect("an identity has the required ordering");
        let mut remote = peer(41);
        remote.identity_pk = remote_identity.public_bytes();
        remote.bundle = remote_bundle.encode();

        let node_bundle = Bundle::decode(&node.info.bundle).unwrap();
        let (winning_first_move, winning_session) = gcoms_crypto::initiate_authenticated(
            &remote_identity,
            &node.info.identity_pk,
            &node_bundle,
            &remote.public().encode(),
        )
        .unwrap();
        let node_identity = IdentityKeypair::from_seed(node.identity_seed);
        let (losing_first_move, losing_session) = gcoms_crypto::initiate_authenticated(
            &node_identity,
            &remote.identity_pk,
            &remote_bundle,
            &node.info.public().encode(),
        )
        .unwrap();
        node.sessions
            .insert(remote.identity_pk.clone(), losing_session.into());
        node.session_states.insert(
            remote.identity_pk.clone(),
            DirectSessionState::InitiatedUnconfirmed {
                expires: std::time::Instant::now() + std::time::Duration::from_secs(600),
            },
        );
        node.peer_routes
            .insert(remote.identity_pk.clone(), remote.clone());
        let now = std::time::Instant::now();
        for (sequence, body) in [(1, &b"first pending"[..]), (2, &b"second pending"[..])] {
            let message_id = [sequence as u8; 16];
            let mut pending_delivery = delivery(sequence as u8);
            pending_delivery.peer = remote.clone();
            if sequence == 1 {
                pending_delivery.cells.insert(
                    0,
                    Cell::new(CellType::Msg, 0, 1, encode_first_move(&losing_first_move)),
                );
            }
            node.pending_1to1.insert(
                message_id,
                PendingDirect {
                    delivery: pending_delivery,
                    logical_record: Some(encode_direct_data(message_id, sequence, false, body)),
                    sequence,
                    next_attempt: now + std::time::Duration::from_secs(60),
                    expires: now + std::time::Duration::from_secs(600),
                    application_event: true,
                },
            );
        }
        node.next_direct_sequence = 3;
        (
            node,
            remote_identity,
            remote,
            winning_first_move,
            winning_session,
        )
    }

    #[test]
    fn collision_loser_reencrypts_pending_records_in_logical_order() {
        let (mut node, _, remote, first_move, mut winning_session) = collision_fixture(true);

        let accepted = accept_first_move(&mut node, &first_move).unwrap();

        assert_eq!(accepted.peer_pk, remote.identity_pk);
        // Two re-encrypted pending records plus the forward-grant offer that
        // every confirmed session sends (SPEC §12).
        assert_eq!(accepted.rewritten.len(), 3);
        assert_eq!(
            node.session_states[&remote.identity_pk],
            DirectSessionState::Established
        );
        let mut bodies = Vec::new();
        let mut grants = 0;
        for delivery in accepted.rewritten {
            assert_eq!(delivery.cells.len(), 1);
            let Some(NodePayload::Frame(sender, frame)) = decode_payload(&delivery.cells[0]) else {
                panic!("rewritten delivery is not a direct frame");
            };
            assert_eq!(sender, node.info.identity_pk);
            let plaintext = winning_session.receive(&frame).unwrap();
            match decode_direct_record(&plaintext) {
                Some(DirectRecord::Data { body, .. }) => bodies.push(body),
                Some(DirectRecord::ForwardGrant { grant, .. }) => {
                    assert_eq!(grant.issued_by, node.info.identity_pk);
                    grants += 1;
                }
                other => panic!("unexpected rewritten record {other:?}"),
            }
        }
        assert_eq!(grants, 1);
        assert_eq!(
            bodies,
            vec![b"first pending".to_vec(), b"second pending".to_vec()]
        );
    }

    #[test]
    fn elected_local_initiator_rejects_competing_unconfirmed_session() {
        let (mut node, _, remote, first_move, _) = collision_fixture(false);
        let before_send = node.sessions[&remote.identity_pk].send_ctr();
        let before_cells = node.pending_1to1[&[1; 16]].delivery.cells.clone();

        assert!(accept_first_move(&mut node, &first_move).is_err());

        assert_eq!(node.sessions[&remote.identity_pk].send_ctr(), before_send);
        assert_eq!(node.pending_1to1[&[1; 16]].delivery.cells, before_cells);
        assert!(matches!(
            node.session_states[&remote.identity_pk],
            DirectSessionState::InitiatedUnconfirmed { .. }
        ));
    }

    #[test]
    fn competing_first_move_cannot_replace_established_session() {
        let (mut node, remote_identity, remote, first_move, _) = collision_fixture(true);
        accept_first_move(&mut node, &first_move).unwrap();
        let before_send = node.sessions[&remote.identity_pk].send_ctr();
        let before_recv = node.sessions[&remote.identity_pk].recv_ctr();
        let node_bundle = Bundle::decode(&node.info.bundle).unwrap();
        let (competing, _) = gcoms_crypto::initiate_authenticated(
            &remote_identity,
            &node.info.identity_pk,
            &node_bundle,
            &remote.public().encode(),
        )
        .unwrap();

        assert!(accept_first_move(&mut node, &competing).is_err());
        assert_eq!(node.sessions[&remote.identity_pk].send_ctr(), before_send);
        assert_eq!(node.sessions[&remote.identity_pk].recv_ctr(), before_recv);
        assert_eq!(
            node.session_states[&remote.identity_pk],
            DirectSessionState::Established
        );
    }

    #[test]
    fn persistent_tls_identity_is_sealed_bound_and_backward_compatible() {
        let mut node = state();
        let identity = TlsIdentity::generate().unwrap();
        node.sealed_tls_identity = seal_tls_identity(&identity, &node.identity_seed).unwrap();
        let encoded = encode_state(&node).unwrap();
        assert!(!encoded
            .windows(identity.private_key_pkcs8_der().len())
            .any(|bytes| bytes == identity.private_key_pkcs8_der()));
        let restored = restore_tls_identity(&encoded, &node.identity_seed)
            .unwrap()
            .unwrap();
        assert_eq!(restored.service_id(), identity.service_id());
        assert!(restore_tls_identity(&encoded, &[0x42; 32]).is_err());
        let mut damaged = encoded.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(restore_tls_identity(&damaged, &node.identity_seed).is_err());
        let mut legacy = historical_archive(&node, HistoricalArchive::Machine16).unwrap();
        let ownership_bytes = seal_central_ownership(&None, &node.identity_seed).unwrap();
        legacy.truncate(
            legacy.len()
                - 4
                - owner_aliases::seal_current(&node).unwrap().len()
                - 4
                - seal_machine_ownership(false, &TEST_SEED).unwrap().len()
                - 4
                - ownership_bytes.len()
                - 4
                - node.sealed_tls_identity.len(),
        );
        legacy[..6].copy_from_slice(MAGIC_V12);
        assert!(restore_tls_identity(&legacy, &node.identity_seed)
            .unwrap()
            .is_none());
    }

    #[test]
    fn application_inbox_archive_preserves_cursor_and_seals_pending_bytes() {
        let mut node = state();
        let peer = vec![1; 1952];
        let body = b"private application payload retained until local commit";
        node.application_inbox
            .stage(&peer, [1; 16], 100, b"consumed")
            .unwrap();
        node.application_inbox
            .stage(&peer, [2; 16], 101, body)
            .unwrap();
        let first = node.application_inbox.entries.front().unwrap().digest();
        node.application_inbox.consume(1, first).unwrap();
        let mut encoded = encode_state(&node).unwrap();
        assert_eq!(&encoded[..6], MAGIC_V19);
        assert!(!encoded.windows(body.len()).any(|window| window == body));
        let decoded = decode_v2(&encoded, &TEST_SEED).unwrap();
        assert_eq!(decoded.application_inbox.next_sequence, 3);
        let entries = decoded.application_inbox.page(0, 32).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 2);
        assert_eq!(entries[0].body, body);
        assert!(decode_v2(&encoded, &[0x22; 32]).is_err());
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(decode_v2(&encoded, &TEST_SEED).is_err());
    }

    #[test]
    fn unsigned_first_move_is_rejected_without_touching_state() {
        let mut node = state();
        let alice_identity = IdentityKeypair::from_seed([0xD1; 32]);
        let (alice_bundle, _) = alice_identity.issue_bundle();
        let mut alice = peer(12);
        alice.identity_pk = alice_identity.public_bytes();
        alice.bundle = alice_bundle.encode();
        let node_bundle = Bundle::decode(&node.info.bundle).unwrap();
        let (unsigned, _) = gcoms_crypto::initiate(
            &node.info.identity_pk,
            &node_bundle,
            &alice.public().encode(),
        )
        .unwrap();

        assert!(accept_first_move(&mut node, &unsigned).is_err());

        assert!(!node.sessions.contains_key(&alice.identity_pk));
        assert!(!node.peer_routes.contains_key(&alice.identity_pk));
        assert!(node.accepted_first_moves.is_empty());
    }

    #[test]
    fn forged_first_move_is_rejected_without_touching_state() {
        let mut node = state();
        // Mallory crafts a first move claiming a victim's identity and
        // supplies her own routing. The signature is Mallory's, so it can
        // never verify against the claimed victim identity.
        let victim = IdentityKeypair::from_seed([0x77; 32]);
        let mallory = IdentityKeypair::from_seed([0x99; 32]);
        let (mallory_bundle, _) = mallory.issue_bundle();
        let mut claimed = peer(12);
        claimed.identity_pk = victim.public_bytes();
        claimed.bundle = mallory_bundle.encode();
        let node_bundle = Bundle::decode(&node.info.bundle).unwrap();
        let (forged, _) = gcoms_crypto::initiate_authenticated(
            &mallory,
            &node.info.identity_pk,
            &node_bundle,
            &claimed.public().encode(),
        )
        .unwrap();

        assert!(accept_first_move(&mut node, &forged).is_err());

        assert!(!node.sessions.contains_key(&victim.public_bytes()));
        assert!(!node.peer_routes.contains_key(&victim.public_bytes()));
        assert!(node.accepted_first_moves.is_empty());
    }

    #[test]
    fn cross_responder_replayed_first_move_is_rejected() {
        // A signature honestly created for one responder must not be
        // accepted by a different responder even when the claimed identity
        // matches the signer.
        let mut node = state();
        let other = state();
        let alice_identity = IdentityKeypair::from_seed([0xD2; 32]);
        let (alice_bundle, _) = alice_identity.issue_bundle();
        let mut alice = peer(12);
        alice.identity_pk = alice_identity.public_bytes();
        alice.bundle = alice_bundle.encode();
        let other_bundle = Bundle::decode(&other.info.bundle).unwrap();
        let (replayed, _) = gcoms_crypto::initiate_authenticated(
            &alice_identity,
            &other.info.identity_pk,
            &other_bundle,
            &alice.public().encode(),
        )
        .unwrap();

        assert!(accept_first_move(&mut node, &replayed).is_err());

        assert!(!node.sessions.contains_key(&alice.identity_pk));
        assert!(node.accepted_first_moves.is_empty());
    }

    #[test]
    fn contact_update_is_encrypted_journaled_and_has_no_application_receipt() {
        let (mut node, alice_pk, mut alice_session) = direct_fixture();
        let now = now_unix();
        for alias in &mut node.info.aliases {
            alias.expiry = now + 3600;
        }

        let deliveries = queue_contact_updates(&mut node).unwrap();

        assert_eq!(node.local_contact_generation, 2);
        // The signed update plus a refreshed forward grant.
        assert_eq!(deliveries.len(), 2);
        let pending = node
            .pending_1to1
            .values()
            .find(|pending| pending.delivery.cells == deliveries[0].cells)
            .unwrap();
        assert!(!pending.application_event);
        let Some(NodePayload::Frame(sender, frame)) = decode_payload(&deliveries[0].cells[0])
        else {
            panic!("contact update was not ratchet encrypted");
        };
        assert_eq!(sender, node.info.identity_pk);
        let plaintext = alice_session.receive(&frame).unwrap();
        let Some(DirectRecord::ContactUpdate { message_id, update }) =
            decode_direct_record(&plaintext)
        else {
            panic!("missing contact update direct record");
        };
        assert_eq!(
            message_id,
            contact_update_message_id(&node.info.identity_pk, &alice_pk, 2)
        );
        assert!(update.verify(&node.info.identity_pk, now));

        let archived = decode_v2(&encode_state(&node).unwrap(), &node.identity_seed).unwrap();
        assert_eq!(archived.local_contact_generation, 2);
        // The update and the grant refresh both journal; pick the update.
        assert_eq!(archived.pending_direct.len(), 2);
        let update_index = archived
            .pending_direct
            .iter()
            .position(|entry| entry.0 == message_id)
            .expect("journaled contact update");
        assert!(!archived.pending_direct[update_index].6);
        assert_eq!(
            archived.pending_direct[update_index].2.as_deref(),
            pending.logical_record.as_deref()
        );
    }

    #[test]
    fn failed_contact_announcement_is_retryable_with_a_new_generation() {
        let mut node = state();
        for alias in &mut node.info.aliases {
            alias.expiry = now_unix() + 3600;
        }
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts_for_sink = attempts.clone();
        node.durable_state_sink = Some(Arc::new(move |_| {
            if attempts_for_sink.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Err("announcement failpoint".into())
            } else {
                Ok(())
            }
        }));

        assert!(matches!(
            queue_contact_updates(&mut node),
            Err(error) if error == "announcement failpoint"
        ));
        assert!(queue_contact_updates(&mut node).unwrap().is_empty());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(node.local_contact_generation, 3);
    }

    #[tokio::test]
    async fn accepted_contact_update_is_idempotent_and_rejects_tamper() {
        let (mut node, alice_pk, mut alice_session) = direct_fixture();
        let alice_identity = IdentityKeypair::from_seed([0xD1; 32]);
        let now = now_unix();
        let mut queued = delivery(0x35);
        queued.peer = node.peer_routes[&alice_pk].clone();
        let ciphertext = queued.cells.clone();
        let mut route = node.peer_routes[&alice_pk].clone();
        route.aliases = vec![contact(120), contact(140)];
        for alias in &mut route.aliases {
            alias.expiry = now + 3600;
        }
        let update =
            ContactUpdate::sign(9, now, now + 3600, route.clone(), &alice_identity).unwrap();
        let message_id = [0x91; 16];
        let frame = alice_session
            .send(&encode_contact_update(message_id, &update).unwrap())
            .unwrap();
        let (events, mut receiver) = broadcast::channel(8);

        process_frame(&mut node, alice_pk.clone(), frame.clone(), &events);
        assert_eq!(node.peer_route_generations[&alice_pk], 9);
        assert_eq!(node.peer_routes[&alice_pk], route);
        reroute_deliveries(&mut node, std::slice::from_mut(&mut queued));
        assert_eq!(
            queued.peer, route,
            "queued retries kept the old receive queue"
        );
        assert_eq!(
            queued.cells, ciphertext,
            "rerouting rewrote encrypted bytes"
        );
        assert_eq!(node.direct_ack_outbox.len(), 1);
        let exact_ack = node.direct_ack_outbox[0].cells.clone();
        assert!(
            receiver.try_recv().is_err(),
            "control update emitted app event"
        );

        process_frame(&mut node, alice_pk.clone(), frame, &events);
        assert_eq!(
            node.direct_ack_outbox.len(),
            2,
            "duplicate did not replay ACK"
        );
        assert_eq!(node.direct_ack_outbox[1].cells, exact_ack);

        let mut tampered = ContactUpdate::sign(
            10,
            now,
            now + 3600,
            node.peer_routes[&alice_pk].clone(),
            &alice_identity,
        )
        .unwrap();
        tampered.signature[0] ^= 1;
        let frame = alice_session
            .send(&encode_contact_update([0x92; 16], &tampered).unwrap())
            .unwrap();
        process_frame(&mut node, alice_pk.clone(), frame, &events);
        assert_eq!(node.peer_route_generations[&alice_pk], 9);
        assert_eq!(node.direct_ack_outbox.len(), 2);

        let stale = ContactUpdate::sign(
            8,
            now,
            now + 3600,
            node.peer_routes[&alice_pk].clone(),
            &alice_identity,
        )
        .unwrap();
        let frame = alice_session
            .send(&encode_contact_update([0x93; 16], &stale).unwrap())
            .unwrap();
        process_frame(&mut node, alice_pk.clone(), frame, &events);
        assert_eq!(node.peer_route_generations[&alice_pk], 9);
        assert_eq!(node.direct_ack_outbox.len(), 2);
    }

    #[test]
    fn stale_caller_card_cannot_downgrade_authenticated_route() {
        let (mut node, alice_pk, _) = direct_fixture();
        let stale = node.peer_routes[&alice_pk].clone();
        let mut authenticated = stale.clone();
        authenticated.aliases = vec![contact(121), contact(141)];
        node.peer_routes
            .insert(alice_pk.clone(), authenticated.clone());
        node.peer_route_generations.insert(alice_pk, 12);

        assert_eq!(select_peer_route(&node, &stale).unwrap(), authenticated);
    }

    #[test]
    fn collision_persist_failpoint_rolls_back_session_and_pending_ciphertexts() {
        let (mut node, _, remote, first_move, _) = collision_fixture(true);
        let before_send = node.sessions[&remote.identity_pk].send_ctr();
        let before_cells = node.pending_1to1[&[1; 16]].delivery.cells.clone();
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let captured = snapshots.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Err("collision boundary failpoint".into())
        }));

        let error = match accept_first_move(&mut node, &first_move) {
            Ok(_) => panic!("collision persistence unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error, "collision boundary failpoint");
        assert_eq!(node.sessions[&remote.identity_pk].send_ctr(), before_send);
        assert_eq!(node.pending_1to1[&[1; 16]].delivery.cells, before_cells);
        assert!(matches!(
            node.session_states[&remote.identity_pk],
            DirectSessionState::InitiatedUnconfirmed { .. }
        ));
        let durable = decode_v2(&snapshots.lock().unwrap()[0], &[0xA5; 32]).unwrap();
        assert!(matches!(
            durable.sessions[0].2,
            ArchivedSessionState::Established
        ));
        assert!(durable
            .pending_direct
            .iter()
            .all(
                |(_, delivery, logical, _, _, _, _)| delivery.cells.len() == 1 && logical.is_some()
            ));
    }

    #[tokio::test]
    async fn restarted_unconfirmed_loser_converges_from_persisted_logical_records() {
        let (node, remote_identity, remote, _, _) = collision_fixture(true);
        let encoded = encode_state(&node).unwrap();
        let restored = Arc::new(Mutex::new(state()));
        let scheduler = restored.lock().unwrap().scheduler.clone();
        decode_state_at_startup(&restored, &scheduler, &encoded)
            .await
            .unwrap();
        let mut restored = restored.lock().unwrap();
        let restored_bundle = Bundle::decode(&restored.info.bundle).unwrap();
        let (first_move, mut winning_session) = gcoms_crypto::initiate_authenticated(
            &remote_identity,
            &restored.info.identity_pk,
            &restored_bundle,
            &remote.public().encode(),
        )
        .unwrap();

        let accepted = accept_first_move(&mut restored, &first_move).unwrap();

        assert_eq!(accepted.peer_pk, remote.identity_pk);
        assert_eq!(accepted.rewritten.len(), 3);
        for delivery in accepted.rewritten {
            let Some(NodePayload::Frame(_, frame)) = decode_payload(&delivery.cells[0]) else {
                panic!("rewritten delivery is not a direct frame");
            };
            winning_session.receive(&frame).unwrap();
        }
        assert_eq!(winning_session.recv_ctr(), 3);
    }

    #[test]
    fn expired_unconfirmed_session_and_pending_records_are_removed_durably() {
        let (mut node, _, remote, _, _) = collision_fixture(true);
        node.session_states.insert(
            remote.identity_pk.clone(),
            DirectSessionState::InitiatedUnconfirmed {
                expires: std::time::Instant::now() - std::time::Duration::from_secs(1),
            },
        );
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let captured = snapshots.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Ok(())
        }));

        cleanup_expired_unconfirmed(&mut node, std::time::Instant::now()).unwrap();

        assert!(!node.sessions.contains_key(&remote.identity_pk));
        assert!(!node.session_states.contains_key(&remote.identity_pk));
        assert!(node.pending_1to1.is_empty());
        let durable = decode_v2(&snapshots.lock().unwrap()[0], &[0xA5; 32]).unwrap();
        assert!(durable.sessions.is_empty());
        assert!(durable.pending_direct.is_empty());
    }

    fn channel_member_fixture(
        channel_name: &str,
    ) -> (
        NodeState,
        gcoms_mls::OwnerSession,
        crate::channel::ChannelRoute,
    ) {
        let mut owner = gcoms_mls::OwnerSession::create(
            gcoms_crypto::IdentityKeypair::from_seed([0xC1; 32]),
            "owner",
            8,
        )
        .unwrap();
        let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
        let key_package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let invite =
            owner.sign_invite_key_package(&key_package, "member", gcoms_mls::Caps::member(), 3600);
        let admission = owner.admit(&invite, &key_package).unwrap();
        let member = gcoms_mls::ChannelMember::join(prepared, &admission.welcome).unwrap();
        let owner_route = route(31, owner.own_pseudonym());
        let owned = owned_channel_route(
            32,
            member.own_pseudonym(),
            channel_direct_secret(&TEST_SEED, &member.own_pseudonym()),
        );
        let member_route = owned.public.clone();
        let mut channel = ChannelState::new(
            ChannelRole::Member(member),
            owned,
            17,
            channel_name.into(),
            crate::channel::ChannelVisibility::Private,
        );
        channel.directory.insert("member".into(), member_route);
        let mut node = state();
        node.channels.insert(channel_name.into(), channel);
        (node, owner, owner_route)
    }

    #[tokio::test]
    async fn channel_presence_rolls_back_mls_state_when_durable_commit_fails() {
        let (mut node, mut owner, _) = channel_member_fixture("presence");
        node.channel_presence_opt_in.insert("presence".into());
        let sequence = node.next_direct_sequence;
        node.durable_state_sink = Some(Arc::new(|_| Err("injected sink failure".into())));
        let state = Arc::new(Mutex::new(node));
        let scheduler = state.lock().unwrap().scheduler.clone();

        let error = send_channel_presence(&state, &scheduler, "presence", PresenceMode::Away, 60)
            .await
            .expect_err("presence send must fail closed");

        assert!(error.contains("injected sink failure"));
        assert_eq!(state.lock().unwrap().next_direct_sequence, sequence);
        let wire = state
            .lock()
            .unwrap()
            .channels
            .get_mut("presence")
            .unwrap()
            .role
            .send(b"after rollback")
            .unwrap();
        assert!(matches!(
            owner.receive_outcome(&wire).unwrap(),
            gcoms_mls::ReceiveOutcome::Application { payload, .. } if payload == b"after rollback"
        ));
    }

    #[tokio::test]
    async fn channel_removal_rolls_back_before_send_when_durable_commit_fails() {
        // The owner identity of a channel on this node is derived from the
        // node seed and the channel name; rollback restores it from there.
        let mut owner = gcoms_mls::OwnerSession::create(
            gcoms_crypto::IdentityKeypair::from_seed(channel_seed_from(
                &TEST_SEED,
                "removal-rollback",
            )),
            "owner",
            8,
        )
        .unwrap();
        let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
        let key_package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let member_id = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
        let invite =
            owner.sign_invite_key_package(&key_package, "member", gcoms_mls::Caps::member(), 3600);
        let admission = owner.admit(&invite, &key_package).unwrap();
        let mut member = gcoms_mls::ChannelMember::join(prepared, &admission.welcome).unwrap();
        let initial_epoch = owner.epoch();
        let owner_route = route(41, owner.own_pseudonym());
        let member_route = route(42, member_id);
        let mut channel = ChannelState::new(
            ChannelRole::Owner(owner),
            crate::channel::OwnedChannelRoute {
                public: owner_route.clone(),
                direct_secret: [9; 32],
                aliases: Vec::new(),
            },
            19,
            "removal-rollback".into(),
            crate::channel::ChannelVisibility::Private,
        );
        channel.directory.insert("owner".into(), owner_route);
        channel.directory.insert("member".into(), member_route);
        let mut node = state();
        node.channels.insert("removal-rollback".into(), channel);
        node.durable_state_sink = Some(Arc::new(|_| Err("injected sink failure".into())));
        let state = Arc::new(Mutex::new(node));
        let scheduler = state.lock().unwrap().scheduler.clone();
        let (events, _) = broadcast::channel(4);

        let error =
            remove_channel_member(&state, &scheduler, "removal-rollback", member_id, &events)
                .await
                .expect_err("removal must fail closed");

        assert!(error.contains("injected sink failure"));
        let wire = {
            let mut state = state.lock().unwrap();
            let channel = state.channels.get_mut("removal-rollback").unwrap();
            assert_eq!(channel.role.epoch(), initial_epoch);
            assert!(channel.membership_outbox.is_none());
            assert!(channel.completed_removals.is_empty());
            assert_eq!(channel.directory["member"].pseudonym, member_id);
            channel.role.send(b"after rollback").unwrap()
        };
        assert!(matches!(
            member.receive_outcome(&wire).unwrap(),
            gcoms_mls::ReceiveOutcome::Application { payload, .. } if payload == b"after rollback"
        ));
    }

    #[tokio::test]
    async fn oversized_payloads_do_not_mutate_sessions_channels_or_outboxes() {
        let oversized = vec![0x5A; gcoms_core::APPLICATION_PAYLOAD_LIMIT + 1];

        let direct_state = Arc::new(Mutex::new(state()));
        let direct_scheduler = direct_state.lock().unwrap().scheduler.clone();
        assert!(
            send_1to1(&direct_state, &direct_scheduler, &peer(9), &oversized, None,)
                .await
                .is_err()
        );
        // This passes the general application ceiling but cannot fit a direct
        // ML-KEM rekey frame once the full ML-DSA identity is included.
        let pq_oversized = vec![0x5A; gcoms_core::APPLICATION_PAYLOAD_LIMIT];
        let error = send_1to1(
            &direct_state,
            &direct_scheduler,
            &peer(9),
            &pq_oversized,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.contains("PQ-safe limit"));
        {
            let direct = direct_state.lock().unwrap();
            assert!(direct.sessions.is_empty());
            assert!(direct.peer_routes.is_empty());
            assert!(direct.pending_1to1.is_empty());
        }

        let (channel_state, _, _) = channel_member_fixture("payload-bound");
        let channel_state = Arc::new(Mutex::new(channel_state));
        let channel_scheduler = channel_state.lock().unwrap().scheduler.clone();
        let initial_epoch = channel_state.lock().unwrap().channels["payload-bound"]
            .role
            .epoch();

        assert!(send_channel_text(
            &channel_state,
            &channel_scheduler,
            "payload-bound",
            &oversized,
        )
        .await
        .is_err());
        assert!(send_channel_direct(
            &channel_state,
            &channel_scheduler,
            "payload-bound",
            [0xEE; 32],
            &oversized,
        )
        .await
        .is_err());

        let state = channel_state.lock().unwrap();
        let channel = &state.channels["payload-bound"];
        assert_eq!(channel.role.epoch(), initial_epoch);
        assert!(channel.pending.is_empty());
        assert!(channel.cell_cache.is_empty());
        assert!(channel.message_outbox.is_empty());
        assert!(state.pending_channel_direct.is_empty());
        assert!(state.last_channel_send.is_none());
    }

    #[test]
    fn payload_limit_fits_the_channel_cell_envelope() {
        let (_, mut owner, _) = channel_member_fixture("payload-boundary");
        let body = vec![0xA5; gcoms_core::APPLICATION_PAYLOAD_LIMIT];
        validate_application_payload(&body).unwrap();
        let wire = owner
            .send(&crate::channel::encode_text(&body, false))
            .unwrap();
        let cell = Cell::new(
            CellType::Msg,
            0,
            0,
            crate::proto::encode_chan("payload-boundary", &wire),
        );
        cell.encode_auto().expect("payload limit must fit a cell");
    }

    #[tokio::test]
    async fn routed_channel_archive_retains_founder_and_joiner_direct_keys() {
        let name = "retained-direct-key";
        for channel_scoped in [true, false] {
            let mut node = state();
            let scoped_seed = channel_seed_from(&TEST_SEED, name);
            let owner = gcoms_mls::OwnerSession::create(
                IdentityKeypair::from_seed(scoped_seed),
                "owner",
                8,
            )
            .unwrap();
            let pseudonym = owner.own_pseudonym();
            let direct_secret = channel_direct_secret(
                if channel_scoped {
                    &scoped_seed
                } else {
                    &TEST_SEED
                },
                &pseudonym,
            );
            let aliases = node.client_relay.aliases.clone();
            let public = crate::channel::ChannelRoute {
                pseudonym,
                direct_public: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                    direct_secret,
                ))
                .to_bytes(),
                data: aliases[0].contact.clone(),
                control: aliases[1].contact.clone(),
            };
            let mut channel = ChannelState::new(
                ChannelRole::Owner(owner),
                crate::channel::OwnedChannelRoute {
                    public: public.clone(),
                    direct_secret,
                    aliases,
                },
                17,
                name.into(),
                crate::channel::ChannelVisibility::Private,
            );
            channel.directory.insert("owner".into(), public.clone());
            node.channels.insert(name.into(), channel);
            node.routing = Some(
                routing::RoutingRuntime::new(
                    RoutingConfig::default(),
                    gcoms_routing::Directory::new(),
                    true,
                )
                .unwrap(),
            );
            let bytes = encode_state(&node).unwrap();
            assert_eq!(&bytes[..6], MAGIC_V19);
            let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
            let restored = &archive.channel_routes[name];
            assert_eq!(restored.public, public);
            assert_eq!(restored.direct_secret, direct_secret);
            // The same retained public key in a v1..v15 directory must select
            // the identical key while its old unarchived queues are recovered.
            let pending =
                routing::pending_channel_route(&TEST_SEED, name, pseudonym, Some(public.clone()))
                    .unwrap();
            assert_eq!(pending.direct_secret, direct_secret);
            assert!(pending.aliases.is_empty());

            node.channels
                .get_mut(name)
                .unwrap()
                .own_route
                .public
                .direct_public = [0xA5; 32];
            assert!(encode_state(&node).is_err());
            node.channels
                .get_mut(name)
                .unwrap()
                .own_route
                .public
                .direct_public = public.direct_public;
            let prior = node.channels[name].own_route.aliases[0].clone();
            let expiry = prior.contact.expiry + 120;
            let saved = Arc::new(Mutex::new(Vec::new()));
            let capture = saved.clone();
            node.durable_state_sink = Some(Arc::new(move |bytes| {
                let archive = decode_v2(&bytes, &TEST_SEED)?;
                capture
                    .lock()
                    .unwrap()
                    .push(archive.channel_routes[name].public.data.expiry);
                Ok(())
            }));
            let announcement = super::super::ticks::apply_accepted_channel_renewal(
                &mut node, name, 0, &prior, expiry,
            )
            .unwrap()
            .unwrap();
            assert_eq!(*saved.lock().unwrap(), [expiry]);
            assert_eq!(node.channels[name].own_route.direct_secret, direct_secret);
            assert_eq!(
                node.channels[name].own_route.public.data.queue_id,
                prior.contact.queue_id
            );
            assert_eq!(node.channels[name].pending[0].wire, announcement);
            assert!(super::super::ticks::apply_accepted_channel_renewal(
                &mut node,
                name,
                0,
                &prior,
                expiry + 60
            )
            .unwrap()
            .is_none());
            let prior = node.channels[name].own_route.aliases[0].clone();
            node.durable_state_sink =
                Some(Arc::new(|_| Err("channel renewal sink failpoint".into())));
            assert!(super::super::ticks::apply_accepted_channel_renewal(
                &mut node,
                name,
                0,
                &prior,
                expiry + 60
            )
            .is_err());
            assert!(node.owner_transition_failed);
            assert!(encode_state(&node).is_err());
            assert!(matches!(
                node.scheduler.subscribe(prior),
                Err(crate::scheduler::EnqueueError::Shutdown)
            ));
        }
    }

    #[tokio::test]
    async fn authenticated_channel_replacement_preserves_retry_wires_and_acknowledgements() {
        for batch in [false, true] {
            let name = "route-replacement";
            let (mut node, mut owner, old_route) = channel_member_fixture(name);
            let (events, _) = broadcast::channel(8);
            let dir = owner
                .send(&crate::channel::encode_dir("owner", &old_route))
                .unwrap();
            process_chan_cell(&mut node, name, dir, std::time::Instant::now(), &events);
            let old_peer = crate::channel::PeerRef::from_route(&old_route);
            let other_route = route(46, [0xEE; 32]);
            let commit_id = crate::channel::msg_id(name, b"exact retained commit");
            let separate_id = crate::channel::msg_id(name, b"separate retained wire");
            let (message_id, text, ack, epoch) = {
                let cs = node.channels.get_mut(name).unwrap();
                let text = cs
                    .role
                    .send(&crate::channel::encode_text(b"retained", false))
                    .unwrap();
                let message_id = crate::channel::msg_id(name, &text);
                let ack = cs
                    .role
                    .send(&crate::channel::encode_text_ack(message_id, false))
                    .unwrap();
                let expected = HashMap::from([
                    (old_route.pseudonym, old_route.clone()),
                    (other_route.pseudonym, other_route.clone()),
                ]);
                let acknowledged = HashSet::from([other_route.pseudonym]);
                cs.message_outbox.insert(
                    message_id,
                    crate::channel::ChannelMessageOutbox {
                        wire: text.clone(),
                        expected: expected.clone(),
                        acknowledged: acknowledged.clone(),
                    },
                );
                // A route update must never enroll this member in an older
                // message whose original recipient set did not include it.
                cs.message_outbox.insert(
                    separate_id,
                    crate::channel::ChannelMessageOutbox {
                        wire: b"separate retained wire".to_vec(),
                        expected: HashMap::from([(other_route.pseudonym, other_route.clone())]),
                        acknowledged: HashSet::new(),
                    },
                );
                cs.membership_outbox = Some(crate::channel::MembershipOutbox {
                    commit_id,
                    epoch: cs.role.epoch(),
                    commit: b"exact retained commit".to_vec(),
                    expected,
                    acknowledged,
                });
                cs.pending_control
                    .push_back((old_route.clone(), ack.clone()));
                cs.cache_ack(message_id, old_route.clone(), ack.clone());
                cs.queue_pull(old_peer.clone(), message_id, text.clone());
                cs.note(message_id, text.clone());
                cs.enqueue_forward(message_id, text.clone());
                for _ in 0..3 {
                    cs.settle_forward(message_id, false);
                }
                (message_id, text, ack, cs.role.epoch())
            };
            let mut replacement = route(45, old_route.pseudonym);
            replacement.direct_public = old_route.direct_public;
            let inner = if batch {
                crate::channel::encode_dir_batch(&[("owner".into(), replacement.clone())]).unwrap()
            } else {
                crate::channel::encode_dir("owner", &replacement)
            };
            let dir = owner.send(&inner).unwrap();
            process_chan_cell(&mut node, name, dir, std::time::Instant::now(), &events);
            let cs = node.channels.get_mut(name).unwrap();
            cs.learn_ref(&old_peer);
            cs.learn(&old_route);
            assert_eq!(
                cs.resolve(&old_peer.id),
                Some(crate::channel::PeerRef::from_route(&replacement))
            );
            assert_eq!(cs.directory["owner"], replacement);
            assert_eq!(
                cs.message_outbox[&message_id].expected[&old_route.pseudonym],
                replacement
            );
            assert_eq!(cs.message_outbox[&message_id].wire, text);
            assert_eq!(
                cs.message_outbox[&message_id].acknowledged,
                HashSet::from([other_route.pseudonym])
            );
            assert_eq!(
                cs.message_outbox[&separate_id].expected,
                HashMap::from([(other_route.pseudonym, other_route.clone())])
            );
            let membership = cs.membership_outbox.as_ref().unwrap();
            assert_eq!(membership.expected[&old_route.pseudonym], replacement);
            assert_eq!(membership.commit, b"exact retained commit");
            assert_eq!(membership.commit_id, commit_id);
            assert_eq!(membership.epoch, epoch);
            assert_eq!(
                membership.acknowledged,
                HashSet::from([other_route.pseudonym])
            );
            assert_eq!(cs.pending_control[0], (replacement.clone(), ack.clone()));
            assert_eq!(
                cs.commit_ack_cache[&message_id],
                (replacement.clone(), ack.clone())
            );
            assert_eq!(
                cs.pull_outbox[0],
                (
                    crate::channel::PeerRef::from_route(&replacement),
                    message_id,
                    text.clone()
                )
            );
            assert_eq!(cs.pending[0].wire, text);
            assert_eq!(cs.pending[0].attempts, 3);
            assert_eq!(cs.cell_cache[&message_id], text);
            assert_eq!(cs.role.epoch(), epoch);

            // Even an MLS owner cannot give another roster name this member's
            // pseudonym; rejected directory data must leave all routes intact.
            let invalid = owner
                .send(&crate::channel::encode_dir("member", &old_route))
                .unwrap();
            process_chan_cell(&mut node, name, invalid, std::time::Instant::now(), &events);
            assert_eq!(node.channels[name].directory["owner"], replacement);
            let archive = decode_v2(&encode_state(&node).unwrap(), &TEST_SEED).unwrap();
            let restored = &archive.channels[0];
            let outbox = restored
                .message_outbox
                .iter()
                .find(|(id, _)| id == &message_id)
                .unwrap();
            assert_eq!(outbox.1.wire, text);
            assert_eq!(outbox.1.expected[&old_route.pseudonym], replacement);
            assert_eq!(restored.commit_acks[0].1, replacement);
            assert_eq!(restored.commit_acks[0].2, ack);
        }
    }

    #[tokio::test]
    async fn text_before_authenticated_dir_retains_and_promotes_exact_ack() {
        let channel_name = "text-before-dir";
        let (mut node, mut owner, owner_route) = channel_member_fixture(channel_name);
        let text_wire = owner
            .send(&crate::channel::encode_text(b"race", false))
            .unwrap();
        let original_id = crate::channel::msg_id(channel_name, &text_wire);
        let key = crate::channel::UnroutedAckKey {
            original_id,
            sender_pseudonym: owner_route.pseudonym,
        };
        let (events, mut receiver) = broadcast::channel(8);

        process_chan_cell(
            &mut node,
            channel_name,
            text_wire.clone(),
            std::time::Instant::now(),
            &events,
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(Ev::ChannelMessage { msg_id, .. }) if msg_id == original_id
        ));
        let exact_wire = node.channels[channel_name].unrouted_ack_journal[&key].clone();

        process_chan_cell(
            &mut node,
            channel_name,
            text_wire,
            std::time::Instant::now(),
            &events,
        );
        assert_eq!(
            node.channels[channel_name].unrouted_ack_journal[&key],
            exact_wire
        );
        assert!(receiver.try_recv().is_err(), "duplicate emitted an event");

        let pex_route = crate::channel::PeerRef::from_route(&owner_route);
        node.channels
            .get_mut(channel_name)
            .unwrap()
            .learn_ref(&pex_route);
        assert!(node.channels[channel_name].resolve(&pex_route.id).is_none());
        assert!(node.channels[channel_name]
            .unrouted_ack_journal
            .contains_key(&key));

        let crash_archive = encode_state(&node).unwrap();
        let restored = decode_v2(&crash_archive, &TEST_SEED).unwrap();
        assert_eq!(restored.channels[0].unrouted_acks[0].0, key);
        assert_eq!(restored.channels[0].unrouted_acks[0].1, exact_wire);

        let dir_wire = owner
            .send(&crate::channel::encode_dir("owner", &owner_route))
            .unwrap();
        process_chan_cell(
            &mut node,
            channel_name,
            dir_wire,
            std::time::Instant::now(),
            &events,
        );
        let channel = &node.channels[channel_name];
        assert!(channel.unrouted_ack_journal.is_empty());
        assert_eq!(channel.pending_control.len(), 1);
        assert_eq!(channel.pending_control[0].1, exact_wire);
        assert_eq!(channel.commit_ack_cache[&original_id].1, exact_wire);
        assert!(
            receiver.try_recv().is_err(),
            "route promotion emitted delivery"
        );
    }

    #[tokio::test]
    async fn commit_before_authenticated_dir_retains_and_promotes_exact_ack() {
        let channel_name = "commit-before-dir";
        let (mut node, mut owner, owner_route) = channel_member_fixture(channel_name);
        let newcomer = gcoms_mls::ChannelMember::prepare("newcomer").unwrap();
        let key_package = gcoms_mls::ChannelMember::key_package_bytes(&newcomer).unwrap();
        let invite = owner.sign_invite_key_package(
            &key_package,
            "newcomer",
            gcoms_mls::Caps::member(),
            3600,
        );
        let admission = owner.admit(&invite, &key_package).unwrap();
        let original_id = crate::channel::msg_id(channel_name, &admission.commit);
        let key = crate::channel::UnroutedAckKey {
            original_id,
            sender_pseudonym: owner_route.pseudonym,
        };
        let (events, mut receiver) = broadcast::channel(8);

        process_chan_cell(
            &mut node,
            channel_name,
            admission.commit.clone(),
            std::time::Instant::now(),
            &events,
        );
        let exact_wire = node.channels[channel_name].unrouted_ack_journal[&key].clone();
        process_chan_cell(
            &mut node,
            channel_name,
            admission.commit,
            std::time::Instant::now(),
            &events,
        );
        assert_eq!(
            node.channels[channel_name].unrouted_ack_journal[&key],
            exact_wire
        );

        let dir_wire = owner
            .send(&crate::channel::encode_dir("owner", &owner_route))
            .unwrap();
        process_chan_cell(
            &mut node,
            channel_name,
            dir_wire,
            std::time::Instant::now(),
            &events,
        );
        let channel = &node.channels[channel_name];
        assert!(channel.unrouted_ack_journal.is_empty());
        assert_eq!(channel.pending_control[0].1, exact_wire);
        assert_eq!(channel.commit_ack_cache[&original_id].1, exact_wire);
        // Membership commits now notify projections. The ACK must still never
        // masquerade as application delivery.
        let event = receiver
            .try_recv()
            .expect("membership commit notifies roster");
        assert!(matches!(event, Ev::ChannelRosterChanged { .. }));
        assert!(
            receiver.try_recv().is_err(),
            "commit ACK emitted extra event"
        );
    }

    #[test]
    fn v2_roundtrips_outstanding_journals_exactly() {
        let mut state = state();
        let message_id = [0x11; 16];
        let pending = delivery(8);
        state
            .peer_routes
            .insert(pending.peer.identity_pk.clone(), pending.peer.clone());
        let instant = std::time::Instant::now();
        state.pending_1to1.insert(
            message_id,
            PendingDirect {
                delivery: pending.clone(),
                logical_record: Some(b"logical direct record".to_vec()),
                sequence: 7,
                next_attempt: instant + std::time::Duration::from_millis(2_500),
                expires: instant + std::time::Duration::from_millis(50_000),
                application_event: true,
            },
        );
        state.next_direct_sequence = 8;
        state.direct_ack_outbox.push_back(delivery(9));
        let processed_key = (vec![8; 32], 17);
        state
            .processed_direct_order
            .push_back(processed_key.clone());
        state.processed_direct.insert(
            processed_key,
            ProcessedDirect {
                frame_hash: [0x22; 32],
                delivery: delivery(10),
            },
        );

        let mut owner = gcoms_mls::OwnerSession::create(
            gcoms_crypto::IdentityKeypair::from_seed(channel_seed_from(&TEST_SEED, "journal")),
            "owner",
            8,
        )
        .unwrap();
        let prepared_recipient = gcoms_mls::ChannelMember::prepare("recipient").unwrap();
        let recipient_key_package =
            gcoms_mls::ChannelMember::key_package_bytes(&prepared_recipient).unwrap();
        let recipient_pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared_recipient);
        let invite = owner.sign_invite_key_package(
            &recipient_key_package,
            "recipient",
            gcoms_mls::Caps::member(),
            3600,
        );
        owner.admit(&invite, &recipient_key_package).unwrap();
        let own_pseudonym = owner.own_pseudonym();
        let owned = owned_channel_route(
            2,
            own_pseudonym,
            channel_direct_secret(&channel_seed_from(&TEST_SEED, "journal"), &own_pseudonym),
        );
        let own_route = owned.public.clone();
        let mut channel = ChannelState::new(
            ChannelRole::Owner(owner),
            owned,
            7,
            "journal".into(),
            crate::channel::ChannelVisibility::Private,
        );
        channel.directory.insert("owner".into(), own_route);
        let recipient = route(3, recipient_pseudonym);
        let second_recipient = route(4, [0x45; 32]);
        let expected = HashMap::from([
            (recipient.pseudonym, recipient.clone()),
            (second_recipient.pseudonym, second_recipient),
        ]);
        let acknowledged = std::collections::HashSet::from([recipient.pseudonym]);
        let channel_wire = b"exact channel ciphertext".to_vec();
        let channel_id = crate::channel::msg_id("journal", &channel_wire);
        channel.message_outbox.insert(
            channel_id,
            ChannelMessageOutbox {
                wire: channel_wire.clone(),
                expected: expected.clone(),
                acknowledged: acknowledged.clone(),
            },
        );
        let commit = b"exact membership commit".to_vec();
        let commit_id = crate::channel::msg_id("journal", &commit);
        channel.membership_outbox = Some(MembershipOutbox {
            commit_id,
            epoch: 7,
            commit: commit.clone(),
            expected,
            acknowledged: acknowledged.clone(),
        });
        channel
            .pending_control
            .push_back((recipient.clone(), b"pending ACK wire".to_vec()));
        channel.admission_cache_order.push_back([0x55; 32]);
        channel.admission_cache.insert(
            [0x55; 32],
            CachedAdmission {
                name: "invitee".into(),
                pseudonym: recipient.pseudonym,
                welcome: b"cached Welcome".to_vec(),
            },
        );
        // A live (unconsumed) and a spent (consumed) invite, to prove single-use
        // survives the archive round-trip.
        channel.invite_order.push_back([0x71; 16]);
        channel.invites.insert(
            [0x71; 16],
            crate::channel::InviteRecord {
                secret: [0x72; 32],
                expiry: 1_900_000_000,
                consumed: None,
            },
        );
        channel.invite_order.push_back([0x73; 16]);
        channel.invites.insert(
            [0x73; 16],
            crate::channel::InviteRecord {
                secret: [0x74; 32],
                expiry: 1_900_000_100,
                consumed: Some(recipient.pseudonym),
            },
        );
        let completed_legacy_name = completed_legacy_removal_key("removed");
        channel
            .completed_removals
            .insert(completed_legacy_name.clone());
        let completed_member_id = completed_member_removal_key(&recipient.pseudonym);
        channel
            .completed_removals
            .insert(completed_member_id.clone());
        channel.commit_ack_order.push_back([0x66; 16]);
        channel
            .commit_ack_cache
            .insert([0x66; 16], (recipient.clone(), b"replay ACK wire".to_vec()));
        let unrouted_key = crate::channel::UnroutedAckKey {
            original_id: [0x67; 16],
            sender_pseudonym: recipient.pseudonym,
        };
        channel.unrouted_ack_order.push_back(unrouted_key);
        channel
            .unrouted_ack_journal
            .insert(unrouted_key, b"unrouted exact ACK wire".to_vec());
        channel.visibility = crate::channel::ChannelVisibility::Public;
        state.channels.insert("journal".into(), channel);
        state.local_contact_generation = 23;
        state
            .peer_route_generations
            .insert(pending.peer.identity_pk.clone(), 11);
        state
            .direct_presence_opt_in
            .insert(pending.peer.identity_pk.clone());
        state.channel_presence_opt_in.insert("journal".into());

        let encoded = encode_state(&state).unwrap();
        assert_eq!(&encoded[..6], MAGIC_V19);
        let archive = decode_v2(&encoded, &TEST_SEED).unwrap();
        assert_eq!(archive.peer_routes[0].1, pending.peer);
        assert_eq!(archive.peer_routes[0].2, 11);
        assert_eq!(archive.local_contact_generation, 23);
        assert!(archive
            .direct_presence_opt_in
            .contains(&pending.peer.identity_pk));
        assert!(archive.channel_presence_opt_in.contains("journal"));
        assert_eq!(archive.pending_direct[0].0, message_id);
        assert_eq!(archive.pending_direct[0].1.cells, pending.cells);
        assert!(archive.pending_direct[0].1.relay.aliases.is_empty());
        assert_eq!(
            archive.pending_direct[0].2.as_deref(),
            Some(&b"logical direct record"[..])
        );
        assert_eq!(archive.pending_direct[0].3, 7);
        assert!(archive.pending_direct[0].4 <= 2_500);
        assert!(archive.pending_direct[0].5 <= 50_000);
        assert!(archive.pending_direct[0].6);
        assert_eq!(archive.direct_acks.len(), 1);
        assert_eq!(archive.processed_direct[0].1.frame_hash, [0x22; 32]);
        let restored = &archive.channels[0];
        assert_eq!(
            restored.visibility,
            crate::channel::ChannelVisibility::Public
        );
        assert_eq!(restored.own_name.as_deref(), Some("owner"));
        assert!(restored.directory.is_empty());
        assert_eq!(restored.message_outbox[0].1.wire, channel_wire);
        assert_eq!(restored.message_outbox[0].1.expected.len(), 2);
        assert_eq!(restored.message_outbox[0].1.acknowledged, acknowledged);
        let membership = restored.membership_outbox.as_ref().unwrap();
        assert_eq!(membership.commit, commit);
        assert_eq!(membership.epoch, 7);
        assert_eq!(membership.acknowledged, acknowledged);
        assert_eq!(restored.pending_control[0].1, b"pending ACK wire");
        assert_eq!(restored.admissions[0].1.welcome, b"cached Welcome");
        // Invite ledger survives, preserving order and the consumed flag.
        assert_eq!(restored.invites.len(), 2);
        assert_eq!(restored.invites[0].0, [0x71; 16]);
        assert_eq!(restored.invites[0].1.secret, [0x72; 32]);
        assert_eq!(restored.invites[0].1.consumed, None);
        assert_eq!(restored.invites[1].0, [0x73; 16]);
        assert_eq!(restored.invites[1].1.consumed, Some(recipient.pseudonym));
        assert!(restored.completed_removals.contains(&completed_legacy_name));
        assert!(restored.completed_removals.contains(&completed_member_id));
        assert_eq!(restored.commit_acks[0].2, b"replay ACK wire");
        assert_eq!(restored.unrouted_acks[0].0, unrouted_key);
        assert_eq!(restored.unrouted_acks[0].1, b"unrouted exact ACK wire");
        // NOTE: this test previously also relabelled the encoded body to v7 and
        // asserted the typed-removal-key downgrade. The v10 invite ledger adds a
        // per-channel trailing field, so a simple truncate-and-relabel can no
        // longer synthesise a byte-faithful v7 body from a v10 encode. The
        // downgrade logic itself is unchanged (see `completed_legacy_removal_key`
        // and the `has_typed_removals` gate); dedicated cross-version coverage
        // for it should be rebuilt from a hand-written v7 fixture rather than by
        // byte surgery on the current encoder.
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn v1_archive_with_historical_node_info_directory_remains_importable() {
        let handle = start(NodeConfig {
            seed: [0x91; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: crate::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        })
        .await
        .unwrap();
        handle
            .create_channel(
                "legacy",
                "owner",
                8,
                crate::channel::ChannelVisibility::Private,
            )
            .await
            .unwrap();
        let current = handle.export_state().await.unwrap();
        let archive = decode_v2(&current, &[0x91; 32]).unwrap();
        let archived = &archive.channels[0];
        let archive_key = channel_archive_key(&[0x91; 32]);
        let (kind, mut role) = match &archived.role {
            ChannelRole::Owner(owner) => (ROLE_OWNER, owner.persist(&archive_key).unwrap()),
            ChannelRole::Member(member) => (ROLE_MEMBER, member.persist(&archive_key).unwrap()),
        };
        let mut old = MAGIC_V1.to_vec();
        old.extend_from_slice(&0u32.to_be_bytes());
        old.extend_from_slice(&1u32.to_be_bytes());
        old.extend_from_slice(&6u16.to_be_bytes());
        old.extend_from_slice(b"legacy");
        old.push(kind);
        old.extend_from_slice(&(role.len() as u32).to_be_bytes());
        old.extend_from_slice(&role);
        role.fill(0);
        old.extend_from_slice(&1u32.to_be_bytes());
        old.extend_from_slice(&5u16.to_be_bytes());
        old.extend_from_slice(b"owner");
        let historical_info = handle.info.encode();
        old.extend_from_slice(&(historical_info.len() as u32).to_be_bytes());
        old.extend_from_slice(&historical_info);

        handle.import_state(&old).await.unwrap();
        let channels = handle.list_channels().await.unwrap();
        assert!(channels.iter().any(|channel| channel.channel == "legacy"));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn crash_cut_restores_pending_without_completing_it() {
        let mut before = state();
        let instant = std::time::Instant::now();
        before.pending_1to1.insert(
            [0x77; 16],
            PendingDirect {
                delivery: delivery(12),
                logical_record: Some(b"recoverable".to_vec()),
                sequence: 1,
                next_attempt: instant + std::time::Duration::from_secs(3),
                expires: instant + std::time::Duration::from_secs(600),
                application_event: true,
            },
        );
        before.next_direct_sequence = 2;
        let encoded = encode_state(&before).unwrap();
        let restored = Arc::new(Mutex::new(state()));
        let scheduler = RelayScheduler::new(Arc::new(Tp1Client::new().unwrap()));
        decode_state_at_startup(&restored, &scheduler, &encoded)
            .await
            .unwrap();
        let restored = restored.lock().unwrap();
        let pending = restored.pending_1to1.get(&[0x77; 16]).unwrap();
        assert_eq!(
            pending.delivery.cells[0],
            before.pending_1to1[&[0x77; 16]].delivery.cells[0]
        );
        assert!(pending.expires > std::time::Instant::now());
    }

    #[tokio::test]
    async fn send_failpoint_keeps_prepared_wire_off_network_and_ratchet_uncommitted() {
        let node = Arc::new(Mutex::new(state()));
        let peer_identity = IdentityKeypair::from_seed([0xE1; 32]);
        let (bundle, _) = peer_identity.issue_bundle();
        let mut recipient = peer(21);
        recipient.identity_pk = peer_identity.public_bytes();
        recipient.bundle = bundle.encode();
        let fixtures = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let captured = fixtures.clone();
        node.lock().unwrap().durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Err("send boundary failpoint".into())
        }));
        let scheduler = node.lock().unwrap().scheduler.clone();

        let error = send_1to1(&node, &scheduler, &recipient, b"not eligible", None)
            .await
            .unwrap_err();
        assert_eq!(error, "send boundary failpoint");
        let node = node.lock().unwrap();
        assert!(!node.sessions.contains_key(&recipient.identity_pk));
        assert!(node.pending_1to1.is_empty());
        let fixtures = fixtures.lock().unwrap();
        let prepared = decode_v2(&fixtures[0], &TEST_SEED).unwrap();
        assert_eq!(prepared.pending_direct.len(), 1);
        assert!(matches!(prepared.sessions[0].1, ArchivedSession::Sealed(_)));
    }

    #[test]
    fn receive_failpoint_exposes_neither_ack_nor_application_event() {
        let (mut node, alice_pk, mut alice_session) = direct_fixture();
        let fixtures = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let captured = fixtures.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Err("receive boundary failpoint".into())
        }));
        let frame = alice_session
            .send(&encode_direct_data([0x31; 16], 1, false, b"hidden"))
            .unwrap();
        let before = node.sessions[&alice_pk].recv_ctr();
        let (events, mut receiver) = broadcast::channel(4);

        process_frame(&mut node, alice_pk.clone(), frame, &events);

        assert_eq!(node.sessions[&alice_pk].recv_ctr(), before);
        assert!(node.direct_ack_outbox.is_empty());
        assert!(node.processed_direct.is_empty());
        assert!(receiver.try_recv().is_err());
        let fixtures = fixtures.lock().unwrap();
        let prepared = decode_v2(&fixtures[0], &TEST_SEED).unwrap();
        assert_eq!(prepared.direct_acks.len(), 1);
        assert_eq!(prepared.processed_direct.len(), 1);
    }

    #[test]
    fn durable_receive_failure_rolls_back_application_and_transport_together() {
        let (mut node, peer, mut sender) = direct_fixture();
        node.durable_applications_enabled = true;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let captured = writes.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Err("application archive failpoint".into())
        }));
        let before = node.sessions[&peer].recv_ctr();
        let wire = sender
            .send(&crate::proto::encode_direct_durable_data(
                [0x42; 16],
                1,
                b"durable body",
            ))
            .unwrap();
        let (events, mut received) = broadcast::channel(4);
        process_frame(&mut node, peer.clone(), wire, &events);
        assert_eq!(node.sessions[&peer].recv_ctr(), before);
        assert!(node.direct_ack_outbox.is_empty());
        assert!(node.processed_direct.is_empty());
        assert_eq!(node.application_inbox.next_sequence, 1);
        assert!(node.application_inbox.entries.is_empty());
        assert!(received.try_recv().is_err());
        let candidate = decode_v2(&writes.lock().unwrap()[0], &TEST_SEED).unwrap();
        assert_eq!(candidate.direct_acks.len(), 1);
        assert_eq!(candidate.application_inbox.entries[0].body, b"durable body");
    }

    #[test]
    fn payload_cleanup_pending_and_delivery_clear_owned_bytes() {
        use zeroize::Zeroize;
        let now = std::time::Instant::now();
        let mut pending = PendingDirect {
            delivery: delivery(12),
            logical_record: Some(vec![0xa7; 4096]),
            sequence: 7,
            next_attempt: now,
            expires: now + std::time::Duration::from_secs(600),
            application_event: false,
        };
        let original_sequence = pending.sequence;
        let original_expiry = pending.expires;
        pending.zeroize();
        assert_eq!(pending.logical_record.as_ref().unwrap(), &vec![0; 4096]);
        assert_eq!(pending.sequence, original_sequence);
        assert_eq!(pending.expires, original_expiry);
        let mut cloned = pending.delivery.clone();
        assert!(cloned
            .cells
            .iter()
            .any(|cell| cell.payload.iter().any(|b| *b != 0)));
        cloned.zeroize();
        assert!(cloned
            .cells
            .iter()
            .all(|cell| cell.payload.iter().all(|b| *b == 0)));
        assert!(pending
            .delivery
            .cells
            .iter()
            .any(|cell| cell.payload.iter().any(|b| *b != 0)));
        assert_eq!(cloned.relay.hop_key, [0; 32]);
    }

    #[test]
    fn durable_receive_persists_body_before_ack_and_exact_replay_keeps_one_entry() {
        let (mut node, peer, mut sender) = direct_fixture();
        node.durable_applications_enabled = true;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let captured = writes.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Ok(())
        }));
        let wire = sender
            .send(&crate::proto::encode_direct_durable_data(
                [0x43; 16],
                1,
                b"survives daemon crash",
            ))
            .unwrap();
        let (events, mut received) = broadcast::channel(4);
        process_frame(&mut node, peer.clone(), wire.clone(), &events);
        assert!(
            received.try_recv().is_err(),
            "durable delivery must use the cursor API"
        );
        let candidate = decode_v2(&writes.lock().unwrap()[0], &TEST_SEED).unwrap();
        assert_eq!(candidate.direct_acks.len(), 1);
        assert_eq!(
            candidate.application_inbox.entries[0].body,
            b"survives daemon crash"
        );
        assert_eq!(candidate.application_inbox.next_sequence, 2);
        process_frame(&mut node, peer, wire, &events);
        assert_eq!(node.application_inbox.entries.len(), 1);
        assert_eq!(node.application_inbox.next_sequence, 2);
        assert_eq!(
            node.direct_ack_outbox.len(),
            2,
            "exact replay returns the retained ACK"
        );
    }

    #[test]
    fn durable_receive_without_storage_never_acknowledges_or_advances() {
        let (mut node, peer, mut sender) = direct_fixture();
        node.durable_applications_enabled = true;
        let before = node.sessions[&peer].recv_ctr();
        let wire = sender
            .send(&crate::proto::encode_direct_durable_data(
                [0x44; 16],
                1,
                b"requires storage",
            ))
            .unwrap();
        let (events, _) = broadcast::channel(4);
        process_frame(&mut node, peer.clone(), wire, &events);
        assert_eq!(node.sessions[&peer].recv_ctr(), before);
        assert!(node.direct_ack_outbox.is_empty());
        assert!(node.application_inbox.entries.is_empty());
    }

    #[test]
    fn durable_receive_without_managed_opt_in_never_archives_the_body() {
        let (mut node, peer, mut sender) = direct_fixture();
        node.durable_state_sink = Some(Arc::new(|_| panic!("disabled durable body was persisted")));
        let before = node.sessions[&peer].recv_ctr();
        let wire = sender
            .send(&crate::proto::encode_direct_durable_data(
                [0x44; 16],
                1,
                b"requires storage",
            ))
            .unwrap();
        let (events, _) = broadcast::channel(4);
        process_frame(&mut node, peer.clone(), wire, &events);
        assert_eq!(node.sessions[&peer].recv_ctr(), before);
        assert!(node.direct_ack_outbox.is_empty());
        assert!(node.application_inbox.entries.is_empty());
    }

    #[test]
    fn receive_ack_failpoint_keeps_outbox_and_delivery_event_uncommitted() {
        let (mut node, alice_pk, mut alice_session) = direct_fixture();
        let message_id = [0x39; 16];
        let now = std::time::Instant::now();
        let mut pending_delivery = delivery(12);
        pending_delivery.peer = node.peer_routes[&alice_pk].clone();
        node.pending_1to1.insert(
            message_id,
            PendingDirect {
                delivery: pending_delivery,
                logical_record: Some(b"pending ACK fixture".to_vec()),
                sequence: 1,
                next_attempt: now + std::time::Duration::from_secs(60),
                expires: now + std::time::Duration::from_secs(600),
                application_event: true,
            },
        );
        let fixtures = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let captured = fixtures.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Err("ACK boundary failpoint".into())
        }));
        let frame = alice_session
            .send(&encode_direct_ack(message_id, false))
            .unwrap();
        let before = node.sessions[&alice_pk].recv_ctr();
        let (events, mut receiver) = broadcast::channel(4);

        process_frame(&mut node, alice_pk.clone(), frame, &events);

        assert_eq!(node.sessions[&alice_pk].recv_ctr(), before);
        assert!(node.pending_1to1.contains_key(&message_id));
        assert!(receiver.try_recv().is_err());
        let fixtures = fixtures.lock().unwrap();
        let prepared = decode_v2(&fixtures[0], &TEST_SEED).unwrap();
        assert!(prepared.pending_direct.is_empty());
    }

    #[tokio::test]
    async fn receive_success_persists_state_and_ack_before_application_event() {
        let (mut node, alice_pk, mut alice_session) = direct_fixture();
        let fixtures = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let captured = fixtures.clone();
        let sink_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called = sink_called.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }));
        let frame = alice_session
            .send(&encode_direct_data([0x41; 16], 1, false, b"visible"))
            .unwrap();
        let before = node.sessions[&alice_pk].recv_ctr();
        let (events, mut receiver) = broadcast::channel(4);

        process_frame(&mut node, alice_pk.clone(), frame, &events);

        assert!(sink_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(node.sessions[&alice_pk].recv_ctr(), before + 1);
        assert_eq!(node.direct_ack_outbox.len(), 1);
        // Presence observation may precede the application event; drain
        // until the message arrives.
        let mut received_message = false;
        while let Ok(event) = receiver.try_recv() {
            if matches!(event, Ev::Message { ref text, .. } if text == b"visible") {
                received_message = true;
                break;
            }
        }
        assert!(received_message, "message event was not emitted");
        let fixtures = fixtures.lock().unwrap();
        let durable = decode_v2(&fixtures[0], &TEST_SEED).unwrap();
        assert_eq!(durable.direct_acks.len(), 1);
        assert_eq!(durable.processed_direct.len(), 1);
    }

    #[test]
    fn v4_session_state_is_sealed_and_bound_to_node_and_peer() {
        let (node, alice_pk, _) = direct_fixture();
        let encoded = encode_state(&node).unwrap();
        let archive = decode_v2(&encoded, &TEST_SEED).unwrap();
        let ArchivedSession::Sealed(sealed) = &archive.sessions[0].1 else {
            panic!("v4 session was not sealed");
        };
        let key = direct_session_wrapping_key(&node.identity_seed);
        let context = direct_session_context(&node, &alice_pk).unwrap();
        let restored = Session::open_state(sealed, &key, &context).unwrap();
        assert_eq!(restored.recv_ctr(), node.sessions[&alice_pk].recv_ctr());
        let wrong_context = direct_session_context(&node, b"wrong peer").unwrap();
        assert!(Session::open_state(sealed, &key, &wrong_context).is_err());
    }

    #[test]
    fn v2_rejects_truncated_and_trailing_archives() {
        let mut minimal = Vec::new();
        minimal.extend_from_slice(MAGIC_V2);
        minimal.extend_from_slice(&1u64.to_be_bytes());
        for _ in 0..6 {
            minimal.extend_from_slice(&0u32.to_be_bytes());
        }
        assert!(decode_v2(&minimal, &TEST_SEED).is_ok());
        let mut legacy_v4 = minimal.clone();
        legacy_v4[..6].copy_from_slice(MAGIC_V4);
        assert!(decode_v2(&legacy_v4, &TEST_SEED).is_ok());
        for end in 0..minimal.len() {
            assert!(
                decode_v2(&minimal[..end], &TEST_SEED).is_err(),
                "accepted cut {end}"
            );
        }
        minimal.push(0);
        assert!(decode_v2(&minimal, &TEST_SEED).is_err());
    }

    #[test]
    fn v2_rejects_oversized_counts_before_allocating() {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(MAGIC_V2);
        malformed.extend_from_slice(&1u64.to_be_bytes());
        malformed.extend_from_slice(&(MAX_SESSIONS as u32 + 1).to_be_bytes());
        assert!(decode_v2(&malformed, &TEST_SEED).is_err());
    }

    #[tokio::test]
    async fn v2_rejects_malformed_and_overbound_unrouted_ack_journals() {
        let (mut node, _owner, owner_route) = channel_member_fixture("malformed-ack");
        let key = crate::channel::UnroutedAckKey {
            original_id: [0xD7; 16],
            sender_pseudonym: owner_route.pseudonym,
        };
        let channel = node.channels.get_mut("malformed-ack").unwrap();
        channel.unrouted_ack_order.push_back(key);
        channel
            .unrouted_ack_journal
            .insert(key, b"persisted ACK".to_vec());
        let encoded = encode_state(&node).unwrap();
        let mut marker = key.original_id.to_vec();
        marker.extend_from_slice(&key.sender_pseudonym);
        let position = encoded
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("unrouted ACK marker");

        let mut unknown_sender = encoded.clone();
        unknown_sender[position + 16..position + 48].fill(0xEE);
        assert!(decode_v2(&unknown_sender, &TEST_SEED).is_err());

        let mut oversized = encoded.clone();
        oversized[position - 4..position]
            .copy_from_slice(&(crate::channel::CHANNEL_ACK_LIMIT as u32 + 1).to_be_bytes());
        assert!(decode_v2(&oversized, &TEST_SEED).is_err());

        let mut empty_wire = encoded;
        empty_wire[position + 48..position + 52].fill(0);
        assert!(decode_v2(&empty_wire, &TEST_SEED).is_err());
    }
    #[test]
    fn volatile_receive_keeps_only_ratchet_and_receipt_metadata() {
        let (mut node, peer, mut sender) = direct_fixture();
        node.durable_applications_enabled = true;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let captured = writes.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Ok(())
        }));
        let body = b"one-use-contact-must-never-be-journaled";
        let frame = sender
            .send(&crate::proto::encode_volatile_application(
                [0x43; 16], 1, body,
            ))
            .unwrap();
        let ciphertext = frame.encode();
        let (events, mut received) = broadcast::channel(4);
        process_frame(&mut node, peer.clone(), frame, &events);
        assert!(
            matches!(received.try_recv(), Ok(Ev::VolatileApplication { body: actual, .. }) if actual == body)
        );
        assert!(received.try_recv().is_err());
        assert!(node.application_inbox.entries.is_empty());
        let writes = writes.lock().unwrap();
        let candidate = decode_v2(&writes[0], &TEST_SEED).unwrap();
        assert!(candidate.application_inbox.entries.is_empty());
        assert!(candidate.pending_direct.is_empty());
        assert_eq!(candidate.direct_acks.len(), 1);
        assert_eq!(candidate.processed_direct.len(), 1);
        assert!(!writes[0].windows(body.len()).any(|w| w == body));
        assert!(!writes[0].windows(ciphertext.len()).any(|w| w == ciphertext));
    }

    #[tokio::test]
    async fn volatile_send_requires_established_session_and_omits_frame_at_commit_boundary() {
        let (mut node, peer, _) = direct_fixture();
        let recipient = node.peer_routes[&peer].clone();
        node.session_states.remove(&peer);
        let scheduler = node.scheduler.clone();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let captured = writes.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            captured.lock().unwrap().push(bytes);
            Err("volatile commit failpoint".into())
        }));
        let node = Arc::new(Mutex::new(node));
        let body = b"one-use-contact-not-in-the-outbox-snapshot";
        assert!(
            send_volatile_application(&node, &scheduler, &recipient, body)
                .await
                .unwrap_err()
                .contains("established")
        );
        assert!(writes.lock().unwrap().is_empty());
        node.lock()
            .unwrap()
            .session_states
            .insert(peer, DirectSessionState::Established);
        assert_eq!(
            send_volatile_application(&node, &scheduler, &recipient, body)
                .await
                .unwrap_err(),
            "volatile commit failpoint"
        );
        assert!(node.lock().unwrap().pending_1to1.is_empty());
        let writes = writes.lock().unwrap();
        let candidate = decode_v2(&writes[0], &TEST_SEED).unwrap();
        assert!(candidate.pending_direct.is_empty());
        assert_eq!(candidate.sessions.len(), 1);
        assert!(!writes[0].windows(body.len()).any(|w| w == body));
    }

    #[tokio::test]
    async fn restart_drops_volatile_attempts_but_preserves_regular_pending_messages() {
        let mut before = state();
        let instant = std::time::Instant::now();
        for (sequence, volatile) in [(1, false), (2, true)] {
            let id = [sequence as u8; 16];
            let body = if volatile {
                crate::proto::encode_volatile_application(id, 1, b"ephemeral")
            } else {
                encode_direct_data(id, 1, false, b"persistent")
            };
            before.pending_1to1.insert(
                id,
                PendingDirect {
                    delivery: delivery(sequence as u8),
                    logical_record: Some(body),
                    sequence,
                    next_attempt: instant + std::time::Duration::from_secs(3),
                    expires: instant + std::time::Duration::from_secs(60),
                    application_event: !volatile,
                },
            );
        }
        before.next_direct_sequence = 3;
        let encoded = encode_state(&before).unwrap();
        let restored = Arc::new(Mutex::new(state()));
        let scheduler = RelayScheduler::new(Arc::new(Tp1Client::new().unwrap()));
        decode_state_at_startup(&restored, &scheduler, &encoded)
            .await
            .unwrap();
        let restored = restored.lock().unwrap();
        assert_eq!(restored.pending_1to1.len(), 1);
        assert!(restored.pending_1to1.contains_key(&[1; 16]));
        assert!(!restored.pending_1to1.contains_key(&[2; 16]));
        assert_eq!(restored.next_direct_sequence, 3);
    }
    fn staged_pair(node: &NodeState) -> Vec<OwnedAlias> {
        [71, 91]
            .into_iter()
            .map(|byte| {
                let mut value = contact(byte);
                value.expiry = now_unix() + 3600;
                value.target = node.client_relay.aliases[0].contact.target.clone();
                valid_alias(value, byte)
            })
            .collect()
    }

    #[test]
    fn owner_saved_rotation_deadline_survives_longer_current_setting() {
        let mut node = state();
        let sealed = owner_aliases::seal_current(&node).unwrap();
        let mut record = owner_aliases::open_unbound(&sealed, &TEST_SEED).unwrap();
        record.groups[0].action_ms = record.captured_ms;
        let clock = owner_aliases::RestoreClock::new(
            record.captured_ms,
            now_ms(),
            std::time::Instant::now(),
        )
        .unwrap();
        record.apply(&mut node, clock).unwrap();
        let timing = AliasLifecycleConfig {
            alias_ttl: std::time::Duration::from_secs(7 * 86400),
            ..Default::default()
        };
        assert!(owner_aliases::rotation_due(&node, timing).unwrap());
    }

    #[tokio::test]
    async fn owner_recovery_replaces_retained_roles_without_duplicate_queues() {
        let mut node = state();
        let now = std::time::Instant::now();
        let aliases = staged_pair(&node);
        node.draining_contact_aliases.push(DrainingContactAliases {
            aliases: aliases.clone(),
            receive_until: now + std::time::Duration::from_secs(30),
            next_revoke: now + std::time::Duration::from_secs(30),
            abandon_at: now + std::time::Duration::from_secs(60),
        });
        let original =
            owner_aliases::open_unbound(&owner_aliases::seal_current(&node).unwrap(), &TEST_SEED)
                .unwrap();
        let records = Arc::new(Mutex::new(Vec::new()));
        let capture = records.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            capture.lock().unwrap().push(decode_v2(&bytes, &TEST_SEED)?);
            Ok(())
        }));
        // Routed recovery re-applies a complete retained record to a live
        // state, unlike startup's initially empty role collections.
        for _ in 0..2 {
            let record = owner_aliases::open_unbound(
                &owner_aliases::seal_current(&node).unwrap(),
                &TEST_SEED,
            )
            .unwrap();
            let clock = node.owner_clock.lock().unwrap().clone();
            super::super::aliases::owner_transition(&mut node, |st| {
                record.apply_retained(st, clock, false)
            })
            .expect("recovery must checkpoint each retained queue exactly once");
            assert!(!node.owner_transition_failed);
            assert_eq!(node.draining_contact_aliases.len(), 1);
            assert_eq!(node.draining_contact_aliases[0].aliases, aliases);
        }
        let saved = records.lock().unwrap();
        assert_eq!(saved.len(), 2);
        for archive in saved.iter() {
            let record = archive.owner_aliases.as_ref().unwrap();
            assert_eq!(record.groups.len(), original.groups.len());
            for (before, after) in original.groups.iter().zip(&record.groups) {
                assert_eq!(before.role, after.role);
                assert_eq!(before.provision, after.provision);
                assert_eq!(before.origins, after.origins);
                assert!(after.deadline_ms <= before.deadline_ms);
                assert!(after.receive_until_ms <= before.receive_until_ms);
            }
        }
        node.scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_accepted_renewal_is_durable_and_failure_rolls_back() {
        for fail in [false, true] {
            let mut node = state();
            let original = node.client_relay.clone();
            let prior = original.aliases[0].clone();
            let expiry = prior.contact.expiry + 3600;
            let wire = LeaseRenew {
                queue_id: prior.contact.queue_id,
                epoch: prior.contact.epoch,
                lease_expiry: expiry,
                nonce: [62; 16],
            }
            .encode(
                &prior.capabilities.admin,
                &prior.contact.target.relay_service_id,
            )
            .unwrap();
            let records = Arc::new(Mutex::new(Vec::new()));
            let capture = records.clone();
            node.durable_state_sink = Some(Arc::new(move |bytes| {
                capture
                    .lock()
                    .unwrap()
                    .push(decode_v2(&bytes, &TEST_SEED)?.owner_aliases.unwrap());
                if fail {
                    Err("renewal sink failpoint".into())
                } else {
                    Ok(())
                }
            }));
            assert_eq!(
                apply_accepted_owner_renewal(&mut node, &prior, expiry, &wire).is_err(),
                fail
            );
            assert_eq!(records.lock().unwrap().len(), 1);
            let record = records.lock().unwrap()[0].clone();
            assert_eq!(record.groups[0].origins[0], prior);
            assert_eq!(record.renewals[&prior.contact.queue_id], wire);
            assert!(record.groups[0].deadline_ms <= prior.contact.expiry * 1000);
            if fail {
                assert_eq!(node.client_relay, original);
                assert!(node.owner_alias_renewals.is_empty());
                assert!(node.owner_alias_origins.is_empty());
                assert!(encode_state(&node).is_err());
            } else {
                assert_eq!(node.client_relay.aliases[0].contact.expiry, expiry);
                assert_eq!(
                    node.client_relay.aliases[0].lease_create,
                    prior.lease_create
                );
                assert!(encode_state(&node).is_ok());
                assert!(apply_accepted_owner_renewal(&mut node, &prior, expiry, &wire).is_err());
            }
            node.scheduler.shutdown();
        }
    }

    #[tokio::test]
    async fn owner_zero_session_promotion_persists_full_lifecycle_before_event() {
        let mut node = state();
        let staged = staged_pair(&node);
        let expected = staged.iter().map(|a| a.contact.clone()).collect::<Vec<_>>();
        node.subscribed_contact_aliases = staged.iter().map(|a| a.contact.queue_id).collect();
        node.staged_contact_aliases = Some(staged);
        assert!(node.sessions.is_empty());
        let records = Arc::new(Mutex::new(Vec::new()));
        let capture = records.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            let archive = decode_v2(&bytes, &TEST_SEED)?;
            capture
                .lock()
                .unwrap()
                .push(archive.owner_aliases.ok_or("missing owner transaction")?);
            Ok(())
        }));
        let scheduler = node.scheduler.clone();
        let shared = Arc::new(Mutex::new(node));
        let (events, mut observed) = broadcast::channel(8);
        contact_alias_lifecycle_tick(
            &shared,
            &scheduler,
            &events,
            AliasLifecycleConfig::default(),
        )
        .await;
        let event = observed
            .try_recv()
            .expect("durable promotion must announce");
        match event {
            Ev::IdentityUpdated { info, .. } => assert_eq!(info.aliases, expected),
            _ => panic!("wrong lifecycle event"),
        }
        let records = records.lock().unwrap();
        let first = records.first().unwrap();
        assert!(first
            .groups
            .iter()
            .any(|g| g.role == owner_aliases::Role::Unannounced));
        assert!(!first
            .groups
            .iter()
            .any(|g| g.role == owner_aliases::Role::Staged));
        let final_record = records.last().unwrap();
        let draining = final_record
            .groups
            .iter()
            .find(|g| g.role == owner_aliases::Role::Draining)
            .unwrap();
        let original = first
            .groups
            .iter()
            .find(|g| g.role == owner_aliases::Role::Unannounced)
            .unwrap();
        // Conversions may consume sub-millisecond budget, never add it.
        assert!(draining.deadline_ms <= original.deadline_ms);
        assert!(draining.receive_until_ms <= original.receive_until_ms);
        assert_eq!(shared.lock().unwrap().info.aliases, expected);
        scheduler.shutdown();
    }

    #[tokio::test]
    async fn owner_failed_promotion_rolls_back_zero_session_contact_and_refuses_retry() {
        let mut node = state();
        let staged = staged_pair(&node);
        node.subscribed_contact_aliases = staged.iter().map(|a| a.contact.queue_id).collect();
        node.staged_contact_aliases = Some(staged.clone());
        let original_info = node.info.clone();
        let original_relay = node.client_relay.clone();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            let archive = decode_v2(&bytes, &TEST_SEED)?;
            assert!(archive
                .owner_aliases
                .unwrap()
                .groups
                .iter()
                .any(|g| g.role == owner_aliases::Role::Unannounced));
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("owner lifecycle sink failpoint".into())
        }));
        let scheduler = node.scheduler.clone();
        let shared = Arc::new(Mutex::new(node));
        let (events, mut observed) = broadcast::channel(8);
        for _ in 0..2 {
            contact_alias_lifecycle_tick(
                &shared,
                &scheduler,
                &events,
                AliasLifecycleConfig::default(),
            )
            .await;
        }
        assert!(observed.try_recv().is_err());
        let node = shared.lock().unwrap();
        assert_eq!(node.info, original_info);
        assert_eq!(node.client_relay, original_relay);
        assert_eq!(node.staged_contact_aliases.as_ref(), Some(&staged));
        assert!(node.unannounced_old_contact_aliases.is_none());
        assert!(node.draining_contact_aliases.is_empty());
        assert!(node.owner_transition_failed);
        assert!(encode_state(&node).is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        scheduler.shutdown();
    }

    #[test]
    fn owner_archive_v14_migration_and_v15_missing_record_refuse() {
        let node = state();
        let encoded = encode_state(&node).unwrap();
        let mut old = historical_archive(&node, HistoricalArchive::Machine16).unwrap();
        let trailer = owner_aliases::seal_current(&node).unwrap();
        old.truncate(old.len() - 4 - trailer.len());
        assert!(
            decode_v2(&old, &TEST_SEED).is_err(),
            "v15 requires its owner record"
        );
        old.truncate(old.len() - 4 - seal_machine_ownership(false, &TEST_SEED).unwrap().len());
        old[..6].copy_from_slice(MAGIC_V14);
        let legacy = decode_v2(&old, &TEST_SEED).unwrap();
        assert!(legacy.owner_aliases.is_none());
        assert!(decode_v2(&encoded, &TEST_SEED)
            .unwrap()
            .owner_aliases
            .is_some());
    }
    #[tokio::test]
    async fn deferred_preparation_failure_preserves_first_move_and_original_deadline() {
        let mut node = state();
        let recipient = IdentityKeypair::from_seed([0xB6; 32]);
        let (bundle, secrets) = recipient.issue_bundle();
        let mut peer = peer(60);
        peer.identity_pk = recipient.public_bytes();
        peer.bundle = bundle.encode();
        let id = [7; 16];
        let now = std::time::Instant::now();
        let expires = now + std::time::Duration::from_secs(123);
        node.pending_1to1.insert(
            id,
            PendingDirect {
                delivery: DirectDelivery {
                    peer: peer.clone(),
                    relay: node.client_relay.clone(),
                    cells: Vec::new(),
                },
                logical_record: Some(vec![0; 32_768]),
                sequence: 1,
                next_attempt: now,
                expires,
                application_event: false,
            },
        );
        node.next_direct_sequence = 2;
        assert!(super::super::direct::materialize_deferred(&mut node).is_err());
        assert!(!node.sessions.contains_key(&peer.identity_pk));
        assert!(!node.session_states.contains_key(&peer.identity_pk));
        assert!(node.pending_1to1[&id].delivery.cells.is_empty());
        assert_eq!(node.pending_1to1[&id].expires, expires);
        assert!(!node.owner_transition_failed);

        let record = crate::proto::encode_direct_durable_data(id, 1, b"retained application");
        node.pending_1to1.get_mut(&id).unwrap().logical_record = Some(record.clone());
        super::super::direct::materialize_deferred(&mut node).unwrap();
        let pending = &node.pending_1to1[&id];
        assert_eq!(pending.expires, expires);
        assert_eq!(pending.delivery.cells.len(), 2);
        let first =
            gcoms_crypto::FirstMove::decode(&pending.delivery.cells[0].payload[1..]).unwrap();
        let (_, mut session) = secrets.accept(&first).unwrap();
        let Some(crate::proto::NodePayload::Frame(_, frame)) =
            crate::proto::decode_payload(&pending.delivery.cells[1])
        else {
            panic!("prepared frame")
        };
        assert_eq!(session.receive(&frame).unwrap(), record);
    }

    #[tokio::test]
    async fn pipelined_session_barrier_retains_logical_records_across_restart() {
        let mut node = state();
        node.scheduler.shutdown();
        node.scheduler = RelayScheduler::with_profile(
            Arc::new(gcoms_transport::Tp1Client::new().unwrap()),
            crate::scheduler::SchedulerProfile::fixture().with_pipelining(),
        );
        let recipient = IdentityKeypair::from_seed([0xB6; 32]);
        let (bundle, secrets) = recipient.issue_bundle();
        let mut peer = peer(60);
        peer.identity_pk = recipient.public_bytes();
        peer.bundle = bundle.encode();
        let now = std::time::Instant::now();
        let expires = now + std::time::Duration::from_secs(123);
        for sequence in 1..=3 {
            let id = [sequence as u8; 16];
            node.pending_1to1.insert(
                id,
                PendingDirect {
                    delivery: DirectDelivery {
                        peer: peer.clone(),
                        relay: node.client_relay.clone(),
                        cells: Vec::new(),
                    },
                    logical_record: Some(crate::proto::encode_direct_durable_data(
                        id,
                        1,
                        b"queued data",
                    )),
                    sequence,
                    next_attempt: now,
                    expires,
                    application_event: false,
                },
            );
        }
        node.next_direct_sequence = 4;
        super::super::direct::materialize_deferred(&mut node).unwrap();
        assert_eq!(node.pending_1to1[&[1; 16]].delivery.cells.len(), 2);
        assert!(node.pending_1to1[&[2; 16]].delivery.cells.is_empty());
        assert!(node.pending_1to1[&[3; 16]].delivery.cells.is_empty());
        let counter = node.sessions[&peer.identity_pk].send_ctr();
        for _ in 0..3 {
            super::super::direct::materialize_deferred(&mut node).unwrap();
        }
        assert_eq!(node.sessions[&peer.identity_pk].send_ctr(), counter);
        assert_eq!(node.pending_1to1[&[2; 16]].expires, expires);
        let archived = encode_state(&node).unwrap();
        let mut old_tag = archived.clone();
        old_tag[..6].copy_from_slice(MAGIC_V18);
        assert!(
            decode_v2(&old_tag, &TEST_SEED).is_err(),
            "v18 cannot represent this readiness wait"
        );
        let mut restored = state();
        restored.scheduler.shutdown();
        restored.scheduler = node.scheduler.clone();
        let restored = Arc::new(Mutex::new(restored));
        decode_state_at_startup(&restored, &node.scheduler, &archived)
            .await
            .unwrap();
        let mut restored = restored.lock().unwrap();
        super::super::direct::materialize_deferred(&mut restored).unwrap();
        assert!(restored.pending_1to1[&[2; 16]].delivery.cells.is_empty());
        assert_eq!(restored.sessions[&peer.identity_pk].send_ctr(), counter);
        let cells = &node.pending_1to1[&[1; 16]].delivery.cells;
        let first = gcoms_crypto::FirstMove::decode(&cells[0].payload[1..]).unwrap();
        let (_, mut remote) = secrets.accept(&first).unwrap();
        let Some(crate::proto::NodePayload::Frame(_, frame)) =
            crate::proto::decode_payload(&cells[1])
        else {
            panic!("frame");
        };
        remote.receive(&frame).unwrap();
        let ack = remote
            .send(&crate::proto::encode_direct_ack([1; 16], false))
            .unwrap();
        let (events, _) = broadcast::channel(8);
        process_frame(&mut restored, peer.identity_pk.clone(), ack, &events);
        super::super::direct::materialize_deferred(&mut restored).unwrap();
        assert_eq!(restored.pending_1to1[&[2; 16]].delivery.cells.len(), 1);
        assert_eq!(restored.pending_1to1[&[3; 16]].delivery.cells.len(), 1);
        assert_eq!(restored.sessions[&peer.identity_pk].send_ctr(), counter + 2);
        node.scheduler.shutdown();
    }

    #[tokio::test]
    async fn installed_inbox_does_not_wait_for_peer_update_delivery() {
        use std::time::Duration;
        use tokio::time::timeout;
        let identity = TlsIdentity::generate().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = RelayTarget {
            address: listener.local_addr().unwrap(),
            relay_service_id: identity.service_id(),
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
        let (observed, mut requests) = tokio::sync::mpsc::channel(16);
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let observed = observed.clone();
                connections.spawn(async move {
                    let tls = acceptor.accept(tcp).await.unwrap();
                    let mut h2 = h2::server::handshake(tls).await.unwrap();
                    let mut jobs = tokio::task::JoinSet::new();
                    while let Some(Ok((request, mut reply))) = h2.accept().await {
                        let observed = observed.clone();
                        jobs.spawn(async move {
                            let mut body = request.into_body();
                            let mut wire = Vec::new();
                            while let Some(Ok(bytes)) = body.data().await {
                                body.flow_control().release_capacity(bytes.len()).unwrap();
                                wire.extend_from_slice(&bytes);
                            }
                            let cell = gcoms_core::decode(&wire).unwrap();
                            let mut response =
                                reply.send_response(http::Response::new(()), false).unwrap();
                            observed.send(cell.cell_type().unwrap()).await.unwrap();
                            if cell.cell_type() == Some(CellType::RelaySub) {
                                response
                                    .send_data(
                                        bytes::Bytes::from(
                                            gcoms_transport::HopReply::Accepted
                                                .cell()
                                                .encode_wire()
                                                .unwrap(),
                                        ),
                                        true,
                                    )
                                    .unwrap();
                            } else {
                                // Keep a live authenticated response outstanding. An
                                // unrelated peer's progress cannot gate installation.
                                let _held = response;
                                std::future::pending::<()>().await;
                            }
                        });
                    }
                });
            }
        });
        let (mut node, _, _) = direct_fixture();
        for peer in node.peer_routes.values_mut() {
            for alias in &mut peer.aliases {
                alias.expiry = now_unix() + 3600;
            }
        }
        node.scheduler.shutdown();
        let saved = Arc::new(Mutex::new(Vec::new()));
        let sink = saved.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }));
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::compressed_production(93),
        );
        node.scheduler = scheduler.clone();
        node.frwd_target_policy = FrwdTargetPolicy::new(true);
        let mut provision = owner_relay();
        for (index, alias) in provision.aliases.iter_mut().enumerate() {
            let mut contact = contact(100 + 20 * index as u8);
            contact.expiry = now_unix() + 3600;
            contact.target = target.clone();
            *alias = valid_alias(contact, 100 + 20 * index as u8);
        }
        let mut card = peer(40);
        card.aliases = provision
            .aliases
            .iter()
            .map(|a| a.contact.clone())
            .collect();
        card.provisioning = Some(provision.clone());
        let state = Arc::new(Mutex::new(node));
        let (events, mut event_rx) = broadcast::channel(8);
        let mut installation = tokio::spawn({
            let state = state.clone();
            let scheduler = scheduler.clone();
            let events = events.clone();
            async move {
                super::super::aliases::install_inbox_relay(&state, &scheduler, &events, &card).await
            }
        });
        for _ in 0..2 {
            assert_eq!(
                timeout(Duration::from_secs(5), requests.recv())
                    .await
                    .unwrap(),
                Some(CellType::RelaySub)
            );
        }
        tokio::select! {
            biased;
            event = timeout(Duration::from_secs(5), event_rx.recv()) => assert!(matches!(event.unwrap().unwrap(), Ev::IdentityUpdated { .. })),
            result = &mut installation => panic!("installation ended before identity event: {result:?}"),
        }
        let completed = timeout(Duration::from_secs(2), &mut installation).await;
        let archive = {
            let st = state.lock().unwrap();
            assert_eq!(st.client_relay, provision);
            assert!(!st.pending_1to1.is_empty());
            assert!(st
                .pending_1to1
                .values()
                .all(|pending| !pending.application_event));
            encode_state(&st).unwrap()
        };
        let restored = decode_v2(&saved.lock().unwrap(), &TEST_SEED).unwrap();
        let in_memory = decode_v2(&archive, &TEST_SEED).unwrap();
        assert_eq!(
            restored.pending_direct.len(),
            in_memory.pending_direct.len()
        );
        assert!(
            !restored.pending_direct.is_empty(),
            "peer updates must remain durable"
        );
        if matches!(&completed, Ok(Ok(Ok(())))) {
            let retained: Vec<_> = state
                .lock()
                .unwrap()
                .pending_1to1
                .iter()
                .map(|(id, pending)| {
                    (
                        *id,
                        pending.delivery.cells.clone(),
                        pending.application_event,
                    )
                })
                .collect();
            // Make the existing retry due; do not alter production retry clocks.
            for pending in state.lock().unwrap().pending_1to1.values_mut() {
                pending.next_attempt = std::time::Instant::now();
            }
            let mut maintenance = super::super::direct::DirectMaintenance::default();
            maintenance.tick(&state, &scheduler, &events);
            tokio::select! {
                observed = timeout(Duration::from_secs(5), requests.recv()) => assert_eq!(observed.unwrap(), Some(CellType::Frwd)),
                _ = maintenance.complete_next(&state) => panic!("stalled peer unexpectedly completed"),
            }
            drop(maintenance);
            let st = state.lock().unwrap();
            for (id, cells, application_event) in retained {
                assert_eq!(st.pending_1to1[&id].delivery.cells, cells);
                assert_eq!(st.pending_1to1[&id].application_event, application_event);
            }
            assert!(
                event_rx.try_recv().is_err(),
                "hop work cannot claim application delivery"
            );
        }
        if completed.is_err() {
            assert_eq!(
                timeout(Duration::from_secs(2), requests.recv())
                    .await
                    .unwrap(),
                Some(CellType::Frwd),
                "the stalled peer request must actually reach the authenticated fixture"
            );
            installation.abort();
            let _ = installation.await;
        }
        server.abort();
        let _ = server.await;
        scheduler.shutdown();
        assert!(
            matches!(completed, Ok(Ok(Ok(())))),
            "durably installed inbox waited for peer notification"
        );
    }

    #[tokio::test]
    async fn inbox_replacement_capacity_refusal_keeps_the_owner_available() {
        let mut node = state();
        node.routing = Some(
            routing::RoutingRuntime::new(
                RoutingConfig::default(),
                gcoms_routing::Directory::new(),
                true,
            )
            .unwrap(),
        );
        let now = std::time::Instant::now();
        let receive_until = now + std::time::Duration::from_secs(30);
        let abandon_at = receive_until + std::time::Duration::from_secs(30);
        for byte in 10..14 {
            node.draining_contact_aliases.push(DrainingContactAliases {
                aliases: vec![owned_alias(byte)],
                receive_until,
                abandon_at,
                next_revoke: receive_until,
            });
        }
        node.unannounced_old_contact_aliases = Some(vec![owned_alias(20)]);
        node.unannounced_contact_deadlines = Some((receive_until, abandon_at));
        node.staged_contact_aliases = Some(vec![owned_alias(30)]);
        let scheduler = node.scheduler.clone();
        let (events, _) = broadcast::channel(4);
        let state = Arc::new(Mutex::new(node));
        let error =
            super::super::aliases::install_inbox_relay(&state, &scheduler, &events, &peer(40))
                .await
                .unwrap_err();
        assert_eq!(error, "retained inbox cleanup capacity reached");
        let node = state.lock().unwrap();
        assert!(!node.owner_transition_failed);
        assert_eq!(node.draining_contact_aliases.len(), 4);
        assert!(node.staged_contact_aliases.is_some());
        assert!(node.unannounced_old_contact_aliases.is_some());
        assert_eq!(
            node.unannounced_contact_deadlines,
            Some((receive_until, abandon_at))
        );
    }

    #[tokio::test]
    async fn routing_guard_persistence_failure_prevents_first_entry_socket() {
        use gcoms_transport::connector::Connector;
        let first = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.3:0").await.unwrap();
        let directory = gcoms_routing::Directory::new();
        for (n, listener) in [(2u8, &first), (3u8, &second)] {
            directory
                .install(
                    gcoms_routing::Relay {
                        addr: listener.local_addr().unwrap(),
                        service_id: [n; 32],
                        reentry_cap: [n + 10; 32],
                        circuit_cap: [n + 20; 32],
                        expires_at: now_unix() + 3600,
                    },
                    now_unix(),
                )
                .unwrap();
        }
        let runtime =
            routing::RoutingRuntime::new(RoutingConfig::default(), directory, true).unwrap();
        let mut node = state();
        node.routing = Some(runtime.clone());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = calls.clone();
        node.durable_state_sink = Some(Arc::new(move |_| {
            capture.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("guard checkpoint failure".into())
        }));
        let state = Arc::new(Mutex::new(node));
        runtime.bind_state(&state).unwrap();
        assert!(runtime
            .discovery
            .connector
            .connect("127.0.0.9:443".parse().unwrap(), [9; 32])
            .await
            .is_err());
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), first.accept())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), second.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owner_real_nonactive_aliases_restore_with_original_operations_and_auto_port() {
        let cfg = || NodeConfig {
            seed: TEST_SEED,
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        };
        let sink: DurableStateSink = Arc::new(|_| Ok(()));
        let node = super::super::start_persistent_restored(cfg(), None, sink.clone(), None)
            .await
            .unwrap();
        let prepared: Result<_, String> = async {
            let before = decode_v2(&node.export_state().await?, &TEST_SEED)?
                .owner_aliases
                .ok_or("missing initial owner record")?;
            // A newly created 24h lease cannot be extended in the same wall
            // second under the unchanged maximum-lifetime policy. Consume time;
            // never rewrite the original expiry or inject a successful receipt.
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            node.renew_contacts_now().await?;
            let bytes = node.export_state().await?;
            let mut record = decode_v2(&bytes, &TEST_SEED)?
                .owner_aliases
                .ok_or("missing owner record")?;
            if record.renewals.len() != 2
                || record.groups[0].origins != before.groups[0].origins
                || record.groups[0].deadline_ms > before.groups[0].deadline_ms
            {
                return Err("actual renewal lost provenance or extended role lifetime".into());
            }
            let authority = record.groups[0].provision.aliases[0].clone();
            for role in [
                owner_aliases::Role::Staged,
                owner_aliases::Role::Unannounced,
                owner_aliases::Role::Draining,
            ] {
                let count = if role == owner_aliases::Role::Staged {
                    2
                } else {
                    1
                };
                let mut aliases = Vec::new();
                for _ in 0..count {
                    aliases.push(create_contact_alias(&node.scheduler, &authority).await?);
                }
                let until = now_ms() + 30_000;
                record.groups.push(owner_aliases::Group {
                    role,
                    origins: aliases.clone(),
                    provision: RelayProvision {
                        aliases,
                        frwd_path: record.groups[0].provision.frwd_path.clone(),
                        hop_key: record.groups[0].provision.hop_key,
                    },
                    deadline_ms: until + 15_000,
                    action_ms: if role == owner_aliases::Role::Staged {
                        0
                    } else {
                        until
                    },
                    receive_until_ms: if role == owner_aliases::Role::Staged {
                        0
                    } else {
                        until
                    },
                });
            }
            record.validate(record.active_target()?)?;
            let mut malformed = record.clone();
            let old = malformed
                .groups
                .last_mut()
                .ok_or("missing nonactive role")?;
            old.provision.aliases[0].contact.target.address = "0.0.0.0:0".parse().unwrap();
            old.origins[0].contact.target.address = "0.0.0.0:0".parse().unwrap();
            if malformed.validate(record.active_target()?).is_ok() {
                return Err("malformed nonactive endpoint accepted".into());
            }
            let expired = create_contact_alias(&node.scheduler, &authority).await?;
            let expired_at = now_ms().saturating_sub(1);
            record.groups.push(owner_aliases::Group {
                role: owner_aliases::Role::Draining,
                origins: vec![expired.clone()],
                provision: RelayProvision {
                    aliases: vec![expired],
                    frwd_path: record.groups[0].provision.frwd_path.clone(),
                    hop_key: record.groups[0].provision.hop_key,
                },
                deadline_ms: expired_at,
                action_ms: expired_at,
                receive_until_ms: expired_at,
            });
            record.captured_ms = now_ms();
            let mut bytes = bytes;
            let mut position = decode_v2(&bytes, &TEST_SEED)?.layout.trailer_start;
            take32(&bytes, &mut position)?; // machine scope
            let start = position;
            take32(&bytes, &mut position)?; // owner record
            let mut replacement = Vec::new();
            put_sensitive(
                &mut replacement,
                owner_aliases::seal(&record, record.active_target()?, &TEST_SEED)?,
            )?;
            bytes.splice(start..position, replacement);
            Ok((bytes, record))
        }
        .await;
        node.shutdown().await;
        let (bytes, original) = prepared.unwrap();
        let reopened = super::super::start_persistent_restored(cfg(), None, sink, Some(&bytes))
            .await
            .unwrap();
        let verified: Result<(), String> = async {
            let after = decode_v2(&reopened.export_state().await?, &TEST_SEED)?
                .owner_aliases
                .ok_or("missing restored owner record")?;
            let live = original
                .groups
                .iter()
                .filter(|group| group.deadline_ms > after.captured_ms)
                .collect::<Vec<_>>();
            if after.groups.len() != live.len() {
                return Err("lost live nonactive role or retained abandoned role".into());
            }
            let mut new_admissions = 0;
            for (old, new) in live.into_iter().zip(&after.groups) {
                if old.role != new.role
                    || old.origins != new.origins
                    || new.deadline_ms > old.deadline_ms
                    || new.receive_until_ms > old.receive_until_ms
                {
                    return Err("restored role changed origin or extended lifetime".into());
                }
                for (a, b) in old.provision.aliases.iter().zip(&new.provision.aliases) {
                    if a.contact != b.contact
                        || a.capabilities != b.capabilities
                        || a.limits != b.limits
                    {
                        return Err("restored alias changed original authority".into());
                    }
                    if a.lease_create != b.lease_create {
                        new_admissions += 1;
                    }
                    let cover = crate::relay::RelayPush::cover(
                        b.contact.queue_id,
                        b.contact.epoch,
                        random_nonzero(),
                        now_unix() + 10,
                    )
                    .encode_into_cell(&b.capabilities.push, &b.contact.target.relay_service_id)
                    .map_err(|e| e.to_string())?;
                    reopened
                        .scheduler
                        .admin_post(
                            b.contact.target.clone(),
                            encode_b64url(&b.contact.queue_id),
                            cover,
                        )
                        .map_err(|e| e.to_string())?
                        .completion()
                        .await
                        .accepted()?;
                }
            }
            let expired = &original
                .groups
                .last()
                .ok_or("missing abandoned fixture")?
                .provision
                .aliases[0];
            let cover = crate::relay::RelayPush::cover(
                expired.contact.queue_id,
                expired.contact.epoch,
                random_nonzero(),
                now_unix() + 10,
            )
            .encode_into_cell(
                &expired.capabilities.push,
                &expired.contact.target.relay_service_id,
            )
            .map_err(|e| e.to_string())?;
            if reopened
                .scheduler
                .admin_post(
                    expired.contact.target.clone(),
                    encode_b64url(&expired.contact.queue_id),
                    cover,
                )
                .map_err(|e| e.to_string())?
                .completion()
                .await
                .accepted()
                .is_ok()
            {
                return Err("abandoned alias was recreated".into());
            }
            if new_admissions == 0 {
                return Err("fixture did not exercise fresh authenticated admission".into());
            }
            Ok(())
        }
        .await;
        reopened.shutdown().await;
        verified.unwrap();
    }
    #[tokio::test]
    async fn owner_abandoned_role_is_retired_before_any_admin_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut node = state();
        let mut value = contact(101);
        value.target.address = listener.local_addr().unwrap();
        value.expiry = now_unix() + 60;
        let old = valid_alias(value, 101);
        let before = std::time::Instant::now() - std::time::Duration::from_secs(1);
        node.draining_contact_aliases.push(DrainingContactAliases {
            aliases: vec![old],
            receive_until: before,
            next_revoke: before,
            abandon_at: before,
        });
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = writes.clone();
        node.durable_state_sink = Some(Arc::new(move |bytes| {
            let record = decode_v2(&bytes, &TEST_SEED)?
                .owner_aliases
                .ok_or("missing owner record")?;
            if record
                .groups
                .iter()
                .any(|g| g.role == owner_aliases::Role::Draining)
            {
                return Err("abandoned role persisted as live".into());
            }
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }));
        let scheduler = node.scheduler.clone();
        let shared = Arc::new(Mutex::new(node));
        let (events, mut observed) = broadcast::channel(8);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            contact_alias_lifecycle_tick(
                &shared,
                &scheduler,
                &events,
                AliasLifecycleConfig::default(),
            ),
        )
        .await;
        scheduler.shutdown();
        assert!(
            result.is_ok(),
            "expired role attempted awaited network cleanup"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(shared.lock().unwrap().draining_contact_aliases.is_empty());
        assert!(observed.try_recv().is_err());
        assert_eq!(writes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
