// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

// (client-persist) legacy GCNST1 decoder.

use super::*;
use crate::channel::{ChannelRole, ChannelState};

const MAGIC: &[u8; 6] = b"GCNST1";
const ROLE_OWNER: u8 = 1;
const ROLE_MEMBER: u8 = 2;

fn take<'a>(buf: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = p.checked_add(n)?;
    let out = buf.get(*p..end)?;
    *p = end;
    Some(out)
}

fn take16<'a>(buf: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let l = u16::from_be_bytes([*buf.get(*p)?, *buf.get(*p + 1)?]) as usize;
    *p += 2;
    take(buf, p, l)
}

fn take32<'a>(buf: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let l = u32::from_be_bytes(buf.get(*p..*p + 4)?.try_into().ok()?) as usize;
    *p += 4;
    take(buf, p, l)
}

pub async fn decode_state(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    buf: &[u8],
) -> Result<(), String> {
    if buf.len() < 6 + 4 + 4 || &buf[..6] != MAGIC {
        return Err("not a gc node state export".into());
    }
    let mut p = 6usize;
    let bad = || "malformed node state export".to_string();
    let identity_seed = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .identity_seed;
    let archive_key = channel_archive_key(&identity_seed);
    let mut sessions = Vec::new();
    let n_sessions = u32::from_be_bytes(take(buf, &mut p, 4).ok_or_else(bad)?.try_into().unwrap());
    if n_sessions as usize > 8192 {
        return Err(bad());
    }
    for _ in 0..n_sessions {
        let pk = take16(buf, &mut p).ok_or_else(bad)?.to_vec();
        let sb = take32(buf, &mut p).ok_or_else(bad)?;
        let session = Session::decode(sb).ok_or_else(bad)?;
        sessions.push((pk, session));
    }
    let n_channels = u32::from_be_bytes(take(buf, &mut p, 4).ok_or_else(bad)?.try_into().unwrap());
    if n_channels as usize > gcoms_mls::CHANNEL_MAX {
        return Err(bad());
    }
    let mut channels = Vec::new();
    for _ in 0..n_channels {
        let name =
            String::from_utf8(take16(buf, &mut p).ok_or_else(bad)?.to_vec()).map_err(|_| bad())?;
        let kind = *take(buf, &mut p, 1).ok_or_else(bad)?.first().unwrap();
        let blob = take32(buf, &mut p).ok_or_else(bad)?;
        let role = match kind {
            ROLE_OWNER => ChannelRole::Owner(
                gcoms_mls::OwnerSession::restore(
                    &archive_key,
                    blob,
                    IdentityKeypair::from_seed(super::persist::channel_seed_from(
                        &identity_seed,
                        &name,
                    )),
                )
                .map_err(|e| e.to_string())?,
            ),
            ROLE_MEMBER => ChannelRole::Member(
                gcoms_mls::ChannelMember::restore(&archive_key, blob).map_err(|e| e.to_string())?,
            ),
            _ => return Err(bad()),
        };
        let n_dir = u32::from_be_bytes(take(buf, &mut p, 4).ok_or_else(bad)?.try_into().unwrap());
        if n_dir as usize > 1024 {
            return Err(bad());
        }
        let mut directory = HashMap::new();
        for _ in 0..n_dir {
            let dname = String::from_utf8(take16(buf, &mut p).ok_or_else(bad)?.to_vec())
                .map_err(|_| bad())?;
            let ib = take32(buf, &mut p).ok_or_else(bad)?;
            let route = if let Some(route) = crate::channel::ChannelRoute::decode(ib) {
                route
            } else {
                let info = NodeInfo::decode(ib).ok_or_else(bad)?;
                let pseudonym = role.pseudonym_for_name(&dname).ok_or_else(bad)?;
                let data = info.primary().cloned().ok_or_else(bad)?;
                let control = info.control().cloned().ok_or_else(bad)?;
                let route = crate::channel::ChannelRoute {
                    pseudonym,
                    direct_public: [0; 32],
                    data,
                    control,
                };
                if !route.is_valid() {
                    return Err(bad());
                }
                route
            };
            directory.insert(dname, route);
        }
        channels.push((name, role, directory));
    }
    if p != buf.len() {
        return Err(bad());
    }
    let relay = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .client_relay
        .clone();
    let mut restored_channels = Vec::with_capacity(channels.len());
    for (name, role, mut directory) in channels {
        let pseudonym = role.own_pseudonym();
        let identity_seed = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .identity_seed;
        let offline = state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .routing
            .is_some();
        let own_route = if offline {
            routing::pending_channel_route(
                &identity_seed,
                &name,
                pseudonym,
                directory
                    .values()
                    .find(|r| r.pseudonym == pseudonym)
                    .cloned(),
            )?
        } else {
            provision_channel_route(
                scheduler,
                &relay,
                pseudonym,
                super::persist::established_route_secret(&identity_seed, &name, &role),
            )
            .await?
        };
        // Fresh entropy for the overlay eviction RNG (T12): the seed is
        // never persisted or sent, so restoring with new randomness is safe
        // and keeps eviction unpredictable across restarts.
        let seed = rand::thread_rng().next_u64();
        if let Some(own_name) = directory
            .iter()
            .find(|(_, route)| route.pseudonym == pseudonym)
            .map(|(name, _)| name.clone())
        {
            if own_route.public.is_valid() {
                directory.insert(own_name, own_route.public.clone());
            }
        }
        let mut channel_state = ChannelState::new(
            role,
            own_route,
            seed,
            name.clone(),
            crate::channel::ChannelVisibility::Private,
        );
        for route in directory.values() {
            channel_state.learn(route);
        }
        channel_state.directory = directory;
        restored_channels.push((name, channel_state));
    }
    let mut st = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (pk, session) in sessions {
        st.sessions.insert(pk.clone(), session);
        st.session_states
            .insert(pk, DirectSessionState::Established);
    }
    for (name, channel_state) in restored_channels {
        st.channels.insert(name, channel_state);
    }
    Ok(())
}
