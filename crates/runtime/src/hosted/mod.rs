//! Durable client-owned MLS state for ciphertext-only hosted channels.
//! Each channel has an exclusively locked encrypted sidecar. Callers archive
//! events before acknowledging them and schedule `Sync` while connected.
mod public;
mod state;
mod storage;

use gcoms_crypto::IdentityKeypair;
use gcoms_mls::hosted::*;
use gcoms_sdk::{hosted as wire, hosted_client as api, GcClient};
use public::{decode, encode, now, snapshot, Routed, SnapshotAuthority, Transport};
use serde::{Deserialize, Serialize};
use state::{Client, Pending, Phase};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const LINK_PREFIX: &str = "gcoms-hosted:v1:";
#[derive(Serialize, Deserialize)]
struct Link {
    channel: [u8; 32],
    endpoint: String,
    secret: Vec<u8>,
    single_use: bool,
    expires_at: u64,
}
impl Drop for Link {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}
impl Link {
    fn export(&self) -> Result<api::InviteLink, String> {
        let bytes =
            Zeroizing::new(postcard::to_allocvec(self).map_err(|_| "encode hosted invitation")?);
        Ok(api::InviteLink(format!("{LINK_PREFIX}{}", encode(&bytes))))
    }
    fn parse(link: &api::InviteLink) -> Result<Self, String> {
        if link.0.len() > 8192 {
            return Err("hosted invitation exceeds bound".into());
        }
        let bytes = Zeroizing::new(decode(
            link.0
                .strip_prefix(LINK_PREFIX)
                .ok_or("unsupported hosted invitation")?,
        )?);
        let value: Self = postcard::from_bytes(&bytes).map_err(|_| "invalid hosted invitation")?;
        endpoint(&value.endpoint)?;
        if value.secret.len() > 128 || (value.expires_at != 0 && value.expires_at <= now()) {
            return Err("expired or invalid hosted invitation".into());
        }
        Ok(value)
    }
}
fn endpoint(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|_| "invalid hosted endpoint")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/v1/hosted"
        || url.host_str().is_none()
    {
        return Err("hosted endpoint must be an HTTPS service origin".into());
    }
    Ok(())
}
fn alias(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err("invalid channel alias".into());
    }
    Ok(())
}
fn filename(channel: [u8; 32]) -> String {
    channel
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + ".hosted"
}
fn parse_filename(name: &str) -> Option<[u8; 32]> {
    let hex = name.strip_suffix(".hosted")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut channel = [0; 32];
    for (i, byte) in channel.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(channel)
}

/// Serialize access to this owner (for example with a runtime async mutex).
/// `client` supplies only protected routing; it never owns channel keys.
pub struct HostedChannels {
    directory: PathBuf,
    key: Zeroizing<[u8; 32]>,
    network: Arc<dyn GcClient>,
    channels: BTreeMap<[u8; 32], Client>,
}
impl HostedChannels {
    /// The profile owner creates and secures the directory before opening it.
    /// A malformed, locked or unauthenticated sidecar fails the whole open.
    pub fn open(
        directory: &Path,
        key: [u8; 32],
        network: Arc<dyn GcClient>,
    ) -> Result<Self, String> {
        crate::private_fs::validate_private_dir(directory, "hosted profiles")?;
        let mut owner = Self {
            directory: directory.into(),
            key: Zeroizing::new(key),
            network,
            channels: BTreeMap::new(),
        };
        for entry in std::fs::read_dir(directory).map_err(|_| "read hosted profiles")? {
            let entry = entry.map_err(|_| "read hosted profile entry")?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(channel) = parse_filename(&name) else {
                continue;
            };
            if owner.channels.len() >= 1000 {
                return Err("too many hosted profiles".into());
            }
            let (storage, data) = storage::Storage::open(&entry.path(), key, channel)?;
            let data = data.ok_or("hosted profile disappeared")?;
            let endpoint = Client::stored_endpoint(&data)?;
            endpoint_check(&endpoint)?;
            let transport = owner.route(&endpoint);
            let client = Client::restore(&data, channel, storage, key, transport)?;
            owner.channels.insert(channel, client);
        }
        Ok(owner)
    }
    fn route(&self, endpoint: &str) -> Arc<dyn Transport> {
        Arc::new(Routed {
            client: self.network.clone(),
            endpoint: endpoint.into(),
        })
    }
    fn storage(&self, channel: [u8; 32]) -> Result<storage::Storage, String> {
        if self.channels.len() >= 1000 || self.channels.contains_key(&channel) {
            return Err("channel already exists or profile limit reached".into());
        }
        let (store, existing) =
            storage::Storage::open(&self.directory.join(filename(channel)), *self.key, channel)?;
        if existing.is_some() {
            return Err("hosted profile already exists".into());
        }
        Ok(store)
    }
    pub async fn request(&mut self, request: api::Request) -> Result<api::Reply, String> {
        use api::Request::*;
        match request {
            Directory {
                endpoint: target,
                after,
                limit,
            } => {
                endpoint(&target)?;
                if limit == 0 || limit > 16 {
                    return Err("Directory page limit must be 1..16".into());
                }
                let wire::Reply::Directory { entries, next } = self
                    .route(&target)
                    .exchange([0; 32], wire::Operation::Directory { after, limit })
                    .await?
                else {
                    return Err("Hosted service does not support public discovery".into());
                };
                if entries.len() > usize::from(limit)
                    || entries.windows(2).any(|w| w[0].channel >= w[1].channel)
                    || entries.iter().any(|e| {
                        e.channel == [0; 32]
                            || after.is_some_and(|after| e.channel <= after)
                            || e.name.is_empty()
                            || e.name.len() > 64
                            || e.name.chars().any(|c| c.is_control() || c.is_whitespace())
                            || !(2..=500).contains(&e.capacity)
                            || !(1..=500).contains(&e.members)
                    })
                    || next.is_some_and(|next| {
                        entries.len() != usize::from(limit)
                            || entries.last().is_none_or(|e| e.channel != next)
                    })
                {
                    return Err("Invalid hosted directory response".into());
                }
                let entries = entries
                    .into_iter()
                    .map(|entry| {
                        let link = entry
                            .public_join
                            .then(|| {
                                Link {
                                    channel: entry.channel,
                                    endpoint: target.clone(),
                                    secret: vec![],
                                    single_use: false,
                                    expires_at: 0,
                                }
                                .export()
                            })
                            .transpose()?;
                        Ok(api::DirectoryEntry {
                            channel: entry.channel,
                            name: entry.name,
                            members: entry.members,
                            capacity: entry.capacity,
                            link,
                        })
                    })
                    .collect::<Result<_, String>>()?;
                Ok(api::Reply::Directory { entries, next })
            }
            List => Ok(api::Reply::Channels(
                self.channels.values().map(Client::view).collect(),
            )),
            Create {
                endpoint: target,
                alias: name,
                nickname,
                capacity,
                admission,
            } => {
                endpoint(&target)?;
                alias(&name)?;
                let root = IdentityKeypair::generate();
                let code = matches!(admission, api::Admission::ReusableCode)
                    .then(HostedAccessCode::generate)
                    .transpose()
                    .map_err(|e| e.to_string())?;
                let session = match &code {
                    Some(code) => HostedSession::create_keyed(&root, &nickname, capacity, code),
                    None => HostedSession::create(
                        &root,
                        &nickname,
                        capacity,
                        matches!(admission, api::Admission::Public),
                    ),
                }
                .map_err(|e| e.to_string())?;
                let channel = session.policy().channel_id();
                let pending = Pending::Create {
                    policy: encode(&session.policy().encode().map_err(|e| e.to_string())?),
                    genesis: encode(&session.export_group_info().map_err(|e| e.to_string())?),
                };
                let stored_code = code
                    .map(|c| c.export_secret().map(|v| v.to_vec()))
                    .transpose()
                    .map_err(|e| e.to_string())?;
                let client = Client::new(
                    session,
                    state::NewClient {
                        alias: name,
                        endpoint: target.clone(),
                        phase: Phase::Creating,
                        pending,
                        access_code: stored_code,
                        join_link: None,
                    },
                    self.storage(channel)?,
                    *self.key,
                    self.route(&target),
                )?;
                let view = client.view();
                self.channels.insert(channel, client);
                Ok(api::Reply::Channel(Box::new(view)))
            }
            Join {
                link,
                alias: name,
                nickname,
            } => {
                alias(&name)?;
                let decoded = Link::parse(&link)?;
                let transport = self.route(&decoded.endpoint);
                let prepared = PreparedHostedJoin::new(&nickname).map_err(|e| e.to_string())?;
                let (session, commit) =
                    prepare_join(transport.as_ref(), &decoded, prepared, &nickname).await?;
                let info = session
                    .proposed_group_info()
                    .map_err(|e| e.to_string())?
                    .to_vec();
                let client = Client::new(
                    session,
                    state::NewClient {
                        alias: name,
                        endpoint: decoded.endpoint.clone(),
                        phase: Phase::Joining,
                        pending: Pending::Membership {
                            commit,
                            info,
                            joining: true,
                        },
                        access_code: None,
                        join_link: Some(link),
                    },
                    self.storage(decoded.channel)?,
                    *self.key,
                    transport,
                )?;
                let view = client.view();
                self.channels.insert(decoded.channel, client);
                Ok(api::Reply::Channel(Box::new(view)))
            }
            PutBlob {
                channel,
                reference,
                bytes,
            } => self.channel(channel)?.blob(reference, Some(bytes)).await,
            GetBlob { channel, reference } => self.channel(channel)?.blob(reference, None).await,
            Send { channel, content } => Ok(api::Reply::Queued(
                self.channel(channel)?.queue_send(content)?,
            )),
            Change {
                channel,
                change,
                reason,
            } => {
                self.channel(channel)?
                    .queue_control(policy_change(change), &reason)?;
                Ok(api::Reply::Done)
            }
            Invite { channel, ttl_secs } => {
                if !(60..=604800).contains(&ttl_secs) {
                    return Err(
                        "invitation lifetime must be between one minute and seven days".into(),
                    );
                }
                let client = self.channel(channel)?;
                let code = HostedAccessCode::generate().map_err(|e| e.to_string())?;
                let expires_at = now() + u64::from(ttl_secs);
                let link = Link {
                    channel,
                    endpoint: client.archive.endpoint.clone(),
                    secret: code.export_secret().map_err(|e| e.to_string())?.to_vec(),
                    single_use: true,
                    expires_at,
                };
                client.register_invite(&code, expires_at, link.export()?)?;
                Ok(api::Reply::Link(link.export()?))
            }
            RotateCode { channel } => {
                let client = self.channel(channel)?;
                let code = HostedAccessCode::generate().map_err(|e| e.to_string())?;
                client.rotate_code(&code)?;
                Ok(api::Reply::Link(
                    Link {
                        channel,
                        endpoint: client.archive.endpoint.clone(),
                        secret: code.export_secret().map_err(|e| e.to_string())?.to_vec(),
                        single_use: false,
                        expires_at: 0,
                    }
                    .export()?,
                ))
            }
            ClearCode { channel } => {
                self.channel(channel)?.clear_code()?;
                Ok(api::Reply::Done)
            }
            Links { channel } => Ok(api::Reply::Links(self.channel(channel)?.links()?)),
            SetPresence {
                channel,
                enabled,
                state,
            } => {
                self.channel(channel)?.set_presence(enabled, state)?;
                Ok(api::Reply::Done)
            }
            Sync { channel } => {
                let client = self.channel(channel)?;
                client.flush_one().await?;
                client.sync_page().await?;
                Ok(api::Reply::Channel(Box::new(client.view())))
            }
            Events {
                channel,
                after,
                limit,
            } => Ok(api::Reply::Events(
                self.channel(channel)?.events(after, limit)?,
            )),
            FileEvents { channel, limit } => Ok(api::Reply::FileEvents(
                self.channel(channel)?.file_events(limit)?,
            )),
            CommitFileEvents { channel, through } => {
                self.channel(channel)?.commit_file_events(through)?;
                Ok(api::Reply::Done)
            }
            SendIdentified {
                channel,
                id,
                content,
            } => Ok(api::Reply::Queued(
                self.channel(channel)?.queue_send_identified(id, content)?,
            )),
            CommitEvents { channel, through } => {
                self.channel(channel)?.commit_events(through)?;
                Ok(api::Reply::Done)
            }
        }
    }
    fn channel(&mut self, id: [u8; 32]) -> Result<&mut Client, String> {
        self.channels
            .get_mut(&id)
            .ok_or_else(|| "unknown hosted channel".into())
    }
}
fn endpoint_check(value: &str) -> Result<(), String> {
    endpoint(value)
}
async fn prepare_join(
    transport: &dyn Transport,
    link: &Link,
    prepared: PreparedHostedJoin,
    nickname: &str,
) -> Result<(HostedSession, Vec<u8>), String> {
    let code = (!link.secret.is_empty())
        .then(|| HostedAccessCode::import_secret(&link.secret))
        .transpose()
        .map_err(|e| e.to_string())?;
    let authority = match &code {
        Some(code) => SnapshotAuthority::Code(code),
        None => SnapshotAuthority::Joining(&prepared),
    };
    let (public, _) = snapshot(transport, link.channel, authority).await?;
    let expiry = if link.expires_at == 0 {
        now() + 120
    } else {
        (now() + 120).min(link.expires_at)
    };
    let permit = match &code {
        Some(code) if link.single_use => {
            code.invitation_permit(&public, prepared.member_id(), nickname, expiry)
        }
        Some(code) => code.permit_for(&public, prepared.member_id(), nickname, expiry),
        None => Ok(JoinPermit::public_for(&public)),
    }
    .map_err(|e| e.to_string())?;
    prepared
        .join(&public, &permit, now())
        .map_err(|e| e.to_string())
}
fn policy_change(change: api::Change) -> HostedPolicyChange {
    match change {
        api::Change::Mode(mode, on) => HostedPolicyChange::Mode(
            match mode {
                api::Mode::Moderated => HostedMode::Moderated,
                api::Mode::InviteOnly => HostedMode::InviteOnly,
                api::Mode::TopicOperators => HostedMode::TopicOperators,
            },
            u8::from(on),
        ),
        api::Change::Operator(id, on) => HostedPolicyChange::Operator(id, u8::from(on)),
        api::Change::Voice(id, on) => HostedPolicyChange::Voice(id, u8::from(on)),
        api::Change::AccessList(list, id, on) => HostedPolicyChange::AccessList(
            match list {
                api::AccessList::Ban => HostedAccessList::Ban,
                api::AccessList::Exemption => HostedAccessList::Exemption,
                api::AccessList::InviteException => HostedAccessList::InviteException,
            },
            id,
            u8::from(on),
        ),
        api::Change::Listing(name) => HostedPolicyChange::Listing(name.into_bytes().into()),
        api::Change::Capacity(n) => HostedPolicyChange::Capacity(n),
        api::Change::Discovery(d) => HostedPolicyChange::Discovery(match d {
            api::Discovery::Public => HostedDiscovery::Public,
            api::Discovery::Private => HostedDiscovery::Private,
            api::Discovery::Secret => HostedDiscovery::Secret,
        }),
        api::Change::Transfer(id) => HostedPolicyChange::Transfer(id),
        api::Change::Kick(id) => HostedPolicyChange::Kick(id),
        api::Change::Leave => HostedPolicyChange::Leave,
        api::Change::Close => HostedPolicyChange::Close,
        api::Change::Role(id, r) => HostedPolicyChange::Role(
            id,
            match r {
                api::Role::Owner => HostedRole::Owner,
                api::Role::Operator => HostedRole::Operator,
                api::Role::Voice => HostedRole::Voice,
                api::Role::Member => HostedRole::Member,
            },
        ),
        api::Change::Invitation {
            verifier,
            expires_at,
        } => HostedPolicyChange::Invitation(verifier, expires_at),
        api::Change::AccessCode { verifier } => HostedPolicyChange::AccessCode(verifier),
    }
}

#[cfg(test)]
mod tests;
