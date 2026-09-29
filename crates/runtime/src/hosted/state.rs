use super::{
    public::{decode, encode, now, query_hash, Transport},
    storage::Storage,
};
use gcoms_channel_service::Record;
use gcoms_mls::hosted::*;
use gcoms_sdk::{hosted as wire, hosted_client as api};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroizing;

const MAX_EVENTS: usize = 4096;
const MAX_PENDING: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Application {
    version: u16,
    id: [u8; 32],
    content: api::Content,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) enum Phase {
    Creating,
    Joining,
    Ready,
    Removed,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) enum Pending {
    Create {
        policy: String,
        genesis: String,
    },
    Membership {
        commit: Vec<u8>,
        info: Vec<u8>,
        joining: bool,
    },
    Message {
        wire: Vec<u8>,
        application: Application,
    },
    Control {
        wire: Vec<u8>,
        reason: String,
    },
}
impl Pending {
    fn id(&self) -> Result<[u8; 32], String> {
        use sha2::{Digest, Sha256};
        Ok(
            Sha256::digest(postcard::to_allocvec(self).map_err(|_| "encode pending identity")?)
                .into(),
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Sent {
    application: Application,
    wire: Vec<u8>,
    expected: Vec<[u8; 32]>,
    accepted: Option<wire::Acceptance>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Archive {
    version: u16,
    pub channel: [u8; 32],
    pub alias: String,
    pub endpoint: String,
    session: Vec<u8>,
    phase: Phase,
    pub cursor: u64,
    head: [u8; 32],
    last_time: u64,
    pending: Vec<Pending>,
    refused: Option<[u8; 32]>,
    sent: BTreeMap<[u8; 32], Sent>,
    events: Vec<api::Event>,
    next_event: u64,
    topic: String,
    nicknames: BTreeMap<[u8; 32], String>,
    presence: BTreeMap<[u8; 32], (api::Presence, u64)>,
    presence_opt_in: bool,
    access_code: Option<Vec<u8>>,
    join_link: Option<api::InviteLink>,
    issued_links: Vec<api::InviteLink>,
    seen: BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
}

pub(super) struct NewClient {
    pub alias: String,
    pub endpoint: String,
    pub phase: Phase,
    pub pending: Pending,
    pub access_code: Option<Vec<u8>>,
    pub join_link: Option<api::InviteLink>,
}

#[derive(Default, Serialize, Deserialize)]
struct Receipts {
    outbox: Vec<(u64, Vec<u8>)>,
    committed: u64,
    cursor: u64,
    received: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
}
fn decode_archive(bytes: &[u8]) -> Result<(Archive, Receipts), String> {
    let (archive, tail): (Archive, _) =
        postcard::take_from_bytes(bytes).map_err(|_| "invalid hosted client archive")?;
    let receipts = match archive.version {
        1 if tail.is_empty() => Receipts::default(),
        2 => postcard::from_bytes(tail).map_err(|_| "invalid hosted receipt archive")?,
        _ => return Err("unsupported hosted client archive".into()),
    };
    Ok((archive, receipts))
}

pub(super) struct Client {
    pub session: HostedSession,
    receipts: Receipts,
    pub archive: Archive,
    pub transport: Arc<dyn Transport>,
    storage: Storage,
    wrapping_key: Zeroizing<[u8; 32]>,
}
fn mls(error: impl std::fmt::Display) -> String {
    error.to_string()
}
pub(super) fn kind(content: &api::Content) -> HostedMessageKind {
    match content {
        api::Content::Text(_) => HostedMessageKind::Text,
        api::Content::Action(_) => HostedMessageKind::Action,
        api::Content::Notice(_) => HostedMessageKind::Notice,
        api::Content::Topic(_) => HostedMessageKind::Topic,
        api::Content::Nickname(_) => HostedMessageKind::Nickname,
        api::Content::Presence { .. } => HostedMessageKind::Presence,
        api::Content::File { .. } => HostedMessageKind::File,
    }
}
pub(super) fn validate(content: &api::Content) -> Result<(), String> {
    let ordinary = |text: &str, limit| {
        !text.is_empty()
            && text.len() <= limit
            && !text.chars().any(|c| {
                c.is_control()
                    && !matches!(
                        c,
                        '\n' | '\t' | '\u{2}' | '\u{3}' | '\u{f}' | '\u{16}' | '\u{1d}' | '\u{1f}'
                    )
            })
    };
    let valid = match content {
        api::Content::Text(s) | api::Content::Action(s) | api::Content::Notice(s) => {
            ordinary(s, 8192)
        }
        api::Content::Topic(s) => s.is_empty() || ordinary(s, 2048),
        api::Content::Nickname(s) => {
            !s.is_empty() && s.len() <= 128 && s.trim() == s && !s.chars().any(char::is_control)
        }
        api::Content::Presence { state, lease_secs } => {
            *lease_secs <= 3600
                && match state {
                    api::Presence::Away { reason } => {
                        reason.len() <= 256 && !reason.chars().any(char::is_control)
                    }
                    _ => true,
                }
        }
        api::Content::File { content_type, body } => {
            !content_type.is_empty()
                && content_type.len() <= 128
                && content_type.is_ascii()
                && !content_type.chars().any(char::is_control)
                && body.len() <= 512 * 1024
        }
    };
    if valid {
        Ok(())
    } else {
        Err("invalid hosted application content".into())
    }
}

impl Client {
    pub fn new(
        session: HostedSession,
        config: NewClient,
        storage: Storage,
        key: [u8; 32],
        transport: Arc<dyn Transport>,
    ) -> Result<Self, String> {
        let NewClient {
            alias,
            endpoint,
            phase,
            pending,
            access_code,
            join_link,
        } = config;
        let channel = session.policy().channel_id();
        let mut client = Self {
            session,
            receipts: Receipts::default(),
            transport,
            storage,
            wrapping_key: Zeroizing::new(key),
            archive: Archive {
                version: 2,
                channel,
                alias,
                endpoint,
                session: Vec::new(),
                phase,
                cursor: 0,
                head: [0; 32],
                last_time: 0,
                pending: vec![pending],
                refused: None,
                sent: BTreeMap::new(),
                events: Vec::new(),
                next_event: 1,
                topic: String::new(),
                nicknames: BTreeMap::new(),
                presence: BTreeMap::new(),
                presence_opt_in: false,
                access_code,
                join_link,
                issued_links: Vec::new(),
                seen: BTreeMap::new(),
            },
        };
        client.checkpoint()?;
        Ok(client)
    }
    pub fn stored_endpoint(bytes: &[u8]) -> Result<String, String> {
        let (archive, _) = decode_archive(bytes)?;
        Ok(archive.endpoint)
    }
    pub fn register_invite(
        &mut self,
        code: &HostedAccessCode,
        expires_at: u64,
        link: api::InviteLink,
    ) -> Result<(), String> {
        if self.archive.issued_links.len() >= 1000 {
            return Err("too many retained invitations".into());
        }
        self.stage_control(
            HostedPolicyChange::Invitation(code.verification_key(), expires_at),
            "",
        )?;
        self.archive.issued_links.push(link);
        self.checkpoint()
    }
    pub fn links(&self) -> Result<Vec<api::InviteLink>, String> {
        self.healthy()?;
        let mut links = self.archive.issued_links.clone();
        if !self.session.rules().mode(HostedMode::InviteOnly) || self.archive.access_code.is_some()
        {
            links.push(
                super::Link {
                    channel: self.archive.channel,
                    endpoint: self.archive.endpoint.clone(),
                    secret: self.archive.access_code.clone().unwrap_or_default(),
                    single_use: false,
                    expires_at: 0,
                }
                .export()?,
            );
        }
        Ok(links)
    }
    pub fn rotate_code(&mut self, code: &HostedAccessCode) -> Result<(), String> {
        let secret = code.export_secret().map_err(mls)?.to_vec();
        self.stage_control(
            HostedPolicyChange::AccessCode(Some(code.verification_key())),
            "",
        )?;
        self.archive.access_code = Some(secret);
        self.checkpoint()
    }
    pub fn clear_code(&mut self) -> Result<(), String> {
        self.stage_control(HostedPolicyChange::AccessCode(None), "")?;
        self.archive.access_code = None;
        self.checkpoint()
    }
    pub fn set_presence(&mut self, enabled: bool, state: api::Presence) -> Result<(), String> {
        let content = api::Content::Presence {
            state: if enabled {
                state
            } else {
                api::Presence::Invisible
            },
            lease_secs: if enabled { 120 } else { 0 },
        };
        self.queue_send(content)?;
        self.archive.presence_opt_in = enabled;
        self.checkpoint()
    }
    pub fn restore(
        bytes: &[u8],
        channel: [u8; 32],
        storage: Storage,
        key: [u8; 32],
        transport: Arc<dyn Transport>,
    ) -> Result<Self, String> {
        let (archive, receipts) = decode_archive(bytes)?;
        if !matches!(archive.version, 1 | 2)
            || receipts.outbox.len() > MAX_EVENTS
            || receipts.received.len() > MAX_EVENTS
            || receipts.received.values().any(|r| r.len() > 500)
            || archive.channel != channel
            || archive.events.len() > MAX_EVENTS
            || archive.pending.len() > MAX_PENDING
            || archive.sent.len() > MAX_EVENTS
            || archive.seen.len() > 100_000
        {
            return Err("hosted client archive outside bounds".into());
        }
        let session = HostedSession::restore(&key, &archive.session, channel).map_err(mls)?;
        Ok(Self {
            session,
            archive,
            receipts,
            storage,
            wrapping_key: Zeroizing::new(key),
            transport,
        })
    }
    fn healthy(&self) -> Result<(), String> {
        if self.storage.healthy() {
            Ok(())
        } else {
            Err("reopen hosted profile after storage failure".into())
        }
    }
    fn checkpoint(&mut self) -> Result<(), String> {
        let result = (|| {
            self.archive.session = self.session.persist(&self.wrapping_key).map_err(mls)?;
            self.archive.version = 2;
            let mut bytes = Zeroizing::new(
                postcard::to_allocvec(&self.archive).map_err(|_| "encode hosted client archive")?,
            );
            bytes.extend_from_slice(
                &postcard::to_allocvec(&self.receipts).map_err(|_| "encode hosted receipts")?,
            );
            self.storage.save(&bytes)
        })();
        if result.is_err() {
            self.storage.poison();
        }
        result
    }
    fn receive_room(&self) -> Result<(), String> {
        self.healthy()?;
        if self.archive.events.len() > MAX_EVENTS - 2 || self.receipts.outbox.len() >= MAX_EVENTS {
            return Err("archive pending channel events before continuing".into());
        }
        Ok(())
    }
    fn room(&self) -> Result<(), String> {
        self.healthy()?;
        if self.archive.pending.len() >= MAX_PENDING
            || self.archive.events.len() >= MAX_EVENTS
            || self.archive.sent.len() >= MAX_EVENTS
        {
            return Err("archive pending channel events before continuing".into());
        }
        Ok(())
    }
    fn emit(&mut self, accepted_at: u64, kind: api::EventKind) {
        let sequence = self.archive.next_event;
        self.archive.next_event += 1;
        self.archive.events.push(api::Event {
            sequence,
            channel: self.archive.channel,
            accepted_at,
            kind,
        });
    }
    pub fn queue_send(&mut self, content: api::Content) -> Result<[u8; 32], String> {
        self.room()?;
        validate(&content)?;
        if !matches!(self.archive.phase, Phase::Ready) {
            return Err("channel admission is not complete".into());
        }
        let mut id = [0; 32];
        rand::thread_rng().fill_bytes(&mut id);
        let application = Application {
            version: 1,
            id,
            content,
        };
        let payload = Zeroizing::new(
            postcard::to_allocvec(&application).map_err(|_| "encode hosted message")?,
        );
        let mut candidate = self.session.try_clone().map_err(mls)?;
        let message = candidate
            .send_kind(kind(&application.content), &payload)
            .map_err(mls)?;
        let wire = message.encode().map_err(mls)?;
        let expected = self
            .session
            .roster()
            .into_iter()
            .map(|member| member.pseudonym)
            .filter(|member| *member != self.session.member_id())
            .collect();
        self.session = candidate;
        self.archive.sent.insert(
            id,
            Sent {
                application: application.clone(),
                wire: wire.clone(),
                expected,
                accepted: None,
            },
        );
        self.archive.pending.push(Pending::Message {
            wire,
            application: application.clone(),
        });
        self.emit(
            now(),
            api::EventKind::Message {
                id,
                sender: self.session.member_id(),
                content: application.content,
                delivery: api::Delivery::Pending,
            },
        );
        self.checkpoint()?;
        Ok(id)
    }
    pub fn queue_control(
        &mut self,
        change: HostedPolicyChange,
        reason: &str,
    ) -> Result<(), String> {
        self.stage_control(change, reason)?;
        self.checkpoint()
    }
    fn stage_control(&mut self, change: HostedPolicyChange, reason: &str) -> Result<(), String> {
        self.room()?;
        if !matches!(self.archive.phase, Phase::Ready) {
            return Err("channel admission is not complete".into());
        }
        let mut candidate = self.session.try_clone().map_err(mls)?;
        let control = candidate.create_control(change, reason).map_err(mls)?;
        let encoded = control.encode().map_err(mls)?;
        self.session = candidate;
        self.archive.pending.push(Pending::Control {
            wire: encoded,
            reason: reason.into(),
        });
        Ok(())
    }
    /// Retry immutable wire after uncertainty. Acceptance never means any peer
    /// received it. Ordinary sends are applied only by ordered replay below.
    pub async fn flush_one(&mut self) -> Result<bool, String> {
        self.receive_room()?;
        let Some(pending) = self.archive.pending.first().cloned() else {
            return Ok(false);
        };
        let operation = match &pending {
            Pending::Create { policy, genesis } => wire::Operation::Create {
                policy: policy.clone(),
                genesis: genesis.clone(),
            },
            Pending::Membership { commit, info, .. } => {
                wire::Operation::Append(wire::Append::Membership {
                    commit: encode(commit),
                    info: encode(info),
                })
            }
            Pending::Message { wire, .. } => {
                wire::Operation::Append(wire::Append::Message(encode(wire)))
            }
            Pending::Control { wire, .. } => {
                wire::Operation::Append(wire::Append::Control(encode(wire)))
            }
        };
        let reply = self
            .transport
            .exchange(self.archive.channel, operation)
            .await?;
        if matches!(&reply, wire::Reply::Fault(fault) if matches!(fault.code, wire::FaultCode::Conflict | wire::FaultCode::Unauthorized | wire::FaultCode::Invalid))
        {
            self.archive.refused = Some(pending.id()?);
            self.checkpoint()?;
            if matches!(pending, Pending::Membership { joining: true, .. }) {
                self.retry_join().await?;
            }
            return Ok(false);
        }
        if let wire::Reply::Accepted(receipt) = &reply {
            use gcoms_channel_service::{content_id, RecordKind};
            let expected = match &pending {
                Pending::Membership { commit, info, .. } => {
                    content_id(RecordKind::Membership, commit, info)
                }
                Pending::Message { wire, .. } => content_id(RecordKind::Message, wire, &[]),
                Pending::Control { wire, .. } => content_id(RecordKind::Control, wire, &[]),
                _ => return Err("unexpected service acceptance".into()),
            };
            if receipt.id != expected || receipt.sequence == 0 || receipt.sequence > 1_000_000 {
                return Err("service acceptance does not match the outgoing operation".into());
            }
        }
        match (pending, reply) {
            (Pending::Create { genesis, .. }, wire::Reply::Created { anchor }) => {
                if gcoms_channel_service::genesis_hash(self.session.policy(), &decode(&genesis)?)
                    .map_err(mls)?
                    != anchor
                {
                    return Err("service returned a different genesis".into());
                }
                self.archive.phase = Phase::Ready;
                self.archive.head = anchor;
                self.archive.pending.remove(0);
                self.checkpoint()?;
            }
            (
                Pending::Membership {
                    commit,
                    joining: true,
                    ..
                },
                wire::Reply::Accepted(receipt),
            ) => {
                self.session.accept_join(&commit).map_err(mls)?;
                self.archive.phase = Phase::Ready;
                self.archive.join_link = None;
                self.archive.refused = None;
                // The newcomer cannot decrypt messages before this admission.
                self.archive.cursor = receipt.sequence;
                self.archive.head = receipt.record_hash;
                self.archive.pending.remove(0);
                self.checkpoint()?;
            }
            (Pending::Message { application, .. }, wire::Reply::Accepted(receipt)) => {
                self.archive
                    .sent
                    .get_mut(&application.id)
                    .ok_or("missing durable outgoing message")?
                    .accepted = Some(receipt);
                self.emit(
                    now(),
                    api::EventKind::Delivery {
                        id: application.id,
                        state: api::Delivery::ServiceAccepted {
                            sequence: receipt.sequence,
                        },
                    },
                );
                self.archive.pending.remove(0);
                self.checkpoint()?;
            }
            // Controls/rekeys must first replay all intervening accepted items;
            // their exact local operation is retained until that record appears.
            (
                Pending::Control { .. } | Pending::Membership { joining: false, .. },
                wire::Reply::Accepted(_),
            ) => {
                return Ok(false);
            }
            (_, reply) => return Err(format!("hosted append refused: {reply:?}")),
        }
        Ok(true)
    }
    async fn retry_join(&mut self) -> Result<(), String> {
        let link = super::Link::parse(
            self.archive
                .join_link
                .as_ref()
                .ok_or("missing durable admission secret")?,
        )?;
        let nickname = self
            .session
            .roster()
            .into_iter()
            .find(|member| member.pseudonym == self.session.member_id())
            .ok_or("missing admission identity")?
            .display_name;
        let prepared = self
            .session
            .try_clone()
            .map_err(mls)?
            .prepare_join_retry()
            .map_err(mls)?;
        let (session, commit) =
            super::prepare_join(self.transport.as_ref(), &link, prepared, &nickname).await?;
        let info = session.proposed_group_info().map_err(mls)?.to_vec();
        self.session = session;
        self.archive.pending[0] = Pending::Membership {
            commit,
            info,
            joining: true,
        };
        self.archive.refused = None;
        self.checkpoint()
    }
    /// Rebase only after explicit refusal and complete ordered replay. An
    /// uncertain transport response always retries the original exact bytes.
    fn recover_refused(&mut self) -> Result<(), String> {
        let Some(id) = self.archive.refused else {
            return Ok(());
        };
        let Some(index) = self
            .archive
            .pending
            .iter()
            .position(|p| p.id().ok() == Some(id))
        else {
            self.archive.refused = None;
            return self.checkpoint();
        };
        if !self.session.rules().pending_removals().is_empty() && self.session.active() {
            return Ok(());
        }
        self.receive_room()?;
        let pending = self.archive.pending[index].clone();
        let mut candidate = self.session.try_clone().map_err(mls)?;
        let replacement = match &pending {
            Pending::Message { application, .. } => {
                let bytes = Zeroizing::new(
                    postcard::to_allocvec(application).map_err(|_| "encode pending message")?,
                );
                candidate
                    .send_kind(kind(&application.content), &bytes)
                    .and_then(|m| m.encode())
                    .map(|wire| Pending::Message {
                        wire,
                        application: application.clone(),
                    })
            }
            Pending::Control { wire, reason } => {
                let control = HostedControl::decode(wire).map_err(mls)?;
                candidate
                    .create_control(control.change().clone(), reason)
                    .and_then(|c| c.encode())
                    .map(|wire| Pending::Control {
                        wire,
                        reason: reason.clone(),
                    })
            }
            Pending::Membership { joining: false, .. } => {
                // A competing commit has already cleared speculative MLS state
                // during replay. A fresh rekey is scheduled only if still needed.
                return Ok(());
            }
            _ => return Err("hosted channel creation or admission was refused".into()),
        };
        match replacement {
            Ok(replacement) => {
                if let Pending::Message { application, wire } = &replacement {
                    let sent = self
                        .archive
                        .sent
                        .get_mut(&application.id)
                        .ok_or("missing durable outgoing message")?;
                    sent.wire = wire.clone();
                    sent.expected = candidate
                        .roster()
                        .into_iter()
                        .map(|m| m.pseudonym)
                        .filter(|id| *id != candidate.member_id())
                        .collect();
                }
                self.session = candidate;
                self.archive.pending[index] = replacement;
            }
            Err(error) => {
                self.archive.pending.remove(index);
                match pending {
                    Pending::Message { application, .. } => {
                        self.archive.sent.remove(&application.id);
                        self.emit(
                            now(),
                            api::EventKind::Delivery {
                                id: application.id,
                                state: api::Delivery::Failed {
                                    reason: error.to_string(),
                                },
                            },
                        );
                    }
                    _ => self.emit(
                        now(),
                        api::EventKind::OperationFailed {
                            reason: error.to_string(),
                        },
                    ),
                }
            }
        }
        self.archive.refused = None;
        self.checkpoint()
    }
    pub fn events(&self, after: u64, limit: u16) -> Result<Vec<api::Event>, String> {
        self.healthy()?;
        if limit == 0 || limit > 256 {
            return Err("invalid hosted event page".into());
        }
        Ok(self
            .archive
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .take(limit as usize)
            .cloned()
            .collect())
    }
    pub fn commit_events(&mut self, through: u64) -> Result<(), String> {
        self.healthy()?;
        if through >= self.archive.next_event {
            return Err("cannot commit unseen hosted events".into());
        }
        self.archive.events.retain(|event| event.sequence > through);
        self.receipts.committed = self.receipts.committed.max(through);
        self.checkpoint()
    }
    async fn fetch_record(&self, item: wire::RecordItem) -> Result<Record, String> {
        let wire = match item {
            wire::RecordItem::Inline(wire) => wire,
            wire::RecordItem::Deferred {
                sequence,
                hash,
                wire_bytes,
            } => {
                if sequence == 0 || wire_bytes > wire::MAX_HTTP_BYTES {
                    return Err("invalid deferred record".into());
                }
                let query = wire::ReadQuery {
                    after: sequence - 1,
                    through: Some(sequence),
                    limit: 1,
                };
                let proof = self
                    .session
                    .read_proof(HostedReadScope::Records, query_hash(query), now() + 120)
                    .map_err(mls)?;
                let reply = self
                    .transport
                    .exchange(
                        self.archive.channel,
                        wire::Operation::Fetch {
                            query,
                            proof: encode(&proof.encode().map_err(mls)?),
                        },
                    )
                    .await?;
                let wire::Reply::Records(mut page) = reply else {
                    return Err(format!("record fetch refused: {reply:?}"));
                };
                if page.after != sequence - 1
                    || page.next != sequence
                    || page.head.sequence != sequence
                    || page.records.len() != 1
                    || page.head.hash != hash
                {
                    return Err("deferred record boundary mismatch".into());
                }
                let wire::RecordItem::Inline(wire) = page.records.remove(0) else {
                    return Err("deferred record remained unavailable".into());
                };
                if wire.len() != wire_bytes {
                    return Err("deferred record length mismatch".into());
                }
                let record = Record::decode(&decode(&wire)?).map_err(mls)?;
                if record.hash().map_err(mls)? != hash {
                    return Err("deferred record hash mismatch".into());
                }
                return Ok(record);
            }
        };
        Record::decode(&decode(&wire)?).map_err(mls)
    }
}

pub(super) fn change(change: &HostedPolicyChange) -> api::Change {
    match change {
        HostedPolicyChange::Mode(mode, enabled) => api::Change::Mode(
            match mode {
                HostedMode::Moderated => api::Mode::Moderated,
                HostedMode::InviteOnly => api::Mode::InviteOnly,
                HostedMode::TopicOperators => api::Mode::TopicOperators,
            },
            *enabled != 0,
        ),
        HostedPolicyChange::Operator(id, enabled) => api::Change::Operator(*id, *enabled != 0),
        HostedPolicyChange::Voice(id, enabled) => api::Change::Voice(*id, *enabled != 0),
        HostedPolicyChange::Role(id, role) => api::Change::Role(*id, role_value(*role)),
        HostedPolicyChange::AccessList(list, id, enabled) => api::Change::AccessList(
            match list {
                HostedAccessList::Ban => api::AccessList::Ban,
                HostedAccessList::Exemption => api::AccessList::Exemption,
                HostedAccessList::InviteException => api::AccessList::InviteException,
            },
            *id,
            *enabled != 0,
        ),
        HostedPolicyChange::Capacity(n) => api::Change::Capacity(*n),
        HostedPolicyChange::Discovery(discovery) => {
            api::Change::Discovery(discovery_value(*discovery))
        }
        HostedPolicyChange::Transfer(id) => api::Change::Transfer(*id),
        HostedPolicyChange::Kick(id) => api::Change::Kick(*id),
        HostedPolicyChange::Leave => api::Change::Leave,
        HostedPolicyChange::Close => api::Change::Close,
        HostedPolicyChange::Invitation(verifier, expiry) => api::Change::Invitation {
            verifier: *verifier,
            expires_at: *expiry,
        },
        HostedPolicyChange::AccessCode(verifier) => api::Change::AccessCode {
            verifier: *verifier,
        },
    }
}
fn role_value(role: HostedRole) -> api::Role {
    match role {
        HostedRole::Owner => api::Role::Owner,
        HostedRole::Operator => api::Role::Operator,
        HostedRole::Voice => api::Role::Voice,
        HostedRole::Member => api::Role::Member,
    }
}
fn discovery_value(discovery: HostedDiscovery) -> api::Discovery {
    match discovery {
        HostedDiscovery::Public => api::Discovery::Public,
        HostedDiscovery::Private => api::Discovery::Private,
        HostedDiscovery::Secret => api::Discovery::Secret,
    }
}

impl Client {
    pub fn view(&self) -> api::Channel {
        let rules = self.session.rules();
        let members = self
            .session
            .roster()
            .into_iter()
            .filter(|member| !rules.departing(member.pseudonym))
            .map(|member| {
                let id = member.pseudonym;
                api::Member {
                    id,
                    nickname: self
                        .archive
                        .nicknames
                        .get(&id)
                        .cloned()
                        .unwrap_or(member.display_name),
                    role: role_value(rules.role(id)),
                    operator: rules.operator(id),
                    voice: rules.voiced(id),
                    presence: self
                        .archive
                        .presence
                        .get(&id)
                        .filter(|(_, expiry)| *expiry > now())
                        .map_or(api::Presence::Unknown, |(state, _)| state.clone()),
                }
            })
            .collect();
        api::Channel {
            id: self.archive.channel,
            alias: self.archive.alias.clone(),
            endpoint: self.archive.endpoint.clone(),
            self_member: self.session.member_id(),
            epoch: self.session.epoch(),
            revision: rules.revision(),
            active: matches!(self.archive.phase, Phase::Ready) && self.session.active(),
            topic: self.archive.topic.clone(),
            members,
            capacity: rules.capacity(),
            bans: rules.list(HostedAccessList::Ban).to_vec(),
            exemptions: rules.list(HostedAccessList::Exemption).to_vec(),
            invite_exceptions: rules.list(HostedAccessList::InviteException).to_vec(),
            moderated: rules.mode(HostedMode::Moderated),
            invite_only: rules.mode(HostedMode::InviteOnly),
            topic_operators: rules.mode(HostedMode::TopicOperators),
            discovery: discovery_value(rules.discovery()),
            cursor: self.archive.cursor,
            pending: self.archive.pending.len(),
            presence_opt_in: self.archive.presence_opt_in,
        }
    }
    fn accept_content(&mut self, sender: [u8; 32], application: &Application, accepted_at: u64) {
        match &application.content {
            api::Content::Topic(topic) => self.archive.topic = topic.clone(),
            api::Content::Nickname(name) => {
                self.archive.nicknames.insert(sender, name.clone());
            }
            api::Content::Presence { state, lease_secs } => {
                if matches!(state, api::Presence::Invisible | api::Presence::Unknown) {
                    self.archive.presence.remove(&sender);
                } else {
                    self.archive.presence.insert(
                        sender,
                        (
                            state.clone(),
                            accepted_at.saturating_add(u64::from(*lease_secs)),
                        ),
                    );
                }
            }
            _ => {}
        }
    }
    fn apply_record(&mut self, record: &Record) -> Result<(), String> {
        self.receive_room()?;
        let result = self.apply_record_inner(record);
        if result.is_err() {
            self.storage.poison();
        }
        result
    }
    fn apply_record_inner(&mut self, record: &Record) -> Result<(), String> {
        if record.sequence != self.archive.cursor + 1
            || record.previous != self.archive.head
            || record.accepted_at < self.archive.last_time
            || record.accepted_at > now().saturating_add(120)
        {
            return Err("hosted transcript prefix mismatch".into());
        }
        if let Some((commit, info)) = record.membership() {
            let before = self.session.roster();
            let own = self.archive.pending.iter().position(|pending| matches!(pending, Pending::Membership { commit: ours, info: our_info, joining: false } if ours == commit && our_info == info));
            if let Some(index) = own {
                self.session.accept_rekey(commit).map_err(mls)?;
                self.archive.pending.remove(index);
            } else {
                match self.session.receive(commit, record.accepted_at) {
                    Ok(gcoms_mls::ReceiveOutcome::CommitMerged { .. }) => {}
                    Err(gcoms_mls::MlsError::Removed) => {
                        self.archive.phase = Phase::Removed;
                        self.emit(record.accepted_at, api::EventKind::Removed);
                    }
                    Ok(_) => return Err("membership record was not a commit".into()),
                    Err(error) => return Err(error.to_string()),
                }
            }
            self.session.verify_group_info(info).map_err(mls)?;
            if own.is_none() {
                self.archive.pending.retain(|pending| {
                    !matches!(pending, Pending::Membership { joining: false, .. })
                });
            }
            for member in self.session.roster() {
                if !before.iter().any(|old| old.pseudonym == member.pseudonym) {
                    self.emit(
                        record.accepted_at,
                        api::EventKind::Joined {
                            member: member.pseudonym,
                            nickname: member.display_name,
                        },
                    );
                }
            }
        } else if let Some(control) = record.control().map_err(mls)? {
            let encoded = control.encode().map_err(mls)?;
            let own = self.archive.pending.iter().position(
                |pending| matches!(pending, Pending::Control { wire, .. } if *wire == encoded),
            );
            let fallback = own.and_then(|index| match &self.archive.pending[index] {
                Pending::Control { reason, .. } => Some(reason.clone()),
                _ => None,
            });
            let event = self.session.apply_control(&control).map_err(mls)?;
            if let Some(index) = own {
                self.archive.pending.remove(index);
            }
            self.emit(
                record.accepted_at,
                api::EventKind::Activity {
                    actor: event.actor,
                    change: change(&event.change),
                    reason: event.reason.or(fallback),
                },
            );
        } else if let Some(message) = record.message().map_err(mls)? {
            let sender = message.member_id();
            let result: Result<Option<Application>, String> = if sender == self.session.member_id()
            {
                self.session
                    .verify_hosted(&message)
                    .map_err(mls)
                    .and_then(|_| {
                        let encoded = message.encode().map_err(mls)?;
                        self.archive
                            .sent
                            .values()
                            .find(|sent| sent.wire == encoded)
                            .map(|sent| Some(sent.application.clone()))
                            .ok_or_else(|| "outgoing content unavailable".into())
                    })
            } else {
                self.session
                    .receive_hosted(&message)
                    .map_err(mls)
                    .and_then(|payload| {
                        let payload = Zeroizing::new(payload);
                        let application: Application = postcard::from_bytes(&payload)
                            .map_err(|_| "invalid application envelope")?;
                        if application.version != 1 || kind(&application.content) != message.kind()
                        {
                            return Err("application class mismatch".into());
                        }
                        validate(&application.content)?;
                        Ok(Some(application))
                    })
            };
            match result {
                Ok(Some(application)) => {
                    if sender == self.session.member_id() {
                        let receipt = wire::Acceptance {
                            sequence: record.sequence,
                            id: record.id(),
                            record_hash: record.hash().map_err(mls)?,
                        };
                        if let Some(sent) = self.archive.sent.get_mut(&application.id) {
                            sent.accepted = Some(receipt);
                        }
                        self.archive.pending.retain(|pending| !matches!(pending, Pending::Message { application: ours, .. } if ours.id == application.id));
                        self.emit(
                            record.accepted_at,
                            api::EventKind::Delivery {
                                id: application.id,
                                state: api::Delivery::ServiceAccepted {
                                    sequence: record.sequence,
                                },
                            },
                        );
                    }
                    use sha2::{Digest, Sha256};
                    let digest: [u8; 32] = Sha256::digest(
                        postcard::to_allocvec(&application.content)
                            .map_err(|_| "encode application digest")?,
                    )
                    .into();
                    let key = (sender, application.id);
                    let receipt_valid = self
                        .archive
                        .seen
                        .get(&key)
                        .is_none_or(|previous| *previous == digest);
                    match self.archive.seen.get(&key) {
                        Some(previous) if *previous != digest => self.emit(
                            record.accepted_at,
                            api::EventKind::Unavailable {
                                sender,
                                reason: "message identity reused with different content".into(),
                            },
                        ),
                        Some(_) => {}
                        None => {
                            self.archive.seen.insert(key, digest);
                            if self.archive.seen.len() > 10_000 {
                                self.archive.seen.pop_first();
                            }
                            self.accept_content(sender, &application, record.accepted_at);
                            if sender != self.session.member_id() {
                                self.emit(
                                    record.accepted_at,
                                    api::EventKind::Message {
                                        id: application.id,
                                        sender,
                                        content: application.content,
                                        delivery: api::Delivery::Delivered,
                                    },
                                );
                            }
                        }
                    }
                    if receipt_valid && sender != self.session.member_id() {
                        let receipt = self
                            .session
                            .receipt(sender, record.id(), record.sequence)
                            .map_err(mls)?;
                        self.receipts
                            .outbox
                            .push((self.archive.next_event - 1, receipt.encode().map_err(mls)?));
                    }
                }
                Ok(None) => {}
                Err(_) => self.emit(
                    record.accepted_at,
                    api::EventKind::Unavailable {
                        sender,
                        reason: "message could not be authenticated or decoded".into(),
                    },
                ),
            }
        } else {
            return Err("unsupported hosted transcript record".into());
        }
        self.archive.cursor = record.sequence;
        self.archive.head = record.hash().map_err(mls)?;
        self.archive.last_time = record.accepted_at;
        // Events become visible to consumers only after this durable boundary.
        self.checkpoint()
    }
    pub async fn sync_page(&mut self) -> Result<bool, String> {
        self.receive_room()?;
        if !matches!(self.archive.phase, Phase::Ready | Phase::Removed) {
            return Ok(false);
        }
        let query = wire::ReadQuery {
            after: self.archive.cursor,
            through: None,
            limit: 32,
        };
        let proof = self
            .session
            .read_proof(HostedReadScope::Records, query_hash(query), now() + 120)
            .map_err(mls)?;
        let reply = self
            .transport
            .exchange(
                self.archive.channel,
                wire::Operation::Read {
                    query,
                    proof: encode(&proof.encode().map_err(mls)?),
                },
            )
            .await?;
        let wire::Reply::Records(page) = reply else {
            return Err(format!("hosted replay refused: {reply:?}"));
        };
        if page.after != self.archive.cursor
            || page.next < page.after
            || page.next > page.head.sequence
            || page.records.len() as u64 != page.next - page.after
            || page.records.len() > 32
            || page.head.sequence > 1_000_000
        {
            return Err("inconsistent hosted replay page".into());
        }
        if page.records.is_empty() && page.after != page.head.sequence {
            return Err("hosted replay made no progress".into());
        }
        let progressed = !page.records.is_empty();
        for item in page.records {
            let record = self.fetch_record(item).await?;
            self.apply_record(&record)?;
        }
        if self.archive.cursor == page.head.sequence && self.archive.head != page.head.hash {
            return Err("hosted replay head mismatch".into());
        }
        if self.session.active()
            && !self.session.rules().banned(self.session.member_id())
            && self.archive.pending.len() < MAX_PENDING
            && !self.session.rules().pending_removals().is_empty()
            && !self
                .archive
                .pending
                .iter()
                .any(|p| matches!(p, Pending::Membership { .. }))
        {
            let commit = self.session.prepare_rekey().map_err(mls)?;
            let info = self.session.proposed_group_info().map_err(mls)?.to_vec();
            self.archive.pending.insert(
                0,
                Pending::Membership {
                    commit,
                    info,
                    joining: false,
                },
            );
            self.checkpoint()?;
        }
        if self.archive.cursor == page.head.sequence {
            self.recover_refused()?;
        }
        self.sync_receipts().await?;
        Ok(progressed)
    }
}

impl Client {
    async fn sync_receipts(&mut self) -> Result<(), String> {
        let outgoing: Vec<_> = self
            .receipts
            .outbox
            .iter()
            .take_while(|(event, _)| *event <= self.receipts.committed)
            .take(16)
            .map(|(_, bytes)| encode(bytes))
            .collect();
        if !outgoing.is_empty() {
            match self
                .transport
                .exchange(
                    self.archive.channel,
                    wire::Operation::Acknowledge {
                        receipts: outgoing.clone(),
                    },
                )
                .await?
            {
                wire::Reply::Acknowledged => {
                    self.receipts.outbox.drain(..outgoing.len());
                    self.checkpoint()?;
                }
                reply => return Err(format!("recipient receipt storage refused: {reply:?}")),
            }
        }
        if self.archive.sent.is_empty() {
            return Ok(());
        }
        let query = wire::ReadQuery {
            after: self.receipts.cursor,
            through: None,
            limit: 32,
        };
        let proof = self
            .session
            .read_proof(HostedReadScope::Receipts, query_hash(query), now() + 120)
            .map_err(mls)?;
        let reply = self
            .transport
            .exchange(
                self.archive.channel,
                wire::Operation::Receipts {
                    query,
                    proof: encode(&proof.encode().map_err(mls)?),
                },
            )
            .await?;
        let wire::Reply::Receipts {
            after,
            next,
            receipts,
        } = reply
        else {
            return Err(format!("receipt recovery refused: {reply:?}"));
        };
        if after != query.after
            || next < after
            || next - after != receipts.len() as u64
            || receipts.len() > 32
        {
            return Err("invalid recipient receipt page".into());
        }
        for bytes in &receipts {
            let receipt = HostedReceipt::decode(&decode(bytes)?).map_err(mls)?;
            receipt.verify(self.archive.channel).map_err(mls)?;
            if receipt.sender() != self.session.member_id() {
                return Err("receipt belongs to another sender".into());
            }
            for (id, sent) in &self.archive.sent {
                if sent.accepted.is_some_and(|a| {
                    a.id == receipt.record_id() && a.sequence == receipt.sequence()
                }) && sent.expected.contains(&receipt.recipient())
                {
                    let received = self.receipts.received.entry(*id).or_default();
                    if !received.contains(&receipt.recipient()) {
                        received.push(receipt.recipient());
                    }
                }
            }
        }
        let completed: Vec<_> = self
            .archive
            .sent
            .iter()
            .filter(|(id, sent)| {
                sent.accepted
                    .is_some_and(|a| a.sequence <= self.archive.cursor)
                    && sent.expected.iter().all(|member| {
                        self.receipts
                            .received
                            .get(*id)
                            .is_some_and(|r| r.contains(member))
                    })
            })
            .map(|(id, sent)| (*id, !sent.expected.is_empty()))
            .take(MAX_EVENTS.saturating_sub(self.archive.events.len()))
            .collect();
        for (id, has_recipients) in &completed {
            if *has_recipients {
                self.emit(
                    now(),
                    api::EventKind::Delivery {
                        id: *id,
                        state: api::Delivery::Delivered,
                    },
                );
            }
            self.archive.sent.remove(id);
            self.receipts.received.remove(id);
        }
        self.receipts.cursor = next;
        if next != after || !completed.is_empty() {
            self.checkpoint()?;
        }
        Ok(())
    }
}
