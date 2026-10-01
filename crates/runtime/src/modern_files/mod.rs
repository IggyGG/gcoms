//! Separate typed file profile for hosted channels and explicitly authorized
//! root contacts. The cache stores verified encrypted pieces; transports own
//! authentication. Legacy channel/PM cache identities are never reinterpreted.
mod storage;
use gcoms_file_transfer::swarm::{self, Action, Cache, Engine, Peer, SendOutcome};
use gcoms_sdk::{
    hosted_client as h, sharing as legacy, sharing_v2 as api, ApplicationMessage, ContactCard,
    GcClient, SdkError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{watch, Mutex as AsyncMutex};
use zeroize::Zeroizing;

type Id = legacy::ShareId;
type Member = [u8; 32];
const CONTACT_SEND_CONCURRENCY: usize = 8;
const CONTACT_QUEUE_LIMIT: usize = 128;
pub(crate) type ClientFactory = Arc<dyn Fn() -> Option<Arc<dyn GcClient>> + Send + Sync>;
fn error(e: impl std::fmt::Display) -> SdkError {
    SdkError::Runtime(e.to_string())
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn hash(bytes: &[u8]) -> Member {
    Sha256::digest(bytes).into()
}
fn cache_scope(scope: &api::Scope, own: Member) -> swarm::Scope {
    let mut bytes = b"gcoms.files.v2/scope\0".to_vec();
    let participants = match scope {
        api::Scope::Hosted { channel } => {
            bytes.push(0);
            bytes.extend(channel);
            vec![]
        }
        api::Scope::Contact { peer } => {
            let mut p = vec![own, *peer];
            p.sort();
            bytes.push(1);
            for id in &p {
                bytes.extend(id);
            }
            p
        }
    };
    swarm::Scope {
        channel: hash(&bytes),
        participants,
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    scope: api::Scope,
    publisher: Member,
    own: bool,
    publish: bool,
    uploaded: u32,
    published: bool,
    publication_id: Member,
    completion_id: Member,
    completion_sent: bool,
    retry_at: u64,
    error: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Metadata {
    version: u8,
    config: legacy::CacheConfig,
    entries: BTreeMap<Id, Entry>,
}
impl Default for Metadata {
    fn default() -> Self {
        Self {
            version: 2,
            config: Default::default(),
            entries: BTreeMap::new(),
        }
    }
}
struct ContactSend {
    action: Action,
    task: Option<tokio::task::JoinHandle<Result<(), SdkError>>>,
}
impl Drop for ContactSend {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
struct Backend {
    engine: Engine,
    metadata: Metadata,
    store: storage::Store,
    contacts: BTreeMap<Member, ContactCard>,
    hosted: BTreeMap<Member, h::Channel>,
    own: Member,
    pending: VecDeque<Action>,
    contact_sends: Vec<ContactSend>,
    inbox_cursor: u64,
    enabled: bool,
    next_file: Option<Id>,
    error: Option<String>,
}
pub struct ModernFileService {
    backend: AsyncMutex<Option<Backend>>,
    factory: ClientFactory,
    snapshot: Mutex<api::Snapshot>,
    interrupt: tokio::sync::Notify,
    active: std::sync::atomic::AtomicBool,
    stop: watch::Sender<bool>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl ModernFileService {
    pub async fn open(
        path: &Path,
        key: [u8; 32],
        factory: ClientFactory,
    ) -> Result<Arc<Self>, SdkError> {
        let sdk = factory().ok_or(SdkError::ConnectionClosed)?;
        let own = hash(
            &sdk.resolve_contact_identity(&sdk.identity().contact_card)
                .await?,
        );
        let path = path.to_owned();
        let backend = tokio::task::spawn_blocking(move || {
            let cache = Cache::open(&path, key, Default::default()).map_err(error)?;
            let mut key_bytes = Zeroizing::new(b"gcoms.files.v2/metadata\0".to_vec());
            key_bytes.extend(key);
            let (store, metadata) =
                storage::Store::open(path.join("profile.v2"), hash(&key_bytes))?;
            let mut engine = Engine::for_contacts(cache);
            engine.cache.config = swarm::CacheConfig {
                quota_bytes: metadata.config.quota_bytes,
                retention_secs: metadata.config.retention_secs,
            };
            // A cache write may precede its metadata checkpoint on a crash. Only
            // a replayed authenticated offer can attach that orphan to a scope.
            for (id, entry) in &metadata.entries {
                if let Ok(state) = engine.cache.get(*id) {
                    if state.manifest.scope != cache_scope(&entry.scope, own) {
                        return Err(error("modern file scope mismatch"));
                    }
                }
            }
            Ok::<_, SdkError>(Backend {
                engine,
                metadata,
                store,
                contacts: BTreeMap::new(),
                hosted: BTreeMap::new(),
                own,
                pending: VecDeque::new(),
                contact_sends: Vec::new(),
                inbox_cursor: 0,
                enabled: true,
                next_file: None,
                error: None,
            })
        })
        .await
        .map_err(error)??;
        let service = Arc::new(Self {
            snapshot: Mutex::new(backend.snapshot()),
            interrupt: tokio::sync::Notify::new(),
            active: std::sync::atomic::AtomicBool::new(true),
            backend: AsyncMutex::new(Some(backend)),
            factory,
            stop: watch::channel(false).0,
            worker: Mutex::new(None),
        });
        let weak = Arc::downgrade(&service);
        let mut stopped = service.stop.subscribe();
        *service.worker.lock().map_err(error)? = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { _ = stopped.changed() => break, _ = interval.tick() => {} }
                let Some(service) = weak.upgrade() else { break };
                let Some(sdk) = (service.factory)() else {
                    break;
                };
                let mut backend = tokio::select! { _ = stopped.changed() => break, b = service.backend.lock() => b };
                let Some(b) = backend.as_mut() else { break };
                if let Err(e) = b.finish_contact_sends().await {
                    b.error = Some(e.to_string());
                }
                if !b.enabled || b.store.check().is_err() {
                    continue;
                }
                // Keep retryable network failures local to their transfer. The
                // independently persisted cache is the resumption authority.
                // Requests can interrupt discovery and hosted reads. Contact
                // sends and their engine tokens survive that interruption;
                // clearing them would admit duplicate durable retries.
                tokio::select! { _ = stopped.changed() => break, _ = service.interrupt.notified() => {}, result = b.tick(sdk.clone()) => { if let Err(e) = result { b.error = Some(e.to_string()); } } };
                *service.snapshot.lock().unwrap_or_else(|e| e.into_inner()) = b.snapshot();
            }
        }));
        Ok(service)
    }
    pub async fn shutdown(&self) {
        self.stop.send_replace(true);
        let task = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            let _ = task.await;
        }
        self.backend.lock().await.take();
    }
    pub async fn request(&self, request: api::Request) -> Result<api::Reply, SdkError> {
        request.validate()?;
        if *self.stop.borrow() {
            return Err(SdkError::ConnectionClosed);
        }
        if matches!(request, api::Request::List) {
            if !self.active.load(std::sync::atomic::Ordering::Acquire) {
                return Err(SdkError::PermissionDenied);
            }
            return Ok(api::Reply::Snapshot(
                self.snapshot.lock().map_err(error)?.clone(),
            ));
        }
        let sdk = (self.factory)().ok_or(SdkError::ConnectionClosed)?;
        // Validate cards before replacing any authority. Invalid replacements
        // cannot partly revoke or grant the registered set.
        let contacts = if let api::Request::Contacts(cards) = &request {
            let mut contacts = BTreeMap::new();
            for card in cards {
                let id = hash(&sdk.resolve_contact_identity(card).await?);
                contacts.insert(id, card.clone());
            }
            Some(contacts)
        } else {
            None
        };
        self.interrupt.notify_waiters();
        let mut backend = self.backend.lock().await;
        let b = backend.as_mut().ok_or(SdkError::ConnectionClosed)?;
        b.store.check()?;
        if let api::Request::SetEnabled(enabled) = request {
            b.enabled = enabled;
            if !enabled {
                b.pending.clear();
                b.contact_sends.clear();
                b.engine.clear_members();
            }
            self.active
                .store(enabled, std::sync::atomic::Ordering::Release);
        } else if !b.enabled {
            return Err(SdkError::PermissionDenied);
        }
        b.refresh(sdk.as_ref()).await?;
        match request {
            api::Request::List | api::Request::SetEnabled(_) => {}
            api::Request::Contacts(_) => {
                let contacts = contacts.unwrap();
                if contacts.contains_key(&b.own) {
                    return Err(SdkError::PermissionDenied);
                }
                b.contacts = contacts;
                b.members();
                b.pending.retain(|a| b.engine.action_allowed(a));
                b.contact_sends
                    .retain(|send| b.engine.action_allowed(&send.action));
            }
            api::Request::Prepare {
                id,
                scope,
                name,
                size_bytes,
            } => {
                let publisher = b.authorize_scope(&scope)?;
                if let Some(previous) = b.metadata.entries.get(&id) {
                    if previous.scope != scope || !previous.own {
                        return Err(error("file identity conflict"));
                    }
                } else {
                    if b.metadata.entries.len() >= 256 {
                        return Err(error("file profile is full"));
                    }
                    b.metadata.entries.insert(
                        id,
                        Entry {
                            scope: scope.clone(),
                            publisher,
                            own: true,
                            publish: false,
                            uploaded: 0,
                            published: false,
                            publication_id: rand::random(),
                            completion_id: rand::random(),
                            completion_sent: false,
                            retry_at: 0,
                            error: None,
                        },
                    );
                    b.save()?;
                }
                b.engine
                    .cache
                    .begin_import(id, cache_scope(&scope, b.own), name, size_bytes, now())
                    .map_err(error)?;
            }
            api::Request::WritePiece { id, piece, bytes } => {
                b.authorize(id)?;
                if !b.metadata.entries[&id].own {
                    return Err(SdkError::PermissionDenied);
                }
                b.engine
                    .cache
                    .import_piece(id, piece, &Zeroizing::new(bytes))
                    .map_err(error)?;
            }
            api::Request::Commit { id } => {
                b.authorize(id)?;
                if !b.metadata.entries[&id].own {
                    return Err(SdkError::PermissionDenied);
                }
                let manifest = b.engine.cache.finish_import(id, now()).map_err(error)?;
                b.metadata.entries.get_mut(&id).unwrap().publish = true;
                b.save()?;
                if let api::Scope::Contact { peer } = b.metadata.entries[&id].scope {
                    if b.queued_contacts() < CONTACT_QUEUE_LIMIT {
                        b.pending.push_back(Action::offer(
                            Peer {
                                channel: manifest.scope.channel,
                                member: peer,
                            },
                            manifest,
                        ));
                    }
                }
            }
            api::Request::Accept { id } | api::Request::Resume { id } => {
                b.authorize(id)?;
                match b.metadata.entries[&id].scope {
                    api::Scope::Contact { .. } => b.engine.accept(id, now()),
                    _ => b.engine.cache.accept(id, now()),
                }
                .map_err(error)?;
                b.metadata.entries.get_mut(&id).unwrap().retry_at = 0;
                b.save()?;
            }
            api::Request::Pause { id } => {
                b.engine.pause(id).map_err(error)?;
            }
            api::Request::Cancel { id } => {
                b.engine.cancel(id).map_err(error)?;
            }
            api::Request::ReadPiece { id, piece } => {
                return b
                    .engine
                    .cache
                    .export_piece(id, piece)
                    .map(api::Reply::Piece)
                    .map_err(error);
            }
            api::Request::Configure(config) => {
                b.metadata.config = config.clone();
                b.save()?;
                b.engine.cache.config = swarm::CacheConfig {
                    quota_bytes: config.quota_bytes,
                    retention_secs: config.retention_secs,
                };
            }
        }
        let snapshot = b.snapshot();
        *self.snapshot.lock().map_err(error)? = snapshot.clone();
        Ok(api::Reply::Snapshot(snapshot))
    }
}
impl Drop for ModernFileService {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
impl Backend {
    fn queued_contacts(&self) -> usize {
        self.pending.len() + self.contact_sends.len()
    }
    async fn finish_contact_sends(&mut self) -> Result<(), SdkError> {
        while let Some(index) = self
            .contact_sends
            .iter()
            .position(|send| send.task.as_ref().is_some_and(|task| task.is_finished()))
        {
            let mut send = self.contact_sends.swap_remove(index);
            let result = send
                .task
                .take()
                .unwrap()
                .await
                .unwrap_or_else(|e| Err(error(e)));
            if let Err(e) = &result {
                #[cfg(test)]
                eprintln!("modern contact send failure: {e}");
                self.error = Some(e.to_string());
            }
            if result.is_ok() {
                if let swarm::Message::Offers { manifests, .. } = &send.action.message {
                    let mut changed = false;
                    for manifest in manifests {
                        if let Some(entry) = self.metadata.entries.get_mut(&manifest.id) {
                            if entry.own && entry.publish && !entry.published {
                                entry.published = true;
                                changed = true;
                            }
                        }
                    }
                    if changed {
                        self.save()?;
                    }
                }
            }
            self.engine.send_finished(
                send.action.send_token(),
                if result.is_ok() {
                    SendOutcome::HopAccepted
                } else {
                    SendOutcome::OutcomeUnknown
                },
                now(),
            );
        }
        Ok(())
    }
    fn save(&mut self) -> Result<(), SdkError> {
        self.store.save(&self.metadata)
    }
    async fn refresh(&mut self, sdk: &dyn GcClient) -> Result<(), SdkError> {
        self.hosted = match sdk.hosted_channels(h::Request::List).await {
            Ok(h::Reply::Channels(channels)) => channels
                .into_iter()
                .filter(|c| c.active)
                .map(|c| (c.id, c))
                .collect(),
            Err(SdkError::PermissionDenied) => BTreeMap::new(),
            Err(e) => return Err(e),
            _ => return Err(error("unexpected hosted file roster")),
        };
        self.members();
        Ok(())
    }
    fn members(&mut self) {
        // Only contact conversations use peer swarming. Hosted pieces are
        // service reads and never claim membership in a legacy channel.
        let active: BTreeMap<_, _> = self
            .contacts
            .keys()
            .map(|peer| {
                (
                    cache_scope(&api::Scope::Contact { peer: *peer }, self.own).channel,
                    *peer,
                )
            })
            .collect();
        let old: Vec<_> = self
            .metadata
            .entries
            .values()
            .filter_map(|e| match e.scope {
                api::Scope::Contact { .. } => Some(cache_scope(&e.scope, self.own).channel),
                _ => None,
            })
            .collect();
        for scope in old {
            if !active.contains_key(&scope) {
                self.engine.set_members(scope, self.own, []);
            }
        }
        for (scope, peer) in active {
            self.engine.set_members(scope, self.own, [self.own, peer]);
        }
    }
    fn authorize_scope(&self, scope: &api::Scope) -> Result<Member, SdkError> {
        match scope {
            api::Scope::Hosted { channel } => self
                .hosted
                .get(channel)
                .map(|c| c.self_member)
                .ok_or(SdkError::PermissionDenied),
            api::Scope::Contact { peer } if self.contacts.contains_key(peer) => Ok(self.own),
            _ => Err(SdkError::PermissionDenied),
        }
    }
    fn authorize(&self, id: Id) -> Result<Member, SdkError> {
        self.authorize_scope(
            &self
                .metadata
                .entries
                .get(&id)
                .ok_or_else(|| error("unknown file"))?
                .scope,
        )
    }
    fn snapshot(&self) -> api::Snapshot {
        api::Snapshot {
            files: self
                .engine
                .views()
                .into_iter()
                .filter_map(|view| {
                    let e = self.metadata.entries.get(&view.state.manifest.id)?;
                    let allowed = self.authorize_scope(&e.scope).is_ok();
                    let hosted = matches!(e.scope, api::Scope::Hosted { .. });
                    Some(api::FileInfo {
                        id: view.state.manifest.id,
                        scope: e.scope.clone(),
                        name: view.state.manifest.name.clone(),
                        size_bytes: view.state.manifest.size,
                        verified_bytes: view.state.verified_bytes(),
                        status: match view.state.status {
                            swarm::Status::Offered => legacy::Status::Offered,
                            swarm::Status::Importing => legacy::Status::Importing,
                            swarm::Status::Downloading
                                if !allowed || (!hosted && view.waiting_for_peers) =>
                            {
                                legacy::Status::WaitingForPeers
                            }
                            swarm::Status::Downloading => legacy::Status::Downloading,
                            swarm::Status::Paused => legacy::Status::Paused,
                            swarm::Status::Complete
                                if hosted && e.own && e.publish && !e.published =>
                            {
                                legacy::Status::Importing
                            }
                            swarm::Status::Complete => legacy::Status::Complete,
                            swarm::Status::Cancelled => legacy::Status::Cancelled,
                            swarm::Status::Failed => legacy::Status::Failed,
                        },
                        sources: if hosted {
                            u16::from(allowed)
                        } else {
                            view.sources as u16
                        },
                        verified_sources: if hosted {
                            u16::from(view.state.verified_bytes() > 0)
                        } else {
                            view.verified_sources as u16
                        },
                        completed_by: view.delivered as u16,
                        error: e.error.clone().or(view.state.error),
                    })
                })
                .collect(),
            config: self.metadata.config.clone(),
            used_bytes: self.engine.cache.used(),
            error: self.error.clone(),
        }
    }
    async fn tick(&mut self, sdk: Arc<dyn GcClient>) -> Result<(), SdkError> {
        self.engine.cache.expire(now()).map_err(error)?;
        self.metadata
            .entries
            .retain(|id, _| self.engine.cache.get(*id).is_ok());
        self.refresh(sdk.as_ref()).await?;
        let hosted_error = self.receive_hosted(sdk.as_ref()).await.err();
        let contact_error = self.receive_contacts(sdk.as_ref()).await.err();
        self.error = hosted_error.or(contact_error).map(|e| e.to_string());
        self.store.check()?;
        for (id, entry) in &self.metadata.entries {
            if let api::Scope::Contact { peer } = entry.scope {
                if entry.own && entry.publish && !entry.published && self.contacts.contains_key(&peer)
                    && self.queued_contacts() < CONTACT_QUEUE_LIMIT && !self.pending.iter().chain(self.contact_sends.iter().map(|send| &send.action)).any(|a| matches!(&a.message, swarm::Message::Offers { manifests, .. } if manifests.iter().any(|m| m.id == *id))) {
                    if let Ok(state) = self.engine.cache.get(*id) {
                        if state.status == swarm::Status::Complete {
                            self.pending.push_back(Action::offer(Peer { channel: state.manifest.scope.channel, member: peer }, state.manifest.clone()));
                        }
                    }
                }
            }
        }
        let actions = self.engine.tick(now()).map_err(error)?;
        for action in actions {
            if self.queued_contacts() < CONTACT_QUEUE_LIMIT {
                self.pending.push_back(action);
            } else {
                self.engine.send_finished(
                    action.send_token(),
                    SendOutcome::DefinitelyNotSent,
                    now(),
                );
            }
        }
        while self.contact_sends.len() < CONTACT_SEND_CONCURRENCY {
            let Some(action) = self.pending.pop_front() else {
                break;
            };
            if !self.engine.action_allowed(&action)
                || !self.contacts.contains_key(&action.peer.member)
            {
                self.engine.send_finished(
                    action.send_token(),
                    SendOutcome::DefinitelyNotSent,
                    now(),
                );
                continue;
            }
            let card = self.contacts[&action.peer.member].clone();
            let bytes = action.message.encode().map_err(error)?;
            let content_type = if matches!(action.message, swarm::Message::Data { .. }) {
                api::DIRECT_TYPE
            } else {
                api::DIRECT_CONTROL_TYPE
            };
            let client = sdk.clone();
            // A local timeout cannot finish an already admitted durable send.
            // Retain its real completion and token in the bounded window while
            // leaving the profile worker available for receive/control work.
            let task = tokio::spawn(async move {
                client
                    .submit_durable_opaque(&card, content_type, &bytes)
                    .await
            });
            self.contact_sends.push(ContactSend {
                action,
                task: Some(task),
            });
        }
        let ids: Vec<_> = self
            .metadata
            .entries
            .iter()
            .filter(|(id, e)| {
                matches!(e.scope, api::Scope::Hosted { .. })
                    && e.retry_at <= now()
                    && self.engine.cache.get(**id).is_ok()
            })
            .map(|(id, _)| *id)
            .collect();
        if let Some(id) = ids
            .iter()
            .find(|id| self.next_file.is_none_or(|last| **id > last))
            .or(ids.first())
            .copied()
        {
            self.next_file = Some(id);
            if let Err(e) = self.hosted_step(sdk.as_ref(), id).await {
                let entry = self.metadata.entries.get_mut(&id).unwrap();
                entry.error = Some(e.to_string());
                entry.retry_at = now() + 5;
                self.save()?;
            }
        }
        Ok(())
    }
    async fn receive_hosted(&mut self, sdk: &dyn GcClient) -> Result<(), SdkError> {
        for channel in self.hosted.keys().copied().collect::<Vec<_>>() {
            let h::Reply::FileEvents(events) = sdk
                .hosted_channels(h::Request::FileEvents { channel, limit: 16 })
                .await?
            else {
                return Err(error("invalid file inbox response"));
            };
            for event in events {
                if let h::EventKind::Message {
                    id,
                    sender,
                    content: h::Content::File { content_type, body },
                    ..
                } = event.kind
                {
                    if content_type == api::OFFER_TYPE {
                        if let Ok((manifest, tail)) =
                            postcard::take_from_bytes::<swarm::Manifest>(&body)
                        {
                            let scope = api::Scope::Hosted { channel };
                            if tail.is_empty()
                                && manifest.validate().is_ok()
                                && manifest.scope == cache_scope(&scope, self.own)
                            {
                                if let Some(entry) = self.metadata.entries.get(&manifest.id) {
                                    if entry.scope != scope || entry.publisher != sender {
                                        sdk.hosted_channels(h::Request::CommitFileEvents {
                                            channel,
                                            through: event.sequence,
                                        })
                                        .await?;
                                        continue;
                                    }
                                }
                                if !self.metadata.entries.contains_key(&manifest.id)
                                    && self.metadata.entries.len() >= 256
                                {
                                    break;
                                }
                                match self.engine.cache.offer(manifest.clone(), now()) {
                                    Ok(()) => {}
                                    Err(swarm::Error::Quota) => break,
                                    Err(swarm::Error::Conflict) => {
                                        sdk.hosted_channels(h::Request::CommitFileEvents {
                                            channel,
                                            through: event.sequence,
                                        })
                                        .await?;
                                        continue;
                                    }
                                    Err(e) => return Err(error(e)),
                                }
                                let entry =
                                    self.metadata.entries.entry(manifest.id).or_insert_with(|| {
                                        Entry {
                                            scope,
                                            publisher: sender,
                                            own: false,
                                            publish: false,
                                            uploaded: 0,
                                            published: true,
                                            publication_id: id,
                                            completion_id: rand::random(),
                                            completion_sent: false,
                                            retry_at: 0,
                                            error: None,
                                        }
                                    });
                                if entry.publication_id == id {
                                    entry.published = true;
                                }
                                self.save()?;
                            }
                        }
                    } else if content_type == api::COMPLETION_TYPE {
                        if let Ok((completion, tail)) =
                            postcard::take_from_bytes::<api::Completion>(&body)
                        {
                            if tail.is_empty() {
                                if let (Some(entry), Ok(state)) = (
                                    self.metadata.entries.get(&completion.file),
                                    self.engine.cache.get(completion.file),
                                ) {
                                    if entry.scope == (api::Scope::Hosted { channel })
                                        && entry.publisher == completion.publisher
                                        && state.manifest.sha256 == completion.sha256
                                        && sender != entry.publisher
                                    {
                                        self.engine
                                            .cache
                                            .receipt(completion.file, sender)
                                            .map_err(error)?;
                                    }
                                }
                            }
                        }
                    }
                }
                sdk.hosted_channels(h::Request::CommitFileEvents {
                    channel,
                    through: event.sequence,
                })
                .await?;
            }
        }
        Ok(())
    }
    async fn receive_contacts(&mut self, sdk: &dyn GcClient) -> Result<(), SdkError> {
        let deliveries = sdk.application_inbox(self.inbox_cursor, 32).await?;
        if deliveries.is_empty() {
            self.inbox_cursor = 0;
        }
        for delivery in deliveries {
            self.inbox_cursor = delivery.sequence;
            if delivery.source_component.is_some() || delivery.destination_component.is_some() {
                continue;
            }
            let Ok(application) = ApplicationMessage::decode(&delivery.body) else {
                continue;
            };
            if !matches!(
                application.content_type.as_str(),
                api::DIRECT_TYPE | api::DIRECT_CONTROL_TYPE
            ) {
                continue;
            }
            let peer = hash(&delivery.peer_identity);
            if self.contacts.contains_key(&peer) {
                if let Ok(message) = swarm::Message::decode(&application.body) {
                    if matches!(message, swarm::Message::Data { .. })
                        == (application.content_type == api::DIRECT_TYPE)
                    {
                        let scope = api::Scope::Contact { peer };
                        let internal = cache_scope(&scope, self.own);
                        // Validate the complete descriptor set before attaching
                        // scope metadata or advancing the durable inbox cursor.
                        if let swarm::Message::Offers { manifests, .. } = &message {
                            if manifests.iter().any(|m| {
                                m.scope != internal
                                    || self
                                        .metadata
                                        .entries
                                        .get(&m.id)
                                        .is_some_and(|e| e.scope != scope)
                            }) {
                                sdk.commit_application(delivery.sequence, delivery.receipt_digest)
                                    .await?;
                                continue;
                            }
                        }
                        if let swarm::Message::Offers { manifests, .. } = &message {
                            let fresh = manifests
                                .iter()
                                .filter(|m| !self.metadata.entries.contains_key(&m.id))
                                .count();
                            if self.metadata.entries.len().saturating_add(fresh) > 256 {
                                continue;
                            }
                        }
                        let offered: Vec<_> =
                            if let swarm::Message::Offers { manifests, .. } = &message {
                                manifests.iter().map(|m| m.id).collect()
                            } else {
                                vec![]
                            };
                        match self.engine.receive(
                            Peer {
                                channel: internal.channel,
                                member: peer,
                            },
                            message,
                            now(),
                        ) {
                            Ok(actions) => {
                                for id in offered {
                                    self.metadata.entries.entry(id).or_insert_with(|| Entry {
                                        scope: scope.clone(),
                                        publisher: peer,
                                        own: false,
                                        publish: false,
                                        uploaded: 0,
                                        published: true,
                                        publication_id: rand::random(),
                                        completion_id: rand::random(),
                                        completion_sent: false,
                                        retry_at: 0,
                                        error: None,
                                    });
                                }
                                self.save()?;
                                for action in actions {
                                    if self.queued_contacts() < CONTACT_QUEUE_LIMIT {
                                        self.pending.push_back(action);
                                    } else {
                                        self.engine.send_finished(
                                            action.send_token(),
                                            SendOutcome::DefinitelyNotSent,
                                            now(),
                                        );
                                    }
                                }
                            }
                            Err(swarm::Error::Io(e)) => return Err(error(e)),
                            Err(swarm::Error::Quota) => continue,
                            Err(_) => {}
                        }
                    }
                }
            }
            sdk.commit_application(delivery.sequence, delivery.receipt_digest)
                .await?;
        }
        Ok(())
    }
    async fn hosted_step(&mut self, sdk: &dyn GcClient, id: Id) -> Result<(), SdkError> {
        let entry = self.metadata.entries[&id].clone();
        let api::Scope::Hosted { channel } = entry.scope else {
            return Ok(());
        };
        let own = self.authorize(id)?;
        let state = self.engine.cache.get(id).map_err(error)?.clone();
        if matches!(
            state.status,
            swarm::Status::Importing
                | swarm::Status::Offered
                | swarm::Status::Paused
                | swarm::Status::Cancelled
                | swarm::Status::Failed
        ) {
            return Ok(());
        }
        let reference = |piece| gcoms_sdk::hosted::BlobRef {
            owner: entry.publisher,
            file: id,
            piece,
        };
        if entry.own && entry.publish && !entry.published {
            if entry.uploaded < state.manifest.pieces() as u32 {
                let mut requests = Vec::new();
                for piece in
                    entry.uploaded..(entry.uploaded + 2).min(state.manifest.pieces() as u32)
                {
                    let bytes = postcard::to_allocvec(
                        &self.engine.cache.read_piece(id, piece).map_err(error)?,
                    )
                    .map_err(error)?;
                    requests.push(h::Request::PutBlob {
                        channel,
                        reference: reference(piece),
                        bytes,
                    });
                }
                for reply in hosted_pair(sdk, requests).await {
                    if !matches!(reply?, h::Reply::Done) {
                        return Err(error("invalid ciphertext upload response"));
                    }
                    let entry = self.metadata.entries.get_mut(&id).unwrap();
                    entry.uploaded += 1;
                    entry.error = None;
                    self.save()?;
                }
            } else {
                sdk.hosted_channels(h::Request::SendIdentified {
                    channel,
                    id: entry.publication_id,
                    content: h::Content::File {
                        content_type: api::OFFER_TYPE.into(),
                        body: postcard::to_allocvec(&state.manifest).map_err(error)?,
                    },
                })
                .await?;
                // Only accepted replay marks the offer published. A queued
                // operation can still fail moderation or revocation checks.
                self.metadata.entries.get_mut(&id).unwrap().retry_at = now() + 5;
                self.save()?;
            }
        } else if !entry.own && state.status == swarm::Status::Downloading {
            let pieces: Vec<_> = state
                .have
                .iter()
                .enumerate()
                .filter_map(|(index, have)| (!have).then_some(index as u32))
                .take(2)
                .collect();
            let requests = pieces
                .iter()
                .map(|piece| h::Request::GetBlob {
                    channel,
                    reference: reference(*piece),
                })
                .collect();
            for (piece, reply) in pieces.into_iter().zip(hosted_pair(sdk, requests).await) {
                let h::Reply::Blob(bytes) = reply? else {
                    return Err(error("invalid ciphertext piece response"));
                };
                let ((proof, bytes), tail): ((Vec<[u8; 32]>, Vec<u8>), _) =
                    postcard::take_from_bytes(&bytes).map_err(error)?;
                if !tail.is_empty() || proof.len() > 16 {
                    return Err(error("invalid ciphertext proof"));
                }
                self.engine
                    .cache
                    .put(id, piece, &bytes, &proof, now())
                    .map_err(error)?;
                self.metadata.entries.get_mut(&id).unwrap().error = None;
                self.save()?;
            }
        } else if !entry.own
            && state.status == swarm::Status::Complete
            && !entry.completion_sent
            && own != entry.publisher
        {
            let completion = api::Completion {
                publisher: entry.publisher,
                file: id,
                sha256: state.manifest.sha256,
            };
            sdk.hosted_channels(h::Request::SendIdentified {
                channel,
                id: entry.completion_id,
                content: h::Content::File {
                    content_type: api::COMPLETION_TYPE.into(),
                    body: postcard::to_allocvec(&completion).map_err(error)?,
                },
            })
            .await?;
            self.metadata.entries.get_mut(&id).unwrap().completion_sent = true;
            self.save()?;
        }
        Ok(())
    }
}

// Keep only two immutable pieces in flight. A cancelled or lost response
// retries identical ciphertext; only individually verified/stored results advance.
async fn hosted_pair(
    sdk: &dyn GcClient,
    requests: Vec<h::Request>,
) -> Vec<Result<h::Reply, SdkError>> {
    debug_assert!(requests.len() <= 2);
    let mut requests = requests.into_iter();
    let Some(first) = requests.next() else {
        return Vec::new();
    };
    let Some(second) = requests.next() else {
        return vec![sdk.hosted_channels(first).await];
    };
    let (first, second) = tokio::join!(sdk.hosted_channels(first), sdk.hosted_channels(second));
    vec![first, second]
}

#[cfg(test)]
mod tests;
