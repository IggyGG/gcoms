//! File cache and transfer worker owned by the protocol host.
use gcoms_file_transfer::swarm::{self, Action, Cache, Engine, Peer, SendOutcome, SendToken};
use gcoms_sdk::{sharing as api, ChannelStatus, ClientEvent, GcClient, SdkError};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{watch, Mutex as AsyncMutex};
use zeroize::Zeroizing;

pub type DiagnosticSource = Arc<dyn Fn() -> serde_json::Value + Send + Sync>;
pub struct FileService {
    diagnostics: Mutex<Option<DiagnosticSource>>,
    send_failures: std::sync::atomic::AtomicU64,
    send_timeouts: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    receipt_gate: Mutex<Option<Arc<ReceiptGate>>>,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    enabled: AtomicBool,
    inner: Mutex<Option<Backend>>,
    operations: AsyncMutex<()>,
    sdk: Arc<dyn GcClient>,
    stop: watch::Sender<bool>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
struct Backend {
    engine: Engine,
    routes: BTreeMap<[u8; 32], String>,
    rosters: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    pending: VecDeque<Action>,
    next_diagnostic: u64,
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn error(e: impl std::fmt::Display) -> SdkError {
    SdkError::Runtime(e.to_string())
}
impl FileService {
    pub async fn open(
        path: &Path,
        key: [u8; 32],
        config: api::CacheConfig,
        sdk: Arc<dyn GcClient>,
    ) -> Result<Arc<Self>, SdkError> {
        api::Request::Configure(config.clone()).validate()?;
        let home = path.to_owned();
        let cache = tokio::task::spawn_blocking(move || {
            let mut cache = Cache::open(
                &home,
                key,
                swarm::CacheConfig {
                    quota_bytes: config.quota_bytes,
                    retention_secs: config.retention_secs,
                },
            )
            .map_err(error)?;
            let settings = home.join("settings.json");
            match std::fs::symlink_metadata(&settings) {
                Ok(metadata) => {
                    gcoms_private_fs::validate_private_file(&settings, "file cache settings")
                        .map_err(error)?;
                    if metadata.len() > 512 {
                        return Err(error("file cache settings exceed limit"));
                    }
                    let config: api::CacheConfig =
                        serde_json::from_slice(&std::fs::read(settings).map_err(error)?)
                            .map_err(error)?;
                    api::Request::Configure(config.clone()).validate()?;
                    cache.config = swarm::CacheConfig {
                        quota_bytes: config.quota_bytes,
                        retention_secs: config.retention_secs,
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(error(e)),
            }
            Ok::<_, SdkError>(cache)
        })
        .await
        .map_err(error)?
        .map_err(error)?;
        let service = Arc::new(Self {
            diagnostics: Mutex::new(None),
            send_failures: std::sync::atomic::AtomicU64::new(0),
            send_timeouts: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            receipt_gate: Mutex::new(None),
            path: path.to_owned(),
            key: Zeroizing::new(key),
            enabled: AtomicBool::new(true),
            inner: Mutex::new(Some(Backend {
                engine: Engine::new(cache),
                routes: BTreeMap::new(),
                rosters: BTreeMap::new(),
                pending: VecDeque::new(),
                next_diagnostic: 0,
            })),
            operations: AsyncMutex::new(()),
            sdk,
            stop: watch::channel(false).0,
            worker: Mutex::new(None),
        });
        service.refresh().await?;
        *service.worker.lock().map_err(error)? = Some(Self::spawn(&service));
        Ok(service)
    }
    pub fn diagnostics(&self, source: DiagnosticSource) {
        *self.diagnostics.lock().unwrap_or_else(|e| e.into_inner()) = Some(source);
    }
    pub fn matches(&self, path: &Path, key: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        self.path == path && bool::from(self.key.ct_eq(key))
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    pub async fn shutdown(&self) {
        self.enabled.store(false, Ordering::Release);
        self.stop.send_replace(true);
        let _operation = self.operations.lock().await;
        let task = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            let _ = task.await;
        }
        // Release the cache's exclusive lock even while callers retain a
        // stopped service handle. Subsequent operations remain closed.
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
    async fn refresh(&self) -> Result<(), SdkError> {
        let joined = self.sdk.list_channels().await?;
        let mut rosters = Vec::new();
        for channel in joined
            .into_iter()
            .filter(|c| c.status == ChannelStatus::Active)
        {
            if let Ok(roster) = self.sdk.channel_roster(&channel.channel).await {
                if let Some(own) = roster.iter().find(|m| m.is_self) {
                    rosters.push((
                        channel.id.0,
                        channel.channel,
                        own.member_id,
                        roster.into_iter().map(|m| m.member_id).collect::<Vec<_>>(),
                    ));
                }
            }
        }
        let mut inner = self.inner.lock().map_err(error)?;
        let b = inner.as_mut().ok_or(SdkError::ConnectionClosed)?;
        let removed: Vec<_> = b
            .routes
            .keys()
            .filter(|id| !rosters.iter().any(|r| r.0 == **id))
            .copied()
            .collect();
        for id in removed {
            b.routes.remove(&id);
            b.rosters.remove(&id);
            b.engine.set_members(id, [0; 32], []);
        }
        for (id, name, own, roster) in rosters {
            b.routes.insert(id, name);
            b.rosters.insert(id, roster.clone());
            b.engine.set_members(id, own, roster);
        }
        Ok(())
    }
    pub async fn request(self: &Arc<Self>, request: api::Request) -> Result<api::Reply, SdkError> {
        request.validate()?;
        let _operation = self.operations.lock().await;
        if *self.stop.borrow() {
            return Err(SdkError::ConnectionClosed);
        }
        self.refresh().await?;
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.execute(request))
            .await
            .map_err(error)?
    }
    fn execute(&self, request: api::Request) -> Result<api::Reply, SdkError> {
        if let api::Request::SetEnabled(enabled) = request {
            self.enabled.store(enabled, Ordering::Release);
        } else if !self.enabled.load(Ordering::Acquire) {
            return Err(SdkError::PermissionDenied);
        }
        let mut inner = self.inner.lock().map_err(error)?;
        let b = inner.as_mut().ok_or(SdkError::ConnectionClosed)?;
        let reuse = matches!(request, api::Request::CommitReusing { .. });
        let mut committed = None;
        match request {
            api::Request::List | api::Request::SetEnabled(_) => {}
            api::Request::Inspect { id } => {
                b.authorize(id)?;
                let state = b.engine.cache.get(id).map_err(error)?;
                return Ok(api::Reply::Metadata(api::Metadata {
                    id,
                    name: state.manifest.name.clone(),
                    sha256: state.manifest.sha256,
                    size_bytes: state.manifest.size,
                }));
            }
            api::Request::Prepare {
                id,
                scope,
                name,
                size_bytes,
            } => {
                let scope = swarm::Scope {
                    channel: scope.channel,
                    participants: scope.participants,
                };
                if !b.engine.own_scope(&scope) {
                    return Err(SdkError::PermissionDenied);
                }
                b.engine
                    .cache
                    .begin_import(id, scope, name, size_bytes, now())
                    .map_err(error)?;
            }
            api::Request::WritePiece { id, piece, bytes } => {
                let bytes = Zeroizing::new(bytes);
                b.authorize(id)?;
                b.engine
                    .cache
                    .import_piece(id, piece, &bytes)
                    .map_err(error)?;
            }
            api::Request::Commit { id } | api::Request::CommitReusing { id } => {
                b.authorize(id)?;
                let mut manifest = b.engine.cache.finish_import(id, now()).map_err(error)?;
                if reuse {
                    manifest = b.engine.cache.reuse_import(id).map_err(error)?;
                    committed = Some((id, manifest.id));
                }
                let members = b
                    .rosters
                    .get(&manifest.scope.channel)
                    .cloned()
                    .unwrap_or_default();
                for member in members.into_iter().take(64) {
                    let peer = Peer {
                        channel: manifest.scope.channel,
                        member,
                    };
                    if b.engine.permits(peer, &manifest.scope) && b.pending.len() < 128 {
                        b.pending.push_back(Action::offer(peer, manifest.clone()));
                    }
                }
            }
            api::Request::Accept { id } | api::Request::Resume { id } => {
                b.authorize(id)?;
                b.engine.accept(id, now()).map_err(error)?;
            }
            api::Request::Pause { id } => {
                b.authorize(id)?;
                b.engine.pause(id).map_err(error)?;
            }
            // The local owner may discard or export already verified retained data after leaving.
            api::Request::Cancel { id } => b.engine.cancel(id).map_err(error)?,
            api::Request::ReadPiece { id, piece } => {
                return b
                    .engine
                    .cache
                    .export_piece(id, piece)
                    .map(api::Reply::Piece)
                    .map_err(error)
            }
            api::Request::Configure(config) => {
                use std::io::Write;
                let mut file = tempfile::NamedTempFile::new_in(&self.path).map_err(error)?;
                gcoms_private_fs::make_private(file.path(), false).map_err(error)?;
                file.write_all(&serde_json::to_vec(&config).map_err(error)?)
                    .map_err(error)?;
                file.as_file().sync_all().map_err(error)?;
                file.persist(self.path.join("settings.json"))
                    .map_err(error)?;
                #[cfg(unix)]
                std::fs::File::open(&self.path)
                    .and_then(|d| d.sync_all())
                    .map_err(error)?;
                b.engine.cache.config = swarm::CacheConfig {
                    quota_bytes: config.quota_bytes,
                    retention_secs: config.retention_secs,
                };
            }
        }
        let snapshot = b.snapshot();
        Ok(match committed {
            Some((original, canonical)) => api::Reply::Committed {
                original,
                canonical,
                snapshot,
            },
            None => api::Reply::Snapshot(snapshot),
        })
    }
    fn spawn(service: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(service);
        let sdk = service.sdk.clone();
        let mut events = sdk.subscribe_events();
        let mut stopped = service.stop.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut sends = tokio::task::JoinSet::<(Option<SendToken>, SendOutcome)>::new();
            loop {
                let (event, completion) = tokio::select! {
                    _ = stopped.changed() => break,
                    _ = interval.tick() => (None, None),
                    result = sends.join_next(), if !sends.is_empty() => (None, result.and_then(Result::ok)),
                    event = events.recv() => match event { Some(event) => (Some(event), None), None => break },
                };
                let Some(service) = weak.upgrade() else { break };
                let operation = tokio::select! { _ = stopped.changed() => break, guard = service.operations.lock() => guard };
                if !service.enabled.load(Ordering::Acquire) {
                    continue;
                }
                if service.refresh().await.is_err() {
                    continue;
                }
                let worker = service.clone();
                let capacity = 4usize.saturating_sub(sends.len());
                let work =
                    tokio::task::spawn_blocking(move || worker.tick(event, completion, capacity))
                        .await;
                drop(operation);
                if let Ok(Ok(actions)) = work {
                    for (channel, action) in actions {
                        let sdk = sdk.clone();
                        let counters = service.clone();
                        #[cfg(test)]
                        let gate = service.receipt_gate.lock().unwrap().clone();
                        sends.spawn(async move {
                            let token = action.send_token();
                            let _reservation = action.payload_guard();
                            let outcome = match action.message.encode() {
                                Ok(bytes) => {
                                    let send = sdk.send_channel_application(
                                        &channel,
                                        action.peer.member,
                                        swarm::CONTENT_TYPE,
                                        &bytes,
                                    );
                                    tokio::pin!(send);
                                    let result = tokio::select! {
                                        result = &mut send => result,
                                        _ = tokio::time::sleep(Duration::from_secs(20)) => {
                                            counters.send_timeouts.fetch_add(1, Ordering::Relaxed);
                                            send.await
                                        }
                                    };
                                    if result.is_ok() {
                                        SendOutcome::HopAccepted
                                    } else {
                                        counters.send_failures.fetch_add(1, Ordering::Relaxed);
                                        SendOutcome::OutcomeUnknown
                                    }
                                }
                                Err(_) => SendOutcome::DefinitelyNotSent,
                            };
                            #[cfg(test)]
                            if let Some(gate) = gate {
                                gate.entered.fetch_add(1, Ordering::SeqCst);
                                let _ = gate.release.acquire().await;
                            }
                            (token, outcome)
                        });
                    }
                }
            }
            sends.shutdown().await;
        })
    }
    fn tick(
        &self,
        event: Option<ClientEvent>,
        completion: Option<(Option<SendToken>, SendOutcome)>,
        capacity: usize,
    ) -> Result<Vec<(String, Action)>, SdkError> {
        let mut inner = self.inner.lock().map_err(error)?;
        let b = inner.as_mut().ok_or(SdkError::ConnectionClosed)?;
        if let Some((token, outcome)) = completion {
            b.engine.send_finished(token, outcome, now());
        }
        let mut actions = Vec::new();
        if let Some(ClientEvent::ChannelDirectMessage {
            channel,
            sender_member_id,
            body,
            ..
        }) = event
        {
            if gcoms_core::is_piece_application_payload(&body) {
                if let (Some(id), Ok(application)) = (
                    b.routes
                        .iter()
                        .find(|(_, n)| **n == channel)
                        .map(|(id, _)| *id),
                    gcoms_sdk::ApplicationMessage::decode(&body),
                ) {
                    if let Ok(message) = swarm::Message::decode(&application.body) {
                        if let Ok(received) = b.engine.receive(
                            Peer {
                                channel: id,
                                member: sender_member_id,
                            },
                            message,
                            now(),
                        ) {
                            actions.extend(received);
                        }
                    }
                }
            }
        }
        actions.extend(b.engine.tick(now()).map_err(error)?);
        for action in actions {
            if b.pending.len() < 128 {
                b.pending.push_back(action);
            } else {
                b.engine
                    .send_finished(action.send_token(), SendOutcome::DefinitelyNotSent, now());
            }
        }
        if now() >= b.next_diagnostic {
            if let Some(source) = self.diagnostics.lock().map_err(error)?.as_ref() {
                use std::io::Write;
                b.next_diagnostic = now().saturating_add(5);
                let d = b.engine.diagnostics();
                let extra = source();
                let observation = serde_json::json!({
                    "event": "file_diagnostics", "unix_seconds": now(), "pid": std::process::id(),
                    "verified_pieces": d.verified_pieces, "received_blocks": d.received_blocks, "received_bytes": d.received_bytes,
                    "send_failures": self.send_failures.load(Ordering::Relaxed), "send_timeouts": self.send_timeouts.load(Ordering::Relaxed),
                    "rejected_pieces": d.rejected_pieces, "retries": d.retries, "buffered_bytes": d.buffered_bytes,
                    "pending_pulls": d.pending_pulls, "pending_actions": b.pending.len(), "cache_bytes": b.engine.cache.used(),
                    "hop_accepted": d.hop_accepted, "outcome_unknown": d.outcome_unknown, "not_sent": d.not_sent,
                    "protocol": extra.get("protocol"), "persistence": extra.get("persistence"),
                });
                let _ = writeln!(std::io::stderr().lock(), "{observation}");
            }
        }
        let mut ready = Vec::new();
        for _ in 0..capacity {
            if let Some(action) = b.pending.pop_front() {
                if let Some(name) = b
                    .routes
                    .get(&action.peer.channel)
                    .filter(|_| b.engine.action_allowed(&action))
                {
                    ready.push((name.clone(), action));
                } else {
                    b.engine.send_finished(
                        action.send_token(),
                        SendOutcome::DefinitelyNotSent,
                        now(),
                    );
                }
            }
        }
        Ok(ready)
    }
}
impl Drop for FileService {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
impl Backend {
    fn authorize(&self, id: api::ShareId) -> Result<(), SdkError> {
        let state = self.engine.cache.get(id).map_err(error)?;
        if self.engine.own_scope(&state.manifest.scope) {
            Ok(())
        } else {
            Err(SdkError::PermissionDenied)
        }
    }
    fn snapshot(&self) -> api::Snapshot {
        api::Snapshot {
            files: self
                .engine
                .views()
                .into_iter()
                .map(|v| api::FileInfo {
                    id: v.state.manifest.id,
                    scope: api::Scope {
                        channel: v.state.manifest.scope.channel,
                        participants: v.state.manifest.scope.participants.clone(),
                    },
                    name: v.state.manifest.name.clone(),
                    size_bytes: v.state.manifest.size,
                    verified_bytes: v.state.verified_bytes(),
                    status: match v.state.status {
                        swarm::Status::Offered => api::Status::Offered,
                        swarm::Status::Importing => api::Status::Importing,
                        swarm::Status::Downloading if v.waiting_for_peers => {
                            api::Status::WaitingForPeers
                        }
                        swarm::Status::Downloading => api::Status::Downloading,
                        swarm::Status::Paused => api::Status::Paused,
                        swarm::Status::Complete => api::Status::Complete,
                        swarm::Status::Failed => api::Status::Failed,
                        swarm::Status::Cancelled => api::Status::Cancelled,
                    },
                    sources: v.sources as u16,
                    verified_sources: v.verified_sources as u16,
                    completed_by: v.delivered as u16,
                    error: v.state.error.clone(),
                })
                .collect(),
            config: api::CacheConfig {
                quota_bytes: self.engine.cache.config.quota_bytes,
                retention_secs: self.engine.cache.config.retention_secs,
            },
            used_bytes: self.engine.cache.used(),
        }
    }
}

#[cfg(test)]
struct ReceiptGate {
    entered: std::sync::atomic::AtomicUsize,
    release: tokio::sync::Semaphore,
}
#[cfg(test)]
mod tests;
