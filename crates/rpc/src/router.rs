use crate::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, Semaphore};

/// Supplied by an authenticated adapter, never decoded from a request body.
#[derive(Clone, Debug)]
pub struct Caller {
    pub principal: String,
}

pub trait Authorize: Send + Sync {
    fn allowed(&self, caller: &Caller, service: &str, version: u16, method: &str) -> bool;
}
impl<F> Authorize for F
where
    F: Fn(&Caller, &str, u16, &str) -> bool + Send + Sync,
{
    fn allowed(&self, caller: &Caller, service: &str, version: u16, method: &str) -> bool {
        self(caller, service, version, method)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationKey {
    pub caller: String,
    pub instance: String,
    pub service: String,
    pub version: u16,
    pub method: String,
    pub operation_id: OperationId,
}
impl OperationKey {
    pub fn new(caller: &Caller, request: &Request, operation_id: &OperationId) -> Self {
        Self {
            caller: caller.principal.clone(),
            instance: request.instance.clone(),
            service: request.service.clone(),
            version: request.version,
            method: request.method.clone(),
            operation_id: operation_id.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub key: OperationKey,
    pub digest: String,
    pub admitted_at: DecimalU64,
    pub retain_until: DecimalU64,
    pub result: Option<ReplyBody>,
}
#[derive(Debug)]
pub enum Admission {
    New,
    Existing(Box<OperationRecord>),
}

#[async_trait]
pub trait OperationStore: Send + Sync {
    /// Atomically compare digest or durably insert admission. Expiry is checked
    /// only for new records, so a completed operation remains recoverable.
    async fn admit(
        &self,
        key: &OperationKey,
        digest: &str,
        deadline: u64,
        now: u64,
    ) -> Result<Admission, RpcError>;
    async fn complete(&self, key: &OperationKey, result: ReplyBody) -> Result<(), RpcError>;
    async fn get(&self, key: &OperationKey, now: u64) -> Result<Option<OperationRecord>, RpcError>;
}

#[derive(Clone, Copy)]
pub struct StoreLimits {
    pub retention_secs: u64,
    pub records: usize,
    pub bytes: usize,
}
impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            retention_secs: DEFAULT_RETENTION_SECS,
            records: DEFAULT_RECORD_LIMIT,
            bytes: LOCAL_FRAME_LIMIT,
        }
    }
}

/// Shared transactional journal logic; persistent backends save a candidate
/// before replacing the live state. No unexpired entry is evicted for capacity.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub records: Vec<OperationRecord>,
}
impl Journal {
    pub fn admit(
        &mut self,
        key: &OperationKey,
        digest: &str,
        deadline: u64,
        now: u64,
        limits: StoreLimits,
    ) -> Result<Admission, RpcError> {
        if let Some(existing) = self
            .records
            .iter()
            .find(|r| r.key == *key && r.retain_until.0 > now)
        {
            return if existing.digest == digest {
                Ok(Admission::Existing(Box::new(existing.clone())))
            } else {
                Err(RpcError::new(
                    ErrorCode::Conflict,
                    "operation ID was used with different contents",
                ))
            };
        }
        if deadline <= now || deadline > now.saturating_add(600) {
            return Err(RpcError::new(
                ErrorCode::Expired,
                "submission deadline expired or exceeds ten minutes",
            ));
        }
        if limits.retention_secs < 600 {
            return Err(RpcError::new(
                ErrorCode::Storage,
                "retention must cover the admission window",
            ));
        }
        self.records.retain(|r| r.retain_until.0 > now);
        if self.records.len() >= limits.records {
            return Err(RpcError::new(ErrorCode::Busy, "operation journal is full"));
        }
        self.records.push(OperationRecord {
            key: key.clone(),
            digest: digest.into(),
            admitted_at: DecimalU64(now),
            retain_until: DecimalU64(now.saturating_add(limits.retention_secs)),
            result: None,
        });
        self.check_size(limits)?;
        Ok(Admission::New)
    }
    pub fn complete(
        &mut self,
        key: &OperationKey,
        result: ReplyBody,
        limits: StoreLimits,
    ) -> Result<(), RpcError> {
        if !matches!(result, ReplyBody::Done { .. } | ReplyBody::Failed { .. }) {
            return Err(RpcError::invalid("only terminal results can be committed"));
        }
        let record = self
            .records
            .iter_mut()
            .find(|r| r.key == *key)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "operation record unavailable"))?;
        if let Some(old) = &record.result {
            return if old == &result {
                Ok(())
            } else {
                Err(RpcError::new(
                    ErrorCode::Conflict,
                    "operation already completed",
                ))
            };
        }
        record.result = Some(result);
        self.check_size(limits)
    }
    pub fn get(&self, key: &OperationKey, now: u64) -> Option<OperationRecord> {
        self.records
            .iter()
            .find(|r| r.key == *key && r.retain_until.0 > now)
            .cloned()
    }
    pub fn check_size(&self, limits: StoreLimits) -> Result<(), RpcError> {
        if serde_json::to_vec(self)
            .map_err(|_| RpcError::new(ErrorCode::Storage, "journal serialization failed"))?
            .len()
            > limits.bytes
        {
            return Err(RpcError::new(
                ErrorCode::Busy,
                "operation journal byte limit",
            ));
        }
        Ok(())
    }
}

/// For isolated fixtures and ephemeral services. Use a persistent store for
/// resumability across process restarts.
pub struct MemoryStore {
    state: Mutex<Journal>,
    limits: StoreLimits,
}
impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(StoreLimits::default())
    }
}
impl MemoryStore {
    pub fn new(limits: StoreLimits) -> Self {
        Self {
            state: Mutex::new(Journal::default()),
            limits,
        }
    }
}
#[async_trait]
impl OperationStore for MemoryStore {
    async fn admit(
        &self,
        key: &OperationKey,
        digest: &str,
        deadline: u64,
        now: u64,
    ) -> Result<Admission, RpcError> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        let admission = candidate.admit(key, digest, deadline, now, self.limits)?;
        *state = candidate;
        Ok(admission)
    }
    async fn complete(&self, key: &OperationKey, result: ReplyBody) -> Result<(), RpcError> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.complete(key, result, self.limits)?;
        *state = candidate;
        Ok(())
    }
    async fn get(&self, key: &OperationKey, now: u64) -> Result<Option<OperationRecord>, RpcError> {
        Ok(self.state.lock().await.get(key, now))
    }
}

struct Registration {
    dispatch: Arc<dyn Dispatch>,
    descriptor: Service,
    store: Arc<dyn OperationStore>,
    authorize: Arc<dyn Authorize>,
}
pub struct Router {
    instance: String,
    services: BTreeMap<(String, u16), Registration>,
    workers: Arc<Semaphore>,
    active: Mutex<BTreeMap<OperationKey, ()>>,
    frame_limit: usize,
}
impl Router {
    pub fn new(instance: impl Into<String>, workers: usize, frame_limit: usize) -> Self {
        Self {
            instance: instance.into(),
            services: BTreeMap::new(),
            workers: Arc::new(Semaphore::new(workers.clamp(1, 256))),
            active: Mutex::new(BTreeMap::new()),
            frame_limit: frame_limit.clamp(1024, LOCAL_FRAME_LIMIT),
        }
    }
    pub fn instance(&self) -> &str {
        &self.instance
    }
    pub fn frame_limit(&self) -> usize {
        self.frame_limit
    }
    pub fn register(
        &mut self,
        dispatch: Arc<dyn Dispatch>,
        store: Arc<dyn OperationStore>,
        authorize: Arc<dyn Authorize>,
    ) -> Result<(), RpcError> {
        let descriptor = dispatch.descriptor();
        let key = (descriptor.name.clone(), descriptor.version);
        if self.services.contains_key(&key) {
            return Err(RpcError::new(
                ErrorCode::Conflict,
                "service version already registered",
            ));
        }
        self.services.insert(
            key,
            Registration {
                dispatch,
                descriptor,
                store,
                authorize,
            },
        );
        Ok(())
    }
    pub async fn handle(self: &Arc<Self>, caller: Caller, request: Request) -> Reply {
        let body = match self.handle_inner(&caller, &request).await {
            Ok(body) => body,
            Err(error) => ReplyBody::Failed { error },
        };
        let reply = request.reply(body);
        if serde_json::to_vec(&reply).map_or(true, |v| v.len() > self.frame_limit) {
            return request.reply(ReplyBody::Failed {
                error: RpcError::new(
                    ErrorCode::PayloadTooLarge,
                    "response exceeds adapter limit; paginate results",
                ),
            });
        }
        reply
    }
    async fn handle_inner(
        self: &Arc<Self>,
        caller: &Caller,
        request: &Request,
    ) -> Result<ReplyBody, RpcError> {
        if serde_json::to_vec(request).map_or(true, |v| v.len() > self.frame_limit) {
            return Err(RpcError::new(
                ErrorCode::PayloadTooLarge,
                "request exceeds adapter limit",
            ));
        }
        if request.rpc != WIRE_VERSION {
            return Err(RpcError::new(ErrorCode::Version, "unsupported RPC version"));
        }
        if request.instance != self.instance {
            return Err(RpcError::new(
                ErrorCode::Instance,
                "instance does not match attachment",
            ));
        }
        let registration = self
            .services
            .get(&(request.service.clone(), request.version))
            .ok_or_else(|| {
                RpcError::new(ErrorCode::Service, "service version is not registered")
            })?;
        if !registration.authorize.allowed(
            caller,
            &request.service,
            request.version,
            &request.method,
        ) {
            return Err(RpcError::new(
                ErrorCode::Unauthorized,
                "service access denied",
            ));
        }
        let method = registration
            .descriptor
            .methods
            .iter()
            .find(|m| m.id == request.method)
            .ok_or_else(|| RpcError::new(ErrorCode::Method, "unknown method"))?;
        match &request.invocation {
            Invocation::Status { operation_id } => {
                if method.kind != MethodKind::Operation {
                    return Err(RpcError::invalid("status requires an operation method"));
                }
                let key = OperationKey::new(caller, request, operation_id);
                let active = self.active.lock().await;
                let record = registration.store.get(&key, unix_time()).await?;
                Ok(state(record.as_ref(), active.contains_key(&key)))
            }
            Invocation::Call { args, operation } => {
                if (method.kind == MethodKind::Operation) != operation.is_some() {
                    return Err(RpcError::invalid(
                        "operation token does not match method kind",
                    ));
                }
                let args = registration
                    .dispatch
                    .validate(&request.method, args.clone())?;
                let context = CallContext {
                    principal: caller.principal.clone(),
                    instance: request.instance.clone(),
                    operation: operation.clone(),
                };
                if let Some(operation) = operation {
                    let key = OperationKey::new(caller, request, &operation.id);
                    let digest = registration.dispatch.digest(&request.method, &args)?;
                    let mut active = self.active.lock().await;
                    // Recover duplicates even if all execution slots are busy.
                    if let Some(record) = registration.store.get(&key, unix_time()).await? {
                        if record.digest != digest {
                            return Err(RpcError::new(
                                ErrorCode::Conflict,
                                "operation ID was used with different contents",
                            ));
                        }
                        return Ok(state(Some(&record), active.contains_key(&key)));
                    }
                    let permit =
                        self.workers.clone().try_acquire_owned().map_err(|_| {
                            RpcError::new(ErrorCode::Busy, "service workers are busy")
                        })?;
                    match registration
                        .store
                        .admit(&key, &digest, operation.deadline.0, unix_time())
                        .await?
                    {
                        Admission::Existing(record) => {
                            return Ok(state(Some(&record), active.contains_key(&key)))
                        }
                        Admission::New => {}
                    }
                    active.insert(key.clone(), ());
                    let router = self.clone();
                    let handler = registration.dispatch.clone();
                    let store = registration.store.clone();
                    let method = request.method.clone();
                    let bound_request = request.clone();
                    // The worker owns execution after admission; cancellation of an
                    // HTTP/IPC request does not abort it or authorize repetition.
                    tokio::spawn(async move {
                        let result =
                            tokio::spawn(
                                async move { handler.invoke(context, &method, args).await },
                            )
                            .await;
                        let body = match result {
                            Ok(Ok(outcome)) => ReplyBody::Done { outcome },
                            // An infrastructure/serialization error does not
                            // prove the handler had no effects. Only typed
                            // outcomes are safe to record as terminal here.
                            Ok(Err(_)) | Err(_) => {
                                router.active.lock().await.remove(&key);
                                return;
                            }
                        };
                        let body = if serde_json::to_vec(&bound_request.reply(body.clone()))
                            .map_or(true, |v| v.len() > router.frame_limit)
                        {
                            ReplyBody::Failed {
                                error: RpcError::new(
                                    ErrorCode::PayloadTooLarge,
                                    "result exceeds adapter limit",
                                ),
                            }
                        } else {
                            body
                        };
                        // Failure leaves the durable admission with unknown outcome.
                        let _ = store.complete(&key, body).await;
                        router.active.lock().await.remove(&key);
                        drop(permit);
                    });
                    Ok(ReplyBody::Running)
                } else {
                    let _permit =
                        self.workers.clone().try_acquire_owned().map_err(|_| {
                            RpcError::new(ErrorCode::Busy, "service workers are busy")
                        })?;
                    registration
                        .dispatch
                        .invoke(context, &request.method, args)
                        .await
                        .map(|outcome| ReplyBody::Done { outcome })
                }
            }
        }
    }
}
fn state(record: Option<&OperationRecord>, active: bool) -> ReplyBody {
    match record {
        None => ReplyBody::Unavailable,
        Some(record) => record.result.clone().unwrap_or(if active {
            ReplyBody::Running
        } else {
            ReplyBody::OutcomeUnknown
        }),
    }
}

pub struct EmbeddedTransport {
    pub router: Arc<Router>,
    pub caller: Caller,
    pub destination: String,
}
#[async_trait]
impl Transport for EmbeddedTransport {
    fn destination(&self) -> &str {
        &self.destination
    }
    fn frame_limit(&self) -> usize {
        self.router.frame_limit()
    }
    async fn exchange(&self, request: &Request) -> Result<Reply, RpcError> {
        Ok(self
            .router
            .handle(self.caller.clone(), request.clone())
            .await)
    }
}
