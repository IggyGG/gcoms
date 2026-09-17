//! Scoped invitation admission and durable, single-writer DNS publication.
//! The publisher owns only records it has journaled, never a whole DNS zone.
use super::{no_store, now_unix, ApiError, AppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_network::{
    NameResponse, RegisterNameRequest, RemoveNameRequest, SignedNetworkDefaults, UpdateNameRequest,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    path::{Path as FilePath, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};

const MAX_NAMES: usize = 10_000;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub network_id: String,
    pub defaults_file: PathBuf,
    pub verification_key_file: PathBuf,
    pub grants_file: PathBuf,
    pub state_dir: PathBuf,
    #[serde(default = "enabled")]
    pub names_enabled: bool,
    #[serde(default = "default_lease")]
    pub name_lease_secs: u64,
    pub spaceship_credentials_file: Option<PathBuf>,
}
fn enabled() -> bool {
    true
}
fn default_lease() -> u64 {
    3600
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    /// SHA-256 domain-separated digest of the random token; no person/app ID.
    pub id: String,
    pub expires_at: u64,
    pub scopes: Vec<String>,
    pub max_names: u32,
    #[serde(default)]
    pub revoked: bool,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantFile {
    pub version: u8,
    pub grants: Vec<GrantRecord>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpaceshipCredentials {
    api_key: String,
    api_secret: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct NameEntry {
    handle: String,
    fqdn: String,
    grant_id: String,
    credential_hash: String,
    registration_id: String,
    registration_hash: String,
    service_id: [u8; 32],
    address: SocketAddr,
    sequence: u64,
    mutation_hash: String,
    lease_expires_at: u64,
    removed: bool,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct DnsState {
    names: BTreeMap<String, NameEntry>,
    /// Journal before PUT: even an ambiguous timeout may have created these records.
    tracked: BTreeMap<String, Value>,
    observed: BTreeMap<String, Value>,
    retry_at: u64,
}
pub struct NetworkService {
    config: NetworkConfig,
    defaults: SignedNetworkDefaults,
    state: Mutex<DnsState>,
    _lock: File,
    client: reqwest::Client,
    provider_url: String,
    credentials: Option<SpaceshipCredentials>,
    probes: Semaphore,
    allow_local_fixture: bool,
}
fn failure(status: StatusCode, message: &'static str) -> ApiError {
    ApiError { status, message }
}
fn unauthorized() -> ApiError {
    failure(StatusCode::UNAUTHORIZED, "network authorization refused")
}
fn unavailable() -> ApiError {
    failure(
        StatusCode::SERVICE_UNAVAILABLE,
        "network service temporarily unavailable",
    )
}
fn conflict() -> ApiError {
    failure(StatusCode::CONFLICT, "stale or conflicting name operation")
}
pub fn token_digest(token: &str) -> Result<String, String> {
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| "invalid token")?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err("token must be canonical base64url of 32 bytes".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"gc/network/grant/v1\0");
    hash.update(bytes);
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}
fn digest(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value))
}
fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|h| h.len() <= 128)
        .ok_or_else(unauthorized)
}
pub fn read_grants(path: &FilePath) -> Result<GrantFile, String> {
    let bytes = std::fs::read(path).map_err(|_| "cannot read network grants")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("network grants exceed limit".into());
    }
    let file: GrantFile = serde_json::from_slice(&bytes).map_err(|_| "invalid network grants")?;
    if file.version != 1 || file.grants.len() > 10_000 {
        return Err("unsupported or oversized grant store".into());
    }
    let mut ids = std::collections::HashSet::new();
    for grant in &file.grants {
        if !ids.insert(&grant.id)
            || grant.scopes.is_empty()
            || grant.scopes.len() > 10
            || grant.max_names > 1000
        {
            return Err("invalid or duplicated network grant".into());
        }
    }
    Ok(file)
}
/// Atomic owner-only persistence shared by service and offline operator tool.
pub fn atomic_json(path: &FilePath, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "cannot encode private state")?;
    atomic_bytes(path, &bytes)
}
pub use crate::persistence::atomic_bytes;
fn random_handle() -> String {
    let mut bytes = [0; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl NetworkService {
    pub fn load(config: NetworkConfig, allow_local_fixture: bool) -> Result<Self, String> {
        if config.network_id != "gchat.boo" || !(300..=86400).contains(&config.name_lease_secs) {
            return Err("invalid network or DNS lease configuration".into());
        }
        super::prepare_state(Some(&config.state_dir), false)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.state_dir.join("publisher.lock"))
            .map_err(|_| "cannot open DNS publisher lock")?;
        lock.try_lock()
            .map_err(|_| "another DNS publisher owns this state directory")?;
        let bytes = std::fs::read(&config.defaults_file)
            .map_err(|_| "cannot read public network defaults")?;
        if bytes.len() > gcoms_network::MAX_DOCUMENT_BYTES {
            return Err("network defaults exceed limit".into());
        }
        let defaults: SignedNetworkDefaults =
            serde_json::from_slice(&bytes).map_err(|_| "invalid network defaults")?;
        let key = std::fs::read(&config.verification_key_file)
            .map_err(|_| "cannot read independent network verification key")?;
        defaults.verify_at(&key, &config.network_id, now_unix(), 0)?;
        read_grants(&config.grants_file)?;
        let path = config.state_dir.join("dns-state.json");
        let state = if path.exists() {
            serde_json::from_slice::<DnsState>(
                &std::fs::read(path).map_err(|_| "cannot read DNS state")?,
            )
            .map_err(|_| "invalid DNS state")?
        } else {
            DnsState::default()
        };
        if state.names.len() > MAX_NAMES {
            return Err("DNS state exceeds reservation limit".into());
        }
        let credentials = config
            .spaceship_credentials_file
            .as_ref()
            .map(|path| {
                let bytes = std::fs::read(path).map_err(|_| "cannot read Spaceship credentials")?;
                let credentials: SpaceshipCredentials =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid Spaceship credentials")?;
                if credentials.api_key.is_empty() || credentials.api_secret.is_empty() {
                    return Err("empty Spaceship credentials");
                }
                Ok(credentials)
            })
            .transpose()?;
        let client = reqwest::Client::builder()
            .user_agent("ghost-network-operator/1.0")
            .https_only(!allow_local_fixture)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| "cannot build DNS HTTP client")?;
        Ok(Self {
            config,
            defaults,
            state: Mutex::new(state),
            _lock: lock,
            client,
            provider_url: "https://spaceship.dev/api/v1/dns/records/gchat.boo".into(),
            credentials,
            probes: Semaphore::new(4),
            allow_local_fixture,
        })
    }
    pub(crate) fn authorize(
        &self,
        headers: &HeaderMap,
        scope: &str,
    ) -> Result<GrantRecord, ApiError> {
        let id = token_digest(bearer(headers)?).map_err(|_| unauthorized())?;
        self.grant_by_id(&id, scope)
    }
    fn grant_by_id(&self, id: &str, scope: &str) -> Result<GrantRecord, ApiError> {
        let grants = read_grants(&self.config.grants_file).map_err(|_| unavailable())?;
        grants
            .grants
            .into_iter()
            .find(|g| {
                g.id == id
                    && !g.revoked
                    && g.expires_at > now_unix()
                    && g.scopes.iter().any(|s| s == scope)
            })
            .ok_or_else(unauthorized)
    }
    fn save(&self, state: &DnsState) -> Result<(), ApiError> {
        atomic_json(&self.config.state_dir.join("dns-state.json"), state).map_err(|_| unavailable())
    }
    async fn probe(&self, encoded: &str) -> Result<gcoms_routing::Relay, ApiError> {
        if encoded.len() > 2048 {
            return Err(ApiError::bad("one listener introduction required"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ApiError::bad("invalid listener introduction"))?;
        let bundle = gcoms_routing::bootstrap::BootstrapBundle::decode(&bytes)
            .map_err(|_| ApiError::bad("invalid listener introduction"))?;
        if bundle.relays.len() != 1 {
            return Err(ApiError::bad("exactly one listener introduction required"));
        }
        let relay = bundle.relays.into_iter().next().unwrap();
        if relay.expires_at <= now_unix()
            || (!self.allow_local_fixture && !gcoms_routing::service::public_ip(relay.addr.ip()))
        {
            return Err(ApiError::bad("listener must be a current public address"));
        }
        let _permit = self
            .probes
            .try_acquire()
            .map_err(|_| failure(StatusCode::TOO_MANY_REQUESTS, "listener probes busy"))?;
        let refreshed = tokio::time::timeout(Duration::from_secs(20), async {
            let tcp = tokio::net::TcpStream::connect(relay.addr).await?;
            gcoms_routing::carrier::refresh(Box::new(tcp), &relay).await
        })
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| {
            failure(
                StatusCode::UNPROCESSABLE_ENTITY,
                "listener identity or reachability verification failed",
            )
        })?;
        if refreshed.first().is_none_or(|verified| {
            verified.service_id != relay.service_id || verified.addr != relay.addr
        }) {
            return Err(unavailable());
        }
        Ok(relay)
    }
    fn response(&self, entry: &NameEntry, state: &DnsState) -> NameResponse {
        let wanted = entry.records(&self.config.network_id, now_unix());
        NameResponse {
            node_handle: entry.handle.clone(),
            fqdn: entry.fqdn.clone(),
            sequence: entry.sequence,
            lease_expires_at: entry.lease_expires_at,
            published: !wanted.is_empty()
                && wanted
                    .iter()
                    .all(|record| state.observed.contains_key(&record_key(record))),
        }
    }
    fn credential<'a>(
        &self,
        state: &'a DnsState,
        handle: &str,
        headers: &HeaderMap,
    ) -> Result<&'a NameEntry, ApiError> {
        let entry = state.names.get(handle).ok_or_else(unauthorized)?;
        let hash = token_digest(bearer(headers)?).map_err(|_| unauthorized())?;
        if hash != entry.credential_hash {
            return Err(unauthorized());
        }
        self.grant_by_id(&entry.grant_id, "names")?;
        Ok(entry)
    }
    fn request(&self, method: reqwest::Method) -> Result<reqwest::RequestBuilder, String> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or("DNS credentials unavailable")?;
        Ok(self
            .client
            .request(method, &self.provider_url)
            .header("X-API-Key", &credentials.api_key)
            .header("X-API-Secret", &credentials.api_secret))
    }
    async fn checked(
        &self,
        response: reqwest::Response,
        state: &mut DnsState,
    ) -> Result<reqwest::Response, String> {
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let wait = response
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| {
                    h.parse::<u64>().ok().or_else(|| {
                        httpdate::parse_http_date(h).ok().map(|t| {
                            t.duration_since(std::time::SystemTime::now())
                                .unwrap_or_default()
                                .as_secs()
                        })
                    })
                })
                .unwrap_or(300)
                .max(1);
            state.retry_at = now_unix().saturating_add(wait);
            self.save(state).map_err(|_| "cannot persist DNS backoff")?;
            return Err("DNS publication rate limited".into());
        }
        if !response.status().is_success() {
            return Err("DNS provider refused publication".into());
        }
        Ok(response)
    }
    /// Desired state itself is the durable coalescing queue. Network calls touch
    /// only this mutex; failures cannot block relay provisioning or private GC.
    pub async fn reconcile(&self) -> Result<(), String> {
        if !self.config.names_enabled || self.credentials.is_none() {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        if state.retry_at > now_unix() {
            return Ok(());
        }
        let grants = read_grants(&self.config.grants_file)?;
        let mut desired = BTreeMap::new();
        for entry in state.names.values() {
            if grants.grants.iter().any(|g| {
                g.id == entry.grant_id
                    && !g.revoked
                    && g.expires_at > now_unix()
                    && g.scopes.iter().any(|s| s == "names")
            }) {
                for record in entry.records(&self.config.network_id, now_unix()) {
                    desired.insert(record_key(&record), record);
                }
            }
        }
        // Read before mutation makes DELETE retry safe even when the previous
        // response was lost: Spaceship refuses a batch containing absent records.
        let mut actual = BTreeMap::new();
        for skip in (0..=MAX_NAMES * 3).step_by(500) {
            let response = self
                .request(reqwest::Method::GET)?
                .query(&[("take", 500), ("skip", skip)])
                .send()
                .await
                .map_err(|_| "DNS provider unavailable")?;
            let response = self.checked(response, &mut state).await?;
            if response
                .content_length()
                .is_some_and(|n| n > 2 * 1024 * 1024)
            {
                return Err("DNS response exceeds limit".into());
            }
            let mut response = response;
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "invalid DNS provider response")?
            {
                if body.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
                    return Err("DNS response exceeds limit".into());
                }
                body.extend_from_slice(&chunk);
            }
            let page: Value =
                serde_json::from_slice(&body).map_err(|_| "invalid DNS provider response")?;
            let items = page
                .get("items")
                .and_then(Value::as_array)
                .ok_or("missing DNS records")?;
            if items.len() > 500 {
                return Err("DNS page exceeds limit".into());
            }
            for item in items {
                let record = normalized_record(item.clone());
                actual.insert(record_key(&record), record);
            }
            if items.len() < 500 {
                break;
            }
            if skip + 500 > MAX_NAMES * 3 {
                return Err("DNS zone exceeds bounded scan".into());
            }
        }
        state.observed = actual.clone();
        let deletes: Vec<_> = state
            .tracked
            .iter()
            .filter(|(key, _)| !desired.contains_key(*key) && actual.contains_key(*key))
            .map(|(_, v)| without_ttl(v.clone()))
            .collect();
        let additions: Vec<_> = desired
            .iter()
            .filter(|(key, v)| actual.get(*key) != Some(*v))
            .map(|(_, v)| v.clone())
            .collect();
        // Every attempted addition is journaled before its external side effect.
        state.tracked.extend(desired.clone());
        self.save(&state)
            .map_err(|_| "cannot journal DNS publication")?;
        for batch in deletes.chunks(500) {
            let response = self
                .request(reqwest::Method::DELETE)?
                .json(batch)
                .send()
                .await
                .map_err(|_| "DNS provider unavailable")?;
            self.checked(response, &mut state).await?;
            for record in batch {
                state.observed.remove(&record_key(record));
            }
            self.save(&state).map_err(|_| "cannot save DNS deletion")?;
        }
        for batch in additions.chunks(500) {
            let response = self
                .request(reqwest::Method::PUT)?
                .json(&json!({"force":false,"items":batch}))
                .send()
                .await
                .map_err(|_| "DNS provider unavailable")?;
            self.checked(response, &mut state).await?;
            for record in batch {
                state.observed.insert(record_key(record), record.clone());
            }
            self.save(&state)
                .map_err(|_| "cannot save DNS publication")?;
        }
        state.tracked.retain(|key, _| desired.contains_key(key));
        state.retry_at = 0;
        self.save(&state)
            .map_err(|_| "cannot save DNS reconciliation".into())
    }
}
fn without_ttl(mut record: Value) -> Value {
    if let Some(map) = record.as_object_mut() {
        map.remove("ttl");
        map.remove("group");
    }
    record
}
fn normalized_record(mut record: Value) -> Value {
    if let Some(map) = record.as_object_mut() {
        map.remove("group");
    }
    record
}
fn record_key(record: &Value) -> String {
    serde_json::to_string(&without_ttl(record.clone())).unwrap()
}
impl NameEntry {
    fn records(&self, domain: &str, now: u64) -> Vec<Value> {
        if self.removed || self.lease_expires_at <= now {
            return vec![];
        }
        let relative = self.fqdn.strip_suffix(&format!(".{domain}")).unwrap();
        vec![
            json!({"type":if self.address.is_ipv4(){"A"}else{"AAAA"},"name":relative,"address":self.address.ip().to_string(),"ttl":300}),
            json!({"type":"SRV","name":relative,"service":"_gchat","protocol":"_tcp","priority":0,"weight":0,"port":self.address.port(),"target":self.fqdn,"ttl":300}),
        ]
    }
}
fn service(state: &AppState) -> Result<&Arc<NetworkService>, ApiError> {
    state
        .network
        .as_ref()
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "network service is not offered here"))
}
pub(crate) async fn defaults(State(state): State<AppState>) -> Result<Response, ApiError> {
    let service = service(&state)?;
    if service.defaults.defaults.expires_at <= now_unix() {
        return Err(unavailable());
    }
    Ok(Json(service.defaults.clone()).into_response())
}
pub(crate) async fn register(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterNameRequest>,
) -> Result<Response, ApiError> {
    let service = service(&app)?;
    if !service.config.names_enabled {
        return Err(unavailable());
    }
    let grant = service.authorize(&headers, "names")?;
    let credential_hash = token_digest(&body.credential_b64)
        .map_err(|_| ApiError::bad("invalid record credential"))?;
    if body.credential_b64 == bearer(&headers)? {
        return Err(ApiError::bad("record credential must be independent"));
    }
    let request_bytes = URL_SAFE_NO_PAD
        .decode(&body.request_id)
        .map_err(|_| ApiError::bad("invalid request_id"))?;
    if !matches!(request_bytes.len(), 16 | 32)
        || URL_SAFE_NO_PAD.encode(&request_bytes) != body.request_id
    {
        return Err(ApiError::bad("invalid request_id"));
    }
    if let Some(label) = &body.server_label {
        if !(1..=8).any(|n| label == &format!("r{n}"))
            || !grant.scopes.contains(&format!("server:{label}"))
        {
            return Err(unauthorized());
        }
    }
    let registration_id = format!("{}:{}", grant.id, body.request_id);
    let registration_hash =
        digest(&serde_json::to_vec(&body).map_err(|_| ApiError::bad("invalid name registration"))?);
    {
        let state = service.state.lock().await;
        if let Some(entry) = state
            .names
            .values()
            .find(|e| e.registration_id == registration_id)
        {
            if entry.registration_hash != registration_hash {
                return Err(conflict());
            }
            return Ok(no_store(
                Json(service.response(entry, &state)).into_response(),
            ));
        }
        if state.names.len() >= MAX_NAMES
            || state
                .names
                .values()
                .filter(|e| e.grant_id == grant.id)
                .count()
                >= grant.max_names as usize
        {
            return Err(failure(
                StatusCode::TOO_MANY_REQUESTS,
                "name reservation limit reached",
            ));
        }
    }
    let relay = service.probe(&body.routing_bundle_b64).await?;
    let grant = service.authorize(&headers, "names")?;
    if let Some(label) = &body.server_label {
        if service
            .defaults
            .defaults
            .founders
            .iter()
            .find(|f| f.name == format!("{label}.relays.{}", service.config.network_id))
            .is_none_or(|f| f.service_id != relay.service_id)
        {
            return Err(unauthorized());
        }
    }
    let mut state = service.state.lock().await;
    if state
        .names
        .values()
        .any(|e| e.registration_id == registration_id)
    {
        return Err(conflict());
    }
    if state.names.len() >= MAX_NAMES
        || state
            .names
            .values()
            .filter(|e| e.grant_id == grant.id)
            .count()
            >= grant.max_names as usize
    {
        return Err(failure(
            StatusCode::TOO_MANY_REQUESTS,
            "name reservation limit reached",
        ));
    }
    let handle = random_handle();
    let fqdn = body
        .server_label
        .map(|name| format!("{name}.relays.{}", service.config.network_id))
        .unwrap_or_else(|| format!("{handle}.nodes.{}", service.config.network_id));
    if state
        .names
        .values()
        .any(|e| e.fqdn == fqdn || e.credential_hash == credential_hash)
    {
        return Err(conflict());
    }
    let entry = NameEntry {
        handle: handle.clone(),
        fqdn,
        grant_id: grant.id,
        credential_hash,
        registration_id,
        registration_hash,
        service_id: relay.service_id,
        address: relay.addr,
        sequence: 1,
        mutation_hash: String::new(),
        lease_expires_at: now_unix()
            .saturating_add(service.config.name_lease_secs)
            .min(grant.expires_at)
            .min(relay.expires_at),
        removed: false,
    };
    let mut candidate = state.clone();
    candidate.names.insert(handle, entry.clone());
    service.save(&candidate)?;
    *state = candidate;
    Ok(no_store(
        (StatusCode::CREATED, Json(service.response(&entry, &state))).into_response(),
    ))
}
pub(crate) async fn update(
    State(app): State<AppState>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateNameRequest>,
) -> Result<Response, ApiError> {
    let service = service(&app)?;
    if !service.config.names_enabled {
        return Err(unavailable());
    }
    let mutation_hash =
        digest(&serde_json::to_vec(&body).map_err(|_| ApiError::bad("invalid update"))?);
    {
        let state = service.state.lock().await;
        let entry = service.credential(&state, &handle, &headers)?;
        if body.sequence == entry.sequence && mutation_hash == entry.mutation_hash {
            return Ok(no_store(
                Json(service.response(entry, &state)).into_response(),
            ));
        }
        if body.sequence != entry.sequence.checked_add(1).ok_or_else(conflict)? {
            return Err(conflict());
        }
    }
    let relay = service.probe(&body.routing_bundle_b64).await?;
    let mut state = service.state.lock().await;
    let old = service.credential(&state, &handle, &headers)?.clone();
    if body.sequence != old.sequence.checked_add(1).ok_or_else(conflict)?
        || relay.service_id != old.service_id
    {
        return Err(conflict());
    }
    let grant = service.grant_by_id(&old.grant_id, "names")?;
    let mut entry = old;
    entry.address = relay.addr;
    entry.sequence = body.sequence;
    entry.mutation_hash = mutation_hash;
    entry.lease_expires_at = now_unix()
        .saturating_add(service.config.name_lease_secs)
        .min(grant.expires_at)
        .min(relay.expires_at);
    entry.removed = false;
    let mut candidate = state.clone();
    candidate.names.insert(handle, entry.clone());
    service.save(&candidate)?;
    *state = candidate;
    Ok(no_store(
        Json(service.response(&entry, &state)).into_response(),
    ))
}
pub(crate) async fn remove(
    State(app): State<AppState>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RemoveNameRequest>,
) -> Result<Response, ApiError> {
    let service = service(&app)?;
    if !service.config.names_enabled {
        return Err(unavailable());
    }
    let mut state = service.state.lock().await;
    let mut entry = service.credential(&state, &handle, &headers)?.clone();
    if entry.removed && body.sequence == entry.sequence {
        return Ok(no_store(
            Json(service.response(&entry, &state)).into_response(),
        ));
    }
    if body.sequence != entry.sequence.checked_add(1).ok_or_else(conflict)? {
        return Err(conflict());
    }
    entry.removed = true;
    entry.sequence = body.sequence;
    entry.mutation_hash = String::new();
    entry.lease_expires_at = now_unix();
    let mut candidate = state.clone();
    candidate.names.insert(handle, entry.clone());
    service.save(&candidate)?;
    *state = candidate;
    Ok(no_store(
        Json(service.response(&entry, &state)).into_response(),
    ))
}

#[cfg(test)]
mod tests;
