pub mod network;
pub mod persistence;
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gcoms_sdk::{CatalogResponse, ChannelId, ChannelVisibility, PublicChannelDescriptor};
use reqwest::Url;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_OWNER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PAGE_SIZE: u16 = 100;
const MAX_DESCRIPTORS: usize = 10_000;
const MAX_IDEMPOTENCY: usize = 10_000;
const MAX_RATE_KEYS: usize = 20_000;
const MAX_DESCRIPTOR_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;
const UPSTREAM_PAGE_LIMIT: usize = 10;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_PERMIT_WAIT: Duration = Duration::from_secs(10);
const MAX_RELAY_CARD_B64: usize = 128 * 1024;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_base_url: String,
    #[serde(default)]
    pub upstream_catalog_urls: Vec<String>,
    pub state_dir: Option<PathBuf>,
    #[serde(default)]
    pub ephemeral_test_mode: bool,
    #[serde(default = "default_source_rate")]
    pub joins_per_source_per_minute: u32,
    #[serde(default = "default_channel_rate")]
    pub joins_per_channel_per_minute: u32,
    #[serde(default)]
    pub channels: Vec<ChannelRouteConfig>,
    #[serde(default)]
    pub relay_bootstrap: Option<RelayBootstrapConfig>,
    #[serde(default)]
    pub network: Option<network::NetworkConfig>,
}

fn default_source_rate() -> u32 {
    20
}

fn default_channel_rate() -> u32 {
    60
}

fn default_relay_source_rate() -> u32 {
    2
}

fn default_relay_global_rate() -> u32 {
    60
}

fn default_relay_in_flight() -> u32 {
    16
}

fn default_relay_idempotency_ttl() -> u64 {
    120
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayBootstrapConfig {
    #[serde(default = "default_relay_source_rate")]
    pub provisions_per_source_per_minute: u32,
    #[serde(default = "default_relay_global_rate")]
    pub provisions_global_per_minute: u32,
    #[serde(default = "default_relay_in_flight")]
    pub max_in_flight: u32,
    #[serde(default = "default_relay_idempotency_ttl")]
    pub idempotency_ttl_secs: u64,
    #[serde(default)]
    pub relay_controls: Vec<OwnerControlConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChannelRouteConfig {
    pub channel_id_b64: String,
    pub channel_name: String,
    pub visibility: ConfigVisibility,
    pub owner_control: OwnerControlConfig,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigVisibility {
    Public,
    Private,
}

impl From<ConfigVisibility> for ChannelVisibility {
    fn from(value: ConfigVisibility) -> Self {
        match value {
            ConfigVisibility::Public => Self::Public,
            ConfigVisibility::Private => Self::Private,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct OwnerControlConfig {
    pub address: String,
    pub server_name: String,
    pub ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub bearer_token_file: PathBuf,
}

#[derive(Clone)]
struct Route {
    channel_name: String,
    visibility: ChannelVisibility,
    owner: OwnerClient,
}

#[derive(Clone)]
struct OwnerClient {
    address: String,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    token: Arc<str>,
}

#[derive(Clone)]
pub struct AppState {
    config: Arc<RuntimeConfig>,
    inner: Arc<Mutex<Inner>>,
    client: reqwest::Client,
    network: Option<Arc<network::NetworkService>>,
}

struct RuntimeConfig {
    public_base_url: Url,
    upstreams: Vec<Url>,
    state_file: Option<PathBuf>,
    source_rate: u32,
    channel_rate: u32,
    routes: HashMap<ChannelId, Route>,
    relay_bootstrap: Option<Arc<RelayBootstrap>>,
}

struct RelayBootstrap {
    source_rate: u32,
    global_rate: u32,
    in_flight: Arc<tokio::sync::Semaphore>,
    idempotency_ttl_secs: u64,
    relays: Vec<OwnerClient>,
}

#[derive(Default)]
struct Inner {
    descriptors: BTreeMap<[u8; 32], PublicChannelDescriptor>,
    idempotency: HashMap<String, JoinResponse>,
    idempotency_order: VecDeque<String>,
    source_rates: HashMap<IpAddr, Window>,
    channel_rates: HashMap<[u8; 32], Window>,
    relay_source_rates: HashMap<IpAddr, Window>,
    relay_global_rate: Option<Window>,
    relay_idempotency: HashMap<String, (RelayBootstrapResponse, u64)>,
    relay_idempotency_order: VecDeque<String>,
}

#[derive(Clone, Copy)]
struct Window {
    minute: u64,
    count: u32,
}

#[derive(Debug, Deserialize)]
struct CatalogQuery {
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct JoinBody {
    pub display_pseudonym: String,
    pub key_package_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct RelayProvisionBody {
    pub request_id: String,
    #[serde(default)]
    pub supported_versions: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayProvisionResponse {
    pub version: u8,
    pub private_card_b64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum RelayBootstrapResponse {
    Legacy(RelayProvisionResponse),
    #[cfg(feature = "experimental-gc2")]
    Gc2 {
        version: u8,
        routing_protocol: String,
        routing_bundle_b64: String,
    },
    Routing {
        version: u8,
        routing_bundle_b64: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    pub channel: String,
    pub visibility: ChannelVisibility,
    pub welcome_b64: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    descriptors: Vec<PublicChannelDescriptor>,
    idempotency: Vec<(String, JoinResponse)>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

impl AppState {
    /// DNS publication has an independent worker; failures never stop GC routing.
    pub fn start_network_publisher(&self) {
        if let Some(network) = &self.network {
            let network = network.clone();
            tokio::spawn(async move {
                loop {
                    let _ = network.reconcile().await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            });
        }
    }
    pub async fn load(config: Config) -> Result<Self, String> {
        if config.joins_per_source_per_minute == 0 || config.joins_per_channel_per_minute == 0 {
            return Err("join rate limits must be greater than zero".into());
        }
        let public_base_url =
            parse_catalog_url(&config.public_base_url, config.ephemeral_test_mode)?;
        if public_base_url
            .host_str()
            .is_some_and(|host| host == "gchat.boo" || host.ends_with(".gchat.boo"))
            && config.network.is_none()
        {
            return Err("gchat.boo requires invitation network authorization configuration".into());
        }
        let upstreams = config
            .upstream_catalog_urls
            .iter()
            .map(|url| parse_catalog_url(url, config.ephemeral_test_mode))
            .collect::<Result<Vec<_>, _>>()?;
        let state_file = prepare_state(config.state_dir.as_deref(), config.ephemeral_test_mode)?;
        let mut routes = HashMap::new();
        for route in config.channels {
            let channel_id = decode_channel_id(&route.channel_id_b64)?;
            if route.channel_name.is_empty() || route.channel_name.len() > 255 {
                return Err("channel_name must contain 1..=255 bytes".into());
            }
            if routes.contains_key(&channel_id) {
                return Err("duplicate configured channel route".into());
            }
            routes.insert(
                channel_id,
                Route {
                    channel_name: route.channel_name,
                    visibility: route.visibility.into(),
                    owner: OwnerClient::load(route.owner_control)?,
                },
            );
        }
        let relay_bootstrap = match config.relay_bootstrap {
            Some(bootstrap) => {
                if bootstrap.provisions_per_source_per_minute == 0
                    || bootstrap.provisions_global_per_minute == 0
                    || bootstrap.max_in_flight == 0
                {
                    return Err("relay bootstrap limits must be greater than zero".into());
                }
                if !(1..=3600).contains(&bootstrap.idempotency_ttl_secs) {
                    return Err("relay bootstrap idempotency_ttl_secs must be 1..=3600".into());
                }
                if bootstrap.relay_controls.is_empty() || bootstrap.relay_controls.len() > 8 {
                    return Err("relay bootstrap requires one to eight relay controls".into());
                }
                let mut relays = Vec::with_capacity(bootstrap.relay_controls.len());
                for control in bootstrap.relay_controls {
                    relays.push(OwnerClient::load(control)?);
                }
                Some(Arc::new(RelayBootstrap {
                    source_rate: bootstrap.provisions_per_source_per_minute,
                    global_rate: bootstrap.provisions_global_per_minute,
                    in_flight: Arc::new(tokio::sync::Semaphore::new(
                        bootstrap.max_in_flight as usize,
                    )),
                    idempotency_ttl_secs: bootstrap.idempotency_ttl_secs,
                    relays,
                }))
            }
            None => None,
        };
        let mut inner = Inner::default();
        if let Some(path) = &state_file {
            if path.exists() {
                let bytes = std::fs::read(path)
                    .map_err(|error| format!("read catalog state {}: {error}", path.display()))?;
                let snapshot: Snapshot = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("parse catalog state {}: {error}", path.display()))?;
                let now = now_unix();
                for descriptor in snapshot.descriptors.into_iter().take(MAX_DESCRIPTORS) {
                    if validate_descriptor(&descriptor, now, None, config.ephemeral_test_mode)
                        .is_ok()
                    {
                        inner
                            .descriptors
                            .insert(descriptor.channel_id.0, descriptor);
                    }
                }
                for (key, response) in snapshot.idempotency.into_iter().take(MAX_IDEMPOTENCY) {
                    inner.idempotency_order.push_back(key.clone());
                    inner.idempotency.insert(key, response);
                }
            }
        }
        let client = reqwest::Client::builder()
            .https_only(!config.ephemeral_test_mode)
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("build upstream client: {error}"))?;
        let network = match config.network {
            Some(network_config) => Some(Arc::new(network::NetworkService::load(
                network_config,
                config.ephemeral_test_mode,
            )?)),
            None => None,
        };
        Ok(Self {
            network,
            config: Arc::new(RuntimeConfig {
                public_base_url,
                upstreams,
                state_file,
                source_rate: config.joins_per_source_per_minute,
                channel_rate: config.joins_per_channel_per_minute,
                routes,
                relay_bootstrap,
            }),
            inner: Arc::new(Mutex::new(inner)),
            client,
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/catalog", get(query_catalog))
        .route("/v1/descriptors", put(publish_descriptor))
        .route("/v1/channels/{channel_id}/join", post(join_channel))
        .route("/v1/relay-provisions", post(relay_provision))
        .route("/v1/network-defaults", get(network::defaults))
        .route("/v1/names", post(network::register))
        .route(
            "/v1/names/{handle}",
            put(network::update).delete(network::remove),
        )
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(35),
        ))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(_): State<AppState>) -> StatusCode {
    StatusCode::OK
}

async fn publish_descriptor(
    State(state): State<AppState>,
    Json(descriptor): Json<PublicChannelDescriptor>,
) -> Result<StatusCode, ApiError> {
    validate_descriptor(
        &descriptor,
        now_unix(),
        Some(&state.config.public_base_url),
        state.config.public_base_url.scheme() == "http",
    )?;
    let mut inner = state.inner.lock().await;
    if let Some(known) = inner.descriptors.get(&descriptor.channel_id.0) {
        if known == &descriptor {
            return Ok(StatusCode::NO_CONTENT);
        }
        if descriptor.expires_at_unix <= known.expires_at_unix {
            return Err(ApiError {
                status: StatusCode::CONFLICT,
                message: "descriptor is not newer",
            });
        }
    } else if inner.descriptors.len() >= MAX_DESCRIPTORS {
        return Err(ApiError {
            status: StatusCode::INSUFFICIENT_STORAGE,
            message: "descriptor capacity reached",
        });
    }
    inner
        .descriptors
        .insert(descriptor.channel_id.0, descriptor);
    persist(&state.config, &inner).map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn query_catalog(
    State(state): State<AppState>,
    Query(query): Query<CatalogQuery>,
) -> Result<Json<CatalogResponse>, ApiError> {
    let limit = query.limit.unwrap_or(50);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(ApiError::bad("limit must be between 1 and 100"));
    }
    let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;
    let now = now_unix();
    let local = {
        let inner = state.inner.lock().await;
        inner.descriptors.values().cloned().collect::<Vec<_>>()
    };
    let mut union = BTreeMap::<[u8; 32], PublicChannelDescriptor>::new();
    for descriptor in local {
        add_valid_descriptor(
            &mut union,
            descriptor,
            now,
            state.config.public_base_url.scheme() == "http",
        );
    }
    for upstream in &state.config.upstreams {
        fetch_upstream(&state, upstream, now, &mut union).await;
    }
    let mut after = union
        .into_iter()
        .filter(|(id, _)| cursor.is_none_or(|cursor| *id > cursor))
        .map(|(_, descriptor)| descriptor);
    let descriptors = after.by_ref().take(usize::from(limit)).collect::<Vec<_>>();
    let has_more = after.next().is_some();
    let next_cursor = has_more
        .then(|| {
            descriptors
                .last()
                .map(|descriptor| encode_id(descriptor.channel_id.0))
        })
        .flatten();
    Ok(Json(CatalogResponse {
        descriptors,
        next_cursor,
    }))
}

async fn fetch_upstream(
    state: &AppState,
    upstream: &Url,
    now: u64,
    union: &mut BTreeMap<[u8; 32], PublicChannelDescriptor>,
) {
    let Ok(mut url) = upstream.join("v1/catalog") else {
        return;
    };
    let mut cursor: Option<String> = None;
    for _ in 0..UPSTREAM_PAGE_LIMIT {
        url.query_pairs_mut()
            .clear()
            .append_pair("limit", &MAX_PAGE_SIZE.to_string());
        if let Some(value) = &cursor {
            url.query_pairs_mut().append_pair("cursor", value);
        }
        let Ok(response) = state.client.get(url.clone()).send().await else {
            return;
        };
        if !response.status().is_success() {
            return;
        }
        let Ok(page) = response.json::<CatalogResponse>().await else {
            return;
        };
        if page.descriptors.len() > usize::from(MAX_PAGE_SIZE) {
            return;
        }
        for descriptor in page.descriptors {
            add_valid_descriptor(
                union,
                descriptor,
                now,
                state.config.public_base_url.scheme() == "http",
            );
        }
        let Some(next) = page.next_cursor else {
            return;
        };
        if cursor.as_ref() == Some(&next) {
            return;
        }
        cursor = Some(next);
    }
}

fn add_valid_descriptor(
    union: &mut BTreeMap<[u8; 32], PublicChannelDescriptor>,
    descriptor: PublicChannelDescriptor,
    now: u64,
    allow_http: bool,
) {
    if validate_descriptor(&descriptor, now, None, allow_http).is_err() {
        return;
    }
    match union.get(&descriptor.channel_id.0) {
        Some(known) if known.expires_at_unix >= descriptor.expires_at_unix => {}
        _ => {
            union.insert(descriptor.channel_id.0, descriptor);
        }
    }
}

async fn join_channel(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(channel_id_b64): AxumPath<String>,
    Json(body): Json<JoinBody>,
) -> Result<Json<JoinResponse>, ApiError> {
    let channel_id =
        decode_channel_id(&channel_id_b64).map_err(|_| ApiError::bad("invalid channel id"))?;
    let route = state.config.routes.get(&channel_id).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        message: "channel is not routed here",
    })?;
    if body.display_pseudonym.is_empty() || body.display_pseudonym.len() > 255 {
        return Err(ApiError::bad(
            "display_pseudonym must contain 1..=255 bytes",
        ));
    }
    let key_package = URL_SAFE_NO_PAD
        .decode(&body.key_package_b64)
        .map_err(|_| ApiError::bad("invalid key_package_b64"))?;
    if key_package.is_empty() || key_package.len() > 48 * 1024 {
        return Err(ApiError::bad("key package size is out of bounds"));
    }
    let digest = Sha256::digest(&key_package);
    let cache_key = format!(
        "{}:{}",
        encode_id(channel_id.0),
        URL_SAFE_NO_PAD.encode(digest)
    );
    {
        let mut inner = state.inner.lock().await;
        if let Some(response) = inner.idempotency.get(&cache_key).cloned() {
            return Ok(Json(response));
        }
        let minute = now_unix() / 60;
        if !take_rate(
            &mut inner.source_rates,
            peer.ip(),
            minute,
            state.config.source_rate,
        ) || !take_rate(
            &mut inner.channel_rates,
            channel_id.0,
            minute,
            state.config.channel_rate,
        ) {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "join rate limit exceeded",
            });
        }
    }
    let welcome_b64 = route
        .owner
        .admit(
            &route.channel_name,
            &body.display_pseudonym,
            &body.key_package_b64,
        )
        .await
        .map_err(owner_error)?;
    URL_SAFE_NO_PAD
        .decode(&welcome_b64)
        .map_err(|_| internal_error("owner returned invalid welcome".into()))?;
    let response = JoinResponse {
        channel: route.channel_name.clone(),
        visibility: route.visibility,
        welcome_b64,
    };
    let mut inner = state.inner.lock().await;
    if let Some(cached) = inner.idempotency.get(&cache_key).cloned() {
        return Ok(Json(cached));
    }
    while inner.idempotency.len() >= MAX_IDEMPOTENCY {
        if let Some(oldest) = inner.idempotency_order.pop_front() {
            inner.idempotency.remove(&oldest);
        }
    }
    inner.idempotency_order.push_back(cache_key.clone());
    inner.idempotency.insert(cache_key, response.clone());
    persist(&state.config, &inner).map_err(internal_error)?;
    Ok(Json(response))
}

fn take_rate<K: Eq + std::hash::Hash + Copy>(
    rates: &mut HashMap<K, Window>,
    key: K,
    minute: u64,
    limit: u32,
) -> bool {
    if rates.len() >= MAX_RATE_KEYS && !rates.contains_key(&key) {
        rates.retain(|_, window| window.minute == minute);
        if rates.len() >= MAX_RATE_KEYS {
            return false;
        }
    }
    let window = rates.entry(key).or_insert(Window { minute, count: 0 });
    if window.minute != minute {
        *window = Window { minute, count: 0 };
    }
    if window.count >= limit {
        return false;
    }
    window.count += 1;
    true
}

fn take_single_rate(window: &mut Option<Window>, minute: u64, limit: u32) -> bool {
    let current = match window {
        Some(known) if known.minute == minute => *known,
        _ => Window { minute, count: 0 },
    };
    if current.count >= limit {
        return false;
    }
    *window = Some(Window {
        minute,
        count: current.count + 1,
    });
    true
}

async fn relay_provision(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RelayProvisionBody>,
) -> Result<Response, ApiError> {
    let bootstrap = state.config.relay_bootstrap.clone().ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        message: "relay provisioning is not offered here",
    })?;
    // Authenticate before any cache lookup, control call, or capacity consumption.
    let grant_namespace = match &state.network {
        Some(network) => network.authorize(&headers, "bootstrap")?.id,
        None => "legacy".into(),
    };
    let version = match body.supported_versions.as_deref() {
        None => 1,
        #[cfg(feature = "experimental-gc2")]
        Some(v) if v.len() <= 8 && v.contains(&3) => 3,
        Some(v) if v.len() <= 8 && v.contains(&2) => 2,
        Some(v) if v.len() <= 8 && v.contains(&1) => 1,
        _ => return Err(ApiError::bad("unsupported bootstrap version")),
    };
    let request_id = body.request_id;
    let request_bytes = URL_SAFE_NO_PAD
        .decode(&request_id)
        .map_err(|_| ApiError::bad("invalid request_id"))?;
    if !matches!(request_bytes.len(), 16 | 32)
        || URL_SAFE_NO_PAD.encode(&request_bytes) != request_id
    {
        return Err(ApiError::bad(
            "request_id must be canonical base64url of 16 or 32 bytes",
        ));
    }
    let request_id = format!("{grant_namespace}:{version}:{request_id}");
    let now = now_unix();
    {
        let mut inner = state.inner.lock().await;
        if let Some((response, expires)) = inner.relay_idempotency.get(&request_id) {
            if *expires > now {
                let response = response.clone();
                return Ok(no_store(Json(response).into_response()));
            }
        }
        let minute = now / 60;
        if !take_rate(
            &mut inner.relay_source_rates,
            peer.ip(),
            minute,
            bootstrap.source_rate,
        ) || !take_single_rate(&mut inner.relay_global_rate, minute, bootstrap.global_rate)
        {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "relay provisioning rate limit exceeded",
            });
        }
    }
    let _permit = tokio::time::timeout(
        RELAY_PERMIT_WAIT,
        tokio::sync::Semaphore::acquire_owned(bootstrap.in_flight.clone()),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?;
    if let Some(network) = &state.network {
        network.authorize(&headers, "bootstrap")?;
    }
    let allow_local = state.config.public_base_url.scheme() == "http";
    let (response, authority_expiry) = if version == 3 {
        #[cfg(feature = "experimental-gc2")]
        {
            gc2_bootstrap_response(&bootstrap, allow_local).await?
        }
        #[cfg(not(feature = "experimental-gc2"))]
        {
            return Err(ApiError::bad("GC/2 bootstrap is not enabled"));
        }
    } else if version == 2 {
        let mut relays: Vec<gcoms_routing::Relay> = Vec::new();
        for relay in &bootstrap.relays {
            let Ok(bundle) = relay.routing_bootstrap().await else {
                continue;
            };
            for intro in bundle.relays {
                if intro.expires_at <= now
                    || (!allow_local && !gcoms_routing::service::public_ip(intro.addr.ip()))
                {
                    continue;
                }
                if !relays
                    .iter()
                    .any(|r| r.service_id == intro.service_id || r.addr.ip() == intro.addr.ip())
                {
                    relays.push(intro);
                }
                if relays.len() == 8 {
                    break;
                }
            }
            if relays.len() == 8 {
                break;
            }
        }
        let bytes = gcoms_routing::bootstrap::BootstrapBundle { relays }
            .encode()
            .map_err(|_| unavailable())?;
        (
            RelayBootstrapResponse::Routing {
                version: 2,
                routing_bundle_b64: URL_SAFE_NO_PAD.encode(bytes),
            },
            u64::MAX,
        )
    } else {
        let mut encoded = None;
        for relay in &bootstrap.relays {
            if let Ok(card) = relay.provision_private_card().await {
                if validate_relay_card(&card, allow_local).is_ok() {
                    encoded = Some(card);
                    break;
                }
            }
        }
        (
            RelayBootstrapResponse::Legacy(RelayProvisionResponse {
                version: 1,
                private_card_b64: encoded.ok_or_else(unavailable)?,
            }),
            u64::MAX,
        )
    };
    drop(_permit);
    if let Some(network) = &state.network {
        network.authorize(&headers, "bootstrap")?;
    }
    let expires_at = (now_unix() + bootstrap.idempotency_ttl_secs).min(authority_expiry);
    if expires_at <= now_unix() {
        return Err(unavailable());
    }
    let mut inner = state.inner.lock().await;
    if let Some((cached, cached_expiry)) = inner.relay_idempotency.get(&request_id) {
        if *cached_expiry > expires_at {
            let cached = cached.clone();
            return Ok(no_store(Json(cached).into_response()));
        }
    }
    prune_relay_idempotency(&mut inner, now_unix());
    inner
        .relay_idempotency
        .insert(request_id.clone(), (response.clone(), expires_at));
    inner.relay_idempotency_order.push_back(request_id);
    Ok(no_store(Json(response).into_response()))
}

fn unavailable() -> ApiError {
    ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "relay provisioning is temporarily unavailable",
    }
}

#[cfg(feature = "experimental-gc2")]
async fn gc2_bootstrap_response(
    bootstrap: &RelayBootstrap,
    allow_local: bool,
) -> Result<(RelayBootstrapResponse, u64), ApiError> {
    let mut relays: Vec<gcoms_routing::gc2::directory::Introduction> = Vec::new();
    for relay in &bootstrap.relays {
        let Ok(bundle) = relay.gc2_routing_bootstrap().await else {
            continue;
        };
        for intro in bundle.relays {
            if intro.entry(now_unix()).is_err()
                || (!allow_local && !gcoms_routing::service::public_ip(intro.addr.ip()))
            {
                continue;
            }
            if !relays
                .iter()
                .any(|r| r.conflicts(intro.addr, intro.service_id))
            {
                relays.push(intro);
            }
            if relays.len() == 8 {
                break;
            }
        }
        if relays.len() == 8 {
            break;
        }
    }
    // Control requests can straddle a credential rollover. Never cache an
    // already-expired response or retain it past its shortest authority.
    relays.retain(|intro| intro.entry(now_unix()).is_ok());
    let expiry = relays
        .iter()
        .map(|r| r.expires_at)
        .min()
        .ok_or_else(unavailable)?;
    let bytes = gcoms_routing::gc2::directory::BootstrapBundle { relays }
        .encode()
        .map_err(|_| unavailable())?;
    Ok((
        RelayBootstrapResponse::Gc2 {
            version: 3,
            routing_protocol: "gc2".into(),
            routing_bundle_b64: URL_SAFE_NO_PAD.encode(bytes),
        },
        expiry,
    ))
}

fn prune_relay_idempotency(inner: &mut Inner, now: u64) {
    inner
        .relay_idempotency
        .retain(|_, (_, expires)| *expires > now);
    inner
        .relay_idempotency_order
        .retain(|key| inner.relay_idempotency.contains_key(key));
    while inner.relay_idempotency.len() >= MAX_IDEMPOTENCY {
        if let Some(oldest) = inner.relay_idempotency_order.pop_front() {
            inner.relay_idempotency.remove(&oldest);
        }
    }
}

fn no_store(response: Response) -> Response {
    let mut response = response;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

fn validate_relay_card(encoded: &str, allow_local: bool) -> Result<(), ApiError> {
    let invalid = || unavailable();
    if encoded.is_empty() || encoded.len() > MAX_RELAY_CARD_B64 {
        return Err(invalid());
    }
    let info = gcoms_node::proto::private_info_from_b64(encoded).ok_or_else(invalid)?;
    if info.validate_relay_provision(now_unix(), allow_local) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn validate_descriptor(
    descriptor: &PublicChannelDescriptor,
    now: u64,
    expected_catalog: Option<&Url>,
    allow_http: bool,
) -> Result<(), ApiError> {
    if !descriptor.verify_at(now) {
        return Err(ApiError::bad("invalid or expired descriptor signature"));
    }
    if descriptor.expires_at_unix > now.saturating_add(MAX_DESCRIPTOR_LIFETIME_SECS)
        || descriptor.capacity > 1_000_000
        || descriptor.title.len() > 128
        || descriptor.description.len() > 1024
        || descriptor.owner_public_key.len() > 4096
        || descriptor.signature.len() > 4096
    {
        return Err(ApiError::bad("descriptor bounds exceeded"));
    }
    let catalog = Url::parse(&descriptor.automatic_join.catalog)
        .map_err(|_| ApiError::bad("invalid automatic join catalog URL"))?;
    if (!allow_http && catalog.scheme() != "https")
        || (allow_http && catalog.scheme() != "https" && catalog.scheme() != "http")
        || catalog.cannot_be_a_base()
        || catalog.query().is_some()
        || catalog.fragment().is_some()
        || catalog.username() != ""
        || catalog.password().is_some()
    {
        return Err(ApiError::bad("unsafe automatic join catalog URL"));
    }
    let normalized = normalize_base(catalog);
    if expected_catalog.is_some_and(|expected| normalize_base(expected.clone()) != normalized) {
        return Err(ApiError::bad("descriptor targets a different catalog"));
    }
    let expected_endpoint = normalized
        .join(&format!(
            "v1/channels/{}/join",
            encode_id(descriptor.channel_id.0)
        ))
        .map_err(|_| ApiError::bad("invalid automatic join endpoint"))?;
    let endpoint = Url::parse(&descriptor.automatic_join.endpoint)
        .map_err(|_| ApiError::bad("invalid automatic join endpoint"))?;
    if endpoint != expected_endpoint {
        return Err(ApiError::bad(
            "automatic join endpoint does not match channel and catalog",
        ));
    }
    Ok(())
}

fn normalize_base(mut url: Url) -> Url {
    url.set_path(&format!("{}/", url.path().trim_end_matches('/')));
    url
}

fn parse_catalog_url(value: &str, allow_http: bool) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| format!("invalid catalog URL: {error}"))?;
    if (!allow_http && url.scheme() != "https")
        || (allow_http && url.scheme() != "https" && url.scheme() != "http")
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
    {
        return Err("catalog URLs must be credential-free HTTPS base URLs".into());
    }
    Ok(normalize_base(url))
}

fn prepare_state(state_dir: Option<&Path>, ephemeral: bool) -> Result<Option<PathBuf>, String> {
    let Some(directory) = state_dir else {
        return if ephemeral {
            Ok(None)
        } else {
            Err("state_dir is required unless ephemeral_test_mode is true".into())
        };
    };
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("create state directory {}: {error}", directory.display()))?;
    gcoms_private_fs::make_private(directory, true)?;
    gcoms_private_fs::validate_private_dir(directory, "state directory")?;
    Ok(Some(directory.join("state.json")))
}

fn persist(config: &RuntimeConfig, inner: &Inner) -> Result<(), String> {
    let Some(path) = &config.state_file else {
        return Ok(());
    };
    let snapshot = Snapshot {
        descriptors: inner.descriptors.values().cloned().collect(),
        idempotency: inner
            .idempotency_order
            .iter()
            .filter_map(|key| {
                inner
                    .idempotency
                    .get(key)
                    .cloned()
                    .map(|value| (key.clone(), value))
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|error| format!("encode state: {error}"))?;
    persistence::atomic_bytes(path, &bytes)
}

impl OwnerClient {
    fn load(config: OwnerControlConfig) -> Result<Self, String> {
        let token = std::fs::read_to_string(&config.bearer_token_file)
            .map_err(|error| format!("read owner bearer token file: {error}"))?;
        let token = token.trim_end_matches(['\r', '\n']);
        if token.len() < 32 {
            return Err("owner bearer token must contain at least 32 bytes".into());
        }
        let roots = read_certificates(&config.ca_file, "owner server CA")?;
        let certificates = read_certificates(&config.client_cert_file, "owner client certificate")?;
        let key_bytes = std::fs::read(&config.client_key_file)
            .map_err(|error| format!("read owner client key: {error}"))?;
        let key = rustls::pki_types::PrivateKeyDer::pem_slice_iter(&key_bytes)
            .next()
            .transpose()
            .map_err(|error| format!("parse owner client key: {error}"))?
            .ok_or("owner client key file contains no key")?;
        let mut root_store = rustls::RootCertStore::empty();
        for root in roots {
            root_store
                .add(root)
                .map_err(|error| format!("invalid owner CA: {error}"))?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| format!("build owner TLS config: {error}"))?
            .with_root_certificates(root_store)
            .with_client_auth_cert(certificates, key)
            .map_err(|error| format!("invalid owner client identity: {error}"))?;
        tls.resumption = rustls::client::Resumption::disabled();
        let server_name = match config.server_name.parse::<IpAddr>() {
            Ok(address) => ServerName::IpAddress(address.into()),
            Err(_) => ServerName::try_from(config.server_name)
                .map_err(|_| "invalid owner TLS server_name")?,
        };
        Ok(Self {
            address: config.address,
            server_name,
            connector: TlsConnector::from(Arc::new(tls)),
            token: Arc::from(token.to_owned()),
        })
    }

    async fn admit(
        &self,
        channel: &str,
        member: &str,
        key_package_b64: &str,
    ) -> Result<String, String> {
        let data = self
            .call(json!({
                "cmd": "admit",
                "channel": channel,
                "member_name": member,
                "kp_b64": key_package_b64,
            }))
            .await?;
        data.pointer("/welcome_b64")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "owner response omitted welcome".into())
    }

    async fn routing_bootstrap(&self) -> Result<gcoms_routing::bootstrap::BootstrapBundle, String> {
        let data = self.call(json!({"cmd": "routing_bootstrap"})).await?;
        let text = data
            .get("routing_bundle_b64")
            .and_then(Value::as_str)
            .ok_or("relay omitted introductions")?;
        if text.len() > gcoms_routing::bootstrap::MAX_BUNDLE_BYTES * 4 / 3 + 4 {
            return Err("relay introductions exceed limit".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| "invalid relay introductions")?;
        gcoms_routing::bootstrap::BootstrapBundle::decode(&bytes).map_err(|e| e.to_string())
    }

    #[cfg(feature = "experimental-gc2")]
    async fn gc2_routing_bootstrap(
        &self,
    ) -> Result<gcoms_routing::gc2::directory::BootstrapBundle, String> {
        // Control version 2 selects GCRB2. It is not HTTP envelope version 2.
        let data = self
            .call(json!({"cmd": "routing_bootstrap", "version": 2}))
            .await?;
        if data.get("version").and_then(Value::as_u64) != Some(2) {
            return Err("relay did not provide GC/2 introductions".into());
        }
        let text = data
            .get("routing_bundle_b64")
            .and_then(Value::as_str)
            .ok_or("relay omitted GC/2 introductions")?;
        if text.len() > gcoms_routing::gc2::directory::MAX_BUNDLE_BYTES * 4 / 3 + 4 {
            return Err("GC/2 relay introductions exceed limit".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| "invalid GC/2 introductions")?;
        if URL_SAFE_NO_PAD.encode(&bytes) != text {
            return Err("noncanonical GC/2 introductions".into());
        }
        gcoms_routing::gc2::directory::BootstrapBundle::decode(&bytes).map_err(|e| e.to_string())
    }

    async fn provision_private_card(&self) -> Result<String, String> {
        let data = self.call(json!({"cmd": "provision_client_relay"})).await?;
        data.pointer("/private_card_b64")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "relay control response omitted private card".into())
    }

    async fn call(&self, mut request: Value) -> Result<Value, String> {
        request["id"] = json!(1);
        request["token"] = json!(self.token.as_ref());
        let tcp = tokio::time::timeout(CONTROL_TIMEOUT, TcpStream::connect(&self.address))
            .await
            .map_err(|_| "owner connection timed out".to_string())?
            .map_err(|error| format!("owner connection failed: {error}"))?;
        let mut stream = tokio::time::timeout(
            CONTROL_TIMEOUT,
            self.connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| "owner TLS handshake timed out".to_string())?
        .map_err(|error| format!("owner TLS authentication failed: {error}"))?;
        stream
            .write_all(format!("{request}\n").as_bytes())
            .await
            .map_err(|_| "owner request failed".to_string())?;
        let mut line = String::new();
        tokio::time::timeout(
            CONTROL_TIMEOUT,
            BufReader::new(stream.take((MAX_OWNER_RESPONSE_BYTES + 1) as u64)).read_line(&mut line),
        )
        .await
        .map_err(|_| "owner response timed out".to_string())?
        .map_err(|_| "owner response failed".to_string())?;
        if line.len() > MAX_OWNER_RESPONSE_BYTES {
            return Err("owner response too large".into());
        }
        let response: Value = serde_json::from_str(&line).map_err(|_| "invalid owner response")?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("owner rejected request")
                .to_owned());
        }
        Ok(response.get("data").cloned().unwrap_or(Value::Null))
    }
}

fn read_certificates(
    path: &Path,
    description: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {description}: {error}"))?;
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse {description}: {error}"))?;
    if certificates.is_empty() {
        return Err(format!("{description} contains no certificates"));
    }
    Ok(certificates)
}

fn decode_channel_id(value: &str) -> Result<ChannelId, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "invalid channel id")?;
    let id: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "channel id must be 32 bytes")?;
    Ok(ChannelId(id))
}

fn encode_id(id: [u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(id)
}

fn decode_cursor(value: &str) -> Result<[u8; 32], ApiError> {
    decode_channel_id(value)
        .map(|id| id.0)
        .map_err(|_| ApiError::bad("invalid cursor"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn internal_error(_error: String) -> ApiError {
    ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "internal service error",
    }
}

fn owner_error(error: String) -> ApiError {
    let lower = error.to_ascii_lowercase();
    let (status, message) = if lower.contains("capacity") || lower.contains("full") {
        (StatusCode::CONFLICT, "channel capacity reached")
    } else if lower.contains("duplicate") || lower.contains("already") {
        (StatusCode::CONFLICT, "owner rejected duplicate admission")
    } else {
        (StatusCode::BAD_GATEWAY, "owner admission failed")
    };
    ApiError { status, message }
}
