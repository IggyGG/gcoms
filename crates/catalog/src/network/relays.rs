//! Member-authorized public relay contributions. DNS naming is independent.
use super::*;
use gcoms_network::{RelayRegistrationRequest, RelayRegistrationResponse};
use gcoms_routing::gc2::{
    directory::{BootstrapBundle, Introduction},
    discovery,
};
use rand::seq::SliceRandom;

const MAX_RELAYS: usize = 1024;
const MAX_PER_GRANT: usize = 64;
const LEASE_SECONDS: u64 = 300;

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    grant_id: String,
    bundle_b64: String,
    lease_expires_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Registry {
    entries: BTreeMap<String, Entry>,
}

impl Registry {
    pub fn load(path: &FilePath) -> Result<Self, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(_) => return Err("cannot read relay registry".into()),
        };
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("relay registry exceeds byte limit".into());
        }
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| "invalid relay registry")?;
        if value.entries.len() > MAX_RELAYS {
            return Err("relay registry exceeds entry limit".into());
        }
        Ok(value)
    }
}

fn key(pin: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(pin)
}

fn intro(encoded: &str) -> Result<Introduction, ApiError> {
    if encoded.len() > 1024 {
        return Err(ApiError::bad("one GC/2 introduction required"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::bad("invalid GC/2 introduction"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(ApiError::bad("noncanonical GC/2 introduction"));
    }
    let mut bundle =
        BootstrapBundle::decode(&bytes).map_err(|_| ApiError::bad("invalid GC/2 introduction"))?;
    if bundle.relays.len() != 1 {
        return Err(ApiError::bad("one GC/2 introduction required"));
    }
    Ok(bundle.relays.remove(0))
}

impl NetworkService {
    fn relay_path(&self) -> PathBuf {
        self.config.state_dir.join("relay-state.json")
    }

    /// Only recent independent listener proofs enter a provider bundle. Grants
    /// are checked again here, so revocation also withdraws existing entries.
    pub(crate) async fn contributed_relays(&self) -> Vec<Introduction> {
        let now = now_unix();
        let Ok(grants) = read_grants(&self.config.grants_file) else {
            return vec![];
        };
        let registry = self.relays.lock().await;
        let mut relays: Vec<_> = registry
            .entries
            .values()
            .filter(|entry| {
                entry.lease_expires_at > now
                    && grants.grants.iter().any(|grant| {
                        grant.id == entry.grant_id
                            && !grant.revoked
                            && grant.expires_at > now
                            && grant.scopes.iter().any(|scope| scope == "bootstrap")
                    })
            })
            .filter_map(|entry| {
                intro(&entry.bundle_b64).ok().map(|mut relay| {
                    relay.expires_at = relay.expires_at.min(entry.lease_expires_at);
                    relay
                })
            })
            .filter(|relay| relay.entry(now).is_ok())
            .collect();
        relays.shuffle(&mut rand::thread_rng());
        relays
    }
}

pub(crate) async fn register(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RelayRegistrationRequest>,
) -> Result<Response, ApiError> {
    let service = service(&app)?;
    let grant = service.authorize(&headers, "bootstrap")?;
    let requested = intro(&body.routing_bundle_b64)?;
    if body.network_id != service.config.network_id
        || body.grant_id != grant.id
        || body.expires_at <= now_unix()
        || body.expires_at > now_unix() + 60
    {
        return Err(unauthorized());
    }
    let decode = |encoded: &str, max: usize| -> Result<Vec<u8>, ApiError> {
        if encoded.len() > max * 4 / 3 + 4 {
            return Err(ApiError::bad("relay possession proof exceeds bound"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ApiError::bad("invalid relay possession proof"))?;
        if bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(ApiError::bad("noncanonical relay possession proof"));
        }
        Ok(bytes)
    };
    let certificate = decode(&body.certificate_b64, 8192)?;
    let signature = decode(&body.signature_b64, 1024)?;
    gcoms_transport::tls::verify_service_claim(
        &certificate,
        requested.service_id,
        body.signature_scheme,
        &body
            .signing_bytes()
            .map_err(|_| ApiError::bad("invalid relay registration claim"))?,
        &signature,
    )
    .map_err(|_| unauthorized())?;
    requested
        .entry(now_unix())
        .map_err(|_| ApiError::bad("expired listener introduction"))?;
    if !service.allow_local_fixture && !gcoms_routing::service::public_ip(requested.addr.ip()) {
        return Err(ApiError::bad("relay listener must have a public address"));
    }
    let _probe = service
        .probes
        .try_acquire()
        .map_err(|_| failure(StatusCode::TOO_MANY_REQUESTS, "listener probes busy"))?;
    let client = gcoms_transport::Tp1Client::new().map_err(|_| unavailable())?;
    let bundle = tokio::time::timeout(
        Duration::from_secs(20),
        discovery::refresh(&client, &requested, &[]),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| {
        failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "listener identity or reachability verification failed",
        )
    })?;
    // A pinned peer's referrals cannot authorize unrelated public services.
    let verified = bundle
        .relays
        .into_iter()
        .find(|own| own.service_id == requested.service_id && own.addr == requested.addr)
        .ok_or_else(unavailable)?;
    if verified != requested {
        return Err(failure(
            StatusCode::CONFLICT,
            "listener authority changed; retry its current introduction",
        ));
    }
    let grant = service.authorize(&headers, "bootstrap")?;
    let now = now_unix();
    let expiry = now
        .saturating_add(LEASE_SECONDS)
        .min(verified.expires_at)
        .min(grant.expires_at);
    if expiry <= now {
        return Err(unavailable());
    }
    let mut registry = service.relays.lock().await;
    registry
        .entries
        .retain(|_, entry| entry.lease_expires_at > now);
    let handle = key(&verified.service_id);
    if let Some(existing) = registry.entries.get(&handle) {
        if existing.grant_id != grant.id {
            return Err(unauthorized());
        }
    } else if registry.entries.len() >= MAX_RELAYS
        || registry
            .entries
            .values()
            .filter(|entry| entry.grant_id == grant.id)
            .count()
            >= MAX_PER_GRANT
    {
        return Err(failure(
            StatusCode::TOO_MANY_REQUESTS,
            "relay contribution limit reached",
        ));
    }
    let same_prefix = registry
        .entries
        .iter()
        .filter(|(id, entry)| {
            **id != handle
                && intro(&entry.bundle_b64)
                    .ok()
                    .is_some_and(|old| prefix(old.addr.ip()) == prefix(verified.addr.ip()))
        })
        .count();
    if !service.allow_local_fixture && same_prefix >= 16 {
        return Err(failure(
            StatusCode::TOO_MANY_REQUESTS,
            "relay network diversity limit reached",
        ));
    }
    let encoded = BootstrapBundle {
        relays: vec![verified.clone()],
    }
    .encode()
    .map_err(|_| unavailable())?;
    let mut next = Registry {
        entries: registry.entries.clone(),
    };
    next.entries.insert(
        handle,
        Entry {
            grant_id: grant.id,
            bundle_b64: URL_SAFE_NO_PAD.encode(encoded),
            lease_expires_at: expiry,
        },
    );
    atomic_json(&service.relay_path(), &next).map_err(|_| unavailable())?;
    *registry = next;
    Ok(no_store(
        Json(RelayRegistrationResponse {
            service_id: verified.service_id,
            lease_expires_at: expiry,
        })
        .into_response(),
    ))
}

pub(crate) async fn remove(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<Response, ApiError> {
    let service = service(&app)?;
    let grant = service.authorize(&headers, "bootstrap")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&handle)
        .map_err(|_| ApiError::bad("invalid relay service"))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != handle {
        return Err(ApiError::bad("invalid relay service"));
    }
    let mut registry = service.relays.lock().await;
    if registry
        .entries
        .get(&handle)
        .is_some_and(|entry| entry.grant_id != grant.id)
    {
        return Err(unauthorized());
    }
    let mut next = Registry {
        entries: registry.entries.clone(),
    };
    next.entries.remove(&handle);
    atomic_json(&service.relay_path(), &next).map_err(|_| unavailable())?;
    *registry = next;
    Ok(no_store(Json(json!({"removed": true})).into_response()))
}

fn prefix(address: std::net::IpAddr) -> [u8; 6] {
    let mut value = [0; 6];
    match address {
        std::net::IpAddr::V4(ip) => {
            value[0] = 4;
            value[1..4].copy_from_slice(&ip.octets()[..3]);
        }
        std::net::IpAddr::V6(ip) => {
            value.copy_from_slice(&ip.octets()[..6]);
        }
    }
    value
}
