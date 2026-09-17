//! These fixtures use ordinary certificate and hostname verification, HTTPS
//! origins and loopback DNS overrides. There is no invalid-cert or HTTP mode.
use super::*;
use axum::{
    extract::{Path as HttpPath, State as HttpState},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use gcoms_crypto::IdentityKeypair;
use gcoms_network::{NameResponse, RegisterNameRequest, RemoveNameRequest, UpdateNameRequest};
use gcoms_routing::Relay;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};
use tokio::sync::Mutex;

const HEL: &str = "bootstrap-a.example";
const FSN: &str = "bootstrap-b.example";
const NEXT: &str = "next.example";
fn origin(host: &str) -> String {
    format!("https://{host}/")
}
fn token(n: u8) -> String {
    URL_SAFE_NO_PAD.encode([n; 32])
}
fn trust(defaults: NetworkDefaults) -> InstalledNetwork {
    let signer = IdentityKeypair::from_seed([7; 32]);
    InstalledNetwork {
        trusted_key_b64: URL_SAFE_NO_PAD.encode(signer.public_bytes()),
        signed_defaults: SignedNetworkDefaults::sign(defaults, &signer, vec![]).unwrap(),
    }
}
fn installed() -> InstalledNetwork {
    super::tests::installed()
}
fn invitation(n: u8) -> NetworkInvitation {
    let mut value = super::tests::invitation();
    value.grant = token(n);
    value
}
fn listener(port: u16) -> BootstrapBundle {
    BootstrapBundle {
        relays: vec![Relay {
            addr: format!("8.8.8.8:{port}").parse().unwrap(),
            service_id: [71; 32],
            reentry_cap: [72; 32],
            circuit_cap: [73; 32],
            expires_at: now_unix() + 1800,
        }],
    }
}
fn encoded(bundle: &BootstrapBundle) -> String {
    URL_SAFE_NO_PAD.encode(bundle.encode().unwrap())
}
struct Exchange {
    method: Method,
    path: String,
    host: String,
    authorization: String,
    body: Value,
}
#[derive(Default)]
struct Faults {
    slow_defaults: HashSet<String>,
    slow_provisions: HashSet<String>,
    lose_register_once: bool,
    lose_update_once: bool,
    reject_register_once: bool,
    wrong_name: bool,
    redirect_private: bool,
    revoked_names: bool,
}
struct Entry {
    credential: String,
    registration: Value,
    last_mutation: Value,
    response: NameResponse,
    removed: bool,
}
struct Backend {
    signed: Mutex<SignedNetworkDefaults>,
    log: Mutex<Vec<Exchange>>,
    faults: Mutex<Faults>,
    names: Mutex<BTreeMap<String, Entry>>,
}
impl Backend {
    async fn record(&self, method: Method, path: String, headers: &HeaderMap, body: Value) {
        self.log.lock().await.push(Exchange {
            method,
            path,
            host: headers.get("host").unwrap().to_str().unwrap().into(),
            authorization: headers
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .into(),
            body,
        });
    }
}
struct TlsListener {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = self.listener.accept().await.unwrap();
            if let Ok(tls) = self.acceptor.accept(tcp).await {
                return (tls, addr);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
struct Fixture {
    root: tempfile::TempDir,
    backend: Arc<Backend>,
    addr: SocketAddr,
    ca: reqwest::Certificate,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        gcoms_private_fs::make_private(root.path(), true).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut server_params =
            CertificateParams::new(vec![HEL.into(), FSN.into(), NEXT.into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server.der().clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let backend = Arc::new(Backend {
            signed: Mutex::new(installed().signed_defaults),
            log: Mutex::new(vec![]),
            faults: Mutex::new(Faults::default()),
            names: Mutex::new(BTreeMap::new()),
        });
        let app = Router::new()
            .route("/v1/network-defaults", get(defaults))
            .route("/v1/relay-provisions", axum::routing::post(provision))
            .route("/v1/names", axum::routing::post(register))
            .route(
                "/v1/names/{handle}",
                axum::routing::put(update).delete(remove),
            )
            .with_state(backend.clone());
        let task = tokio::spawn(async move {
            axum::serve(
                TlsListener {
                    listener,
                    acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
                },
                app,
            )
            .await
            .unwrap();
        });
        Self {
            root,
            backend,
            addr,
            ca: reqwest::Certificate::from_der(ca.der()).unwrap(),
            task,
        }
    }
    fn client(&self, with_ca: bool) -> NetworkClient {
        let mut client =
            NetworkClient::open(&self.root.path().join("network"), installed()).unwrap();
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(10));
        for host in [HEL, FSN, NEXT] {
            builder = builder.resolve(host, self.addr);
        }
        if with_ca {
            builder = builder.add_root_certificate(self.ca.clone());
        }
        client.http = builder.build().unwrap();
        client
    }
    fn invite(&self, client: &NetworkClient, n: u8) {
        client
            .import_invitation(&invitation(n).encode().unwrap())
            .unwrap();
    }
    fn mutate_state(&self, mutate: impl FnOnce(&mut Value)) {
        let path = self.root.path().join("network/network.json");
        let mut state: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        mutate(&mut state);
        std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
    }
}
fn auth(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("")
}
async fn defaults(HttpState(state): HttpState<Arc<Backend>>, headers: HeaderMap) -> Response {
    state
        .record(
            Method::GET,
            "/v1/network-defaults".into(),
            &headers,
            Value::Null,
        )
        .await;
    let host = headers.get("host").unwrap().to_str().unwrap();
    let slow = state.faults.lock().await.slow_defaults.contains(host);
    if slow {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Json(state.signed.lock().await.clone()).into_response()
}
async fn provision(
    HttpState(state): HttpState<Arc<Backend>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .record(Method::POST, "/v1/relay-provisions".into(), &headers, body)
        .await;
    let host = headers.get("host").unwrap().to_str().unwrap();
    let slow = state.faults.lock().await.slow_provisions.contains(host);
    if slow {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if auth(&headers) != token(9) && auth(&headers) != token(10) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({"version":2,"routing_bundle_b64":encoded(&listener(4433))})).into_response()
}
async fn register(
    HttpState(state): HttpState<Arc<Backend>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .record(Method::POST, "/v1/names".into(), &headers, body.clone())
        .await;
    if auth(&headers) != token(9) && auth(&headers) != token(10) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    {
        let mut faults = state.faults.lock().await;
        if faults.redirect_private {
            return (StatusCode::TEMPORARY_REDIRECT, [("location", origin(NEXT))]).into_response();
        }
        if faults.revoked_names {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if faults.reject_register_once {
            faults.reject_register_once = false;
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let request: RegisterNameRequest = serde_json::from_value(body.clone()).unwrap();
    let mut names = state.names.lock().await;
    if let Some(entry) = names
        .values()
        .find(|entry| entry.registration["request_id"] == request.request_id)
    {
        if entry.registration != body {
            return StatusCode::CONFLICT.into_response();
        }
        return Json(entry.response.clone()).into_response();
    }
    let proof =
        BootstrapBundle::decode(&canonical_b64(&request.routing_bundle_b64).unwrap()).unwrap();
    if proof.relays[0].expires_at <= now_unix() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let handle = format!("{:032x}", names.len() + 1);
    let fqdn = request
        .server_label
        .as_ref()
        .map(|label| format!("{label}.relays.gchat.boo"))
        .unwrap_or_else(|| format!("{handle}.nodes.gchat.boo"));
    let response = NameResponse {
        node_handle: handle.clone(),
        fqdn,
        sequence: 1,
        lease_expires_at: (now_unix() + 900).min(proof.relays[0].expires_at),
        published: false,
    };
    names.insert(
        handle,
        Entry {
            credential: request.credential_b64,
            registration: body,
            last_mutation: Value::Null,
            response: response.clone(),
            removed: false,
        },
    );
    drop(names);
    let (lose, wrong) = {
        let mut faults = state.faults.lock().await;
        let lose = faults.lose_register_once;
        faults.lose_register_once = false;
        (lose, faults.wrong_name)
    };
    if lose {
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
    let mut response = response;
    if wrong {
        response.fqdn = "attacker.example".into();
    }
    (StatusCode::CREATED, Json(response)).into_response()
}
async fn update(
    HttpState(state): HttpState<Arc<Backend>>,
    HttpPath(handle): HttpPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .record(
            Method::PUT,
            format!("/v1/names/{handle}"),
            &headers,
            body.clone(),
        )
        .await;
    if state.faults.lock().await.revoked_names {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut names = state.names.lock().await;
    let Some(entry) = names.get_mut(&handle) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if auth(&headers) != entry.credential {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let request: UpdateNameRequest = serde_json::from_value(body.clone()).unwrap();
    if request.sequence == entry.response.sequence && entry.last_mutation == body {
        return Json(entry.response.clone()).into_response();
    }
    if request.sequence != entry.response.sequence + 1 {
        return StatusCode::CONFLICT.into_response();
    }
    let proof =
        BootstrapBundle::decode(&canonical_b64(&request.routing_bundle_b64).unwrap()).unwrap();
    if proof.relays[0].expires_at <= now_unix() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    entry.response.sequence = request.sequence;
    entry.response.lease_expires_at = (now_unix() + 900).min(proof.relays[0].expires_at);
    entry.last_mutation = body;
    entry.removed = false;
    let response = entry.response.clone();
    drop(names);
    let lose = {
        let mut faults = state.faults.lock().await;
        let value = faults.lose_update_once;
        faults.lose_update_once = false;
        value
    };
    if lose {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    Json(response).into_response()
}
async fn remove(
    HttpState(state): HttpState<Arc<Backend>>,
    HttpPath(handle): HttpPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .record(
            Method::DELETE,
            format!("/v1/names/{handle}"),
            &headers,
            body.clone(),
        )
        .await;
    if state.faults.lock().await.revoked_names {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut names = state.names.lock().await;
    let Some(entry) = names.get_mut(&handle) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if auth(&headers) != entry.credential {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let request: RemoveNameRequest = serde_json::from_value(body).unwrap();
    if entry.removed && request.sequence == entry.response.sequence {
        return Json(entry.response.clone()).into_response();
    }
    if request.sequence != entry.response.sequence + 1 {
        return StatusCode::CONFLICT.into_response();
    }
    entry.response.sequence = request.sequence;
    entry.response.lease_expires_at = now_unix();
    entry.removed = true;
    Json(entry.response.clone()).into_response()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

#[tokio::test]
async fn verified_tls_and_budget_preserve_private_provider_fallback() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    {
        let mut faults = fixture.backend.faults.lock().await;
        faults.slow_defaults.extend([HEL.into(), FSN.into()]);
        faults.slow_provisions.insert(HEL.into());
    }
    let started = Instant::now();
    let bundle = client
        .fetch_routing(started + Duration::from_millis(900))
        .await
        .unwrap();
    assert_eq!(bundle.relays.len(), 1);
    assert!(started.elapsed() < Duration::from_millis(900));
    let log = fixture.backend.log.lock().await;
    assert!(log
        .iter()
        .filter(|entry| entry.path == "/v1/network-defaults")
        .all(|entry| entry.authorization.is_empty()));
    let requests: Vec<_> = log
        .iter()
        .filter(|entry| entry.path == "/v1/relay-provisions")
        .collect();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].host, HEL);
    assert_eq!(requests[1].host, FSN);
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(requests[0].authorization, format!("Bearer {}", token(9)));
    drop(log);
    let bad = fixture.client(false);
    assert!(bad
        .fetch_routing(Instant::now() + Duration::from_millis(500))
        .await
        .is_err());
}
#[tokio::test]
async fn signed_origin_rotation_rollback_equivocation_and_installer_floor() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    let mut next = installed().signed_defaults.defaults;
    next.sequence = 6;
    next.provider_urls = vec![origin(NEXT)];
    *fixture.backend.signed.lock().await = trust(next.clone()).signed_defaults;
    client.fetch_routing(deadline()).await.unwrap();
    assert_eq!(client.current_defaults().unwrap().sequence, 6);
    let log = fixture.backend.log.lock().await;
    assert!(log
        .iter()
        .filter(|entry| !entry.authorization.is_empty())
        .all(|entry| entry.host == NEXT));
    drop(log);
    let before = std::fs::read(fixture.root.path().join("network/network.json")).unwrap();
    for sequence in [5, 6] {
        let mut stale = next.clone();
        stale.sequence = sequence;
        stale.expires_at += 1;
        *fixture.backend.signed.lock().await = trust(stale).signed_defaults;
        assert!(client.refresh_defaults(deadline()).await.is_err());
        assert_eq!(
            std::fs::read(fixture.root.path().join("network/network.json")).unwrap(),
            before
        );
    }
    let mut malicious = invitation(9);
    malicious.provider_urls = vec!["https://attacker.example/".into()];
    assert!(client
        .import_invitation(&malicious.encode().unwrap())
        .is_err());
    let mut newer = next;
    newer.sequence = 10;
    let reopened =
        NetworkClient::open(&fixture.root.path().join("network"), trust(newer.clone())).unwrap();
    assert_eq!(reopened.current_defaults().unwrap().sequence, 10);
    assert!(reopened.has_invitation().unwrap());
    newer.expires_at += 1;
    assert!(NetworkClient::open(&fixture.root.path().join("network"), trust(newer)).is_err());
}
#[tokio::test]
async fn dns_lost_reply_reopen_lease_renewal_optout_and_grant_isolation() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    fixture.backend.faults.lock().await.lose_register_once = true;
    assert!(client
        .update_listener(&listener(4433), Instant::now() + Duration::from_millis(250))
        .await
        .is_err());
    assert!(client.name_status().unwrap().pending);
    assert_eq!(fixture.backend.names.lock().await.len(), 1);
    drop(client);
    let client = fixture.client(true);
    fixture.invite(&client, 10);
    let registered = client.flush_name(deadline()).await.unwrap().unwrap();
    assert_eq!(registered.sequence, 1);
    let log = fixture.backend.log.lock().await;
    let requests: Vec<_> = log
        .iter()
        .filter(|entry| entry.path == "/v1/names")
        .collect();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(requests[0].authorization, requests[1].authorization);
    assert_eq!(requests[1].authorization, format!("Bearer {}", token(9)));
    let credential = requests[0].body["credential_b64"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(credential, token(9));
    drop(log);
    let count = fixture.backend.log.lock().await.len();
    client
        .update_listener(&listener(4433), deadline())
        .await
        .unwrap();
    assert_eq!(
        fixture.backend.log.lock().await.len(),
        count,
        "healthy lease is not needlessly renewed"
    );
    fixture.mutate_state(|state| {
        state["names"]["registration"]["response"]["lease_expires_at"] = json!(now_unix() - 1)
    });
    fixture.backend.faults.lock().await.lose_update_once = true;
    assert!(client
        .update_listener(&listener(8443), deadline())
        .await
        .is_err());
    client.configure_opt_in(false).unwrap();
    assert!(client.flush_name(deadline()).await.unwrap().is_none());
    let status = client.name_status().unwrap();
    assert!(!status.opted_in);
    assert!(!status.pending);
    assert!(status.removed);
    assert_eq!(status.registration.unwrap().sequence, 3);
    assert!(fixture
        .backend
        .names
        .lock()
        .await
        .values()
        .all(|entry| entry.removed));
    client.configure_opt_in(true).unwrap();
    let renewed = client
        .update_listener(&listener(8443), deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renewed.node_handle, registered.node_handle);
    assert_eq!(renewed.sequence, 4);
    assert_eq!(fixture.backend.names.lock().await.len(), 1);
    let log = fixture.backend.log.lock().await;
    let updates: Vec<_> = log
        .iter()
        .filter(|entry| entry.method == Method::PUT)
        .collect();
    assert_eq!(updates[0].body, updates[1].body);
    assert!(updates
        .iter()
        .all(|entry| entry.authorization == format!("Bearer {credential}")));
    drop(log);
    let mut wrong = listener(4433);
    wrong.relays[0].service_id = [91; 32];
    assert!(client.update_listener(&wrong, deadline()).await.is_err());
    let mut private = listener(4433);
    private.relays[0].addr = "127.0.0.1:4433".parse().unwrap();
    assert!(client.update_listener(&private, deadline()).await.is_err());
    fixture.backend.faults.lock().await.revoked_names = true;
    let error = client
        .update_listener(&listener(4433), deadline())
        .await
        .unwrap_err();
    assert!(!error.contains(&credential));
    assert!(!error.contains(&token(9)));
    assert!(
        client.fetch_routing(deadline()).await.is_ok(),
        "DNS authorization failure never affects private bootstrap"
    );
    let public_status = format!("{:?}", client.name_status().unwrap());
    assert!(!public_status.contains(&credential));
    assert!(!public_status.contains(&token(9)));
}
#[tokio::test]
async fn wrong_name_and_redirect_never_commit_or_forward_credentials() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    fixture.backend.faults.lock().await.redirect_private = true;
    assert!(client
        .update_listener(&listener(4433), deadline())
        .await
        .is_err());
    assert_eq!(fixture.backend.log.lock().await.len(), 1);
    assert!(client.name_status().unwrap().registration.is_none());
    {
        let mut faults = fixture.backend.faults.lock().await;
        faults.redirect_private = false;
        faults.wrong_name = true;
    }
    assert!(client.flush_name(deadline()).await.is_err());
    assert!(client.name_status().unwrap().registration.is_none());
    assert!(client.name_status().unwrap().pending);
    fixture.backend.faults.lock().await.wrong_name = false;
    client.configure_opt_in(false).unwrap();
    assert!(client.flush_name(deadline()).await.unwrap().is_none());
    assert!(fixture
        .backend
        .names
        .lock()
        .await
        .values()
        .all(|entry| entry.removed));
    assert!(fixture
        .backend
        .log
        .lock()
        .await
        .iter()
        .all(|entry| entry.host == HEL));
}

#[tokio::test]
async fn founder_label_requires_signed_pin_and_becomes_immutable_with_credential() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_server_label(Some("r1")).unwrap();
    client.configure_opt_in(true).unwrap();
    assert!(client.configure_server_label(Some("r9")).is_err());
    assert!(client
        .update_listener(&listener(4433), deadline())
        .await
        .is_err());
    assert!(
        fixture.backend.log.lock().await.is_empty(),
        "wrong founder pin is refused before any HTTP call"
    );
    let mut founder = listener(4433);
    founder.relays[0].service_id = [3; 32];
    fixture.backend.faults.lock().await.lose_register_once = true;
    assert!(client
        .update_listener(&founder, Instant::now() + Duration::from_millis(250))
        .await
        .is_err());
    assert!(client.configure_server_label(None).is_err());
    assert!(client.configure_server_label(Some("r2")).is_err());
    client.configure_server_label(Some("r1")).unwrap();
    let registered = client.flush_name(deadline()).await.unwrap().unwrap();
    assert_eq!(registered.fqdn, "r1.relays.gchat.boo");
    assert!(client.configure_server_label(None).is_err());
    let log = fixture.backend.log.lock().await;
    let registrations: Vec<_> = log
        .iter()
        .filter(|entry| entry.path == "/v1/names")
        .collect();
    assert_eq!(registrations[0].body["server_label"], "r1");
    assert_eq!(registrations[0].body, registrations[1].body);
    drop(log);
    let generic = Fixture::new().await;
    let client = generic.client(true);
    generic.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    let response = client
        .update_listener(&founder, deadline())
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.fqdn.ends_with(".nodes.gchat.boo"),
        "generic clients stay random even with a founder pin"
    );
    assert!(client.configure_server_label(Some("r1")).is_err());
}
#[tokio::test]
async fn expired_rejected_proof_recovers_and_expired_grant_does_not_reenable_optout() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    fixture.backend.faults.lock().await.reject_register_once = true;
    assert!(client
        .update_listener(&listener(4433), deadline())
        .await
        .is_err());
    // A cold-restoration fixture of the exact request after its proof and the
    // server's bounded in-flight probe window have elapsed, without application.
    fixture.mutate_state(|state| {
        let mut old = listener(4433);
        old.relays[0].expires_at = now_unix() - 60;
        state["names"]["pending"]["proof_expires_at"] = json!(old.relays[0].expires_at);
        state["names"]["pending"]["operation"]["request"]["routing_bundle_b64"] =
            json!(encoded(&old));
    });
    assert!(client.flush_name(deadline()).await.is_err());
    assert!(!client.name_status().unwrap().pending);
    assert!(client
        .update_listener(&listener(8443), deadline())
        .await
        .unwrap()
        .is_some());
    assert_eq!(fixture.backend.names.lock().await.len(), 1);
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    fixture.backend.faults.lock().await.reject_register_once = true;
    assert!(client
        .update_listener(&listener(4433), deadline())
        .await
        .is_err());
    fixture.mutate_state(|state| {
        state["names"]["pending"]["grant_expires_at"] = json!(now_unix() - 1)
    });
    let count = fixture.backend.log.lock().await.len();
    client.configure_opt_in(false).unwrap();
    assert!(client.flush_name(deadline()).await.unwrap().is_none());
    assert_eq!(fixture.backend.log.lock().await.len(), count);
    assert!(!client.name_status().unwrap().pending);
}
#[tokio::test]
async fn removed_authority_and_expired_deadline_send_no_private_request() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    client
        .update_listener(&listener(4433), deadline())
        .await
        .unwrap();
    let mut next = installed().signed_defaults.defaults;
    next.sequence = 6;
    next.provider_urls = vec![origin(NEXT)];
    *fixture.backend.signed.lock().await = trust(next).signed_defaults;
    client.refresh_defaults(deadline()).await.unwrap();
    let count = fixture.backend.log.lock().await.len();
    assert!(client
        .update_listener(&listener(8443), deadline())
        .await
        .is_err());
    assert_eq!(fixture.backend.log.lock().await.len(), count);
    assert!(client.fetch_routing(Instant::now()).await.is_err());
    assert_eq!(fixture.backend.log.lock().await.len(), count);
}

#[tokio::test]
async fn delayed_optout_delete_uses_current_confirmation_time() {
    let fixture = Fixture::new().await;
    let client = fixture.client(true);
    fixture.invite(&client, 9);
    client.configure_opt_in(true).unwrap();
    client
        .update_listener(&listener(4433), deadline())
        .await
        .unwrap();
    client.configure_opt_in(false).unwrap();
    fixture.backend.faults.lock().await.revoked_names = true;
    assert!(client.flush_name(deadline()).await.is_err());
    fixture
        .mutate_state(|state| state["names"]["pending"]["maximum_lease"] = json!(now_unix() - 60));
    fixture.backend.faults.lock().await.revoked_names = false;
    let client = fixture.client(true);
    assert!(client.flush_name(deadline()).await.unwrap().is_none());
    assert!(!client.name_status().unwrap().pending);
    assert!(fixture
        .backend
        .names
        .lock()
        .await
        .values()
        .all(|entry| entry.removed));
}
