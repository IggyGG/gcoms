use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
    routing::get,
    Router,
};
use gcoms_crypto::IdentityKeypair;
use gcoms_network::{Founder, NetworkDefaults};
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
use tower::ServiceExt;

struct Fixture {
    dir: PathBuf,
    config: NetworkConfig,
    token: String,
    record_token: String,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("gchat-network-{}", random_handle()));
        std::fs::create_dir(&dir).unwrap();
        let key = IdentityKeypair::from_seed([71; 32]);
        let defaults = NetworkDefaults {
            version: 1,
            network_id: "gchat.boo".into(),
            sequence: 1,
            issued_at: now_unix() - 1,
            expires_at: now_unix() + 7200,
            provider_urls: vec!["https://bootstrap-hel.gchat.boo/".into()],
            founders: vec![Founder {
                name: "r1.relays.gchat.boo".into(),
                service_id: [1; 32],
                address_hints: vec!["8.8.8.8:4433".parse().unwrap()],
            }],
            dns_domain: "gchat.boo".into(),
        };
        atomic_json(
            &dir.join("defaults.json"),
            &SignedNetworkDefaults::sign(defaults, &key, vec![]).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("root.pub"), key.public_bytes()).unwrap();
        let token = URL_SAFE_NO_PAD.encode([41; 32]);
        let record_token = URL_SAFE_NO_PAD.encode([42; 32]);
        atomic_json(
            &dir.join("grants.json"),
            &GrantFile {
                version: 1,
                grants: vec![GrantRecord {
                    id: token_digest(&token).unwrap(),
                    expires_at: now_unix() + 7200,
                    scopes: vec!["bootstrap".into(), "names".into()],
                    max_names: 4,
                    revoked: false,
                }],
            },
        )
        .unwrap();
        atomic_json(
            &dir.join("spaceship.json"),
            &json!({"api_key":"fixture-key","api_secret":"fixture-secret"}),
        )
        .unwrap();
        let config = NetworkConfig {
            network_id: "gchat.boo".into(),
            defaults_file: dir.join("defaults.json"),
            verification_key_file: dir.join("root.pub"),
            grants_file: dir.join("grants.json"),
            state_dir: dir.join("state"),
            names_enabled: true,
            name_lease_secs: 3600,
            spaceship_credentials_file: Some(dir.join("spaceship.json")),
        };
        Self {
            dir,
            config,
            token,
            record_token,
        }
    }
    async fn app(&self, service: Arc<NetworkService>) -> AppState {
        let config:super::super::Config=serde_json::from_value(json!({"listen":"127.0.0.1:0","public_base_url":"http://127.0.0.1/","ephemeral_test_mode":true,"state_dir":null})).unwrap();
        let mut app = AppState::load(config).await.unwrap();
        app.network = Some(service);
        app
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
async fn request(
    app: &AppState,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = super::super::router(app.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn relay(identity: &TlsIdentity) -> (gcoms_routing::Relay, tokio::task::JoinHandle<()>) {
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        identity,
    )
    .await
    .unwrap();
    let service = gcoms_routing::RelayService::new(
        server.local_addr().unwrap(),
        identity.service_id(),
        [51; 32],
        Arc::new(gcoms_routing::Directory::new()),
        gcoms_routing::ServicePolicy::default(),
    )
    .unwrap();
    let intro = service.introduction(now_unix());
    let server = server.with_duplex(service.handler());
    let task = tokio::spawn(async move {
        let _ = server.run_until(std::future::pending::<()>()).await;
    });
    (intro, task)
}
fn bundle(relay: &gcoms_routing::Relay) -> String {
    URL_SAFE_NO_PAD.encode(
        gcoms_routing::bootstrap::BootstrapBundle {
            relays: vec![relay.clone()],
        }
        .encode()
        .unwrap(),
    )
}
#[derive(Default)]
struct ProviderState {
    records: BTreeMap<String, Value>,
    calls: Vec<(String, usize)>,
    rate_once: bool,
    ambiguous_put_once: bool,
}
async fn provider() -> (String, Arc<Mutex<ProviderState>>) {
    let state = Arc::new(Mutex::new(ProviderState::default()));
    async fn get_records(
        State(state): State<Arc<Mutex<ProviderState>>>,
        headers: HeaderMap,
        axum::extract::Query(query): axum::extract::Query<BTreeMap<String, usize>>,
    ) -> Response {
        assert_eq!(
            headers.get("user-agent").unwrap(),
            "ghost-network-operator/1.0"
        );
        assert_eq!(headers.get("x-api-key").unwrap(), "fixture-key");
        let mut state = state.lock().await;
        state.calls.push(("GET".into(), 0));
        if state.rate_once {
            state.rate_once = false;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "120")],
                Json(json!({})),
            )
                .into_response();
        }
        let values: Vec<_> = state
            .records
            .values()
            .skip(*query.get("skip").unwrap())
            .take(*query.get("take").unwrap())
            .cloned()
            .collect();
        Json(json!({"items":values,"total":state.records.len()})).into_response()
    }
    async fn put_records(
        State(state): State<Arc<Mutex<ProviderState>>>,
        Json(body): Json<Value>,
    ) -> Response {
        assert_eq!(body["force"], false);
        let items = body["items"].as_array().unwrap();
        assert!(items.len() <= 500);
        let mut state = state.lock().await;
        state.calls.push(("PUT".into(), items.len()));
        for record in items {
            assert_eq!(record["ttl"], 300);
            state.records.insert(record_key(record), record.clone());
        }
        if state.ambiguous_put_once {
            state.ambiguous_put_once = false;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    }
    async fn delete_records(
        State(state): State<Arc<Mutex<ProviderState>>>,
        Json(items): Json<Vec<Value>>,
    ) -> Response {
        assert!(items.len() <= 500);
        let mut state = state.lock().await;
        state.calls.push(("DELETE".into(), items.len()));
        if items
            .iter()
            .any(|r| !state.records.contains_key(&record_key(r)))
        {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        for record in items {
            assert!(record.get("ttl").is_none());
            state.records.remove(&record_key(&record));
        }
        StatusCode::NO_CONTENT.into_response()
    }
    let app = Router::new()
        .route(
            "/records",
            get(get_records).put(put_records).delete(delete_records),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/records"), state)
}
#[tokio::test]
async fn authenticated_names_probe_replay_update_restart_lease_and_reservation() {
    let fixture = Fixture::new();
    let (url, provider) = provider().await;
    let unrelated = json!({"type":"A","name":"www","address":"8.8.4.4","ttl":300});
    provider
        .lock()
        .await
        .records
        .insert(record_key(&unrelated), unrelated);
    let mut backend = NetworkService::load(fixture.config.clone(), true).unwrap();
    backend.provider_url = url.clone();
    assert!(
        NetworkService::load(fixture.config.clone(), true).is_err(),
        "second active publisher must refuse lock"
    );
    let service = Arc::new(backend);
    let app = fixture.app(service.clone()).await;
    let identity = TlsIdentity::generate().unwrap();
    let (intro, relay_task) = relay(&identity).await;
    let body = json!({"request_id":URL_SAFE_NO_PAD.encode([9;16]),"credential_b64":fixture.record_token,"routing_bundle_b64":bundle(&intro),"server_label":null});
    assert_eq!(
        request(&app, "POST", "/v1/names", "wrong", body.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let mut wrong = intro.clone();
    wrong.service_id = [12; 32];
    let mut wrong_body = body.clone();
    wrong_body["routing_bundle_b64"] = json!(bundle(&wrong));
    assert_eq!(
        request(&app, "POST", "/v1/names", &fixture.token, wrong_body)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, response) = request(&app, "POST", "/v1/names", &fixture.token, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let handle = response["node_handle"].as_str().unwrap().to_string();
    assert_eq!(handle.len(), 32);
    assert_eq!(response["fqdn"], format!("{handle}.nodes.gchat.boo"));
    assert_eq!(
        request(&app, "POST", "/v1/names", &fixture.token, body.clone())
            .await
            .1,
        response
    );
    let mut changed = body.clone();
    changed["credential_b64"] = json!(URL_SAFE_NO_PAD.encode([19; 32]));
    assert_eq!(
        request(&app, "POST", "/v1/names", &fixture.token, changed)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let path = format!("/v1/names/{handle}");
    let update = json!({"sequence":2,"routing_bundle_b64":bundle(&intro)});
    assert_eq!(
        request(&app, "PUT", &path, &fixture.token, update.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (intro2, relay_task2) = relay(&identity).await;
    let update = json!({"sequence":2,"routing_bundle_b64":bundle(&intro2)});
    assert_eq!(
        request(&app, "PUT", &path, &fixture.record_token, update.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "PUT", &path, &fixture.record_token, update)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &path,
            &fixture.record_token,
            json!({"sequence":2,"routing_bundle_b64":bundle(&intro)})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let disk = std::fs::read_to_string(fixture.config.state_dir.join("dns-state.json")).unwrap();
    assert!(!disk.contains(&fixture.token));
    assert!(!disk.contains(&fixture.record_token));
    assert!(!disk.contains(&bundle(&intro)));
    provider.lock().await.rate_once = true;
    assert!(service.reconcile().await.is_err());
    let calls = provider.lock().await.calls.len();
    assert!(service.reconcile().await.is_ok());
    assert_eq!(
        provider.lock().await.calls.len(),
        calls,
        "Retry-After suppresses another call"
    );
    service.state.lock().await.retry_at = 0;
    provider.lock().await.ambiguous_put_once = true;
    assert!(
        service.reconcile().await.is_err(),
        "provider applies PUT then loses success response"
    );
    assert_eq!(provider.lock().await.records.len(), 3);
    service.reconcile().await.unwrap();
    assert_eq!(
        provider
            .lock()
            .await
            .calls
            .iter()
            .filter(|(method, _)| method == "PUT")
            .count(),
        1,
        "GET finds ambiguous PUT and avoids duplicate write"
    );
    drop(app);
    drop(service);
    let mut backend = NetworkService::load(fixture.config.clone(), true).unwrap();
    backend.provider_url = url;
    let service = Arc::new(backend);
    let app = fixture.app(service.clone()).await;
    assert_eq!(service.state.lock().await.names[&handle].sequence, 2);
    {
        let mut state = service.state.lock().await;
        state.names.get_mut(&handle).unwrap().lease_expires_at = now_unix() - 1;
        service.save(&state).unwrap();
    }
    service.reconcile().await.unwrap();
    assert_eq!(
        provider.lock().await.records.len(),
        1,
        "expired name removes A and SRV but preserves unrelated records"
    );
    assert!(
        service.state.lock().await.names.contains_key(&handle),
        "expired name remains reserved"
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &path,
            &fixture.record_token,
            json!({"sequence":3,"routing_bundle_b64":bundle(&intro2)})
        )
        .await
        .0,
        StatusCode::OK,
        "same credential recovers reserved name after lease expiry"
    );
    service.reconcile().await.unwrap();
    assert_eq!(provider.lock().await.records.len(), 3);
    assert_eq!(
        request(
            &app,
            "DELETE",
            &path,
            &fixture.record_token,
            json!({"sequence":4})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &path,
            &fixture.record_token,
            json!({"sequence":4})
        )
        .await
        .0,
        StatusCode::OK
    );
    service.reconcile().await.unwrap();
    assert_eq!(provider.lock().await.records.len(), 1);
    let mut grants = read_grants(&fixture.config.grants_file).unwrap();
    grants.grants[0].revoked = true;
    atomic_json(&fixture.config.grants_file, &grants).unwrap();
    assert_eq!(
        request(&app, "POST", "/v1/names", &fixture.token, body)
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "revocation is checked before registration replay"
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &path,
            &fixture.record_token,
            json!({"sequence":5,"routing_bundle_b64":bundle(&intro2)})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    relay_task.abort();
    relay_task2.abort();
}
#[tokio::test]
async fn publisher_coalesces_and_batches_over_500_without_private_targets() {
    let fixture = Fixture::new();
    let (url, provider) = provider().await;
    let mut backend = NetworkService::load(fixture.config.clone(), true).unwrap();
    backend.provider_url = url;
    let grant_id = token_digest(&fixture.token).unwrap();
    {
        let mut state = backend.state.lock().await;
        for n in 0..501 {
            let handle = format!("{n:032x}");
            state.names.insert(
                handle.clone(),
                NameEntry {
                    handle: handle.clone(),
                    fqdn: format!("{handle}.nodes.gchat.boo"),
                    grant_id: grant_id.clone(),
                    credential_hash: String::new(),
                    registration_id: handle.clone(),
                    registration_hash: String::new(),
                    service_id: [1; 32],
                    address: "8.8.8.8:4433".parse().unwrap(),
                    sequence: 4,
                    mutation_hash: String::new(),
                    lease_expires_at: now_unix() + 300,
                    removed: false,
                },
            );
        }
    }
    backend.reconcile().await.unwrap();
    let state = provider.lock().await;
    let batches: Vec<_> = state
        .calls
        .iter()
        .filter(|(method, _)| method == "PUT")
        .map(|(_, count)| *count)
        .collect();
    assert_eq!(batches, vec![500, 500, 2]);
    drop(state);
    let count = provider
        .lock()
        .await
        .calls
        .iter()
        .filter(|(method, _)| method == "PUT")
        .count();
    backend.reconcile().await.unwrap();
    assert_eq!(
        provider
            .lock()
            .await
            .calls
            .iter()
            .filter(|(method, _)| method == "PUT")
            .count(),
        count
    );
    backend.allow_local_fixture = false;
    for addr in [
        "127.0.0.1:4433",
        "169.254.169.254:80",
        "10.0.0.1:4433",
        "[::1]:4433",
        "[fc00::1]:4433",
    ] {
        let intro = gcoms_routing::Relay {
            addr: addr.parse().unwrap(),
            service_id: [1; 32],
            reentry_cap: [2; 32],
            circuit_cap: [3; 32],
            expires_at: now_unix() + 300,
        };
        let error = backend.probe(&bundle(&intro)).await.unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}
