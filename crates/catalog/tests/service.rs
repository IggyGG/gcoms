use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gcoms_catalog::{
    router, AppState, ChannelRouteConfig, Config, ConfigVisibility, JoinResponse,
    OwnerControlConfig, RelayBootstrapConfig, RelayProvisionResponse, MAX_BODY_BYTES,
};
use gcoms_crypto::IdentityKeypair;
use gcoms_sdk::{
    ActivityBucket, AutomaticJoinEndpoint, CatalogResponse, ChannelId, ChannelVisibility,
    PublicChannelDescriptor,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const TOKEN: &str = "catalog-owner-test-token-at-least-thirty-two-bytes";

struct TestPki {
    directory: PathBuf,
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl TestPki {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "gc-catalog-test-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key_pair = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["owner.test".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params
            .signed_by(&server_key_pair, &ca, &ca_key)
            .unwrap();

        let client_key_pair = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_params
            .signed_by(&client_key_pair, &ca, &ca_key)
            .unwrap();

        let paths = Self {
            ca: directory.join("ca.pem"),
            server_cert: directory.join("server.pem"),
            server_key: directory.join("server-key.pem"),
            client_cert: directory.join("client.pem"),
            client_key: directory.join("client-key.pem"),
            directory,
        };
        std::fs::write(&paths.ca, ca.pem()).unwrap();
        std::fs::write(&paths.server_cert, server.pem()).unwrap();
        std::fs::write(&paths.server_key, server_key_pair.serialize_pem()).unwrap();
        std::fs::write(&paths.client_cert, client.pem()).unwrap();
        std::fs::write(&paths.client_key, client_key_pair.serialize_pem()).unwrap();
        std::fs::write(paths.directory.join("token"), TOKEN).unwrap();
        paths
    }

    fn owner_config(&self, address: String) -> OwnerControlConfig {
        OwnerControlConfig {
            address,
            server_name: "owner.test".into(),
            ca_file: self.ca.clone(),
            client_cert_file: self.client_cert.clone(),
            client_key_file: self.client_key.clone(),
            bearer_token_file: self.directory.join("token"),
        }
    }
}

impl Drop for TestPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn rand_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn read_certs(path: &Path) -> Vec<CertificateDer<'static>> {
    let bytes = std::fs::read(path).unwrap();
    rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

async fn fake_owner(pki: &TestPki) -> (String, Arc<AtomicUsize>) {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in read_certs(&pki.ca) {
        roots.add(certificate).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let key_bytes = std::fs::read(&pki.server_key).unwrap();
    let key: PrivateKeyDer<'static> = rustls::pki_types::PrivateKeyDer::pem_slice_iter(&key_bytes)
        .next()
        .transpose()
        .unwrap()
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(read_certs(&pki.server_cert), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let calls = Arc::new(AtomicUsize::new(0));
    let task_calls = calls.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let calls = task_calls.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                let authenticated = request.get("token").and_then(Value::as_str) == Some(TOKEN);
                let member = request
                    .get("member_name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let response = if !authenticated {
                    json!({"id": 1, "ok": false, "error": "unauthorized"})
                } else if member == "full" {
                    json!({"id": 1, "ok": false, "error": "channel capacity reached"})
                } else {
                    calls.fetch_add(1, Ordering::SeqCst);
                    json!({"id": 1, "ok": true, "data": {"welcome_b64": URL_SAFE_NO_PAD.encode(b"welcome")}})
                };
                let _ = reader
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await;
            });
        }
    });
    (address, calls)
}

fn descriptor(
    id: [u8; 32],
    base: &str,
    expiry: u64,
    key: &IdentityKeypair,
) -> PublicChannelDescriptor {
    let id_b64 = URL_SAFE_NO_PAD.encode(id);
    let base = base.trim_end_matches('/');
    let mut value = PublicChannelDescriptor {
        version: 1,
        expires_at_unix: expiry,
        channel_id: ChannelId(id),
        owner_public_key: key.public_bytes(),
        capacity: 64,
        title: format!("channel-{}", id[0]),
        description: "coarse public metadata".into(),
        activity: ActivityBucket::Today,
        automatic_join: AutomaticJoinEndpoint {
            catalog: base.into(),
            endpoint: format!("{base}/v1/channels/{id_b64}/join"),
        },
        signature: Vec::new(),
    };
    value.signature = key.sign(&value.signing_payload().unwrap());
    value
}

fn config(base: &str, pki: &TestPki, owner: String, channel_id: [u8; 32]) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_base_url: base.into(),
        upstream_catalog_urls: Vec::new(),
        state_dir: None,
        ephemeral_test_mode: true,
        joins_per_source_per_minute: 1,
        joins_per_channel_per_minute: 20,
        network: None,
        relay_bootstrap: None,
        channels: vec![ChannelRouteConfig {
            channel_id_b64: URL_SAFE_NO_PAD.encode(channel_id),
            channel_name: "Exact Channel".into(),
            visibility: ConfigVisibility::Public,
            owner_control: pki.owner_config(owner),
        }],
    }
}

async fn serve_catalog(config: Config) -> String {
    let state = AppState::load(config).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://{address}")
}

#[tokio::test]
async fn descriptor_validation_pagination_and_request_limit() {
    let pki = TestPki::new();
    let (owner, _) = fake_owner(&pki).await;
    let channel_id = [9; 32];
    let service = serve_catalog(config("http://catalog.test", &pki, owner, channel_id)).await;
    let client = reqwest::Client::new();
    let key = IdentityKeypair::from_seed([42; 32]);

    for id in [[1; 32], [2; 32], [3; 32]] {
        let response = client
            .put(format!("{service}/v1/descriptors"))
            .json(&descriptor(id, "http://catalog.test", now() + 600, &key))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    }
    let first: CatalogResponse = client
        .get(format!("{service}/v1/catalog?limit=2"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first.descriptors.len(), 2);
    let second: CatalogResponse = client
        .get(format!(
            "{service}/v1/catalog?limit=2&cursor={}",
            first.next_cursor.unwrap()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second.descriptors.len(), 1);
    assert!(second.next_cursor.is_none());

    let mut tampered = descriptor([4; 32], "http://catalog.test", now() + 600, &key);
    tampered.title.push('!');
    assert_eq!(
        client
            .put(format!("{service}/v1/descriptors"))
            .json(&tampered)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let expired = descriptor([5; 32], "http://catalog.test", now() - 1, &key);
    assert_eq!(
        client
            .put(format!("{service}/v1/descriptors"))
            .json(&expired)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .put(format!("{service}/v1/descriptors"))
            .header("content-type", "application/json")
            .body("x".repeat(MAX_BODY_BYTES + 1))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn federation_validates_and_deduplicates_while_ignoring_invalid_upstreams() {
    let key = IdentityKeypair::from_seed([7; 32]);
    let upstream_base_slot = Arc::new(tokio::sync::RwLock::new(String::new()));
    let slot = upstream_base_slot.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_base = format!("http://{}", listener.local_addr().unwrap());
    *upstream_base_slot.write().await = upstream_base.clone();
    let newer = descriptor([1; 32], &upstream_base, now() + 1200, &key);
    let mut tampered = descriptor([8; 32], &upstream_base, now() + 1200, &key);
    tampered.description.push_str("tamper");
    let upstream = Router::new()
        .route(
            "/v1/catalog",
            get(
                |State(values): State<Arc<Vec<PublicChannelDescriptor>>>| async move {
                    Json(CatalogResponse {
                        descriptors: values.as_ref().clone(),
                        next_cursor: None,
                    })
                },
            ),
        )
        .with_state(Arc::new(vec![newer.clone(), tampered]));
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let pki = TestPki::new();
    let (owner, _) = fake_owner(&pki).await;
    let mut cfg = config("http://catalog.test", &pki, owner, [9; 32]);
    cfg.upstream_catalog_urls = vec![upstream_base, "http://127.0.0.1:9/".into()];
    let service = serve_catalog(cfg).await;
    let client = reqwest::Client::new();
    let older = descriptor([1; 32], "http://catalog.test", now() + 300, &key);
    client
        .put(format!("{service}/v1/descriptors"))
        .json(&older)
        .send()
        .await
        .unwrap();
    let page: CatalogResponse = client
        .get(format!("{service}/v1/catalog?limit=100"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.descriptors, vec![newer]);
    drop(slot);
}

#[tokio::test]
async fn automatic_join_is_authenticated_idempotent_rate_limited_and_redacted() {
    let pki = TestPki::new();
    let (owner, calls) = fake_owner(&pki).await;
    let channel_id = [9; 32];
    let service = serve_catalog(config("http://catalog.test", &pki, owner, channel_id)).await;
    let endpoint = format!(
        "{service}/v1/channels/{}/join",
        URL_SAFE_NO_PAD.encode(channel_id)
    );
    let client = reqwest::Client::new();
    let body = json!({
        "display_pseudonym": "visitor",
        "key_package_b64": URL_SAFE_NO_PAD.encode(b"key-package-one")
    });
    let first = client.post(&endpoint).json(&body).send().await.unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let response: JoinResponse = first.json().await.unwrap();
    assert_eq!(response.channel, "Exact Channel");
    assert_eq!(response.visibility, ChannelVisibility::Public);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&response.welcome_b64).unwrap(),
        b"welcome"
    );

    let replay: JoinResponse = client
        .post(&endpoint)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay, response);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let limited = client
        .post(&endpoint)
        .json(&json!({
            "display_pseudonym": "visitor-two",
            "key_package_b64": URL_SAFE_NO_PAD.encode(b"different-package")
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let text = limited.text().await.unwrap();
    assert!(!text.contains(TOKEN));

    let mut capacity_config = config(
        "http://capacity.test",
        &pki,
        // Reuse the same authenticated endpoint with an independent source window.
        pki.owner_config("unused".into()).address,
        [10; 32],
    );
    // The helper above needs a live address, not the placeholder used to make the config shape.
    let (capacity_owner, _) = fake_owner(&pki).await;
    capacity_config.channels[0].owner_control = pki.owner_config(capacity_owner);
    capacity_config.joins_per_source_per_minute = 10;
    let capacity_service = serve_catalog(capacity_config).await;
    let capacity = client
        .post(format!(
            "{capacity_service}/v1/channels/{}/join",
            URL_SAFE_NO_PAD.encode([10; 32])
        ))
        .json(&json!({
            "display_pseudonym": "full",
            "key_package_b64": URL_SAFE_NO_PAD.encode(b"capacity-package")
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(capacity.status(), reqwest::StatusCode::CONFLICT);
    assert!(!capacity.text().await.unwrap().contains(TOKEN));
}

#[tokio::test]
async fn production_requires_https_and_persistent_state() {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://catalog.invalid".into(),
        upstream_catalog_urls: Vec::new(),
        state_dir: None,
        ephemeral_test_mode: false,
        joins_per_source_per_minute: 1,
        joins_per_channel_per_minute: 1,
        channels: Vec::new(),
        network: None,
        relay_bootstrap: None,
    };
    assert!(AppState::load(config).await.is_err());
}

#[tokio::test]
async fn idempotent_join_response_survives_restart_in_owner_only_state() {
    let pki = TestPki::new();
    let (owner, calls) = fake_owner(&pki).await;
    let channel_id = [11; 32];
    let mut cfg = config("https://catalog.test", &pki, owner, channel_id);
    let state_dir = pki.directory.join("state");
    cfg.state_dir = Some(state_dir.clone());
    cfg.ephemeral_test_mode = false;
    cfg.joins_per_source_per_minute = 10;
    let first_service = serve_catalog(cfg.clone()).await;
    let endpoint_path = format!("/v1/channels/{}/join", URL_SAFE_NO_PAD.encode(channel_id));
    let body = json!({
        "display_pseudonym": "persistent-visitor",
        "key_package_b64": URL_SAFE_NO_PAD.encode(b"persistent-key-package")
    });
    let client = reqwest::Client::new();
    let first: JoinResponse = client
        .post(format!("{first_service}{endpoint_path}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let restarted_service = serve_catalog(cfg).await;
    let replay: JoinResponse = client
        .post(format!("{restarted_service}{endpoint_path}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(state_dir.join("state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

enum RelayCard {
    Valid,
    Garbage,
    Public,
}

fn private_card(now_unix: u64) -> String {
    let identity = IdentityKeypair::from_seed([0xA1; 32]);
    let (bundle, _secrets) = identity.issue_bundle();
    let alias = |n: u8| gcoms_node::alias::OwnedAlias {
        contact: gcoms_node::alias::AliasContact {
            target: gcoms_node::relay::RelayTarget {
                address: format!("192.0.2.{n}:8443").parse().unwrap(),
                relay_service_id: [n; 32],
            },
            queue_id: [n; 32],
            epoch: u64::from(n),
            push_cap: [n.wrapping_add(60); 32],
            expiry: now_unix + 7200,
        },
        capabilities: gcoms_node::lease::Capabilities {
            push: [n.wrapping_add(1); 32],
            sub: [n.wrapping_add(2); 32],
            admin: [n.wrapping_add(3); 32],
        },
        limits: gcoms_node::lease::LeaseLimits {
            max_queue_cells: 256,
            max_queue_bytes: 4 * 1024 * 1024,
        },
        create_path: format!("create-{n}"),
        lease_create: gcoms_core::Cell::new(gcoms_core::CellType::RelaySub, 0, 0, vec![n; 16]),
    };
    let owned = vec![alias(1), alias(2)];
    let info = gcoms_node::proto::NodeInfo {
        identity_pk: identity.public_bytes(),
        bundle: bundle.encode(),
        aliases: owned.iter().map(|o| o.contact.clone()).collect(),
        provisioning: Some(gcoms_node::alias::RelayProvision {
            aliases: owned,
            frwd_path: "frwd-token".into(),
            hop_key: [9; 32],
        }),
    };
    gcoms_node::proto::b64_private_info(&info).unwrap()
}

async fn fake_relay(pki: &TestPki, card: RelayCard) -> (String, Arc<AtomicUsize>) {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in read_certs(&pki.ca) {
        roots.add(certificate).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let key_bytes = std::fs::read(&pki.server_key).unwrap();
    let key: PrivateKeyDer<'static> = rustls::pki_types::PrivateKeyDer::pem_slice_iter(&key_bytes)
        .next()
        .transpose()
        .unwrap()
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(read_certs(&pki.server_cert), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let calls = Arc::new(AtomicUsize::new(0));
    let task_calls = calls.clone();
    let card = Arc::new(card);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let calls = task_calls.clone();
            let card = card.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                let authenticated = request.get("token").and_then(Value::as_str) == Some(TOKEN);
                let payload = if !authenticated {
                    json!({"id": 1, "ok": false, "error": "unauthorized"})
                } else {
                    calls.fetch_add(1, Ordering::SeqCst);
                    match &*card {
                        RelayCard::Valid
                            if request.get("cmd").and_then(Value::as_str)
                                == Some("routing_bootstrap") =>
                        {
                            let relays = (2..5u8)
                                .map(|n| gcoms_routing::Relay {
                                    addr: format!("127.0.0.{n}:8443").parse().unwrap(),
                                    service_id: [n; 32],
                                    reentry_cap: [n + 10; 32],
                                    circuit_cap: [n + 20; 32],
                                    expires_at: now() + 3600,
                                })
                                .collect();
                            let bytes = gcoms_routing::bootstrap::BootstrapBundle { relays }
                                .encode()
                                .unwrap();
                            json!({ "id": 1, "ok": true, "data": {"routing_bundle_b64": URL_SAFE_NO_PAD.encode(bytes)} })
                        }
                        RelayCard::Valid => json!({
                            "id": 1,
                            "ok": true,
                            "data": {"private_card_b64": private_card(now())}
                        }),
                        RelayCard::Garbage => json!({
                            "id": 1,
                            "ok": true,
                            "data": {"private_card_b64": URL_SAFE_NO_PAD.encode(b"not-a-card")}
                        }),
                        RelayCard::Public => {
                            let identity = IdentityKeypair::from_seed([0xA2; 32]);
                            let (bundle, _secrets) = identity.issue_bundle();
                            let info = gcoms_node::proto::NodeInfo {
                                identity_pk: identity.public_bytes(),
                                bundle: bundle.encode(),
                                aliases: Vec::new(),
                                provisioning: None,
                            };
                            json!({
                                "id": 1,
                                "ok": true,
                                "data": {"private_card_b64": URL_SAFE_NO_PAD.encode(info.encode())}
                            })
                        }
                    }
                };
                let _ = reader
                    .get_mut()
                    .write_all(format!("{payload}\n").as_bytes())
                    .await;
            });
        }
    });
    (address, calls)
}

fn relay_config(base: &str, pki: &TestPki, controls: Vec<String>) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_base_url: base.into(),
        upstream_catalog_urls: Vec::new(),
        state_dir: None,
        ephemeral_test_mode: true,
        joins_per_source_per_minute: 1,
        joins_per_channel_per_minute: 1,
        channels: Vec::new(),
        network: None,
        relay_bootstrap: Some(RelayBootstrapConfig {
            provisions_per_source_per_minute: 5,
            provisions_global_per_minute: 50,
            max_in_flight: 4,
            idempotency_ttl_secs: 120,
            relay_controls: controls
                .into_iter()
                .map(|address| pki.owner_config(address))
                .collect(),
        }),
    }
}

async fn relay_provision_request(service: &str, request_id: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{service}/v1/relay-provisions"))
        .json(&json!({"request_id": request_id}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn relay_bootstrap_provisions_validated_card_idempotently() {
    let pki = TestPki::new();
    let (relay, calls) = fake_relay(&pki, RelayCard::Valid).await;
    let service = serve_catalog(relay_config("http://catalog.test", &pki, vec![relay])).await;
    let request_id = URL_SAFE_NO_PAD.encode([7u8; 16]);

    let first = relay_provision_request(&service, &request_id).await;
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    assert_eq!(first.headers()["pragma"], "no-cache");
    let body: RelayProvisionResponse = first.json().await.unwrap();
    assert_eq!(body.version, 1);
    let info = gcoms_node::proto::private_info_from_b64(&body.private_card_b64).unwrap();
    assert_eq!(info.provisioning.as_ref().unwrap().aliases.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let replay: RelayProvisionResponse = relay_provision_request(&service, &request_id)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(replay, body);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let second_id = URL_SAFE_NO_PAD.encode([8u8; 32]);
    let second = relay_provision_request(&service, &second_id).await;
    assert_eq!(second.status(), reqwest::StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn relay_bootstrap_rejects_bad_request_ids_without_spending_rate() {
    let pki = TestPki::new();
    let (relay, calls) = fake_relay(&pki, RelayCard::Valid).await;
    let mut cfg = relay_config("http://catalog.test", &pki, vec![relay]);
    if let Some(bootstrap) = cfg.relay_bootstrap.as_mut() {
        bootstrap.provisions_per_source_per_minute = 1;
    }
    let service = serve_catalog(cfg).await;

    let short = relay_provision_request(&service, &URL_SAFE_NO_PAD.encode([1u8; 15])).await;
    assert_eq!(short.status(), reqwest::StatusCode::BAD_REQUEST);
    let noncanonical = {
        let encoded = URL_SAFE_NO_PAD.encode([2u8; 16]);
        format!("{encoded}a")
    };
    let noncanonical = relay_provision_request(&service, &noncanonical).await;
    assert_eq!(noncanonical.status(), reqwest::StatusCode::BAD_REQUEST);
    let garbage = relay_provision_request(&service, "not-base64!!").await;
    assert_eq!(garbage.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The 60-second rate window can roll over between the two valid requests;
    // retry the pair with fresh ids whenever that boundary was crossed.
    let mut statuses = None;
    for attempt in 0..3u8 {
        let before_minute = now() / 60;
        let first = relay_provision_request(
            &service,
            &URL_SAFE_NO_PAD.encode([3u8; 16].map(|b| b.wrapping_add(attempt))),
        )
        .await;
        assert_eq!(first.status(), reqwest::StatusCode::OK);
        let limited = relay_provision_request(
            &service,
            &URL_SAFE_NO_PAD.encode([4u8; 16].map(|b| b.wrapping_add(attempt))),
        )
        .await;
        if now() / 60 == before_minute {
            statuses = Some((first, limited));
            break;
        }
        statuses = Some((first, limited));
    }
    let (first, limited) = statuses.unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    assert_eq!(limited.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(!limited.text().await.unwrap().contains(TOKEN));
}

#[tokio::test]
async fn relay_bootstrap_validates_cards_fails_over_and_redacts() {
    let pki = TestPki::new();
    let (garbage_relay, garbage_calls) = fake_relay(&pki, RelayCard::Garbage).await;
    let (public_relay, _) = fake_relay(&pki, RelayCard::Public).await;
    let (valid_relay, valid_calls) = fake_relay(&pki, RelayCard::Valid).await;

    let rejecting = serve_catalog(relay_config(
        "http://catalog.test",
        &pki,
        vec![garbage_relay.clone(), public_relay.clone()],
    ))
    .await;
    let request_id = URL_SAFE_NO_PAD.encode([9u8; 16]);
    let failed = relay_provision_request(&rejecting, &request_id).await;
    assert_eq!(failed.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let text = failed.text().await.unwrap();
    assert!(!text.contains(TOKEN));
    assert!(!text.contains("private_card"));
    assert_eq!(garbage_calls.load(Ordering::SeqCst), 1);

    let failed_again = relay_provision_request(&rejecting, &request_id).await;
    assert_eq!(
        failed_again.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(garbage_calls.load(Ordering::SeqCst), 2);

    let failing_over = serve_catalog(relay_config(
        "http://catalog.test",
        &pki,
        vec![garbage_relay, valid_relay],
    ))
    .await;
    let ok = relay_provision_request(&failing_over, &URL_SAFE_NO_PAD.encode([10u8; 16])).await;
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let body: RelayProvisionResponse = ok.json().await.unwrap();
    assert!(gcoms_node::proto::private_info_from_b64(&body.private_card_b64).is_some());
    assert_eq!(valid_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_bootstrap_requires_configuration_and_valid_limits() {
    let pki = TestPki::new();
    let (relay, _) = fake_relay(&pki, RelayCard::Valid).await;
    let mut absent = relay_config("http://catalog.test", &pki, vec![relay.clone()]);
    absent.relay_bootstrap = None;
    let service = serve_catalog(absent).await;
    let response = relay_provision_request(&service, &URL_SAFE_NO_PAD.encode([5u8; 16])).await;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let mut zero_rate = relay_config("http://catalog.test", &pki, vec![relay.clone()]);
    zero_rate
        .relay_bootstrap
        .as_mut()
        .unwrap()
        .provisions_global_per_minute = 0;
    assert!(AppState::load(zero_rate).await.is_err());

    let mut no_controls = relay_config("http://catalog.test", &pki, Vec::new());
    no_controls.relay_bootstrap.as_mut().unwrap().relay_controls = Vec::new();
    assert!(AppState::load(no_controls).await.is_err());

    let mut bad_ttl = relay_config("http://catalog.test", &pki, vec![relay]);
    bad_ttl
        .relay_bootstrap
        .as_mut()
        .unwrap()
        .idempotency_ttl_secs = 0;
    assert!(AppState::load(bad_ttl).await.is_err());
}

#[tokio::test]
async fn bootstrap_v2_is_private_introductions_only_and_separates_legacy_replay() {
    let pki = TestPki::new();
    let (relay, calls) = fake_relay(&pki, RelayCard::Valid).await;
    let service = serve_catalog(relay_config("http://catalog.test", &pki, vec![relay])).await;
    let client = reqwest::Client::new();
    let request_id = URL_SAFE_NO_PAD.encode([42u8; 16]);
    let request = json!({"request_id":request_id,"supported_versions":[2]});
    let mut previous = None;
    for _ in 0..2 {
        let response = client
            .post(format!("{service}/v1/relay-provisions"))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let response: Value = response.json().await.unwrap();
        assert_eq!(response.as_object().unwrap().len(), 2);
        assert_eq!(response["version"], 2);
        assert!(response.get("private_card_b64").is_none());
        let bytes = URL_SAFE_NO_PAD
            .decode(response["routing_bundle_b64"].as_str().unwrap())
            .unwrap();
        let bundle = gcoms_routing::bootstrap::BootstrapBundle::decode(&bytes).unwrap();
        assert_eq!(bundle.relays.len(), 3);
        if let Some(old) = previous {
            assert_eq!(response, old);
        }
        previous = Some(response);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let legacy: RelayProvisionResponse = relay_provision_request(&service, &request_id)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(legacy.version, 1);
    assert!(!legacy.private_card_b64.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let unsupported = client
        .post(format!("{service}/v1/relay-provisions"))
        .json(&json!({"request_id":request_id,"supported_versions":[99]}))
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 400);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn network_grants_authorize_before_relay_cache_and_persist_revocation() {
    use gcoms_catalog::network::{
        atomic_json, token_digest, GrantFile, GrantRecord, NetworkConfig,
    };
    use gcoms_network::{Founder, NetworkDefaults, SignedNetworkDefaults};
    let pki = TestPki::new();
    let (relay, calls) = fake_relay(&pki, RelayCard::Valid).await;
    let key = IdentityKeypair::from_seed([81; 32]);
    let defaults = NetworkDefaults {
        version: 1,
        network_id: "gchat.boo".into(),
        sequence: 1,
        issued_at: now() - 1,
        expires_at: now() + 3600,
        provider_urls: vec!["https://bootstrap-hel.gchat.boo/".into()],
        founders: vec![Founder {
            name: "r1.relays.gchat.boo".into(),
            service_id: [1; 32],
            address_hints: vec!["8.8.8.8:4433".parse().unwrap()],
        }],
        dns_domain: "gchat.boo".into(),
    };
    atomic_json(
        &pki.directory.join("defaults.json"),
        &SignedNetworkDefaults::sign(defaults, &key, vec![]).unwrap(),
    )
    .unwrap();
    std::fs::write(pki.directory.join("root.pub"), key.public_bytes()).unwrap();
    let tokens: Vec<_> = (83..86).map(|n| URL_SAFE_NO_PAD.encode([n; 32])).collect();
    let mut grants = GrantFile {
        version: 1,
        grants: tokens
            .iter()
            .enumerate()
            .map(|(index, token)| GrantRecord {
                id: token_digest(token).unwrap(),
                expires_at: now() + 3600,
                scopes: vec![if index == 2 { "names" } else { "bootstrap" }.into()],
                max_names: 1,
                revoked: false,
            })
            .collect(),
    };
    let grants_file = pki.directory.join("grants.json");
    atomic_json(&grants_file, &grants).unwrap();
    let mut config = relay_config("http://127.0.0.1/", &pki, vec![relay]);
    config.network = Some(NetworkConfig {
        network_id: "gchat.boo".into(),
        defaults_file: pki.directory.join("defaults.json"),
        verification_key_file: pki.directory.join("root.pub"),
        grants_file: grants_file.clone(),
        state_dir: pki.directory.join("network-state"),
        names_enabled: true,
        name_lease_secs: 3600,
        spaceship_credentials_file: None,
    });
    let service = serve_catalog(config).await;
    let client = reqwest::Client::new();
    let body = json!({"request_id":URL_SAFE_NO_PAD.encode([14;16]),"supported_versions":[2]});
    for token in ["wrong", &tokens[2]] {
        assert_eq!(
            client
                .post(format!("{service}/v1/relay-provisions"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let first = client
        .post(format!("{service}/v1/relay-provisions"))
        .bearer_auth(&tokens[0])
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let first: Value = first.json().await.unwrap();
    assert_eq!(first["version"], 2);
    let replay: Value = client
        .post(format!("{service}/v1/relay-provisions"))
        .bearer_auth(&tokens[0])
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        client
            .post(format!("{service}/v1/relay-provisions"))
            .bearer_auth(&tokens[1])
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "same request ID is separate for each grant"
    );
    grants.grants[0].revoked = true;
    atomic_json(&grants_file, &grants).unwrap();
    assert_eq!(
        client
            .post(format!("{service}/v1/relay-provisions"))
            .bearer_auth(&tokens[0])
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "revocation overrides cached provision"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    std::fs::write(&grants_file, b"corrupt").unwrap();
    assert_eq!(
        client
            .post(format!("{service}/v1/relay-provisions"))
            .bearer_auth(&tokens[1])
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        503,
        "unreadable registry must fail closed, including cache hits"
    );
}

#[tokio::test]
async fn gchat_origins_never_enable_legacy_unauthenticated_bootstrap() {
    let config:Config=serde_json::from_value(json!({"listen":"127.0.0.1:0","public_base_url":"https://bootstrap-hel.gchat.boo/","ephemeral_test_mode":true,"state_dir":null})).unwrap();
    let error = AppState::load(config).await.err().unwrap();
    assert!(error.contains("invitation network authorization"));
}
