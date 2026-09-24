//! Production-profile bootstrap journey in a disconnected Linux namespace.
//! Provider TLS/hostname checks remain enabled with an explicit fixture CA.
use super::*;
#[cfg(target_os = "linux")]
use crate::runtime::ProtocolRuntime;
use axum::{extract::State, response::IntoResponse, Json};
#[cfg(target_os = "linux")]
use gcoms_node::node::{start_with_routing, NodeConfig, NodeProfile, RoutingConfig};
use gcoms_routing::gc2::directory::BootstrapBundle;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

struct Provider {
    current: serde_json::Value,
    legacy: serde_json::Value,
    downgrade: AtomicBool,
    requests: Mutex<Vec<serde_json::Value>>,
}

async fn provision(
    State(state): State<Arc<Provider>>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    state.requests.lock().unwrap().push(body);
    Json(if state.downgrade.load(Ordering::SeqCst) {
        state.legacy.clone()
    } else {
        state.current.clone()
    })
    .into_response()
}

struct TlsListener {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = self.listener.accept().await.unwrap();
            if let Ok(stream) = self.acceptor.accept(tcp).await {
                return (stream, addr);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

async fn provider(state: Arc<Provider>) -> (Url, reqwest::Client, tokio::task::JoinHandle<()>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&server_key, &ca, &ca_key)
        .unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![server.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route("/v1/relay-provisions", axum::routing::post(provision))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(
            TlsListener {
                listener,
                acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
            },
            app,
        )
        .await
        .unwrap()
    });
    let client = http_builder(true, Duration::from_secs(3))
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_der(ca.der()).unwrap())
        .resolve("localhost", addr)
        .build()
        .unwrap();
    (
        Url::parse(&format!("https://localhost:{}/", addr.port())).unwrap(),
        client,
        task,
    )
}

#[tokio::test]
async fn gc2_https_bootstrap_refuses_legacy_and_preserves_explicit_selection() {
    let bundle = BootstrapBundle {
        relays: vec![gcoms_routing::service::gc2_introduction_from(
            "8.8.8.8:4433".parse().unwrap(),
            [1; 32],
            &[2; 32],
            now_unix(),
        )],
    };
    let state = Arc::new(Provider {
        current: serde_json::json!({"version":3,"routing_protocol":"gc2","routing_bundle_b64":URL_SAFE_NO_PAD.encode(bundle.encode().unwrap())}),
        legacy: serde_json::json!({"version":2,"routing_bundle_b64":"AA"}),
        downgrade: AtomicBool::new(true),
        requests: Mutex::new(vec![]),
    });
    let (url, client, task) = provider(state.clone()).await;
    assert!(fetch_gc2_routing_with(&client, std::slice::from_ref(&url))
        .await
        .is_err());
    state.downgrade.store(false, Ordering::SeqCst);
    let fetched = fetch_gc2_routing_with(&client, std::slice::from_ref(&url))
        .await
        .unwrap();
    assert_eq!(fetched.encode().unwrap(), bundle.encode().unwrap());
    let untrusted = http_builder(true, Duration::from_secs(2))
        .no_proxy()
        .build()
        .unwrap();
    assert!(
        fetch_gc2_routing_with(&untrusted, std::slice::from_ref(&url))
            .await
            .is_err()
    );
    assert!(state
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["supported_versions"] == serde_json::json!([3])));
    task.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the disconnected namespace created by scripts/test-bootstrap-namespace.py"]
async fn production_bootstrap_fresh_reopen_and_recovery() {
    assert_eq!(
        std::env::var("GCHAT_BOOTSTRAP_NAMESPACE").as_deref(),
        Ok("isolated")
    );
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_str()
            .unwrap(),
        std::env::var("GCHAT_BOOTSTRAP_HOST_NAMESPACE").unwrap()
    );
    assert_eq!(
        std::fs::read_to_string("/proc/net/dev")
            .unwrap()
            .lines()
            .skip(2)
            .map(|line| line.split_once(':').unwrap().0.trim().to_string())
            .collect::<Vec<_>>(),
        vec!["lo".to_string()]
    );
    tokio::time::timeout(Duration::from_secs(360), production_journey())
        .await
        .unwrap();
}

#[cfg(target_os = "linux")]
fn assert_current_ready(node: &gcoms_node::node::NodeHandle) {
    let status = node.transport_status();
    assert_eq!(status.profile_id, Some(22));
    assert_eq!(status.bootstrap_version, Some(2));
    // This bootstrap journey has inboxes but no joined channels. Require both
    // traffic classes for every owned alias, rather than counting channel routes.
    assert!(status.owned_aliases >= 2, "{status:?}");
    assert!(
        status.routing_ready
            && status.interactive_subscriptions >= status.owned_aliases
            && status.bulk_subscriptions >= status.owned_aliases,
        "{status:?}"
    );
    eprintln!("current bootstrap ready: {status:?}");
}

#[cfg(target_os = "linux")]
async fn production_journey() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    retained_bootstrap_without_invitation_obeys_deadline(directory.path()).await;
    let mut relays = Vec::new();
    for n in 71..75u8 {
        let config = NodeConfig {
            seed: [n; 32],
            listen: format!("93.184.216.{n}:0").parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            alias_lifecycle: Default::default(),
            profile: NodeProfile::gchat_file_transfer_production(None, 2),
        };
        relays.push(
            start_with_routing(config, RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = BootstrapBundle {
        relays: relays
            .iter()
            .map(|r| r.gc2_relay_introduction().unwrap())
            .collect(),
    };
    for relay in &relays {
        relay.install_gc2_routing_bootstrap(&bundle).unwrap();
    }
    let legacy = gcoms_routing::bootstrap::BootstrapBundle {
        relays: relays
            .iter()
            .map(|r| r.relay_introduction().unwrap())
            .collect(),
    };
    let state = Arc::new(Provider {
        current: serde_json::json!({"version":3,"routing_protocol":"gc2","routing_bundle_b64":URL_SAFE_NO_PAD.encode(bundle.encode().unwrap())}),
        legacy: serde_json::json!({"version":2,"routing_bundle_b64":URL_SAFE_NO_PAD.encode(legacy.encode().unwrap())}),
        downgrade: AtomicBool::new(false),
        requests: Mutex::new(vec![]),
    });
    let (url, http, provider_task) = provider(state.clone()).await;
    let profile = directory.path().join("fresh.gcprotocol");
    let first = protected(&profile, "127.0.0.1:24491".parse().unwrap(), true)
        .await
        .unwrap();
    let node = first.sdk_client().embedded().node().clone();
    assert!(node.uses_gc2_routing());
    assert!(!node.has_routing_bootstrap());
    assert!(recover_network(
        &node,
        first.network_client().as_ref(),
        &[],
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap_err()
    .contains("Enter a network invitation"));
    assert!(state.requests.lock().unwrap().is_empty());
    recover_routing_with(
        &node,
        std::slice::from_ref(&url),
        tokio::time::Instant::now() + Duration::from_secs(120),
        &http,
    )
    .await
    .unwrap();
    assert!(node.has_routing_bootstrap());
    assert!(node.routing_bootstrap().is_err());
    assert!(node
        .install_routing_bootstrap(legacy.clone())
        .await
        .is_err());
    assert_current_ready(&node);
    let identity = node.current_info().await.unwrap().identity_pk;
    let introductions: std::collections::BTreeSet<_> = node
        .gc2_routing_bootstrap()
        .unwrap()
        .relays
        .iter()
        .map(|r| r.service_id)
        .collect();
    first.shutdown().await.unwrap();
    drop(node);
    state.downgrade.store(true, Ordering::SeqCst);
    let calls = state.requests.lock().unwrap().len();
    let reopened = protected(&profile, "127.0.0.1:24491".parse().unwrap(), false)
        .await
        .unwrap();
    let node = reopened.sdk_client().embedded().node().clone();
    assert!(node.has_routing_bootstrap());
    assert_eq!(
        node.gc2_routing_bootstrap()
            .unwrap()
            .relays
            .iter()
            .map(|r| r.service_id)
            .collect::<std::collections::BTreeSet<_>>(),
        introductions
    );
    assert_ne!(
        reopened.network_status().state,
        crate::network_status::NetworkState::InvitationRequired
    );
    recover_network(
        &node,
        reopened.network_client().as_ref(),
        &[],
        tokio::time::Instant::now() + Duration::from_secs(120),
    )
    .await
    .unwrap();
    assert_eq!(
        state.requests.lock().unwrap().len(),
        calls,
        "retained bootstrap avoids HTTPS recovery"
    );
    assert_eq!(node.current_info().await.unwrap().identity_pk, identity);
    assert_current_ready(&node);
    reopened.shutdown().await.unwrap();
    drop(node);
    let recovery = ProtocolRuntime::create_protected(
        &directory.path().join("recover.gcprotocol"),
        "bootstrap-test",
        "127.0.0.1:24492".parse().unwrap(),
        None,
        None,
        &[],
    )
    .await
    .unwrap();
    let node = recovery.sdk_client().embedded().node().clone();
    let identity = node.current_info().await.unwrap().identity_pk;
    assert!(recover_routing_with(
        &node,
        std::slice::from_ref(&url),
        tokio::time::Instant::now() + Duration::from_secs(10),
        &http
    )
    .await
    .is_err());
    assert!(!node.has_routing_bootstrap());
    assert!(!node.transport_status().routing_ready);
    state.downgrade.store(false, Ordering::SeqCst);
    recover_routing_with(
        &node,
        std::slice::from_ref(&url),
        tokio::time::Instant::now() + Duration::from_secs(120),
        &http,
    )
    .await
    .unwrap();
    assert_eq!(node.current_info().await.unwrap().identity_pk, identity);
    assert_current_ready(&node);
    assert!(state
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["supported_versions"] == serde_json::json!([3])));
    recovery.shutdown().await.unwrap();
    drop(node);
    provider_task.abort();
    for relay in relays {
        relay.shutdown().await;
    }
}

#[cfg(target_os = "linux")]
async fn retained_bootstrap_without_invitation_obeys_deadline(directory: &std::path::Path) {
    // No relay listens here. The disconnected namespace makes this a real
    // unavailable retained route without contacting an operated provider.
    let profile = directory.join("retained-unavailable.gcprotocol");
    let runtime = protected(&profile, "127.0.0.1:24493".parse().unwrap(), true)
        .await
        .unwrap();
    let node = runtime.sdk_client().embedded().node().clone();
    let bundle = BootstrapBundle {
        relays: vec![gcoms_routing::service::gc2_introduction_from(
            "93.184.216.71:4433".parse().unwrap(),
            [89; 32],
            &[90; 32],
            now_unix(),
        )],
    };
    node.install_gc2_routing_bootstrap(&bundle).unwrap();
    assert!(node.has_routing_bootstrap());
    let network = runtime.network_client().unwrap();
    assert!(!network.has_invitation().unwrap());
    let identity = node.current_info().await.unwrap().identity_pk;
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(35);
    let error = recover_network(&node, Some(&network), &[], deadline)
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(error, "inbox routing is recovering", "elapsed={elapsed:?}");
    assert!(
        tokio::time::Instant::now() >= deadline,
        "retained re-entry abandoned the caller's budget: {elapsed:?}"
    );
    assert!(node.has_routing_bootstrap());
    assert!(!node.transport_status().routing_ready);
    assert_eq!(node.current_info().await.unwrap().identity_pk, identity);
    runtime.shutdown().await.unwrap();
    drop(node);
}

#[cfg(target_os = "linux")]
async fn protected(
    path: &std::path::Path,
    listen: std::net::SocketAddr,
    create: bool,
) -> Result<ProtocolRuntime, String> {
    ProtocolRuntime::open_options(
        path,
        "bootstrap-test",
        create,
        crate::RuntimeOptions {
            durable_channel_inbox: false,
            listen,
            advertise: None,
            relay: None,
            fixture: false,
            carrier: gcoms_sdk::CarrierProfile::Gc2,
            network: Some(crate::network::from_json(include_bytes!(
                "../tests/fixtures/network.json"
            ))?),
        },
    )
    .await
}
