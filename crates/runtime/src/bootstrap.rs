//! Trusted HTTPS bootstrap for the explicitly selected routing protocol.
//!
//! Configured HTTPS endpoints supply typed introductions for node validation
//! and retained re-entry. Legacy private-card provisioning remains a separate
//! compatibility API; it cannot replace current-protocol routing authority.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gcoms_node::proto::NodeInfo;
use reqwest::Url;
use serde::Deserialize;

const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(all(test, feature = "gc2-carrier"))]
#[path = "bootstrap_gc2_tests.rs"]
mod gc2_tests;

/// Use the encrypted private view first, then configured HTTPS only if re-entry
/// has not recovered. This runs after local startup, with one caller deadline.
pub async fn recover_routing(
    node: &gcoms_node::node::NodeHandle,
    endpoints: &[Url],
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    let client = http_builder(true, FETCH_TIMEOUT)
        .build()
        .map_err(|_| "build bootstrap client")?;
    recover_routing_with(node, endpoints, deadline, &client).await
}

async fn recover_routing_with(
    node: &gcoms_node::node::NodeHandle,
    endpoints: &[Url],
    deadline: tokio::time::Instant,
    client: &reqwest::Client,
) -> Result<(), String> {
    if node.has_routing_bootstrap() {
        let cached_deadline =
            deadline.min(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
        if node.wait_for_inbox(cached_deadline).await.is_ok() {
            return Ok(());
        }
    }
    #[cfg(feature = "gc2-carrier")]
    if node.uses_gc2_routing() {
        let bundle = tokio::time::timeout_at(deadline, fetch_gc2_routing_with(client, endpoints))
            .await
            .map_err(|_| "routing bootstrap deadline elapsed")??;
        node.install_gc2_routing_bootstrap(&bundle)?;
        return node.wait_for_inbox(deadline).await;
    }
    let _ = client;
    let bundle = tokio::time::timeout_at(deadline, fetch_routing_bootstrap(endpoints, false))
        .await
        .map_err(|_| "routing bootstrap deadline elapsed")??;
    node.install_routing_bootstrap(bundle).await?;
    node.wait_for_inbox(deadline).await
}

pub(crate) fn uses_installed_network(
    network: Option<&gcoms_network_client::NetworkClient>,
    urls: &[String],
) -> bool {
    urls.is_empty()
        || network
            .and_then(|n| n.current_defaults().ok())
            .is_some_and(|n| urls.iter().all(|url| n.provider_urls.contains(url)))
}

/// Shared signed-network recovery for current and retained combined stores.
pub async fn recover_network(
    node: &gcoms_node::node::NodeHandle,
    network: Option<&gcoms_network_client::NetworkClient>,
    urls: &[String],
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    if !uses_installed_network(network, urls) {
        return recover_routing(node, &parse_bootstrap_urls(urls, false)?, deadline).await;
    }
    let cached = deadline.min(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
    let retained = node.has_routing_bootstrap();
    if retained && node.wait_for_inbox(cached).await.is_ok() {
        return Ok(());
    }
    let Some(network) = network else {
        if retained {
            return node.wait_for_inbox(deadline).await;
        }
        return Err("Configure network trust and enter a network invitation to connect.".into());
    };
    if !network.has_invitation()? {
        // Thirty seconds decides when an authorized provider fallback may
        // help. Without a grant, retained re-entry still owns the caller's
        // remaining budget; slow readiness does not erase its authority.
        if retained {
            return node.wait_for_inbox(deadline).await;
        }
        return Err("Enter a network invitation to connect.".into());
    }
    #[cfg(feature = "gc2-carrier")]
    if node.uses_gc2_routing() {
        let bundle = network.fetch_gc2_routing(deadline).await?;
        node.install_gc2_routing_bootstrap(&bundle)?;
        return node.wait_for_inbox(deadline).await;
    }
    let bundle = network.fetch_routing(deadline).await?;
    node.install_routing_bootstrap(bundle).await?;
    node.wait_for_inbox(deadline).await
}

/// A reqwest builder with the client's fixed policy plus static DNS pins.
///
/// `GC_HTTP_RESOLVE=host=ip[:port][,host=ip...]` maps hostnames to
/// addresses before any lookup. Static musl builds on Android have no
/// `/etc/resolv.conf`, so this is how the HTTPS bootstrap and catalog
/// fetches reach a relay by name there; the port defaults to 443.
pub fn http_builder(https_only: bool, timeout: std::time::Duration) -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder()
        .https_only(https_only)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(crate::dns::FallbackResolver));
    if let Ok(pins) = std::env::var("GC_HTTP_RESOLVE") {
        for pin in pins.split(',').map(str::trim).filter(|pin| !pin.is_empty()) {
            let Some((host, address)) = pin.split_once('=') else {
                continue;
            };
            let address = address.trim();
            let socket: Option<std::net::SocketAddr> = address.parse().ok().or_else(|| {
                address
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(|ip| std::net::SocketAddr::new(ip, 443))
            });
            if let Some(socket) = socket {
                builder = builder.resolve(host.trim(), socket);
            }
        }
    }
    builder
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct RelayProvisionResponse {
    version: u8,
    private_card_b64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingBootstrapResponse {
    version: u8,
    routing_bundle_b64: String,
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err("bootstrap response too large".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "bootstrap response failed")?
    {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
            return Err("bootstrap response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Explicitly configured HTTPS providers retain their TLS/origin trust policy,
/// but current-protocol nodes request only GC/2 introductions, never v1/v2.
#[cfg(feature = "gc2-carrier")]
pub async fn fetch_gc2_routing_bootstrap(
    endpoints: &[Url],
) -> Result<gcoms_routing::gc2::directory::BootstrapBundle, String> {
    let client = http_builder(true, FETCH_TIMEOUT)
        .build()
        .map_err(|_| "build bootstrap client")?;
    fetch_gc2_routing_with(&client, endpoints).await
}

#[cfg(feature = "gc2-carrier")]
async fn fetch_gc2_routing_with(
    client: &reqwest::Client,
    endpoints: &[Url],
) -> Result<gcoms_routing::gc2::directory::BootstrapBundle, String> {
    if endpoints.is_empty() {
        return Err("no relay bootstrap endpoints configured".into());
    }
    let request_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
    let mut last = String::from("no GC/2 bootstrap endpoint succeeded");
    for base in endpoints {
        let url = base
            .join("v1/relay-provisions")
            .map_err(|_| "invalid bootstrap base URL")?;
        let response = match client
            .post(url)
            .json(&serde_json::json!({"request_id":request_id,"supported_versions":[3]}))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                last = format!("bootstrap endpoint returned {}", response.status());
                continue;
            }
            Err(_) => {
                last = "bootstrap endpoint unreachable".into();
                continue;
            }
        };
        let bytes = match bounded_body(response).await {
            Ok(bytes) => bytes,
            Err(error) => {
                last = error;
                continue;
            }
        };
        match gcoms_network_client::routing::decode_gc2_response(&bytes) {
            Ok(bundle) => return Ok(bundle),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// Initial trusted HTTPS discovery carries private relay introductions only.
/// Queue ownership is acquired later through an authenticated complete circuit.
/// Existing endpoints/configuration URLs are retained. A v1-only response does
/// not authorize a direct application connection.
pub async fn fetch_routing_bootstrap(
    endpoints: &[Url],
    ephemeral: bool,
) -> Result<gcoms_routing::bootstrap::BootstrapBundle, String> {
    if endpoints.is_empty() {
        return Err("no relay bootstrap endpoints configured".into());
    }
    let client = http_builder(!ephemeral, FETCH_TIMEOUT)
        .build()
        .map_err(|_| "build bootstrap client")?;
    let request_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
    let mut last = String::from("no circuit bootstrap endpoint succeeded");
    for base in endpoints {
        let url = base
            .join("v1/relay-provisions")
            .map_err(|_| "invalid bootstrap base URL")?;
        let response = match client
            .post(url)
            .json(&serde_json::json!({"request_id": request_id, "supported_versions": [2]}))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                last = format!("bootstrap endpoint returned {}", response.status());
                continue;
            }
            Err(_) => {
                last = "bootstrap endpoint unreachable".into();
                continue;
            }
        };
        let bytes = match bounded_body(response).await {
            Ok(bytes) => bytes,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let parsed = match serde_json::from_slice::<RoutingBootstrapResponse>(&bytes) {
            Ok(parsed) if parsed.version == 2 => parsed,
            _ => {
                last = "bootstrap endpoint does not provide circuit introductions".into();
                continue;
            }
        };
        let Some(raw) = gcoms_transport::decode_b64url(&parsed.routing_bundle_b64) else {
            last = "bootstrap routing bundle is not canonical".into();
            continue;
        };
        match gcoms_routing::bootstrap::BootstrapBundle::decode(&raw) {
            Ok(bundle) => {
                if !ephemeral
                    && bundle
                        .relays
                        .iter()
                        .any(|r| !gcoms_routing::service::public_ip(r.addr.ip()))
                {
                    last = "bootstrap relay is not publicly reachable".into();
                    continue;
                }
                return Ok(bundle);
            }
            Err(_) => {
                last = "bootstrap routing bundle is invalid".into();
            }
        }
    }
    Err(last)
}

/// Parse credential-free base URLs for bootstrap. Production requires HTTPS;
/// `ephemeral` test deployments may use HTTP loopback services.
pub fn parse_bootstrap_urls(values: &[String], ephemeral: bool) -> Result<Vec<Url>, String> {
    let mut urls = Vec::with_capacity(values.len());
    for value in values {
        let url =
            Url::parse(value.trim()).map_err(|error| format!("invalid bootstrap URL: {error}"))?;
        let scheme_ok = if ephemeral {
            url.scheme() == "https" || url.scheme() == "http"
        } else {
            url.scheme() == "https"
        };
        if !scheme_ok
            || url.host_str().is_none()
            || url.cannot_be_a_base()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.username() != ""
            || url.password().is_some()
        {
            return Err("bootstrap URLs must be credential-free base URLs".into());
        }
        let mut normalized = url;
        normalized.set_path(&format!("{}/", normalized.path().trim_end_matches('/')));
        if !urls.contains(&normalized) {
            urls.push(normalized);
        }
    }
    if urls.is_empty() {
        return Err("no relay bootstrap endpoints configured".into());
    }
    Ok(urls)
}

/// Try each endpoint in order and return the first valid private card.
pub async fn fetch_relay_provision(endpoints: &[Url], ephemeral: bool) -> Result<NodeInfo, String> {
    if endpoints.is_empty() {
        return Err("no relay bootstrap endpoints configured".into());
    }
    let client = http_builder(!ephemeral, FETCH_TIMEOUT)
        .build()
        .map_err(|error| format!("build bootstrap client: {error}"))?;
    let request_id = {
        let bytes: [u8; 16] = rand::random();
        URL_SAFE_NO_PAD.encode(bytes)
    };
    let mut last = String::from("no relay bootstrap endpoint succeeded");
    for base in endpoints {
        let url = match base.join("v1/relay-provisions") {
            Ok(url) => url,
            Err(_) => continue,
        };
        let response = match client
            .post(url)
            .json(&serde_json::json!({"request_id": request_id}))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                last = format!("bootstrap endpoint unreachable: {error}");
                continue;
            }
        };
        if !response.status().is_success() {
            last = format!("bootstrap endpoint returned {}", response.status());
            continue;
        }
        let bytes = match bounded_body(response).await {
            Ok(bytes) => bytes,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let Ok(parsed) = serde_json::from_slice::<RelayProvisionResponse>(&bytes) else {
            last = "bootstrap response was not the expected schema".into();
            continue;
        };
        if parsed.version != 1 {
            last = "bootstrap response used an unsupported version".into();
            continue;
        }
        let Some(info) = gcoms_node::proto::private_info_from_b64(&parsed.private_card_b64) else {
            last = "bootstrap response contained an invalid private card".into();
            continue;
        };
        if !info.validate_relay_provision(now_unix(), ephemeral) {
            last = "bootstrap response contained an unusable relay card".into();
            continue;
        }
        return Ok(info);
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_private_card(now_unix: u64) -> String {
        let identity = gcoms_crypto::IdentityKeypair::from_seed([0xB1; 32]);
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
        let info = NodeInfo {
            identity_pk: identity.public_bytes(),
            bundle: bundle.encode(),
            aliases: owned.iter().map(|o| o.contact.clone()).collect(),
            provisioning: Some(gcoms_node::alias::RelayProvision {
                aliases: owned,
                frwd_path: "frwd-token".into(),
                hop_key: [8; 32],
            }),
        };
        URL_SAFE_NO_PAD.encode(gcoms_node::proto::NodeInfo::encode_private(&info).unwrap())
    }

    fn url(value: &str) -> Url {
        parse_bootstrap_urls(&[value.to_string()], true)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    async fn bootstrap_server(handler: axum::routing::MethodRouter) -> Url {
        let router = axum::Router::new().route("/v1/relay-provisions", handler);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        url(&format!("http://{address}"))
    }

    #[test]
    fn bootstrap_rejects_unsafe_urls() {
        assert!(parse_bootstrap_urls(&["http://a.example/".into()], false).is_err());
        assert!(parse_bootstrap_urls(&["https://user:pw@a.example/".into()], true).is_err());
        assert!(parse_bootstrap_urls(&["https://a.example/?x=1".into()], true).is_err());
        assert!(parse_bootstrap_urls(&["https://a.example/#frag".into()], true).is_err());
        assert!(parse_bootstrap_urls(&["not a url".into()], true).is_err());
        assert!(parse_bootstrap_urls(&[], true).is_err());
        assert_eq!(
            parse_bootstrap_urls(&["https://a.example".into()], false).unwrap()[0].as_str(),
            "https://a.example/"
        );
        assert!(parse_bootstrap_urls(&["http://127.0.0.1:1/".into()], true).is_ok());
    }

    #[tokio::test]
    async fn bootstrap_tries_endpoints_and_validates_cards() {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_body = serde_json::json!({
            "version": 1,
            "private_card_b64": valid_private_card(now_unix)
        });
        let bad = bootstrap_server(axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "version": 1,
                "private_card_b64": URL_SAFE_NO_PAD.encode(b"not-a-card")
            }))
        }))
        .await;
        let good = bootstrap_server(axum::routing::post(move || {
            let valid_body = valid_body.clone();
            async move { axum::Json(valid_body) }
        }))
        .await;

        let card = fetch_relay_provision(&[bad, good], true).await.unwrap();
        assert!(card.provisioning.is_some());

        let public_only = bootstrap_server(axum::routing::post(|| async {
            let identity = gcoms_crypto::IdentityKeypair::from_seed([1; 32]);
            let (bundle, _secrets) = identity.issue_bundle();
            let info = NodeInfo {
                identity_pk: identity.public_bytes(),
                bundle: bundle.encode(),
                aliases: Vec::new(),
                provisioning: None,
            };
            axum::Json(serde_json::json!({
                "version": 1,
                "private_card_b64": URL_SAFE_NO_PAD.encode(info.encode())
            }))
        }))
        .await;
        assert!(fetch_relay_provision(&[public_only], true).await.is_err());
    }

    #[tokio::test]
    async fn bootstrap_rejects_wrong_version_and_oversized_responses() {
        let wrong_version = bootstrap_server(axum::routing::post(|| async {
            axum::Json(serde_json::json!({"version": 2, "private_card_b64": "AA"}))
        }))
        .await;
        assert!(fetch_relay_provision(&[wrong_version], true).await.is_err());
        let oversized = bootstrap_server(axum::routing::post(|| async {
            (
                axum::http::StatusCode::OK,
                [b'x'; MAX_RESPONSE_BYTES + 1].to_vec(),
            )
        }))
        .await;
        assert!(fetch_relay_provision(&[oversized], true).await.is_err());
    }

    #[tokio::test]
    async fn circuit_bootstrap_negotiates_v2_and_never_uses_a_legacy_queue_card() {
        let bundle = gcoms_routing::bootstrap::BootstrapBundle {
            relays: (1..=3u8)
                .map(|n| gcoms_routing::Relay {
                    addr: format!("192.0.2.{n}:443").parse().unwrap(),
                    service_id: [n; 32],
                    reentry_cap: [n + 10; 32],
                    circuit_cap: [n + 20; 32],
                    expires_at: now_unix() + 60,
                })
                .collect(),
        };
        let expected = bundle.encode().unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&expected);
        let legacy = bootstrap_server(axum::routing::post(|| async {
            axum::Json(serde_json::json!({"version": 1, "private_card_b64": valid_private_card(now_unix())}))
        })).await;
        let good = bootstrap_server(axum::routing::post(
            move |axum::Json(request): axum::Json<serde_json::Value>| {
                let encoded = encoded.clone();
                async move {
                    assert_eq!(request["supported_versions"], serde_json::json!([2]));
                    axum::Json(serde_json::json!({"version": 2, "routing_bundle_b64": encoded}))
                }
            },
        ))
        .await;
        assert!(fetch_routing_bootstrap(std::slice::from_ref(&legacy), true)
            .await
            .is_err());
        let fetched = fetch_routing_bootstrap(&[legacy, good], true)
            .await
            .unwrap();
        assert_eq!(fetched.encode().unwrap(), expected);
    }

    #[tokio::test]
    async fn bootstrap_bounds_a_chunked_body_without_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            for _ in 0..40 {
                if stream.write_all(b"1000\r\n").await.is_err()
                    || stream.write_all(&[b' '; 4096]).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });
        let error = fetch_routing_bootstrap(&[url(&format!("http://{addr}"))], true)
            .await
            .unwrap_err();
        assert_eq!(error, "bootstrap response too large");
        task.await.unwrap();
    }

    #[test]
    fn decode_relay_card_accepts_private_and_rejects_public() {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let identity = gcoms_crypto::IdentityKeypair::from_seed([0xB2; 32]);
        let (bundle, _secrets) = identity.issue_bundle();
        let public = NodeInfo {
            identity_pk: identity.public_bytes(),
            bundle: bundle.encode(),
            aliases: Vec::new(),
            provisioning: None,
        };
        assert!(
            crate::contacts::decode_relay_card(&URL_SAFE_NO_PAD.encode(public.encode())).is_err()
        );
        assert!(crate::contacts::decode_relay_card(&valid_private_card(now_unix)).is_ok());
        assert!(
            crate::contacts::decode_contact_card(&URL_SAFE_NO_PAD.encode(public.encode())).is_ok()
        );
    }
}
