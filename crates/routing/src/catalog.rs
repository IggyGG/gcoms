//! Bounded catalog HTTP over a circuit, with ordinary end-to-end WebPKI.
//! There is no local DNS, redirect, arbitrary header or general proxy operation.
use crate::{OnionConnector, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::{sync::Arc, time::Duration};
use tokio_rustls::{rustls, TlsConnector};

pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn validate(method: &str, value: &str, body: &[u8]) -> Result<url::Url> {
    if value.len() > 4096 || body.len() > MAX_REQUEST_BYTES {
        return Err("catalog request exceeds limit".into());
    }
    let url = url::Url::parse(value)?;
    let host = url.host_str().ok_or("catalog host is absent")?;
    if url.scheme() != "https"
        || !crate::wire::valid_host(host)
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path().contains('%')
        || url.path().contains("//")
    {
        return Err("catalog requires a credential-free HTTPS origin".into());
    }
    let parts: Vec<_> = url.path().split('/').collect();
    let allowed = match method {
        "GET" => url.path().ends_with("/v1/catalog") && body.is_empty(),
        "PUT" => url.path().ends_with("/v1/descriptors") && url.query().is_none(),
        "POST" => {
            parts.len() >= 5
                && parts[parts.len() - 4] == "v1"
                && parts[parts.len() - 3] == "channels"
                && parts[parts.len() - 1] == "join"
                && parts[parts.len() - 2].len() == 43
                && parts[parts.len() - 2]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && url.query().is_none()
        }
        _ => false,
    };
    let mut keys = std::collections::HashSet::new();
    if !allowed
        || url.query_pairs().any(|(k, v)| {
            !matches!(k.as_ref(), "limit" | "cursor")
                || v.len() > 1024
                || !keys.insert(k.into_owned())
        })
    {
        return Err("unsupported catalog operation".into());
    }
    Ok(url)
}

pub async fn request(
    connector: &OnionConnector,
    origins: &[String],
    method: &str,
    value: &str,
    body: &[u8],
) -> Result<Response> {
    request_with_connector(
        CatalogConnector::Legacy(connector),
        origins,
        method,
        value,
        body,
    )
    .await
}

/// Catalog access over an already-established GC/2 entry. No legacy or direct
/// connection is available to this path, including while entries are unavailable.
#[cfg(feature = "experimental-gc2")]
pub async fn request_gc2(
    connector: &crate::gc2::owner::ReadyConnector,
    origins: &[String],
    method: &str,
    value: &str,
    body: &[u8],
) -> Result<Response> {
    request_with_connector(
        CatalogConnector::Gc2(connector),
        origins,
        method,
        value,
        body,
    )
    .await
}

#[derive(Clone, Copy)]
enum CatalogConnector<'a> {
    Legacy(&'a OnionConnector),
    #[cfg(feature = "experimental-gc2")]
    Gc2(&'a crate::gc2::owner::ReadyConnector),
}

impl CatalogConnector<'_> {
    async fn connect_https(
        &self,
        host: &str,
        origins: &[String],
    ) -> Result<gcoms_transport::connector::BoxStream> {
        match self {
            Self::Legacy(connector) => connector.connect_https(host, origins).await,
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2(connector) => connector.connect_https(host, origins).await,
        }
    }
}

async fn request_with_connector(
    connector: CatalogConnector<'_>,
    origins: &[String],
    method: &str,
    value: &str,
    body: &[u8],
) -> Result<Response> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    request_with_tls(connector, origins, method, value, body, Arc::new(tls)).await
}

async fn request_with_tls(
    connector: CatalogConnector<'_>,
    origins: &[String],
    method: &str,
    value: &str,
    body: &[u8],
    tls: Arc<rustls::ClientConfig>,
) -> Result<Response> {
    let url = validate(method, value, body)?;
    let host = url.host_str().ok_or("catalog host is absent")?.to_owned();
    tokio::time::timeout(Duration::from_secs(180), async {
        let stream = connector.connect_https(&host, origins).await?;
        let tls = TlsConnector::from(tls)
            .connect(
                rustls::pki_types::ServerName::try_from(host.clone())?,
                stream,
            )
            .await?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(16 * 1024)
            .handshake(TokioIo::new(tls))
            .await?;
        // The owner aborts the connection on cancellation, timeout and every exit.
        let connection = Connection(tokio::spawn(connection));
        let mut target = url.path().to_owned();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        let request = http::Request::builder()
            .method(method)
            .uri(target)
            .header(http::header::HOST, host)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::CONNECTION, "close")
            .body(Full::new(Bytes::copy_from_slice(body)))?;
        let response = sender.send_request(request).await?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err("catalog redirects are not accepted".into());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                if data.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                    return Err("catalog response exceeds limit".into());
                }
                bytes.extend_from_slice(&data);
            }
        }
        drop(connection);
        Ok(Response {
            status,
            body: bytes,
        })
    })
    .await
    .map_err(|_| "catalog request deadline elapsed")?
}

struct Connection(tokio::task::JoinHandle<std::result::Result<(), hyper::Error>>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_scope_rejects_proxy_and_redirect_inputs() {
        assert!(validate("GET", "https://catalog.example/v1/catalog?limit=100", &[]).is_ok());
        for (method, url) in [
            ("CONNECT", "https://catalog.example/v1/catalog"),
            ("GET", "http://catalog.example/v1/catalog"),
            ("GET", "https://127.0.0.1/v1/catalog"),
            ("GET", "https://catalog.example:8443/v1/catalog"),
            ("GET", "https://user@catalog.example/v1/catalog"),
            ("GET", "https://catalog.example/admin"),
            (
                "GET",
                "https://catalog.example/v1/catalog?redirect=https://example.org",
            ),
            ("GET", "https://catalog.example/v1/catalog?limit=1&limit=2"),
        ] {
            assert!(validate(method, url, &[]).is_err(), "{url}");
        }
        assert!(validate(
            "PUT",
            "https://catalog.example/v1/descriptors",
            &vec![0; MAX_REQUEST_BYTES + 1]
        )
        .is_err());
    }
    #[tokio::test]
    async fn https_uses_remote_dns_and_end_to_end_certificate_validation() {
        https_scenario(false).await;
    }

    #[cfg(feature = "experimental-gc2")]
    #[tokio::test]
    async fn gc2_https_uses_ready_entries_remote_dns_and_end_to_end_certificate_validation() {
        https_scenario(true).await;
    }

    async fn https_scenario(current: bool) {
        #[cfg(not(feature = "experimental-gc2"))]
        assert!(!current);
        use crate::{
            carrier::CarrierConfig, route::now_unix, Directory, RelayService, ServicePolicy,
        };
        use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
        use std::{
            net::SocketAddr,
            sync::atomic::{AtomicUsize, Ordering},
        };
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let cert = rcgen::generate_simple_self_signed(vec!["catalog.test".into()]).unwrap();
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
        .unwrap();
        server_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.9:0").await.unwrap();
        let origin = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let origin_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (tcp, _) = listener.accept().await.unwrap();
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let mut io = BufReader::new(tls);
                    let mut line = String::new();
                    io.read_line(&mut line).await.unwrap();
                    assert_eq!(line, "GET /v1/catalog?limit=1 HTTP/1.1\r\n");
                    loop {
                        line.clear();
                        io.read_line(&mut line).await.unwrap();
                        if line == "\r\n" {
                            break;
                        }
                    }
                    observed.fetch_add(1, Ordering::SeqCst);
                    io.get_mut()
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await
                        .unwrap();
                }
            }
        });
        let directory = Arc::new(Directory::new());
        let resolved = Arc::new(AtomicUsize::new(0));
        let mut servers = Vec::new();
        let mut services = Vec::new();
        for n in 2..4 {
            let identity = TlsIdentity::generate().unwrap();
            let server = Tp1Server::bind_with_identity(
                format!("127.0.0.{n}:0").parse().unwrap(),
                TokenRegistry::new(),
                Arc::new(|_, _| Ok(None)),
                Arc::new(|_| None),
                &identity,
            )
            .await
            .unwrap();
            let calls = resolved.clone();
            let service = RelayService::new(
                server.local_addr().unwrap(),
                identity.service_id(),
                [n; 32],
                Arc::new(Directory::new()),
                ServicePolicy {
                    carrier: CarrierConfig::fixture(),
                    catalog_origins: vec!["catalog.test".into(), "other.test".into()],
                    target_allowed: Arc::new(|a: SocketAddr| a.ip().is_loopback()),
                    fixture_catalog_resolver: Some(Arc::new(move |host| {
                        assert!(matches!(host, "catalog.test" | "other.test"));
                        calls.fetch_add(1, Ordering::SeqCst);
                        vec![origin]
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
            directory
                .install(service.introduction(now_unix()), now_unix())
                .unwrap();
            let server = server.with_duplex(service.handler());
            #[cfg(feature = "experimental-gc2")]
            let server = if current {
                server.with_dispatch_factory(service.gc2_handler_factory())
            } else {
                server
            };
            servers.push(tokio::spawn(async move {
                server
                    .run_until(std::future::pending::<()>())
                    .await
                    .unwrap();
            }));
            services.push(service);
        }
        let connector = OnionConnector::new(directory)
            .with_carrier_config(CarrierConfig::fixture())
            .unwrap();
        #[cfg(feature = "experimental-gc2")]
        let gc2_owner = if current {
            use crate::gc2::{directory, owner::EntryOwner, CandidateProfile};
            let directory = Arc::new(directory::Directory::for_loopback_fixture());
            directory
                .remember(
                    &directory::BootstrapBundle {
                        relays: services
                            .iter()
                            .map(|service| service.gc2_introduction(now_unix()))
                            .collect(),
                    },
                    now_unix(),
                )
                .unwrap();
            let (owner, ready) =
                EntryOwner::new(directory, CandidateProfile::file_transfer(), 1).unwrap();
            let task = tokio::spawn(owner.run());
            tokio::time::timeout(Duration::from_secs(10), async {
                while ready.ready_entries() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            Some((task, ready))
        } else {
            None
        };
        let connector = CatalogConnector::Legacy(&connector);
        #[cfg(feature = "experimental-gc2")]
        let connector = match &gc2_owner {
            Some((_, ready)) => CatalogConnector::Gc2(ready),
            None => connector,
        };
        let origins = vec!["catalog.test".into(), "other.test".into()];
        // The normal roots reject this private certificate through the same circuit.
        assert!(request_with_connector(
            connector,
            &origins,
            "GET",
            "https://catalog.test/v1/catalog?limit=1",
            &[]
        )
        .await
        .is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = Arc::new(tls);
        // Trusting the certificate must not bypass validation of the requested
        // hostname. Egress DNS resolves it, but no HTTP request may be sent.
        let mismatch = request_with_tls(
            connector,
            &origins,
            "GET",
            "https://other.test/v1/catalog?limit=1",
            &[],
            tls.clone(),
        )
        .await
        .err()
        .expect("trusted certificate has the wrong hostname");
        assert!(format!("{mismatch:?}").contains("NotValidForName"));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        let response = request_with_tls(
            connector,
            &origins,
            "GET",
            "https://catalog.test/v1/catalog?limit=1",
            &[],
            tls,
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(resolved.load(Ordering::SeqCst), 3);
        assert!(request_with_connector(
            connector,
            &[],
            "GET",
            "https://catalog.test/v1/catalog",
            &[]
        )
        .await
        .is_err());
        assert_eq!(
            resolved.load(Ordering::SeqCst),
            3,
            "unconfigured origin never reaches DNS"
        );
        // A client allowlist cannot override the egress relay's policy.
        assert!(request_with_connector(
            connector,
            &["denied.test".into()],
            "GET",
            "https://denied.test/v1/catalog",
            &[],
        )
        .await
        .is_err());
        assert_eq!(
            resolved.load(Ordering::SeqCst),
            3,
            "egress refuses before DNS"
        );
        origin_task.await.unwrap();
        // Requests must release both hops while the physical entry stays alive;
        // stopping its owner must not conceal leaked circuit permits.
        tokio::time::timeout(Duration::from_secs(10), async {
            while services.iter().any(|s| s.active_circuits() != 0) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        #[cfg(feature = "experimental-gc2")]
        if let Some((task, ready)) = gc2_owner {
            assert_eq!(ready.ready_entries(), 1);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(ready.ready_entries(), 0);
            assert!(request_gc2(
                &ready,
                &origins,
                "GET",
                "https://catalog.test/v1/catalog",
                &[]
            )
            .await
            .is_err());
            assert_eq!(
                resolved.load(Ordering::SeqCst),
                3,
                "stopped entries cannot fall back"
            );
        }
        for server in servers {
            server.abort();
            let _ = server.await;
        }
    }
}
