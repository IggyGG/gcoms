use crate::metrics;
use crate::node::{Cmd, Ev, NodeState};
use crate::proto::{b64_info, b64_private_info, info_from_b64};
use gcoms_transport::encode_b64url;
use rustls::pki_types::pem::PemObject;
use serde_json::{json, Value};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::TlsAcceptor;

const MIN_CONTROL_TOKEN_BYTES: usize = 32;
const MAX_CONTROL_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONTROL_CONNECTIONS: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone)]
pub struct RemoteControlConfig {
    tls: TlsAcceptor,
    bearer_token: Arc<str>,
}

impl RemoteControlConfig {
    pub fn from_pem_files(
        certificate: &Path,
        private_key: &Path,
        client_ca: &Path,
        bearer_token: String,
    ) -> Result<Self, String> {
        if bearer_token.len() < MIN_CONTROL_TOKEN_BYTES {
            return Err(format!(
                "GC_CONTROL_TOKEN must contain at least {MIN_CONTROL_TOKEN_BYTES} bytes"
            ));
        }
        let certificates = read_certificates(certificate, "control server certificate")?;
        let key_bytes = std::fs::read(private_key).map_err(|error| {
            format!(
                "read control server private key {}: {error}",
                private_key.display()
            )
        })?;
        let key = rustls::pki_types::PrivateKeyDer::pem_slice_iter(&key_bytes)
            .next()
            .transpose()
            .map_err(|error| {
                format!(
                    "parse control server private key {}: {error}",
                    private_key.display()
                )
            })?
            .ok_or_else(|| {
                format!(
                    "control server private key {} contains no private key",
                    private_key.display()
                )
            })?;
        let ca_certificates = read_certificates(client_ca, "control client CA bundle")?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in ca_certificates {
            roots.add(certificate).map_err(|error| {
                format!(
                    "invalid certificate in control client CA bundle {}: {error}",
                    client_ca.display()
                )
            })?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(|error| format!("invalid control client CA verifier: {error}"))?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| format!("build control TLS configuration: {error}"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .map_err(|error| {
                format!("invalid control server certificate or private key: {error}")
            })?;
        config.send_tls13_tickets = 0;
        Ok(Self {
            tls: TlsAcceptor::from(Arc::new(config)),
            bearer_token: Arc::from(bearer_token),
        })
    }
}

fn read_certificates(
    path: &Path,
    description: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("read {description} {}: {error}", path.display()))?;
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse {description} {}: {error}", path.display()))?;
    if certificates.is_empty() {
        return Err(format!(
            "{description} {} contains no certificates",
            path.display()
        ));
    }
    Ok(certificates)
}

pub struct ControlListener {
    listener: TcpListener,
    remote: Option<RemoteControlConfig>,
}

impl ControlListener {
    pub async fn bind(
        listen: SocketAddr,
        remote: Option<RemoteControlConfig>,
    ) -> std::io::Result<Self> {
        if !listen.ip().is_loopback() && remote.is_none() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "non-loopback control listener requires server certificate, private key, client CA, and bearer token",
            ));
        }
        let listener = TcpListener::bind(listen).await?;
        Ok(Self { listener, remote })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

pub async fn serve(
    state: Arc<Mutex<NodeState>>,
    cmd_tx: mpsc::Sender<Cmd>,
    events_tx: broadcast::Sender<Ev>,
    listener: ControlListener,
) -> std::io::Result<()> {
    let listen = listener.local_addr()?;
    let remote = listener.remote;
    metrics::log_event("control_listening", &[("port", listen.port().to_string())]);
    let mut connections = tokio::task::JoinSet::new();
    loop {
        if connections.len() >= MAX_CONTROL_CONNECTIONS {
            let _ = connections.join_next().await;
            continue;
        }
        let accepted = tokio::select! {
            accepted = listener.listener.accept() => accepted,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let (stream, peer) = match accepted {
            Ok(s) => s,
            Err(_) => continue,
        };
        metrics::log_event("control_accept", &[]);
        let state = state.clone();
        let cmd_tx = cmd_tx.clone();
        let events_tx = events_tx.clone();
        let remote = remote.clone();
        connections.spawn(async move {
            if let Some(remote) = remote {
                let handshake =
                    tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, remote.tls.accept(stream)).await;
                match handshake {
                    Ok(Ok(stream)) => {
                        handle_conn(
                            stream,
                            state,
                            cmd_tx,
                            events_tx,
                            Some(remote.bearer_token),
                            peer,
                        )
                        .await;
                    }
                    Ok(Err(_)) => metrics::log_event(
                        "control_conn_close",
                        &[("reason", "TLS authentication failed".into())],
                    ),
                    Err(_) => metrics::log_event(
                        "control_conn_close",
                        &[("reason", "TLS handshake timeout".into())],
                    ),
                }
            } else {
                handle_conn(stream, state, cmd_tx, events_tx, None, peer).await;
            }
        });
    }
}

async fn handle_conn<S>(
    stream: S,
    state: Arc<Mutex<NodeState>>,
    cmd_tx: mpsc::Sender<Cmd>,
    events_tx: broadcast::Sender<Ev>,
    expected_token: Option<Arc<str>>,
    _peer: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let write = std::sync::Arc::new(tokio::sync::Mutex::new(write_half));
    let mut authenticated = expected_token.is_none();
    let mut events_rx = authenticated.then(|| events_tx.subscribe());

    metrics::log_event("control_conn_open", &[]);
    loop {
        let cmd_result = tokio::select! {
            line = read_control_line(&mut reader) => line,
            ev = async {
                match &mut events_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            }, if authenticated => {
                match ev {
                    Ok(ev) => {
                        let payload = ev_to_json(&ev);
                        let mut w = write.lock().await;
                        let _ = w.write_all(format!("{payload}\n").as_bytes()).await;
                        continue;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        let line = match cmd_result {
            Ok(Some(line)) => line,
            Ok(None) => {
                metrics::log_event("control_conn_close", &[("reason", "eof".to_string())]);
                break;
            }
            Err(error) => {
                metrics::log_event("control_conn_close", &[("reason", error.to_string())]);
                break;
            }
        };
        let Ok(req) = parse_request(&line) else {
            let mut w = write.lock().await;
            let _ = w
                .write_all(b"{\"ok\":false,\"error\":\"bad json\"}\n")
                .await;
            continue;
        };
        let id = req.get("id").cloned().unwrap_or(json!(0));
        if !authenticated {
            if request_has_valid_token(expected_token.as_deref(), &req) {
                authenticated = true;
                events_rx = Some(events_tx.subscribe());
            } else {
                let out = json!({"id": id, "ok": false, "error": "unauthorized"});
                let mut w = write.lock().await;
                let _ = w.write_all(format!("{out}\n").as_bytes()).await;
                metrics::log_event(
                    "control_conn_close",
                    &[("reason", "unauthorized".to_string())],
                );
                break;
            }
        }
        let resp = dispatch(&state, &cmd_tx, &req).await;
        let mut out = json!({"id": id});
        match resp {
            Ok(data) => {
                out["ok"] = json!(true);
                out["data"] = data;
            }
            Err(e) => {
                out["ok"] = json!(false);
                out["error"] = json!(e);
            }
        }
        let mut w = write.lock().await;
        if w.write_all(format!("{out}\n").as_bytes()).await.is_err() {
            metrics::log_event(
                "control_conn_close",
                &[("reason", "write failed".to_string())],
            );
            break;
        }
    }
}

async fn read_control_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len() + newline > MAX_CONTROL_LINE_BYTES {
                return Err(Error::new(ErrorKind::InvalidData, "control line too large"));
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
        if line.len() + available.len() > MAX_CONTROL_LINE_BYTES {
            return Err(Error::new(ErrorKind::InvalidData, "control line too large"));
        }
        let consumed = available.len();
        line.extend_from_slice(available);
        reader.consume(consumed);
    }
}

fn request_has_valid_token(expected: Option<&str>, req: &Value) -> bool {
    let Some(expected) = expected.filter(|token| token.len() >= MIN_CONTROL_TOKEN_BYTES) else {
        return false;
    };
    let Some(supplied) = req.get("token").and_then(Value::as_str) else {
        return false;
    };
    constant_time_eq(expected.as_bytes(), supplied.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    // Length is public; content comparison is constant time.
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

pub fn parse_request(input: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice(input)
}

async fn dispatch(
    state: &Arc<Mutex<NodeState>>,
    cmd_tx: &mpsc::Sender<Cmd>,
    req: &Value,
) -> Result<Value, String> {
    let cmd = req
        .get("cmd")
        .and_then(Value::as_str)
        .ok_or("missing cmd")?;
    match cmd {
        "status" => {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            Ok(json!({
                "addr": st.info.primary().map(|alias| alias.target.address.to_string()),
                "sessions": st.sessions.len(),
                "channels": st.channels.len(),
                "safety_number": gcoms_crypto::safety_number_of(&st.info.identity_pk),
            }))
        }
        "create_channel" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let display = req
                .get("display")
                .and_then(Value::as_str)
                .ok_or("missing display")?
                .to_string();
            let capacity = req.get("capacity").and_then(Value::as_u64).unwrap_or(64) as usize;
            let visibility = match req.get("visibility").and_then(Value::as_str) {
                Some("public") => crate::channel::ChannelVisibility::Public,
                Some("private") | None => crate::channel::ChannelVisibility::Private,
                Some(_) => return Err("visibility must be public or private".into()),
            };
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::CreateChannel {
                    channel,
                    display,
                    capacity,
                    visibility,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            let id = done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!({"channel_id_b64": encode_b64url(&id.0)}))
        }
        "prepare_join" => {
            let display = req
                .get("display")
                .and_then(Value::as_str)
                .ok_or("missing display")?
                .to_string();
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::PrepareChannelJoin { display, done })
                .await
                .map_err(|e| e.to_string())?;
            let req_id = done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!({"req_id": req_id}))
        }
        "key_package" => {
            let req_id = req
                .get("req_id")
                .and_then(Value::as_u64)
                .ok_or("missing req_id")?;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::ChannelKeyPackage { req_id, done })
                .await
                .map_err(|e| e.to_string())?;
            let kp = done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!({"kp_b64": encode_b64url(&kp)}))
        }
        "admit" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let kp_b64 = req
                .get("kp_b64")
                .and_then(Value::as_str)
                .ok_or("missing kp_b64")?;
            let member_name = req
                .get("member_name")
                .and_then(Value::as_str)
                .ok_or("missing member_name")?
                .to_string();
            let kp = gcoms_transport::decode_b64url(kp_b64).ok_or("bad kp_b64")?;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::AdmitChannel {
                    channel,
                    key_package: kp,
                    member_name,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            let welcome = done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!({"welcome_b64": encode_b64url(&welcome)}))
        }
        "join" => {
            let req_id = req
                .get("req_id")
                .and_then(Value::as_u64)
                .ok_or("missing req_id")?;
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let visibility = match req.get("visibility").and_then(Value::as_str) {
                Some("public") => crate::channel::ChannelVisibility::Public,
                Some("private") | None => crate::channel::ChannelVisibility::Private,
                Some(_) => return Err("visibility must be public or private".into()),
            };
            let welcome_b64 = req
                .get("welcome_b64")
                .and_then(Value::as_str)
                .ok_or("missing welcome_b64")?;
            let welcome = gcoms_transport::decode_b64url(welcome_b64).ok_or("bad welcome_b64")?;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::JoinChannel {
                    req_id,
                    channel,
                    visibility,
                    welcome,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "send_channel" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let text_b64 = req
                .get("text_b64")
                .and_then(Value::as_str)
                .ok_or("missing text_b64")?;
            if text_b64.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT.saturating_mul(4) / 3 + 4 {
                return Err("application payload exceeds limit".into());
            }
            let text = gcoms_transport::decode_b64url(text_b64).ok_or("bad text_b64")?;
            if text.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT {
                return Err("application payload exceeds limit".into());
            }
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::SendChannelText {
                    channel,
                    text,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "set_channel_presence" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let mode = parse_presence_mode(req)?;
            let lease_secs = parse_presence_lease(req)?;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::SendChannelPresence {
                    channel,
                    mode,
                    lease_secs,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "set_channel_presence_opt_in" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let enabled = req
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or("missing enabled")?;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::SetChannelPresenceOptIn {
                    channel,
                    enabled,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "send_1to1" => {
            let info_b64 = req
                .get("peer_info_b64")
                .and_then(Value::as_str)
                .ok_or("missing peer_info_b64")?;
            let text_b64 = req
                .get("text_b64")
                .and_then(Value::as_str)
                .ok_or("missing text_b64")?;
            if text_b64.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT.saturating_mul(4) / 3 + 4 {
                return Err("application payload exceeds limit".into());
            }
            let peer = info_from_b64(info_b64).ok_or("bad peer_info_b64")?;
            let text = gcoms_transport::decode_b64url(text_b64).ok_or("bad text_b64")?;
            if text.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT {
                return Err("application payload exceeds limit".into());
            }
            let via = req
                .get("via_info_b64")
                .and_then(Value::as_str)
                .and_then(info_from_b64);
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::Send1to1 {
                    durable: false,
                    peer: Box::new(peer),
                    text,
                    via: Box::new(via),
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "set_direct_presence" => {
            let info_b64 = req
                .get("peer_info_b64")
                .and_then(Value::as_str)
                .ok_or("missing peer_info_b64")?;
            let peer = info_from_b64(info_b64).ok_or("bad peer_info_b64")?;
            let mode = parse_presence_mode(req)?;
            let lease_secs = parse_presence_lease(req)?;
            let via = req
                .get("via_info_b64")
                .and_then(Value::as_str)
                .and_then(info_from_b64);
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::SendDirectPresence {
                    peer: Box::new(peer),
                    mode,
                    lease_secs,
                    via: Box::new(via),
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "set_direct_presence_opt_in" => {
            let info_b64 = req
                .get("peer_info_b64")
                .and_then(Value::as_str)
                .ok_or("missing peer_info_b64")?;
            let peer = info_from_b64(info_b64).ok_or("bad peer_info_b64")?;
            let enabled = req
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or("missing enabled")?;
            let via = req
                .get("via_info_b64")
                .and_then(Value::as_str)
                .and_then(info_from_b64);
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::SetDirectPresenceOptIn {
                    peer: Box::new(peer),
                    enabled,
                    via: Box::new(via),
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "remove" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let member_id = parse_member_id(req)?;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::RemoveChannelMember {
                    channel,
                    member_id,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        #[cfg(feature = "chaos-debug")]
        "debug_replay_channel" => {
            let channel = req
                .get("channel")
                .and_then(Value::as_str)
                .ok_or("missing channel")?
                .to_string();
            let count = req.get("count").and_then(Value::as_u64).unwrap_or(1) as usize;
            let (done, done_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(Cmd::ReplayLastChannel {
                    channel,
                    count,
                    done,
                })
                .await
                .map_err(|e| e.to_string())?;
            done_rx.await.map_err(|e| e.to_string())??;
            Ok(json!(null))
        }
        "node_info" => {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            Ok(json!({"info_b64": b64_info(&st.info)}))
        }
        "routing_bootstrap" => {
            // This authenticated operator interface exports only independent
            // relay introductions, never a user's inbox ownership or identity.
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            let runtime = st.routing.as_ref().ok_or("routing is not enabled")?;
            let mut relays = runtime.discovery.directory.reentry_candidates();
            let service = runtime.service.lock().unwrap_or_else(|p| p.into_inner());
            let own = service
                .as_ref()
                .ok_or("relay service is not ready")?
                .introduction(gcoms_routing::route::now_unix());
            relays.retain(|r| r.service_id != own.service_id);
            relays.insert(0, own);
            relays.truncate(8);
            let bundle = gcoms_routing::bootstrap::BootstrapBundle { relays };
            Ok(
                json!({"routing_bundle_b64": encode_b64url(&bundle.encode().map_err(|e| e.to_string())?)}),
            )
        }
        "provision_client_relay" => provision_client_relay(cmd_tx).await,
        _ => Err(format!("unknown cmd {cmd}")),
    }
}

fn parse_member_id(req: &Value) -> Result<[u8; 32], String> {
    let encoded = req
        .get("member_id_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing member_id_b64".to_string())?;
    let decoded = gcoms_transport::decode_b64url(encoded).ok_or("bad member_id_b64")?;
    if decoded.len() != 32 || encode_b64url(&decoded) != encoded {
        return Err("member_id_b64 must be canonical base64url for exactly 32 bytes".into());
    }
    decoded
        .try_into()
        .map_err(|_| "member_id_b64 must decode to exactly 32 bytes".to_string())
}

fn parse_presence_mode(req: &Value) -> Result<crate::proto::PresenceMode, String> {
    match req.get("mode").and_then(Value::as_str) {
        Some("recently_reachable") => Ok(crate::proto::PresenceMode::RecentlyReachable),
        Some("away") => Ok(crate::proto::PresenceMode::Away),
        Some("invisible") => Ok(crate::proto::PresenceMode::Invisible),
        _ => Err("mode must be recently_reachable, away, or invisible".into()),
    }
}

fn parse_presence_lease(req: &Value) -> Result<u32, String> {
    req.get("lease_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing lease_seconds".to_string())?
        .try_into()
        .map_err(|_| "lease_seconds exceeds u32".to_string())
}

async fn provision_client_relay(cmd_tx: &mpsc::Sender<Cmd>) -> Result<Value, String> {
    let (done, done_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(Cmd::ProvisionClientRelay { done })
        .await
        .map_err(|e| e.to_string())?;
    let info = done_rx.await.map_err(|e| e.to_string())??;
    let private_card_b64 =
        b64_private_info(&info).ok_or("relay card has no private provisioning")?;
    Ok(json!({"private_card_b64": private_card_b64}))
}

fn ev_to_json(ev: &Ev) -> Value {
    match ev {
        Ev::IdentityUpdated { info, generation } => json!({
            "event": "identity_updated",
            "generation": generation,
            "node_info_b64": crate::proto::b64_info(info),
        }),
        Ev::SessionOpened {
            peer_pk,
            safety_number,
        } => json!({
            "event": "session_opened",
            "peer_b64": encode_b64url(peer_pk),
            "safety_number": safety_number,
        }),
        Ev::VolatileApplication {
            peer_pk,
            msg_id,
            ts_unix,
            body,
        } => json!({
            "event": "volatile_application", "peer_b64": encode_b64url(peer_pk),
            "message_id_b64": encode_b64url(msg_id), "ts_unix": ts_unix, "body_bytes": body.len(),
        }),
        Ev::Message {
            peer_pk,
            msg_id,
            text,
            latency_hint_ms,
            ts_unix,
        } => json!({
            "event": "message",
            "peer_b64": encode_b64url(peer_pk),
            "message_id_b64": encode_b64url(msg_id),
            "text_b64": encode_b64url(text),
            "latency_ms": latency_hint_ms,
            "ts_unix": ts_unix,
        }),
        Ev::DirectDelivery { peer_pk, msg_id } => json!({
            "event": "direct_delivery",
            "stage": "recipient_processed",
            "peer_b64": encode_b64url(peer_pk),
            "message_id_b64": encode_b64url(msg_id),
        }),
        Ev::PresenceChanged {
            peer_pk,
            reachability,
        } => json!({
            "event": "presence_changed",
            "peer_b64": encode_b64url(peer_pk),
            "reachability": match reachability {
                crate::node::Reachability::RecentlyReachable => "recently_reachable",
                crate::node::Reachability::Away => "away",
                crate::node::Reachability::Unknown => "unknown",
            },
        }),
        Ev::ChannelPresenceChanged {
            channel,
            member_id,
            reachability,
        } => json!({
            "event": "channel_presence_changed",
            "channel": channel,
            "member_id_b64": encode_b64url(member_id),
            "reachability": match reachability {
                crate::node::Reachability::RecentlyReachable => "recently_reachable",
                crate::node::Reachability::Away => "away",
                crate::node::Reachability::Unknown => "unknown",
            },
        }),
        Ev::ChannelMessage {
            channel,
            msg_id,
            sender,
            text,
            latency_hint_ms,
            ts_unix,
            ..
        } => json!({
            "event": "channel_message",
            "channel": channel,
            "message_id_b64": encode_b64url(msg_id),
            "sender": sender,
            "text_b64": encode_b64url(text),
            "latency_ms": latency_hint_ms,
            "ts_unix": ts_unix,
        }),
        Ev::ChannelDelivery { channel, msg_id } => json!({
            "event": "channel_delivery",
            "stage": "recipients_processed",
            "channel": channel,
            "message_id_b64": encode_b64url(msg_id),
        }),
        Ev::ChannelRemoved { channel } => json!({
            "event": "channel_removed",
            "channel": channel,
        }),
        Ev::ChannelRosterChanged {
            channel,
            channel_id,
        } => json!({
            "event": "channel_roster_changed",
            "channel": channel,
            "channel_id_b64": encode_b64url(&channel_id.0),
        }),
        Ev::ChannelDirectMessage {
            channel,
            sender_member_id,
            recipient_member_id,
            msg_id,
            ts_unix,
            text,
        } => json!({
            "event": "channel_direct_message",
            "channel": channel,
            "sender_member_id_b64": encode_b64url(sender_member_id),
            "recipient_member_id_b64": encode_b64url(recipient_member_id),
            "message_id_b64": encode_b64url(msg_id),
            "ts_unix": ts_unix,
            "text_b64": encode_b64url(text),
        }),
        Ev::ChannelDirectDelivery {
            channel,
            recipient_member_id,
            msg_id,
        } => json!({
            "event": "channel_direct_delivery",
            "stage": "recipient_processed",
            "channel": channel,
            "recipient_member_id_b64": encode_b64url(recipient_member_id),
            "message_id_b64": encode_b64url(msg_id),
        }),
        Ev::Lagged { skipped } => json!({
            "event": "events_lagged",
            "skipped": skipped,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_member_id, parse_request, provision_client_relay, read_control_line,
        request_has_valid_token, MAX_CONTROL_LINE_BYTES,
    };
    use crate::alias::RelayProvision;
    use crate::node::Cmd;
    use crate::proto::{private_info_from_b64, NodeInfo};
    use serde_json::json;
    use tokio::io::BufReader;

    #[test]
    fn parses_control_request() {
        assert_eq!(
            parse_request(br#"{"id":7,"cmd":"status"}"#).unwrap(),
            json!({"id": 7, "cmd": "status"})
        );
    }

    #[test]
    fn parses_provision_client_relay_request() {
        assert_eq!(
            parse_request(br#"{"id":8,"cmd":"provision_client_relay"}"#).unwrap(),
            json!({"id": 8, "cmd": "provision_client_relay"})
        );
    }

    #[test]
    fn remove_member_id_requires_canonical_base64url_and_exact_length() {
        let member_id = [0xff; 32];
        let encoded = gcoms_transport::encode_b64url(&member_id);
        assert_eq!(
            parse_member_id(&json!({"member_id_b64": encoded})).unwrap(),
            member_id
        );
        for invalid in [
            json!({}),
            json!({"member_name": "legacy"}),
            json!({"member_id_b64": "_w=="}),
            json!({"member_id_b64": "+///"}),
            json!({"member_id_b64": gcoms_transport::encode_b64url(&[0; 31])}),
            json!({"member_id_b64": gcoms_transport::encode_b64url(&[0; 33])}),
        ] {
            assert!(parse_member_id(&invalid).is_err(), "accepted {invalid}");
        }
    }

    #[tokio::test]
    async fn provision_client_relay_private_card_roundtrip() {
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let Some(Cmd::ProvisionClientRelay { done }) = cmd_rx.recv().await else {
                panic!("expected relay provisioning command");
            };
            done.send(Ok(NodeInfo {
                identity_pk: vec![1, 2, 3],
                bundle: vec![4, 5, 6],
                aliases: vec![],
                provisioning: Some(RelayProvision {
                    aliases: vec![],
                    frwd_path: "one-use".into(),
                    hop_key: [7; 32],
                }),
            }))
            .unwrap();
        });

        let response = provision_client_relay(&cmd_tx).await.unwrap();
        let card = response["private_card_b64"].as_str().unwrap();
        let decoded = private_info_from_b64(card).unwrap();
        assert_eq!(decoded.identity_pk, vec![1, 2, 3]);
        assert_eq!(decoded.provisioning.unwrap().frwd_path, "one-use");
    }

    #[test]
    fn rejects_malformed_and_adversarial_json() {
        for input in [
            b"{".as_slice(),
            b"{\"cmd\":\"status\"} trailing".as_slice(),
            b"{\"cmd\":\"\\uD800\"}".as_slice(),
            b"{\"id\":1e10000,\"cmd\":\"status\"}".as_slice(),
            b"\xff\xfe\xfd".as_slice(),
        ] {
            assert!(parse_request(input).is_err(), "accepted {input:?}");
        }

        let nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(parse_request(nested.as_bytes()).is_err());
    }

    #[test]
    fn remote_authentication_accepts_only_the_expected_strong_token() {
        let token = "a-strong-control-token-that-is-32-bytes-or-more";
        assert!(request_has_valid_token(
            Some(token),
            &json!({"token": token})
        ));
        assert!(!request_has_valid_token(
            Some(token),
            &json!({"token": "a-strong-control-token-that-is-32-bytes-or-lesX"})
        ));
        assert!(!request_has_valid_token(Some(token), &json!({})));
        assert!(!request_has_valid_token(
            Some("weak"),
            &json!({"token": "weak"})
        ));
        assert!(!request_has_valid_token(None, &json!({"token": token})));
    }

    #[tokio::test]
    async fn rejects_oversized_control_lines() {
        let input = vec![b'x'; MAX_CONTROL_LINE_BYTES + 1];
        let mut reader = BufReader::new(input.as_slice());
        let error = read_control_line(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
