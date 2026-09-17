use rand::RngCore;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

mod network_runtime;

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl-C handler");
}

fn load_or_create_tls_identity(
    path: &std::path::Path,
) -> Result<gcoms_transport::tls::TlsIdentity, String> {
    let shown = path.display();
    if path.exists() {
        let encoded = std::fs::read(path).map_err(|e| format!("read TLS identity {shown}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("secure TLS identity {shown}: {e}"))?;
        }
        return gcoms_transport::tls::TlsIdentity::decode(&encoded)
            .map_err(|e| format!("decode TLS identity {shown}: {e}"));
    }
    let identity = gcoms_transport::tls::TlsIdentity::generate()
        .map_err(|e| format!("generate TLS identity: {e}"))?;
    let encoded = identity
        .encode()
        .map_err(|e| format!("encode TLS identity: {e}"))?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("TLS identity path {shown} must name a file"))?;
        let temp = parent.join(format!(
            ".{file_name}.{}.tmp",
            rand::thread_rng().next_u64()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| format!("create TLS identity temporary file: {e}"))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("write TLS identity: {e}"))?;
        match std::fs::hard_link(&temp, path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&temp);
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|e| format!("sync TLS identity directory: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&temp);
                return load_or_create_tls_identity(path);
            }
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                return Err(format!("install TLS identity {shown}: {e}"));
            }
        }
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("create TLS identity {shown}: {e}"))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("write TLS identity: {e}"))?;
    }
    Ok(identity)
}

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn has_flag(flag: &str) -> bool {
    std::env::args().any(|value| value == flag)
}

fn require(flag: &str) -> String {
    arg(flag).unwrap_or_else(|| {
        eprintln!("missing required flag {flag}");
        std::process::exit(2);
    })
}

/// Read a passphrase from `--pass-file`, or prompt on the terminal. A
/// passphrase is never accepted as a process argument: it would be visible
/// in `ps`, `/proc/<pid>/cmdline`, and shell history.
fn require_secret(file_flag: &str, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
    if arg("--pass").is_some() {
        return Err(
            "--pass is not accepted because it leaks through the process list; use --pass-file or answer the prompt"
                .into(),
        );
    }
    if let Some(path) = arg(file_flag) {
        let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
        let value = raw.trim_end_matches(['\r', '\n']).to_string();
        if value.is_empty() {
            return Err(format!("{path} is empty"));
        }
        return Ok(zeroize::Zeroizing::new(value));
    }
    let value = prompt_password(prompt)?;
    if value.is_empty() {
        return Err("empty passphrase".into());
    }
    Ok(value)
}

/// Prompt for a passphrase with terminal echo disabled.
fn prompt_password(prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::{BufRead, Write};
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    #[cfg(unix)]
    let restore = {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: termios is a plain C struct; tcgetattr/tcsetattr only read
        // and write it through the provided pointer.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::isatty(fd) } == 1 && unsafe { libc::tcgetattr(fd, &mut original) } == 0 {
            let mut silent = original;
            silent.c_lflag &= !libc::ECHO;
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &silent) };
            Some((fd, original))
        } else {
            None
        }
    };
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    #[cfg(unix)]
    if let Some((fd, original)) = restore {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
        let _ = writeln!(stderr);
    }
    read.map_err(|e| format!("read passphrase: {e}"))?;
    Ok(zeroize::Zeroizing::new(
        line.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

fn loopback_control_addr(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|e| format!("invalid --control {value}: {e}"))?;
    if !address.ip().is_loopback() {
        return Err("--control must be a loopback address for provision-relay".into());
    }
    Ok(address)
}

fn remote_control_config(
    control: SocketAddr,
) -> Result<Option<gcoms_node::control::RemoteControlConfig>, String> {
    let certificate = arg("--control-server-cert");
    let private_key = arg("--control-server-key");
    let client_ca = arg("--control-client-ca");
    if control.ip().is_loopback()
        && certificate.is_none()
        && private_key.is_none()
        && client_ca.is_none()
    {
        return Ok(None);
    }
    let certificate = certificate.ok_or("missing --control-server-cert for remote control")?;
    let private_key = private_key.ok_or("missing --control-server-key for remote control")?;
    let client_ca = client_ca.ok_or("missing --control-client-ca for remote control")?;
    let token = std::env::var("GC_CONTROL_TOKEN")
        .map_err(|_| "GC_CONTROL_TOKEN is required for remote control")?;
    gcoms_node::control::RemoteControlConfig::from_pem_files(
        Path::new(&certificate),
        Path::new(&private_key),
        Path::new(&client_ca),
        token,
    )
    .map(Some)
}

async fn request_relay_card(control: SocketAddr) -> Result<String, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut stream = tokio::net::TcpStream::connect(control)
        .await
        .map_err(|e| format!("connect to control plane: {e}"))?;
    stream
        .write_all(b"{\"id\":1,\"cmd\":\"provision_client_relay\"}\n")
        .await
        .map_err(|e| format!("write control request: {e}"))?;

    let mut lines = BufReader::new(stream).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| format!("read control response: {e}"))?
    {
        let response: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| "invalid control response".to_string())?;
        if response.get("id").and_then(serde_json::Value::as_u64) != Some(1) {
            continue;
        }
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            let error = response
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("control request failed");
            return Err(error.to_string());
        }
        let card = response
            .get("data")
            .and_then(|data| data.get("private_card_b64"))
            .and_then(serde_json::Value::as_str)
            .ok_or("control response is missing private_card_b64")?;
        gcoms_node::proto::private_info_from_b64(card)
            .ok_or("control response contains an invalid private relay card")?;
        return Ok(card.to_string());
    }
    Err("control plane closed without a response".into())
}

fn write_private_card(path: &Path, card: &str) -> std::io::Result<()> {
    if gcoms_node::proto::private_info_from_b64(card).is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid private relay card",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::other("output path must name a file"))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.tmp",
        rand::thread_rng().next_u64()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(card.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::hard_link(&temporary, path)?;
        std::fs::remove_file(&temporary)?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gcnode: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), String> {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if has_flag("--help") || has_flag("-h") || cmd.is_empty() {
        print_usage();
        return Ok(());
    }
    match cmd.as_str() {
        "keygen" => {
            let out = std::path::PathBuf::from(require("--out"));
            let pass = require_secret("--pass-file", "new keystore passphrase: ")?;
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            gcoms_node::keystore::write_identity(&out, &pass, seed)
                .map_err(|e| format!("write keystore {}: {e}", out.display()))?;
            println!("keystore written: {}", out.display());
        }
        "rekey" => {
            let keystore = std::path::PathBuf::from(require("--keystore"));
            let old_pass = require_secret("--old-pass-file", "current passphrase: ")?;
            let new_pass = if arg("--new-pass-file").is_some() {
                require_secret("--new-pass-file", "")?
            } else {
                prompt_password("new passphrase: ")?
            };
            gcoms_node::keystore::rekey_identity(&keystore, &old_pass, &new_pass)
                .map_err(|e| format!("rekey keystore {}: {e}", keystore.display()))?;
            println!("keystore rekeyed: {}", keystore.display());
        }
        "provision-relay" => {
            let control_value = require("--control");
            let control = loopback_control_addr(&control_value)?;
            let out = std::path::PathBuf::from(require("--out"));
            if out
                .try_exists()
                .map_err(|e| format!("inspect output {}: {e}", out.display()))?
            {
                return Err(format!("refusing to overwrite {}", out.display()));
            }
            let card = request_relay_card(control)
                .await
                .map_err(|e| format!("provision relay: {e}"))?;
            write_private_card(&out, &card)
                .map_err(|e| format!("write relay card {}: {e}", out.display()))?;
            println!("{}", out.display());
        }
        "serve" => {
            let keystore = std::path::PathBuf::from(require("--keystore"));
            let network_selection =
                network_runtime::Selection::parse(&std::env::args().collect::<Vec<_>>())?;
            let pass = require_secret("--pass-file", "keystore passphrase: ")?;
            // An explicit port is fixed. New full nodes select and retain an
            // available listener without requesting elevated privileges.
            let automatic_listener = has_flag("--auto-listen") || arg("--port").is_none();
            if has_flag("--auto-listen") && arg("--port").is_some() {
                return Err("--auto-listen and --port are mutually exclusive".into());
            }
            let port: u16 = match arg("--port") {
                Some(value) => value
                    .parse()
                    .map_err(|e| format!("invalid --port {value}: {e}"))?,
                None => 0,
            };
            let control_port: u16 = match arg("--control-port") {
                Some(value) => value
                    .parse()
                    .map_err(|e| format!("invalid --control-port {value}: {e}"))?,
                None => 9090,
            };
            let control_bind = arg("--control-bind").unwrap_or_else(|| "127.0.0.1".to_string());
            let control_addr: SocketAddr = format!("{control_bind}:{control_port}")
                .parse()
                .map_err(|e| {
                    format!("invalid control address {control_bind}:{control_port}: {e}")
                })?;
            let remote_control = remote_control_config(control_addr)
                .map_err(|e| format!("configure control listener: {e}"))?;
            let advertise = match arg("--advertise-addr") {
                Some(address) => Some(
                    address
                        .parse()
                        .map_err(|e| format!("invalid --advertise-addr {address}: {e}"))?,
                ),
                None => None,
            };
            let frwd_private_cidr = arg("--allow-frwd-private-cidr")
                .or_else(|| std::env::var("GC_FRWD_PRIVATE_CIDR").ok());
            let mut frwd_target_policy = gcoms_node::relay::FrwdTargetPolicy::new(false);
            if let Some(cidr) = frwd_private_cidr {
                frwd_target_policy = frwd_target_policy
                    .allow_private_cidr(&cidr, port)
                    .map_err(|e| format!("invalid private FRWD target policy: {e}"))?;
            }
            let inbox_relay = match arg("--inbox-relay-file") {
                Some(path) => {
                    let card = std::fs::read_to_string(&path)
                        .map_err(|e| format!("read inbox relay card {path}: {e}"))?;
                    Some(
                        gcoms_node::proto::private_info_from_b64(card.trim())
                            .ok_or_else(|| format!("invalid inbox relay card in {path}"))?,
                    )
                }
                None => None,
            };
            let tls_identity_path = arg("--tls-identity")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| keystore.with_extension("tls-identity"));
            let tls_identity = load_or_create_tls_identity(&tls_identity_path)?;
            // Argon2id (64 MiB, t=3) runs off the async runtime so it cannot
            // stall the executor while the node comes up.
            let keystore_for_load = keystore.clone();
            let loaded = tokio::task::spawn_blocking(move || {
                gcoms_node::keystore::load_identity_detailed(&keystore_for_load, &pass)
            })
            .await
            .map_err(|e| format!("keystore task failed: {e}"))?
            .map_err(|e| format!("unlock keystore {}: {e}", keystore.display()))?;
            if loaded.legacy_kdf {
                eprintln!(
                    "warning: {} uses the legacy GC1KS1 key derivation (a single HKDF round, brute-forceable). Run `gcnode rekey` to upgrade it.",
                    keystore.display()
                );
            }
            let seed = *loaded.seed;
            if let Some(m) = arg("--metrics") {
                gcoms_node::metrics::init(std::path::Path::new(&m))
                    .map_err(|e| format!("metrics init {m}: {e}"))?;
            }
            let profile = match arg("--schedule")
                .unwrap_or_else(|| "production".to_string())
                .as_str()
            {
                "production" => gcoms_node::node::NodeProfile::Production,
                // Production traffic behavior at a compressed cadence —
                // for LOCAL QUALIFICATION runs only (multi-second
                // multi-chunk transfers instead of tens of minutes).
                "compressed" => {
                    let mut lane_seed = [0u8; 8];
                    lane_seed.copy_from_slice(&seed[..8]);
                    gcoms_node::node::NodeProfile::compressed_production(u64::from_le_bytes(
                        lane_seed,
                    ))
                }
                other => {
                    return Err(format!(
                        "unknown --schedule {other:?} (expected production|compressed)"
                    ))
                }
            };
            let routing = if profile.is_production() {
                let mut routing = gcoms_node::node::RoutingConfig::from_environment()?;
                routing.routing_state = Some(std::sync::Arc::new(
                    gcoms_node::routing_cache::Cache::open(
                        &keystore.with_extension("routing"),
                        &seed,
                    )
                    .map_err(|e| format!("open private routing state: {e}"))?,
                ));
                if automatic_listener {
                    routing.connectivity = Some(gcoms_node::connectivity::ConnectivityConfig {
                        state: Some(std::sync::Arc::new(
                            gcoms_node::connectivity::PortState::open(
                                &keystore.with_extension("routing"),
                                &seed,
                            )?,
                        )),
                        mapping: !has_flag("--no-router-mapping"),
                        ..Default::default()
                    });
                }
                Some(routing)
            } else {
                None
            };
            let handle = gcoms_node::node::start_with_tls_policy_control_routing_and_bootstrap(
                gcoms_node::node::NodeConfig {
                    seed,
                    listen: format!("0.0.0.0:{port}").parse().unwrap(),
                    control: Some(control_addr),
                    advertise,
                    inbox_relay,
                    profile,
                    alias_lifecycle: Default::default(),
                },
                tls_identity,
                frwd_target_policy,
                remote_control,
                routing,
                arg("--bootstrap-directory").map(std::path::PathBuf::from),
            )
            .await
            .map_err(|e| format!("node start: {e}"))?;
            // The listener and control service are already running. Private
            // network state or HTTPS failures cannot prevent ordinary GC use.
            let network_worker = match network_selection.open(&keystore) {
                Ok(network) => Some(network_runtime::Worker::start(handle.clone(), network)),
                Err(_) => {
                    eprintln!("gcnode: network configuration unavailable; maintenance deferred");
                    None
                }
            };
            let info = handle.info.clone();
            println!(
                "node up: {}",
                info.primary()
                    .map(|alias| alias.target.address.to_string())
                    .unwrap_or_default()
            );
            if has_flag("--print-node-info") {
                println!("safety: {}", handle.safety_number);
                println!("nodeinfo: {}", gcoms_node::proto::b64_info(&info));
            }
            let signal = shutdown_signal();
            tokio::pin!(signal);
            loop {
                let ev = tokio::select! {
                    _ = &mut signal => break,
                    ev = handle.next_event() => ev,
                };
                let Some(ev) = ev else { break };
                match ev {
                    gcoms_node::node::Ev::IdentityUpdated { generation, .. } => {
                        println!("identity updated generation={generation}")
                    }
                    gcoms_node::node::Ev::SessionOpened { .. } => println!("session opened"),
                    gcoms_node::node::Ev::VolatileApplication { body, .. } => {
                        println!("volatile application bytes={}", body.len());
                    }
                    gcoms_node::node::Ev::Message {
                        text,
                        latency_hint_ms,
                        ..
                    } => {
                        println!("msg ms={} bytes={}", latency_hint_ms, text.len());
                    }
                    gcoms_node::node::Ev::DirectDelivery { .. } => {
                        println!("msg recipient-processed");
                    }
                    gcoms_node::node::Ev::PresenceChanged { reachability, .. } => {
                        println!("presence {reachability:?}");
                    }
                    gcoms_node::node::Ev::ChannelPresenceChanged { reachability, .. } => {
                        println!("channel presence {reachability:?}");
                    }
                    gcoms_node::node::Ev::ChannelDelivery { .. } => {
                        println!("chan recipients-processed");
                    }
                    gcoms_node::node::Ev::ChannelMessage {
                        text,
                        latency_hint_ms,
                        ..
                    } => {
                        println!("chan ms={} bytes={}", latency_hint_ms, text.len());
                    }
                    gcoms_node::node::Ev::ChannelRemoved { .. } => {
                        println!("chan removed-this-node")
                    }
                    gcoms_node::node::Ev::ChannelRosterChanged { .. } => {
                        println!("chan roster-changed")
                    }
                    gcoms_node::node::Ev::ChannelDirectMessage { text, .. } => {
                        println!("chan direct bytes={}", text.len())
                    }
                    gcoms_node::node::Ev::ChannelDirectDelivery { .. } => {
                        println!("chan direct recipient-processed")
                    }
                    gcoms_node::node::Ev::Lagged { skipped } => {
                        eprintln!("warning: {skipped} events were dropped (consumer too slow)")
                    }
                }
            }
            if let Some(worker) = network_worker {
                worker.shutdown().await;
            }
            handle.shutdown().await;
        }
        other => {
            print_usage();
            return Err(format!("unknown command {other:?}"));
        }
    }
    Ok(())
}

fn print_usage() {
    eprintln!("usage: gcnode <keygen|rekey|provision-relay|serve> [flags]");
    eprintln!("  keygen --out <file> [--pass-file <file>]");
    eprintln!("  rekey --keystore <file> [--old-pass-file <file>] [--new-pass-file <file>]");
    eprintln!("  provision-relay --control <loopback-address:port> --out <file>");
    eprintln!(
        "  serve --keystore <file> [--pass-file <file>] [--auto-listen | --port N] [--no-router-mapping] [--advertise-addr <ip:port>] [--tls-identity <file>] [--control-bind <address>] [--control-port 9090] [--control-server-cert <file> --control-server-key <file> --control-client-ca <file>] [--inbox-relay-file <file>] [--network-config <installed-network-json>] [--network-invitation-file <private-file>] [--dns-server-label r1..r8] [--dns-opt-in | --dns-opt-out] [--metrics <file>] [--print-node-info]"
    );
    eprintln!();
    eprintln!(
        "Passphrases are read from --pass-file or prompted; they are never accepted as arguments."
    );
    eprintln!("Automatic full nodes retain a free listener and try owned router mappings; --port keeps a fixed listener.");
    eprintln!("Network invitations stay in private files. DNS consent and server labels persist; ordinary bootstrap does not require DNS opt-in.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn tls_identity_is_stable_and_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "gc1-tls-{}-{}",
            std::process::id(),
            rand::thread_rng().next_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("identity.bin");
        let first = load_or_create_tls_identity(&path).unwrap();
        let second = load_or_create_tls_identity(&path).unwrap();
        assert_eq!(first.service_id(), second.service_id());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn provision_relay_rejects_non_loopback_control() {
        assert!(loopback_control_addr("127.0.0.1:9090").is_ok());
        assert!(loopback_control_addr("[::1]:9090").is_ok());
        assert!(loopback_control_addr("192.0.2.1:9090").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_card_write_is_owner_only_and_refuses_overwrite() {
        use gcoms_node::alias::RelayProvision;
        use gcoms_node::proto::{b64_private_info, NodeInfo};
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "gc1-relay-card-{}-{}",
            std::process::id(),
            rand::thread_rng().next_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("relay.card");
        let card = b64_private_info(&NodeInfo {
            identity_pk: vec![1],
            bundle: vec![2],
            aliases: vec![],
            provisioning: Some(RelayProvision {
                aliases: vec![],
                frwd_path: "one-use".into(),
                hop_key: [3; 32],
            }),
        })
        .unwrap();

        write_private_card(&path, &card).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{card}\n"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            write_private_card(&path, &card).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{card}\n"));
        std::fs::remove_dir_all(dir).ok();
    }
}
