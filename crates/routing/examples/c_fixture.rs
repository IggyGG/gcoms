//! Disposable C/Rust interop fixture. Writes only private files to the supplied
//! test directory. No operator service or installed profile is involved.
use gcoms_routing::{
    bootstrap::BootstrapBundle, carrier::CarrierConfig, route::now_unix, wire::encode_address,
    Directory, RelayService, ServicePolicy,
};
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("test directory required")?,
    );
    let production_slots = std::env::args().nth(2).as_deref() == Some("production-slots");
    let directory = Arc::new(Directory::new());
    let mut services = Vec::new();
    let mut listeners = tokio::task::JoinSet::new();
    for n in 2..=4u8 {
        let identity = TlsIdentity::generate()?;
        let server = Tp1Server::bind_with_identity(
            format!("127.0.0.{n}:0").parse()?,
            TokenRegistry::new(),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await?;
        let service = RelayService::new(
            server.local_addr()?,
            identity.service_id(),
            [n; 32],
            directory.clone(),
            ServicePolicy {
                carrier: if production_slots {
                    CarrierConfig::default()
                } else {
                    CarrierConfig::fixture()
                },
                target_allowed: Arc::new(|a| a.ip().is_loopback()),
                ..ServicePolicy::default()
            },
        )?;
        directory.install(service.introduction(now_unix()), now_unix())?;
        let server = server.with_duplex(service.handler());
        listeners.spawn(async move { server.run().await });
        services.push(service);
    }
    let identity = TlsIdentity::generate()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(identity.server_config()?));
    let terminal = tokio::net::TcpListener::bind("127.0.0.99:0").await?;
    let mut target = encode_address(terminal.local_addr()?).to_vec();
    target.extend_from_slice(&identity.service_id());
    let mut endpoints = tokio::task::JoinSet::new();
    let bytes = BootstrapBundle {
        relays: services
            .iter()
            .map(|s| s.introduction(now_unix()))
            .collect(),
    }
    .encode()?;
    private_file(path.join("routing.bootstrap"), &bytes)?;
    private_file(path.join("target"), &target)?;
    private_file(path.join("ready"), b"ready\n")?;
    loop {
        tokio::select! {
            accepted = terminal.accept() => {
                let (io, _) = accepted?;
                let acceptor = acceptor.clone();
                endpoints.spawn(async move {
                    let Ok(mut tls) = acceptor.accept(io).await else { return; };
                    let mut buffer = [0; 1371];
                    while let Ok(mut left) = tls.read_u32().await {
                        if left > 16384 { break; }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        while left > 0 {
                            let n = usize::min(left as usize, buffer.len());
                            if tls.read_exact(&mut buffer[..n]).await.is_err() ||
                                tls.write_all(&buffer[..n]).await.is_err() { return; }
                            left -= n as u32;
                        }
                    }
                });
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if path.join("stop").exists() { break; }
            }
            _ = endpoints.join_next(), if !endpoints.is_empty() => {}
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while services.iter().any(|s| s.active_circuits() != 0) {
        if tokio::time::Instant::now() >= deadline {
            return Err("C circuit leaked relay permits".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    private_file(path.join("clean"), b"all circuit permits released\n")?;
    listeners.shutdown().await;
    endpoints.shutdown().await;
    Ok(())
}

fn private_file(path: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}
