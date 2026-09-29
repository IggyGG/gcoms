use gcoms_channel_service::api::{Config, Service};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: gcoms-channel-service <config.json>")?;
    let bytes = std::fs::read(path)?;
    if bytes.len() > 64 * 1024 {
        return Err("configuration exceeds bound".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    let listen = config.listen;
    let service = Service::open(config)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(
        listener,
        service
            .router()
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
