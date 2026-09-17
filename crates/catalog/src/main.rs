use gcoms_catalog::{router, AppState, Config};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), String> {
    let config_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("GC_CATALOG_CONFIG").map(PathBuf::from))
        .ok_or("usage: gcoms-catalog <config.json> (or set GC_CATALOG_CONFIG)")?;
    let bytes = std::fs::read(&config_path)
        .map_err(|error| format!("read config {}: {error}", config_path.display()))?;
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse config {}: {error}", config_path.display()))?;
    let listen = config.listen;
    let state = AppState::load(config).await?;
    state.start_network_publisher();
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("bind {listen}: {error}"))?;
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|error| format!("catalog server failed: {error}"))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
