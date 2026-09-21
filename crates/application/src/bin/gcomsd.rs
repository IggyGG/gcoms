#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--endpoint" {
        eprintln!("usage: gcomsd --endpoint /private/directory/service.sock");
        std::process::exit(2);
    }
    if let Err(error) = gcoms::daemon::serve(std::path::Path::new(&args[1]), async {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install termination signal");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    {
        eprintln!("gcomsd: {error}");
        std::process::exit(1);
    }
}
