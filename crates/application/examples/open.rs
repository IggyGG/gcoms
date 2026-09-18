//! cargo run -p gcoms --example open -- /private/app/profile [gcomsd service-endpoint]
use gcoms::{Application, Backend};
#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 && args.len() != 3 {
        return Err(
            "provide an absolute profile path, optionally bundled executable and endpoint".into(),
        );
    }
    let mut builder = Application::builder("example.application")
        .profile(std::path::PathBuf::from(&args[0]))
        .unlock_secret(
            std::env::var("GCOMS_UNLOCK_SECRET")
                .map_err(|_| "set GCOMS_UNLOCK_SECRET for this example")?,
        );
    if args.len() == 3 {
        builder = builder.backend(Backend::Shared {
            executable: (&args[1]).into(),
            endpoint: (&args[2]).into(),
        });
    }
    if let Ok(invitation) = std::env::var("GCOMS_INVITATION") {
        builder = builder.invitation(invitation);
    }
    let app = builder.open().await?;
    println!("{:?}", app.status().await.map_err(|e| e.to_string())?);
    app.close().await
}
