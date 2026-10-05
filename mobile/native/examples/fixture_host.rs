//! Disposable loopback relay for outbound emulator/simulator qualification only.
use base64::Engine;
use gcoms::{sdk, Application};
use std::io::{BufRead, Write};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    gcoms_private_fs::make_private(directory.path(), true).map_err(|e| e.to_string())?;
    let app = Application::builder("mobile-fixture-host")
        .profile(directory.path().join("profile"))
        .unlock_secret("disposable-mobile-fixture")
        .local_fixture()
        .open()
        .await?;
    let client = app
        .embedded_runtime()
        .ok_or("embedded runtime")?
        .sdk_client()
        .embedded();
    let (send, mut receive) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if send.blocking_send(line).is_err() {
                break;
            }
        }
    });
    loop {
        let card = client.node().provision_client_relay().await?;
        let card = sdk::RelayCard(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(card.encode_private().ok_or("fixture card")?)
                .into_bytes(),
        );
        println!(
            "{}",
            serde_json::json!({"relay": card, "port": client.node().listener_addr().port()})
        );
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        if receive.recv().await.as_deref() != Some("provision") {
            break;
        }
    }
    app.close().await
}
