//! Minimal host application with messaging, channels and bounded file streaming.
use gcoms::{
    sdk::{self, sharing::Scope},
    Application,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        println!("gcoms-integration PROFILE COMMAND [ARGS]\nCommands: identity, status, channels, create-channel NAME, send CHANNEL TEXT, invite CHANNEL, join LINK, files, share CHANNEL PATH, save ID PATH, accept|pause|resume|cancel ID, run SECONDS\nGCOMS_SECRET supplies the profile password. IPC requires GCOMS_ENDPOINT; both modes use GC/2 unless GCOMS_FIXTURE=1 for local tests.");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
        .map_err(Into::into)
}
async fn run(args: Vec<String>) -> Result<(), String> {
    let secret = std::env::var("GCOMS_SECRET").map_err(|_| "set GCOMS_SECRET")?;
    let builder = Application::builder("integration-example")
        .profile(std::path::absolute(&args[0]).map_err(err)?)
        .unlock_secret(secret)
        .receive_messages(false);
    let builder = match std::env::var("GCOMS_NETWORK") {
        Ok(path) => builder.network_config(std::fs::read(path).map_err(err)?),
        Err(_) => builder,
    };
    let builder = match std::env::var("GCOMS_RELAY") {
        Ok(path) => builder.relay(Some(sdk::RelayCard(std::fs::read(path).map_err(err)?))),
        Err(_) => builder,
    };
    let builder = match std::env::var("GCOMS_INVITATION") {
        Ok(invitation) => builder.invitation(invitation),
        Err(_) => builder,
    };
    let builder = if std::env::var("GCOMS_FIXTURE").as_deref() == Ok("1") {
        builder.local_fixture()
    } else {
        builder.carrier_profile(sdk::CarrierProfile::Gc2)
    };
    #[cfg(all(
        feature = "ipc",
        not(any(feature = "embedded", feature = "network-client"))
    ))]
    let builder = builder.backend(gcoms::Backend::Attach {
        endpoint: std::env::var("GCOMS_ENDPOINT")
            .map_err(|_| "set GCOMS_ENDPOINT")?
            .into(),
    });
    let application = builder.open().await?;
    let result = command(&application, &args[1..]).await;
    let closed = application.close().await;
    result.and(closed)
}
async fn command(app: &Application, args: &[String]) -> Result<(), String> {
    let messaging = app.messaging();
    let arg = |n: usize| {
        args.get(n)
            .map(String::as_str)
            .ok_or_else(|| "missing command argument".to_owned())
    };
    match args[0].as_str() {
        "run" => {
            app.files().list().await.map_err(err)?;
            tokio::time::sleep(std::time::Duration::from_secs(
                arg(1)?.parse().map_err(err)?,
            ))
            .await;
        }
        "identity" => println!("{}", app.identity().safety_number),
        "status" => println!("{:?}", app.status().await.map_err(err)?),
        "channels" => {
            for channel in messaging.list_channels().await.map_err(err)? {
                println!("{}", channel.channel);
            }
        }
        "create-channel" => {
            messaging
                .create_channel(arg(1)?, "member", 32, sdk::ChannelVisibility::Private)
                .await
                .map_err(err)?;
        }
        "send" => {
            messaging
                .send_channel(arg(1)?, arg(2)?.as_bytes())
                .await
                .map_err(err)?;
        }
        "invite" => println!(
            "{}",
            messaging
                .create_channel_invitation(arg(1)?, 3600)
                .await
                .map_err(err)?
                .link
        ),
        "join" => println!(
            "{}",
            messaging
                .join_channel_invitation(arg(1)?, "member", 60)
                .await
                .map_err(err)?
        ),
        "files" => {
            for file in app.files().list().await.map_err(err)?.files {
                println!(
                    "{} {} {} {} {:?}",
                    hex(&file.id),
                    file.name,
                    file.verified_bytes,
                    file.size_bytes,
                    file.status
                );
            }
        }
        "share" => {
            let name = arg(1)?;
            let channel = messaging
                .list_channels()
                .await
                .map_err(err)?
                .into_iter()
                .find(|c| c.channel == name)
                .ok_or("unknown channel")?;
            println!(
                "{}",
                hex(&app
                    .files()
                    .send_path(
                        Scope {
                            channel: channel.id.0,
                            participants: vec![]
                        },
                        Path::new(arg(2)?)
                    )
                    .await
                    .map_err(err)?)
            );
        }
        "save" => app
            .files()
            .save_path(id(arg(1)?)?, Path::new(arg(2)?))
            .await
            .map_err(err)?,
        "accept" => app.files().accept(id(arg(1)?)?).await.map_err(err)?,
        "pause" => app.files().pause(id(arg(1)?)?).await.map_err(err)?,
        "resume" => app.files().resume(id(arg(1)?)?).await.map_err(err)?,
        "cancel" => app.files().cancel(id(arg(1)?)?).await.map_err(err)?,
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid file id".into());
    }
    let mut id = [0; 16];
    for (n, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[n * 2..n * 2 + 2], 16).map_err(err)?;
    }
    Ok(id)
}
