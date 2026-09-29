//! A member-scoped bot: only !ping text receives a rate-limited notice response.
//! No automatic reply to notices, actions, receipts, files or control events.
use gcoms::{sdk::hosted_client as chat, Application, Backend};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: hosted_bot PRIVATE_PROFILE INSTALLED_NETWORK_JSON".into());
    }
    let app = Application::builder("example.hosted-bot")
        .backend(Backend::NetworkClient)
        .profile(PathBuf::from(&args[0]))
        .unlock_secret(std::env::var("GCOMS_UNLOCK_SECRET").map_err(|_| "set GCOMS_UNLOCK_SECRET")?)
        .network_config(std::fs::read(&args[1]).map_err(|e| e.to_string())?)
        .carrier_profile(gcoms::sdk::CarrierProfile::Gc2)
        .receive_messages(false)
        .open()
        .await?;
    let sdk = app.messaging();
    let channel = match sdk
        .hosted_channels(chat::Request::List)
        .await
        .map_err(|e| e.to_string())?
    {
        chat::Reply::Channels(channels) => {
            match channels.into_iter().find(|c| c.alias == "bot-channel") {
                Some(channel) => channel.id,
                None => {
                    let link = chat::InviteLink(
                        std::env::var("GCOMS_HOSTED_INVITATION")
                            .map_err(|_| "set GCOMS_HOSTED_INVITATION for the first join")?,
                    );
                    let chat::Reply::Channel(channel) = sdk
                        .hosted_channels(chat::Request::Join {
                            link,
                            alias: "bot-channel".into(),
                            nickname: "ping-bot".into(),
                        })
                        .await
                        .map_err(|e| e.to_string())?
                    else {
                        return Err("invalid join response".into());
                    };
                    channel.id
                }
            }
        }
        _ => return Err("invalid channel listing".into()),
    };
    let mut next_reply = Instant::now();
    let result = async {
        loop {
            tokio::select! {
                result = tokio::signal::ctrl_c() => { result.map_err(|e| e.to_string())?; break; }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            if sdk
                .hosted_channels(chat::Request::Sync { channel })
                .await
                .is_err()
            {
                // Preserve pending operations through network outages.
                continue;
            }
            let chat::Reply::Events(events) = sdk
                .hosted_channels(chat::Request::Events {
                    channel,
                    after: 0,
                    limit: 32,
                })
                .await
                .map_err(|e| e.to_string())?
            else {
                return Err("invalid event reply".into());
            };
            for event in events {
                if let chat::EventKind::Message {
                    content: chat::Content::Text(text),
                    ..
                } = &event.kind
                {
                    if text == "!ping" && Instant::now() >= next_reply {
                        sdk.hosted_channels(chat::Request::Send {
                            channel,
                            content: chat::Content::Notice("pong".into()),
                        })
                        .await
                        .map_err(|e| e.to_string())?;
                        next_reply = Instant::now() + Duration::from_secs(2);
                    }
                }
                // The response is now durably queued in the encrypted runtime;
                // this bot has no separate transcript or other external effects.
                sdk.hosted_channels(chat::Request::CommitEvents {
                    channel,
                    through: event.sequence,
                })
                .await
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
    .await;
    let closed = app.close().await;
    result.and(closed)
}
