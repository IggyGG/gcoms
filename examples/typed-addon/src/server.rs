use gcoms_addon_example::{Greeting, GreetingService, GreetingServiceDispatcher};
use gcoms_rpc::{async_trait, Caller, Router, StoreLimits};
use std::{path::PathBuf, sync::Arc};

struct Service;
#[async_trait]
impl GreetingService for Service {
    async fn greet(&self, name: String) -> Result<Greeting, String> {
        if name.len() > 256 {
            return Err("name is too long".into());
        }
        Ok(Greeting {
            text: format!("Hello, {name}!"),
        })
    }
    async fn uppercase(&self, text: String) -> Result<Greeting, String> {
        if text.len() > 4096 {
            return Err("text is too long".into());
        }
        Ok(Greeting {
            text: text.to_uppercase(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: typed-addon-server SOCKET JOURNAL SECRET_FILE (32 private bytes)".into(),
        );
    }
    let socket = PathBuf::from(&args[0]);
    let journal = PathBuf::from(&args[1]);
    let secret = PathBuf::from(&args[2]);
    gcoms_private_fs::validate_private_file(&secret, "example wrapping secret")?;
    let key: [u8; 32] = std::fs::read(secret)?
        .try_into()
        .map_err(|_| "secret must contain exactly 32 bytes")?;
    let store = gcoms_rpc::file_store::FileStore::open(
        &journal,
        key,
        "example.greeting",
        StoreLimits::default(),
    )?;
    let mut router = Router::new("greeting-example", 8, gcoms_rpc::LOCAL_FRAME_LIMIT);
    router.register(
        Arc::new(GreetingServiceDispatcher(Service)),
        Arc::new(store),
        Arc::new(|caller: &Caller, _: &str, _: u16, _: &str| caller.principal == "local-owner"),
    )?;
    gcoms_rpc::local::serve(&socket, Arc::new(router), async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
