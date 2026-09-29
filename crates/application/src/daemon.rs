//! A per-user host with an independently owned runtime for every application profile.
use crate::control::{self, Attachment, ProfileConfig, Reply, Request};
use gcoms_runtime::ProtocolRuntime;
use gcoms_sdk::{GcClient, LocalEndpoint};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{watch, Mutex};

struct Hosted {
    config: ProfileConfig,
    token: [u8; 32],
    runtime: ProtocolRuntime,
    attachment: Attachment,
    stop: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), gcoms_sdk::SdkError>>,
}
impl Hosted {
    async fn shutdown(self) -> Result<(), String> {
        let _ = self.stop.send(true);
        let _ = self.server.await;
        let result = self.runtime.shutdown().await;
        let _ = LocalEndpoint::new(&self.attachment.endpoint).cleanup();
        result
    }
}
type Profiles = Arc<Mutex<BTreeMap<PathBuf, Hosted>>>;
/// Hold an exclusive service lock until all profiles and connections have stopped.
pub async fn serve(
    endpoint: &Path,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    use fs2::FileExt;
    let parent = endpoint.parent().ok_or("daemon endpoint needs a parent")?;
    control::private_directory(parent)?;
    let lock_path = endpoint.with_extension("daemon-lock");
    let lock = control::private_lock(&lock_path)?;
    lock.try_lock_exclusive()
        .map_err(|_| "GComs service is already running")?;
    let local = LocalEndpoint::new(endpoint);
    local.prepare_server().map_err(|e| e.to_string())?;
    let mut listener = gcoms_sdk::local::LocalListener::bind(&local).map_err(|e| e.to_string())?;
    let profiles: Profiles = Arc::new(Mutex::new(BTreeMap::new()));
    let mut connections = tokio::task::JoinSet::new();
    let slots = Arc::new(tokio::sync::Semaphore::new(32));
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(mut stream) => {
                    let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                    let profiles = profiles.clone();
                    let service_directory = parent.to_owned();
                    connections.spawn(async move {
                        let _slot = slot;
                        let request = tokio::time::timeout(std::time::Duration::from_secs(10), control::read_request(&mut stream)).await;
                        let result = match request {
                            Ok(Ok(request)) => handle(&profiles, &request, &service_directory).await,
                            _ => Err("invalid or incomplete control request".into()),
                        };
                        let _ = control::write_reply(&mut stream, &Reply { version: control::VERSION, result }).await;
                    });
                }
                Err(e) => break Err(e.to_string()),
            },
            _ = connections.join_next(), if !connections.is_empty() => {},
        }
    };
    drop(listener);
    // Finish admitted opens before shutdown, so their runtimes cannot escape cleanup.
    while connections.join_next().await.is_some() {}
    let hosted = std::mem::take(&mut *profiles.lock().await);
    let mut stopped = Ok(());
    for (_, profile) in hosted {
        if let Err(e) = profile.shutdown().await {
            stopped = Err(e);
        }
    }
    let cleaned = local.cleanup().map_err(|e| e.to_string());
    result.and(stopped).and(cleaned)
}
async fn handle(
    profiles: &Profiles,
    request: &Request,
    service_directory: &Path,
) -> Result<Option<Attachment>, String> {
    match request {
        Request::Ping => Ok(None),
        Request::ConfigureFileCache {
            profile,
            token,
            path,
            key,
            config,
        } => {
            let profiles = profiles.lock().await;
            let host = profiles.get(profile).ok_or("profile is not open")?;
            if !control::credentials_equal(token, &host.token) {
                return Err("profile credential rejected".into());
            }
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(
                    "cache requires an absolute host-local path without parent traversal".into(),
                );
            }
            #[cfg(feature = "files")]
            {
                host.runtime
                    .configure_file_cache(path, *key, config.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(None)
            }
            #[cfg(not(feature = "files"))]
            {
                let _ = (key, config);
                Err("host was built without file sharing".into())
            }
        }
        Request::Open {
            config,
            token,
            secret,
            create,
        } => {
            crate::application::validate_application(&config.application)?;
            if !config.profile.is_absolute()
                || config
                    .profile
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || config
                    .network
                    .as_ref()
                    .is_some_and(|n| n.len() > 512 * 1024)
                || config.providers.len() > 16
                || secret.is_empty()
                || secret.len() > 4096
            {
                return Err("invalid profile or unlock secret".into());
            }
            let expected = control::registration(&config.profile, &config.application)?;
            if !control::credentials_equal(token, &expected) {
                return Err("profile credential rejected".into());
            }
            let mut profiles = profiles.lock().await;
            if let Some(existing) = profiles.get(&config.profile) {
                if !control::credentials_equal(token, &existing.token)
                    || &existing.config != config
                    || *create
                {
                    return Err("profile is already open with different configuration".into());
                }
                existing.runtime.verify_secret(secret)?;
                return Ok(Some(existing.attachment.clone()));
            }
            if profiles.len() >= 64 {
                return Err("GComs profile limit reached".into());
            }
            let installed = config
                .network
                .as_ref()
                .map(|bytes| gcoms_runtime::network::from_json(bytes))
                .transpose()?;
            let runtime = ProtocolRuntime::open_options(
                &config.profile,
                secret,
                *create,
                gcoms_runtime::RuntimeOptions {
                    durable_channel_inbox: false,
                    listen: config.listen,
                    advertise: config.advertise,
                    relay: config.relay.clone().map(gcoms_sdk::RelayCard),
                    fixture: config.fixture,
                    carrier: config.carrier,
                    network: installed,
                },
            )
            .await?;
            let ready = async {
                runtime.personal_profile().await?;
                runtime.enable_durable_applications().await?;
                runtime
                    .start_network_maintenance(config.providers.clone(), config.network_recovery)?;
                Ok::<_, String>(())
            }
            .await;
            if let Err(e) = ready {
                let _ = runtime.shutdown().await;
                return Err(e);
            }
            let endpoint = service_directory.join(format!(
                "p-{}.sock",
                &crate::application::digest_name(config.profile.as_os_str().as_encoded_bytes())
                    [..24]
            ));
            let local = LocalEndpoint::new(&endpoint);
            if let Err(e) = local.prepare_server() {
                let _ = runtime.shutdown().await;
                return Err(e.to_string());
            }
            let listener = match gcoms_sdk::local::LocalListener::bind(&local) {
                Ok(listener) => listener,
                Err(e) => {
                    let _ = runtime.shutdown().await;
                    return Err(e.to_string());
                }
            };
            let attachment = Attachment {
                endpoint: endpoint.clone(),
                safety_number: runtime.sdk_client().identity().safety_number,
            };
            let (stop, mut stopped) = watch::channel(false);
            let sdk = runtime.sdk_client();
            let token = *token;
            let server = tokio::spawn(async move {
                gcoms_sdk::ipc::serve_profile_listener_until(
                    listener,
                    sdk,
                    control::capabilities(),
                    token,
                    async move {
                        let _ = stopped.changed().await;
                    },
                )
                .await
            });
            profiles.insert(
                config.profile.clone(),
                Hosted {
                    config: config.clone(),
                    token,
                    runtime,
                    attachment: attachment.clone(),
                    stop,
                    server,
                },
            );
            Ok(Some(attachment))
        }
        Request::Stop { profile, token } => {
            let mut profiles = profiles.lock().await;
            if let Some(hosted) = profiles.get(profile) {
                if !control::credentials_equal(token, &hosted.token) {
                    return Err("profile credential rejected".into());
                }
            }
            if let Some(hosted) = profiles.remove(profile) {
                hosted.shutdown().await?;
            }
            Ok(None)
        }
    }
}
