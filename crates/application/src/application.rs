#[cfg(feature = "rpc")]
use crate::rpc::{
    self,
    gc::{DirectLink, GcEndpoint},
};
use crate::{control, sdk};
use sdk::Peer;
use sdk::{GcClient, SdkError};
#[cfg(feature = "ipc")]
use std::path::Path;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// The shared executable is supplied by the application bundle, never downloaded.
#[derive(Clone, Debug)]
pub enum Backend {
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    Embedded,
    /// Outbound protocol client; inboxes are hosted by remote relays.
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    NetworkClient,
    #[cfg(feature = "launch")]
    Shared {
        executable: PathBuf,
        endpoint: PathBuf,
    },
    #[cfg(feature = "ipc")]
    Attach { endpoint: PathBuf },
}
pub struct ApplicationBuilder {
    application: String,
    profile: Option<PathBuf>,
    secret: Zeroizing<String>,
    backend: Backend,
    create: Option<bool>,
    listen: std::net::SocketAddr,
    fixture: bool,
    carrier: sdk::CarrierProfile,
    advertise: Option<std::net::SocketAddr>,
    relay: Option<sdk::RelayCard>,
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    storage: Option<(
        Arc<dyn gcoms_runtime::store::ProfileStorage>,
        gcoms_runtime::store::ProtocolData,
    )>,
    network: Option<Vec<u8>>,
    network_recovery: bool,
    providers: Vec<String>,
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    central: Option<(sdk::component::RoutingPolicy, Vec<[u8; 16]>, String)>,
    invitation: Option<Zeroizing<String>>,
    receive: bool,
    peers: Vec<Peer>,
    #[cfg(feature = "rpc")]
    contracts: Vec<(String, u16)>,
    #[cfg(feature = "rpc")]
    services: Vec<(Arc<dyn rpc::Dispatch>, Arc<dyn rpc::Authorize>)>,
}
impl ApplicationBuilder {
    /// Explicit local host ownership of component routes under this identity.
    /// Only in-process backends support a separately authenticated component IPC.
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    pub fn central_components(
        mut self,
        policy: sdk::component::RoutingPolicy,
        primary: Vec<[u8; 16]>,
        safety_number: String,
    ) -> Self {
        self.central = Some((policy, primary, safety_number));
        self
    }
    pub fn carrier_profile(mut self, carrier: sdk::CarrierProfile) -> Self {
        self.carrier = carrier;
        self
    }
    pub fn advertise(mut self, value: Option<std::net::SocketAddr>) -> Self {
        self.advertise = value;
        self
    }
    pub fn relay(mut self, value: Option<sdk::RelayCard>) -> Self {
        self.relay = value;
        self
    }
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    pub fn legacy_storage(
        mut self,
        storage: Arc<dyn gcoms_runtime::store::ProfileStorage>,
        data: gcoms_runtime::store::ProtocolData,
    ) -> Self {
        self.storage = Some((storage, data));
        self
    }

    pub fn profile(mut self, path: impl Into<PathBuf>) -> Self {
        self.profile = Some(path.into());
        self
    }
    pub fn unlock_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Zeroizing::new(secret.into());
        self
    }
    pub fn backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }
    /// Require creation or opening explicitly. Absent selects create only on NotFound.
    pub fn create(mut self, create: bool) -> Self {
        self.create = Some(create);
        self
    }
    pub fn listen(mut self, listen: std::net::SocketAddr) -> Self {
        self.listen = listen;
        self
    }
    pub fn network_config(mut self, installed_json: Vec<u8>) -> Self {
        self.network = Some(installed_json);
        self
    }
    pub fn network_providers(mut self, urls: Vec<String>) -> Self {
        self.providers = urls;
        self
    }
    pub fn network_recovery(mut self, enabled: bool) -> Self {
        self.network_recovery = enabled;
        self
    }
    pub fn invitation(mut self, invitation: impl Into<String>) -> Self {
        self.invitation = Some(Zeroizing::new(invitation.into()));
        self
    }
    /// Read-only/event-only attachments do not claim the durable application inbox.
    pub fn receive_messages(mut self, enabled: bool) -> Self {
        self.receive = enabled;
        self
    }
    /// Disposable local qualification only. Production never infers this from a bind address.
    #[doc(hidden)]
    pub fn local_fixture(mut self) -> Self {
        self.fixture = true;
        self.listen = "127.0.0.1:0".parse().unwrap();
        self
    }
    pub fn peer(mut self, peer: Peer) -> Self {
        self.peers.push(peer);
        self
    }
    #[cfg(feature = "rpc")]
    pub fn rpc_contract(mut self, contract: rpc::Service) -> Self {
        self.contracts.push((contract.name, contract.version));
        self
    }
    /// Register a handler with explicit authorization and an encrypted operation journal.
    #[cfg(feature = "rpc")]
    pub fn service(
        mut self,
        dispatcher: Arc<dyn rpc::Dispatch>,
        authorize: Arc<dyn rpc::Authorize>,
    ) -> Self {
        let contract = dispatcher.descriptor();
        self.contracts.push((contract.name, contract.version));
        self.services.push((dispatcher, authorize));
        self
    }
    /// Open the profile without embedding the large startup state in the
    /// caller's future. This also leaves stack space for post-quantum key setup.
    pub fn open(self) -> impl std::future::Future<Output = Result<Application, String>> + Send {
        Box::pin(self.open_inner())
    }

    async fn open_inner(self) -> Result<Application, String> {
        validate_application(&self.application)?;
        #[cfg(any(feature = "embedded", feature = "network-client"))]
        if self.central.is_some()
            && !matches!(self.backend, Backend::Embedded | Backend::NetworkClient)
        {
            return Err("component hosts require an in-process backend".into());
        }
        if self.secret.is_empty() || self.secret.len() > 4096 {
            return Err("supply an unlock secret of 1–4096 bytes".into());
        }
        let profile = self
            .profile
            .clone()
            .ok_or("supply a private profile path")?;
        if !profile.is_absolute()
            || profile
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("profile must be an absolute path without parent traversal".into());
        }
        if self.network.as_ref().is_some_and(|n| n.len() > 512 * 1024) {
            return Err("network configuration exceeds limit".into());
        }
        let exists = match std::fs::symlink_metadata(&profile) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.to_string()),
        };
        let create = self.create.unwrap_or(!exists);
        if create == exists {
            return Err("profile creation state changed; open existing profiles explicitly".into());
        }
        #[cfg(any(feature = "embedded", feature = "network-client"))]
        if self.storage.is_some()
            && !matches!(self.backend, Backend::Embedded | Backend::NetworkClient)
        {
            return Err("legacy storage adapters require an embedded runtime".into());
        }
        let token = control::registration(&profile, &self.application)?;
        #[cfg(not(any(feature = "ipc", feature = "rpc")))]
        let _ = token;
        #[cfg(feature = "ipc")]
        let config = control::ProfileConfig {
            application: self.application.clone(),
            profile: profile.clone(),
            listen: self.listen,
            fixture: self.fixture,
            carrier: self.carrier,
            advertise: self.advertise,
            relay: self.relay.as_ref().map(|r| r.0.clone()),
            network: self.network.clone(),
            network_recovery: self.network_recovery,
            providers: self.providers.clone(),
        };
        let (sdk, backing): (Arc<dyn GcClient>, Backing) = match &self.backend {
            #[cfg(any(feature = "embedded", feature = "network-client"))]
            Backend::Embedded | Backend::NetworkClient => {
                let client_only = matches!(self.backend, Backend::NetworkClient);
                let network = self
                    .network
                    .as_ref()
                    .map(|n| gcoms_runtime::network::from_json(n))
                    .transpose()?;
                let options = gcoms_runtime::RuntimeOptions {
                    listen: self.listen,
                    advertise: self.advertise,
                    relay: self.relay.clone(),
                    fixture: self.fixture,
                    carrier: self.carrier,
                    network,
                };
                let runtime = match self.storage {
                    Some((store, data)) => {
                        if client_only {
                            gcoms_runtime::ProtocolRuntime::from_client_storage(
                                store, data, options,
                            )
                            .await?
                        } else {
                            gcoms_runtime::ProtocolRuntime::from_storage(store, data, options)
                                .await?
                        }
                    }
                    None if client_only => {
                        gcoms_runtime::ProtocolRuntime::open_client_options(
                            &profile,
                            &self.secret,
                            create,
                            options,
                        )
                        .await?
                    }
                    None => {
                        gcoms_runtime::ProtocolRuntime::open_options(
                            &profile,
                            &self.secret,
                            create,
                            options,
                        )
                        .await?
                    }
                };
                let ready = async {
                    let client = if let Some((policy, primary, safety)) = self.central {
                        if runtime.sdk_client().identity().safety_number != safety {
                            return Err("component host identity does not match its pin".into());
                        }
                        runtime.central_client(policy, primary).await?
                    } else {
                        runtime.personal_profile().await?;
                        runtime.sdk_client()
                    };
                    runtime.enable_durable_applications().await?;
                    runtime
                        .start_network_maintenance(self.providers.clone(), self.network_recovery)?;
                    Ok::<_, String>(client)
                }
                .await;
                let client = match ready {
                    Ok(client) => client,
                    Err(error) => {
                        let _ = runtime.shutdown().await;
                        return Err(error);
                    }
                };
                (Arc::new(client), Backing::Embedded(runtime))
            }
            #[cfg(feature = "launch")]
            Backend::Shared {
                executable,
                endpoint,
            } => {
                ensure_service(executable, endpoint).await?;
                attach(endpoint, config, token, &self.secret, create).await?
            }
            #[cfg(feature = "ipc")]
            Backend::Attach { endpoint } => {
                attach(endpoint, config, token, &self.secret, create).await?
            }
        };
        let opened = async {
            if let Some(invitation) = &self.invitation {
                sdk.import_network_invitation(invitation)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if self.peers.len() > 64 {
                return Err("too many trusted peers".into());
            }
            for peer in &self.peers {
                if peer.component.is_some()
                    || sdk
                        .resolve_contact_identity(&peer.contact)
                        .await
                        .map_err(|e| e.to_string())?
                        != peer.identity
                {
                    return Err("peer identity does not match contact card".into());
                }
            }
            let peers = Arc::new(std::sync::RwLock::new(self.peers.clone()));
            #[cfg(not(feature = "rpc"))]
            let rpc = RpcState {};
            #[cfg(feature = "rpc")]
            let rpc = {
                let mut contracts = self.contracts.clone();
                contracts.sort();
                contracts.dedup();
                if (!contracts.is_empty() || !self.services.is_empty()) && !self.receive {
                    return Err("typed services require the profile inbox consumer".into());
                }
                let router = if self.services.is_empty() {
                    None
                } else {
                    let mut router = rpc::Router::new(&self.application, 4, 11_000);
                    for (dispatcher, authorize) in &self.services {
                        let descriptor = dispatcher.descriptor();
                        let namespace = format!(
                            "{}/{}/{}",
                            self.application, descriptor.name, descriptor.version
                        );
                        let journal_path = control::sidecar(
                            &profile,
                            &format!("rpc-{}", digest_name(namespace.as_bytes())),
                        );
                        let mut secret = Zeroizing::new([0u8; 32]);
                        // Independent purpose salt; the profile registration token is random and retained.
                        let salt = sha2_digest(
                            &[
                                b"gcoms.application.rpc.v1".as_slice(),
                                &token,
                                namespace.as_bytes(),
                            ]
                            .concat(),
                        );
                        argon2::Argon2::default()
                            .hash_password_into(self.secret.as_bytes(), &salt, &mut *secret)
                            .map_err(|e| e.to_string())?;
                        let journal = rpc::file_store::FileStore::open(
                            &journal_path,
                            *secret,
                            &namespace,
                            rpc::StoreLimits::default(),
                        )
                        .map_err(|e| e.to_string())?;
                        router
                            .register(dispatcher.clone(), Arc::new(journal), authorize.clone())
                            .map_err(|e| e.to_string())?;
                    }
                    Some(Arc::new(router))
                };
                let endpoint = if contracts.is_empty() {
                    None
                } else {
                    Some(
                        GcEndpoint::new(
                            Arc::new(DirectLink(sdk.clone())),
                            self.peers.clone(),
                            &contracts,
                            router,
                        )
                        .await
                        .map_err(|e| e.to_string())?,
                    )
                };
                let handles = Arc::new(
                    rpc::file_store::FileHandles::open(&control::sidecar(
                        &profile,
                        "gcoms-handles",
                    ))
                    .map_err(|e| e.to_string())?,
                );
                RpcState { endpoint, handles }
            };
            let (sender, messages) = mpsc::channel(64);
            let (errors_tx, errors_rx) = tokio::sync::watch::channel(None);
            let task = if self.receive {
                // Claim the daemon lease before reporting successful application startup.
                sdk.application_inbox(0, 1)
                    .await
                    .map_err(|e| e.to_string())?;
                let (stop, stopped) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(pump(
                    sdk.clone(),
                    rpc.clone(),
                    peers.clone(),
                    sender,
                    errors_tx,
                    stopped,
                ));
                Some((stop, task))
            } else {
                None
            };
            Ok::<_, String>((rpc, peers, messages, task, errors_rx))
        }
        .await;
        match opened {
            Ok((_rpc, peers, messages, task, errors)) => Ok(Application(Arc::new(Inner {
                sdk,
                backing,
                #[cfg(feature = "rpc")]
                rpc: _rpc,
                peers,
                messages: tokio::sync::Mutex::new(messages),
                task: Mutex::new(task),
                closed: AtomicBool::new(false),
                errors,
            }))),
            Err(error) => {
                let _ = backing.close(false).await;
                Err(error)
            }
        }
    }
}
pub(crate) fn validate_application(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
    {
        Err(
            "application ID must contain 1–80 ASCII letters, digits, dots, hyphens or underscores"
                .into(),
        )
    } else {
        Ok(())
    }
}
enum Backing {
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    Embedded(gcoms_runtime::ProtocolRuntime),
    #[cfg(feature = "ipc")]
    Shared {
        client: sdk::IpcClient,
        control: PathBuf,
        profile: PathBuf,
        token: [u8; 32],
    },
}
impl Backing {
    async fn close(&self, _stop: bool) -> Result<(), String> {
        match self {
            #[cfg(any(feature = "embedded", feature = "network-client"))]
            Self::Embedded(runtime) => runtime.clone().shutdown().await,
            #[cfg(feature = "ipc")]
            Self::Shared {
                client,
                control,
                profile,
                token,
            } => {
                client.close().await;
                if _stop {
                    control::exchange(
                        control,
                        control::Request::Stop {
                            profile: profile.clone(),
                            token: *token,
                        },
                    )
                    .await?;
                }
                Ok(())
            }
        }
    }
}
#[derive(Clone)]
struct RpcState {
    #[cfg(feature = "rpc")]
    endpoint: Option<Arc<GcEndpoint>>,
    #[cfg(feature = "rpc")]
    handles: Arc<rpc::file_store::FileHandles>,
}
struct Inner {
    sdk: Arc<dyn GcClient>,
    backing: Backing,
    #[cfg(feature = "rpc")]
    rpc: RpcState,
    peers: Arc<std::sync::RwLock<Vec<Peer>>>,
    messages: tokio::sync::Mutex<mpsc::Receiver<MessageDelivery>>,
    task: Mutex<Option<InboxWorker>>,
    errors: tokio::sync::watch::Receiver<Option<String>>,
    closed: AtomicBool,
}
impl Drop for Inner {
    fn drop(&mut self) {
        if let Some((stop, _task)) = self
            .task
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = stop.send(());
        }
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            #[cfg(feature = "rpc")]
            if let Some(endpoint) = self.rpc.endpoint.clone() {
                handle.spawn(async move {
                    let _ = endpoint.shutdown().await;
                });
            }
            match &self.backing {
                #[cfg(any(feature = "embedded", feature = "network-client"))]
                Backing::Embedded(runtime) => {
                    let runtime = runtime.clone();
                    handle.spawn(async move {
                        let _ = runtime.shutdown().await;
                    });
                }
                #[cfg(feature = "ipc")]
                Backing::Shared { client, .. } => {
                    let client = client.clone();
                    handle.spawn(async move {
                        client.close().await;
                    });
                }
            }
        }
    }
}
#[derive(Clone)]
pub struct Application(Arc<Inner>);
impl Application {
    pub fn builder(application: impl Into<String>) -> ApplicationBuilder {
        #[cfg(feature = "embedded")]
        let backend = Backend::Embedded;
        #[cfg(all(not(feature = "embedded"), feature = "network-client"))]
        let backend = Backend::NetworkClient;
        #[cfg(all(
            not(any(feature = "embedded", feature = "network-client")),
            feature = "ipc"
        ))]
        let backend = Backend::Attach {
            endpoint: PathBuf::new(),
        };
        ApplicationBuilder {
            application: application.into(),
            profile: None,
            secret: Zeroizing::new(String::new()),
            backend,
            create: None,
            listen: "0.0.0.0:0".parse().unwrap(),
            fixture: false,
            carrier: sdk::CarrierProfile::default(),
            advertise: None,
            relay: None,
            #[cfg(any(feature = "embedded", feature = "network-client"))]
            storage: None,
            #[cfg(any(feature = "embedded", feature = "network-client"))]
            central: None,
            network: None,
            network_recovery: true,
            providers: Vec::new(),
            invitation: None,
            receive: true,
            peers: Vec::new(),
            #[cfg(feature = "rpc")]
            contracts: Vec::new(),
            #[cfg(feature = "rpc")]
            services: Vec::new(),
        }
    }
    #[cfg(feature = "files")]
    pub fn files(&self) -> crate::Files {
        crate::Files(self.0.sdk.clone())
    }
    /// Owner-only local compatibility hook for an existing encrypted cache.
    /// This configures storage on this machine; file upload/export paths stay in `Files`.
    #[cfg(feature = "files")]
    pub async fn configure_file_cache(
        &self,
        path: &std::path::Path,
        key: [u8; 32],
        config: sdk::sharing::CacheConfig,
    ) -> Result<(), String> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err("application is closed".into());
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
        match &self.0.backing {
            #[cfg(any(feature = "embedded", feature = "network-client"))]
            Backing::Embedded(runtime) => runtime
                .configure_file_cache(path, key, config)
                .await
                .map_err(|e| e.to_string()),
            #[cfg(feature = "ipc")]
            Backing::Shared {
                control: endpoint,
                profile,
                token,
                ..
            } => {
                control::exchange(
                    endpoint,
                    control::Request::ConfigureFileCache {
                        profile: profile.clone(),
                        token: *token,
                        path: path.to_owned(),
                        key,
                        config,
                    },
                )
                .await?;
                Ok(())
            }
        }
    }
    pub fn messaging(&self) -> Arc<dyn GcClient> {
        self.0.sdk.clone()
    }
    /// The caller authenticates the public identity out of band before trusting its card.
    pub async fn trust_peer(&self, peer: Peer) -> Result<(), SdkError> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(SdkError::ConnectionClosed);
        }
        if peer.component.is_some()
            || self.0.sdk.resolve_contact_identity(&peer.contact).await? != peer.identity
        {
            return Err(SdkError::InvalidContactCard);
        }
        #[cfg(feature = "rpc")]
        if let Some(endpoint) = &self.0.rpc.endpoint {
            endpoint
                .trust_peer(peer.clone())
                .await
                .map_err(|e| SdkError::Runtime(e.to_string()))?;
        }
        let mut peers = self
            .0
            .peers
            .write()
            .map_err(|_| SdkError::ConnectionClosed)?;
        if let Some(old) = peers.iter_mut().find(|p| p.principal() == peer.principal()) {
            *old = peer;
        } else if peers.len() >= 64 {
            return Err(SdkError::Runtime("too many trusted peers".into()));
        } else {
            peers.push(peer);
        }
        Ok(())
    }
    pub async fn peer(&self) -> Result<Peer, SdkError> {
        let identity = self.0.sdk.refresh_identity().await?;
        Ok(Peer {
            identity: self
                .0
                .sdk
                .resolve_contact_identity(&identity.contact_card)
                .await?,
            contact: identity.contact_card,
            component: None,
        })
    }
    pub fn identity(&self) -> sdk::Identity {
        self.0.sdk.identity()
    }
    pub async fn status(&self) -> Result<sdk::RuntimeStatus, SdkError> {
        self.0.sdk.runtime_status().await
    }
    pub fn worker_error(&self) -> Option<String> {
        self.0.errors.borrow().clone()
    }
    pub async fn receive(&self) -> Option<MessageDelivery> {
        self.0.messages.lock().await.recv().await
    }
    #[cfg(feature = "rpc")]
    pub fn rpc(
        &self,
        peer: &Peer,
        instance: &str,
        contract: &rpc::Service,
    ) -> Result<rpc::Client<rpc::gc::GcTransport>, rpc::RpcError> {
        let endpoint = self.0.rpc.endpoint.as_ref().ok_or_else(|| {
            rpc::RpcError::invalid(
                "register the RPC contract and trusted peer when opening the application",
            )
        })?;
        Ok(rpc::Client::new(
            endpoint.transport(peer, &contract.name, contract.version)?,
            instance,
        )
        .with_handles(self.0.rpc.handles.clone()))
    }
    #[cfg(feature = "rpc")]
    pub fn handles(&self) -> &dyn rpc::HandleStore {
        self.0.rpc.handles.as_ref()
    }
    pub async fn close(self) -> Result<(), String> {
        self.close_inner(false).await
    }
    pub async fn stop_profile(self) -> Result<(), String> {
        self.close_inner(true).await
    }
    async fn close_inner(&self, stop: bool) -> Result<(), String> {
        if !self.0.closed.swap(true, Ordering::AcqRel) {
            let task = self
                .0
                .task
                .lock()
                .map_err(|_| "application task lock poisoned")?
                .take();
            if let Some((stop, task)) = task {
                let _ = stop.send(());
                let _ = task.await;
            }
            #[cfg(not(feature = "rpc"))]
            let stopped: Result<(), String> = Ok(());
            #[cfg(feature = "rpc")]
            let stopped = if let Some(endpoint) = &self.0.rpc.endpoint {
                endpoint.shutdown().await.map_err(|e| e.to_string())
            } else {
                Ok(())
            };
            let closed = self.0.backing.close(stop).await;
            stopped.and(closed)?;
        }
        Ok(())
    }
    #[cfg(any(feature = "embedded", feature = "network-client"))]
    pub fn embedded_runtime(&self) -> Option<&gcoms_runtime::ProtocolRuntime> {
        match &self.0.backing {
            Backing::Embedded(runtime) => Some(runtime),
            #[cfg(feature = "ipc")]
            _ => None,
        }
    }
}
struct PendingDelivery {
    sequence: u64,
    active: Arc<Mutex<BTreeSet<u64>>>,
}
impl Drop for PendingDelivery {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.sequence);
        }
    }
}
/// A durable message. Acknowledge only after the application's effects are durable.
/// Dropping without acknowledging makes it eligible for redelivery.
pub struct MessageDelivery {
    pub delivery: sdk::ApplicationDelivery,
    pub message: sdk::ApplicationMessage,
    sdk: Arc<dyn GcClient>,
    _pending: PendingDelivery,
}
impl MessageDelivery {
    pub async fn acknowledge(self) -> Result<(), SdkError> {
        self.sdk
            .commit_application(self.delivery.sequence, self.delivery.receipt_digest)
            .await
    }
}
type InboxWorker = (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
);
async fn pump(
    sdk: Arc<dyn GcClient>,
    rpc: RpcState,
    peers: Arc<std::sync::RwLock<Vec<Peer>>>,
    sender: mpsc::Sender<MessageDelivery>,
    errors: tokio::sync::watch::Sender<Option<String>>,
    stopped: tokio::sync::oneshot::Receiver<()>,
) {
    let active = Arc::new(Mutex::new(BTreeSet::new()));
    let mut cursor = 0;
    let mut jobs = tokio::task::JoinSet::new();
    tokio::select! {
      _ = stopped => {},
      _ = async { loop {
        tokio::select! {
            _ = sender.closed() => break,
            _ = jobs.join_next(), if !jobs.is_empty() => {},
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                let deliveries = match sdk.application_inbox(cursor, 32).await {
                    Ok(deliveries) => deliveries,
                    Err(e) => { errors.send_replace(Some(e.to_string())); break; }
                };
                let count = deliveries.len();
                for delivery in deliveries {
                    cursor = cursor.max(delivery.sequence);
                    if delivery.destination_component.is_some() || !peers.read().unwrap_or_else(|e| e.into_inner()).iter().any(|p| p.identity == delivery.peer_identity && p.component == delivery.source_component) { continue; }
                    let Ok(message) = sdk::ApplicationMessage::decode(&delivery.body) else { continue };
                    {
                        let mut pending = active.lock().unwrap_or_else(|e| e.into_inner());
                        if pending.len() >= 64 || !pending.insert(delivery.sequence) { continue; }
                    }
                    let pending = PendingDelivery { sequence: delivery.sequence, active: active.clone() };
                    let sdk = sdk.clone(); let rpc = rpc.clone(); let sender = sender.clone();
                    #[cfg(feature = "rpc")]
                    let errors = errors.clone();
                    jobs.spawn(async move {
                        #[cfg(not(feature = "rpc"))]
                        let _ = rpc;
                        #[cfg(feature = "rpc")]
                        if let Some(endpoint) = rpc.endpoint {
                            match endpoint.dispatch_delivery(&delivery).await {
                                Ok(true) => return,
                                Ok(false) => {},
                                Err(e) => { errors.send_replace(Some(e.to_string())); return; }
                            }
                        }
                        let _ = sender.try_send(MessageDelivery { delivery, message, sdk, _pending: pending });
                    });
                }
                if count < 32 { cursor = 0; }
            }
        }
      } } => {},
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
}
#[cfg(any(
    feature = "rpc",
    all(any(feature = "embedded", feature = "network-client"), feature = "ipc")
))]
fn sha2_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
#[cfg(any(
    feature = "rpc",
    all(any(feature = "embedded", feature = "network-client"), feature = "ipc")
))]
pub(crate) fn digest_name(bytes: &[u8]) -> String {
    sha2_digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(feature = "ipc")]
async fn attach(
    endpoint: &Path,
    config: control::ProfileConfig,
    token: [u8; 32],
    secret: &str,
    create: bool,
) -> Result<(Arc<dyn GcClient>, Backing), String> {
    control::exchange(endpoint, control::Request::Ping).await?;
    let profile = config.profile.clone();
    let attachment = control::exchange(
        endpoint,
        control::Request::Open {
            config,
            token,
            secret: secret.into(),
            create,
        },
    )
    .await?
    .ok_or("daemon returned no profile")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(
            deadline,
            sdk::IpcClient::connect_profile(
                &attachment.endpoint,
                "gcoms",
                control::capabilities(),
                token,
            ),
        )
        .await
        .map_err(|_| "GComs profile handshake timed out")?
        {
            Ok(client) => {
                if client.identity().safety_number != attachment.safety_number {
                    client.close().await;
                    return Err("daemon profile identity changed".into());
                }
                return Ok((
                    Arc::new(client.clone()),
                    Backing::Shared {
                        client,
                        control: endpoint.into(),
                        profile,
                        token,
                    },
                ));
            }
            Err(error) if tokio::time::Instant::now() >= deadline => {
                return Err(format!("GComs profile did not become ready: {error}"))
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}
#[cfg(feature = "launch")]
async fn ensure_service(executable: &Path, endpoint: &Path) -> Result<(), String> {
    use fs2::FileExt;
    if control::exchange(endpoint, control::Request::Ping)
        .await
        .is_ok()
    {
        return Ok(());
    }
    if !executable.is_absolute() || !endpoint.is_absolute() {
        return Err("use absolute bundled executable and service endpoint paths".into());
    }
    let parent = endpoint.parent().ok_or("service endpoint needs a parent")?;
    control::private_directory(parent)?;
    let lock_path = endpoint.with_extension("startup-lock");
    let lock = control::private_lock(&lock_path)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            Err(_) => return Err("GComs service startup is busy".into()),
        }
    }
    if control::exchange(endpoint, control::Request::Ping)
        .await
        .is_ok()
    {
        return Ok(());
    }
    if sdk::local::connect(&sdk::LocalEndpoint::new(endpoint))
        .await
        .is_ok()
    {
        return Err("a running incompatible service owns the GComs endpoint".into());
    }
    let mut command = std::process::Command::new(executable);
    command
        .arg("--endpoint")
        .arg(endpoint)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe and does not access Rust allocations.
        unsafe {
            command.pre_exec(|| rustix::process::setsid().map(|_| ()).map_err(Into::into));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("start bundled GComs service: {e}"))?;
    loop {
        if control::exchange(endpoint, control::Request::Ping)
            .await
            .is_ok()
        {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("GComs service exited before readiness: {status}"));
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("GComs service readiness timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
