//! Routing belongs to the backend. Application APIs never select transport hops.
use super::*;
use gcoms_routing::{
    bootstrap::BootstrapBundle, carrier::CarrierConfig, discovery::Discovery, Directory,
    OnionConnector, RelayService, ServicePolicy,
};
use gcoms_transport::connector::{ConnectFuture, Connector, DirectConnector};
use std::sync::atomic::{AtomicBool, Ordering};

/// A selected guard must survive a crash before it sees the first connection.
/// The profile owns the sink; a weak reference avoids a runtime/state cycle.
struct PersistedEntry {
    state: std::sync::OnceLock<std::sync::Weak<Mutex<NodeState>>>,
    directory: Arc<Directory>,
    saved: Mutex<Option<[u8; 32]>>,
    routing_state: Option<Arc<dyn RoutingStateStore>>,
}

impl PersistedEntry {
    fn checkpoint(&self) -> Result<(), String> {
        // Serialize snapshots before encoding, so simultaneous circuit
        // attempts cannot publish an older view over a newer one.
        let mut saved = self.saved.lock().unwrap_or_else(|p| p.into_inner());
        let bytes =
            zeroize::Zeroizing::new(self.directory.encode_private().map_err(|e| e.to_string())?);
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if *saved != Some(digest) {
            let state = self
                .state
                .get()
                .and_then(std::sync::Weak::upgrade)
                .ok_or("routing profile is not ready")?;
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            persist_current_direct_state(&st)?;
            if let Some(store) = &self.routing_state {
                store.save(&bytes)?;
            }
            *saved = Some(digest);
        }
        Ok(())
    }
}

impl Connector for PersistedEntry {
    fn connect(&self, addr: SocketAddr, pin: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async move {
            self.checkpoint()?;
            DirectConnector.connect(addr, pin).await
        })
    }
}

/// Optional private partial-view persistence for hosts that do not archive node
/// messages. Implementations must authenticate, bound and atomically save bytes.
pub trait RoutingStateStore: Send + Sync {
    fn load(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String>;
    fn save(&self, bytes: &[u8]) -> Result<(), String>;
}

#[derive(Clone, Default)]
pub struct RoutingConfig {
    /// Full native automatic listener; absent preserves fixed-port behavior.
    pub connectivity: Option<crate::connectivity::ConnectivityConfig>,
    pub bootstrap: Option<BootstrapBundle>,
    /// Canonical HTTPS host names; both endpoint and egress enforce this list.
    pub catalog_origins: Vec<String>,
    pub routing_state: Option<Arc<dyn RoutingStateStore>>,
}

impl RoutingConfig {
    pub fn from_environment() -> Result<Self, String> {
        let bootstrap = match std::env::var_os("GC_ROUTING_BOOTSTRAP") {
            Some(path) => {
                let bytes = crate::routing_cache::read_optional(
                    std::path::Path::new(&path),
                    gcoms_routing::bootstrap::MAX_BUNDLE_BYTES,
                )
                .map_err(|e| format!("cannot read private routing bootstrap: {e}"))?
                .ok_or("private routing bootstrap is missing")?;
                Some(BootstrapBundle::decode(&bytes).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        let catalog_origins = std::env::var("GC_CATALOG_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(Self {
            connectivity: None,
            bootstrap,
            catalog_origins,
            routing_state: None,
        })
    }
}

pub(crate) struct RoutingRuntime {
    pub discovery: Discovery,
    pub service: Mutex<Option<Arc<RelayService>>>,
    pub catalog_origins: Mutex<Vec<String>>,
    pub recovering_owner: AtomicBool,
    pub published: Arc<AtomicBool>,
    pub automatic_connectivity: bool,
    stopping: AtomicBool,
    provision_target: Arc<Mutex<Option<RelayTarget>>>,
    pub fixture: bool,
    provision_request: [u8; 32],
    pub channel_ready: Mutex<HashSet<String>>,
    prepared_ready: Mutex<HashSet<u64>>,
    entry: Arc<PersistedEntry>,
}

impl RoutingRuntime {
    pub fn new(
        config: RoutingConfig,
        mut directory: Directory,
        fixture: bool,
    ) -> Result<Arc<Self>, String> {
        if config.catalog_origins.len() > 8
            || config
                .catalog_origins
                .iter()
                .any(|h| !gcoms_routing::wire::valid_host(h))
        {
            return Err("invalid catalog origin allowlist".into());
        }
        if let Some(store) = &config.routing_state {
            if !directory.introductions().is_empty() {
                return Err("routing state must have one persistence owner".into());
            }
            if let Some(bytes) = store.load()? {
                directory = Directory::restore_private(&bytes).map_err(|e| e.to_string())?;
            }
        }
        let directory = Arc::new(directory);
        if !fixture
            && directory
                .introductions()
                .iter()
                .any(|r| !gcoms_routing::service::public_ip(r.addr.ip()))
        {
            return Err("retained routing material contains a nonpublic relay".into());
        }
        let entry = Arc::new(PersistedEntry {
            state: std::sync::OnceLock::new(),
            directory: directory.clone(),
            saved: Mutex::new(None),
            routing_state: config.routing_state,
        });
        let mut connector =
            OnionConnector::new(directory.clone()).with_entry_connector(entry.clone());
        if fixture {
            connector = connector
                .with_carrier_config(CarrierConfig::fixture())
                .map_err(|e| e.to_string())?;
        }
        let connector = Arc::new(connector);
        let mut discovery = Discovery::new(directory, connector);
        if fixture {
            discovery = discovery.with_local_fixture();
        }
        if let Some(bundle) = config.bootstrap {
            discovery.install(&bundle).map_err(|e| e.to_string())?;
        }
        Ok(Arc::new(Self {
            discovery,
            service: Mutex::new(None),
            catalog_origins: Mutex::new(config.catalog_origins),
            recovering_owner: AtomicBool::new(true),
            published: Arc::new(AtomicBool::new(false)),
            automatic_connectivity: config.connectivity.is_some(),
            stopping: AtomicBool::new(false),
            provision_target: Arc::new(Mutex::new(None)),
            fixture,
            provision_request: random_nonzero(),
            channel_ready: Mutex::new(HashSet::new()),
            prepared_ready: Mutex::new(HashSet::new()),
            entry,
        }))
    }

    pub fn bind_state(&self, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
        self.entry
            .state
            .set(Arc::downgrade(state))
            .map_err(|_| "routing profile is already attached".into())
    }

    pub(crate) fn stop_publication(&self) {
        // Serialize with a completing independent probe, so shutdown cannot
        // be followed by a late proof restoring public transit admission.
        let _service = self.service.lock().unwrap_or_else(|p| p.into_inner());
        self.stopping.store(true, Ordering::Release);
        self.published.store(false, Ordering::Release);
    }

    /// The candidate is updated independently of inbox/session ownership. The
    /// next normal discovery publication must authenticate the new listener.
    pub(crate) fn update_endpoint(&self, address: SocketAddr) -> Result<(), String> {
        let service = self.service.lock().unwrap_or_else(|p| p.into_inner());
        let service = service.as_ref().ok_or("relay listener not attached")?;
        if service.address() != address {
            self.published.store(false, Ordering::Release);
            let mut target = self
                .provision_target
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(target) = target.as_mut() {
                target.address = address;
                self.discovery
                    .directory
                    .set_own_services(vec![(address, target.relay_service_id)])
                    .map_err(|e| e.to_string())?;
            }
            drop(target);
            service.update_address(address);
        }
        Ok(())
    }

    pub fn bootstrap(&self) -> Result<BootstrapBundle, String> {
        let relays = self.discovery.directory.reentry_candidates();
        let bundle = BootstrapBundle { relays };
        bundle.validate().map_err(|e| e.to_string())?;
        Ok(bundle)
    }

    pub fn attach(
        &self,
        tls: &TlsIdentity,
        target: &RelayTarget,
        leases: Arc<Mutex<LeaseStore>>,
        registry: TokenRegistry,
        authorities: Arc<Mutex<ProvisionAuthorities>>,
    ) -> Result<gcoms_transport::server::DuplexHandler, String> {
        self.discovery
            .directory
            .set_own_services(vec![(target.address, target.relay_service_id)])
            .map_err(|e| e.to_string())?;
        // This service principal is domain-separated from the user's GC key.
        let mut seed = [0; 32];
        Hkdf::<Sha256>::new(Some(&target.relay_service_id), tls.private_key_pkcs8_der())
            .expand(b"ghost.relay.private-service.v1", &mut seed)
            .map_err(|_| "relay key derivation")?;
        let identity = IdentityKeypair::from_seed(seed);
        let (bundle, _) = identity.issue_bundle();
        let public = identity.public_bytes();
        let bundle = bundle.encode();
        *self
            .provision_target
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(target.clone());
        let provision_target = self.provision_target.clone();
        let mut policy = ServicePolicy {
            catalog_origins: self
                .catalog_origins
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
            transit_ready: self.automatic_connectivity.then(|| self.published.clone()),
            provision: Some(Arc::new(move || {
                let target = provision_target
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .ok_or("listener candidate unavailable")?;
                let card = provision_relay(
                    &leases,
                    &registry,
                    &authorities,
                    &target,
                    &public,
                    &bundle,
                    false,
                )?;
                card.encode_private()
                    .ok_or_else(|| "invalid private inbox grant".into())
            })),
            ..ServicePolicy::default()
        };
        if self.fixture {
            policy.carrier = CarrierConfig::fixture();
            policy.target_allowed = Arc::new(|addr| addr.ip().is_loopback());
        }
        let service = RelayService::new(
            target.address,
            target.relay_service_id,
            seed,
            self.discovery.directory.clone(),
            policy,
        )
        .map_err(|e| e.to_string())?;
        seed.fill(0);
        let handler = service.handler();
        *self.service.lock().unwrap_or_else(|p| p.into_inner()) = Some(service);
        Ok(handler)
    }
}

pub(crate) fn empty_provision() -> RelayProvision {
    RelayProvision {
        aliases: Vec::new(),
        frwd_path: String::new(),
        hop_key: [0; 32],
    }
}

pub(crate) fn recovering(st: &NodeState) -> bool {
    st.routing
        .as_ref()
        .is_some_and(|r| r.recovering_owner.load(Ordering::Acquire))
}

pub(crate) fn owner_unavailable(st: &NodeState, alias: &OwnedAlias) {
    if st
        .client_relay
        .aliases
        .iter()
        .any(|a| a.contact.queue_id == alias.contact.queue_id)
    {
        if let Some(runtime) = &st.routing {
            runtime.recovering_owner.store(true, Ordering::Release);
        }
    }
}

pub(crate) fn refresh_public_info(st: &mut NodeState) {
    let Some(runtime) = &st.routing else {
        return;
    };
    let service = runtime.service.lock().unwrap_or_else(|p| p.into_inner());
    let own = service.as_ref().map(|s| s.introduction(now_unix()));
    st.info.aliases = st
        .client_relay
        .aliases
        .iter()
        .filter(|a| {
            a.contact.expiry > now_unix()
                && !own.as_ref().is_some_and(|r| {
                    r.conflicts(a.contact.target.address, a.contact.target.relay_service_id)
                })
        })
        .map(|a| a.contact.clone())
        .collect();
}

/// Unavailable internal route for old archives that never stored owned channel
/// leases. Its invalid contacts are never advertised; recovery provisions them.
#[cfg(feature = "client-persist")]
pub(crate) fn pending_channel_route(
    seed: &[u8; 32],
    channel: &str,
    pseudonym: [u8; 32],
    previous: Option<crate::channel::ChannelRoute>,
) -> Result<crate::channel::OwnedChannelRoute, String> {
    let direct_secret = retained_channel_direct_secret(
        seed,
        channel,
        &pseudonym,
        &previous.as_ref().map_or([0; 32], |r| r.direct_public),
    )?;
    let empty = AliasContact {
        target: RelayTarget {
            address: "0.0.0.0:0".parse().expect("constant address"),
            relay_service_id: [0; 32],
        },
        queue_id: [0; 32],
        epoch: 0,
        push_cap: [0; 32],
        expiry: 0,
    };
    let public = previous.unwrap_or(crate::channel::ChannelRoute {
        pseudonym,
        direct_public: [0; 32],
        data: empty.clone(),
        control: empty,
    });
    Ok(crate::channel::OwnedChannelRoute {
        public,
        direct_secret,
        aliases: Vec::new(),
    })
}

/// Channel founders historically derived this key from their channel seed;
/// joiners (and routes reprovisioned by older restores) used the node seed.
/// Recover the key matching the retained public capability without rekeying it.
#[cfg(feature = "client-persist")]
pub(crate) fn retained_channel_direct_secret(
    seed: &[u8; 32],
    channel: &str,
    pseudonym: &[u8; 32],
    public: &[u8; 32],
) -> Result<[u8; 32], String> {
    for derived_seed in [*seed, super::persist::channel_seed_from(seed, channel)] {
        let secret = channel_direct_secret(&derived_seed, pseudonym);
        let key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        if public == &[0; 32] || key.as_bytes() == public {
            return Ok(secret);
        }
    }
    Err("retained channel-direct capability does not match its identity".into())
}

pub(crate) fn spawn(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let runtime = state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .routing
            .clone()
            .expect("routing runtime");
        let mut failures = 0u32;
        let mut next_publish = std::time::Instant::now();
        let mut publication_failures = 0u32;
        let mut last_candidate = None;
        loop {
            let _ = runtime.discovery.refresh().await;
            // Cache and guard changes are sealed even while inboxes are offline.
            {
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                refresh_public_info(&mut st);
                if persist_current_direct_state(&st).is_err() {
                    return;
                }
            }
            if runtime.entry.checkpoint().is_err() {
                return;
            }
            if runtime.recovering_owner.load(Ordering::Acquire) {
                let deadline = if runtime.fixture {
                    std::time::Duration::from_secs(10)
                } else {
                    std::time::Duration::from_secs(90)
                };
                if tokio::time::timeout(
                    deadline,
                    recover_owner(&state, &scheduler, &events, &runtime, failures >= 2),
                )
                .await
                .is_ok_and(|r| r.is_ok())
                {
                    runtime.recovering_owner.store(false, Ordering::Release);
                    runtime
                        .channel_ready
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clear();
                    runtime
                        .prepared_ready
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clear();
                    failures = 0;
                } else {
                    failures = failures.saturating_add(1);
                }
            }
            if !runtime.recovering_owner.load(Ordering::Acquire) {
                let _ = recover_channels(&state, &scheduler, &runtime).await;
            }
            let introduction = runtime
                .service
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|s| s.introduction(now_unix()));
            if let Some(own) = introduction {
                if last_candidate != Some(own.addr) {
                    next_publish = std::time::Instant::now();
                    publication_failures = 0;
                    last_candidate = Some(own.addr);
                }
                if std::time::Instant::now() >= next_publish
                    && (runtime.fixture || gcoms_routing::service::public_ip(own.addr.ip()))
                {
                    let verified = runtime.discovery.publish(&own).await.is_ok();
                    // A concurrent router change cannot turn an obsolete proof
                    // into authority for the new endpoint.
                    let service = runtime.service.lock().unwrap_or_else(|p| p.into_inner());
                    if !runtime.stopping.load(Ordering::Acquire)
                        && service
                            .as_ref()
                            .is_some_and(|service| service.address() == own.addr)
                    {
                        runtime.published.store(verified, Ordering::Release);
                    }
                    publication_failures = if verified {
                        0
                    } else {
                        publication_failures.saturating_add(1)
                    };
                    let retry = if verified {
                        300
                    } else {
                        5u64.saturating_mul(1 << publication_failures.min(6))
                            .min(300)
                    };
                    next_publish = std::time::Instant::now()
                        + std::time::Duration::from_secs(
                            retry + rand::random::<u64>() % (retry / 4 + 1),
                        );
                }
            }
            tokio::time::sleep(if runtime.fixture {
                std::time::Duration::from_millis(200)
            } else {
                std::time::Duration::from_secs(25 + rand::random::<u64>() % 11)
            })
            .await;
        }
    })
}

async fn recover_aliases(
    scheduler: &RelayScheduler,
    authority: &OwnedAlias,
    retained: &[OwnedAlias],
) -> Result<Vec<OwnedAlias>, String> {
    let expiry = retained
        .iter()
        .map(|a| a.contact.expiry)
        .min()
        .ok_or("missing retained aliases")?;
    let remaining = expiry
        .checked_sub(now_unix())
        .filter(|n| *n > 0)
        .ok_or("retained route expired")?;
    tokio::time::timeout(std::time::Duration::from_secs(remaining.min(60)), async {
        let mut aliases = Vec::new();
        for alias in retained {
            let restored = restore_contact_alias(scheduler, authority, alias).await?;
            if restored.contact != alias.contact
                || restored.capabilities != alias.capabilities
                || restored.limits != alias.limits
            {
                return Err("route recovery changed retained authority".into());
            }
            aliases.push(restored);
        }
        if now_unix() >= expiry {
            return Err("retained route expired during recovery".into());
        }
        Ok(aliases)
    })
    .await
    .map_err(|_| "route recovery exceeded original lifetime")?
}

async fn recover_channels(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    runtime: &RoutingRuntime,
) -> Result<(), String> {
    let (authority, relay, channels, prepared) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let authority = st
            .client_relay
            .aliases
            .first()
            .ok_or("inbox is unavailable")?
            .clone();
        let mut ready = runtime
            .channel_ready
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        ready.retain(|name| st.channels.contains_key(name));
        let channels: Vec<_> = st
            .channels
            .iter()
            .filter(|(name, _)| !ready.contains(*name))
            .take(4)
            .map(|(name, cs)| {
                (
                    name.clone(),
                    cs.own_route.public.clone(),
                    cs.own_route.aliases.clone(),
                    cs.own_route.direct_secret,
                )
            })
            .collect();
        let mut ready = runtime
            .prepared_ready
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        ready.retain(|id| st.prepared.contains_key(id));
        let prepared: Vec<_> = st
            .prepared
            .iter()
            .filter(|(id, _)| !ready.contains(id))
            .take(4)
            .map(|(id, p)| (*id, p.route.aliases.clone()))
            .collect();
        (authority, st.client_relay.clone(), channels, prepared)
    };
    for (id, aliases) in prepared {
        // An in-flight key package keeps its exact route and expiry. Only an
        // active channel may receive a newly announced replacement route.
        let Ok(restored) = recover_aliases(scheduler, &authority, &aliases).await else {
            continue;
        };
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(prepared) = st.prepared.get_mut(&id) else {
            continue;
        };
        if prepared.route.aliases != aliases {
            continue;
        }
        prepared.route.aliases = restored;
        if let Err(error) = persist_current_direct_state(&st) {
            st.pause_failed_owner_transition();
            return Err(error);
        }
        runtime
            .prepared_ready
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id);
    }
    for (name, public, retained, direct_secret) in channels {
        let route = match recover_aliases(scheduler, &authority, &retained).await {
            Ok(aliases) => crate::channel::OwnedChannelRoute {
                public: public.clone(),
                direct_secret,
                aliases,
            },
            Err(_) => {
                provision_channel_route(scheduler, &relay, public.pseudonym, direct_secret).await?
            }
        };
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(cs) = st.channels.get_mut(&name) else {
            continue;
        };
        if cs.own_route.public != public || cs.own_route.aliases != retained {
            continue;
        }
        // Reannounce after every recovered subscription, including an exact
        // restore: a crash may have followed the durable route checkpoint but
        // preceded delivery of its previous directory announcement.
        {
            let own_name = cs
                .roster()
                .into_iter()
                .find(|member| member.is_self)
                .ok_or("channel has no own roster entry")?
                .display_name;
            let public = route.public.clone();
            let wire = match cs
                .role
                .send(&crate::channel::encode_dir(&own_name, &public))
            {
                Ok(wire) => wire,
                Err(error) => {
                    st.pause_failed_owner_transition();
                    return Err(error.to_string());
                }
            };
            if cs.install_authenticated_route(&own_name, &public).is_none() {
                st.pause_failed_owner_transition();
                return Err("owned channel route replacement refused".into());
            }
            let id = crate::channel::msg_id(&name, &wire);
            cs.note(id, wire.clone());
            cs.enqueue_forward(id, wire);
        }
        cs.own_route = route;
        if let Err(error) = persist_current_direct_state(&st) {
            st.pause_failed_owner_transition();
            return Err(error);
        }
        runtime
            .channel_ready
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name);
    }
    Ok(())
}

async fn recover_owner(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
    runtime: &RoutingRuntime,
    allow_replacement: bool,
) -> Result<(), String> {
    let current = state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .client_relay
        .clone();
    let own = runtime
        .service
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(|s| s.introduction(now_unix()));
    let live = !current.aliases.is_empty()
        && current.aliases.iter().all(|a| {
            a.contact.expiry > now_unix()
                && !own.as_ref().is_some_and(|r| {
                    r.conflicts(a.contact.target.address, a.contact.target.relay_service_id)
                })
        });
    if live {
        if resume_owner(state, scheduler, events, runtime, &current)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if !allow_replacement {
            return Err("retained inbox recovery is still pending".into());
        }
    }
    let excluded: Vec<_> = current
        .aliases
        .first()
        .map(|a| (a.contact.target.address, a.contact.target.relay_service_id))
        .into_iter()
        .collect();
    let (_, encoded) = runtime
        .discovery
        .provision(runtime.provision_request, &excluded)
        .await
        .map_err(|e| e.to_string())?;
    let card = NodeInfo::decode_private(&encoded).ok_or("invalid private inbox response")?;
    install_inbox_relay(state, scheduler, events, &card).await
}

async fn resume_owner(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    events: &broadcast::Sender<Ev>,
    runtime: &RoutingRuntime,
    current: &RelayProvision,
) -> Result<(), String> {
    let target = current
        .aliases
        .first()
        .ok_or("no retained inbox")?
        .contact
        .target
        .clone();
    // Freshly issued legacy cards can be consumed without any new UI action.
    let card = NodeInfo {
        identity_pk: Vec::new(),
        bundle: Vec::new(),
        aliases: current.aliases.iter().map(|a| a.contact.clone()).collect(),
        provisioning: Some(current.clone()),
    };
    let initial = consume_provision(scheduler, &card).await;
    let mut authority = current.clone();
    if initial.is_err() {
        let relay = runtime
            .discovery
            .directory
            .introductions()
            .into_iter()
            .find(|r| r.addr == target.address && r.service_id == target.relay_service_id)
            .ok_or("retained service has no fresh introduction")?;
        use gcoms_transport::connector::Connector;
        let stream = runtime
            .discovery
            .connector
            .connect(relay.addr, relay.service_id)
            .await
            .map_err(|e| e.to_string())?;
        let encoded = gcoms_routing::carrier::provision(stream, &relay, runtime.provision_request)
            .await
            .map_err(|e| e.to_string())?;
        let card = NodeInfo::decode_private(&encoded).ok_or("invalid recovery authority")?;
        authority = consume_provision(scheduler, &card).await?;
    }
    #[cfg(feature = "client-persist")]
    {
        let (record, mut clock) = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            let sealed = zeroize::Zeroizing::new(persist::owner_aliases::seal_current(&st)?);
            let record = persist::owner_aliases::open_unbound(&sealed, &st.identity_seed)?;
            let clock = st
                .owner_clock
                .lock()
                .map_err(|_| "owner clock poisoned")?
                .clone();
            (record, clock)
        };
        let restored = record
            .restore_for_constructor(scheduler, &authority, &mut clock)
            .await?;
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.client_relay != *current {
            return Err("owner route changed during restoration".into());
        }
        aliases::owner_transition(&mut st, |st| {
            st.client_relay = authority;
            restored.apply_retained(st, clock, false)
        })?;
        // The queue IDs and deadlines remain unchanged; the freshly restored
        // forwarding authority is announced through existing signed updates.
        let deliveries = queue_contact_updates(&mut st)?;
        let info = st.info.clone();
        let generation = st.local_contact_generation;
        let _ = events.send(Ev::IdentityUpdated { info, generation });
        for delivery in deliveries {
            if let Some(destination) = delivery.peer.primary() {
                for cell in &delivery.cells {
                    let _ = scheduler.frwd(
                        ProducerClass::Direct,
                        delivery.relay.clone(),
                        destination.clone(),
                        cell.clone(),
                        st.frwd_target_policy.clone(),
                    );
                }
            }
        }
    }
    #[cfg(not(feature = "client-persist"))]
    {
        let mut aliases = Vec::new();
        for alias in &current.aliases {
            aliases.push(restore_contact_alias(scheduler, &authority.aliases[0], alias).await?);
        }
        authority.aliases = aliases;
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.client_relay != *current {
            return Err("owner route changed during restoration".into());
        }
        st.client_relay = authority;
        refresh_public_info(&mut st);
        let _ = events.send(Ev::IdentityUpdated {
            info: st.info.clone(),
            generation: st.local_contact_generation,
        });
    }
    Ok(())
}
