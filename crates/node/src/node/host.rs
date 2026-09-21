//! Relay listener and queue ownership. Absent from outbound-only builds.
use super::*;

pub(super) struct RelayHost {
    pub leases: Arc<Mutex<LeaseStore>>,
    registry: TokenRegistry,
    authorities: Arc<Mutex<ProvisionAuthorities>>,
    queue_tokens: Arc<Mutex<HashMap<[u8; 32], String>>>,
    pub target: RelayTarget,
    identity_pk: Vec<u8>,
    bundle: Vec<u8>,
}

impl RelayHost {
    pub fn provision(&self, permanent: bool) -> Result<NodeInfo, String> {
        provision_relay(
            &self.leases,
            &self.registry,
            &self.authorities,
            &self.target,
            &self.identity_pk,
            &self.bundle,
            permanent,
        )
    }
    pub fn admitted(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.authorities
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admitted
            .clone()
    }
    pub fn sweep(&self) -> tokio::task::JoinHandle<()> {
        relay_service::spawn_lease_sweeper(
            self.leases.clone(),
            self.queue_tokens.clone(),
            self.registry.clone(),
            self.authorities.clone(),
        )
    }
}

pub(super) async fn start(
    cfg: &NodeConfig,
    tls_identity: &TlsIdentity,
    routing: Option<&Arc<routing::RoutingRuntime>>,
    connectivity: Option<&crate::connectivity::ConnectivityConfig>,
    transit_scheduler: &RelayScheduler,
    frwd_target_policy: &FrwdTargetPolicy,
    identity: (&[u8], &[u8]),
) -> Result<
    (
        Arc<RelayHost>,
        startup_transport::StartupTransport,
        SocketAddr,
    ),
    String,
> {
    let service_id = tls_identity.service_id();
    let stream_emission = cfg.profile.stream_emission();
    let registry = TokenRegistry::new();
    let leases = Arc::new(Mutex::new(
        LeaseStore::new(service_id, StoreConfig::default()).map_err(|e| e.to_string())?,
    ));
    let queue_tokens = Arc::new(Mutex::new(HashMap::<[u8; 32], String>::new()));
    let authorities = Arc::new(Mutex::new(ProvisionAuthorities {
        transit_ready: routing
            .as_ref()
            .filter(|r| r.automatic_connectivity)
            .map(|r| r.published.clone()),
        ..Default::default()
    }));
    let (on_cell, on_queue_cell, on_stream) = relay_service::build_handlers(
        &leases,
        &registry,
        &queue_tokens,
        &authorities,
        transit_scheduler,
        frwd_target_policy,
        service_id,
        stream_emission,
    );

    let listener = match &connectivity {
        Some(config) => config.bind(cfg.listen)?,
        None => Tp1Server::bind_listener(cfg.listen).map_err(|e| e.to_string())?,
    };
    let server = Tp1Server::from_listener_with_identity_and_queue(
        listener,
        registry.clone(),
        on_cell,
        on_stream,
        on_queue_cell,
        tls_identity,
    )
    .map_err(|e| e.to_string())?
    .with_limits(cfg.profile.server_limits());
    #[cfg(feature = "experimental-gc2")]
    let server = if cfg.profile.gc2_gate() {
        // Compose the owned terminal queue service under the same role gate.
        // Its handler only accepts authenticated queue tokens that resolve to a
        // current lease in this node's store.
        let queues = crate::gc2::QueueService::new(leases.clone()).handler();
        let forwards = gc2_forward::handler(
            authorities.clone(),
            transit_scheduler.clone(),
            service_id,
            frwd_target_policy.clone(),
        );
        let terminal: Option<gcoms_transport::server::DuplexHandler> =
            Some(Arc::new(move |path| {
                queues(path).or_else(|| forwards(path))
            }));
        server.with_dispatch_factory(gc2_gate::dispatch_factory(routing.cloned(), terminal))
    } else {
        server
    };
    let local_addr = server.local_addr().map_err(|e| e.to_string())?;
    let candidate = match cfg.advertise {
        Some(address) => address,
        None if connectivity.is_some() => crate::connectivity::initial_candidate(local_addr).await,
        None => local_addr,
    };
    let relay_target = RelayTarget {
        address: candidate,
        relay_service_id: service_id,
    };
    let server = if let Some(runtime) = routing {
        server.with_duplex(runtime.attach(
            tls_identity,
            &relay_target,
            leases.clone(),
            registry.clone(),
            authorities.clone(),
        )?)
    } else {
        server
    };
    let transport = startup_transport::StartupTransport::spawn(server);
    Ok((
        Arc::new(RelayHost {
            leases,
            registry,
            authorities,
            queue_tokens,
            target: relay_target,
            identity_pk: identity.0.to_vec(),
            bundle: identity.1.to_vec(),
        }),
        transport,
        local_addr,
    ))
}
