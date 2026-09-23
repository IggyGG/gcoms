//! GC/2-native inbox provisioning: a fresh carrier node obtains a relay-minted
//! card (its aliases plus an advertised introduction) over a protected route
//! using only the introduction's re-entry capability. No GC/1 circuit or
//! re-entry material is involved. This is the chain carrier bootstrap relies
//! on; the relay is served with the production-shaped provisioning policy.

use super::*;
use gcoms_crypto::IdentityKeypair;
use gcoms_routing::service::gc2_introduction_from;
use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};

/// Production-shaped provisioning policy: the relay mints a normal client card
/// and, when the request carries the GC/2 option, embeds its advertised
/// introduction in it. Relay secret matches the served identity derivation.
fn provisioning_policy(target: RelayTarget, secret: [u8; 32]) -> ServicePolicy {
    let leases = Arc::new(Mutex::new(
        crate::queues::LeaseStore::new(
            target.relay_service_id,
            crate::queues::StoreConfig::default(),
        )
        .unwrap(),
    ));
    let registry = TokenRegistry::new();
    let authorities = Arc::new(Mutex::new(
        super::relay_service::ProvisionAuthorities::default(),
    ));
    let identity = IdentityKeypair::from_seed(secret);
    let (bundle, _) = identity.issue_bundle();
    let bundle = bundle.encode();
    let public = identity.public_bytes();
    let provision_target = Arc::new(Mutex::new(Some(target)));
    ServicePolicy {
        carrier: CarrierConfig::fixture(),
        target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
        provision: Some(Arc::new(move |options: &[u8]| {
            let target = provision_target
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
                .ok_or("listener candidate unavailable")?;
            let card = super::relay_service::provision_relay(
                &leases,
                &registry,
                &authorities,
                &target,
                &public,
                &bundle,
                false,
            )?;
            if options.first() == Some(&gcoms_protocol::proto::PROVISION_OPTION_GC2) {
                let introduction = gc2_introduction_from(
                    target.address,
                    target.relay_service_id,
                    &secret,
                    super::now_unix(),
                );
                let encoded = introduction.encode().map_err(|error| error.to_string())?;
                return card
                    .encode_private_gc2(&encoded[..])
                    .ok_or_else(|| "invalid GC/2 advertisement".into());
            }
            card.encode_private()
                .ok_or_else(|| "invalid private inbox grant".into())
        })),
        ..ServicePolicy::default()
    }
}

async fn start_relay(
    ip: &str,
    secret: [u8; 32],
    policy: impl FnOnce(RelayTarget) -> ServicePolicy,
) -> (
    gcoms_routing::gc2::directory::Introduction,
    tokio::task::JoinHandle<()>,
) {
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        format!("{ip}:0").parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap();
    let service = RelayService::new(
        server.local_addr().unwrap(),
        identity.service_id(),
        secret,
        Arc::new(Directory::new()),
        policy(RelayTarget {
            address: server.local_addr().unwrap(),
            relay_service_id: identity.service_id(),
        }),
    )
    .unwrap();
    let introduction = service.gc2_introduction(super::now_unix());
    let factory = service.gc2_handler_factory();
    let server = server.with_dispatch_factory(Arc::new(move || factory()));
    let handle = tokio::spawn(async move {
        let _ = server.run_until(std::future::pending::<()>()).await;
    });
    (introduction, handle)
}

#[tokio::test]
async fn fresh_carrier_node_provisions_its_inbox_over_the_protected_route() {
    let secret = [8; 32];
    let (introduction, _relay_a) = start_relay("127.0.0.71", secret, |target| {
        provisioning_policy(target, secret)
    })
    .await;
    let intro_addr = introduction.addr;
    let intro_service = introduction.service_id;
    let (middle, _relay_b) = start_relay("127.0.0.87", [9; 32], |_| ServicePolicy {
        carrier: CarrierConfig::fixture(),
        target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
        ..ServicePolicy::default()
    })
    .await;
    let (third, _relay_c) = start_relay("127.0.0.88", [10; 32], |_| ServicePolicy {
        carrier: CarrierConfig::fixture(),
        target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
        ..ServicePolicy::default()
    })
    .await;

    let mut extra_relays = Vec::new();
    let mut extra_introductions = Vec::new();
    for (ip, secret) in [("127.0.0.89", 11), ("127.0.0.90", 12)] {
        let (introduction, relay) = start_relay(ip, [secret; 32], |_| ServicePolicy {
            carrier: CarrierConfig::fixture(),
            target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
            ..ServicePolicy::default()
        })
        .await;
        extra_introductions.push(introduction.encode().unwrap().to_vec());
        extra_relays.push(relay);
    }

    // Fresh carrier node: directory seeded only with the relay's private
    // introduction; nothing else is shared.
    let cfg = NodeConfig {
        seed: [7; 32],
        listen: "127.0.0.72:0".parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::gc2_carrier_qualification_fixture_seeded(
            None,
            3,
            5,
            [
                introduction.encode().unwrap().to_vec(),
                middle.encode().unwrap().to_vec(),
                third.encode().unwrap().to_vec(),
            ]
            .into_iter()
            .chain(extra_introductions)
            .collect(),
        ),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    };
    let runtime = RoutingRuntime::new(RoutingConfig::default(), Directory::new(), true).unwrap();
    let prepared = super::gc2_bootstrap::prepare(&cfg, Some(&runtime))
        .expect("carrier prepare")
        .expect("carrier profile engages the runtime");
    assert!(runtime.gc2.get().is_some());
    let _owner_task = tokio::spawn(prepared.owner.run());
    let _ = prepared.ready;

    // Cold-entry dials can stall on a loaded host; retry the request across the
    // owner's whole startup window instead of asserting on its readiness timer.
    let reply = tokio::time::timeout(std::time::Duration::from_secs(240), async {
        loop {
            if let Ok(reply) = runtime
                .provision_inbox(&[gcoms_protocol::proto::PROVISION_OPTION_GC2], &[], None)
                .await
            {
                return Ok::<_, String>(reply);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("GCP2 provisioning answers within the startup window")
    .expect("GCP2 provisioning answers");
    let (card, advertised) = NodeInfo::decode_private_any(&reply).expect("private card decodes");
    assert_eq!(
        card.provisioning.as_ref().map(|p| p.aliases.len()),
        Some(2),
        "the inbox card carries normal and control aliases"
    );
    let advertised = advertised.expect("GC/2 reply advertises an introduction");
    let advertised = gcoms_routing::gc2::directory::Introduction::decode(&advertised)
        .expect("advertised introduction decodes");
    assert_eq!(advertised.service_id, intro_service);
    assert_eq!(advertised.addr, intro_addr);
    let accepted = prepared
        .directory
        .remember(
            &gcoms_routing::gc2::directory::BootstrapBundle {
                relays: vec![advertised.clone()],
            },
            super::now_unix(),
        )
        .expect("advertised introduction installs");
    assert_eq!(accepted, 1);

    // Without the option the relay answers the legacy card with no
    // advertisement (version-1 relays keep their behavior). A request ID is
    // bound to its options, so the negative uses a fresh request.
    let current = runtime.gc2.get().expect("carrier runtime");
    let relay_intro = introduction;
    let legacy = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            if let Ok(reply) = gcoms_routing::gc2::discovery::provision(
                &current.control,
                &relay_intro,
                rand::random::<[u8; 32]>(),
                &[],
                &[],
            )
            .await
            {
                return Ok::<_, String>(reply);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("legacy provisioning answers within the startup window")
    .expect("legacy provisioning answers");
    let (card, advertised) = NodeInfo::decode_private_any(&legacy).expect("legacy card decodes");
    assert_eq!(card.provisioning.as_ref().map(|p| p.aliases.len()), Some(2));
    assert!(advertised.is_none(), "legacy cards carry no advertisement");
}

/// Live-fabric probe: does a DEPLOYED relay answer the GCP2 inbox provisioning
/// request? Run explicitly with a freshly fetched GCRB v2 bundle:
///   GC2_PROBE_BUNDLE=/path/bundle.b64 cargo test -p gcoms-node --features experimental-gc2 --lib deployed_relay_probe -- --ignored
#[tokio::test]
#[ignore = "explicit live relay provisioning; requires separately authorized GC2_PROBE_BUNDLE"]
async fn deployed_relay_probe() {
    let path = std::env::var("GC2_PROBE_BUNDLE")
        .expect("GC2_PROBE_BUNDLE must name a file with a GCRB v2 base64 bundle");
    let raw = std::fs::read_to_string(path).expect("read bundle file");
    let bytes = gcoms_transport::decode_b64url(raw.trim()).expect("base64url bundle");
    let bundle = gcoms_routing::gc2::directory::BootstrapBundle::decode(&bytes)
        .expect("deployed bundle decodes");
    let intros: Vec<Vec<u8>> = bundle
        .relays
        .iter()
        .take(3)
        .map(|i| i.encode().unwrap().to_vec())
        .collect();
    assert_eq!(intros.len(), 3, "probe needs three fleet introductions");
    // Deployed relays are public addresses: use the production carrier profile
    // (public address policy), not the loopback fixture directory.
    let cfg = NodeConfig {
        seed: [11; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::Gc2Carrier(crate::node::Gc2CarrierProfile {
            directory: None,
            entries: 3,
            record_len: 4096,
            period_ms: 1000,
            cover_mode: gcoms_routing::gc2::CoverMode::Interactive,
            scheduler: crate::scheduler::SchedulerProfile::fixture(),
            introductions: intros,
        }),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    };
    let runtime = RoutingRuntime::new(RoutingConfig::default(), Directory::new(), true).unwrap();
    let prepared = super::gc2_bootstrap::prepare(&cfg, Some(&runtime))
        .expect("carrier prepare")
        .expect("carrier profile engages the runtime");
    let _owner_task = tokio::spawn(prepared.owner.run());
    let reply = tokio::time::timeout(std::time::Duration::from_secs(240), async {
        loop {
            if let Ok(reply) = runtime
                .provision_inbox(&[gcoms_protocol::proto::PROVISION_OPTION_GC2], &[], None)
                .await
            {
                return Ok::<_, String>(reply);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("GCP2 answers within the startup window")
    .expect("GCP2 provisioning answers");
    let (card, advertised) = NodeInfo::decode_private_any(&reply).expect("private card decodes");
    assert_eq!(
        card.provisioning.as_ref().map(|p| p.aliases.len()),
        Some(2),
        "the deployed relay mints normal and control aliases"
    );
    assert!(
        advertised.is_some(),
        "the deployed relay advertises its GC/2 introduction"
    );
}

#[tokio::test]
async fn client_bundle_install_seeds_only_the_carrier_directory() {
    let cfg = NodeConfig {
        seed: [19; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::gc2_carrier_qualification_fixture(None, 1, 19),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    };
    let node = start_with_routing(cfg, RoutingConfig::default())
        .await
        .unwrap();
    let carrier = node
        .state
        .upgrade()
        .unwrap()
        .lock()
        .unwrap()
        .gc2_carrier_directory
        .clone()
        .unwrap();
    let advertised = node
        .routing
        .as_ref()
        .unwrap()
        .service
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .gc2_directory()
        .clone();
    let before_advertised = advertised.reentry_candidates();
    let fresh = gc2_introduction_from(
        "127.0.0.81:65001".parse().unwrap(),
        [20; 32],
        &[21; 32],
        now_unix(),
    );
    let bundle = gcoms_routing::gc2::directory::BootstrapBundle {
        relays: vec![fresh.clone()],
    };
    assert_eq!(
        node.install_gc2_bootstrap(bundle.encode().unwrap().to_vec())
            .await
            .unwrap(),
        1
    );
    assert!(carrier.reentry_candidates().contains(&fresh));
    assert!(advertised.reentry_candidates() == before_advertised);
    let retained = carrier.reentry_candidates();
    assert!(node.install_gc2_bootstrap(vec![0xA5; 32]).await.is_err());
    let stale = gc2_introduction_from(
        "127.0.0.82:65002".parse().unwrap(),
        [22; 32],
        &[23; 32],
        now_unix().saturating_sub(4 * 3600),
    );
    let mixed = gcoms_routing::gc2::directory::BootstrapBundle {
        relays: vec![
            gc2_introduction_from(
                "127.0.0.83:65003".parse().unwrap(),
                [24; 32],
                &[25; 32],
                now_unix(),
            ),
            stale,
        ],
    };
    assert!(node
        .install_gc2_bootstrap(mixed.encode().unwrap().to_vec())
        .await
        .is_err());
    assert!(carrier.reentry_candidates() == retained);
    assert!(advertised.reentry_candidates() == before_advertised);
    node.shutdown().await;
}

#[tokio::test]
async fn client_bundle_install_refuses_a_non_gc2_node() {
    let cfg = NodeConfig {
        seed: [26; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::compressed_production(26),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    };
    let node = start(cfg).await.unwrap();
    let fresh = gc2_introduction_from(
        "127.0.0.84:65004".parse().unwrap(),
        [27; 32],
        &[28; 32],
        now_unix(),
    );
    let bundle = gcoms_routing::gc2::directory::BootstrapBundle {
        relays: vec![fresh],
    };
    let error = node
        .install_gc2_bootstrap(bundle.encode().unwrap().to_vec())
        .await
        .unwrap_err();
    assert_eq!(error, "GC/2 carrier directory is not enabled");
    node.shutdown().await;
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exhausted_retained_inbox_recovery_does_not_starve_replacement() {
    use std::time::Duration;
    use tokio::time::timeout;

    let config = |seed: u8| NodeConfig {
        seed: [seed; 32],
        listen: format!("127.0.0.{seed}:0").parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::gchat_file_transfer_fixture(2, u64::from(seed)),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    };
    let mut relays = Vec::new();
    for seed in 131..136 {
        relays.push(
            start_with_routing(config(seed), RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = gcoms_routing::gc2::directory::BootstrapBundle {
        relays: relays
            .iter()
            .map(|r| r.gc2_relay_introduction().unwrap())
            .collect(),
    };
    for relay in &relays {
        relay.install_gc2_routing_bootstrap(&bundle).unwrap();
    }
    let runtime = RoutingRuntime::new(
        RoutingConfig {
            gc2_bootstrap: Some(bundle),
            ..Default::default()
        },
        Directory::new(),
        true,
    )
    .unwrap();
    let prepared = super::super::gc2_bootstrap::prepare(&config(140), Some(&runtime))
        .unwrap()
        .unwrap();
    let ready = prepared.ready.clone();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let _ = prepared.owner.run().await;
    });
    timeout(Duration::from_secs(30), async {
        while ready.ready_entries() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("protected entries become ready");

    // The old inbox completes pinned TLS and reads the request, but never
    // answers it. A TLS-connect timeout must not masquerade as this full
    // administrative-request stall.
    let identity = TlsIdentity::generate().unwrap();
    let terminal = Tp1Server::bind_with_identity(
        "127.0.0.141:0".parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap();
    let old_target = RelayTarget {
        address: terminal.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let (observed, mut accepted) = tokio::sync::mpsc::channel(8);
    let terminal = terminal.with_dispatch_factory(Arc::new(move || {
        let observed = observed.clone();
        Arc::new(move |_, _| {
            let observed = observed.clone();
            gcoms_transport::server::Dispatch::Accepted(Box::new(move |mut body, response| {
                Box::pin(async move {
                    let request =
                        gcoms_transport::server::read_body(&mut body, gcoms_core::gc2::MAX_CELL)
                            .await
                            .unwrap();
                    assert!(!request.is_empty());
                    let _ = observed.send(()).await;
                    std::future::pending::<()>().await;
                    drop((body, response));
                })
            }))
        })
    }));
    tasks.spawn(async move {
        let _ = terminal.run().await;
    });
    let scheduler = RelayScheduler::gc2(ready).unwrap();
    let mut node = persist::tests::state();
    node.scheduler = scheduler.clone();
    node.gc2_carrier = Some(runtime.gc2.get().unwrap().ready.clone());
    node.gc2_carrier_directory = Some(runtime.gc2.get().unwrap().directory.clone());
    node.routing = Some(runtime.clone());
    let saved = Arc::new(Mutex::new(Vec::new()));
    let sink = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        *sink.lock().unwrap() = bytes;
        Ok(())
    }));
    let mut old_leases = crate::queues::LeaseStore::new(
        old_target.relay_service_id,
        crate::queues::StoreConfig::default(),
    )
    .unwrap();
    for alias in &mut node.client_relay.aliases {
        let grant = old_leases
            .issue_grant(
                GrantRequest {
                    queue_id: alias.contact.queue_id,
                    epoch: alias.contact.epoch,
                    limits: alias.limits,
                },
                now_unix(),
            )
            .unwrap();
        alias.contact.target = old_target.clone();
        alias.contact.expiry = now_unix() + 300;
        let create = LeaseCreate {
            queue_id: alias.contact.queue_id,
            epoch: alias.contact.epoch,
            lease_expiry: alias.contact.expiry,
            queue_cells: alias.limits.max_queue_cells,
            queue_bytes: alias.limits.max_queue_bytes,
            capabilities: alias.capabilities,
            nonce: rand::random(),
            grant: grant.wire,
        };
        let wire = create.encode(&old_target.relay_service_id).unwrap();
        old_leases.create_lease(&wire, now_unix()).unwrap();
        alias.create_path = encode_b64url(&grant.wire[49..81]);
        alias.lease_create = Cell::new(CellType::RelaySub, 0, 0, wire.to_vec());
    }
    node.info.aliases = node
        .client_relay
        .aliases
        .iter()
        .map(|a| a.contact.clone())
        .collect();
    let old = node.client_relay.clone();
    let state = Arc::new(Mutex::new(node));
    runtime.bind_state(&state).unwrap();
    let (events, _) = broadcast::channel(16);

    // The caller has exhausted the retained-recovery rounds. A still-hung old
    // terminal must not consume every subsequent round before failover starts.
    timeout(
        Duration::from_secs(45),
        recover_owner(&state, &scheduler, &events, &runtime, true),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "replacement must not wait on the exhausted retained route: old request observed={}, phase={:?}",
            accepted.try_recv().is_ok(), runtime.recovery_status.lock().unwrap()
        )
    })
    .expect("healthy protected relay provisions the replacement");
    assert!(
        matches!(
            accepted.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "exhausted recovery must not start another retained request"
    );
    {
        let st = state.lock().unwrap();
        assert_ne!(st.client_relay.aliases[0].contact.target, old_target);
        assert_eq!(
            st.unannounced_old_contact_aliases.as_ref(),
            Some(&old.aliases)
        );
        assert!(!st.owner_transition_failed);
        assert!(
            !saved.lock().unwrap().is_empty(),
            "replacement commits before publication"
        );
    }
    scheduler.shutdown();
    tasks.shutdown().await;
    for relay in relays {
        relay.shutdown().await;
    }
}
