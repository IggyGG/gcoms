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
) -> (gcoms_routing::gc2::directory::Introduction, tokio::task::JoinHandle<()>) {
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
            vec![
                introduction.encode().unwrap().to_vec(),
                middle.encode().unwrap().to_vec(),
                third.encode().unwrap().to_vec(),
            ],
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
                .provision_inbox(
                    &[gcoms_protocol::proto::PROVISION_OPTION_GC2],
                    &[],
                    None,
                )
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
    let (card, advertised) =
        NodeInfo::decode_private_any(&reply).expect("private card decodes");
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
    let (card, advertised) =
        NodeInfo::decode_private_any(&legacy).expect("legacy card decodes");
    assert_eq!(
        card.provisioning.as_ref().map(|p| p.aliases.len()),
        Some(2)
    );
    assert!(advertised.is_none(), "legacy cards carry no advertisement");
}

/// Live-fabric probe: does a DEPLOYED relay answer the GCP2 inbox provisioning
/// request? Run explicitly with a freshly fetched GCRB v2 bundle:
///   GC2_PROBE_BUNDLE=/path/bundle.b64 cargo test -p gcoms-node --features experimental-gc2 --lib deployed_relay_probe
#[tokio::test]
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
                .provision_inbox(
                    &[gcoms_protocol::proto::PROVISION_OPTION_GC2],
                    &[],
                    None,
                )
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
    let (card, advertised) =
        NodeInfo::decode_private_any(&reply).expect("private card decodes");
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
