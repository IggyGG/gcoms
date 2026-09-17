#![cfg(feature = "client-persist")]
use gcoms_node::{
    connectivity::{ConnectivityConfig, PortState},
    node::{start_persistent_restored_with_routing, NodeConfig, NodeProfile, RoutingConfig},
};
use std::sync::{Arc, Mutex};

fn config() -> NodeConfig {
    NodeConfig {
        seed: [103; 32],
        listen: "127.239.27.31:0".parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::fixture(),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_restart_reuses_port_then_survives_collision_without_identity_reset() {
    let path = std::env::temp_dir().join(format!("gc-auto-restart-{:016x}", rand::random::<u64>()));
    let archive = Arc::new(Mutex::new(Vec::new()));
    let sink = archive.clone();
    let routing = || RoutingConfig {
        connectivity: Some(ConnectivityConfig {
            state: Some(Arc::new(PortState::open(&path, &[103; 32]).unwrap())),
            mapping: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    let first = start_persistent_restored_with_routing(
        config(),
        routing(),
        Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }),
        None,
    )
    .await
    .unwrap();
    let initial_port = first.listener_addr();
    let identity = first.info.identity_pk.clone();
    let tls = first.relay_introduction().unwrap().service_id;
    let state = first.export_state().await.unwrap();
    first.shutdown().await;
    let sink = archive.clone();
    let second = start_persistent_restored_with_routing(
        config(),
        routing(),
        Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }),
        Some(&state),
    )
    .await
    .unwrap();
    assert_eq!(second.listener_addr(), initial_port);
    assert_eq!(second.info.identity_pk, identity);
    assert_eq!(second.relay_introduction().unwrap().service_id, tls);
    let state = second.export_state().await.unwrap();
    second.shutdown().await;
    let occupied = tokio::net::TcpListener::bind(initial_port).await.unwrap();
    let sink = archive.clone();
    let third = start_persistent_restored_with_routing(
        config(),
        routing(),
        Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }),
        Some(&state),
    )
    .await
    .unwrap();
    assert_ne!(third.listener_addr(), initial_port);
    assert_eq!(third.info.identity_pk, identity);
    assert_eq!(third.relay_introduction().unwrap().service_id, tls);
    assert!(
        !third.relay_published(),
        "no independent relay has authenticated this listener"
    );
    assert!(!archive.lock().unwrap().is_empty());
    third.shutdown().await;
    drop(occupied);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn fixed_mode_reports_collision_without_selecting_another_port() {
    let occupied = tokio::net::TcpListener::bind("127.239.27.32:0")
        .await
        .unwrap();
    let mut cfg = config();
    cfg.listen = occupied.local_addr().unwrap();
    let result = gcoms_node::node::start_with_routing(cfg, RoutingConfig::default()).await;
    assert!(result.is_err());
    assert!(
        tokio::net::TcpStream::connect(occupied.local_addr().unwrap())
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_listener_is_admitted_only_after_an_independent_pinned_probe() {
    use gcoms_routing::bootstrap::BootstrapBundle;
    use std::time::Duration;
    let mut relays = Vec::new();
    for n in 40..44 {
        let mut cfg = config();
        cfg.seed = [n; 32];
        cfg.listen = format!("127.239.27.{n}:0").parse().unwrap();
        relays.push(
            gcoms_node::node::start_with_routing(cfg, RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = BootstrapBundle {
        relays: relays
            .iter()
            .map(|r| r.relay_introduction().unwrap())
            .collect(),
    };
    for relay in &relays {
        relay
            .install_routing_bootstrap(bundle.clone())
            .await
            .unwrap();
    }
    let mut cfg = config();
    cfg.listen = "127.239.27.33:0".parse().unwrap();
    let node = gcoms_node::node::start_with_routing(
        cfg,
        RoutingConfig {
            connectivity: Some(ConnectivityConfig {
                mapping: false,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!node.relay_published());
    assert!(node.local_relay_introduction().unwrap().is_none());
    let original = node.relay_introduction().unwrap();
    node.install_routing_bootstrap(bundle).await.unwrap();
    tokio::time::timeout(Duration::from_secs(25), async {
        while !node.relay_published() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("independent pinned probe must admit reachable full node");
    assert_eq!(
        node.relay_introduction().unwrap().service_id,
        original.service_id
    );
    let proof = node.local_relay_introduction().unwrap().unwrap();
    assert_eq!(
        proof.relays.len(),
        1,
        "local proof must not include bootstrap peers"
    );
    assert_eq!(proof.relays[0].addr, node.listener_addr());
    assert_eq!(proof.relays[0].service_id, original.service_id);
    let encoded = proof.encode().unwrap();
    assert_eq!(BootstrapBundle::decode(&encoded).unwrap().relays.len(), 1);
    node.shutdown().await;
    assert!(!node.relay_published());
    assert!(node.local_relay_introduction().unwrap().is_none());
    for relay in relays {
        relay.shutdown().await;
    }
}
