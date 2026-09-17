#![cfg(feature = "client-persist")]
use gcoms_node::node::{
    start_persistent_restored_with_routing, start_with_routing, NodeConfig, NodeHandle,
    NodeProfile, RoutingConfig,
};
use gcoms_routing::bootstrap::BootstrapBundle;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
static NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn config(seed: u8, ip: u8) -> NodeConfig {
    NodeConfig {
        seed: [seed; 32],
        listen: format!("127.0.0.{ip}:0").parse().unwrap(),
        control: None,
        advertise: None,
        profile: NodeProfile::fixture(),
        inbox_relay: None,
        alias_lifecycle: Default::default(),
    }
}

async fn ready(node: &NodeHandle) -> gcoms_node::proto::NodeInfo {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let info = node.current_info().await.unwrap();
            if info.aliases.len() == 2 {
                return info;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("inbox recovery")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_durable_acceptance_survives_restart_then_delivers_over_relays() {
    let _network = NETWORK.lock().await;
    let mut relays = Vec::new();
    for n in 2..6 {
        relays.push(
            start_with_routing(config(n, n), RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = BootstrapBundle {
        relays: relays
            .iter()
            .map(|n| n.relay_introduction().unwrap())
            .collect(),
    };
    for relay in &relays {
        relay
            .install_routing_bootstrap(bundle.clone())
            .await
            .unwrap();
    }
    let received_archive = Arc::new(Mutex::new(Vec::new()));
    let sink = received_archive.clone();
    let receiver = start_persistent_restored_with_routing(
        config(20, 20),
        RoutingConfig {
            bootstrap: Some(bundle.clone()),
            ..Default::default()
        },
        Arc::new(move |bytes| {
            *sink.lock().unwrap() = bytes;
            Ok(())
        }),
        None,
    )
    .await
    .unwrap();
    receiver.enable_durable_applications().await.unwrap();
    let contact = ready(&receiver).await;
    assert!(contact
        .aliases
        .iter()
        .all(|a| a.target.address.ip() != "127.0.0.20".parse::<std::net::IpAddr>().unwrap()));

    let archive = Arc::new(Mutex::new(Vec::new()));
    let sink = archive.clone();
    let sender = tokio::time::timeout(
        Duration::from_secs(2),
        start_persistent_restored_with_routing(
            config(21, 21),
            RoutingConfig::default(),
            Arc::new(move |bytes| {
                *sink.lock().unwrap() = bytes;
                Ok(())
            }),
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(sender.info.aliases.is_empty());
    sender.enable_durable_applications().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        sender.send_durable_1to1(&contact, b"offline durable application", None),
    )
    .await
    .unwrap()
    .unwrap();
    let saved = archive.lock().unwrap().clone();
    assert_eq!(&saved[..6], b"GCNSTI");
    sender.shutdown().await;
    let sink = archive.clone();
    let sender = tokio::time::timeout(
        Duration::from_secs(2),
        start_persistent_restored_with_routing(
            config(21, 21),
            RoutingConfig::default(),
            Arc::new(move |bytes| {
                *sink.lock().unwrap() = bytes;
                Ok(())
            }),
            Some(&saved),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(sender.info.aliases.is_empty());
    sender.enable_durable_applications().await.unwrap();
    sender.install_routing_bootstrap(bundle).await.unwrap();
    ready(&sender).await;
    let deliveries = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let entries = receiver.application_inbox(0, 10).await.unwrap();
            if !entries.is_empty() {
                return entries;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("deferred application delivery");
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].body, b"offline durable application");
    sender.shutdown().await;
    receiver.shutdown().await;
    for relay in relays {
        relay.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_owner_and_channel_load_offline_without_replacing_receive_contacts() {
    let _network = NETWORK.lock().await;
    let mut relays = Vec::new();
    for n in 2..6 {
        relays.push(
            start_with_routing(config(n, n), RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = BootstrapBundle {
        relays: relays
            .iter()
            .map(|n| n.relay_introduction().unwrap())
            .collect(),
    };
    for relay in &relays {
        relay
            .install_routing_bootstrap(bundle.clone())
            .await
            .unwrap();
    }
    let mut legacy_config = config(30, 30);
    legacy_config.inbox_relay = Some(relays[0].provision_client_relay().await.unwrap());
    let legacy = gcoms_node::node::start_persistent(legacy_config, Arc::new(|_| Ok(())))
        .await
        .unwrap();
    let before = legacy.current_info().await.unwrap();
    legacy
        .create_channel(
            "retained",
            "owner",
            8,
            gcoms_node::channel::ChannelVisibility::Private,
        )
        .await
        .unwrap();
    let roster = legacy.channel_roster("retained").await.unwrap();
    let saved = legacy.export_state().await.unwrap();
    assert_eq!(&saved[..6], b"GCNSTI");
    legacy.shutdown().await;
    let restored = tokio::time::timeout(
        Duration::from_secs(2),
        start_persistent_restored_with_routing(
            config(30, 30),
            RoutingConfig::default(),
            Arc::new(|_| Ok(())),
            Some(&saved),
        ),
    )
    .await
    .expect("offline retained local startup")
    .unwrap();
    assert_eq!(
        restored.current_info().await.unwrap().aliases,
        before.aliases
    );
    assert_eq!(restored.channel_roster("retained").await.unwrap(), roster);
    assert_eq!(restored.list_channels().await.unwrap().len(), 1);
    // Archive18 retains the existing owned channel grant even while discovery
    // is offline. Historical15's missing-grant/pending case is covered by the
    // synthetic archive compatibility tests in the native persistence module.
    let offline = restored.export_state().await.unwrap();
    assert_eq!(&offline[..6], b"GCNSTI");
    restored.shutdown().await;
    let restored = start_persistent_restored_with_routing(
        config(30, 30),
        RoutingConfig {
            bootstrap: Some(bundle),
            ..Default::default()
        },
        Arc::new(|_| Ok(())),
        Some(&offline),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if restored
                .send_channel_text("retained", b"after recovery")
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("channel route recovery");
    assert_eq!(
        restored.current_info().await.unwrap().aliases,
        before.aliases,
        "original queue IDs, epochs, capabilities and expiry must survive"
    );
    assert_eq!(restored.channel_roster("retained").await.unwrap(), roster);
    restored.shutdown().await;
    for relay in relays {
        relay.shutdown().await;
    }
}
