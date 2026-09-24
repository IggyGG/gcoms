#![cfg(all(feature = "experimental-gc2", feature = "client-persist"))]
//! Cold GCRB2 startup, real protected circuits, and the channel application path
//! used by GChat's piece exchange. No direct application fallback is available.
use gcoms_node::{
    channel::ChannelVisibility,
    node::{start_with_routing, Ev, NodeConfig, NodeProfile, RoutingConfig},
    NodeHandle,
};
use gcoms_routing::gc2::directory::BootstrapBundle;
use std::time::Duration;

fn config(seed: u8) -> NodeConfig {
    NodeConfig {
        seed: [seed; 32],
        listen: format!("127.0.0.{seed}:0").parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        alias_lifecycle: Default::default(),
        profile: NodeProfile::gchat_file_transfer_fixture(2, u64::from(seed)),
    }
}
async fn ready(node: &NodeHandle) {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if node.transport_status().routing_ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("routing not ready: {:?}", node.transport_status()));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_bootstrap_provisions_and_delivers_channel_file_as_authenticated_bulk() {
    tokio::time::timeout(Duration::from_secs(270), scenario())
        .await
        .expect("cold-start scenario deadline");
}

async fn scenario() {
    let scratch = tempfile::tempdir().unwrap();
    let metrics = scratch.path().join("metrics.jsonl");
    gcoms_node::metrics::init(&metrics).unwrap();
    let mut relays = Vec::new();
    for seed in 71..77 {
        relays.push(
            start_with_routing(config(seed), RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = BootstrapBundle {
        relays: relays
            .iter()
            .map(|relay| relay.gc2_relay_introduction().unwrap())
            .collect(),
    };
    let encoded = bundle.encode().unwrap();
    assert_eq!(&encoded[..5], b"GCRB\x02");
    for relay in &relays {
        relay.install_gc2_routing_bootstrap(&bundle).unwrap();
    }
    let routing = || RoutingConfig {
        gc2_bootstrap: Some(BootstrapBundle::decode(&encoded).unwrap()),
        ..Default::default()
    };
    let sender = start_with_routing(config(77), routing()).await.unwrap();
    let receiver = start_with_routing(config(78), routing()).await.unwrap();
    sender.enable_diagnostics();
    receiver.enable_diagnostics();
    tokio::join!(ready(&sender), ready(&receiver));
    eprintln!("clients ready");
    assert!(sender
        .install_routing_bootstrap(gcoms_routing::bootstrap::BootstrapBundle {
            relays: relays
                .iter()
                .map(|r| r.relay_introduction().unwrap())
                .collect()
        })
        .await
        .is_err());
    sender
        .create_channel("files", "sender", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    eprintln!("channel created");
    // Exercise the actual shareable invitation path. Direct owner admission
    // bypasses bootstrap export and previously hid a legacy-directory lookup.
    let (id, secret, expiry) = sender.create_channel_invite("files", 240).await.unwrap();
    let invitation = gcoms_node::channel_invite::ChannelInvite {
        owner: sender.current_info().await.unwrap(),
        channel: "files".into(),
        id,
        secret,
        expiry,
    };
    let link = sender.channel_invite_link(&invitation).unwrap();
    let envelope = gcoms_node::channel_invite::InviteEnvelope::from_link(&link).unwrap();
    assert!(envelope.bootstrap.is_none());
    assert!(envelope.gc2_bootstrap.is_some());
    receiver.install_invite_bootstrap(&envelope).await.unwrap();
    receiver
        .wait_for_inbox(tokio::time::Instant::now() + Duration::from_secs(90))
        .await
        .unwrap();
    let request = receiver
        .prepare_channel_join("receiver")
        .await
        .unwrap_or_else(|error| panic!("prepare join: {error}; {:?}", receiver.transport_status()));
    eprintln!("join prepared");
    let package = receiver.channel_key_package(request).await.unwrap();
    let welcome = receiver
        .redeem_invite_remote(
            envelope.invite.owner,
            "files",
            "receiver",
            &package,
            id,
            secret,
            90,
        )
        .await
        .unwrap();
    eprintln!("member admitted");
    receiver
        .join_channel(request, "files", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    eprintln!("member joined");
    let member = sender
        .channel_roster("files")
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.display_name == "receiver")
        .unwrap()
        .member_id;
    let content = gcoms_core::PIECE_CONTENT_TYPE.as_bytes();
    let mut payload = b"GCAPP1".to_vec();
    payload.extend_from_slice(&(content.len() as u16).to_be_bytes());
    payload.extend_from_slice(content);
    payload.extend_from_slice(&vec![43; 11 * 1024]);
    let received = tokio::time::timeout(Duration::from_secs(90), async {
        // Membership directory announcements use interactive traffic. Wait for
        // their ordinary receipt before the independent bulk payload.
        sender.send_channel_text("files", b"ready").await.unwrap();
        loop {
            if let Some(Ev::ChannelMessage { text, .. }) = receiver.next_event().await {
                if text == b"ready" {
                    break;
                }
            }
        }
        sender
            .send_channel_direct("files", member, &payload)
            .await
            .unwrap();
        loop {
            if let Some(Ev::ChannelDirectMessage { text, .. }) = receiver.next_event().await {
                break text;
            }
        }
    })
    .await
    .expect("channel application delivery");
    assert_eq!(received, payload);
    let status = receiver.transport_status();
    assert_eq!(status.protocol, "gchat");
    assert_eq!(status.bootstrap_version, Some(2));
    assert_eq!(
        status.profile_id,
        Some(gcoms_routing::gc2::RESPONSIVE_PROFILE)
    );
    assert!(status.bulk_subscriptions >= 4, "{status:?}");
    assert!(status.usable_terminal_routes > 0);
    // Cross a complete subscription lifetime without reprovisioning healthy
    // inboxes. Each class must renew using its current authority.
    for _ in 0..70 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !sender.transport_status().recovering_inbox,
            "healthy sender entered recovery"
        );
        assert!(
            !receiver.transport_status().recovering_inbox,
            "healthy receiver entered recovery"
        );
    }
    tokio::join!(ready(&sender), ready(&receiver));
    sender
        .send_channel_direct("files", member, &payload)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(Ev::ChannelDirectMessage { text, .. }) = receiver.next_event().await {
                assert_eq!(text, payload);
                break;
            }
        }
    })
    .await
    .expect("file after subscription renewal");
    sender.shutdown().await;
    receiver.shutdown().await;
    for relay in relays {
        relay.shutdown().await;
    }
    // The terminal observes the class only after authenticating the envelope.
    // Delivery plus subscribed Bulk inboxes alone would not prove file traffic
    // actually used its reserved class.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let accepted = std::fs::read_to_string(&metrics)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|event| event["event"] == "gchat_push_accepted" && event["class"] == "Bulk")
                .count();
            if accepted >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both file sends must reach an authenticated Bulk queue");
}
