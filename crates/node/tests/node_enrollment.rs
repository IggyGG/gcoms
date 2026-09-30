//! Actual protected-session enrollment on confined loopback relays. This is not
//! a production-network, platform UI, or long-lived descriptor receipt.
#![cfg(feature = "client-persist")]
use gcoms_core::invitation::{EnrollmentPhase, InvitationPolicy};
use gcoms_node::{
    channel::ChannelVisibility,
    channel_invite::{ChannelInvite, InviteEnvelope},
    node::{NodeConfig, NodeHandle, NodeProfile},
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn config(seed: u8, port: u16) -> NodeConfig {
    NodeConfig {
        seed: [seed; 32],
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    }
}
async fn spawn(
    seed: u8,
    port: u16,
    saved: Arc<Mutex<Vec<u8>>>,
    initial: Option<&[u8]>,
) -> NodeHandle {
    gcoms_node::node::start_persistent_restored(
        config(seed, port),
        None,
        Arc::new(move |bytes| {
            *saved.lock().unwrap() = bytes;
            Ok(())
        }),
        initial,
    )
    .await
    .unwrap()
}
fn port(node: &NodeHandle) -> u16 {
    node.info.aliases[0].target.address.port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reusable_enrollment_waits_for_owner_and_survives_both_restarts() {
    let metrics = tempfile::tempdir().unwrap();
    gcoms_node::metrics::init(&metrics.path().join("enrollment.jsonl")).unwrap();
    let owner_saved = Arc::new(Mutex::new(Vec::new()));
    let mut owner = spawn(81, 0, owner_saved.clone(), None).await;
    let owner_port = port(&owner);
    owner
        .create_channel("friends", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let policy = InvitationPolicy {
        expires_at: None,
        max_admissions: Some(3),
    };
    let issued = owner
        .create_reusable_invitation("friends", policy)
        .await
        .unwrap();
    let invite = ChannelInvite {
        owner: owner.current_info().await.unwrap(),
        channel: "friends".into(),
        id: issued.summary.id,
        secret: issued.secret,
        expiry: u64::MAX,
    };
    let mut envelope =
        InviteEnvelope::from_link(&owner.channel_invite_link(&invite).unwrap()).unwrap();
    envelope.policy = Some(policy);
    let link = envelope.to_link().unwrap();

    let member_saved = Arc::new(Mutex::new(Vec::new()));
    let mut member = spawn(82, 0, member_saved.clone(), None).await;
    let member_port = port(&member);
    let operation = member.start_enrollment(&link, "alice").await.unwrap();
    assert_eq!(
        member.start_enrollment(&link, "alice").await.unwrap().id,
        operation.id
    );
    let member_archive = member.export_state().await.unwrap();
    member.shutdown().await;
    assert!(!member_archive.is_empty());

    member = spawn(82, member_port, member_saved, Some(&member_archive)).await;
    assert_eq!(
        member.enrollment_status(operation.id).await.unwrap().id,
        operation.id
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(75);
    loop {
        let status = member.enrollment_status(operation.id).await.unwrap();
        if status.phase == EnrollmentPhase::Joined {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "enrollment did not finish: {status:?}; diagnostics: {}",
            std::fs::read_to_string(metrics.path().join("enrollment.jsonl")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let summaries = owner.list_invitations("friends").await.unwrap();
    assert_eq!(summaries[0].admissions, 1);
    assert_eq!(member.list_channels().await.unwrap().len(), 1);
    owner
        .revoke_invitation("friends", issued.summary.id)
        .await
        .unwrap();
    let owner_archive = owner.export_state().await.unwrap();
    owner.shutdown().await;
    owner = spawn(81, owner_port, owner_saved, Some(&owner_archive)).await;
    let joined = member.export_state().await.unwrap();
    member.shutdown().await;
    member = spawn(
        82,
        member_port,
        Arc::new(Mutex::new(Vec::new())),
        Some(&joined),
    )
    .await;
    assert_eq!(
        member.enrollment_status(operation.id).await.unwrap().phase,
        EnrollmentPhase::Joined
    );
    assert_eq!(member.list_channels().await.unwrap().len(), 1);
    owner.shutdown().await;
    member.shutdown().await;
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reusable_enrollment_uses_current_gc2_carriers_for_both_members() {
    let metrics = tempfile::tempdir().unwrap();
    let metrics_path = metrics.path().join("gc2-enrollment.jsonl");
    gcoms_node::metrics::init(&metrics_path).unwrap();
    let started = tokio::time::Instant::now();
    use gcoms_node::node::{
        start_persistent_restored_with_routing, start_with_routing, Ev, RoutingConfig,
    };
    use gcoms_routing::gc2::directory::BootstrapBundle;
    let config = |seed: u8| NodeConfig {
        listen: format!("127.0.0.{seed}:0").parse().unwrap(),
        profile: NodeProfile::gchat_file_transfer_fixture(2, u64::from(seed)),
        ..config(seed, 0)
    };
    let mut relays = Vec::new();
    for seed in 101..107 {
        relays.push(
            start_with_routing(config(seed), RoutingConfig::default())
                .await
                .unwrap(),
        );
    }
    let bundle = BootstrapBundle {
        relays: relays
            .iter()
            .map(|r| r.gc2_relay_introduction().unwrap())
            .collect(),
    };
    for r in &relays {
        r.install_gc2_routing_bootstrap(&bundle).unwrap();
    }
    let mut clients = Vec::new();
    for seed in 107..110 {
        let saved = Arc::new(Mutex::new(Vec::new()));
        clients.push(
            start_persistent_restored_with_routing(
                config(seed),
                RoutingConfig {
                    gc2_bootstrap: Some(bundle.clone()),
                    ..Default::default()
                },
                Arc::new(move |bytes| {
                    *saved.lock().unwrap() = bytes;
                    Ok(())
                }),
                None,
            )
            .await
            .unwrap(),
        );
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
    for c in &clients {
        c.wait_for_inbox(deadline).await.unwrap();
    }
    eprintln!("all current inboxes ready after {:?}", started.elapsed());
    let owner = &clients[0];
    owner
        .create_channel("devices", "operator", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let policy = InvitationPolicy {
        expires_at: None,
        max_admissions: Some(2),
    };
    let issued = owner
        .create_reusable_invitation("devices", policy)
        .await
        .unwrap();
    let invite = ChannelInvite {
        owner: owner.current_info().await.unwrap(),
        channel: "devices".into(),
        id: issued.summary.id,
        secret: issued.secret,
        expiry: u64::MAX,
    };
    let mut envelope =
        InviteEnvelope::from_link(&owner.channel_invite_link(&invite).unwrap()).unwrap();
    assert!(envelope.bootstrap.is_none());
    assert!(envelope.gc2_bootstrap.is_some());
    envelope.policy = Some(policy);
    let link = envelope.to_link().unwrap();
    let first = clients[1]
        .start_enrollment(&link, "device-a")
        .await
        .unwrap();
    let second = clients[2]
        .start_enrollment(&link, "device-b")
        .await
        .unwrap();
    for (client, op) in [(&clients[1], first), (&clients[2], second)] {
        loop {
            let status = client.enrollment_status(op.id).await.unwrap();
            if status.phase == EnrollmentPhase::Joined {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{status:?}; diagnostics: {}",
                std::fs::read_to_string(&metrics_path).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    eprintln!(
        "both durable enrollments completed after {:?}",
        started.elapsed()
    );
    owner
        .send_channel_text("devices", b"authenticated operator round trip")
        .await
        .unwrap();
    for c in &clients[1..] {
        tokio::time::timeout_at(deadline, async {
            loop {
                if let Some(Ev::ChannelMessage {
                    text,
                    sender,
                    channel,
                    ..
                }) = c.next_event().await
                {
                    if text == b"authenticated operator round trip" {
                        assert_eq!(sender, "operator");
                        assert_eq!(channel, "devices");
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(c.transport_status().protocol, "gchat");
        assert!(c
            .change_channel(
                "devices",
                gcoms_node::channel::ChannelChange::Topic("unauthorized".into())
            )
            .await
            .is_err());
        let own = c
            .channel_roster("devices")
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.is_self)
            .unwrap();
        let reply = format!("reply from {}", own.display_name);
        c.send_channel_text("devices", reply.as_bytes())
            .await
            .unwrap();
        tokio::time::timeout_at(deadline, async {
            loop {
                if let Some(Ev::ChannelMessage { text, sender, .. }) = owner.next_event().await {
                    if text == reply.as_bytes() {
                        assert_eq!(sender, own.display_name);
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
    }
    assert_eq!(
        owner.list_invitations("devices").await.unwrap()[0].admissions,
        2
    );
    eprintln!(
        "both authenticated round trips completed after {:?}",
        started.elapsed()
    );
    for c in clients {
        c.shutdown().await;
    }
    for r in relays {
        r.shutdown().await;
    }
}
