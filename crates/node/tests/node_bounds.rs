//! A node flooded with channel traffic to unreachable members stays bounded.
//!
//! The internal caps (per-id forward queue <= 256 entries / 4 MiB,
//! `MAX_LANES` = 64) are proven directly by lib-level unit tests in
//! `channel.rs`, `scheduler.rs`, and `queues.rs`. This file proves the
//! black-box consequence a friend's node depends on: after thousands of
//! channel sends whose members went away, the node has not fallen over — it
//! still answers `current_info` promptly, its intermediary stats stay bounded,
//! and it remains usable for a fresh delivery.

use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, NodeConfig, NodeHandle, NodeProfile};

async fn spawn(seed: u8) -> NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start")
}

async fn admit(owner: &NodeHandle, channel: &str, member: &NodeHandle, name: &str) {
    let req = member.prepare_channel_join(name).await.expect("prepare");
    let kp = member.channel_key_package(req).await.expect("kp");
    let welcome = owner
        .admit_channel(channel, &kp, name)
        .await
        .expect("admit");
    member
        .join_channel(req, channel, ChannelVisibility::Private, &welcome)
        .await
        .expect("join");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flood_to_unreachable_members_leaves_the_node_bounded_and_live() {
    let owner = spawn(0x01).await;
    owner
        .create_channel("ops", "founder", 64, ChannelVisibility::Private)
        .await
        .expect("create");

    // Admit three members, then take them offline so all subsequent channel
    // traffic addressed to them piles into the owner's forward path.
    let mut members = Vec::new();
    for i in 0..3u8 {
        let m = spawn(0x20 + i).await;
        admit(&owner, "ops", &m, &format!("m{i}")).await;
        members.push(m);
    }
    // Wait for the roster to include everyone before they vanish.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let roster = owner.channel_roster("ops").await.expect("roster");
        if roster.len() == 4 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "roster never converged"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    for m in members {
        m.shutdown().await;
    }

    let stats_before = owner.intermediary_stats().await.expect("stats before");

    // Flood: ~2000 channel sends to now-unreachable members.
    for i in 0..2000u32 {
        // A send may legitimately fail once internal queues are saturated; the
        // invariant is that the node neither panics nor wedges, not that every
        // send is accepted.
        let _ = owner
            .send_channel_text("ops", format!("flood-{i}").as_bytes())
            .await;
    }

    // The node still answers promptly under the accumulated backlog.
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..20 {
        let t0 = std::time::Instant::now();
        owner
            .current_info()
            .await
            .expect("current_info after flood");
        worst = worst.max(t0.elapsed());
    }
    assert!(
        worst < std::time::Duration::from_millis(500),
        "node unresponsive after flood: worst current_info {worst:?}"
    );

    // Intermediary state stayed bounded: the grant pool and active set cannot
    // exceed their caps regardless of traffic (MAX_FORWARD_GRANTS / LANE_SET).
    let stats_after = owner.intermediary_stats().await.expect("stats after");
    assert!(
        stats_after.pool <= 256,
        "grant pool exceeded MAX_FORWARD_GRANTS: {}",
        stats_after.pool
    );
    assert!(
        stats_after.active <= 8,
        "active intermediary set exceeded its cap: {}",
        stats_after.active
    );
    // Nothing about the flood should have grown the pool at all (no new peers).
    assert!(
        stats_after.pool <= stats_before.pool.max(256),
        "pool grew unexpectedly under flood"
    );

    // The node is still usable for a fresh delivery. A 1:1 message avoids the
    // channel-convergence gate (the dead members are still in the roster, so a
    // new admit would legitimately block on their acks — not a bounds issue).
    let fresh = spawn(0x40).await;
    let fresh_info = fresh.current_info().await.expect("fresh info");
    owner
        .send_1to1(&fresh_info, b"post-flood delivery", None)
        .await
        .expect("send 1to1 after flood");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let delivered = tokio::time::timeout_at(deadline, async {
        loop {
            if let Some(gcoms_node::node::Ev::Message { text, .. }) = fresh.next_event().await {
                if text == b"post-flood delivery" {
                    return true;
                }
            }
        }
    })
    .await;
    assert!(
        delivered.is_ok(),
        "fresh peer never received a post-flood message"
    );

    fresh.shutdown().await;
    owner.shutdown().await;
}
