//! Local multi-node end-to-end resilience — the "before sharing" rehearsal.
//!
//! The container/distinct-IP form of this (Production profile on real IPs) is
//! `scripts/local-e2e.sh`; this in-process form covers the two failure modes a
//! friend group will actually hit, on loopback fixtures:
//!
//!   1. a node is killed mid-session while others keep working — the survivors
//!      must stay responsive and keep delivering, never wedge waiting on it;
//!   2. a killed node's peers heal (a fresh 1:1 to a live peer still lands).
//!
//! Restart-survives-a-dropped-frame is already proven by
//! `node_1to1::restored_direct_session_propagates_fresh_route_without_card_exchange`;
//! this file is the multi-party liveness complement.

use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, Ev, NodeConfig, NodeHandle, NodeProfile};

async fn spawn(seed: u8) -> NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::compressed_production(u64::from(seed)),
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

async fn await_chan(h: &NodeHandle, channel: &str, want: &[u8]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let ev = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {}", String::from_utf8_lossy(want)))
            .expect("node ended");
        if let Ev::ChannelMessage {
            channel: c, text, ..
        } = ev
        {
            if c == channel && text == want {
                return;
            }
        }
    }
}

async fn await_direct(h: &NodeHandle, want: &[u8]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let ev = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "timeout waiting for direct {}",
                    String::from_utf8_lossy(want)
                )
            })
            .expect("node ended");
        if let Ev::Message { text, .. } = ev {
            if text == want {
                return;
            }
        }
    }
}

/// A three-member channel keeps working for the survivors after one member's
/// node is killed: the owner still answers control calls promptly, a broadcast
/// still reaches the remaining live member, and a fresh 1:1 to a live peer
/// still lands. The node must not wedge waiting on the departed member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn survivors_stay_live_and_deliver_after_a_node_is_killed() {
    let owner = spawn(0x01).await;
    owner
        .create_channel("ops", "founder", 64, ChannelVisibility::Private)
        .await
        .expect("create");

    let alice = spawn(0x11).await;
    let bob = spawn(0x12).await;
    admit(&owner, "ops", &alice, "alice").await;
    admit(&owner, "ops", &bob, "bob").await;

    // Roster converges to 3 (owner + alice + bob).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let roster = owner.channel_roster("ops").await.expect("roster");
        if roster.len() == 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "roster never reached 3"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // Baseline: a broadcast reaches both members.
    owner
        .send_channel_text("ops", b"before kill")
        .await
        .expect("broadcast");
    await_chan(&alice, "ops", b"before kill").await;
    await_chan(&bob, "ops", b"before kill").await;

    // Kill bob's node mid-session.
    bob.shutdown().await;

    // The owner must stay responsive immediately after the kill — no wedge
    // waiting on the departed member.
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..10 {
        let t0 = std::time::Instant::now();
        owner
            .current_info()
            .await
            .expect("owner responsive after kill");
        worst = worst.max(t0.elapsed());
    }
    assert!(
        worst < std::time::Duration::from_millis(500),
        "owner stalled after a member was killed: worst {worst:?}"
    );

    // A broadcast after the kill still reaches the surviving member. (The dead
    // member simply never acks; delivery to the live member must not block on
    // it.)
    // The existing API reports a partial transport refusal for the departed
    // target. The liveness contract is delivery to Alice, which is checked
    // independently below, not complete success for all roster members.
    if let Err(error) = owner.send_channel_text("ops", b"after kill").await {
        assert_eq!(error, "channel send failed for 1 target(s)");
    }
    await_chan(&alice, "ops", b"after kill").await;

    // And a fresh direct message between two live peers still lands.
    let alice_info = alice.current_info().await.expect("alice info");
    owner
        .send_1to1(&alice_info, b"direct after kill", None)
        .await
        .expect("direct after kill");
    await_direct(&alice, b"direct after kill").await;

    owner.shutdown().await;
    alice.shutdown().await;
}
