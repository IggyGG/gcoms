//! The command loop must never serialize behind a slow operation.
//!
//! Before the keyed-dispatch fix (commit 362335b / the Phase 6 hardening) a
//! single `admit_channel` that awaited membership acks could block the whole
//! Cmd loop for up to the convergence timeout, freezing unrelated calls like
//! `current_info`. This test drives several admissions plus channel and direct
//! sends concurrently and asserts a `current_info` round-trip stays fast while
//! an admit is in flight.

use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, NodeConfig, NodeHandle, NodeProfile};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_info_stays_responsive_while_admissions_and_sends_are_in_flight() {
    let owner = std::sync::Arc::new(spawn(0x01).await);
    owner
        .create_channel("ops", "founder", 64, ChannelVisibility::Private)
        .await
        .expect("create");

    // Seed a couple of members so there are direct/channel peers to send to.
    let seed_members: Vec<NodeHandle> = {
        let mut v = Vec::new();
        for i in 0..2u8 {
            let m = spawn(0x10 + i).await;
            admit(&owner, "ops", &m, &format!("seed{i}")).await;
            v.push(m);
        }
        v
    };

    // Prepare 8 fresh members to admit concurrently. Admissions await ack
    // convergence — the historically-blocking path.
    let mut pending = Vec::new();
    for i in 0..8u8 {
        pending.push(std::sync::Arc::new(spawn(0x30 + i).await));
    }

    // Keep every admitted member online until all work completes: later
    // membership commits require acknowledgments from earlier members too.
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    for (i, m) in pending.iter().enumerate() {
        let m = m.clone();
        let owner = owner.clone();
        tasks.spawn(async move {
            let name = format!("cc{i}");
            let req = m.prepare_channel_join(&name).await.expect("prepare");
            let kp = m.channel_key_package(req).await.expect("kp");
            let welcome = owner.admit_channel("ops", &kp, &name).await.expect("admit");
            m.join_channel(req, "ops", ChannelVisibility::Private, &welcome)
                .await
                .expect("join");
        });
    }
    for i in 0..4u8 {
        let owner = owner.clone();
        tasks.spawn(async move {
            owner
                .send_channel_text("ops", format!("chan-{i}").as_bytes())
                .await
                .expect("channel send");
        });
    }
    for m in &seed_members {
        let owner = owner.clone();
        let target = m.current_info().await.expect("member info");
        tasks.spawn(async move {
            owner
                .send_1to1(&target, b"concurrent direct", None)
                .await
                .expect("direct send");
        });
    }

    // While all of that is in flight, `current_info` must stay snappy. Sample
    // it repeatedly; the worst-case must stay well under the old multi-second
    // stall. 50 ms is the plan's bar; we allow generous CI headroom but still
    // orders of magnitude below a blocked loop.
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..20 {
        let t0 = std::time::Instant::now();
        owner
            .current_info()
            .await
            .expect("current_info during load");
        worst = worst.max(t0.elapsed());
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        worst < std::time::Duration::from_millis(500),
        "current_info stalled behind concurrent work: worst {worst:?}"
    );

    // Drain the concurrent work so nothing is left half-done.
    while let Some(result) = tasks.join_next().await {
        result.expect("concurrent operation must complete successfully");
    }

    owner.shutdown().await;
    for m in seed_members {
        m.shutdown().await;
    }
    for m in pending {
        m.shutdown().await;
    }
}
