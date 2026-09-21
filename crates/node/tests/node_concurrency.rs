//! The command loop must never serialize behind a slow operation.
//!
//! Before the keyed-dispatch fix (commit 362335b / the Phase 6 hardening) a
//! single `admit_channel` that awaited membership acks could block the whole
//! Cmd loop for up to the convergence timeout, freezing unrelated calls like
//! `current_info`. This test drives several admissions plus channel and direct
//! sends concurrently and asserts a `current_info` round-trip stays fast while
//! an admit is in flight.

use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, ChannelStatus, NodeConfig, NodeHandle, NodeProfile};

async fn channel_status(owner: &NodeHandle, channel: &str) -> ChannelStatus {
    owner
        .list_channels()
        .await
        .expect("channel list")
        .into_iter()
        .find(|view| view.channel == channel)
        .expect("channel exists")
        .status
}

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
    assert_eq!(channel_status(owner, channel).await, ChannelStatus::Active);
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
    let prepared = std::sync::Arc::new(tokio::sync::Barrier::new(pending.len() + 1));
    // Owner commands already serialize admissions. Include the caller's
    // application of each Welcome in that fixture ordering before advancing
    // the next membership epoch; it is a separate command on another node.
    let admission_cycle = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    for (i, m) in pending.iter().enumerate() {
        let m = m.clone();
        let owner = owner.clone();
        let prepared = prepared.clone();
        let admission_cycle = admission_cycle.clone();
        tasks.spawn(async move {
            let name = format!("cc{i}");
            let req = m.prepare_channel_join(&name).await.expect("prepare");
            let kp = m.channel_key_package(req).await.expect("kp");
            prepared.wait().await;
            let _cycle = admission_cycle.lock().await;
            let welcome = owner.admit_channel("ops", &kp, &name).await.expect("admit");
            m.join_channel(req, "ops", ChannelVisibility::Private, &welcome)
                .await
                .expect("join");
            assert_eq!(channel_status(&owner, "ops").await, ChannelStatus::Active);
        });
    }

    prepared.wait().await;
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

/// A briefly delayed Welcome is supported by the parked-cell and ACK paths.
/// Exercise that overlap explicitly so ordering the load fixture cannot hide
/// a failure to recover after the missing member actually joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_welcome_keeps_commands_responsive_and_membership_recovers() {
    use std::time::Duration;

    let owner = std::sync::Arc::new(spawn(0x61).await);
    let first = spawn(0x62).await;
    let second = spawn(0x63).await;
    owner
        .create_channel("delayed", "founder", 8, ChannelVisibility::Private)
        .await
        .expect("create");
    let first_req = first.prepare_channel_join("first").await.expect("prepare");
    let first_kp = first.channel_key_package(first_req).await.expect("kp");
    let first_welcome = owner
        .admit_channel("delayed", &first_kp, "first")
        .await
        .expect("first admission");
    let second_req = second
        .prepare_channel_join("second")
        .await
        .expect("prepare");
    let second_kp = second.channel_key_package(second_req).await.expect("kp");
    let second_owner = owner.clone();
    let admission = tokio::spawn(async move {
        second_owner
            .admit_channel("delayed", &second_kp, "second")
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while channel_status(&owner, "delayed").await != ChannelStatus::MembershipPending {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second admission must await the not-yet-joined member");
    for _ in 0..20 {
        assert!(
            !admission.is_finished(),
            "admission cannot converge before join"
        );
        tokio::time::timeout(Duration::from_millis(500), owner.current_info())
            .await
            .expect("current_info must remain responsive during the blocked admission")
            .expect("current_info");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    first
        .join_channel(
            first_req,
            "delayed",
            ChannelVisibility::Private,
            &first_welcome,
        )
        .await
        .expect("apply the delayed Welcome");
    let second_welcome = tokio::time::timeout(Duration::from_secs(90), admission)
        .await
        .expect("membership recovery must remain bounded")
        .expect("admission task")
        .expect("second admission");
    assert_eq!(
        channel_status(&owner, "delayed").await,
        ChannelStatus::Active
    );
    second
        .join_channel(
            second_req,
            "delayed",
            ChannelVisibility::Private,
            &second_welcome,
        )
        .await
        .expect("second join");
    owner.shutdown().await;
    first.shutdown().await;
    second.shutdown().await;
}
