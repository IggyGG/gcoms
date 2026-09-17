use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, Ev, NodeConfig, NodeProfile};

async fn spawn(seed: u8) -> gcoms_node::NodeHandle {
    let node = start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::compressed_production(u64::from(seed)),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start");
    node.enable_diagnostics();
    node
}

async fn admit(
    owner: &gcoms_node::NodeHandle,
    channel: &str,
    member: &gcoms_node::NodeHandle,
    name: &str,
) -> Result<(), String> {
    let req = member.prepare_channel_join(name).await.expect("prepare");
    let kp = member.channel_key_package(req).await.expect("kp");
    let welcome = owner.admit_channel(channel, &kp, name).await?;
    member
        .join_channel(req, channel, ChannelVisibility::Private, &welcome)
        .await
        .expect("join");
    Ok(())
}

async fn await_chan(h: &gcoms_node::NodeHandle, channel: &str, want: &str) -> u64 {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let ev = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .expect("timeout waiting for channel message")
            .expect("node ended");
        if let Ev::ChannelMessage {
            channel: c,
            text,
            latency_hint_ms,
            ..
        } = ev
        {
            if c == channel && text == want.as_bytes() {
                return latency_hint_ms;
            }
        }
    }
}

// Deadlines here are 180s, not the ~208s this test needs standalone would
// suggest is tight: 24-node gossip convergence is real-time-bound, and when the
// native-qualification harness runs the whole workspace suite in parallel on a
// saturated machine a single node can starve past a 60s per-message window.
// 180s is load headroom, not a masked hang — a genuinely broken broadcast still
// fails well within it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_delivers_to_24_nodes() {
    let metrics_path =
        std::env::temp_dir().join(format!("gc-overlay-metrics-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&metrics_path);
    gcoms_node::metrics::init(&metrics_path).unwrap();
    let owner = spawn(0x01).await;
    owner
        .create_channel("ops", "founder", 64, ChannelVisibility::Private)
        .await
        .expect("create");

    let mut members: Vec<gcoms_node::NodeHandle> = Vec::new();
    for i in 0..23u8 {
        let name = format!("m{i}");
        let m = spawn(0x10 + i).await;
        if let Err(error) = admit(&owner, "ops", &m, &name).await {
            eprintln!("owner diagnostics: {:?}", owner.diagnostics());
            for (index, member) in members.iter().enumerate() {
                eprintln!("member {index} diagnostics: {:?}", member.diagnostics());
            }
            panic!("admit {name}: {error}; metrics {}", metrics_path.display());
        }
        members.push(m);
    }

    let roster_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    for (index, node) in std::iter::once(&owner).chain(members.iter()).enumerate() {
        loop {
            let roster = node.channel_roster("ops").await.expect("channel roster");
            if roster.len() == 24 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < roster_deadline,
                "24-node roster did not converge: node {index}, {} members; metrics {}",
                roster.len(),
                metrics_path.display()
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    for (i, m) in members.iter().enumerate() {
        let address = m.info.primary().expect("primary alias").target.address;
        eprintln!("[t] m{i} addr={address} tag={}", &address.to_string()[13..]);
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    eprintln!(
        "[t] m0 addr={} q={} m7 addr={}",
        members[0]
            .info
            .primary()
            .expect("primary alias")
            .target
            .address,
        &gcoms_transport::encode_b64url(
            &members[0].info.primary().expect("primary alias").queue_id
        )[..8],
        members[7]
            .info
            .primary()
            .expect("primary alias")
            .target
            .address
    );
    members[7]
        .send_channel_text("ops", b"mid-member broadcast")
        .await
        .expect("send");
    for (i, m) in members.iter().enumerate() {
        if i == 7 {
            continue;
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
        let result = tokio::time::timeout_at(deadline, async {
            loop {
                let ev = m.next_event().await.expect("node ended");
                if let Ev::ChannelMessage {
                    channel: c, text, ..
                } = ev
                {
                    if c == "ops" && text == b"mid-member broadcast" {
                        return;
                    }
                }
            }
        })
        .await;
        if result.is_err() {
            let log = std::fs::read_to_string(metrics_path).unwrap_or_default();
            let address = members[i]
                .info
                .primary()
                .expect("primary alias")
                .target
                .address
                .to_string();
            eprintln!("[t] FAILED NODE {i} tag={}", &address[13..]);
            let tail: Vec<&str> = log.lines().rev().take(80).collect();
            eprintln!("NODE {i} MISSED mid-member broadcast; metrics tail:");
            for l in tail.iter().rev() {
                eprintln!("  {l}");
            }
            panic!("node {i} missed");
        }
    }
    await_chan(&owner, "ops", "mid-member broadcast").await;

    members[0]
        .send_channel_text("ops", b"edge broadcast")
        .await
        .expect("send2");
    for (i, m) in members.iter().enumerate() {
        if i == 0 {
            continue;
        }
        await_chan(m, "ops", "edge broadcast").await;
    }
    await_chan(&owner, "ops", "edge broadcast").await;

    members[0]
        .send_1to1(&members[22].info, b"qualification direct message", None)
        .await
        .expect("send direct message");
    let direct_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let event = tokio::time::timeout_at(direct_deadline, members[22].next_event())
            .await
            .expect("timeout waiting for direct message")
            .expect("node ended");
        if let Ev::Message { text, .. } = event {
            if text == b"qualification direct message" {
                break;
            }
        }
    }
}
