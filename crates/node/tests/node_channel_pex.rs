//! Actual relay/channel regression: overlay PEX must traverse the same strict
//! relay MSG ingress as channel commits and messages, without local framing refusal.
use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, Ev, NodeConfig, NodeProfile};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_pex_reaches_real_members_without_non_msg_relay_push() {
    let dir = std::env::temp_dir().join(format!("gc-channel-pex-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("new private fixture directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let metrics = dir.join("metrics.jsonl");
    gcoms_node::metrics::init(&metrics).unwrap();
    let mut nodes = Vec::new();
    for seed in [0x41, 0x42, 0x43] {
        let result = start(NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        })
        .await;
        match result {
            Ok(node) => nodes.push(node),
            Err(error) => {
                for node in &nodes {
                    node.shutdown().await;
                }
                panic!("actual fixture startup failed: {error}");
            }
        }
    }
    let result = tokio::time::timeout(Duration::from_secs(40), async {
        let owner = &nodes[0];
        owner
            .create_channel("pex-regression", "owner", 8, ChannelVisibility::Private)
            .await?;
        for (member, name) in [(&nodes[1], "member-b"), (&nodes[2], "member-c")] {
            let request = member.prepare_channel_join(name).await?;
            let package = member.channel_key_package(request).await?;
            let welcome = owner
                .admit_channel("pex-regression", &package, name)
                .await?;
            member
                .join_channel(
                    request,
                    "pex-regression",
                    ChannelVisibility::Private,
                    &welcome,
                )
                .await?;
        }
        // Membership and application ACKs are independent assertions: receiving
        // PEX alone cannot stand in for an admitted roster or delivered plaintext.
        let send_deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        loop {
            match owner.send_channel_text("pex-regression", b"three actual members").await {
                Ok(()) => break,
                Err(error) if error.contains("membership operation is awaiting commit ACKs") && tokio::time::Instant::now() < send_deadline => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(format!("ordinary channel send failed: {error}")),
            }
        }
        let delivery_deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        let mut ids = Vec::new();
        for member in [&nodes[1], &nodes[2]] {
            loop {
                let event = tokio::time::timeout_at(delivery_deadline, member.next_event()).await
                    .map_err(|_| "actual member plaintext timed out".to_string())?;
                if let Some(Ev::ChannelMessage { channel, msg_id, text, .. }) = event {
                    if channel == "pex-regression" && text == b"three actual members" {
                        ids.push(msg_id);
                        break;
                    }
                }
            }
        }
        if ids.len() != 2 || ids[0] != ids[1] { return Err("actual members received different message IDs".into()); }
        loop {
            let event = tokio::time::timeout_at(delivery_deadline, owner.next_event()).await
                .map_err(|_| "authenticated all-member delivery ACK timed out".to_string())?;
            if matches!(event, Some(Ev::ChannelDelivery { channel, msg_id }) if channel == "pex-regression" && msg_id == ids[0]) { break; }
        }
        eprintln!("actual three-member plaintext and exact all-member ACK PASS");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        loop {
            let text = std::fs::read_to_string(&metrics).map_err(|e| e.to_string())?;
            if text.contains("RELAY_PUSH does not contain exactly one MSG") {
                return Err("actual channel sender emitted non-MSG relay payload".to_string());
            }
            if text.lines().any(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .is_some_and(|row| {
                        row["event"] == "chan_pex_received" && row["channel"] == "pex-regression"
                    })
            }) {
                return Ok::<_, String>(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(
                    "no PEX reached an actual joined member before original deadline".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    // Normal NodeHandle shutdown owns every listener/task even on the red assertion.
    for node in &nodes {
        tokio::time::timeout(Duration::from_secs(10), node.shutdown())
            .await
            .expect("owned node cleanup");
    }
    let log = std::fs::read_to_string(&metrics).unwrap_or_default();
    let rejections = log
        .lines()
        .filter(|line| line.contains("RELAY_PUSH does not contain exactly one MSG"))
        .count();
    eprintln!(
        "actual channel framing rejections={rejections}; metrics={}",
        metrics.display()
    );
    assert_eq!(result.expect("original overall fixture deadline"), Ok(()));
}
