use gcoms_node::channel::ChannelVisibility;
use gcoms_node::node::{start, Ev, NodeConfig, Reachability};
use gcoms_node::proto::PresenceMode;

static NETWORK_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spawn(seed: u8) -> gcoms_node::NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start")
}

async fn admit(
    owner: &gcoms_node::NodeHandle,
    channel: &str,
    member: &gcoms_node::NodeHandle,
    name: &str,
) {
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

async fn await_channel_message_id(
    h: &gcoms_node::NodeHandle,
    channel: &str,
    want: &str,
) -> [u8; 16] {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let event = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .expect("timeout waiting for channel message")
            .expect("node ended");
        if let Ev::ChannelMessage {
            channel: received_channel,
            msg_id,
            text,
            ..
        } = event
        {
            if received_channel == channel && text == want.as_bytes() {
                return msg_id;
            }
        }
    }
}

async fn await_channel_receipt(h: &gcoms_node::NodeHandle, channel: &str, message_id: [u8; 16]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let event = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .expect("timeout waiting for channel ACKs")
            .expect("node ended");
        if let Ev::ChannelDelivery {
            channel: received_channel,
            msg_id,
        } = event
        {
            if received_channel == channel && msg_id == message_id {
                return;
            }
        }
    }
}

async fn assert_no_channel_presence_event(
    handle: &gcoms_node::NodeHandle,
    duration: std::time::Duration,
) {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        match tokio::time::timeout_at(deadline, handle.next_event()).await {
            Err(_) => return,
            Ok(Some(Ev::ChannelPresenceChanged { .. })) => {
                panic!("unexpected channel presence event")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("node ended"),
        }
    }
}

async fn await_channel_presence(
    handle: &gcoms_node::NodeHandle,
    channel: &str,
    member_id: [u8; 32],
    want: Reachability,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let event = tokio::time::timeout_at(deadline, handle.next_event())
            .await
            .expect("timeout waiting for channel presence")
            .expect("node ended");
        if let Ev::ChannelPresenceChanged {
            channel: received_channel,
            member_id: received_member,
            reachability,
        } = event
        {
            if received_channel == channel && received_member == member_id && reachability == want {
                return;
            }
        }
    }
}

async fn await_channel_direct(
    handle: &gcoms_node::NodeHandle,
    channel: &str,
    expected: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let event = tokio::time::timeout_at(deadline, handle.next_event())
            .await
            .expect("timeout waiting for channel direct")
            .expect("node ended");
        if let Ev::ChannelDirectMessage {
            channel: received_channel,
            sender_member_id,
            recipient_member_id,
            text,
            ..
        } = event
        {
            if received_channel == channel && text == expected {
                return (sender_member_id, recipient_member_id);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_full_lifecycle_between_nodes() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x01).await;
    let b = spawn(0x02).await;
    let c = spawn(0x03).await;
    let d = spawn(0x04).await;

    owner
        .create_channel("ops", "founder", 32, ChannelVisibility::Private)
        .await
        .expect("create");

    admit(&owner, "ops", &b, "redwing").await;
    admit(&owner, "ops", &c, "kestrel").await;
    admit(&owner, "ops", &d, "heron").await;

    owner
        .send_channel_text("ops", b"all hands meeting at 6")
        .await
        .expect("send");
    let ms_b = await_chan(&b, "ops", "all hands meeting at 6").await;
    let ms_c = await_chan(&c, "ops", "all hands meeting at 6").await;
    let ms_d = await_chan(&d, "ops", "all hands meeting at 6").await;
    for ms in [ms_b, ms_c, ms_d] {
        assert!(ms < 90_000, "latency {ms}ms");
    }

    b.send_channel_text("ops", b"redwing checking in")
        .await
        .expect("member send");
    await_chan(&owner, "ops", "redwing checking in").await;
    await_chan(&c, "ops", "redwing checking in").await;
    await_chan(&d, "ops", "redwing checking in").await;

    for i in 0..3 {
        let msg = format!("convo-{i}");
        let nodes = [&owner, &b, &c, &d];
        let sender = nodes[i % 4];
        sender
            .send_channel_text("ops", msg.as_bytes())
            .await
            .unwrap();
        for (j, h) in nodes.iter().enumerate() {
            if j != i % 4 {
                await_chan(h, "ops", &msg).await;
            }
        }
    }

    let kestrel_id = owner
        .channel_roster("ops")
        .await
        .unwrap()
        .into_iter()
        .find(|member| member.display_name == "kestrel")
        .unwrap()
        .member_id;

    owner
        .remove_channel_member("ops", kestrel_id)
        .await
        .expect("remove");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut c_removed_event = false;
    while tokio::time::Instant::now() < deadline {
        let ev = tokio::time::timeout_at(deadline, c.next_event()).await;
        match ev {
            Ok(Some(Ev::ChannelRemoved { channel })) if channel == "ops" => {
                c_removed_event = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    assert!(c_removed_event, "removed member must observe removal");

    owner
        .send_channel_text("ops", b"post-removal traffic")
        .await
        .expect("send after removal");
    await_chan(&b, "ops", "post-removal traffic").await;
    await_chan(&d, "ops", "post-removal traffic").await;

    let silent = tokio::time::timeout(std::time::Duration::from_secs(5), c.next_event()).await;
    if let Ok(Some(Ev::ChannelMessage { text, .. })) = silent {
        panic!(
            "removed member decrypted channel traffic: {:?}",
            String::from_utf8_lossy(&text)
        );
    }
    owner.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    d.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn membership_operations_are_idempotent() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x31).await;
    let member = spawn(0x32).await;
    owner
        .create_channel("idempotent", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let request = member.prepare_channel_join("member").await.unwrap();
    let key_package = member.channel_key_package(request).await.unwrap();
    let first = owner
        .admit_channel("idempotent", &key_package, "member")
        .await
        .unwrap();
    let retry = owner
        .admit_channel("idempotent", &key_package, "member")
        .await
        .unwrap();
    assert_eq!(retry, first);
    member
        .join_channel(request, "idempotent", ChannelVisibility::Private, &first)
        .await
        .unwrap();
    owner
        .send_channel_text("idempotent", b"tracked")
        .await
        .unwrap();
    let message_id = await_channel_message_id(&member, "idempotent", "tracked").await;
    await_channel_receipt(&owner, "idempotent", message_id).await;
    let member_id = owner
        .channel_roster("idempotent")
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.display_name == "member")
        .unwrap()
        .member_id;
    owner
        .remove_channel_member("idempotent", member_id)
        .await
        .unwrap();
    owner
        .remove_channel_member("idempotent", member_id)
        .await
        .unwrap();
    owner.shutdown().await;
    member.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn removal_retry_does_not_remove_reused_display_name() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x33).await;
    let original = spawn(0x34).await;
    let replacement = spawn(0x37).await;
    owner
        .create_channel("reuse", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    admit(&owner, "reuse", &original, "shared").await;
    let original_id = owner
        .channel_roster("reuse")
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.display_name == "shared")
        .unwrap()
        .member_id;

    owner
        .remove_channel_member("reuse", original_id)
        .await
        .unwrap();
    admit(&owner, "reuse", &replacement, "shared").await;
    let replacement_id = owner
        .channel_roster("reuse")
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.display_name == "shared")
        .unwrap()
        .member_id;
    assert_ne!(replacement_id, original_id);

    owner
        .remove_channel_member("reuse", original_id)
        .await
        .unwrap();
    assert!(owner
        .channel_roster("reuse")
        .await
        .unwrap()
        .iter()
        .any(|entry| entry.member_id == replacement_id));

    owner
        .send_channel_text("reuse", b"replacement remains")
        .await
        .unwrap();
    await_chan(&replacement, "reuse", "replacement remains").await;
    owner.shutdown().await;
    original.shutdown().await;
    replacement.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_presence_is_mls_bound_and_withdrawable() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x35).await;
    let member = spawn(0x36).await;
    owner
        .create_channel("presence", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    admit(&owner, "presence", &member, "member").await;
    let member_id = owner
        .channel_roster("presence")
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.display_name == "member")
        .unwrap()
        .member_id;

    owner
        .send_channel_text("presence", b"bootstrap presence route")
        .await
        .expect("bootstrap channel route");
    await_chan(&member, "presence", "bootstrap presence route").await;

    assert!(member
        .send_channel_presence("presence", PresenceMode::Away, 30)
        .await
        .is_err());
    member
        .set_channel_presence_opt_in("presence", true)
        .await
        .expect("member opt in");
    member
        .send_channel_presence("presence", PresenceMode::Away, 30)
        .await
        .expect("send one-sided channel presence");
    assert_no_channel_presence_event(&owner, std::time::Duration::from_millis(250)).await;
    owner
        .set_channel_presence_opt_in("presence", true)
        .await
        .expect("owner opt in");
    member
        .send_channel_presence("presence", PresenceMode::Away, 30)
        .await
        .expect("send channel presence");
    await_channel_presence(&owner, "presence", member_id, Reachability::Away).await;

    member
        .set_channel_presence_opt_in("presence", false)
        .await
        .expect("withdraw channel presence");
    await_channel_presence(&owner, "presence", member_id, Reachability::Unknown).await;

    owner.shutdown().await;
    member.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn roster_is_channel_local_and_channel_direct_is_pairwise() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x51).await;
    let member = spawn(0x52).await;
    for channel in ["left", "right"] {
        owner
            .create_channel(channel, "owner", 8, ChannelVisibility::Private)
            .await
            .unwrap();
        admit(&owner, channel, &member, "member").await;
    }

    let left = owner.channel_roster("left").await.unwrap();
    let right = owner.channel_roster("right").await.unwrap();
    assert_eq!(left.len(), 2);
    assert_eq!(right.len(), 2);
    assert!(left.iter().all(|member| member.joined_at_unix.is_none()));
    let left_member = left.iter().find(|member| !member.is_self).unwrap();
    let right_member = right.iter().find(|member| !member.is_self).unwrap();
    assert_ne!(left_member.member_id, right_member.member_id);

    owner
        .send_channel_direct("left", left_member.member_id, b"private left")
        .await
        .unwrap();
    let (sender, recipient) = await_channel_direct(&member, "left", b"private left").await;
    assert_eq!(
        sender,
        left.iter().find(|member| member.is_self).unwrap().member_id
    );
    assert_eq!(recipient, left_member.member_id);

    owner.shutdown().await;
    member.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_direct_message_is_private_and_acknowledged() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x41).await;
    let member = spawn(0x42).await;
    owner
        .create_channel("direct", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    admit(&owner, "direct", &member, "member").await;

    let recipient = owner
        .channel_roster("direct")
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.display_name == "member")
        .unwrap()
        .member_id;
    let message_id = owner
        .send_channel_direct("direct", recipient, b"private hello")
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let event = tokio::time::timeout_at(deadline, member.next_event())
            .await
            .expect("timeout waiting for channel direct message")
            .expect("node ended");
        if let Ev::ChannelDirectMessage {
            channel,
            recipient_member_id,
            msg_id,
            text,
            ..
        } = event
        {
            if channel == "direct" && msg_id == message_id {
                assert_eq!(recipient_member_id, recipient);
                assert_eq!(text, b"private hello");
                break;
            }
        }
    }

    loop {
        let event = tokio::time::timeout_at(deadline, owner.next_event())
            .await
            .expect("timeout waiting for channel direct ACK")
            .expect("node ended");
        if let Ev::ChannelDirectDelivery {
            channel,
            recipient_member_id,
            msg_id,
        } = event
        {
            if channel == "direct" && msg_id == message_id {
                assert_eq!(recipient_member_id, recipient);
                break;
            }
        }
    }

    owner.shutdown().await;
    member.shutdown().await;
}
