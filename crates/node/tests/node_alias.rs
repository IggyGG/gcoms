use gcoms_core::{Cell, CellType};
use gcoms_node::lease::{LeaseRenew, OP_RENEW};
use gcoms_node::node::{start, AliasLifecycleConfig, Ev, NodeConfig, NodeHandle};
use gcoms_node::relay::RelayPush;

async fn spawn(seed: u8) -> NodeHandle {
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

async fn wait_for_text(node: &NodeHandle, expected: &[u8]) {
    wait_for_texts(node, &[expected]).await;
}

async fn wait_for_texts(node: &NodeHandle, expected: &[&[u8]]) {
    let mut remaining = expected
        .iter()
        .map(|text| text.to_vec())
        .collect::<std::collections::BTreeSet<_>>();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(240);
    while !remaining.is_empty() {
        let event = tokio::time::timeout_at(deadline, node.next_event())
            .await
            .unwrap_or_else(|_| panic!("message timeout: {remaining:?}"))
            .expect("event stream closed");
        if let Ev::Message { text, .. } = event {
            remaining.remove(&text);
        }
    }
}

async fn wait_for_identity_update(
    events: &mut tokio::sync::broadcast::Receiver<Ev>,
    previous: &gcoms_node::proto::NodeInfo,
) -> gcoms_node::proto::NodeInfo {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("identity update timeout")
            .expect("identity event stream closed or lagged");
        if let Ev::IdentityUpdated { info, .. } = event {
            if info != *previous {
                return info;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_only_node_receives_through_remote_alias() {
    let relay = spawn(0x31).await;
    let sender = spawn(0x32).await;
    let relay_card = relay
        .provision_client_relay()
        .await
        .expect("relay provisioning card");
    let forwarder = start(NodeConfig {
        seed: [0x33; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: Some(relay_card),
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("forwarder registers remote inboxes");

    assert_eq!(
        forwarder.info.primary().unwrap().target,
        relay.info.primary().unwrap().target
    );
    assert_ne!(
        forwarder.info.primary().unwrap().queue_id,
        relay.info.primary().unwrap().queue_id
    );
    assert!(forwarder.info.provisioning.is_none());
    assert!(
        gcoms_node::proto::NodeInfo::decode(&forwarder.info.encode())
            .unwrap()
            .provisioning
            .is_none()
    );

    sender
        .send_1to1(&forwarder.info, b"through remote inbox", None)
        .await
        .expect("send to remote alias");
    wait_for_text(&forwarder, b"through remote inbox").await;

    forwarder
        .send_1to1(&sender.info, b"forwarder reply", None)
        .await
        .expect("outbound reply");
    wait_for_text(&sender, b"forwarder reply").await;

    forwarder.shutdown().await;
    sender.shutdown().await;
    relay.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_malformed_frwd_on_valid_token() {
    let relay = spawn(0x41).await;
    let relay_card = relay
        .provision_client_relay()
        .await
        .expect("relay provisioning card");
    let provision = relay_card.provisioning.as_ref().expect("private provision");
    let target = &provision.aliases[0].contact.target;
    let wire = Cell::new(CellType::Frwd, 0, 0, vec![0; 32])
        .encode_wire()
        .unwrap();
    let client = gcoms_transport::Tp1Client::new().unwrap();

    let outcome = client
        .post_cell_pinned(
            target.address,
            target.relay_service_id,
            &provision.frwd_path,
            bytes::Bytes::from(wire),
        )
        .await
        .unwrap();
    assert_eq!(outcome, gcoms_transport::HopOutcome::Decoy(404));

    relay.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_alias_create_overlap_announce_drain_and_revoke() {
    let relay = spawn(0x51).await;
    let established = spawn(0x52).await;
    let old_sender = spawn(0x53).await;
    let new_sender = spawn(0x54).await;
    let relay_card = relay
        .provision_client_relay()
        .await
        .expect("relay provisioning card");
    let old_owned = relay_card
        .provisioning
        .as_ref()
        .expect("private provision")
        .aliases[0]
        .clone();
    let forwarder = start(NodeConfig {
        seed: [0x55; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: Some(relay_card),
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: AliasLifecycleConfig {
            alias_ttl: std::time::Duration::from_millis(250),
            alias_drain: std::time::Duration::from_secs(30),
            poll_interval: std::time::Duration::from_millis(50),
            revoke_retry: std::time::Duration::from_millis(100),
            revoke_timeout: std::time::Duration::from_secs(2),
        },
    })
    .await
    .expect("forwarder registers remote inboxes");
    // The message waiter must not consume the first rotation notification.
    let mut identity_events = forwarder.subscribe();
    let old_info = forwarder.current_info().await.unwrap();

    established
        .send_1to1(&old_info, b"establish before alias change", None)
        .await
        .unwrap();
    wait_for_text(&forwarder, b"establish before alias change").await;

    let new_info = wait_for_identity_update(&mut identity_events, &old_info).await;
    assert_ne!(old_info.aliases[0].queue_id, new_info.aliases[0].queue_id);
    assert_ne!(old_info.aliases[1].queue_id, new_info.aliases[1].queue_id);
    assert_eq!(forwarder.current_info().await.unwrap(), new_info);
    assert!(new_info.provisioning.is_none());

    old_sender
        .send_1to1(&old_info, b"old queue during drain", None)
        .await
        .unwrap();
    new_sender
        .send_1to1(&new_info, b"new queue during drain", None)
        .await
        .unwrap();
    wait_for_texts(
        &forwarder,
        &[b"old queue during drain", b"new queue during drain"],
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    established
        .send_1to1(&old_info, b"established peer uses announced route", None)
        .await
        .unwrap();
    wait_for_text(&forwarder, b"established peer uses announced route").await;

    tokio::time::sleep(std::time::Duration::from_secs(31)).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let client = gcoms_transport::Tp1Client::new().unwrap();
    let push = RelayPush {
        queue_id: old_owned.contact.queue_id,
        epoch: old_owned.contact.epoch,
        push_nonce: [0x61; 16],
        push_expiry: now + 30,
        msg: Some(Cell::new(CellType::Msg, 0, 0, b"revoked".to_vec())),
    }
    .encode_into_cell(
        &old_owned.capabilities.push,
        &old_owned.contact.target.relay_service_id,
    )
    .unwrap()
    .encode_wire()
    .unwrap();
    let outcome = client
        .post_cell_pinned(
            old_owned.contact.target.address,
            old_owned.contact.target.relay_service_id,
            &gcoms_transport::encode_b64url(&old_owned.contact.queue_id),
            bytes::Bytes::from(push),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome,
        gcoms_transport::HopOutcome::Decoy(404),
        "old push capability survived revoke"
    );

    let sub = gcoms_node::relay::RelaySub {
        queue_id: old_owned.contact.queue_id,
        epoch: old_owned.contact.epoch,
        subscription_expiry: now + 30,
        nonce: [0x62; 16],
    }
    .encode_into_cell(
        &old_owned.capabilities.sub,
        &old_owned.contact.target.relay_service_id,
    )
    .unwrap()
    .encode_wire()
    .unwrap();
    assert!(client
        .open_stream_body_pinned(
            old_owned.contact.target.address,
            old_owned.contact.target.relay_service_id,
            &gcoms_transport::encode_b64url(&old_owned.contact.queue_id),
            Some(&sub),
        )
        .await
        .is_err());

    let renew = LeaseRenew {
        queue_id: old_owned.contact.queue_id,
        epoch: old_owned.contact.epoch,
        lease_expiry: old_owned.contact.expiry + 1,
        nonce: [0x63; 16],
    }
    .encode(
        &old_owned.capabilities.admin,
        &old_owned.contact.target.relay_service_id,
    )
    .unwrap();
    assert_eq!(renew[1], OP_RENEW);
    let outcome = client
        .post_cell_pinned(
            old_owned.contact.target.address,
            old_owned.contact.target.relay_service_id,
            &old_owned.create_path,
            bytes::Bytes::from(
                Cell::new(CellType::RelaySub, 0, 0, renew.to_vec())
                    .encode_wire()
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome,
        gcoms_transport::HopOutcome::Decoy(404),
        "old admin capability survived revoke"
    );

    forwarder.shutdown().await;
    new_sender.shutdown().await;
    old_sender.shutdown().await;
    established.shutdown().await;
    relay.shutdown().await;
}

/// SPEC §7.4 / §11.1: an authenticated cover deposit (`msg_len = 0`) is
/// accepted with the same receipt as a real deposit, consumes a replay
/// nonce, and enqueues nothing, so a subscriber never sees it.
#[tokio::test(flavor = "multi_thread")]
async fn cover_deposit_is_accepted_and_never_delivered() {
    let relay = spawn(0x41).await;
    let card = relay
        .provision_client_relay()
        .await
        .expect("relay provisioning card");
    let provision = card
        .provisioning
        .clone()
        .expect("private provisioning fields");
    let subscriber = start(NodeConfig {
        seed: [0x42; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: Some(card.clone()),
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("subscriber start");
    let owned = &provision.aliases[0];
    let client = gcoms_transport::Tp1Client::new().unwrap();
    // Allow the subscriber to attach before depositing.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    for nonce in 1u8..=8 {
        let cover = RelayPush::cover(
            owned.contact.queue_id,
            owned.contact.epoch,
            [nonce; 16],
            owned.contact.expiry,
        )
        .encode_into_cell(
            &owned.capabilities.push,
            &owned.contact.target.relay_service_id,
        )
        .unwrap()
        .encode_wire()
        .unwrap();
        let outcome = client
            .post_cell_pinned(
                owned.contact.target.address,
                owned.contact.target.relay_service_id,
                &gcoms_transport::encode_b64url(&owned.contact.queue_id),
                bytes::Bytes::from(cover),
            )
            .await
            .unwrap();
        assert_eq!(outcome, gcoms_transport::HopOutcome::Accepted(None));
    }
    // A replayed cover nonce is a duplicate, not an error: the receipt is
    // identical so a prober learns nothing.
    let replay = RelayPush::cover(
        owned.contact.queue_id,
        owned.contact.epoch,
        [1; 16],
        owned.contact.expiry,
    )
    .encode_into_cell(
        &owned.capabilities.push,
        &owned.contact.target.relay_service_id,
    )
    .unwrap()
    .encode_wire()
    .unwrap();
    let outcome = client
        .post_cell_pinned(
            owned.contact.target.address,
            owned.contact.target.relay_service_id,
            &gcoms_transport::encode_b64url(&owned.contact.queue_id),
            bytes::Bytes::from(replay),
        )
        .await
        .unwrap();
    assert_eq!(outcome, gcoms_transport::HopOutcome::Accepted(None));

    // Nothing reaches the subscriber's application layer.
    let got = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match subscriber.next_event().await {
                Some(Ev::Message { .. }) => break true,
                Some(_) => continue,
                None => break false,
            }
        }
    })
    .await;
    assert!(got.is_err(), "cover deposit reached the application");
    subscriber.shutdown().await;
    relay.shutdown().await;
}
