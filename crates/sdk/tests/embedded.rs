#![cfg(feature = "embedded")]

use gcoms_node::node::{start, NodeConfig};
use gcoms_sdk::{
    ActivityBucket, ApplicationMessage, AutomaticJoinEndpoint, ChannelRole, ChannelStatus,
    ChannelVisibility, ClientEvent, EmbeddedClient, GcClient, PresenceMode, Reachability,
};

static NETWORK_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn client(seed: u8) -> EmbeddedClient {
    let node = start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("start node");
    EmbeddedClient::new(node)
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_clients_use_typed_cards_and_events() {
    let _guard = NETWORK_TEST.lock().await;
    let alice = client(0x71).await;
    let bob = client(0x72).await;
    let mut bob_events = bob.subscribe_events();

    assert!(alice
        .set_direct_presence(&bob.identity().contact_card, PresenceMode::Away, 30, None)
        .await
        .is_err());
    alice
        .set_direct_presence_opt_in(&bob.identity().contact_card, true, None)
        .await
        .expect("sender opt in");
    bob.set_direct_presence_opt_in(&alice.identity().contact_card, true, None)
        .await
        .expect("receiver opt in");
    alice
        .set_direct_presence(&bob.identity().contact_card, PresenceMode::Away, 30, None)
        .await
        .expect("send typed presence");
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), bob_events.recv())
            .await
            .expect("presence timeout")
            .expect("event stream closed");
        if let ClientEvent::PresenceChanged {
            reachability: Reachability::Away,
            ..
        } = event
        {
            break;
        }
    }

    alice
        .send_direct(&bob.identity().contact_card, b"typed hello", None)
        .await
        .expect("send direct");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let event = tokio::time::timeout_at(deadline, bob_events.recv())
            .await
            .expect("message timeout")
            .expect("event stream closed");
        if let ClientEvent::DirectMessage { body, .. } = event {
            assert_eq!(body, b"typed hello");
            break;
        }
    }

    alice
        .submit_opaque(
            &bob.identity().contact_card,
            "application/vnd.ghost.report",
            b"sealed",
        )
        .await
        .expect("submit opaque");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let event = tokio::time::timeout_at(deadline, bob_events.recv())
            .await
            .expect("opaque timeout")
            .expect("event stream closed");
        if let ClientEvent::DirectMessage { body, .. } = event {
            assert_eq!(
                ApplicationMessage::decode(&body).unwrap(),
                ApplicationMessage {
                    content_type: "application/vnd.ghost.report".into(),
                    body: b"sealed".to_vec(),
                }
            );
            break;
        }
    }

    alice.node().shutdown().await;
    bob.node().shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_identity_refresh_tracks_contact_renewal() {
    let _guard = NETWORK_TEST.lock().await;
    let relay = client(0x74).await;
    let relay_card = relay.node().provision_client_relay().await.unwrap();
    let alice = EmbeddedClient::new(
        start(NodeConfig {
            seed: [0x75; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: Some(relay_card),
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        })
        .await
        .expect("start relayed node"),
    );
    let initial = alice.identity();
    let mut events = alice.subscribe_events();

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    alice.node().renew_contacts_now().await.unwrap();
    let refreshed = alice.refresh_identity().await.unwrap();

    assert_eq!(initial.safety_number, refreshed.safety_number);
    assert_ne!(initial.contact_card, refreshed.contact_card);
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
            .await
            .unwrap(),
        Some(ClientEvent::IdentityUpdated { identity, generation: 2 })
            if identity == refreshed
    ));
    alice.node().shutdown().await;
    relay.node().shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_client_rejects_invalid_cards_before_sending() {
    let _guard = NETWORK_TEST.lock().await;
    let alice = client(0x73).await;
    let error = alice
        .send_direct(&gcoms_sdk::ContactCard(vec![0xff]), b"no", None)
        .await
        .unwrap_err();
    assert_eq!(error, gcoms_sdk::SdkError::InvalidContactCard);
    alice.node().shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_channel_inspection_is_read_only_and_minimal() {
    let _guard = NETWORK_TEST.lock().await;
    let alice = client(0x74).await;
    let mut events = alice.subscribe_events();
    alice
        .create_channel("ops", "alice", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
            .await
            .unwrap(),
        Some(ClientEvent::ChannelRosterChanged { channel, .. }) if channel == "ops"
    ));

    let channels = alice.list_channels().await.unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].channel, "ops");
    assert_ne!(channels[0].id.0, [0; 32]);
    assert_eq!(channels[0].visibility, ChannelVisibility::Private);
    assert_eq!(channels[0].status, ChannelStatus::Active);
    assert_eq!(channels[0].role, ChannelRole::Owner);
    assert_eq!(channels[0].epoch, 0);
    let roster = alice.channel_roster("ops").await.unwrap();
    assert_eq!(roster.len(), 1);
    assert!(roster[0].is_self);

    alice.node().shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_channel_presence_uses_member_scoped_events() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = client(0x76).await;
    let member = client(0x77).await;
    owner
        .create_channel("presence", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let request = member.prepare_channel_join("member").await.unwrap();
    let package = member.channel_key_package(request).await.unwrap();
    let welcome = owner
        .admit_channel("presence", &package, "member")
        .await
        .unwrap();
    member
        .join_channel(request, "presence", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    let member_id = owner
        .channel_roster("presence")
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.display_name == "member")
        .unwrap()
        .member_id;
    let mut owner_events = owner.subscribe_events();
    let mut member_events = member.subscribe_events();
    owner.send_channel("presence", b"bootstrap").await.unwrap();
    loop {
        if matches!(
            tokio::time::timeout(std::time::Duration::from_secs(20), member_events.recv())
                .await
                .expect("bootstrap timeout"),
            Some(ClientEvent::ChannelMessage { body, .. }) if body == b"bootstrap"
        ) {
            break;
        }
    }

    owner
        .set_channel_presence_opt_in("presence", true)
        .await
        .unwrap();
    member
        .set_channel_presence_opt_in("presence", true)
        .await
        .unwrap();
    member
        .set_channel_presence("presence", PresenceMode::Away, 30)
        .await
        .unwrap();
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), owner_events.recv())
            .await
            .expect("channel presence timeout")
            .expect("event stream closed");
        if matches!(
            event,
            ClientEvent::ChannelPresenceChanged {
                channel,
                member_id: received_member,
                reachability: Reachability::Away,
            } if channel == "presence" && received_member == member_id
        ) {
            break;
        }
    }

    owner.node().shutdown().await;
    member.node().shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn public_descriptors_verify_and_private_channels_cannot_publish() {
    let _guard = NETWORK_TEST.lock().await;
    let alice = client(0x75).await;
    alice
        .create_channel("public", "alice", 16, ChannelVisibility::Public)
        .await
        .unwrap();
    alice
        .create_channel("private", "alice", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let now = 1_800_000_000;
    let descriptor = alice
        .public_channel_descriptor(
            "public",
            "A public operations channel",
            ActivityBucket::Today,
            AutomaticJoinEndpoint {
                catalog: "https://catalog.example".into(),
                endpoint: "/v1/channels/public/join".into(),
            },
            now + 3600,
        )
        .await
        .unwrap();
    assert!(descriptor.verify_at(now));
    assert!(!descriptor.verify_at(now + 3600));
    let mut tampered = descriptor.clone();
    tampered.capacity += 1;
    assert!(!tampered.verify_at(now));
    assert!(alice
        .public_channel_descriptor(
            "private",
            "must stay hidden",
            ActivityBucket::None,
            AutomaticJoinEndpoint {
                catalog: "https://catalog.example".into(),
                endpoint: "/join".into(),
            },
            now + 3600,
        )
        .await
        .is_err());
    alice.node().shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn local_client_accepts_late_relay_provisioning_and_receives_messages() {
    let _guard = NETWORK_TEST.lock().await;
    let relay = client(0x7a).await;
    let recipient = client(0x7b).await;
    let sender = client(0x7c).await;
    let old = recipient.identity();
    let mut events = recipient.subscribe_events();
    let provision = relay.node().provision_client_relay().await.unwrap();
    recipient
        .node()
        .install_inbox_relay(provision)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(ClientEvent::IdentityUpdated { identity, .. }) = events.recv().await {
                assert_ne!(identity.contact_card, old.contact_card);
                break;
            }
        }
    })
    .await
    .unwrap();
    sender
        .send_direct(&recipient.identity().contact_card, b"after bootstrap", None)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if let Some(ClientEvent::DirectMessage { body, .. }) = events.recv().await {
                assert_eq!(body, b"after bootstrap");
                break;
            }
        }
    })
    .await
    .unwrap();
    sender.node().shutdown().await;
    recipient.node().shutdown().await;
    relay.node().shutdown().await;
}
