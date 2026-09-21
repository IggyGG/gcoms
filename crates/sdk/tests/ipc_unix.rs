#![cfg(all(unix, feature = "embedded", feature = "ipc"))]

use gcoms_node::node::{start, NodeConfig};
use gcoms_sdk::ipc::Capability;
use gcoms_sdk::{
    serve_unix, ActivityBucket, ApplicationMessage, AutomaticJoinEndpoint, ChannelVisibility,
    ClientEvent, EmbeddedClient, GcClient, IpcClient, PresenceMode, Reachability,
};

async fn embedded(seed: u8) -> EmbeddedClient {
    EmbeddedClient::new(
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
        .expect("start node"),
    )
}

fn socket_path(test: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("gc-sdk-{}-{test}.sock", std::process::id()))
}

#[tokio::test(flavor = "multi_thread")]
async fn ipc_backend_matches_embedded_messages_and_events() {
    let relay = embedded(0x60).await;
    let relay_card = relay.node().provision_client_relay().await.unwrap();
    let alice = EmbeddedClient::new(
        start(NodeConfig {
            seed: [0x61; 32],
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
    let bob = embedded(0x62).await;
    alice
        .create_channel("ops", "alice", 8, ChannelVisibility::Public)
        .await
        .unwrap();
    let path = socket_path("roundtrip");
    let _ = std::fs::remove_file(&path);
    let server_client = alice.clone();
    let server_path = path.clone();
    let server = tokio::spawn(async move {
        serve_unix(
            server_path,
            server_client,
            vec![
                Capability::IdentityRead,
                Capability::DirectMessage,
                Capability::EventRead,
                Capability::OpaqueTransfer,
                Capability::ChannelMember,
                Capability::ChannelAdmin,
                Capability::IdentitySign,
            ],
        )
        .await
    });
    let requested = vec![
        Capability::IdentityRead,
        Capability::DirectMessage,
        Capability::EventRead,
        Capability::OpaqueTransfer,
        Capability::ChannelAdmin,
        Capability::ChannelMember,
        Capability::IdentitySign,
    ];
    let mut connected = None;
    let mut last_error = None;
    for _ in 0..100 {
        match IpcClient::connect(&path, "sdk-test", requested.clone()).await {
            Ok(client) => {
                connected = Some(client);
                break;
            }
            Err(error) => last_error = Some(error),
        }
        if server.is_finished() {
            panic!("IPC server exited before accepting a client");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let ipc = connected.unwrap_or_else(|| panic!("connect IPC client: {last_error:?}"));
    assert_eq!(ipc.authenticated_component_id(), None);
    assert_eq!(
        ipc.routed([1; 16], [2; 16]).authenticated_component_id(),
        None
    );
    assert_eq!(ipc.identity(), alice.identity());
    let shared = std::sync::Arc::new(ipc.clone());
    shared
        .change_channel("ops", gcoms_sdk::ChannelChange::Topic("IPC19 topic".into()))
        .await
        .unwrap();
    assert_eq!(shared.channel_topic("ops").await.unwrap(), "IPC19 topic");
    assert_eq!(alice.channel_topic("ops").await.unwrap(), "IPC19 topic");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    alice.node().renew_contacts_now().await.unwrap();
    assert_eq!(
        ipc.refresh_identity().await.unwrap(),
        alice.refresh_identity().await.unwrap()
    );
    assert_ne!(ipc.identity(), ipc.refresh_identity().await.unwrap());
    let digest = [0xa5; 32];
    let signature = ipc.sign_identity_digest(digest).await.unwrap();
    assert!(gcoms_crypto::verify_signature(
        &alice.node().info.identity_pk,
        &gcoms_core::identity_digest_signature_payload(&digest),
        &signature,
    ));
    let claims_hash = [0x5a; 32];
    let signature = ipc.sign_principal_binding_hash(claims_hash).await.unwrap();
    assert!(gcoms_crypto::verify_signature(
        &alice.node().info.identity_pk,
        &gcoms_core::principal_binding_signature_payload(&claims_hash),
        &signature,
    ));
    assert!(ipc
        .granted_capabilities()
        .contains(&Capability::ChannelAdmin));
    assert_eq!(
        ipc.list_channels().await.unwrap(),
        alice.list_channels().await.unwrap()
    );
    assert_eq!(
        ipc.channel_roster("ops").await.unwrap(),
        alice.channel_roster("ops").await.unwrap()
    );
    let now = 1_800_000_000;
    let descriptor = ipc
        .public_channel_descriptor(
            "ops",
            "IPC descriptor",
            ActivityBucket::ThisWeek,
            AutomaticJoinEndpoint {
                catalog: "https://catalog.example".into(),
                endpoint: "/join/ops".into(),
            },
            now + 300,
        )
        .await
        .unwrap();
    assert!(descriptor.verify_at(now));

    let mut bob_events = bob.subscribe_events();
    ipc.set_direct_presence_opt_in(&bob.identity().contact_card, true, None)
        .await
        .expect("IPC sender opt in");
    bob.set_direct_presence_opt_in(&alice.identity().contact_card, true, None)
        .await
        .expect("receiver opt in");
    ipc.set_direct_presence(&bob.identity().contact_card, PresenceMode::Away, 30, None)
        .await
        .expect("send presence through IPC");
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), bob_events.recv())
            .await
            .expect("bob presence timeout")
            .expect("bob events closed");
        if let ClientEvent::PresenceChanged {
            reachability: Reachability::Away,
            ..
        } = event
        {
            break;
        }
    }
    ipc.send_direct(&bob.identity().contact_card, b"from ipc", None)
        .await
        .expect("send through IPC");
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), bob_events.recv())
            .await
            .expect("bob event timeout")
            .expect("bob events closed");
        if let ClientEvent::DirectMessage { body, .. } = event {
            assert_eq!(body, b"from ipc");
            break;
        }
    }

    ipc.submit_opaque(
        &bob.identity().contact_card,
        "application/vnd.ghost.report",
        b"sealed report",
    )
    .await
    .expect("submit opaque report");
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), bob_events.recv())
            .await
            .expect("opaque event timeout")
            .expect("bob events closed");
        if let ClientEvent::DirectMessage { body, .. } = event {
            assert_eq!(
                ApplicationMessage::decode(&body).unwrap(),
                ApplicationMessage {
                    content_type: "application/vnd.ghost.report".into(),
                    body: b"sealed report".to_vec(),
                }
            );
            break;
        }
    }

    let mut ipc_events = ipc.subscribe_events();
    bob.set_direct_presence_opt_in(&alice.identity().contact_card, true, None)
        .await
        .expect("bob sender opt in");
    ipc.set_direct_presence_opt_in(&bob.identity().contact_card, true, None)
        .await
        .expect("IPC receiver opt in");
    bob.set_direct_presence(&alice.identity().contact_card, PresenceMode::Away, 30, None)
        .await
        .expect("send presence to IPC node");
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), ipc_events.recv())
            .await
            .expect("IPC presence timeout")
            .expect("IPC events closed");
        if let ClientEvent::PresenceChanged {
            reachability: Reachability::Away,
            ..
        } = event
        {
            break;
        }
    }
    bob.send_direct(&alice.identity().contact_card, b"to ipc", None)
        .await
        .expect("send to IPC node");
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), ipc_events.recv())
            .await
            .expect("IPC event timeout")
            .expect("IPC events closed");
        if let ClientEvent::DirectMessage { body, .. } = event {
            assert_eq!(body, b"to ipc");
            break;
        }
    }

    server.abort();
    alice.node().shutdown().await;
    bob.node().shutdown().await;
    relay.node().shutdown().await;
    let _ = std::fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_component_accessor_survives_clone_and_route() {
    use gcoms_sdk::machine::{ComponentCredentials, ComponentRegistration, MachineRegistry};
    let backend = embedded(0xD4).await;
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("g.sock");
    let credentials = ComponentCredentials {
        component_id: [7; 16],
        token: [8; 32],
    };
    let registry = MachineRegistry {
        version: 1,
        components: vec![ComponentRegistration {
            credentials: credentials.clone(),
            capabilities: vec![Capability::IdentityRead],
            peers: vec![],
            files: None,
        }],
    };
    let server = tokio::spawn(gcoms_sdk::ipc::serve_machine(
        path.clone(),
        backend.clone(),
        registry,
    ));
    let client = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(c) = IpcClient::connect_component(
                &path,
                "subject-test",
                vec![Capability::IdentityRead],
                credentials.clone(),
            )
            .await
            {
                break c;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(client.authenticated_component_id(), Some([7; 16]));
    assert_eq!(client.clone().authenticated_component_id(), Some([7; 16]));
    assert_eq!(
        client
            .routed([9; 16], [10; 16])
            .authenticated_component_id(),
        Some([7; 16])
    );
    let mut wrong = credentials;
    wrong.token = [0; 32];
    assert!(
        IpcClient::connect_component(&path, "wrong", vec![Capability::IdentityRead], wrong)
            .await
            .is_err()
    );
    drop(client);
    server.abort();
    let _ = server.await;
    backend.node().shutdown().await;
}
