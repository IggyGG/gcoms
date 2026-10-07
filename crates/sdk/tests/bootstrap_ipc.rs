#![cfg(all(unix, feature = "embedded", feature = "ipc"))]

use gcoms_core::{
    bootstrap::CONTENT_TYPE,
    component::RoutedApplication,
    file_stream::{Contact, FileContact, PROFILE_VERSION_V2},
    payload_contact::PayloadContact,
    VOLATILE_CONTACT_CONTENT_TYPE,
};
use gcoms_node::node::{start, NodeConfig, NodeProfile};
use gcoms_sdk::{
    ipc::{serve_machine_on_listener_until, Capability},
    local::LocalListener,
    machine::{ComponentCredentials, ComponentRegistration, MachineRegistry},
    ApplicationMessage, ClientEvent, ContactCard, EmbeddedClient, GcClient, IpcClient,
    LocalEndpoint, SdkError,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

async fn embedded(seed: u8) -> EmbeddedClient {
    // This isolates the real SDK/IPC boundary over the local Legacy carrier.
    // It is not an Android or production GC/2 transport qualification.
    EmbeddedClient::new(
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
        .unwrap(),
    )
}

async fn send(
    sender: &EmbeddedClient,
    recipient: &ContactCard,
    source: u8,
    destination: u8,
    kind: &str,
    body: &[u8],
) {
    let wire = RoutedApplication {
        source: [source; 16],
        destination: [destination; 16],
        application: ApplicationMessage {
            content_type: kind.into(),
            body: body.to_vec(),
        }
        .encode()
        .unwrap(),
    }
    .encode()
    .unwrap();
    let outer = ApplicationMessage::decode(&wire).unwrap();
    sender
        .submit_volatile_opaque(recipient, &outer.content_type, &outer.body)
        .await
        .unwrap();
}

async fn next(events: &mut mpsc::Receiver<ClientEvent>) -> ClientEvent {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("SDK event deadline")
            .expect("SDK event stream open");
        assert!(!matches!(event, ClientEvent::EventsLagged { .. }));
        if matches!(event, ClientEvent::VolatileApplication { .. }) {
            return event;
        }
    }
}

fn assert_event(event: ClientEvent, identity: &[u8], kind: &str, bytes: &[u8]) {
    let ClientEvent::VolatileApplication {
        peer_identity,
        source_component,
        destination_component,
        body,
        ..
    } = event
    else {
        panic!("volatile application expected")
    };
    assert_eq!(peer_identity, identity);
    assert_eq!(source_component, Some([4; 16]));
    assert_eq!(destination_component, Some([7; 16]));
    let app = ApplicationMessage::decode(&body).unwrap();
    assert_eq!(app.content_type, kind);
    assert_eq!(app.body, bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_payload_contact_crosses_real_ipc_and_is_scoped_to_connection_and_components() {
    let sender = embedded(0xE4).await;
    let owner = embedded(0xE5).await;
    let mut sender_events = sender.subscribe_events();
    let mut owner_events = owner.subscribe_events();
    let identity = sender
        .contact_identity(&sender.identity().contact_card)
        .unwrap();
    let credentials = ComponentCredentials {
        component_id: [7; 16],
        token: [8; 32],
    };
    let capabilities = vec![
        Capability::IdentityRead,
        Capability::EventRead,
        Capability::BootstrapApplication,
    ];
    let registry = MachineRegistry {
        version: 1,
        components: vec![ComponentRegistration {
            credentials: credentials.clone(),
            capabilities: capabilities.clone(),
            peers: vec![],
            files: None,
        }],
    };
    registry.validate().unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("bootstrap.sock");
    let listener = LocalListener::bind(&LocalEndpoint::new(&path)).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_machine_on_listener_until(
        listener,
        owner.clone(),
        registry,
        async {
            let _ = stopped.await;
        },
    ));
    let controller =
        IpcClient::connect_component(&path, "admitted", capabilities.clone(), credentials.clone())
            .await
            .unwrap();
    let observer = IpcClient::connect_component(
        &path,
        "unadmitted",
        capabilities.clone(),
        credentials.clone(),
    )
    .await
    .unwrap();
    assert_ne!(controller.event_stream_id(), observer.event_stream_id());
    let mut events = controller.subscribe_events();
    let mut observed = observer.subscribe_events();
    let result = tokio::time::timeout(Duration::from_secs(45), async {
        let recipient = owner.identity().contact_card;
        // Volatile application submission deliberately cannot create a peer
        // session. Establish one with the public SDK and its authenticated ACK.
        sender
            .send_direct(&recipient, b"session setup", None)
            .await
            .unwrap();
        let id = loop {
            if let Some(ClientEvent::DirectMessage {
                peer_identity,
                message_id,
                body,
                ..
            }) = owner_events.recv().await
            {
                assert_eq!(peer_identity, identity);
                assert_eq!(body, b"session setup");
                break message_id;
            }
        };
        loop {
            if let Some(ClientEvent::DirectDelivered {
                peer_identity,
                message_id,
            }) = sender_events.recv().await
            {
                assert_eq!(peer_identity, owner.contact_identity(&recipient).unwrap());
                assert_eq!(message_id, id);
                break;
            }
        }
        send(&sender, &recipient, 4, 7, CONTENT_TYPE, b"admission").await;
        assert_event(
            next(&mut events).await,
            &identity,
            CONTENT_TYPE,
            b"admission",
        );
        assert_event(
            next(&mut observed).await,
            &identity,
            CONTENT_TYPE,
            b"admission",
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        controller
            .admit_bootstrap_peer(identity.clone(), [4; 16], now + 600)
            .await
            .unwrap();
        controller
            .clone()
            .submit_bootstrap(
                sender.identity().contact_card,
                [4; 16],
                CONTENT_TYPE.into(),
                b"payload reply".to_vec(),
            )
            .await
            .unwrap();
        let ClientEvent::VolatileApplication {
            peer_identity,
            body,
            ..
        } = next(&mut sender_events).await
        else {
            unreachable!()
        };
        assert_eq!(peer_identity, owner.contact_identity(&recipient).unwrap());
        let route = RoutedApplication::decode(&body).unwrap();
        assert_eq!((route.source, route.destination), ([7; 16], [4; 16]));
        let reply = ApplicationMessage::decode(&route.application).unwrap();
        assert_eq!(reply.content_type, CONTENT_TYPE);
        assert_eq!(reply.body, b"payload reply");

        let contact = PayloadContact::new(
            [1; 16],
            [7; 32],
            FileContact {
                profile_version: PROFILE_VERSION_V2,
                transfer_id: [2; 16],
                recipient_contact: Contact {
                    address: "192.0.2.1:443".parse().unwrap(),
                    relay_service_id: [3; 32],
                    queue_id: [4; 32],
                    epoch: 1,
                    push_cap: [5; 32],
                    lease_expiry: now + 900,
                },
                file_cap: [6; 32],
                contact_expiry: now + 600,
                max_file_size: 5_235_248,
                max_chunk_size: 4096,
                max_inflight_bytes: 8192,
            },
            now,
        )
        .unwrap()
        .encode(now)
        .unwrap();
        assert_eq!(contact.len(), 268);
        send(
            &sender,
            &recipient,
            4,
            7,
            VOLATILE_CONTACT_CONTENT_TYPE,
            &contact,
        )
        .await;
        assert_event(
            next(&mut events).await,
            &identity,
            VOLATILE_CONTACT_CONTENT_TYPE,
            &contact,
        );

        // A later authenticated event is an ordering barrier, avoiding a
        // timing-only assertion that the unadmitted stream dropped Contact.
        send(&sender, &recipient, 4, 7, CONTENT_TYPE, b"after contact").await;
        assert_event(
            next(&mut events).await,
            &identity,
            CONTENT_TYPE,
            b"after contact",
        );
        assert_event(
            next(&mut observed).await,
            &identity,
            CONTENT_TYPE,
            b"after contact",
        );
        // Drain the raw node copy up to this authenticated marker first; the
        // following negative controls must each be proved received by the node.
        loop {
            let ClientEvent::VolatileApplication { body, .. } = next(&mut owner_events).await
            else {
                unreachable!()
            };
            let route = RoutedApplication::decode(&body).unwrap();
            if ApplicationMessage::decode(&route.application).unwrap().body == b"after contact" {
                break;
            }
        }
        for (source, destination) in [(5, 7), (4, 9)] {
            send(
                &sender,
                &recipient,
                source,
                destination,
                VOLATILE_CONTACT_CONTENT_TYPE,
                &contact,
            )
            .await;
            let ClientEvent::VolatileApplication {
                peer_identity,
                body,
                ..
            } = next(&mut owner_events).await
            else {
                unreachable!()
            };
            assert_eq!(peer_identity, identity);
            let route = RoutedApplication::decode(&body).unwrap();
            assert_eq!(
                (route.source, route.destination),
                ([source; 16], [destination; 16])
            );
            let app = ApplicationMessage::decode(&route.application).unwrap();
            assert_eq!(app.content_type, VOLATILE_CONTACT_CONTENT_TYPE);
            assert_eq!(app.body, contact);
        }
        send(
            &sender,
            &recipient,
            4,
            7,
            CONTENT_TYPE,
            b"after wrong component",
        )
        .await;
        assert_event(
            next(&mut events).await,
            &identity,
            CONTENT_TYPE,
            b"after wrong component",
        );
        assert_event(
            next(&mut observed).await,
            &identity,
            CONTENT_TYPE,
            b"after wrong component",
        );

        observer.close().await;
        let fresh = IpcClient::connect_component(&path, "reconnected", capabilities, credentials)
            .await
            .unwrap();
        assert_ne!(fresh.event_stream_id(), observer.event_stream_id());
        let mut fresh_events = fresh.subscribe_events();
        assert_eq!(
            fresh
                .admit_bootstrap_peer(identity.clone(), [4; 16], now + 600)
                .await,
            Err(SdkError::PermissionDenied),
            "another session's admission is not inherited"
        );
        send(&sender, &recipient, 4, 7, CONTENT_TYPE, b"fresh admission").await;
        assert_event(
            next(&mut events).await,
            &identity,
            CONTENT_TYPE,
            b"fresh admission",
        );
        assert_event(
            next(&mut fresh_events).await,
            &identity,
            CONTENT_TYPE,
            b"fresh admission",
        );
        fresh
            .admit_bootstrap_peer(identity.clone(), [4; 16], now + 600)
            .await
            .unwrap();
        send(
            &sender,
            &recipient,
            4,
            7,
            VOLATILE_CONTACT_CONTENT_TYPE,
            &contact,
        )
        .await;
        assert_event(
            next(&mut events).await,
            &identity,
            VOLATILE_CONTACT_CONTENT_TYPE,
            &contact,
        );
        assert_event(
            next(&mut fresh_events).await,
            &identity,
            VOLATILE_CONTACT_CONTENT_TYPE,
            &contact,
        );
        fresh.close().await;
    })
    .await;
    controller.close().await;
    observer.close().await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    sender.node().shutdown().await;
    owner.node().shutdown().await;
    result.expect("bounded SDK bootstrap journey");
}
