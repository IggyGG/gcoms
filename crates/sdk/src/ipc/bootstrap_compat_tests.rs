use super::*;
use crate::machine::{ComponentCredentials, ComponentRegistration, MachineRegistry};
use std::time::Duration;

fn bootstrap_event() -> ClientEvent {
    ClientEvent::VolatileApplication {
        peer_identity: vec![3; 1952],
        message_id: crate::MessageId([1; 16]),
        timestamp_unix: 1,
        source_component: Some([4; 16]),
        destination_component: Some([7; 16]),
        body: ApplicationMessage {
            content_type: gcoms_core::bootstrap::CONTENT_TYPE.into(),
            body: vec![9],
        }
        .encode()
        .unwrap(),
    }
}

#[test]
fn bootstrap_control_never_leaks_through_an_old_volatile_event_subscription() {
    let event = bootstrap_event();
    let ordinary = [Capability::EventRead, Capability::VolatileApplication];
    let bootstrap = [Capability::EventRead, Capability::BootstrapApplication];
    for version in 10..=16 {
        assert!(!event_allowed_for_version(&event, &ordinary, version));
        assert_eq!(
            event_allowed_for_version(&event, &bootstrap, version),
            version == 16
        );
    }
    let mut file = event;
    if let ClientEvent::VolatileApplication { body, .. } = &mut file {
        *body = ApplicationMessage {
            content_type: gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE.into(),
            body: vec![9],
        }
        .encode()
        .unwrap();
    }
    for version in 12..=16 {
        assert!(event_allowed_for_version(&file, &ordinary, version));
    }
}

#[tokio::test]
async fn v16_routed_event_populates_only_the_current_bootstrap_session_before_admission() {
    let node = node().await;
    let client = crate::EmbeddedClient::new(node.clone());
    let registration = registry().components[0].clone();
    let mut event = bootstrap_event();
    if let ClientEvent::VolatileApplication { body, .. } = &mut event {
        *body = gcoms_core::component::RoutedApplication {
            source: [4; 16],
            destination: [7; 16],
            application: body.clone(),
        }
        .encode()
        .unwrap();
    }
    let (sender, mut events) = mpsc::channel(1);
    sender.send(event).await.unwrap();
    let (stream, mut peer) = tokio::io::duplex(65536);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut sequence = 1;
    let mut session = crate::bootstrap::Session::default();
    let reading = read_request_with_events(
        &mut reader,
        &mut writer,
        &mut events,
        &registration.capabilities,
        true,
        &mut sequence,
        Some(&registration),
        16,
        &mut session,
    );
    let receiving = async {
        let Frame::Event(event) = read_frame(&mut peer).await.unwrap() else {
            panic!("event")
        };
        assert_eq!(event.version, 16);
        write_frame(
            &mut peer,
            &Frame::Request(RequestEnvelope {
                version: 16,
                request_id: 1,
                request: Request::Identity,
            }),
        )
        .await
        .unwrap();
    };
    let (result, ()) = tokio::join!(reading, receiving);
    assert!(matches!(result.unwrap(), Frame::Request(_)));
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let request = Request::AdmitBootstrapPeer {
        peer_identity: vec![3; 1952],
        source: [4; 16],
        expires_at_unix: expiry,
    };
    assert_eq!(
        session.dispatch(&client, [7; 16], request.clone()).await,
        Ok(Response::Empty)
    );
    assert_eq!(
        crate::bootstrap::Session::default()
            .dispatch(&client, [7; 16], request)
            .await,
        Err(SdkError::PermissionDenied)
    );
    node.shutdown().await;
}

async fn node() -> gcoms_node::node::NodeHandle {
    gcoms_node::node::start(gcoms_node::node::NodeConfig {
        seed: [91; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .unwrap()
}

fn credentials() -> ComponentCredentials {
    ComponentCredentials {
        component_id: [7; 16],
        token: [8; 32],
    }
}

fn registry() -> Arc<MachineRegistry> {
    let registry = MachineRegistry {
        version: 1,
        components: vec![ComponentRegistration {
            credentials: credentials(),
            capabilities: vec![
                Capability::IdentityRead,
                Capability::EventRead,
                Capability::BootstrapApplication,
            ],
            peers: vec![],
            files: None,
        }],
    };
    registry.validate().unwrap();
    Arc::new(registry)
}

#[test]
fn append_only_bootstrap_wire_allocations_and_registry_names() {
    for (request, bytes) in [
        (
            Request::AdmitBootstrapPeer {
                peer_identity: vec![],
                source: [0; 16],
                expires_at_unix: 1,
            },
            [vec![35, 0], vec![0; 16], vec![1]].concat(),
        ),
        (
            Request::SubmitBootstrap {
                recipient: ContactCard(vec![]),
                destination: [0; 16],
                content_type: String::new(),
                body: vec![],
            },
            [vec![36, 0], vec![0; 16], vec![0, 0]].concat(),
        ),
    ] {
        assert_eq!(postcard::to_allocvec(&request).unwrap(), bytes);
        assert_eq!(postcard::from_bytes::<Request>(&bytes).unwrap(), request);
        assert_eq!(request.minimum_version(), 16);
        assert_eq!(
            request.required_capability(),
            Capability::BootstrapApplication
        );
    }
    assert_eq!(
        postcard::to_allocvec(&Capability::CatalogAccess).unwrap(),
        [12]
    );
    assert_eq!(
        postcard::to_allocvec(&Capability::BootstrapApplication).unwrap(),
        [13]
    );
    assert_eq!(postcard::to_allocvec(&Response::Empty).unwrap(), [1]);
    let wire = postcard::to_allocvec(&*registry()).unwrap();
    let restored: MachineRegistry = postcard::from_bytes(&wire).unwrap();
    restored.validate().unwrap();
    assert_eq!(
        restored.components[0].capabilities,
        registry().components[0].capabilities
    );
}

#[tokio::test]
async fn frozen_bootstrap_v13_hello_rejects_before_buffered_colliding_requests() {
    let node = node().await;
    // Frozen postcard Hello from the v13 fork: IdentityRead, EventRead,
    // BootstrapApplication (12), no component. Do not encode with current enums.
    let hello = [vec![0, 0, 13, 13, 6], b"legacy".to_vec(), vec![3, 1, 6, 12]].concat();
    for request in [
        [
            vec![2, 13, 1, 30, 0xa0, 0x0f],
            vec![3; 1952],
            vec![4; 16],
            vec![1],
        ]
        .concat(),
        [vec![2, 13, 1, 31, 0], vec![4; 16], vec![0, 0]].concat(),
    ] {
        let (mut peer, stream) = tokio::io::duplex(65536);
        let server = tokio::spawn(serve_connection(
            stream,
            crate::EmbeddedClient::new(node.clone()),
            vec![
                Capability::IdentityRead,
                Capability::EventRead,
                Capability::DirectMessage,
                Capability::ChannelMember,
                Capability::CatalogAccess,
            ],
            None,
        ));
        for bytes in [&hello, &request] {
            peer.write_all(&(bytes.len() as u32).to_be_bytes())
                .await
                .unwrap();
            peer.write_all(bytes).await.unwrap();
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            Err(SdkError::Protocol(
                "incompatible IPC capability version".into()
            ))
        );
        let mut byte = [0];
        assert_eq!(
            peer.read(&mut byte).await.unwrap(),
            0,
            "no Welcome or effect reply"
        );
    }
    node.shutdown().await;
}

#[tokio::test]
async fn bootstrap_registration_and_capability_require_v16_before_welcome() {
    let node = node().await;
    for version in 10..16 {
        for capabilities in [
            vec![Capability::IdentityRead],
            vec![Capability::IdentityRead, Capability::BootstrapApplication],
        ] {
            let (mut peer, stream) = tokio::io::duplex(65536);
            let server = tokio::spawn(serve_connection(
                stream,
                crate::EmbeddedClient::new(node.clone()),
                vec![],
                Some(registry()),
            ));
            write_frame(
                &mut peer,
                &Frame::Hello(Hello {
                    min_version: version,
                    max_version: version,
                    application: "old-bootstrap".into(),
                    requested_capabilities: capabilities,
                    component: Some(credentials()),
                }),
            )
            .await
            .unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            assert!(read_frame(&mut peer).await.is_err());
        }
    }
    node.shutdown().await;
}

#[tokio::test]
async fn v16_bootstrap_connection_keeps_identity_and_checks_grant_and_request_version() {
    let node = node().await;
    for granted_bootstrap in [false, true] {
        let (mut peer, stream) = tokio::io::duplex(65536);
        let server = tokio::spawn(serve_connection(
            stream,
            crate::EmbeddedClient::new(node.clone()),
            vec![],
            Some(registry()),
        ));
        let mut requested = vec![Capability::IdentityRead];
        if granted_bootstrap {
            requested.push(Capability::BootstrapApplication);
        }
        write_frame(
            &mut peer,
            &Frame::Hello(Hello {
                min_version: 16,
                max_version: 16,
                application: "bootstrap16".into(),
                requested_capabilities: requested.clone(),
                component: Some(credentials()),
            }),
        )
        .await
        .unwrap();
        let Frame::Welcome(welcome) = read_frame(&mut peer).await.unwrap() else {
            panic!("welcome")
        };
        assert_eq!(welcome.granted_capabilities, requested);
        write_frame(
            &mut peer,
            &Frame::Request(RequestEnvelope {
                version: 16,
                request_id: 1,
                request: Request::Identity,
            }),
        )
        .await
        .unwrap();
        let Frame::Response(reply) = read_frame(&mut peer).await.unwrap() else {
            panic!("identity")
        };
        assert!(matches!(reply.result, Ok(Response::Identity(_))));
        write_frame(
            &mut peer,
            &Frame::Request(RequestEnvelope {
                version: 16,
                request_id: 2,
                request: Request::AdmitBootstrapPeer {
                    peer_identity: vec![3; 1952],
                    source: [4; 16],
                    expires_at_unix: u64::MAX,
                },
            }),
        )
        .await
        .unwrap();
        let Frame::Response(reply) = read_frame(&mut peer).await.unwrap() else {
            panic!("denial")
        };
        // A capability is necessary, but never supplies a pending authenticated peer.
        assert_eq!(reply.result, Err(SdkError::PermissionDenied));
        write_frame(
            &mut peer,
            &Frame::Request(RequestEnvelope {
                version: 15,
                request_id: 3,
                request: Request::Identity,
            }),
        )
        .await
        .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(read_frame(&mut peer).await.is_err());
    }
    node.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn new_bootstrap_sdk_rejects_old_welcome_without_sending_a_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let Frame::Hello(hello) = read_frame(&mut stream).await.unwrap() else {
            panic!("hello")
        };
        assert_eq!((hello.min_version, hello.max_version), (VERSION, VERSION));
        write_frame(
            &mut stream,
            &Frame::Welcome(Welcome {
                version: 15,
                granted_capabilities: vec![Capability::IdentityRead],
                event_stream_id: [1; 16],
            }),
        )
        .await
        .unwrap();
        assert!(read_frame(&mut stream).await.is_err());
    });
    assert!(IpcClient::connect_component(
        &path,
        "bootstrap16",
        vec![Capability::IdentityRead, Capability::BootstrapApplication],
        credentials()
    )
    .await
    .is_err());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}
