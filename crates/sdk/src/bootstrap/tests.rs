use super::*;
use crate::ipc::Capability;
use crate::machine::{ComponentCredentials, ComponentRegistration, MachineRegistry};

fn packet(peer: u8, source: u8, kind: &str) -> ClientEvent {
    ClientEvent::VolatileApplication {
        peer_identity: vec![peer; 1952],
        message_id: crate::MessageId([1; 16]),
        timestamp_unix: unix().unwrap(),
        source_component: Some([source; 16]),
        destination_component: Some([7; 16]),
        body: ApplicationMessage {
            content_type: kind.into(),
            body: vec![9; 100],
        }
        .encode()
        .unwrap(),
    }
}
fn listener() -> ComponentRegistration {
    ComponentRegistration {
        credentials: ComponentCredentials {
            component_id: [7; 16],
            token: [8; 32],
        },
        capabilities: vec![
            Capability::IdentityRead,
            Capability::EventRead,
            Capability::BootstrapApplication,
        ],
        peers: vec![],
        files: None,
    }
}

#[test]
fn file_events_require_current_admission_for_the_same_authenticated_peer_and_component() {
    let mut session = Session::default();
    let file = gcoms_core::VOLATILE_FILE_CONTENT_TYPE;
    assert!(session.filter_event(packet(1, 2, file)).is_none());
    assert!(session
        .admit(vec![1; 1952], [2; 16], unix().unwrap() + 600)
        .is_err());
    assert!(session
        .filter_event(packet(1, 2, gcoms_core::bootstrap::CONTENT_TYPE))
        .is_some());
    assert!(session.filter_event(packet(1, 2, file)).is_none());
    let expiry = unix().unwrap() + 600;
    session.admit(vec![1; 1952], [2; 16], expiry).unwrap();
    session.admit(vec![1; 1952], [2; 16], expiry).unwrap();
    assert!(session.admit(vec![1; 1952], [2; 16], expiry + 1).is_err());
    assert!(session.filter_event(packet(1, 2, file)).is_some());
    assert!(session.filter_event(packet(2, 2, file)).is_none());
    assert!(session.filter_event(packet(1, 3, file)).is_none());
    assert!(session.filter_event(packet(1, 2, "text/plain")).is_none());
    session
        .peers
        .get_mut(&(vec![1; 1952], [2; 16]))
        .unwrap()
        .admitted
        .as_mut()
        .unwrap()
        .deadline = Instant::now() - Duration::from_secs(1);
    assert!(session.filter_event(packet(1, 2, file)).is_none());
    assert!(session.admit(vec![1; 1952], [2; 16], expiry).is_err());
}

#[test]
fn listener_capacity_rejects_new_peers_without_extending_or_evicting_live_entries() {
    let mut session = Session::default();
    for peer in 0..128 {
        assert!(session
            .filter_event(packet(peer, 1, gcoms_core::bootstrap::CONTENT_TYPE))
            .is_some());
    }
    let original = session.peers[&(vec![0; 1952], [1; 16])].pending;
    assert!(session
        .filter_event(packet(128, 1, gcoms_core::bootstrap::CONTENT_TYPE))
        .is_none());
    assert!(session
        .filter_event(packet(0, 1, gcoms_core::bootstrap::CONTENT_TYPE))
        .is_some());
    assert_eq!(session.peers[&(vec![0; 1952], [1; 16])].pending, original);
    assert_eq!(session.peers.len(), 128);
}

#[test]
fn bootstrap_registration_cannot_inherit_managed_or_chat_capabilities_and_routes() {
    let registry = MachineRegistry {
        version: 1,
        components: vec![listener()],
    };
    registry.validate().unwrap();
    for capability in [
        Capability::DirectMessage,
        Capability::ChannelMember,
        Capability::IdentitySign,
        Capability::DurableApplication,
        Capability::VolatileApplication,
        Capability::HostShell,
        Capability::FileTransfer,
    ] {
        let mut changed = registry.clone();
        changed.components[0].capabilities.push(capability);
        assert!(changed.validate().is_err());
    }
    let mut changed = registry.clone();
    changed.components[0]
        .peers
        .push(crate::machine::ComponentPeer {
            identity: vec![3; 1952],
            component_id: [4; 16],
            content_types: vec![gcoms_core::bootstrap::CONTENT_TYPE.into()],
        });
    assert!(changed.validate().is_err());
    let wire = |kind: &str, destination| {
        RoutedApplication {
            source: [2; 16],
            destination,
            application: ApplicationMessage {
                content_type: kind.into(),
                body: vec![5; 32],
            }
            .encode()
            .unwrap(),
        }
        .encode()
        .unwrap()
    };
    let policy = registry.routing_policy();
    assert!(policy.permits(
        &vec![3; 1952],
        &wire(gcoms_core::bootstrap::CONTENT_TYPE, [7; 16])
    ));
    assert!(!policy.permits(&vec![3; 1952], &wire("text/plain", [7; 16])));
    assert!(!policy.permits(
        &vec![3; 1952],
        &wire(gcoms_core::bootstrap::CONTENT_TYPE, [6; 16])
    ));
    let registration = listener();
    let mut incoming = packet(3, 2, gcoms_core::bootstrap::CONTENT_TYPE);
    if let ClientEvent::VolatileApplication { body, .. } = &mut incoming {
        *body = wire(gcoms_core::bootstrap::CONTENT_TYPE, [7; 16]);
    }
    for version in 10..16 {
        assert!(registration
            .filter_event(incoming.clone(), version)
            .is_none());
    }
    assert!(registration.filter_event(incoming, 16).is_some());
}
