//! Registration and dispatch for a shared machine transport. Local credentials
//! select a component; they do not claim isolation from the owning OS account.

use crate::{
    ipc::{Capability, Request, Response},
    ApplicationMessage, ContactCard, GcClient, SdkError,
};
use gcoms_core::component::{ComponentId, RoutedApplication};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentCredentials {
    pub component_id: ComponentId,
    pub token: [u8; 32],
}

impl std::fmt::Debug for ComponentCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComponentCredentials")
            .field("component_id", &self.component_id)
            .field("token", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPeer {
    pub identity: Vec<u8>,
    pub component_id: ComponentId,
    /// Exact application content types permitted in either direction.
    pub content_types: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRegistration {
    pub credentials: ComponentCredentials,
    pub capabilities: Vec<Capability>,
    pub peers: Vec<ComponentPeer>,
    #[serde(default)]
    pub files: Option<crate::files::FileStorage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineRegistry {
    pub version: u16,
    pub components: Vec<ComponentRegistration>,
}

impl MachineRegistry {
    pub fn routing_policy(&self) -> gcoms_core::component::RoutingPolicy {
        gcoms_core::component::RoutingPolicy {
            bootstrap_listeners: self
                .components
                .iter()
                .filter(|c| c.capabilities.contains(&Capability::BootstrapApplication))
                .map(|c| c.credentials.component_id)
                .collect(),
            components: self
                .components
                .iter()
                .map(|c| c.credentials.component_id)
                .collect(),
            routes: self
                .components
                .iter()
                .flat_map(|c| {
                    c.peers
                        .iter()
                        .map(move |p| gcoms_core::component::RoutePermission {
                            local: c.credentials.component_id,
                            remote: p.component_id,
                            peer_identity: p.identity.clone(),
                            content_types: p.content_types.clone(),
                        })
                })
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), SdkError> {
        if self.version != 1 || self.components.is_empty() || self.components.len() > 64 {
            return Err(SdkError::Protocol(
                "invalid machine registry version or size".into(),
            ));
        }
        for (index, component) in self.components.iter().enumerate() {
            if component.credentials.component_id == [0; 16]
                || component.credentials.token == [0; 32]
                || self.components[..index].iter().any(|known| {
                    known.credentials.component_id == component.credentials.component_id
                        || constant_time_equal(
                            &known.credentials.token,
                            &component.credentials.token,
                        )
                })
                || component.capabilities.iter().any(|cap| {
                    !matches!(
                        cap,
                        Capability::IdentityRead
                            | Capability::IdentitySign
                            | Capability::EventRead
                            | Capability::DurableApplication
                            | Capability::FileTransfer
                            | Capability::VolatileApplication
                            | Capability::BootstrapApplication
                            | Capability::HostShell
                            | Capability::ChannelMember
                    )
                })
                || !component.capabilities.contains(&Capability::IdentityRead)
                || component.peers.len() > 64
            {
                return Err(SdkError::Protocol("invalid component registration".into()));
            }
            if component
                .capabilities
                .contains(&Capability::BootstrapApplication)
                && (!component.peers.is_empty()
                    || component.files.is_some()
                    || component.capabilities.iter().any(|c| {
                        !matches!(
                            c,
                            Capability::IdentityRead
                                | Capability::EventRead
                                | Capability::BootstrapApplication
                        )
                    }))
            {
                return Err(SdkError::Protocol(
                    "bootstrap listener must have its own restricted registration".into(),
                ));
            }
            if component.files.as_ref().is_some_and(|files| {
                files.attempt_trust_file.as_ref().is_some_and(|p| {
                    !p.is_absolute()
                        || p.components()
                            .any(|part| matches!(part, std::path::Component::ParentDir))
                }) || !files.directory.is_absolute()
                    || files
                        .directory
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                    || files.state_auth_key == [0; 32]
                    || files.disk_quota_bytes == 0
                    || files.max_file_size == 0
                    || files.max_file_size > files.disk_quota_bytes
                    || self.components[..index].iter().any(|c| {
                        c.files.as_ref().is_some_and(|f| {
                            f.directory.starts_with(&files.directory)
                                || files.directory.starts_with(&f.directory)
                        })
                    })
            }) {
                return Err(SdkError::Protocol("invalid component file storage".into()));
            }
            for (peer_index, peer) in component.peers.iter().enumerate() {
                if peer.identity.len() != 1952
                    || peer.component_id == [0; 16]
                    || peer.content_types.is_empty()
                    || peer.content_types.len() > 64
                    || component.peers[..peer_index].iter().any(|known| {
                        known.identity == peer.identity && known.component_id == peer.component_id
                    })
                    || peer.content_types.iter().any(|kind| {
                        kind == gcoms_core::component::CONTENT_TYPE
                            || !crate::application_body_limit(kind)
                                .is_ok_and(|limit| limit >= gcoms_core::component::OVERHEAD)
                    })
                {
                    return Err(SdkError::Protocol("invalid component peer".into()));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn authenticate(
        &self,
        credentials: &ComponentCredentials,
    ) -> Result<ComponentRegistration, SdkError> {
        self.components
            .iter()
            .find(|entry| {
                entry.credentials.component_id == credentials.component_id
                    && constant_time_equal(&entry.credentials.token, &credentials.token)
            })
            .cloned()
            .ok_or(SdkError::PermissionDenied)
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

impl ComponentRegistration {
    #[cfg(all(any(unix, windows), feature = "ipc"))]
    pub(crate) fn filter_event(
        &self,
        event: crate::ClientEvent,
        version: u16,
    ) -> Option<crate::ClientEvent> {
        if version < 16
            && self
                .capabilities
                .contains(&Capability::BootstrapApplication)
        {
            return None;
        }
        match event {
            crate::ClientEvent::IdentityUpdated { .. } => Some(event),
            crate::ClientEvent::VolatileApplication {
                peer_identity,
                message_id,
                timestamp_unix,
                body,
                ..
            } if version >= 12 => {
                if version >= 16
                    && self
                        .capabilities
                        .contains(&Capability::BootstrapApplication)
                {
                    let route = RoutedApplication::decode(&body).ok()?;
                    let app = ApplicationMessage::decode(&route.application).ok()?;
                    if route.destination != self.credentials.component_id
                        || !crate::bootstrap::valid_application(&app.content_type, &app.body)
                    {
                        return None;
                    }
                    return Some(crate::ClientEvent::VolatileApplication {
                        peer_identity,
                        message_id,
                        timestamp_unix,
                        source_component: Some(route.source),
                        destination_component: Some(route.destination),
                        body: route.application,
                    });
                }
                let route = self.incoming(&peer_identity, &body).ok()?;
                if self.files.is_some()
                    && gcoms_core::component::application_parts(&route.application)
                        .is_some_and(|(kind, _)| kind == gcoms_core::VOLATILE_FILE_CONTENT_TYPE)
                {
                    return None;
                }
                Some(crate::ClientEvent::VolatileApplication {
                    peer_identity,
                    message_id,
                    timestamp_unix,
                    source_component: Some(route.source),
                    destination_component: Some(route.destination),
                    body: route.application,
                })
            }
            _ => None,
        }
    }

    fn incoming(&self, peer_identity: &[u8], body: &[u8]) -> Result<RoutedApplication, SdkError> {
        let route = RoutedApplication::decode(body).map_err(|_| SdkError::PermissionDenied)?;
        let app = ApplicationMessage::decode(&route.application)?;
        if route.destination != self.credentials.component_id
            || !self.peers.iter().any(|peer| {
                peer.identity == peer_identity
                    && peer.component_id == route.source
                    && peer.content_types.contains(&app.content_type)
            })
        {
            return Err(SdkError::PermissionDenied);
        }
        Ok(route)
    }

    async fn send<C: GcClient>(
        &self,
        client: &C,
        peer: ContactCard,
        destination: Option<ComponentId>,
        volatile: bool,
        content_type: String,
        mut body: Zeroizing<Vec<u8>>,
    ) -> Result<Response, SdkError> {
        let identity = client.contact_identity(&peer)?;
        let mut destinations = self.peers.iter().filter(|remote| {
            remote.identity == identity
                && destination.is_none_or(|id| id == remote.component_id)
                && remote.content_types.contains(&content_type)
        });
        let remote = destinations.next().ok_or(SdkError::PermissionDenied)?;
        if destinations.next().is_some() {
            return Err(SdkError::Protocol(
                "ambiguous destination component; select an explicit destination".into(),
            ));
        }
        let application = Zeroizing::new(ApplicationMessage {
            content_type,
            body: std::mem::take(&mut *body),
        });
        let route = Zeroizing::new(RoutedApplication {
            source: self.credentials.component_id,
            destination: remote.component_id,
            application: application.encode()?,
        });
        let wire = Zeroizing::new(
            route
                .encode()
                .map_err(|error| SdkError::Protocol(error.into()))?,
        );
        let local_identity = client.contact_identity(&client.identity().contact_card)?;
        if identity == local_identity {
            if volatile {
                return Err(SdkError::PermissionDenied);
            }
            client.submit_local_component(&wire).await?;
            return Ok(Response::Empty);
        }
        let routed = Zeroizing::new(ApplicationMessage::decode(&wire)?);
        if volatile {
            client
                .submit_volatile_opaque(&peer, &routed.content_type, &routed.body)
                .await?;
        } else {
            client
                .submit_durable_opaque(&peer, &routed.content_type, &routed.body)
                .await?;
        }
        Ok(Response::Empty)
    }
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub(crate) async fn dispatch<C: GcClient>(
    client: &C,
    component: &ComponentRegistration,
    request: Request,
) -> Result<Response, SdkError> {
    match request {
        Request::AdmitBootstrapPeer { .. } | Request::SubmitBootstrap { .. } => {
            Err(SdkError::PermissionDenied)
        }
        Request::SubmitVolatileComponent {
            recipient,
            destination,
            content_type,
            body,
        } => {
            let body = Zeroizing::new(body);
            if !gcoms_core::is_volatile_content_type(&content_type) {
                return Err(SdkError::PermissionDenied);
            }
            component
                .send(
                    client,
                    recipient,
                    Some(destination),
                    true,
                    content_type,
                    body,
                )
                .await
        }
        Request::Shell(request) => client
            .component_shell(component.credentials.component_id, request)
            .await
            .map(Response::Shell),
        Request::File(request) => {
            if component.files.is_none()
                || (request.is_managed()
                    && component
                        .files
                        .as_ref()
                        .is_none_or(|f| f.attempt_trust_file.is_none()))
            {
                return Err(SdkError::PermissionDenied);
            }
            if let crate::files::FileRequest::Offer {
                peer, destination, ..
            } = &request
            {
                let identity = client.contact_identity(peer)?;
                if !component.peers.iter().any(|p| {
                    p.identity == identity
                        && p.component_id == *destination
                        && p.content_types
                            .iter()
                            .any(|k| k == crate::files::CONTENT_TYPE)
                        && p.content_types
                            .iter()
                            .any(|k| k == crate::files::ACK_CONTENT_TYPE)
                }) {
                    return Err(SdkError::PermissionDenied);
                }
            }
            client
                .component_files(component.credentials.component_id, request)
                .await
                .map(Response::File)
        }
        Request::SubmitDurableOpaque {
            recipient,
            content_type,
            body,
        } => {
            component
                .send(
                    client,
                    recipient,
                    None,
                    false,
                    content_type,
                    Zeroizing::new(body),
                )
                .await
        }
        Request::SubmitComponent {
            recipient,
            destination,
            content_type,
            body,
        } => {
            component
                .send(
                    client,
                    recipient,
                    Some(destination),
                    false,
                    content_type,
                    Zeroizing::new(body),
                )
                .await
        }
        Request::ApplicationInbox { after, limit } => {
            if limit == 0 || limit > 32 {
                return Err(SdkError::Protocol(
                    "invalid component inbox page size".into(),
                ));
            }
            let mut cursor = after;
            let mut entries = Vec::new();
            loop {
                let page = client.application_inbox(cursor, 32).await?;
                let exhausted = page.len() < 32;
                for mut entry in page {
                    cursor = entry.sequence;
                    if let Ok(route) = component.incoming(&entry.peer_identity, &entry.body) {
                        if component.files.is_some()
                            && gcoms_core::component::application_parts(&route.application)
                                .is_some_and(|(kind, _)| kind == crate::files::CONTENT_TYPE)
                        {
                            continue;
                        }
                        entry.source_component = Some(route.source);
                        entry.destination_component = Some(route.destination);
                        entry.body = route.application;
                        entries.push(entry);
                        if entries.len() == usize::from(limit) {
                            return Ok(Response::ApplicationInbox(entries));
                        }
                    }
                }
                if exhausted {
                    return Ok(Response::ApplicationInbox(entries));
                }
            }
        }
        Request::CommitApplication { sequence, digest } => {
            if sequence == 0 {
                return Err(SdkError::PermissionDenied);
            }
            let page = client.application_inbox(sequence - 1, 1).await?;
            if let Some(entry) = page.first().filter(|entry| entry.sequence == sequence) {
                let route = component.incoming(&entry.peer_identity, &entry.body)?;
                if component.files.is_some()
                    && gcoms_core::component::application_parts(&route.application)
                        .is_some_and(|(kind, _)| kind == crate::files::CONTENT_TYPE)
                {
                    return Err(SdkError::PermissionDenied);
                }
                if entry.receipt_digest != digest {
                    return Err(SdkError::PermissionDenied);
                }
            }
            client.commit_application(sequence, digest).await?;
            Ok(Response::Empty)
        }
        // Machine membership is deliberately narrower than the personal-chat
        // ChannelMember interface: no sending, administration or removal.
        request @ (Request::PrepareChannelJoin { .. }
        | Request::ChannelKeyPackage { .. }
        | Request::JoinChannel { .. }
        | Request::ListChannels
        | Request::ChannelRoster { .. }) => crate::ipc::dispatch(client, request).await,
        request @ (Request::Identity
        | Request::FileRoute
        | Request::ContactIdentity { .. }
        | Request::SignIdentityDigest { .. }
        | Request::SignPrincipalBindingHash { .. }
        | Request::SubscribeEvents) => crate::ipc::dispatch(client, request).await,
        _ => Err(SdkError::PermissionDenied),
    }
}

#[cfg(all(test, any(unix, windows), feature = "ipc"))]
mod volatile_tests {
    use super::*;
    #[test]
    fn scoped_volatile_event_rejects_wrong_peer_source_destination_type_and_old_version() {
        let registration = ComponentRegistration {
            credentials: ComponentCredentials {
                component_id: [1; 16],
                token: [2; 32],
            },
            capabilities: vec![
                Capability::IdentityRead,
                Capability::EventRead,
                Capability::VolatileApplication,
            ],
            peers: vec![ComponentPeer {
                identity: vec![7; 1952],
                component_id: [3; 16],
                content_types: vec![gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE.into()],
            }],
            files: None,
        };
        let packet = |peer: u8, source: u8, destination: u8, kind: &str| {
            crate::ClientEvent::VolatileApplication {
                peer_identity: vec![peer; 1952],
                message_id: crate::MessageId([8; 16]),
                timestamp_unix: 1,
                source_component: None,
                destination_component: None,
                body: RoutedApplication {
                    source: [source; 16],
                    destination: [destination; 16],
                    application: ApplicationMessage {
                        content_type: kind.into(),
                        body: vec![9],
                    }
                    .encode()
                    .unwrap(),
                }
                .encode()
                .unwrap(),
            }
        };
        for (peer, source, destination, kind, version) in [
            (6, 3, 1, gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE, 12),
            (7, 4, 1, gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE, 12),
            (7, 3, 2, gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE, 12),
            (7, 3, 1, "other/type", 12),
            (7, 3, 1, gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE, 11),
        ] {
            assert!(registration
                .filter_event(packet(peer, source, destination, kind), version)
                .is_none());
        }
        let Some(crate::ClientEvent::VolatileApplication {
            source_component,
            destination_component,
            body,
            ..
        }) = registration.filter_event(
            packet(7, 3, 1, gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE),
            12,
        )
        else {
            panic!("scoped event required")
        };
        assert_eq!(source_component, Some([3; 16]));
        assert_eq!(destination_component, Some([1; 16]));
        assert_eq!(ApplicationMessage::decode(&body).unwrap().body, vec![9]);
    }
}
