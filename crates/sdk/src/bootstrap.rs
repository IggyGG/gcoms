//! Temporary bootstrap dispatch for one explicitly registered CMD listener.
//! Peer/component grants stay in RAM and are fixed to the admitted run deadline.
use crate::ipc::{Request, Response};
#[cfg(all(any(unix, windows), feature = "ipc"))]
use crate::IpcClient;
use crate::{ApplicationMessage, ClientEvent, ContactCard, GcClient, SdkError};
use gcoms_core::component::{ComponentId, RoutedApplication};
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
#[cfg(test)]
mod tests;

pub(crate) fn valid_application(kind: &str, body: &[u8]) -> bool {
    matches!(
        kind,
        gcoms_core::bootstrap::CONTENT_TYPE
            | gcoms_core::VOLATILE_FILE_CONTENT_TYPE
            | gcoms_core::VOLATILE_FILE_ACK_CONTENT_TYPE
            | gcoms_core::VOLATILE_CONTACT_CONTENT_TYPE
    ) && body.len() <= gcoms_core::bootstrap::MAX_CONTROL_BYTES
}

struct Admission {
    expires_at: u64,
    deadline: Instant,
}
struct Peer {
    pending: Instant,
    admitted: Option<Admission>,
}
#[derive(Default)]
pub(crate) struct Session {
    peers: HashMap<(Vec<u8>, ComponentId), Peer>,
}

fn unix() -> Result<u64, SdkError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| SdkError::PermissionDenied)
}
impl Peer {
    fn live(&self, now: u64, clock: Instant) -> bool {
        self.admitted.as_ref().map_or(clock < self.pending, |a| {
            now < a.expires_at && clock < a.deadline
        })
    }
}
impl Session {
    pub(crate) fn filter_event(&mut self, event: ClientEvent) -> Option<ClientEvent> {
        let now = unix().ok()?;
        let clock = Instant::now();
        self.peers.retain(|_, peer| peer.live(now, clock));
        if matches!(
            &event,
            ClientEvent::VolatileApplication {
                source_component: None,
                ..
            } | ClientEvent::VolatileApplication {
                destination_component: None,
                ..
            }
        ) {
            return None;
        }
        if let ClientEvent::VolatileApplication {
            peer_identity,
            source_component: Some(source),
            body,
            ..
        } = &event
        {
            let app = ApplicationMessage::decode(body).ok()?;
            if peer_identity.len() != 1952 || !valid_application(&app.content_type, &app.body) {
                return None;
            }
            let key = (peer_identity.clone(), *source);
            if app.content_type == gcoms_core::bootstrap::CONTENT_TYPE {
                if !self.peers.contains_key(&key) {
                    if self.peers.len() >= 128 {
                        return None;
                    }
                    self.peers.insert(
                        key,
                        Peer {
                            pending: clock + Duration::from_secs(300),
                            admitted: None,
                        },
                    );
                }
            } else if self.peers.get(&key).is_none_or(|p| p.admitted.is_none()) {
                return None;
            }
        }
        Some(event)
    }

    fn admit(
        &mut self,
        identity: Vec<u8>,
        source: ComponentId,
        expires_at: u64,
    ) -> Result<(), SdkError> {
        let now = unix()?;
        let clock = Instant::now();
        let peer = self
            .peers
            .get_mut(&(identity, source))
            .ok_or(SdkError::PermissionDenied)?;
        if !peer.live(now, clock) || expires_at <= now || expires_at > now.saturating_add(86_400) {
            return Err(SdkError::PermissionDenied);
        }
        if let Some(admitted) = &peer.admitted {
            if admitted.expires_at != expires_at {
                return Err(SdkError::PermissionDenied);
            }
        } else {
            peer.admitted = Some(Admission {
                expires_at,
                deadline: clock + Duration::from_secs(expires_at - now),
            });
        }
        Ok(())
    }

    #[cfg(all(any(unix, windows), feature = "ipc"))]
    pub(crate) async fn dispatch<C: GcClient>(
        &mut self,
        client: &C,
        local: ComponentId,
        request: Request,
    ) -> Result<Response, SdkError> {
        match request {
            Request::AdmitBootstrapPeer {
                peer_identity,
                source,
                expires_at_unix,
            } => {
                self.admit(peer_identity, source, expires_at_unix)?;
                Ok(Response::Empty)
            }
            Request::SubmitBootstrap {
                recipient,
                destination,
                content_type,
                body,
            } => {
                let mut body = Zeroizing::new(body);
                if !valid_application(&content_type, &body) {
                    return Err(SdkError::PermissionDenied);
                }
                let identity = client.contact_identity(&recipient)?;
                let peer = self
                    .peers
                    .get(&(identity, destination))
                    .ok_or(SdkError::PermissionDenied)?;
                if !peer.live(unix()?, Instant::now())
                    || (content_type != gcoms_core::bootstrap::CONTENT_TYPE
                        && peer.admitted.is_none())
                {
                    return Err(SdkError::PermissionDenied);
                }
                let app = Zeroizing::new(ApplicationMessage {
                    content_type,
                    body: std::mem::take(&mut *body),
                });
                let route = Zeroizing::new(RoutedApplication {
                    source: local,
                    destination,
                    application: app.encode()?,
                });
                let encoded =
                    Zeroizing::new(route.encode().map_err(|e| SdkError::Protocol(e.into()))?);
                let routed = Zeroizing::new(ApplicationMessage::decode(&encoded)?);
                client
                    .submit_volatile_opaque(&recipient, &routed.content_type, &routed.body)
                    .await?;
                Ok(Response::Empty)
            }
            _ => Err(SdkError::PermissionDenied),
        }
    }
}

#[cfg(all(any(unix, windows), feature = "ipc"))]
impl IpcClient {
    pub async fn admit_bootstrap_peer(
        &self,
        peer_identity: Vec<u8>,
        source: ComponentId,
        expires_at_unix: u64,
    ) -> Result<(), SdkError> {
        match self
            .request(Request::AdmitBootstrapPeer {
                peer_identity,
                source,
                expires_at_unix,
            })
            .await?
        {
            Response::Empty => Ok(()),
            _ => Err(SdkError::Protocol(
                "invalid bootstrap admission reply".into(),
            )),
        }
    }
    pub async fn submit_bootstrap(
        &self,
        recipient: ContactCard,
        destination: ComponentId,
        content_type: String,
        body: Vec<u8>,
    ) -> Result<(), SdkError> {
        match self
            .request(Request::SubmitBootstrap {
                recipient,
                destination,
                content_type,
                body,
            })
            .await?
        {
            Response::Empty => Ok(()),
            _ => Err(SdkError::Protocol(
                "invalid bootstrap submission reply".into(),
            )),
        }
    }
}
