//! Component routing within an authenticated GC identity. This envelope is
//! encrypted by GC; its source is an application claim, verified against the
//! component's signed binding by the receiving application.

use alloc::{string::String, vec::Vec};
pub type ComponentId = [u8; 16];
pub const CONTENT_TYPE: &str = "application/vnd.ghost.component.v1";
pub const OVERHEAD: usize = 8 + CONTENT_TYPE.len() + 38;
const MAGIC: &[u8; 6] = b"GCCMP1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedApplication {
    pub source: ComponentId,
    pub destination: ComponentId,
    /// A complete, unchanged GCAPP1 application, including its content type.
    pub application: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RoutePermission {
    pub local: ComponentId,
    pub remote: ComponentId,
    pub peer_identity: Vec<u8>,
    pub content_types: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RoutingPolicy {
    pub components: Vec<ComponentId>,
    pub routes: Vec<RoutePermission>,
    /// Explicit temporary installer listeners. They accept only the reserved
    /// bootstrap/file volatile kinds; SDK admission additionally fences file
    /// events by authenticated peer/component and a fixed run deadline.
    pub bootstrap_listeners: Vec<ComponentId>,
}

impl RoutingPolicy {
    pub fn permits(&self, peer: &[u8], bytes: &[u8]) -> bool {
        let Ok(message) = RoutedApplication::decode(bytes) else {
            return false;
        };
        let Some((kind, _)) = application_parts(&message.application) else {
            return false;
        };
        (self.bootstrap_listeners.contains(&message.destination)
            && matches!(
                kind,
                crate::bootstrap::CONTENT_TYPE
                    | crate::VOLATILE_FILE_CONTENT_TYPE
                    | crate::VOLATILE_FILE_ACK_CONTENT_TYPE
                    | crate::VOLATILE_CONTACT_CONTENT_TYPE
            ))
            || self.routes.iter().any(|route| {
                route.local == message.destination
                    && route.remote == message.source
                    && route.peer_identity == peer
                    && route.content_types.iter().any(|allowed| allowed == kind)
            })
    }

    pub fn quota(&self, total: usize, maximum: usize) -> usize {
        (total / self.components.len().max(1)).clamp(1, maximum)
    }
}

impl zeroize::Zeroize for RoutedApplication {
    fn zeroize(&mut self) {
        self.application.as_mut_slice().zeroize();
    }
}

impl RoutedApplication {
    fn validate(&self) -> Result<(), &'static str> {
        if self.source == [0; 16] || self.destination == [0; 16] {
            return Err("nil component route");
        }
        let (kind, _) = application_parts(&self.application).ok_or("invalid inner application")?;
        if kind == CONTENT_TYPE
            || self.application.len() + OVERHEAD > crate::APPLICATION_PAYLOAD_LIMIT
        {
            return Err("nested or oversized component application");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(OVERHEAD + self.application.len());
        bytes.extend_from_slice(b"GCAPP1");
        bytes.extend_from_slice(&(CONTENT_TYPE.len() as u16).to_be_bytes());
        bytes.extend_from_slice(CONTENT_TYPE.as_bytes());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.destination);
        bytes.extend_from_slice(&self.application);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > crate::APPLICATION_PAYLOAD_LIMIT {
            return Err("oversized component application");
        }
        let (kind, body) = application_parts(bytes).ok_or("invalid application")?;
        if kind != CONTENT_TYPE || body.len() < 38 || &body[..6] != MAGIC {
            return Err("not a routed application");
        }
        let result = Self {
            source: body[6..22].try_into().map_err(|_| "source component")?,
            destination: body[22..38]
                .try_into()
                .map_err(|_| "destination component")?,
            application: body[38..].to_vec(),
        };
        let mut result = zeroize::Zeroizing::new(result);
        result.validate()?;
        Ok(Self {
            source: result.source,
            destination: result.destination,
            application: core::mem::take(&mut result.application),
        })
    }
}

pub fn application_parts(bytes: &[u8]) -> Option<(&str, &[u8])> {
    if bytes.len() < 8 || &bytes[..6] != b"GCAPP1" {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(bytes[6..8].try_into().ok()?));
    let kind = core::str::from_utf8(bytes.get(8..8 + length)?).ok()?;
    if kind.is_empty() || !kind.is_ascii() || kind.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    Some((kind, bytes.get(8 + length..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_cleanup_keeps_route_metadata_and_clears_owned_bytes() {
        use zeroize::Zeroize;
        let mut route = RoutedApplication {
            source: [1; 16],
            destination: [2; 16],
            application: vec![0xa7; 4096],
        };
        route.zeroize();
        assert_eq!(route.application, vec![0; 4096]);
        assert_eq!(route.source, [1; 16]);
        assert_eq!(route.destination, [2; 16]);
    }

    #[test]
    fn preserves_signed_bytes_and_rejects_malformed_routes() {
        let route = RoutedApplication {
            source: [1; 16],
            destination: [2; 16],
            application: b"GCAPP1\0\x04test\0signed bytes\xff".to_vec(),
        };
        let wire = route.encode().unwrap();
        assert_eq!(RoutedApplication::decode(&wire), Ok(route.clone()));
        for end in 0..OVERHEAD + 12 {
            assert!(RoutedApplication::decode(&wire[..end]).is_err());
        }
        assert!(RoutedApplication {
            source: [0; 16],
            ..route.clone()
        }
        .encode()
        .is_err());
        assert!(RoutedApplication {
            application: wire,
            ..route
        }
        .encode()
        .is_err());
    }
}
