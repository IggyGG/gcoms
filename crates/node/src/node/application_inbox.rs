//! Bounded application deliveries retained until the local consumer commits.
//! This journal is separate from the transport ACK replay cache: accepting an
//! encrypted frame must not discard its application body after a daemon crash.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const APPLICATION_INBOX_LIMIT: usize = 256;
pub const APPLICATION_INBOX_PEER_LIMIT: usize = 32;
pub const APPLICATION_INBOX_PAGE_LIMIT: usize = 32;
const MAX_CURSOR: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationDelivery {
    pub sequence: u64,
    pub peer_identity: Vec<u8>,
    pub message_id: [u8; 16],
    pub received_at_unix: u64,
    /// Opaque application bytes. The enclosing node archive seals this body.
    pub body: Vec<u8>,
}

impl ApplicationDelivery {
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"gc1/application-delivery/v1\0");
        hash.update(self.sequence.to_be_bytes());
        hash.update((self.peer_identity.len() as u32).to_be_bytes());
        hash.update(&self.peer_identity);
        hash.update(self.message_id);
        hash.update(self.received_at_unix.to_be_bytes());
        hash.update(&self.body);
        hash.finalize().into()
    }
}

impl Drop for ApplicationDelivery {
    fn drop(&mut self) {
        self.body.fill(0);
    }
}

/// Sealed profile ownership, independent of the optional endpoint configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CentralOwnership {
    pub(crate) primary: Vec<[u8; 16]>,
    pub(crate) scoped: Vec<[u8; 16]>,
    pub(crate) policy_hash: [u8; 32],
}
impl CentralOwnership {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let valid = |ids: &Vec<[u8; 16]>| {
            !ids.is_empty()
                && ids.len() <= 64
                && !ids.contains(&[0; 16])
                && ids.windows(2).all(|v| v[0] < v[1])
        };
        if !valid(&self.primary)
            || !valid(&self.scoped)
            || self.primary.len() + self.scoped.len() > 64
            || self.primary.iter().any(|id| self.scoped.contains(id))
            || self.policy_hash == [0; 32]
        {
            return Err("invalid central ownership".into());
        }
        Ok(())
    }
    pub(crate) fn for_policy(
        policy: &gcoms_core::component::RoutingPolicy,
        mut primary: Vec<[u8; 16]>,
    ) -> Result<Self, String> {
        let mut components = policy.components.clone();
        components.sort();
        primary.sort();
        if components.windows(2).any(|v| v[0] == v[1])
            || primary.iter().any(|id| !components.contains(id))
        {
            return Err("invalid central component partition".into());
        }
        let scoped = components
            .iter()
            .filter(|id| !primary.contains(id))
            .copied()
            .collect();
        let mut routes = Vec::new();
        for route in &policy.routes {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&route.local);
            bytes.extend_from_slice(&route.remote);
            bytes.extend_from_slice(&(route.peer_identity.len() as u64).to_be_bytes());
            bytes.extend_from_slice(&route.peer_identity);
            let mut types = route.content_types.clone();
            types.sort();
            bytes.extend_from_slice(&(types.len() as u64).to_be_bytes());
            for kind in types {
                bytes.extend_from_slice(&(kind.len() as u64).to_be_bytes());
                bytes.extend_from_slice(kind.as_bytes());
            }
            routes.push(bytes);
        }
        routes.sort();
        let mut hash = Sha256::new();
        hash.update(b"gc1/central-local-ownership/v1\0");
        hash.update((components.len() as u64).to_be_bytes());
        for id in components {
            hash.update(id);
        }
        hash.update((primary.len() as u64).to_be_bytes());
        for id in &primary {
            hash.update(id);
        }
        hash.update((routes.len() as u64).to_be_bytes());
        for route in routes {
            hash.update((route.len() as u64).to_be_bytes());
            hash.update(route);
        }
        let result = Self {
            primary,
            scoped,
            policy_hash: hash.finalize().into(),
        };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone)]
pub(crate) struct ApplicationInbox {
    pub(crate) central_ownership: Option<CentralOwnership>,
    // Sealed profile scope; the live registry policy is revalidated at every boot.
    pub(crate) machine_owned: bool,
    pub(crate) routing_policy: Option<gcoms_core::component::RoutingPolicy>,
    // Central local IPC routes do not impose machine-profile admission on
    // existing network traffic, channels or retained inbox/outbox records.
    pub(crate) local_routing_policy: Option<gcoms_core::component::RoutingPolicy>,
    pub(crate) next_sequence: u64,
    pub(crate) entries: VecDeque<ApplicationDelivery>,
}

impl Default for ApplicationInbox {
    fn default() -> Self {
        Self {
            central_ownership: None,
            machine_owned: false,
            routing_policy: None,
            local_routing_policy: None,
            next_sequence: 1,
            entries: VecDeque::new(),
        }
    }
}

impl ApplicationInbox {
    /// Stage before the atomic ratchet/transport-ACK archive write. Callers
    /// restore the previous journal if that write fails.
    pub(crate) fn stage(
        &mut self,
        peer_identity: &[u8],
        message_id: [u8; 16],
        received_at_unix: u64,
        body: &[u8],
    ) -> Result<u64, String> {
        if self.machine_owned && self.routing_policy.is_none() {
            return Err("machine routing policy not configured".into());
        }
        if self
            .routing_policy
            .as_ref()
            .is_some_and(|policy| !policy.permits(peer_identity, body))
        {
            return Err("unregistered component route".into());
        }
        if peer_identity.len() != 1952
            || body.is_empty()
            || body.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT
            || message_id == [0; 16]
            || received_at_unix == 0
            || received_at_unix > MAX_CURSOR
        {
            return Err("invalid durable application delivery".into());
        }
        if let Some(prior) = self
            .entries
            .iter()
            .find(|entry| entry.peer_identity == peer_identity && entry.message_id == message_id)
        {
            return if prior.body == body {
                Ok(prior.sequence)
            } else {
                Err("durable application message ID conflicts with retained bytes".into())
            };
        }
        let destination = gcoms_core::component::RoutedApplication::decode(body)
            .ok()
            .map(|r| r.destination);
        let quota = self
            .routing_policy
            .as_ref()
            .map_or(APPLICATION_INBOX_PEER_LIMIT, |policy| {
                policy.quota(APPLICATION_INBOX_LIMIT, APPLICATION_INBOX_PEER_LIMIT)
            });
        if self.entries.len() >= APPLICATION_INBOX_LIMIT
            || self
                .entries
                .iter()
                .filter(|entry| {
                    let target = gcoms_core::component::RoutedApplication::decode(&entry.body)
                        .ok()
                        .map(|r| r.destination);
                    if self.routing_policy.is_some() && destination.is_some() {
                        target == destination
                    } else {
                        target == destination
                            && entry.peer_identity == peer_identity
                            && gcoms_core::component::RoutedApplication::decode(&entry.body)
                                .ok()
                                .map(|r| r.source)
                                == gcoms_core::component::RoutedApplication::decode(body)
                                    .ok()
                                    .map(|r| r.source)
                    }
                })
                .count()
                >= quota
        {
            return Err("durable application inbox is full".into());
        }
        if self.next_sequence >= MAX_CURSOR {
            return Err("durable application cursor exhausted".into());
        }
        let sequence = self.next_sequence;
        self.entries.push_back(ApplicationDelivery {
            sequence,
            peer_identity: peer_identity.to_vec(),
            message_id,
            received_at_unix,
            body: body.to_vec(),
        });
        self.next_sequence += 1;
        Ok(sequence)
    }

    pub(crate) fn page(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<ApplicationDelivery>, String> {
        if after >= self.next_sequence || limit == 0 || limit > APPLICATION_INBOX_PAGE_LIMIT {
            return Err("invalid durable application cursor or page limit".into());
        }
        Ok(self
            .entries
            .iter()
            .filter(|entry| entry.sequence > after)
            .take(limit)
            .cloned()
            .collect())
    }

    /// Idempotent receipt; a live entry must match the exact delivered bytes.
    /// The caller persists the removal before returning success to the consumer.
    pub(crate) fn consume(&mut self, sequence: u64, digest: [u8; 32]) -> Result<bool, String> {
        if sequence == 0 || sequence >= self.next_sequence {
            return Err("invalid durable application receipt sequence".into());
        }
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.sequence == sequence)
        else {
            return Ok(false);
        };
        if self.entries[index].digest() != digest {
            return Err("durable application receipt digest mismatch".into());
        }
        self.entries.remove(index);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> Vec<u8> {
        vec![byte; 1952]
    }

    #[test]
    fn retained_replay_is_idempotent_and_conflicts_cannot_replace_bytes() {
        let mut inbox = ApplicationInbox::default();
        assert_eq!(inbox.stage(&peer(1), [1; 16], 100, b"body"), Ok(1));
        assert_eq!(inbox.stage(&peer(1), [1; 16], 200, b"body"), Ok(1));
        assert!(inbox.stage(&peer(1), [1; 16], 200, b"changed").is_err());
        assert_eq!(inbox.next_sequence, 2);
        let delivery = inbox.page(0, 1).unwrap().remove(0);
        assert_eq!(delivery.received_at_unix, 100);
        assert!(inbox.consume(1, [0; 32]).is_err());
        assert_eq!(inbox.entries.len(), 1);
        assert_eq!(inbox.consume(1, delivery.digest()), Ok(true));
        assert_eq!(inbox.consume(1, delivery.digest()), Ok(false));
        assert!(inbox.page(0, 1).unwrap().is_empty());
        assert_eq!(inbox.stage(&peer(1), [2; 16], 201, b"next"), Ok(2));
    }

    #[test]
    fn a_full_peer_cannot_consume_another_peers_quota() {
        let mut inbox = ApplicationInbox::default();
        for id in 1..=APPLICATION_INBOX_PEER_LIMIT {
            inbox.stage(&peer(1), [id as u8; 16], 1, b"body").unwrap();
        }
        assert!(inbox.stage(&peer(1), [100; 16], 1, b"body").is_err());
        assert!(inbox.stage(&peer(2), [100; 16], 1, b"body").is_ok());
        assert_eq!(inbox.page(0, 32).unwrap().len(), 32);
        assert_eq!(inbox.page(32, 32).unwrap().len(), 1);
        assert!(inbox.page(34, 1).is_err());
        assert!(inbox.page(0, 33).is_err());
    }
    #[test]
    fn component_quotas_are_independent_and_unknown_routes_are_rejected() {
        use gcoms_core::component::{RoutePermission, RoutedApplication, RoutingPolicy};
        let wire = |destination| {
            RoutedApplication {
                source: [9; 16],
                destination,
                application: b"GCAPP1\0\x04testpayload".to_vec(),
            }
            .encode()
            .unwrap()
        };
        let mut inbox = ApplicationInbox {
            routing_policy: Some(RoutingPolicy {
                bootstrap_listeners: Vec::new(),
                components: vec![[1; 16], [2; 16]],
                routes: [1, 2]
                    .into_iter()
                    .map(|id| RoutePermission {
                        local: [id; 16],
                        remote: [9; 16],
                        peer_identity: peer(3),
                        content_types: vec!["test".into()],
                    })
                    .collect(),
            }),
            ..Default::default()
        };
        for id in 1..=32 {
            inbox.stage(&peer(3), [id; 16], 1, &wire([1; 16])).unwrap();
        }
        assert!(inbox.stage(&peer(3), [33; 16], 1, &wire([1; 16])).is_err());
        assert!(inbox.stage(&peer(3), [34; 16], 1, &wire([2; 16])).is_ok());
        assert!(inbox.stage(&peer(4), [35; 16], 1, &wire([2; 16])).is_err());
        assert!(inbox.stage(&peer(3), [35; 16], 1, &wire([8; 16])).is_err());
        assert!(inbox.stage(&peer(3), [35; 16], 1, b"unrouted").is_err());
        // A dedicated collector can accept the same destination from many peers.
        let mut collector = ApplicationInbox::default();
        for peer_id in 1..=40 {
            collector
                .stage(&peer(peer_id), [1; 16], 1, &wire([2; 16]))
                .unwrap();
        }
    }
}
