//! Explicit operator budgets; ordinary clients retain the original defaults.
use gcoms_transport::ServerLimits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayCapacity {
    circuits: usize,
    connections: usize,
}

impl Default for RelayCapacity {
    fn default() -> Self {
        Self {
            circuits: 128,
            connections: gcoms_transport::server::MAX_CONNECTIONS,
        }
    }
}

impl RelayCapacity {
    /// Bound both logical forwarding work and physical accepted connections.
    /// Each circuit can also consume an incoming transit connection; leave
    /// room for both sides. Zero and unbounded configurations are rejected.
    pub fn new(circuits: usize, connections: usize) -> Result<Self, String> {
        if !(1..=gcoms_routing::service::MAX_SERVICE_CIRCUITS).contains(&circuits)
            || connections > 8192
            || connections < circuits * 2
        {
            return Err("relay capacity requires 1..4096 circuits and twice that many connections, at most 8192".into());
        }
        Ok(Self {
            circuits,
            connections,
        })
    }

    pub fn circuits(self) -> usize {
        self.circuits
    }

    pub fn connections(self) -> usize {
        self.connections
    }

    pub(super) fn server_limits(self, mut limits: ServerLimits) -> ServerLimits {
        // Never relax the unauthenticated per-source admission allowance.
        limits.max_connections = self.connections;
        limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_capacity_preserves_source_admission_and_rejects_unbounded_values() {
        let default = RelayCapacity::default();
        assert_eq!(default.circuits(), 128);
        assert_eq!(
            default.server_limits(ServerLimits::default()),
            ServerLimits::default()
        );
        let hosted = RelayCapacity::new(2048, 4096).unwrap();
        let limits = hosted.server_limits(ServerLimits::default());
        assert_eq!(limits.max_connections, 4096);
        assert_eq!(limits.max_connections_per_ip, 8);
        for (circuits, connections) in [
            (0, 1024),
            (4097, 8192),
            (128, 0),
            (2048, 4095),
            (1, 8193),
            (usize::MAX, usize::MAX),
        ] {
            assert!(RelayCapacity::new(circuits, connections).is_err());
        }
        assert!(RelayCapacity::new(4096, 8192).is_ok());
    }
}
