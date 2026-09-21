//! Portable configuration; router mapping code is feature-gated.
use std::{net::Ipv4Addr, time::Duration};

#[derive(Clone, Debug)]
pub struct NatConfig {
    pub gateway: Option<Ipv4Addr>,
    pub requested_lifetime: Duration,
    pub request_timeout: Duration,
    pub discovery_timeout: Duration,
    pub operation_timeout: Duration,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            gateway: None,
            requested_lifetime: Duration::from_secs(1200),
            request_timeout: Duration::from_secs(2),
            discovery_timeout: Duration::from_secs(2),
            operation_timeout: Duration::from_secs(30),
        }
    }
}
