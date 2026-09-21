//! Runtime ownership, encrypted profiles and network recovery shared by GComs applications.
pub mod bootstrap;
pub mod dns;
pub mod network;
pub mod runtime;
pub mod store;
pub mod private_fs {
    pub use gcoms_private_fs::*;
}
pub use runtime::{ErrorSink, ProtocolClient, ProtocolRuntime};

pub mod contacts;
pub struct RuntimeOptions {
    pub listen: std::net::SocketAddr,
    pub advertise: Option<std::net::SocketAddr>,
    pub relay: Option<gcoms_sdk::RelayCard>,
    pub fixture: bool,
    pub carrier: gcoms_sdk::CarrierProfile,
    pub network: Option<network::InstalledNetwork>,
}

pub mod network_status;

#[cfg(feature = "files")]
pub mod files;

pub use gcoms_node::metrics;
#[cfg(feature = "push-notifications")]
pub use gcoms_node::push_notifications;
