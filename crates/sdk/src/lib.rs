//! Application-facing GC/1 API.
//!
//! Protocol implementations live below this crate. Applications depend on
//! these opaque values and typed operations instead of transport, routing, or
//! cryptographic internals.

mod catalog_http;
#[cfg(feature = "in-process")]
mod embedded;
pub mod ipc;
#[cfg(all(any(unix, windows), feature = "ipc"))]
pub mod local;
pub mod machine;
mod types;
pub use catalog_http::{CatalogHttpRequest, CatalogHttpResponse};

#[cfg(feature = "in-process")]
pub use embedded::EmbeddedClient;
pub use gcoms_core::APPLICATION_PAYLOAD_LIMIT;
#[cfg(all(unix, feature = "ipc"))]
pub use ipc::serve_unix;
#[cfg(all(any(unix, windows), feature = "ipc"))]
pub use ipc::{serve_local, IpcClient};
#[cfg(all(any(unix, windows), feature = "ipc"))]
pub use local::LocalEndpoint;
#[cfg(any(feature = "in-process", feature = "descriptor-verification"))]
pub use types::InMemoryCatalog;
pub use types::{
    application_body_limit, ActivityBucket, ApplicationDelivery, ApplicationMessage,
    AutomaticJoinEndpoint, Blob, CarrierProfile, CatalogRequest, CatalogResponse, ChannelChange,
    ChannelId, ChannelInvitation, ChannelMemberSummary, ChannelRole, ChannelStatus,
    ChannelVisibility, ClientEvent, ConnectionState, ContactCard, GcClient, Identity, JoinRequest,
    JoinedChannel, MessageId, NetworkNameStatus, Peer, PresenceMode, PublicChannelDescriptor,
    Reachability, RelayCard, RelayState, RuntimeStatus, SdkError,
};

pub use gcoms_core::component;

pub mod files;
pub mod shell;

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub mod private_fs;
pub use gcoms_core::file_stream;

#[cfg(all(any(unix, windows), feature = "ipc"))]
pub mod bootstrap;
#[cfg(all(any(unix, windows), feature = "ipc"))]
pub mod local_rpc;

mod network_status;
pub mod sharing;
pub use network_status::{NetworkState, NetworkStatus};
