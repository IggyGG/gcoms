//! GC/2 private queue paths and optional relay-side queue service.
use gcoms_transport::encode_b64url;

pub fn queue_token(queue_id: &[u8; 32]) -> String {
    format!("gc2/{}", encode_b64url(queue_id))
}

#[cfg(feature = "relay-host")]
mod service;
#[cfg(feature = "relay-host")]
pub use service::QueueService;
