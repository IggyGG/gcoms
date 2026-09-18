//! Private, resumable piece exchange. The host supplies authenticated membership,
//! transport and the cache key. This module never opens a network connection.
mod engine;
mod protocol;
mod store;
pub use engine::{Action, Diagnostics, Engine, Peer, View};
pub use protocol::{Manifest, Message, Scope, ShareId, BLOCK_BYTES, CONTENT_TYPE, PIECE_BYTES};
pub use store::{Cache, CacheConfig, State, Status};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid file transfer: {0}")]
    Invalid(&'static str),
    #[error("file cache quota exceeded")]
    Quota,
    #[error("file transfer is unavailable")]
    Unavailable,
    #[error("file transfer authorization failed")]
    Unauthorized,
    #[error("file transfer conflicts with retained state")]
    Conflict,
}
