pub mod dedup;
pub mod overlay;
pub mod view;

pub use dedup::Dedup;
pub use overlay::{Overlay, OverlayConfig};
pub use view::{PeerDescriptor, View};

pub type NodeId = u64;

pub const VIEW_SIZE: usize = 32;
pub const PEX_BATCH: usize = 8;
pub const DEDUP_LRU: usize = 8192;
