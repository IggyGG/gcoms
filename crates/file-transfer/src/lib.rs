//! Durable streaming file engine shared by the GC backend and legacy receiver.
pub mod journal;
pub mod receiver;
pub use receiver::{Receiver, ReceiverError};
