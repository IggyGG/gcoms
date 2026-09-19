#![cfg_attr(not(feature = "std"), no_std)]
//! Shared wire codecs. No sockets, event loop, filesystem, or application authority.
extern crate alloc;
pub use gcoms_core::lease;
pub mod alias;
#[cfg(feature = "experimental-gc2")]
pub mod flow;
#[cfg(feature = "experimental-gc2")]
pub mod gc2_session;
pub mod proto;
pub mod relay;
