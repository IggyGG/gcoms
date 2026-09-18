//! One application API for embedded and shared GComs runtimes.
//! See the application guide for profile ownership, invitations and service grants.
extern crate self as gcoms;
pub use gcoms_rpc as rpc;
pub use gcoms_rpc::async_trait;
pub use gcoms_rpc::service;
#[cfg(all(not(target_arch = "wasm32"), feature = "embedded"))]
pub use gcoms_runtime as runtime;
#[cfg(not(target_arch = "wasm32"))]
pub use gcoms_sdk as sdk;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "ipc")
))]
mod application;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "ipc")
))]
pub use application::*;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "ipc")
))]
pub mod control;
#[cfg(all(not(target_arch = "wasm32"), feature = "embedded", feature = "ipc"))]
pub mod daemon;
