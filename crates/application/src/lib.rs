//! One application API for embedded and shared GComs runtimes.
//! See the application guide for profile ownership, invitations and service grants.
extern crate self as gcoms;
#[cfg(any(feature = "rpc", feature = "wasm"))]
pub use gcoms_rpc as rpc;
#[cfg(any(feature = "rpc", feature = "wasm"))]
pub use gcoms_rpc::async_trait;
#[cfg(any(feature = "rpc", feature = "wasm"))]
pub use gcoms_rpc::service;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "network-client")
))]
pub use gcoms_runtime as runtime;
#[cfg(not(target_arch = "wasm32"))]
pub use gcoms_sdk as sdk;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "network-client", feature = "ipc")
))]
mod application;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "network-client", feature = "ipc")
))]
pub use application::*;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "network-client", feature = "ipc")
))]
pub mod control;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "embedded", feature = "network-client"),
    feature = "ipc"
))]
pub mod daemon;

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "files",
    any(feature = "embedded", feature = "network-client", feature = "ipc")
))]
mod files;
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "files",
    any(feature = "embedded", feature = "network-client", feature = "ipc")
))]
pub use files::Files;
