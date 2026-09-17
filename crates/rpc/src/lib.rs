//! Typed service calls with explicit transport and durable operation semantics.
extern crate self as gcoms_rpc;
pub use async_trait::async_trait;
pub use gcoms_rpc_contract::*;
pub use gcoms_rpc_macros::service;
pub use {schemars, serde, serde_json, ts_rs};

mod client;
pub use client::*;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod router;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use router::*;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod browser;
#[cfg(all(feature = "file-store", not(target_arch = "wasm32")))]
pub mod file_store;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod gc;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod local;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Dispatch: Send + Sync {
    fn descriptor(&self) -> Service;
    /// Deserialize, validate and reserialize before computing an operation digest.
    fn validate(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError>;
    fn digest(&self, _method: &str, args: &serde_json::Value) -> Result<String, RpcError> {
        use sha2::{Digest, Sha256};
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(args).map_err(|_| RpcError::invalid("arguments"))?)
        ))
    }
    async fn invoke(
        &self,
        context: CallContext,
        method: &str,
        args: serde_json::Value,
    ) -> Result<Outcome, RpcError>;
}

/// Authenticated invocation metadata injected by the runtime. A service method
/// can accept `context: gcoms_rpc::CallContext`; it is omitted from client arguments.
#[derive(Clone, Debug)]
pub struct CallContext {
    pub principal: String,
    pub instance: String,
    pub operation: Option<OperationToken>,
}

pub fn encode_outcome<R: serde::Serialize, E: serde::Serialize>(
    value: Result<R, E>,
) -> Result<Outcome, RpcError> {
    match value {
        Ok(value) => serde_json::to_value(value).map(Outcome::Ok),
        Err(error) => serde_json::to_value(error).map(Outcome::Error),
    }
    .map_err(|_| RpcError::protocol("handler result cannot be serialized"))
}

pub fn new_id() -> OperationId {
    OperationId::new(uuid::Uuid::new_v4().to_string()).expect("UUID is valid")
}

pub fn unix_time() -> u64 {
    #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

async fn pause() {
    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
    gloo_timers::future::TimeoutFuture::new(100).await;
}
