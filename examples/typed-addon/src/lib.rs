//! One service definition for the native host and both browser clients.
use gcoms_rpc::{
    schemars,
    serde::{Deserialize, Serialize},
    ts_rs::TS,
};

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema, TS)]
#[serde(crate = "gcoms_rpc::serde", deny_unknown_fields)]
#[schemars(crate = "gcoms_rpc::schemars")]
#[ts(crate = "gcoms_rpc::ts_rs")]
pub struct Greeting {
    pub text: String,
}

#[gcoms_rpc::service(name = "example.greeting", version = 1)]
pub trait GreetingService {
    #[rpc(id = "greet", kind = "query")]
    async fn greet(&self, name: String) -> Result<Greeting, String>;
    #[rpc(id = "uppercase", kind = "operation")]
    async fn uppercase(&self, text: String) -> Result<Greeting, String>;
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod browser {
    use super::*;
    use gcoms_rpc::{
        browser::{BrowserHandles, FetchTransport},
        Client, OperationHandle,
    };
    use std::sync::Arc;
    use wasm_bindgen::prelude::*;
    fn client(instance: &str) -> Result<GreetingServiceClient<FetchTransport>, JsValue> {
        let transport =
            FetchTransport::new("/rpc").map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(GreetingServiceClient::new(
            Client::new(transport, instance)
                .with_handles(Arc::new(BrowserHandles::new("greeting-example"))),
        ))
    }
    #[wasm_bindgen]
    pub async fn rust_greet(instance: String, name: String) -> Result<String, JsValue> {
        client(&instance)?
            .greet(name)
            .await
            .map(|g| g.text)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    #[wasm_bindgen]
    pub async fn rust_uppercase(instance: String, text: String) -> Result<String, JsValue> {
        client(&instance)?
            .uppercase(text)
            .await
            .map(|g| g.text)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    #[wasm_bindgen]
    pub async fn rust_resume(instance: String, handle: String) -> Result<String, JsValue> {
        let handle: OperationHandle = gcoms_rpc::serde_json::from_str(&handle)
            .map_err(|_| JsValue::from_str("invalid handle"))?;
        client(&instance)?
            .inner
            .resume::<Greeting, String>(&handle)
            .await
            .map(|g| g.text)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
