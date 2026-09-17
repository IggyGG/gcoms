//! Browser fetch adapter. The authenticated same-origin gateway fixes the
//! upstream destination and service instance; callers cannot provide a peer URL.
use crate::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
pub struct FetchTransport {
    url: String,
    limit: usize,
}
impl FetchTransport {
    pub fn new(path: &str) -> Result<Self, RpcError> {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.contains('#')
        {
            return Err(RpcError::invalid("use a same-origin gateway path"));
        }
        Ok(Self {
            url: path.into(),
            limit: LOCAL_FRAME_LIMIT,
        })
    }
}
#[async_trait(?Send)]
impl Transport for FetchTransport {
    fn destination(&self) -> &str {
        &self.url
    }
    fn frame_limit(&self) -> usize {
        self.limit
    }
    async fn exchange(&self, request: &Request) -> Result<Reply, RpcError> {
        let controller = web_sys::AbortController::new()
            .map_err(|_| RpcError::new(ErrorCode::Transport, "fetch controller unavailable"))?;
        struct Abort(web_sys::AbortController);
        impl Drop for Abort {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _abort = Abort(controller.clone());
        let timer_controller = controller.clone();
        let _timeout =
            gloo_timers::callback::Timeout::new(150_000, move || timer_controller.abort());
        let response = gloo_net::http::Request::post(&self.url)
            .credentials(web_sys::RequestCredentials::SameOrigin)
            .redirect(web_sys::RequestRedirect::Error)
            .abort_signal(Some(&controller.signal()))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(request).map_err(|_| RpcError::invalid("request"))?)
            .map_err(|_| RpcError::new(ErrorCode::Transport, "could not build fetch request"))?
            .send()
            .await
            .map_err(|_| {
                RpcError::new(
                    ErrorCode::Transport,
                    "gateway unavailable; check the retained operation",
                )
            })?;
        if !response.ok() {
            return Err(RpcError::new(
                ErrorCode::Transport,
                format!("gateway returned HTTP {}", response.status()),
            ));
        }
        let body = response
            .body()
            .ok_or_else(|| RpcError::protocol("empty gateway response"))?;
        let reader: web_sys::ReadableStreamDefaultReader = body
            .get_reader()
            .dyn_into()
            .map_err(|_| RpcError::protocol("gateway stream unavailable"))?;
        struct Reader(web_sys::ReadableStreamDefaultReader);
        impl Drop for Reader {
            fn drop(&mut self) {
                self.0.release_lock();
            }
        }
        let reader = Reader(reader);
        let mut bytes = Vec::new();
        loop {
            let chunk = JsFuture::from(reader.0.read())
                .await
                .map_err(|_| RpcError::new(ErrorCode::Transport, "gateway response interrupted"))?;
            let done = js_sys::Reflect::get(&chunk, &"done".into())
                .map_err(|_| RpcError::protocol("invalid stream"))?;
            if done.as_bool() == Some(true) {
                break;
            }
            let value = js_sys::Reflect::get(&chunk, &"value".into())
                .map_err(|_| RpcError::protocol("invalid stream"))?;
            let data = js_sys::Uint8Array::new(&value);
            if bytes.len().saturating_add(data.length() as usize) > self.limit {
                return Err(RpcError::new(
                    ErrorCode::PayloadTooLarge,
                    "gateway response exceeds limit",
                ));
            }
            bytes.extend_from_slice(&data.to_vec());
        }
        serde_json::from_slice(&bytes).map_err(|_| RpcError::protocol("invalid gateway reply"))
    }
}

/// Browser storage contains only opaque operation handles. A blocked or full
/// storage area aborts admission rather than sending an untracked operation.
pub struct BrowserHandles {
    key: String,
}
impl BrowserHandles {
    pub fn new(namespace: &str) -> Self {
        Self {
            key: format!("gc-rpc:{namespace}:handle-v1:"),
        }
    }
    fn storage(&self) -> Result<web_sys::Storage, RpcError> {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .ok_or_else(|| RpcError::new(ErrorCode::Storage, "browser storage unavailable"))
    }
    fn handle_key(&self, handle: &OperationHandle) -> Result<String, RpcError> {
        use sha2::{Digest, Sha256};
        let binding = (
            &handle.destination,
            &handle.instance,
            &handle.service,
            handle.version,
            &handle.method,
            &handle.operation.id,
        );
        Ok(format!(
            "{}{:x}",
            self.key,
            Sha256::digest(serde_json::to_vec(&binding).map_err(|_| RpcError::invalid("handle"))?)
        ))
    }
}
impl HandleStore for BrowserHandles {
    fn retain(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        let entries = self.list()?;
        if entries.contains(handle) {
            return Ok(());
        }
        if entries.len() >= DEFAULT_RECORD_LIMIT {
            return Err(RpcError::new(ErrorCode::Busy, "retained handle limit"));
        }
        self.storage()?
            .set_item(
                &self.handle_key(handle)?,
                &serde_json::to_string(handle).map_err(|_| RpcError::invalid("handle"))?,
            )
            .map_err(|_| RpcError::new(ErrorCode::Storage, "could not retain operation handle"))
    }
    fn list(&self) -> Result<Vec<OperationHandle>, RpcError> {
        let storage = self.storage()?;
        let invalid = || RpcError::new(ErrorCode::Storage, "cannot read saved handles");
        let mut handles = Vec::new();
        for index in 0..storage.length().map_err(|_| invalid())? {
            let Some(key) = storage.key(index).map_err(|_| invalid())? else {
                continue;
            };
            if !key.starts_with(&self.key) {
                continue;
            }
            if let Some(value) = storage.get_item(&key).map_err(|_| invalid())? {
                handles.push(serde_json::from_str(&value).map_err(|_| invalid())?);
            }
            if handles.len() > DEFAULT_RECORD_LIMIT {
                return Err(invalid());
            }
        }
        Ok(handles)
    }
    fn forget(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        self.storage()?
            .remove_item(&self.handle_key(handle)?)
            .map_err(|_| RpcError::new(ErrorCode::Storage, "cannot remove saved handle"))
    }
}
