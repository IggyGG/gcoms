use crate::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Transport: Send + Sync {
    fn destination(&self) -> &str;
    fn frame_limit(&self) -> usize;
    async fn exchange(&self, request: &Request) -> Result<Reply, RpcError>;
}
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Transport {
    fn destination(&self) -> &str;
    fn frame_limit(&self) -> usize;
    async fn exchange(&self, request: &Request) -> Result<Reply, RpcError>;
}

/// Persist only opaque handles, before transmission. Failing to retain aborts the send.
pub trait HandleStore: Send + Sync {
    fn retain(&self, handle: &OperationHandle) -> Result<(), RpcError>;
    fn list(&self) -> Result<Vec<OperationHandle>, RpcError>;
    fn forget(&self, handle: &OperationHandle) -> Result<(), RpcError>;
}

#[derive(Default)]
pub struct MemoryHandles(Mutex<BTreeMap<String, OperationHandle>>);
impl HandleStore for MemoryHandles {
    fn retain(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        let mut entries = self
            .0
            .lock()
            .map_err(|_| RpcError::new(ErrorCode::Storage, "handle lock poisoned"))?;
        let key = serde_json::to_string(handle).map_err(|_| RpcError::invalid("handle"))?;
        if entries.len() >= DEFAULT_RECORD_LIMIT && !entries.contains_key(&key) {
            return Err(RpcError::new(ErrorCode::Busy, "pending handle limit"));
        }
        entries.insert(key, handle.clone());
        Ok(())
    }
    fn list(&self) -> Result<Vec<OperationHandle>, RpcError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| RpcError::new(ErrorCode::Storage, "handle lock poisoned"))?
            .values()
            .cloned()
            .collect())
    }
    fn forget(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        self.0
            .lock()
            .map_err(|_| RpcError::new(ErrorCode::Storage, "handle lock poisoned"))?
            .remove(&serde_json::to_string(handle).map_err(|_| RpcError::invalid("handle"))?);
        Ok(())
    }
}

/// Contains arguments in memory. Persist `handle`, never this prepared request.
pub struct Prepared<R, E> {
    pub handle: OperationHandle,
    args: serde_json::Value,
    marker: PhantomData<fn() -> (R, E)>,
}

#[derive(Debug)]
pub enum CallError<E> {
    Service(E),
    Rpc(RpcError),
    /// Execution may have happened. Check status; never recreate the operation.
    OutcomeUnknown(Box<OperationHandle>),
    Unavailable(Box<OperationHandle>),
}
impl<E: std::fmt::Debug> std::fmt::Display for CallError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl<E: std::fmt::Debug> std::error::Error for CallError<E> {}

pub struct Client<T> {
    transport: Arc<T>,
    instance: String,
    handles: Arc<dyn HandleStore>,
}
impl<T> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            instance: self.instance.clone(),
            handles: self.handles.clone(),
        }
    }
}
impl<T: Transport> Client<T> {
    /// Instance and destination are selected by the host, never by an incoming call.
    pub fn new(transport: T, instance: impl Into<String>) -> Self {
        Self {
            transport: Arc::new(transport),
            instance: instance.into(),
            handles: Arc::new(MemoryHandles::default()),
        }
    }
    pub fn with_handles(mut self, handles: Arc<dyn HandleStore>) -> Self {
        self.handles = handles;
        self
    }
    pub fn handles(&self) -> &dyn HandleStore {
        self.handles.as_ref()
    }
    pub fn instance(&self) -> &str {
        &self.instance
    }
    pub fn destination(&self) -> &str {
        self.transport.destination()
    }

    fn request(
        &self,
        service: &str,
        version: u16,
        method: &str,
        invocation: Invocation,
    ) -> Request {
        Request {
            rpc: WIRE_VERSION,
            id: new_id(),
            instance: self.instance.clone(),
            service: service.into(),
            version,
            method: method.into(),
            invocation,
        }
    }
    async fn exchange(&self, request: &Request) -> Result<ReplyBody, RpcError> {
        let bytes = serde_json::to_vec(request).map_err(|e| RpcError::invalid(e.to_string()))?;
        if bytes.len() > self.transport.frame_limit() {
            return Err(RpcError::new(
                ErrorCode::PayloadTooLarge,
                "request exceeds transport limit",
            ));
        }
        let reply = self.transport.exchange(request).await?;
        request.check_reply(&reply)?;
        if serde_json::to_vec(&reply)
            .map_err(|_| RpcError::protocol("invalid response"))?
            .len()
            > self.transport.frame_limit()
        {
            return Err(RpcError::new(
                ErrorCode::PayloadTooLarge,
                "response exceeds transport limit",
            ));
        }
        match reply.body {
            ReplyBody::Failed { error } => Err(error),
            body => Ok(body),
        }
    }
    pub async fn call<A: Serialize + Sync, R: DeserializeOwned, E: DeserializeOwned>(
        &self,
        service: &str,
        version: u16,
        method: &str,
        args: &A,
    ) -> Result<R, CallError<E>> {
        let args = serde_json::to_value(args)
            .map_err(|e| CallError::Rpc(RpcError::invalid(e.to_string())))?;
        let request = self.request(
            service,
            version,
            method,
            Invocation::Call {
                args,
                operation: None,
            },
        );
        match self.exchange(&request).await.map_err(CallError::Rpc)? {
            ReplyBody::Done { outcome } => decode(outcome),
            _ => Err(CallError::Rpc(RpcError::protocol(
                "nonterminal query response",
            ))),
        }
    }
    pub fn prepare<A: Serialize, R, E>(
        &self,
        service: &str,
        version: u16,
        method: &str,
        args: &A,
    ) -> Result<Prepared<R, E>, RpcError> {
        let handle = OperationHandle {
            destination: self.destination().into(),
            instance: self.instance.clone(),
            service: service.into(),
            version,
            method: method.into(),
            operation: OperationToken {
                id: new_id(),
                deadline: DecimalU64(unix_time().saturating_add(600)),
            },
        };
        let args = serde_json::to_value(args).map_err(|e| RpcError::invalid(e.to_string()))?;
        Ok(Prepared {
            handle,
            args,
            marker: PhantomData,
        })
    }
    fn check_handle(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        if handle.instance != self.instance || handle.destination != self.destination() {
            return Err(RpcError::new(
                ErrorCode::Instance,
                "handle belongs to another attachment",
            ));
        }
        Ok(())
    }
    pub async fn start<R, E>(&self, prepared: &Prepared<R, E>) -> Result<ReplyBody, RpcError> {
        self.check_handle(&prepared.handle)?;
        self.handles.retain(&prepared.handle)?;
        let h = &prepared.handle;
        self.exchange(&self.request(
            &h.service,
            h.version,
            &h.method,
            Invocation::Call {
                args: prepared.args.clone(),
                operation: Some(h.operation.clone()),
            },
        ))
        .await
    }
    /// Recovery is a read. It cannot execute a missing or interrupted operation.
    pub async fn status(&self, handle: &OperationHandle) -> Result<ReplyBody, RpcError> {
        self.check_handle(handle)?;
        self.exchange(&self.request(
            &handle.service,
            handle.version,
            &handle.method,
            Invocation::Status {
                operation_id: handle.operation.id.clone(),
            },
        ))
        .await
    }
    pub async fn resume<R: DeserializeOwned, E: DeserializeOwned>(
        &self,
        handle: &OperationHandle,
    ) -> Result<R, CallError<E>> {
        self.wait(handle).await
    }
    pub async fn wait<R: DeserializeOwned, E: DeserializeOwned>(
        &self,
        handle: &OperationHandle,
    ) -> Result<R, CallError<E>> {
        // A bounded observation window, not an execution/cancellation deadline.
        for _ in 0..1500 {
            let body = self.status(handle).await.map_err(CallError::Rpc)?;
            if body != ReplyBody::Running {
                return finish(handle, body);
            }
            pause().await;
        }
        Err(CallError::Rpc(RpcError::new(
            ErrorCode::Timeout,
            "wait timed out; retained operation may still complete",
        )))
    }
    pub async fn start_and_wait<R: DeserializeOwned, E: DeserializeOwned>(
        &self,
        prepared: &Prepared<R, E>,
    ) -> Result<R, CallError<E>> {
        match self.start(prepared).await.map_err(CallError::Rpc)? {
            ReplyBody::Running => self.wait(&prepared.handle).await,
            body => finish(&prepared.handle, body),
        }
    }
}
fn decode<R: DeserializeOwned, E: DeserializeOwned>(outcome: Outcome) -> Result<R, CallError<E>> {
    match outcome {
        Outcome::Ok(value) => serde_json::from_value(value)
            .map_err(|_| CallError::Rpc(RpcError::protocol("invalid method result"))),
        Outcome::Error(value) => Err(CallError::Service(
            serde_json::from_value(value)
                .map_err(|_| CallError::Rpc(RpcError::protocol("invalid method error")))?,
        )),
    }
}
fn finish<R: DeserializeOwned, E: DeserializeOwned>(
    handle: &OperationHandle,
    body: ReplyBody,
) -> Result<R, CallError<E>> {
    match body {
        ReplyBody::Done { outcome } => decode(outcome),
        ReplyBody::OutcomeUnknown => Err(CallError::OutcomeUnknown(Box::new(handle.clone()))),
        ReplyBody::Unavailable => Err(CallError::Unavailable(Box::new(handle.clone()))),
        ReplyBody::Failed { error } => Err(CallError::Rpc(error)),
        ReplyBody::Running => Err(CallError::Rpc(RpcError::protocol(
            "operation still running",
        ))),
    }
}
