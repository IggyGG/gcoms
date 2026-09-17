//! Current-user authenticated local RPC, separate from the SDK's stable IPC schema.
use crate::*;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub struct LocalTransport {
    endpoint: PathBuf,
    destination: String,
    limit: usize,
}
impl LocalTransport {
    pub fn new(endpoint: impl Into<PathBuf>) -> Self {
        let endpoint = endpoint.into();
        Self {
            destination: endpoint.to_string_lossy().into_owned(),
            endpoint,
            limit: LOCAL_FRAME_LIMIT,
        }
    }
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.min(LOCAL_FRAME_LIMIT);
        self
    }
}
#[async_trait]
impl Transport for LocalTransport {
    fn destination(&self) -> &str {
        &self.destination
    }
    fn frame_limit(&self) -> usize {
        self.limit
    }
    async fn exchange(&self, request: &Request) -> Result<Reply, RpcError> {
        tokio::time::timeout(Duration::from_secs(150), async {
            gcoms_private_fs::validate_private_parent(&self.endpoint, "RPC socket")
                .map_err(transport)?;
            let endpoint = gcoms_sdk::LocalEndpoint::new(&self.endpoint);
            #[cfg(unix)]
            let mut stream = {
                let before = socket_identity(&self.endpoint)?;
                let stream = gcoms_sdk::local::connect(&endpoint)
                    .await
                    .map_err(transport)?;
                if stream.peer_cred().map_err(transport)?.uid()
                    != rustix::process::getuid().as_raw()
                    || socket_identity(&self.endpoint)? != before
                {
                    return Err(RpcError::new(
                        ErrorCode::Unauthorized,
                        "local RPC server ownership changed",
                    ));
                }
                stream
            };
            #[cfg(windows)]
            let mut stream = gcoms_sdk::local::connect(&endpoint)
                .await
                .map_err(transport)?;
            let bytes = serde_json::to_vec(request).map_err(transport)?;
            gcoms_sdk::local_rpc::write(&mut stream, &bytes, self.limit)
                .await
                .map_err(transport)?;
            let reply = gcoms_sdk::local_rpc::read(&mut stream, self.limit)
                .await
                .map_err(transport)?;
            serde_json::from_slice(&reply)
                .map_err(|_| RpcError::protocol("invalid local RPC reply"))
        })
        .await
        .map_err(|_| {
            RpcError::new(
                ErrorCode::Timeout,
                "local RPC timed out; operation may still complete",
            )
        })?
    }
}
fn transport(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(ErrorCode::Transport, e.to_string())
}

#[cfg(unix)]
fn socket_identity(path: &Path) -> Result<(u64, u64), RpcError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path).map_err(transport)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(RpcError::new(
            ErrorCode::Unauthorized,
            "local RPC socket is not owner-only",
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

pub async fn serve<F: std::future::Future<Output = ()>>(
    path: &Path,
    router: Arc<Router>,
    stop: F,
) -> Result<(), RpcError> {
    let endpoint = gcoms_sdk::LocalEndpoint::new(path);
    gcoms_private_fs::validate_private_parent(path, "RPC endpoint").map_err(transport)?;
    endpoint.prepare_server().map_err(transport)?;
    let mut listener = gcoms_sdk::local::LocalListener::bind(&endpoint).map_err(transport)?;
    let slots = Arc::new(tokio::sync::Semaphore::new(64));
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            stream = listener.accept() => {
                let mut stream = stream.map_err(transport)?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                let router = router.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(Duration::from_secs(150), async {
                        let bytes = gcoms_sdk::local_rpc::read(&mut stream, router.frame_limit()).await.map_err(transport)?;
                        let request: Request = serde_json::from_slice(&bytes).map_err(|_| RpcError::invalid("invalid local RPC request"))?;
                        let reply = router.handle(Caller {principal: "local-owner".into()}, request).await;
                        let encoded = serde_json::to_vec(&reply).map_err(transport)?;
                        gcoms_sdk::local_rpc::write(&mut stream, &encoded, router.frame_limit()).await.map_err(transport)
                    }).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    endpoint.cleanup().map_err(transport)
}
