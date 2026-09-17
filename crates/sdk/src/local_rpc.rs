//! Bounded byte framing for component-specific local RPC. Uses the same
//! owner-only Unix sockets / Windows named pipes as the typed GC API.
use crate::{LocalEndpoint, SdkError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read(
    stream: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> Result<Vec<u8>, SdkError> {
    let size = stream
        .read_u32()
        .await
        .map_err(|e| SdkError::Runtime(e.to_string()))? as usize;
    if size == 0 || size > limit {
        return Err(SdkError::Protocol("local RPC frame exceeds bound".into()));
    }
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| SdkError::Runtime(e.to_string()))?;
    Ok(bytes)
}
pub async fn write(
    stream: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
    limit: usize,
) -> Result<(), SdkError> {
    if bytes.is_empty() || bytes.len() > limit || bytes.len() > u32::MAX as usize {
        return Err(SdkError::Protocol("local RPC frame exceeds bound".into()));
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|e| SdkError::Runtime(e.to_string()))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|e| SdkError::Runtime(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| SdkError::Runtime(e.to_string()))
}
pub fn call(endpoint: &std::path::Path, bytes: &[u8], limit: usize) -> Result<Vec<u8>, SdkError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SdkError::Runtime(e.to_string()))?;
    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
            let mut stream = crate::local::connect(&LocalEndpoint::new(endpoint)).await?;
            write(&mut stream, bytes, limit).await?;
            read(&mut stream, limit).await
        })
        .await
        .map_err(|_| SdkError::Runtime("local RPC timeout".into()))?
    })
}
