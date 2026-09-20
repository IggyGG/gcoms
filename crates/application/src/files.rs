//! File-sharing convenience methods over either application backend.
use crate::sdk::{self, sharing::*, GcClient, SdkError};
use std::{path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone)]
pub struct Files(pub(crate) Arc<dyn GcClient>);
impl Files {
    pub async fn request(&self, request: Request) -> Result<Reply, SdkError> {
        request.validate()?;
        self.0.sharing(request).await
    }
    pub async fn list(&self) -> Result<Snapshot, SdkError> {
        match self.request(Request::List).await? {
            Reply::Snapshot(snapshot) => Ok(snapshot),
            _ => Err(SdkError::Protocol("invalid file list reply".into())),
        }
    }
    pub async fn prepare(
        &self,
        scope: Scope,
        name: String,
        size_bytes: u64,
    ) -> Result<ShareId, SdkError> {
        let id = rand::random();
        self.request(Request::Prepare {
            id,
            scope,
            name,
            size_bytes,
        })
        .await?;
        Ok(id)
    }
    /// Upload one bounded piece; callers may resume an unfinished import by index.
    pub async fn write_piece(
        &self,
        id: ShareId,
        piece: u32,
        bytes: Vec<u8>,
    ) -> Result<(), SdkError> {
        self.request(Request::WritePiece { id, piece, bytes })
            .await
            .map(|_| ())
    }
    pub async fn read_piece(&self, id: ShareId, piece: u32) -> Result<Vec<u8>, SdkError> {
        match self.request(Request::ReadPiece { id, piece }).await? {
            Reply::Piece(bytes) if bytes.len() <= PIECE_BYTES => Ok(bytes),
            _ => Err(SdkError::Protocol("invalid file piece reply".into())),
        }
    }
    pub async fn commit(&self, id: ShareId) -> Result<(), SdkError> {
        self.request(Request::Commit { id }).await.map(|_| ())
    }
    pub async fn accept(&self, id: ShareId) -> Result<(), SdkError> {
        self.request(Request::Accept { id }).await.map(|_| ())
    }
    pub async fn pause(&self, id: ShareId) -> Result<(), SdkError> {
        self.request(Request::Pause { id }).await.map(|_| ())
    }
    pub async fn resume(&self, id: ShareId) -> Result<(), SdkError> {
        self.request(Request::Resume { id }).await.map(|_| ())
    }
    pub async fn cancel(&self, id: ShareId) -> Result<(), SdkError> {
        self.request(Request::Cancel { id }).await.map(|_| ())
    }
    /// Read exactly the declared length, retaining at most one piece in this client.
    pub async fn import(
        &self,
        scope: Scope,
        name: String,
        size: u64,
        input: &mut (impl AsyncRead + Unpin),
    ) -> Result<ShareId, SdkError> {
        let id = self.prepare(scope, name, size).await?;
        let imported = async {
            let mut remaining = size;
            let mut piece = 0;
            while remaining != 0 {
                let count = remaining.min(PIECE_BYTES as u64) as usize;
                let mut bytes = zeroize::Zeroizing::new(vec![0; count]);
                input.read_exact(&mut bytes).await.map_err(io)?;
                self.write_piece(id, piece, std::mem::take(&mut *bytes))
                    .await?;
                remaining -= count as u64;
                piece += 1;
            }
            let mut extra = [0];
            if input.read(&mut extra).await.map_err(io)? != 0 {
                return Err(SdkError::Protocol("file grew during import".into()));
            }
            self.commit(id).await
        }
        .await;
        if let Err(error) = imported {
            let _ = self.cancel(id).await;
            return Err(error);
        }
        Ok(id)
    }
    pub async fn send_path(&self, scope: Scope, path: &Path) -> Result<ShareId, SdkError> {
        let mut file = tokio::fs::File::open(path).await.map_err(io)?;
        let metadata = file.metadata().await.map_err(io)?;
        if !metadata.is_file() {
            return Err(SdkError::Protocol("select a regular file".into()));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SdkError::Protocol("invalid filename".into()))?;
        self.import(scope, name.to_owned(), metadata.len(), &mut file)
            .await
    }
    pub async fn export(
        &self,
        id: ShareId,
        output: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), SdkError> {
        let snapshot = self.list().await?;
        let file = snapshot
            .files
            .iter()
            .find(|f| f.id == id)
            .ok_or_else(|| SdkError::Protocol("unknown file".into()))?;
        if file.status != Status::Complete {
            return Err(SdkError::Protocol("file is not complete".into()));
        }
        let mut remaining = file.size_bytes;
        let mut piece = 0;
        while remaining != 0 {
            let bytes = zeroize::Zeroizing::new(self.read_piece(id, piece).await?);
            if bytes.len() as u64 != remaining.min(PIECE_BYTES as u64) {
                return Err(SdkError::Protocol("invalid exported piece length".into()));
            }
            output.write_all(&bytes).await.map_err(io)?;
            remaining -= bytes.len() as u64;
            piece += 1;
        }
        output.flush().await.map_err(io)
    }
    /// Atomically publish a verified export. An existing destination is never replaced.
    pub async fn save_path(&self, id: ShareId, path: &Path) -> Result<(), SdkError> {
        let parent = path
            .parent()
            .ok_or_else(|| SdkError::Protocol("destination needs a parent".into()))?;
        let temporary = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
        let mut output = tokio::fs::File::from_std(temporary.reopen().map_err(io)?);
        self.export(id, &mut output).await?;
        output.sync_all().await.map_err(io)?;
        drop(output);
        temporary.persist_noclobber(path).map_err(io)?;
        Ok(())
    }
}
fn io(error: impl std::fmt::Display) -> sdk::SdkError {
    SdkError::Runtime(error.to_string())
}
