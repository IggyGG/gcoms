//! Encrypted, owner-only atomic journal. The host supplies a 256-bit secret;
//! no secret is generated beside the ciphertext or exported to clients.
use crate::*;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use fs2::FileExt;
use gcoms_private_fs::{make_private, validate_private_file, validate_private_parent};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"GCRPC1";
struct State {
    journal: Journal,
    path: PathBuf,
    secret: Zeroizing<[u8; 32]>,
    aad: Vec<u8>,
    limits: StoreLimits,
    _lock: File,
}
#[derive(Clone)]
pub struct FileStore(Arc<Mutex<State>>);

/// A native caller's owner-only opaque handle journal. It stores no invocation
/// arguments, results or authentication material. Attach it with `with_handles`.
pub struct FileHandles(Mutex<HandleState>);
struct HandleState {
    path: PathBuf,
    handles: Vec<OperationHandle>,
    _lock: File,
}
impl FileHandles {
    pub fn open(path: &Path) -> Result<Self, RpcError> {
        validate_private_parent(path, "RPC handles").map_err(storage)?;
        let lock_path = path.with_extension("handles-lock");
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => {
                make_private(&lock_path, false).map_err(storage)?;
                file
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_private_file(&lock_path, "RPC handles lock").map_err(storage)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lock_path)
                    .map_err(storage)?
            }
            Err(e) => return Err(storage(e)),
        };

        Ok(Self(Mutex::new(HandleState {
            path: path.into(),
            handles: Vec::new(),
            _lock: lock,
        })))
    }
    fn transaction<R>(
        &self,
        f: impl FnOnce(&mut HandleState) -> Result<R, RpcError>,
    ) -> Result<R, RpcError> {
        let mut state = self.0.lock().map_err(storage)?;
        let lock = state._lock.try_clone().map_err(storage)?;
        lock.lock_exclusive().map_err(storage)?;
        struct Unlock(File);
        impl Drop for Unlock {
            fn drop(&mut self) {
                let _ = FileExt::unlock(&self.0);
            }
        }
        let _guard = Unlock(lock);
        state.handles = load_handles(&state.path)?;
        f(&mut state)
    }
}
impl std::fmt::Debug for FileHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHandles").finish_non_exhaustive()
    }
}
fn load_handles(path: &Path) -> Result<Vec<OperationHandle>, RpcError> {
    let handles = match std::fs::symlink_metadata(path) {
        Ok(_) => {
            validate_private_file(path, "RPC handles").map_err(storage)?;
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(storage)?
                .take((LOCAL_FRAME_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(storage)?;
            if bytes.len() > LOCAL_FRAME_LIMIT {
                return Err(storage("handle limit"));
            }
            let handles: Vec<OperationHandle> = serde_json::from_slice(&bytes).map_err(storage)?;
            if handles.len() > DEFAULT_RECORD_LIMIT {
                return Err(storage("handle limit"));
            }
            handles
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(storage(e)),
    };
    Ok(handles)
}
impl HandleState {
    fn save(&mut self, handles: Vec<OperationHandle>) -> Result<(), RpcError> {
        let bytes = serde_json::to_vec(&handles).map_err(storage)?;
        if handles.len() > DEFAULT_RECORD_LIMIT || bytes.len() > LOCAL_FRAME_LIMIT {
            return Err(RpcError::new(ErrorCode::Busy, "retained handle limit"));
        }
        validate_private_parent(&self.path, "RPC handles").map_err(storage)?;
        let parent = self.path.parent().ok_or_else(|| storage("parent"))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(storage)?;
        make_private(temp.path(), false).map_err(storage)?;
        temp.write_all(&bytes).map_err(storage)?;
        temp.as_file().sync_all().map_err(storage)?;
        temp.persist(&self.path).map_err(storage)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(storage)?;
        self.handles = handles;
        Ok(())
    }
}
impl HandleStore for FileHandles {
    fn retain(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        self.transaction(|state| {
            if state.handles.contains(handle) {
                return Ok(());
            }
            let mut handles = state.handles.clone();
            handles.push(handle.clone());
            state.save(handles)
        })
    }
    fn list(&self) -> Result<Vec<OperationHandle>, RpcError> {
        self.transaction(|state| Ok(state.handles.clone()))
    }
    fn forget(&self, handle: &OperationHandle) -> Result<(), RpcError> {
        self.transaction(|state| {
            let handles = state
                .handles
                .iter()
                .filter(|h| *h != handle)
                .cloned()
                .collect();
            state.save(handles)
        })
    }
}

fn storage(_: impl std::fmt::Display) -> RpcError {
    RpcError::new(
        ErrorCode::Storage,
        "operation journal could not be read or committed",
    )
}
impl FileStore {
    pub fn open(
        path: &Path,
        secret: [u8; 32],
        namespace: &str,
        limits: StoreLimits,
    ) -> Result<Self, RpcError> {
        validate_private_parent(path, "RPC journal").map_err(storage)?;
        if namespace.is_empty()
            || namespace.len() > 256
            || limits.bytes > LOCAL_FRAME_LIMIT
            || limits.records > DEFAULT_RECORD_LIMIT
            || limits.retention_secs < 600
        {
            return Err(RpcError::invalid("invalid journal configuration"));
        }
        let lock_path = path.with_extension("rpc-lock");
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => {
                make_private(&lock_path, false).map_err(storage)?;
                file
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_private_file(&lock_path, "RPC journal lock").map_err(storage)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lock_path)
                    .map_err(storage)?
            }
            Err(e) => return Err(storage(e)),
        };
        lock.try_lock_exclusive().map_err(|_| {
            RpcError::new(ErrorCode::Storage, "operation journal already has an owner")
        })?;
        let mut aad = MAGIC.to_vec();
        aad.extend_from_slice(namespace.as_bytes());
        let journal = match std::fs::symlink_metadata(path) {
            Ok(_) => {
                validate_private_file(path, "RPC journal").map_err(storage)?;
                let mut bytes = Vec::new();
                File::open(path)
                    .map_err(storage)?
                    .take((limits.bytes + 64) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(storage)?;
                if bytes.len() < MAGIC.len() + 12 + 16
                    || bytes.len() > limits.bytes + MAGIC.len() + 12 + 16
                    || !bytes.starts_with(MAGIC)
                {
                    return Err(storage("invalid journal"));
                }
                let cipher = Aes256Gcm::new_from_slice(&secret).map_err(storage)?;
                let plaintext = Zeroizing::new(
                    cipher
                        .decrypt(
                            Nonce::from_slice(&bytes[MAGIC.len()..MAGIC.len() + 12]),
                            Payload {
                                msg: &bytes[MAGIC.len() + 12..],
                                aad: &aad,
                            },
                        )
                        .map_err(storage)?,
                );
                let journal: Journal = serde_json::from_slice(&plaintext).map_err(storage)?;
                if journal.records.len() > limits.records {
                    return Err(storage("record limit"));
                }
                journal.check_size(limits)?;
                let mut unique = std::collections::BTreeSet::new();
                for record in &journal.records {
                    if !unique.insert(&record.key)
                        || record.retain_until.0 < record.admitted_at.0
                        || record.result.as_ref().is_some_and(|r| {
                            !matches!(r, ReplyBody::Done { .. } | ReplyBody::Failed { .. })
                        })
                    {
                        return Err(storage("invalid record"));
                    }
                }
                journal
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Journal::default(),
            Err(e) => return Err(storage(e)),
        };
        Ok(Self(Arc::new(Mutex::new(State {
            journal,
            path: path.into(),
            secret: Zeroizing::new(secret),
            aad,
            limits,
            _lock: lock,
        }))))
    }
}
impl State {
    fn save(&mut self, journal: Journal) -> Result<(), RpcError> {
        journal.check_size(self.limits)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&journal).map_err(storage)?);
        let cipher = Aes256Gcm::new_from_slice(self.secret.as_ref()).map_err(storage)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(storage)?;
        validate_private_parent(&self.path, "RPC journal").map_err(storage)?;
        let parent = self.path.parent().ok_or_else(|| storage("parent"))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(storage)?;
        make_private(temp.path(), false).map_err(storage)?;
        temp.write_all(MAGIC).map_err(storage)?;
        temp.write_all(&nonce).map_err(storage)?;
        temp.write_all(&ciphertext).map_err(storage)?;
        temp.as_file().sync_all().map_err(storage)?;
        temp.persist(&self.path).map_err(storage)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(storage)?;
        self.journal = journal;
        Ok(())
    }
}
#[async_trait]
impl OperationStore for FileStore {
    async fn admit(
        &self,
        key: &OperationKey,
        digest: &str,
        deadline: u64,
        now: u64,
    ) -> Result<Admission, RpcError> {
        let state = self.0.clone();
        let key = key.clone();
        let digest = digest.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut state = state.lock().map_err(storage)?;
            let mut candidate = state.journal.clone();
            let admission = candidate.admit(&key, &digest, deadline, now, state.limits)?;
            if matches!(admission, Admission::New) {
                state.save(candidate)?;
            }
            Ok(admission)
        })
        .await
        .map_err(storage)?
    }
    async fn complete(&self, key: &OperationKey, result: ReplyBody) -> Result<(), RpcError> {
        let state = self.0.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = state.lock().map_err(storage)?;
            let mut candidate = state.journal.clone();
            candidate.complete(&key, result, state.limits)?;
            state.save(candidate)
        })
        .await
        .map_err(storage)?
    }
    async fn get(&self, key: &OperationKey, now: u64) -> Result<Option<OperationRecord>, RpcError> {
        let state = self.0.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            Ok(state.lock().map_err(storage)?.journal.get(&key, now))
        })
        .await
        .map_err(storage)?
    }
}
