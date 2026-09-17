use crate::journal::{hash_prefix, read_range, Journal, TerminalState, TransferState};
use gcoms_core::file_stream::{
    checkpoint_batch_chunks, AckCode, AckStage, Contact, FileAck, FileContact, FileInit,
    FileRecord, PROFILE_VERSION_V2,
};
use gcoms_core::MAX_MESSAGE;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiverError {
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("authorization failed")]
    Authorization,
    #[error("transfer conflicts with existing state")]
    Conflict,
    #[error("disk quota exceeded")]
    Quota,
    #[error("receiver I/O: {0}")]
    Io(String),
    #[error("receiver state is corrupt: {0}")]
    Corrupt(String),
    #[error("transfer was cancelled")]
    Cancelled,
}

impl ReceiverError {
    pub fn ack_code(&self) -> AckCode {
        match self {
            Self::Authorization => AckCode::Auth,
            Self::Conflict => AckCode::Conflict,
            Self::Quota => AckCode::Quota,
            Self::Protocol(_) => AckCode::Format,
            Self::Io(_) => AckCode::Io,
            Self::Corrupt(_) => AckCode::Internal,
            Self::Cancelled => AckCode::Internal,
        }
    }
}

struct ActiveTransfer {
    state: TransferState,
    file: Option<File>,
    cancelled: bool,
    /// Records consumed in the current v2 checkpoint batch (RAM-only; a
    /// restart replays the batch and recounting converges).
    batch_index: u64,
}

pub struct Receiver {
    storage_root: PathBuf,
    journal: Journal,
    contacts: HashMap<[u8; 16], FileContact>,
    transfers: HashMap<[u8; 16], ActiveTransfer>,
    disk_quota: u64,
    max_file_size: u64,
    max_chunk_size: u64,
    reserved_bytes: u64,
}

impl Receiver {
    pub fn open(
        storage_root: &Path,
        state_root: &Path,
        disk_quota: u64,
        max_file_size: u64,
        max_chunk_size: u64,
        state_auth_key: &[u8; 32],
    ) -> Result<Self, ReceiverError> {
        crate::journal::create_owner_dir(storage_root).map_err(ReceiverError::Io)?;
        if std::fs::symlink_metadata(storage_root)
            .map_err(|e| ReceiverError::Io(e.to_string()))?
            .file_type()
            .is_symlink()
        {
            return Err(ReceiverError::Corrupt("storage root is a symlink".into()));
        }
        let journal = Journal::open(&state_root.join("transfers"), state_auth_key)
            .map_err(ReceiverError::Corrupt)?;
        let mut transfers = HashMap::new();
        let mut reserved_bytes = 0u64;
        for mut state in journal.load_all().map_err(ReceiverError::Corrupt)? {
            let id = state.transfer_id_bytes().map_err(ReceiverError::Corrupt)?;
            reserved_bytes = reserved_bytes
                .checked_add(state.file_size)
                .ok_or(ReceiverError::Quota)?;
            let temp = storage_root.join(&state.temp_name);
            let final_path = storage_root.join(&state.final_name);
            match &state.terminal {
                TerminalState::Active => {
                    if final_path.exists() {
                        let metadata = std::fs::symlink_metadata(&final_path)
                            .map_err(|e| ReceiverError::Corrupt(e.to_string()))?;
                        let digest = hash_prefix(&final_path, state.file_size)
                            .map_err(ReceiverError::Corrupt)?;
                        if !metadata.file_type().is_file()
                            || metadata.len() != state.file_size
                            || state.committed_offset != state.file_size
                            || digest != state.expected_digest().map_err(ReceiverError::Corrupt)?
                        {
                            return Err(ReceiverError::Corrupt(
                                "partial publication conflicts with active journal".into(),
                            ));
                        }
                        if temp.exists() {
                            std::fs::remove_file(&temp)
                                .map_err(|e| ReceiverError::Io(e.to_string()))?;
                        }
                        sync_dir(storage_root).map_err(ReceiverError::Io)?;
                        state.terminal = TerminalState::Published {
                            digest: hex::encode(digest),
                            complete_ack: false,
                        };
                        journal.store(&mut state).map_err(ReceiverError::Io)?;
                        transfers.insert(
                            id,
                            ActiveTransfer {
                                state,
                                file: None,
                                cancelled: false,
                                batch_index: 0,
                            },
                        );
                        continue;
                    }
                    let metadata = std::fs::symlink_metadata(&temp)
                        .map_err(|e| ReceiverError::Corrupt(e.to_string()))?;
                    if !metadata.file_type().is_file() || metadata.len() < state.committed_offset {
                        return Err(ReceiverError::Corrupt(
                            "temporary file is shorter than journal".into(),
                        ));
                    }
                    let digest = hash_prefix(&temp, state.committed_offset)
                        .map_err(ReceiverError::Corrupt)?;
                    if hex::encode(digest) != state.committed_sha256 {
                        return Err(ReceiverError::Corrupt(
                            "temporary file digest differs from journal".into(),
                        ));
                    }
                    if metadata.len() > state.committed_offset {
                        let file = open_existing(&temp).map_err(ReceiverError::Io)?;
                        file.set_len(state.committed_offset)
                            .and_then(|_| file.sync_all())
                            .map_err(|e| ReceiverError::Io(e.to_string()))?;
                        sync_dir(storage_root).map_err(ReceiverError::Io)?;
                    }
                    transfers.insert(
                        id,
                        ActiveTransfer {
                            state,
                            file: None,
                            cancelled: false,
                            batch_index: 0,
                        },
                    );
                }
                TerminalState::Published { digest, .. } => {
                    let metadata = std::fs::symlink_metadata(&final_path)
                        .map_err(|e| ReceiverError::Corrupt(e.to_string()))?;
                    if !metadata.file_type().is_file()
                        || metadata.len() != state.file_size
                        || hex::encode(
                            hash_prefix(&final_path, state.file_size)
                                .map_err(ReceiverError::Corrupt)?,
                        ) != *digest
                    {
                        return Err(ReceiverError::Corrupt(
                            "published file differs from journal".into(),
                        ));
                    }
                    transfers.insert(
                        id,
                        ActiveTransfer {
                            state,
                            file: None,
                            cancelled: false,
                            batch_index: 0,
                        },
                    );
                }
                TerminalState::Failed { .. } => {
                    transfers.insert(
                        id,
                        ActiveTransfer {
                            state,
                            file: None,
                            cancelled: true,
                            batch_index: 0,
                        },
                    );
                }
            }
        }
        cleanup_orphans(storage_root, &transfers)?;
        if reserved_bytes > disk_quota {
            return Err(ReceiverError::Quota);
        }
        Ok(Self {
            storage_root: storage_root.into(),
            journal,
            contacts: HashMap::new(),
            transfers,
            disk_quota,
            max_file_size,
            max_chunk_size,
            reserved_bytes,
        })
    }

    /// Adds one RAM-only authorization. It is removed on the first valid init.
    pub fn offer_contact(&mut self, contact: FileContact, now: u64) -> Result<(), ReceiverError> {
        contact
            .validate(now)
            .map_err(|e| ReceiverError::Protocol(e.to_string()))?;
        if contact.max_file_size > self.max_file_size
            || contact.max_chunk_size > self.max_chunk_size
        {
            return Err(ReceiverError::Quota);
        }
        if self.contacts.contains_key(&contact.transfer_id)
            || self.transfers.contains_key(&contact.transfer_id)
        {
            return Err(ReceiverError::Conflict);
        }
        self.contacts.insert(contact.transfer_id, contact);
        Ok(())
    }

    pub fn process_encoded(
        &mut self,
        encoded: &[u8],
        now: u64,
    ) -> Result<Option<FileAck>, ReceiverError> {
        let record = FileRecord::decode(encoded, now, MAX_MESSAGE)
            .map_err(|e| ReceiverError::Protocol(e.to_string()))?;
        self.process(record, now)
    }

    /// Handles one authenticated application record. Returns `None` when the
    /// record consumed a v2 checkpoint batch slot without reaching a batch
    /// boundary; the checkpoint ACK is emitted at the boundary instead.
    pub fn process(
        &mut self,
        record: FileRecord,
        now: u64,
    ) -> Result<Option<FileAck>, ReceiverError> {
        match record {
            FileRecord::Init(init) => self.init(init, now).map(Some),
            FileRecord::Chunk(chunk) => self.chunk(chunk),
            FileRecord::Finish(finish) => self.finish(finish).map(Some),
            FileRecord::Ack(_) => Err(ReceiverError::Protocol(
                "receiver does not accept FileAck".into(),
            )),
        }
    }

    /// Pre-authorizes a new session's FileInit before its return route can be
    /// retained or used. Existing-transfer replays are served by the exact ACK
    /// journal before reaching this path.
    pub fn authorizes_init(&self, init: &FileInit, now: u64) -> bool {
        if self
            .contacts
            .get(&init.transfer_id)
            .is_some_and(|contact| init.validate_authorization(contact, now).is_ok())
        {
            return true;
        }
        let Some(existing) = self.transfers.get(&init.transfer_id) else {
            return false;
        };
        let route_is_valid = init
            .ack_route
            .encode()
            .ok()
            .and_then(|wire| Contact::decode(&wire, now).ok())
            .is_some();
        route_is_valid
            && init_hash(init)
                .is_ok_and(|hash| existing.state.authorization_hash == hex::encode(hash))
    }

    pub fn error_for_authorized_init(init: &FileInit, error: ReceiverError) -> FileAck {
        FileAck {
            profile_version: init.profile_version,
            transfer_id: init.transfer_id,
            stage: AckStage::Error,
            code: error.ack_code(),
            received_size: 0,
            file_sha256: init.file_sha256,
        }
    }

    /// Builds the ERROR ack for a failed record. A v2 record with an active
    /// transfer consumes one batch slot and defers the ERROR to the batch
    /// boundary (SPEC 11.4: no mid-batch ERROR rotations).
    pub fn error_for(
        &mut self,
        id: [u8; 16],
        error: ReceiverError,
    ) -> Result<Option<FileAck>, ReceiverError> {
        let code = error.ack_code();
        let Some(transfer) = self.transfers.get_mut(&id) else {
            return Ok(None);
        };
        let profile = transfer.state.profile_version;
        let committed = transfer.state.committed_offset;
        let digest = transfer.state.expected_digest().expect("validated state");
        if matches!(transfer.state.terminal, TerminalState::Published { .. }) {
            return Ok(Some(ack(&transfer.state, AckStage::Complete, AckCode::Ok)));
        }
        if profile != PROFILE_VERSION_V2
            || !matches!(transfer.state.terminal, TerminalState::Active)
            || (committed == transfer.state.file_size && transfer.batch_index == 0)
        {
            return Ok(Some(FileAck {
                profile_version: profile,
                transfer_id: id,
                stage: AckStage::Error,
                code,
                received_size: committed,
                file_sha256: digest,
            }));
        }
        if transfer.state.deferred_error.is_none() {
            transfer.state.deferred_error = Some(code as u16);
            self.journal
                .store(&mut transfer.state)
                .map_err(ReceiverError::Io)?;
        }
        transfer.batch_index += 1;
        let boundary = transfer.batch_index >= transfer.state.batch_chunks;
        if boundary {
            transfer.batch_index = 0;
            let deferred = transfer
                .state
                .deferred_error
                .and_then(|value| AckCode::try_from(value).ok())
                .unwrap_or(code);
            return Ok(Some(FileAck {
                profile_version: profile,
                transfer_id: id,
                stage: AckStage::Error,
                code: deferred,
                received_size: transfer.state.committed_offset,
                file_sha256: digest,
            }));
        }
        Ok(None)
    }

    fn chunk(
        &mut self,
        chunk: gcoms_core::file_stream::FileChunk,
    ) -> Result<Option<FileAck>, ReceiverError> {
        let id = chunk.transfer_id;
        let transfer = self
            .transfers
            .get_mut(&id)
            .ok_or(ReceiverError::Authorization)?;
        if chunk.profile_version != transfer.state.profile_version {
            return Err(ReceiverError::Protocol(
                "file profile version mismatch".into(),
            ));
        }
        if transfer.cancelled {
            return Err(ReceiverError::Cancelled);
        }
        if !matches!(transfer.state.terminal, TerminalState::Active) {
            return Err(ReceiverError::Conflict);
        }
        let offset = transfer.state.committed_offset;
        let file_size = transfer.state.file_size;
        let temp = self.storage_root.join(&transfer.state.temp_name);
        chunk
            .validate_stream_bounds(
                chunk.offset,
                file_size,
                transfer.state.chunk_size,
                self.max_chunk_size,
                MAX_MESSAGE,
            )
            .map_err(|e| ReceiverError::Protocol(e.to_string()))?;
        if transfer.state.deferred_error.is_some() {
            return Ok(self.checkpoint(id, false));
        }
        if chunk.offset < offset {
            let end = chunk
                .offset
                .checked_add(chunk.data.len() as u64)
                .ok_or(ReceiverError::Conflict)?;
            if end > offset {
                return Err(ReceiverError::Conflict);
            }
            let old =
                read_range(&temp, chunk.offset, chunk.data.len()).map_err(ReceiverError::Io)?;
            if old != chunk.data {
                return Err(ReceiverError::Conflict);
            }
            return Ok(self.checkpoint(id, end == file_size));
        }
        chunk
            .validate_stream_bounds(
                offset,
                transfer.state.file_size,
                transfer.state.chunk_size,
                self.max_chunk_size,
                MAX_MESSAGE,
            )
            .map_err(|e| ReceiverError::Protocol(e.to_string()))?;
        let file = transfer
            .file
            .get_or_insert(open_existing(&temp).map_err(ReceiverError::Io)?);
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| ReceiverError::Io(e.to_string()))?;
        file.write_all(&chunk.data)
            .map_err(|e| ReceiverError::Io(e.to_string()))?;
        file.sync_data()
            .map_err(|e| ReceiverError::Io(e.to_string()))?;
        transfer.state.committed_offset += chunk.data.len() as u64;
        transfer.state.committed_sha256 = hex::encode(
            hash_prefix(&temp, transfer.state.committed_offset).map_err(ReceiverError::Io)?,
        );
        self.journal
            .store(&mut transfer.state)
            .map_err(ReceiverError::Io)?;
        Ok(self.checkpoint(id, chunk.offset + chunk.data.len() as u64 == file_size))
    }

    /// Advances the v2 checkpoint batch by one consumed slot. v1 emits an
    /// ACCEPTED after every record. At a full-batch or EOF boundary the
    /// current (or deferred error) disposition is emitted.
    fn checkpoint(&mut self, id: [u8; 16], eof_boundary: bool) -> Option<FileAck> {
        let v2 = {
            let transfer = self.transfers.get(&id)?;
            transfer.state.profile_version == PROFILE_VERSION_V2
        };
        if !v2 {
            let transfer = self.transfers.get(&id)?;
            return Some(ack(&transfer.state, AckStage::Accepted, AckCode::Ok));
        }
        let (boundary, deferred) = {
            let transfer = self.transfers.get_mut(&id)?;
            transfer.batch_index += 1;
            let boundary = transfer.batch_index >= transfer.state.batch_chunks || eof_boundary;
            if boundary {
                transfer.batch_index = 0;
            }
            let deferred = if boundary {
                transfer
                    .state
                    .deferred_error
                    .and_then(|value| AckCode::try_from(value).ok())
            } else {
                None
            };
            (boundary, deferred)
        };
        let transfer = self.transfers.get(&id)?;
        if boundary {
            if let Some(code) = deferred {
                return Some(FileAck {
                    profile_version: transfer.state.profile_version,
                    transfer_id: id,
                    stage: AckStage::Error,
                    code,
                    received_size: transfer.state.committed_offset,
                    file_sha256: transfer.state.expected_digest().expect("validated state"),
                });
            }
            return Some(ack(&transfer.state, AckStage::Accepted, AckCode::Ok));
        }
        None
    }

    fn init(&mut self, init: FileInit, now: u64) -> Result<FileAck, ReceiverError> {
        let authorization_hash = init_hash(&init)?;
        if let Some(existing) = self.transfers.get(&init.transfer_id) {
            let route_is_valid = init
                .ack_route
                .encode()
                .ok()
                .and_then(|wire| Contact::decode(&wire, now).ok())
                .is_some();
            if route_is_valid
                && existing.state.authorization_hash == hex::encode(authorization_hash)
            {
                return Ok(ack(
                    &existing.state,
                    match existing.state.terminal {
                        TerminalState::Published { .. } => AckStage::Complete,
                        _ => AckStage::Accepted,
                    },
                    AckCode::Ok,
                ));
            }
            return Err(ReceiverError::Authorization);
        }
        let contact = self
            .contacts
            .get(&init.transfer_id)
            .ok_or(ReceiverError::Authorization)?;
        init.validate_authorization(contact, now)
            .map_err(|_| ReceiverError::Authorization)?;
        if init.file_size > self.max_file_size
            || self
                .reserved_bytes
                .checked_add(init.file_size)
                .is_none_or(|n| n > self.disk_quota)
        {
            return Err(ReceiverError::Quota);
        }
        let name = hex::encode(init.transfer_id);
        let temp_name = format!(".{name}.part");
        let final_name = format!("{name}.bin");
        let temp_path = self.storage_root.join(&temp_name);
        let file = create_new(&temp_path).map_err(ReceiverError::Io)?;
        file.sync_all()
            .map_err(|e| ReceiverError::Io(e.to_string()))?;
        sync_dir(&self.storage_root).map_err(ReceiverError::Io)?;
        let batch_chunks = if init.profile_version == PROFILE_VERSION_V2 {
            checkpoint_batch_chunks(contact.max_inflight_bytes, init.chunk_size)
                .map_err(|e| ReceiverError::Protocol(e.to_string()))?
        } else {
            1
        };
        let mut state = TransferState::new(
            init.transfer_id,
            authorization_hash,
            init.profile_version,
            batch_chunks,
            init.file_size,
            init.chunk_size,
            init.file_sha256,
            init.init_nonce,
            temp_name,
            final_name,
        );
        self.journal.store(&mut state).map_err(ReceiverError::Io)?;
        self.contacts.remove(&init.transfer_id);
        self.reserved_bytes += init.file_size;
        let response = ack(&state, AckStage::Accepted, AckCode::Ok);
        self.transfers.insert(
            init.transfer_id,
            ActiveTransfer {
                state,
                file: Some(file),
                cancelled: false,
                batch_index: 0,
            },
        );
        Ok(response)
    }

    fn finish(
        &mut self,
        finish: gcoms_core::file_stream::FileFinish,
    ) -> Result<FileAck, ReceiverError> {
        let transfer = self
            .transfers
            .get_mut(&finish.transfer_id)
            .ok_or(ReceiverError::Authorization)?;
        if finish.profile_version != transfer.state.profile_version {
            return Err(ReceiverError::Protocol(
                "file profile version mismatch".into(),
            ));
        }
        if let TerminalState::Published { .. } = transfer.state.terminal {
            return Ok(ack(&transfer.state, AckStage::Complete, AckCode::Ok));
        }
        if transfer.cancelled {
            return Err(ReceiverError::Cancelled);
        }
        if finish.file_size != transfer.state.file_size
            || finish.file_sha256
                != transfer
                    .state
                    .expected_digest()
                    .map_err(ReceiverError::Corrupt)?
            || transfer.state.committed_offset != finish.file_size
        {
            return Err(ReceiverError::Protocol("FileFinish mismatch".into()));
        }
        let temp = self.storage_root.join(&transfer.state.temp_name);
        if let Some(file) = transfer.file.take() {
            file.sync_all()
                .map_err(|e| ReceiverError::Io(e.to_string()))?;
        }
        let digest = hash_prefix(&temp, finish.file_size).map_err(ReceiverError::Io)?;
        if digest != finish.file_sha256 {
            return Err(ReceiverError::Protocol("terminal digest mismatch".into()));
        }
        let final_path = self.storage_root.join(&transfer.state.final_name);
        std::fs::hard_link(&temp, &final_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ReceiverError::Conflict
            } else {
                ReceiverError::Io(e.to_string())
            }
        })?;
        sync_dir(&self.storage_root).map_err(ReceiverError::Io)?;
        std::fs::remove_file(&temp).map_err(|e| ReceiverError::Io(e.to_string()))?;
        sync_dir(&self.storage_root).map_err(ReceiverError::Io)?;
        transfer.state.terminal = TerminalState::Published {
            digest: hex::encode(digest),
            complete_ack: false,
        };
        self.journal
            .store(&mut transfer.state)
            .map_err(ReceiverError::Io)?;
        Ok(ack(&transfer.state, AckStage::Complete, AckCode::Ok))
    }

    pub fn mark_complete_ack_delivered(&mut self, id: [u8; 16]) -> Result<(), ReceiverError> {
        let transfer = self
            .transfers
            .get_mut(&id)
            .ok_or(ReceiverError::Authorization)?;
        let TerminalState::Published { digest, .. } = &transfer.state.terminal else {
            return Err(ReceiverError::Conflict);
        };
        transfer.state.terminal = TerminalState::Published {
            digest: digest.clone(),
            complete_ack: true,
        };
        self.journal
            .store(&mut transfer.state)
            .map_err(ReceiverError::Io)
    }

    pub fn cancel(&mut self, id: [u8; 16]) -> Result<(), ReceiverError> {
        let transfer = self
            .transfers
            .get_mut(&id)
            .ok_or(ReceiverError::Authorization)?;
        transfer.cancelled = true;
        transfer.file.take();
        transfer.state.terminal = TerminalState::Failed {
            code: AckCode::Internal as u16,
        };
        self.journal
            .store(&mut transfer.state)
            .map_err(ReceiverError::Io)
    }

    pub fn transfer_ids(&self) -> Vec<[u8; 16]> {
        self.transfers.keys().copied().collect()
    }

    /// Explicit consumer release after copying or abandoning its file. Persist a
    /// failed terminal state before removing bytes so interrupted cleanup resumes.
    pub fn release(&mut self, id: [u8; 16]) -> Result<(), ReceiverError> {
        self.contacts.remove(&id);
        if !self.transfers.contains_key(&id) {
            return Ok(());
        }
        self.cancel(id)?;
        let transfer = &self.transfers[&id];
        for name in [&transfer.state.temp_name, &transfer.state.final_name] {
            match std::fs::remove_file(self.storage_root.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(ReceiverError::Io(e.to_string())),
            }
        }
        sync_dir(&self.storage_root).map_err(ReceiverError::Io)?;
        self.journal
            .remove(&transfer.state.transfer_id)
            .map_err(ReceiverError::Io)?;
        self.reserved_bytes = self.reserved_bytes.saturating_sub(transfer.state.file_size);
        self.transfers.remove(&id);
        Ok(())
    }

    pub fn status(&self, id: [u8; 16]) -> Option<TransferState> {
        self.transfers
            .get(&id)
            .map(|transfer| transfer.state.clone())
    }

    pub fn clear_offered_contacts(&mut self) {
        self.contacts.clear();
    }
}

fn init_hash(init: &FileInit) -> Result<[u8; 32], ReceiverError> {
    let encoded = FileRecord::Init(init.clone())
        .encode()
        .map_err(|error| ReceiverError::Protocol(error.to_string()))?;
    Ok(Sha256::digest(encoded).into())
}

fn ack(state: &TransferState, stage: AckStage, code: AckCode) -> FileAck {
    FileAck {
        profile_version: state.profile_version,
        transfer_id: state.transfer_id_bytes().expect("validated state"),
        stage,
        code,
        received_size: state.committed_offset,
        file_sha256: state.expected_digest().expect("validated state"),
    }
}

fn create_new(path: &Path) -> Result<File, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .mode(0o600)
            .custom_flags(libc_no_follow())
            .open(path)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(path)
            .map_err(|e| e.to_string())
    }
}
fn open_existing(path: &Path) -> Result<File, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .read(true)
            .custom_flags(libc_no_follow())
            .open(path)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|e| e.to_string())
    }
}
#[cfg(target_os = "linux")]
fn libc_no_follow() -> i32 {
    0o400000
}
#[cfg(all(unix, not(target_os = "linux")))]
fn libc_no_follow() -> i32 {
    0x00000100
}
fn sync_dir(path: &Path) -> Result<(), String> {
    crate::journal::sync_directory(path).map_err(|e| e.to_string())
}

fn cleanup_orphans(
    root: &Path,
    transfers: &HashMap<[u8; 16], ActiveTransfer>,
) -> Result<(), ReceiverError> {
    let referenced = transfers
        .values()
        .map(|v| v.state.temp_name.as_str())
        .collect::<std::collections::HashSet<_>>();
    for entry in std::fs::read_dir(root).map_err(|e| ReceiverError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| ReceiverError::Io(e.to_string()))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| ReceiverError::Corrupt("non-UTF8 storage entry".into()))?;
        if name.starts_with('.')
            && name.ends_with(".part")
            && !referenced.contains(name)
            && entry
                .file_type()
                .map_err(|e| ReceiverError::Io(e.to_string()))?
                .is_file()
        {
            std::fs::remove_file(entry.path()).map_err(|e| ReceiverError::Io(e.to_string()))?;
        }
    }
    Ok(())
}
