use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const VERSION: u16 = 3;
const STATE_KEY_DOMAIN: &[u8] = b"dropship-state-auth-key-v1\0";
const TRANSFER_AUTH_DOMAIN: &[u8] = b"dropship-transfer-journal-v3\0";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalState {
    Active,
    Published { digest: String, complete_ack: bool },
    Failed { code: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferState {
    pub version: u16,
    pub transfer_id: String,
    pub authorization_hash: String,
    pub profile_version: u8,
    pub batch_chunks: u64,
    pub file_size: u64,
    pub chunk_size: u64,
    pub file_sha256: String,
    pub init_nonce: String,
    pub temp_name: String,
    pub final_name: String,
    pub committed_offset: u64,
    pub committed_sha256: String,
    pub deferred_error: Option<u16>,
    pub terminal: TerminalState,
    pub checksum: String,
    pub auth_tag: String,
}

#[derive(Serialize)]
struct Checked<'a> {
    version: u16,
    transfer_id: &'a str,
    authorization_hash: &'a str,
    profile_version: u8,
    batch_chunks: u64,
    file_size: u64,
    chunk_size: u64,
    file_sha256: &'a str,
    init_nonce: &'a str,
    temp_name: &'a str,
    final_name: &'a str,
    committed_offset: u64,
    committed_sha256: &'a str,
    deferred_error: Option<u16>,
    terminal: &'a TerminalState,
}

impl TransferState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer_id: [u8; 16],
        authorization_hash: [u8; 32],
        profile_version: u8,
        batch_chunks: u64,
        file_size: u64,
        chunk_size: u64,
        file_sha256: [u8; 32],
        init_nonce: [u8; 16],
        temp_name: String,
        final_name: String,
    ) -> Self {
        let mut value = Self {
            version: VERSION,
            transfer_id: hex::encode(transfer_id),
            authorization_hash: hex::encode(authorization_hash),
            profile_version,
            batch_chunks,
            file_size,
            chunk_size,
            file_sha256: hex::encode(file_sha256),
            init_nonce: hex::encode(init_nonce),
            temp_name,
            final_name,
            committed_offset: 0,
            committed_sha256: hex::encode(Sha256::digest([])),
            deferred_error: None,
            terminal: TerminalState::Active,
            checksum: String::new(),
            auth_tag: String::new(),
        };
        value.refresh_checksum();
        value
    }

    pub fn transfer_id_bytes(&self) -> Result<[u8; 16], String> {
        decode_hex(&self.transfer_id, "transfer ID")
    }

    pub fn expected_digest(&self) -> Result<[u8; 32], String> {
        decode_hex(&self.file_sha256, "file digest")
    }

    pub fn refresh_checksum(&mut self) {
        self.checksum = hex::encode(Sha256::digest(self.checked_bytes()));
    }

    fn refresh_auth_tag(&mut self, auth_key: &[u8; 32]) {
        let mut mac = HmacSha256::new_from_slice(auth_key).expect("fixed HMAC key length");
        mac.update(TRANSFER_AUTH_DOMAIN);
        mac.update(self.checksum.as_bytes());
        self.auth_tag = hex::encode(mac.finalize().into_bytes());
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported transfer journal version".into());
        }
        let _: [u8; 16] = decode_hex(&self.transfer_id, "transfer ID")?;
        let _: [u8; 32] = decode_hex(&self.authorization_hash, "authorization hash")?;
        let _: [u8; 32] = decode_hex(&self.file_sha256, "file digest")?;
        let _: [u8; 16] = decode_hex(&self.init_nonce, "init nonce")?;
        let _: [u8; 32] = decode_hex(&self.committed_sha256, "committed digest")?;
        if !matches!(self.profile_version, 1 | 2)
            || self.batch_chunks == 0
            || self.chunk_size == 0
            || self.committed_offset > self.file_size
            || self.deferred_error.is_some_and(|code| {
                code == gcoms_core::file_stream::AckCode::Ok as u16
                    || gcoms_core::file_stream::AckCode::try_from(code).is_err()
            })
            || (self.deferred_error.is_some() && !matches!(self.terminal, TerminalState::Active))
            || !safe_leaf(&self.temp_name)
            || !safe_leaf(&self.final_name)
            || self.temp_name == self.final_name
        {
            return Err("invalid transfer journal fields".into());
        }
        let want = hex::encode(Sha256::digest(self.checked_bytes()));
        if self.checksum != want {
            return Err("transfer journal checksum mismatch".into());
        }
        Ok(())
    }

    fn validate_authenticated(&self, auth_key: &[u8; 32]) -> Result<(), String> {
        self.validate()?;
        let tag: [u8; 32] = hex::decode(&self.auth_tag)
            .map_err(|_| "invalid transfer journal authentication tag")?
            .try_into()
            .map_err(|_| "invalid transfer journal authentication tag length")?;
        let mut mac = HmacSha256::new_from_slice(auth_key).expect("fixed HMAC key length");
        mac.update(TRANSFER_AUTH_DOMAIN);
        mac.update(self.checksum.as_bytes());
        mac.verify_slice(&tag)
            .map_err(|_| "transfer journal authentication failed".into())
    }

    fn checked_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&Checked {
            version: self.version,
            transfer_id: &self.transfer_id,
            authorization_hash: &self.authorization_hash,
            profile_version: self.profile_version,
            batch_chunks: self.batch_chunks,
            file_size: self.file_size,
            chunk_size: self.chunk_size,
            file_sha256: &self.file_sha256,
            init_nonce: &self.init_nonce,
            temp_name: &self.temp_name,
            final_name: &self.final_name,
            committed_offset: self.committed_offset,
            committed_sha256: &self.committed_sha256,
            deferred_error: self.deferred_error,
            terminal: &self.terminal,
        })
        .expect("fixed journal fields serialize")
    }
}

fn safe_leaf(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains('\\')
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn decode_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|_| format!("invalid {field}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("invalid {field} length"))
}

pub struct Journal {
    root: PathBuf,
    auth_key: zeroize::Zeroizing<[u8; 32]>,
}

impl Journal {
    pub fn open(root: &Path, auth_key: &[u8; 32]) -> Result<Self, String> {
        create_owner_dir(root)?;
        reject_symlink(root)?;
        Ok(Self {
            root: root.to_owned(),
            auth_key: zeroize::Zeroizing::new(*auth_key),
        })
    }

    pub fn store(&self, value: &mut TransferState) -> Result<(), String> {
        value.refresh_checksum();
        value.refresh_auth_tag(&self.auth_key);
        value.validate_authenticated(&self.auth_key)?;
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        atomic_owner_write(&self.path(&value.transfer_id), &bytes)
    }

    pub fn load_all(&self) -> Result<Vec<TransferState>, String> {
        let mut values = Vec::new();
        for entry in std::fs::read_dir(&self.root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                return Err("symlink in journal directory".into());
            }
            if !kind.is_file() || entry.path().extension().and_then(|v| v.to_str()) != Some("json")
            {
                continue;
            }
            let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
            let value: TransferState = serde_json::from_slice(&bytes)
                .map_err(|_| "corrupt transfer journal".to_string())?;
            value.validate_authenticated(&self.auth_key)?;
            if entry.file_name() != format!("{}.json", value.transfer_id).as_str() {
                return Err("journal filename mismatch".into());
            }
            values.push(value);
        }
        Ok(values)
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        if !safe_leaf(id) {
            return Err("invalid transfer ID".into());
        }
        match std::fs::remove_file(self.path(id)) {
            Ok(()) => sync_directory(&self.root).map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
}

pub fn derive_state_auth_key(wrapping_key: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(wrapping_key).expect("fixed HMAC key length");
    mac.update(STATE_KEY_DOMAIN);
    mac.finalize().into_bytes().into()
}

pub fn atomic_owner_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("path has no parent")?;
    reject_symlink(parent)?;
    let leaf = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("invalid filename")?;
    let random: u64 = rand::random();
    let temporary = parent.join(format!(".{leaf}.{random:016x}.tmp"));
    #[cfg(unix)]
    let file_result = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
    };
    #[cfg(not(unix))]
    let file_result = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary);
    let mut file = file_result.map_err(|e| e.to_string())?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|e| e.to_string())
}

// Match the controller's platform-specific atomic publication: Windows uses
// write-through replacement, while Unix commits the containing directory.
#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}
#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
pub fn sync_directory(_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(_path)?.sync_all()?;
    Ok(())
}

pub fn hash_prefix(path: &Path, length: u64) -> Result<[u8; 32], String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut remaining = length;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let capacity = buffer.len();
        let count = file
            .read(&mut buffer[..remaining.min(capacity as u64) as usize])
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("temporary file shorter than committed journal offset".into());
        }
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(digest.finalize().into())
}

pub fn read_range(path: &Path, offset: u64, length: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    if std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("managed path is a symlink".into());
    }
    Ok(())
}

pub fn create_owner_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_journal_and_path_fields_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open(dir.path(), &[0xa5; 32]).unwrap();
        let mut value = TransferState::new(
            [1; 16],
            [2; 32],
            gcoms_core::file_stream::PROFILE_VERSION_V1,
            2,
            3,
            3,
            [4; 32],
            [5; 16],
            ".01.part".into(),
            "01".into(),
        );
        journal.store(&mut value).unwrap();
        let path = dir.path().join(format!("{}.json", value.transfer_id));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 1;
        std::fs::write(path, bytes).unwrap();
        assert!(journal.load_all().is_err());
        value.temp_name = "../escape".into();
        value.refresh_checksum();
        assert!(value.validate().is_err());
    }

    #[test]
    fn recomputed_checksum_cannot_forge_authenticated_state() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open(dir.path(), &[0xa5; 32]).unwrap();
        let mut value = TransferState::new(
            [1; 16],
            [2; 32],
            gcoms_core::file_stream::PROFILE_VERSION_V2,
            2,
            8,
            4,
            [4; 32],
            [5; 16],
            ".01.part".into(),
            "01.bin".into(),
        );
        journal.store(&mut value).unwrap();
        let path = dir.path().join(format!("{}.json", value.transfer_id));
        let mut forged: TransferState =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        forged.committed_offset = 4;
        forged.refresh_checksum();
        std::fs::write(path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(journal
            .load_all()
            .unwrap_err()
            .contains("authentication failed"));
    }
}
