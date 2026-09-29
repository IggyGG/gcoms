use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::RngCore;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

type OpenedStorage = (Storage, Option<Zeroizing<Vec<u8>>>);

const MAGIC: &[u8] = b"GCHCLIENT1";
const MAX_ARCHIVE: usize = 64 * 1024 * 1024;

/// An exclusively owned encrypted sidecar, separate from all legacy profiles.
/// A failed/uncertain save poisons the live owner until disk state is reopened.
pub(super) struct Storage {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    channel: [u8; 32],
    _lock: std::fs::File,
    poisoned: bool,
}
impl Storage {
    pub(super) fn open(
        path: &Path,
        key: [u8; 32],
        channel: [u8; 32],
    ) -> Result<OpenedStorage, String> {
        crate::private_fs::validate_private_parent(path, "hosted profile")?;
        let lock = crate::store::acquire_lock(path)?;
        let store = Self {
            path: path.to_owned(),
            key: Zeroizing::new(key),
            channel,
            _lock: lock,
            poisoned: false,
        };
        let data = match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                crate::private_fs::validate_private_file(path, "hosted profile")?;
                if metadata.len() > (MAX_ARCHIVE + 64) as u64 {
                    return Err("hosted profile exceeds bound".into());
                }
                let raw = std::fs::read(path).map_err(|_| "read hosted profile")?;
                if !raw.starts_with(MAGIC) || raw.len() < MAGIC.len() + 12 + 16 {
                    return Err("invalid hosted profile".into());
                }
                let cipher = Aes256Gcm::new_from_slice(store.key.as_slice())
                    .map_err(|_| "hosted profile key")?;
                Some(Zeroizing::new(
                    cipher
                        .decrypt(
                            Nonce::from_slice(&raw[MAGIC.len()..MAGIC.len() + 12]),
                            Payload {
                                msg: &raw[MAGIC.len() + 12..],
                                aad: &store.aad(),
                            },
                        )
                        .map_err(|_| "hosted profile authentication failed")?,
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("inspect hosted profile".into()),
        };
        Ok((store, data))
    }
    fn aad(&self) -> Vec<u8> {
        let mut aad = MAGIC.to_vec();
        aad.extend_from_slice(&self.channel);
        aad
    }
    pub(super) fn save(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.poisoned {
            return Err("hosted profile must be reopened after a failed save".into());
        }
        self.poisoned = true;
        if bytes.len() > MAX_ARCHIVE {
            return Err("hosted profile storage limit reached".into());
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_slice()).map_err(|_| "hosted profile key")?;
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: bytes,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| "seal hosted profile")?;
        let mut record = MAGIC.to_vec();
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        self.poisoned = true;
        crate::store::atomic_write(&self.path, &record, false)?;
        self.poisoned = false;
        Ok(())
    }
    pub(super) fn poison(&mut self) {
        self.poisoned = true;
    }
    pub(super) fn healthy(&self) -> bool {
        !self.poisoned
    }
}
