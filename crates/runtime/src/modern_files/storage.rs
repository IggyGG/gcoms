use super::*;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};

const MAGIC: &[u8] = b"GCFMETA2";
pub(super) struct Store {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    healthy: bool,
}
impl Store {
    pub fn open(path: PathBuf, key: [u8; 32]) -> Result<(Self, Metadata), SdkError> {
        let store = Self {
            path,
            key: Zeroizing::new(key),
            healthy: true,
        };
        let metadata = match std::fs::symlink_metadata(&store.path) {
            Ok(meta) => {
                gcoms_private_fs::validate_private_file(&store.path, "modern file metadata")
                    .map_err(error)?;
                if meta.len() > 2 * 1024 * 1024 {
                    return Err(error("modern file metadata too large"));
                }
                let bytes = std::fs::read(&store.path).map_err(error)?;
                if bytes.len() < MAGIC.len() + 28 || !bytes.starts_with(MAGIC) {
                    return Err(error("invalid modern file metadata"));
                }
                let plain = Zeroizing::new(
                    Aes256Gcm::new_from_slice(store.key.as_slice())
                        .map_err(error)?
                        .decrypt(
                            Nonce::from_slice(&bytes[MAGIC.len()..MAGIC.len() + 12]),
                            Payload {
                                msg: &bytes[MAGIC.len() + 12..],
                                aad: MAGIC,
                            },
                        )
                        .map_err(error)?,
                );
                let (value, tail): (Metadata, _) =
                    postcard::take_from_bytes(&plain).map_err(error)?;
                if !tail.is_empty() || value.version != 2 || value.entries.len() > 256 {
                    return Err(error("invalid modern file metadata bounds"));
                }
                legacy::Request::Configure(value.config.clone()).validate()?;
                value
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Metadata::default(),
            Err(e) => return Err(error(e)),
        };
        Ok((store, metadata))
    }
    pub fn check(&self) -> Result<(), SdkError> {
        if self.healthy {
            Ok(())
        } else {
            Err(error("reopen file cache after storage failure"))
        }
    }
    pub fn save(&mut self, metadata: &Metadata) -> Result<(), SdkError> {
        self.check()?;
        self.healthy = false;
        let plain = Zeroizing::new(postcard::to_allocvec(metadata).map_err(error)?);
        if plain.len() > 2 * 1024 * 1024 {
            return Err(error("modern file metadata too large"));
        }
        let nonce: [u8; 12] = rand::random();
        let sealed = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(error)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: MAGIC,
                },
            )
            .map_err(error)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(nonce);
        bytes.extend(sealed);
        crate::store::atomic_write(&self.path, &bytes, false).map_err(error)?;
        self.healthy = true;
        Ok(())
    }
}
