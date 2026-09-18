//! GCPRT1 encrypted protocol storage, extracted without changing its encoding.
use fs2::FileExt;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zeroize::Zeroizing;
const PROTOCOL_MAGIC: &[u8; 6] = b"GCPRT1";
const ARGON_M_COST: u32 = 64 * 1024;
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;
const HEADER_LEN: usize = 6 + 12 + 16 + 12;
#[derive(Serialize, Deserialize)]
pub struct ProtocolData {
    pub identity_seed: [u8; 32],
    pub node_state: Option<Vec<u8>>,
}
fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = argon2::Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(out)
}

fn parse_header(raw: &[u8], magic: &[u8; 6]) -> Result<([u8; 16], [u8; 12]), String> {
    if raw.len() < HEADER_LEN + 16 || &raw[..6] != magic {
        return Err("not a gc client store".into());
    }
    let m = u32::from_be_bytes(raw[6..10].try_into().unwrap());
    let t = u32::from_be_bytes(raw[10..14].try_into().unwrap());
    let p = u32::from_be_bytes(raw[14..18].try_into().unwrap());
    // Refuse KDF params that differ from client policy: a tampered header
    // must not weaken (or DoS) the unlock.
    if m != ARGON_M_COST || t != ARGON_T_COST || p != ARGON_P_COST {
        return Err("store KDF params differ from client policy".into());
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&raw[18..34]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[34..46]);
    Ok((salt, nonce))
}

struct EncryptedStore {
    path: std::path::PathBuf,
    magic: &'static [u8; 6],
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    initialized: AtomicBool,
    save_lock: Mutex<()>,
    _profile_lock: std::fs::File,
}

impl EncryptedStore {
    fn create(
        path: &std::path::Path,
        passphrase: &str,
        magic: &'static [u8; 6],
        label: &str,
    ) -> Result<Self, String> {
        ensure_parent(path)?;
        let profile_lock = acquire_lock(path)?;
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!("{label} exists: {}", path.display()));
        }
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        Ok(Self {
            path: path.to_path_buf(),
            magic,
            salt,
            key: derive_key(passphrase, &salt)?,
            initialized: AtomicBool::new(false),
            save_lock: Mutex::new(()),
            _profile_lock: profile_lock,
        })
    }

    fn open<T: DeserializeOwned>(
        path: &std::path::Path,
        passphrase: &str,
        magic: &'static [u8; 6],
        corruption: &str,
    ) -> Result<(Self, T), String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

        ensure_parent(path)?;
        crate::private_fs::validate_private_file(path, "encrypted store")?;
        let profile_lock = acquire_lock(path)?;
        let raw = std::fs::read(path).map_err(|error| error.to_string())?;
        let (salt, nonce) = parse_header(&raw, magic)?;
        let key = derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
        let plain = cipher
            .decrypt(Nonce::from_slice(&nonce), &raw[HEADER_LEN..])
            .map_err(|_| corruption.to_string())?;
        let (data, trailing) =
            postcard::take_from_bytes(&plain).map_err(|error| format!("deserialize: {error}"))?;
        if !trailing.is_empty() {
            return Err("trailing bytes in encrypted store".into());
        }
        Ok((
            Self {
                path: path.to_path_buf(),
                magic,
                salt,
                key,
                initialized: AtomicBool::new(true),
                save_lock: Mutex::new(()),
                _profile_lock: profile_lock,
            },
            data,
        ))
    }

    fn save<T: Serialize>(&self, data: &T) -> Result<(), String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

        let _save = self.save_lock.lock().map_err(|_| "store lock poisoned")?;
        let plain = postcard::to_allocvec(data).map_err(|error| format!("serialize: {error}"))?;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| "encrypt failed".to_string())?;
        let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        output.extend_from_slice(self.magic);
        output.extend_from_slice(&ARGON_M_COST.to_be_bytes());
        output.extend_from_slice(&ARGON_T_COST.to_be_bytes());
        output.extend_from_slice(&ARGON_P_COST.to_be_bytes());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        atomic_write(
            &self.path,
            &output,
            !self.initialized.load(Ordering::Acquire),
        )?;
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }
}

fn ensure_parent(path: &std::path::Path) -> Result<(), String> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if !parent.exists() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        crate::private_fs::make_private(parent, true)?;
    }
    crate::private_fs::validate_private_dir(parent, "profile directory")?;
    Ok(())
}

pub(crate) fn acquire_lock(path: &std::path::Path) -> Result<std::fs::File, String> {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(std::path::PathBuf::from(lock_name))
        .map_err(|error| error.to_string())?;
    lock.try_lock_exclusive()
        .map_err(|_| format!("profile is already in use: {}", path.display()))?;
    Ok(lock)
}

pub(crate) fn atomic_write(
    path: &std::path::Path,
    bytes: &[u8],
    no_clobber: bool,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let prefix = format!(
        ".{}.",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("gcstore")
    );
    let mut temporary = tempfile::Builder::new()
        .prefix(&prefix)
        .tempfile_in(parent)
        .map_err(|error| error.to_string())?;
    // Fix ownership and ACLs before publication, including elevated Windows
    // accounts whose default file owner is the Administrators group.
    crate::private_fs::make_private(temporary.path(), false)?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| error.to_string())?;
    if no_clobber {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error.to_string())?;
    } else {
        temporary
            .persist(path)
            .map_err(|error| error.error.to_string())?;
    }
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub struct ProtocolStore(EncryptedStore);
impl ProtocolStore {
    pub fn verify_secret(&self, secret: &str) -> Result<(), String> {
        use subtle::ConstantTimeEq;
        let candidate = derive_key(secret, &self.0.salt)?;
        if bool::from(candidate.ct_eq(&*self.0.key)) {
            Ok(())
        } else {
            Err("profile unlock rejected".into())
        }
    }

    pub fn network_directory(&self) -> std::path::PathBuf {
        self.0.path.with_extension("network")
    }

    pub fn create(
        path: &std::path::Path,
        passphrase: &str,
    ) -> Result<(Self, ProtocolData), String> {
        let store = Self(EncryptedStore::create(
            path,
            passphrase,
            PROTOCOL_MAGIC,
            "protocol profile",
        )?);
        let mut identity_seed = [0; 32];
        rand::thread_rng().fill_bytes(&mut identity_seed);
        let data = ProtocolData {
            identity_seed,
            node_state: None,
        };
        store.save(&data)?;
        Ok((store, data))
    }

    pub fn open(path: &std::path::Path, passphrase: &str) -> Result<(Self, ProtocolData), String> {
        let (store, data) = EncryptedStore::open(
            path,
            passphrase,
            PROTOCOL_MAGIC,
            "wrong passphrase or corrupted protocol profile",
        )?;
        Ok((Self(store), data))
    }

    /// Read a consistent encrypted snapshot without creating a profile/lock or
    /// changing the live writer. Saves use atomic replacement; identity is stable.
    /// Return only the public key, never the seed or protocol state.
    pub fn inspect_identity_public_key(
        path: &std::path::Path,
        passphrase: &str,
    ) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
        crate::private_fs::validate_private_file(path, "encrypted profile")?;
        crate::private_fs::validate_private_parent(path, "encrypted profile")?;
        let raw = std::fs::read(path).map_err(|_| "read encrypted profile")?;
        let (salt, nonce) = parse_header(&raw, PROTOCOL_MAGIC)?;
        let key = derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
        let plain = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce), &raw[HEADER_LEN..])
                .map_err(|_| "profile decryption refused")?,
        );
        let (mut data, trailing): (ProtocolData, _) =
            postcard::take_from_bytes(&plain).map_err(|_| "invalid encrypted profile")?;
        if !trailing.is_empty() {
            return Err("trailing encrypted profile data".into());
        }
        let public = gcoms_crypto::IdentityKeypair::from_seed(data.identity_seed).public_bytes();
        zeroize::Zeroize::zeroize(&mut data.identity_seed);
        Ok(public)
    }

    pub fn save(&self, data: &ProtocolData) -> Result<(), String> {
        self.0.save(data)
    }
}

impl ProtocolStore {
    /// Import an already unlocked legacy profile into a new, exclusively owned file.
    pub fn import_new(
        path: &std::path::Path,
        passphrase: &str,
        data: &ProtocolData,
    ) -> Result<Self, String> {
        let store = Self(EncryptedStore::create(
            path,
            passphrase,
            PROTOCOL_MAGIC,
            "protocol profile",
        )?);
        store.save(data)?;
        Ok(store)
    }
}

/// Compatibility adapter for hosts retaining an existing encrypted combined archive.
/// Save is synchronous and must atomically persist before returning.
pub trait ProfileStorage: Send + Sync {
    fn save(&self, data: &ProtocolData) -> Result<(), String>;
    fn network_directory(&self) -> std::path::PathBuf;
    fn verify_secret(&self, secret: &str) -> Result<(), String>;
}
impl ProfileStorage for ProtocolStore {
    fn save(&self, data: &ProtocolData) -> Result<(), String> {
        ProtocolStore::save(self, data)
    }
    fn network_directory(&self) -> std::path::PathBuf {
        ProtocolStore::network_directory(self)
    }
    fn verify_secret(&self, secret: &str) -> Result<(), String> {
        ProtocolStore::verify_secret(self, secret)
    }
}
impl ProtocolData {
    pub fn safety_number(&self) -> String {
        gcoms_crypto::safety_number_of(
            &gcoms_crypto::IdentityKeypair::from_seed(self.identity_seed).public_bytes(),
        )
    }
}
