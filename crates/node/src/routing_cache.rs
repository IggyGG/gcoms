use crate::node::RoutingStateStore;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use gcoms_private_fs::{make_private, validate_private_dir, validate_private_file};
use gcoms_routing::Result;
use rand::RngCore;
use sha2::Sha256;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(crate) const MAX_CACHE: usize = 7 + 64 * 123 + 3 * 32;
pub struct Cache {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    _lock: File,
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
        make_private(path, true)?;
    }
    validate_private_dir(path, "routing state")?;
    Ok(())
}

pub(crate) fn options(write: bool) -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts
}

pub(crate) fn read_optional(path: &Path, max: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let file = match options(false).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A dangling symlink must not be interpreted as an absent cache.
            return match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err("routing state path is not a readable regular file".into()),
            };
        }
        Err(e) => return Err(e.into()),
    };
    validate_private_file(path, "private routing material")?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > max as u64 {
        return Err("routing state exceeds bounds or is not regular".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err("routing state exceeds bounds".into());
    }
    Ok(Some(bytes))
}

pub(crate) fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    validate_private_dir(parent, "routing material parent")?;
    let temp = parent.join(format!(
        ".routing-{:016x}.tmp",
        rand::rngs::OsRng.next_u64()
    ));
    let mut file = options(true).create_new(true).open(&temp)?;
    let result = (|| {
        make_private(&temp, false)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            std::fs::rename(&temp, path)?;
            File::open(parent)?.sync_all()?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            };
            let from: Vec<_> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err("private routing persistence is unsupported on this platform".into());
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

impl Cache {
    pub fn open(directory: &Path, seed: &[u8; 32]) -> Result<Self> {
        private_directory(directory)?;
        let lock_path = directory.join("routing.lock");
        let lock = options(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        make_private(&lock_path, false)?;
        validate_private_file(&lock_path, "routing writer lock")?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| "routing state is already owned by another process")?;
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(None, seed)
            .expand(b"ghost.gcnode.routing-cache.v1", &mut *key)
            .map_err(|_| "routing key derivation")?;
        Ok(Self {
            path: directory.join("routing.cache"),
            key,
            _lock: lock,
        })
    }

    fn load_inner(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(bytes) = read_optional(&self.path, MAX_CACHE + 35)? else {
            return Ok(None);
        };
        if bytes.len() < 35
            || &bytes[..5] != b"GCRN\x01"
            || usize::from(u16::from_be_bytes(bytes[17..19].try_into()?)) + 35 != bytes.len()
        {
            return Err("invalid encrypted routing cache".into());
        }
        let plain = Aes256Gcm::new_from_slice(self.key.as_slice())?
            .decrypt(
                Nonce::from_slice(&bytes[5..17]),
                Payload {
                    msg: &bytes[19..],
                    aad: &bytes[..19],
                },
            )
            .map_err(|_| "routing cache authentication failed")?;
        Ok(Some(Zeroizing::new(plain)))
    }

    fn save_inner(&self, plain: &[u8]) -> Result<()> {
        if plain.len() > MAX_CACHE {
            return Err("routing cache exceeds bounds".into());
        }
        gcoms_routing::Directory::restore_private(plain)?;
        let mut aad = [0; 19];
        aad[..5].copy_from_slice(b"GCRN\x01");
        rand::rngs::OsRng.fill_bytes(&mut aad[5..17]);
        aad[17..].copy_from_slice(&(plain.len() as u16).to_be_bytes());
        let mut bytes = aad.to_vec();
        bytes.extend(
            Aes256Gcm::new_from_slice(self.key.as_slice())?
                .encrypt(
                    Nonce::from_slice(&aad[5..17]),
                    Payload {
                        msg: plain,
                        aad: &aad,
                    },
                )
                .map_err(|_| "routing cache encryption failed")?,
        );
        replace(&self.path, &bytes)
    }
}

impl RoutingStateStore for Cache {
    fn load(&self) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, String> {
        self.load_inner().map_err(|e| e.to_string())
    }
    fn save(&self, bytes: &[u8]) -> std::result::Result<(), String> {
        self.save_inner(bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_view_survives_restart_and_refuses_tampering_and_second_writer() {
        let path =
            std::env::temp_dir().join(format!("gc-routing-cache-{:016x}", rand::random::<u64>()));
        let cache = Cache::open(&path, &[7; 32]).unwrap();
        assert!(cache.load().unwrap().is_none());
        assert!(Cache::open(&path, &[7; 32]).is_err());
        let directory = gcoms_routing::Directory::new();
        for n in 2..6 {
            directory
                .install(
                    gcoms_routing::Relay {
                        addr: format!("8.0.0.{n}:443").parse().unwrap(),
                        service_id: [n; 32],
                        reentry_cap: [n + 10; 32],
                        circuit_cap: [n + 20; 32],
                        expires_at: gcoms_routing::route::now_unix() + 3600,
                    },
                    gcoms_routing::route::now_unix(),
                )
                .unwrap();
        }
        directory
            .path(&[], gcoms_routing::route::now_unix())
            .unwrap();
        let plain = Zeroizing::new(directory.encode_private().unwrap());
        cache.save(&plain).unwrap();
        drop(cache);
        let cache = Cache::open(&path, &[7; 32]).unwrap();
        assert_eq!(&*cache.load().unwrap().unwrap(), &*plain);
        drop(cache);
        assert!(Cache::open(&path, &[8; 32]).unwrap().load().is_err());
        let cache = Cache::open(&path, &[7; 32]).unwrap();
        let mut encrypted = std::fs::read(&cache.path).unwrap();
        encrypted[19] ^= 1;
        std::fs::write(&cache.path, encrypted).unwrap();
        assert!(cache.load().is_err());
        drop(cache);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_read_rejects_links_fifo_and_overlong_material() {
        let path =
            std::env::temp_dir().join(format!("gc-routing-read-{:016x}", rand::random::<u64>()));
        private_directory(&path).unwrap();
        let file = path.join("bootstrap");
        std::os::unix::fs::symlink(path.join("missing"), &file).unwrap();
        assert!(read_optional(&file, 8).is_err());
        std::fs::remove_file(&file).unwrap();
        let cpath = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(read_optional(&file, 8).is_err());
        std::fs::remove_file(&file).unwrap();
        replace(&file, &[0; 9]).unwrap();
        assert!(read_optional(&file, 8).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
