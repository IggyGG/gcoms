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
#[derive(Clone, Copy, PartialEq, Eq)]
enum CacheFormat {
    Gc1,
    #[cfg(feature = "experimental-gc2")]
    Gc2,
}
impl CacheFormat {
    fn max_bytes(self) -> usize {
        match self {
            Self::Gc1 => MAX_CACHE,
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2 => gcoms_routing::gc2::directory::MAX_PRIVATE_BYTES,
        }
    }
    fn magic(self) -> &'static [u8; 5] {
        match self {
            Self::Gc1 => b"GCRN\x01",
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2 => b"GCRN\x02",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Gc1 => "routing.cache",
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2 => "routing-gc2.cache",
        }
    }
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Gc1 => b"ghost.gcnode.routing-cache.v1",
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2 => b"ghost.gcnode.routing-cache.v2",
        }
    }
    fn validate(self, plain: &[u8]) -> Result<()> {
        match self {
            Self::Gc1 => {
                gcoms_routing::Directory::restore_private(plain)?;
            }
            #[cfg(feature = "experimental-gc2")]
            Self::Gc2 => {
                gcoms_routing::gc2::directory::Directory::restore_private(
                    plain,
                    gcoms_routing::route::now_unix(),
                )?;
            }
        }
        Ok(())
    }
}
pub struct Cache {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    _lock: File,
    format: CacheFormat,
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
        Self::open_format(directory, seed, CacheFormat::Gc1)
    }

    /// A distinct file, authenticated header and derived key. Opening GC/2
    /// neither interprets nor overwrites the retained GC/1 cache.
    #[cfg(feature = "experimental-gc2")]
    pub fn open_gc2(directory: &Path, seed: &[u8; 32]) -> Result<Self> {
        Self::open_format(directory, seed, CacheFormat::Gc2)
    }

    /// Transfers the exclusive writer lock into the directory's checkpoint.
    /// Every published change is encrypted and synced before routing can use it.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_directory(self, now: u64) -> Result<gcoms_routing::gc2::directory::Directory> {
        use gcoms_routing::gc2::directory::Directory;
        if self.format != CacheFormat::Gc2 {
            return Err("GC/2 routing cache required".into());
        }
        let directory = match self.load_inner()? {
            Some(bytes) => Directory::restore_private(&bytes, now)?,
            None => Directory::new(),
        };
        directory.with_checkpoint(std::sync::Arc::new(move |bytes| self.save_inner(bytes)))
    }

    fn open_format(directory: &Path, seed: &[u8; 32], format: CacheFormat) -> Result<Self> {
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
            .expand(format.domain(), &mut *key)
            .map_err(|_| "routing key derivation")?;
        Ok(Self {
            path: directory.join(format.name()),
            key,
            _lock: lock,
            format,
        })
    }

    fn load_inner(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(bytes) = read_optional(&self.path, self.format.max_bytes() + 35)? else {
            return Ok(None);
        };
        if bytes.len() < 35
            || &bytes[..5] != self.format.magic()
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
        if plain.len() > self.format.max_bytes() {
            return Err("routing cache exceeds bounds".into());
        }
        self.format.validate(plain)?;
        let mut aad = [0; 19];
        aad[..5].copy_from_slice(self.format.magic());
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
    #[cfg(feature = "experimental-gc2")]
    #[test]
    fn gc2_checkpoint_restores_guards_without_modifying_gc1_or_losing_writer_lock() {
        use gcoms_routing::gc2::directory::{BootstrapBundle, Directory, Introduction};
        let path =
            std::env::temp_dir().join(format!("gc2-routing-cache-{:016x}", rand::random::<u64>()));
        let now = gcoms_routing::route::now_unix();
        let gc1 = Cache::open(&path, &[7; 32]).unwrap();
        gc1.save(&gcoms_routing::Directory::new().encode_private().unwrap())
            .unwrap();
        let old = std::fs::read(path.join("routing.cache")).unwrap();
        assert!(Cache::open_gc2(&path, &[7; 32]).is_err());
        drop(gc1);
        let directory = Cache::open_gc2(&path, &[7; 32])
            .unwrap()
            .gc2_directory(now)
            .unwrap();
        assert!(Cache::open(&path, &[7; 32]).is_err());
        assert!(Cache::open_gc2(&path, &[7; 32]).is_err());
        for group in 0..8 {
            directory
                .remember(
                    &BootstrapBundle {
                        relays: (2 + group * 8..10 + group * 8)
                            .map(|seed| Introduction {
                                addr: format!("8.0.0.{seed}:443").parse().unwrap(),
                                service_id: [seed; 32],
                                reentry_cap: [12; 32],
                                entry_cap: [22; 32],
                                transit_cap: [32; 32],
                                expires_at: now + 100,
                            })
                            .collect(),
                    },
                    now,
                )
                .unwrap();
        }
        for seed in 2..5 {
            directory.retain_guard([seed; 32]).unwrap();
        }
        directory
            .set_own_services(
                (100..108)
                    .map(|seed| (format!("9.0.0.{seed}:443").parse().unwrap(), [seed; 32]))
                    .collect(),
            )
            .unwrap();
        let expected = directory.encode_private().unwrap();
        assert_eq!(
            expected.len(),
            gcoms_routing::gc2::directory::MAX_PRIVATE_BYTES
        );
        let encrypted = std::fs::read(path.join("routing-gc2.cache")).unwrap();
        assert_eq!(encrypted.len(), expected.len() + 35);
        assert_eq!(&encrypted[..5], b"GCRN\x02");
        assert!(!encrypted.windows(32).any(|value| value == [12; 32]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path.join("routing-gc2.cache"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        drop(directory);
        let restored = Cache::open_gc2(&path, &[7; 32])
            .unwrap()
            .gc2_directory(now + 101)
            .unwrap();
        assert_eq!(restored.encode_private().unwrap(), expected);
        assert_eq!(restored.guards(), vec![[2; 32], [3; 32], [4; 32]]);
        assert!(restored.eligible(&[], now + 101).unwrap().is_empty());
        assert_eq!(std::fs::read(path.join("routing.cache")).unwrap(), old);
        drop(restored);
        assert!(Cache::open_gc2(&path, &[8; 32])
            .unwrap()
            .gc2_directory(now)
            .is_err());
        let cache = Cache::open_gc2(&path, &[7; 32]).unwrap();
        assert!(cache
            .save(&gcoms_routing::Directory::new().encode_private().unwrap())
            .is_err());
        let mut bad = encrypted.clone();
        bad[19] ^= 1;
        std::fs::write(&cache.path, bad).unwrap();
        assert!(cache.load().is_err());
        std::fs::write(&cache.path, &old).unwrap();
        assert!(cache.load().is_err()); // GC/1 is never treated as GC/2
        std::fs::write(&cache.path, &encrypted).unwrap();
        assert_eq!(
            Directory::restore_private(&cache.load().unwrap().unwrap(), now)
                .unwrap()
                .guards(),
            vec![[2; 32], [3; 32], [4; 32]]
        );
        drop(cache);
        assert!(Cache::open(&path, &[7; 32])
            .unwrap()
            .gc2_directory(now)
            .is_err());
        std::fs::remove_dir_all(path).unwrap();
    }

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
