use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::io::Write;

/// v2: argon2id passphrase KDF (m=64 MiB, t=3, p=1).
const MAGIC_V2: &[u8; 6] = b"GC1KS2";
/// v1 (legacy, read-only): single-round HKDF — brute-forceable, superseded.
const MAGIC_V1: &[u8; 6] = b"GC1KS1";

const ARGON_M_COST: u32 = 64 * 1024; // KiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

fn derive_key_v2(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    let params = argon2::Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(32))
        .expect("valid argon2 params");
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .expect("argon2 output is 32 bytes");
    out
}

fn derive_key_v1(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), passphrase.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"gc1/keystore/v1", &mut okm)
        .expect("32 bytes fit hkdf-sha256");
    okm
}

fn seal(key: &[u8; 32], seed: &[u8; 32]) -> ([u8; 12], Vec<u8>) {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), seed.as_slice())
        .expect("aes-gcm seal of 32 bytes");
    (nonce, ct)
}

fn open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> std::io::Result<[u8; 32]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let seed = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| std::io::Error::other("wrong passphrase or corrupted keystore"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&seed);
    Ok(out)
}

pub fn write_identity(
    path: &std::path::Path,
    passphrase: &str,
    mut seed: [u8; 32],
) -> std::io::Result<()> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut key = derive_key_v2(passphrase, &salt);
    let (nonce, ct) = seal(&key, &seed);
    seed.fill(0);
    key.fill(0);
    let mut out = Vec::with_capacity(6 + 12 + 16 + 12 + ct.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&ARGON_M_COST.to_be_bytes());
    out.extend_from_slice(&ARGON_T_COST.to_be_bytes());
    out.extend_from_slice(&ARGON_P_COST.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("gc-key"),
        u64::from_be_bytes(suffix)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(&out)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)?;
        std::fs::remove_file(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Result of unlocking a keystore, including whether it still uses the
/// superseded single-round derivation and should be rekeyed.
pub struct LoadedIdentity {
    pub seed: zeroize::Zeroizing<[u8; 32]>,
    pub legacy_kdf: bool,
}

pub fn load_identity_detailed(
    path: &std::path::Path,
    passphrase: &str,
) -> std::io::Result<LoadedIdentity> {
    let data = std::fs::read(path)?;
    let legacy_kdf = data.len() >= 6 && &data[..6] == MAGIC_V1;
    let seed = load_identity(path, passphrase)?;
    Ok(LoadedIdentity {
        seed: zeroize::Zeroizing::new(seed),
        legacy_kdf,
    })
}

pub fn load_identity(path: &std::path::Path, passphrase: &str) -> std::io::Result<[u8; 32]> {
    let data = std::fs::read(path)?;
    if data.len() >= 6 + 12 + 16 + 12 + 16 && &data[..6] == MAGIC_V2 {
        let m = u32::from_be_bytes(data[6..10].try_into().unwrap());
        let t = u32::from_be_bytes(data[10..14].try_into().unwrap());
        let p = u32::from_be_bytes(data[14..18].try_into().unwrap());
        if (m, t, p) != (ARGON_M_COST, ARGON_T_COST, ARGON_P_COST) {
            return Err(std::io::Error::other("unsupported argon2 parameters"));
        }
        let params = argon2::Params::new(m, t, p, Some(32))
            .map_err(|_| std::io::Error::other("bad argon2 params in keystore"))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[18..34]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[34..46]);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|_| std::io::Error::other("argon2 failed"))?;
        let result = open(&key, &nonce, &data[46..]);
        key.fill(0);
        result
    } else if data.len() >= 6 + 16 + 12 + 16 && &data[..6] == MAGIC_V1 {
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[6..22]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[22..34]);
        let mut key = derive_key_v1(passphrase, &salt);
        let result = open(&key, &nonce, &data[34..]);
        key.fill(0);
        result
    } else {
        Err(std::io::Error::other("not a gc1 keystore"))
    }
}

pub fn rekey_identity(
    path: &std::path::Path,
    old_passphrase: &str,
    new_passphrase: &str,
) -> std::io::Result<()> {
    let mut seed = load_identity(path, old_passphrase)?;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let replacement = parent.join(format!(
        ".{}.{}.rekey",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("gc-key"),
        u64::from_be_bytes(suffix)
    ));
    let result = (|| {
        write_identity(&replacement, new_passphrase, seed)?;
        std::fs::rename(&replacement, path)?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    seed.fill(0);
    if result.is_err() {
        let _ = std::fs::remove_file(&replacement);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gc1ks-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn roundtrip() {
        let dir = tmpdir("v2");
        let path = dir.join("ks.bin");
        write_identity(&path, "correct horse", [7; 32]).unwrap();
        assert_eq!(load_identity(&path, "correct horse").unwrap(), [7; 32]);
        assert!(load_identity(&path, "wrong").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_v1_still_loads() {
        // hand-build a v1 file with the legacy derivation
        let dir = tmpdir("v1");
        let path = dir.join("ks.bin");
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive_key_v1("legacy pass", &salt);
        let (nonce, ct) = seal(&key, &[9; 32]);
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_V1);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        std::fs::write(&path, out).unwrap();
        assert_eq!(load_identity(&path, "legacy pass").unwrap(), [9; 32]);
        assert!(load_identity(&path, "wrong").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v2_file_uses_argon2_header() {
        let dir = tmpdir("hdr");
        let path = dir.join("ks.bin");
        write_identity(&path, "pw", [1; 32]).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[..6], MAGIC_V2);
        let m = u32::from_be_bytes(data[6..10].try_into().unwrap());
        assert_eq!(m, ARGON_M_COST);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_refuses_to_replace_an_identity() {
        let dir = tmpdir("replace");
        let path = dir.join("ks.bin");
        write_identity(&path, "first pass", [1; 32]).unwrap();
        assert!(write_identity(&path, "second pass", [2; 32]).is_err());
        assert_eq!(load_identity(&path, "first pass").unwrap(), [1; 32]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir("mode");
        let path = dir.join("ks.bin");
        write_identity(&path, "pass", [3; 32]).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_preserves_identity_and_rejects_the_old_passphrase() {
        let dir = tmpdir("rekey");
        let path = dir.join("ks.bin");
        write_identity(&path, "old pass", [4; 32]).unwrap();
        rekey_identity(&path, "old pass", "new pass").unwrap();
        assert_eq!(load_identity(&path, "new pass").unwrap(), [4; 32]);
        assert!(load_identity(&path, "old pass").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_rekey_keeps_the_original_identity() {
        let dir = tmpdir("failed-rekey");
        let path = dir.join("ks.bin");
        write_identity(&path, "old pass", [5; 32]).unwrap();
        assert!(rekey_identity(&path, "wrong pass", "new pass").is_err());
        assert_eq!(load_identity(&path, "old pass").unwrap(), [5; 32]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
