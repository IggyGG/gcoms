//! Shared owner-only file checks, extracted from gc-client-core::private_fs.
use std::path::Path;

pub fn validate_private_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    validate_private_metadata(path, &metadata, label, false)
}

pub fn validate_private_dir(path: &Path, label: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a real directory"));
    }
    validate_private_metadata(path, &metadata, label, true)
}

pub fn validate_private_parent(path: &Path, label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("{label} must have a parent directory"))?;
    validate_private_dir(parent, &format!("{label} parent"))
}

/// Make `path` private to the current user: mode 0700/0600 on Unix; on
/// Windows take ownership and replace the DACL with an owner-only grant
/// (an elevated shell otherwise leaves new files owned by Administrators,
/// which `validate_private_*` rejects).
pub fn make_private(path: &Path, directory: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if directory { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("chmod {}: {error}", path.display()))
    }
    #[cfg(windows)]
    {
        windows::make_owner_only(path, directory)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, directory);
        Ok(())
    }
}

#[cfg(unix)]
fn validate_private_metadata(
    _path: &Path,
    metadata: &std::fs::Metadata,
    label: &str,
    directory: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(format!("{label} must be owned by the current user"));
    }
    let forbidden = if directory { 0o077 } else { 0o177 };
    if metadata.permissions().mode() & forbidden != 0 {
        return Err(format!(
            "{label} must have mode {} or stricter",
            if directory { "0700" } else { "0600" }
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_metadata(
    path: &Path,
    _metadata: &std::fs::Metadata,
    label: &str,
    _directory: bool,
) -> Result<(), String> {
    windows::validate_owner_only(path).map_err(|error| format!("{label} {error}"))
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid, GetTokenInformation,
        TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) fn validate_owner_only(path: &Path) -> Result<(), String> {
        let current_sid = current_user_sid()?;
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(format!("security lookup failed: OS error {status}"));
        }
        let result = inspect_acl(owner, dacl, &current_sid);
        unsafe { LocalFree(descriptor) };
        result
    }

    fn inspect_acl(owner: *mut c_void, dacl: *mut ACL, current_sid: &[u8]) -> Result<(), String> {
        if owner.is_null()
            || unsafe { EqualSid(owner, current_sid.as_ptr().cast_mut().cast()) } == 0
        {
            return Err("must be owned by the current user".into());
        }
        if dacl.is_null() {
            return Err("must have a non-null owner-only DACL".into());
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(format!(
                "DACL lookup failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut owner_allow = false;
        for index in 0..information.AceCount {
            let mut ace = null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(format!(
                    "DACL entry lookup failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
            if allowed.Header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8 {
                let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
                if unsafe { EqualSid(sid, current_sid.as_ptr().cast_mut().cast()) } == 0 {
                    return Err(
                        "DACL grants access to a principal other than the current user".into(),
                    );
                }
                owner_allow = true;
            } else if allowed.Header.AceType != ACCESS_DENIED_ACE_TYPE as u8 {
                return Err("DACL contains an unsupported access entry".into());
            }
        }
        if !owner_allow {
            return Err("DACL does not grant the current user access".into());
        }
        Ok(())
    }

    /// `S-1-5-...` for the current process token.
    pub(super) fn current_user_sid_string() -> Result<String, String> {
        let sid = current_user_sid()?;
        let mut out: *mut u16 = null_mut();
        if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut out) } == 0 {
            return Err(format!(
                "SID conversion failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut length = 0;
        while unsafe { *out.add(length) } != 0 {
            length += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, length) });
        unsafe { LocalFree(out.cast()) };
        Ok(text)
    }

    /// Take ownership and install an owner-only DACL through `icacls`, the
    /// same tool the installers and the Windows process test rely on.
    pub(super) fn make_owner_only(path: &Path, directory: bool) -> Result<(), String> {
        let sid = current_user_sid_string()?;
        let grant = if directory {
            format!("*{sid}:(OI)(CI)F")
        } else {
            format!("*{sid}:F")
        };
        for arguments in [
            vec!["/setowner".to_string(), format!("*{sid}")],
            vec!["/inheritance:r".to_string(), "/grant:r".to_string(), grant],
        ] {
            let output = std::process::Command::new("icacls.exe")
                .arg(path)
                .args(&arguments)
                .output()
                .map_err(|error| format!("run icacls: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "icacls {} failed: {}",
                    arguments.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
        }
        Ok(())
    }

    fn current_user_sid() -> Result<Vec<u8>, String> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!(
                "token lookup failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut length = 0;
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length) };
        let mut token_user = vec![0u8; length as usize];
        let loaded = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_user.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        };
        unsafe { CloseHandle(token) };
        if loaded == 0 {
            return Err(format!(
                "token lookup failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let sid = unsafe { (*(token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        let mut result = vec![0u8; sid_length];
        unsafe { std::ptr::copy_nonoverlapping(sid.cast::<u8>(), result.as_mut_ptr(), sid_length) };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_private_then_validate_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("private");
        std::fs::create_dir(&dir).unwrap();
        make_private(&dir, true).unwrap();
        validate_private_dir(&dir, "dir").unwrap();
        let file = dir.join("secret");
        std::fs::write(&file, b"secret").unwrap();
        make_private(&file, false).unwrap();
        validate_private_file(&file, "file").unwrap();
        validate_private_parent(&file, "file").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_file_and_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("secret");
        std::fs::write(&file, b"secret").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(validate_private_file(&file, "secret").is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_private_file(&file, "secret").is_ok());
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_private_dir(temp.path(), "directory").is_err());
    }
}
