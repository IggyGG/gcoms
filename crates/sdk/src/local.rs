use crate::SdkError;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEndpoint(PathBuf);

impl LocalEndpoint {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn prepare_server(&self) -> Result<(), SdkError> {
        prepare_server(self.path())
    }

    pub fn cleanup(&self) -> Result<(), SdkError> {
        cleanup(self.path())
    }
}

impl<P: Into<PathBuf>> From<P> for LocalEndpoint {
    fn from(path: P) -> Self {
        Self::new(path)
    }
}

#[cfg(unix)]
pub type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(unix)]
pub type ServerStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type ServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(unix)]
pub async fn connect(endpoint: &LocalEndpoint) -> Result<ClientStream, SdkError> {
    tokio::net::UnixStream::connect(endpoint.path())
        .await
        .map_err(runtime_error)
}

/// Explicit Unix admission policy. Consumers must allowlist non-owner requests.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LocalPeerPolicy {
    #[default]
    OwnerOnly,
    OwnerOrRoot,
}

/// Authenticated kernel peer credentials, retained through consumer dispatch.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub struct LocalPeer {
    uid: u32,
    owner_uid: u32,
}

#[cfg(unix)]
impl LocalPeer {
    pub fn uid(self) -> u32 {
        self.uid
    }
    pub fn is_owner(self) -> bool {
        self.uid == self.owner_uid
    }
}

/// Connect using independently configured server ownership and a safe absolute path.
/// This authenticates the local service, not the authority of its returned data.
#[cfg(unix)]
pub async fn connect_pinned(
    endpoint: &LocalEndpoint,
    expected_server_uid: u32,
) -> Result<ClientStream, SdkError> {
    let before = pinned_path(endpoint.path(), expected_server_uid)?;
    let stream = connect(endpoint).await?;
    if stream.peer_cred().map_err(runtime_error)?.uid() != expected_server_uid
        || pinned_path(endpoint.path(), expected_server_uid)? != before
    {
        return Err(SdkError::Runtime("IPC server ownership changed".into()));
    }
    Ok(stream)
}

#[cfg(unix)]
fn pinned_path(path: &Path, uid: u32) -> Result<Vec<(u64, u64)>, SdkError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::path::Component;
    let deny = || SdkError::Runtime("unsafe pinned IPC endpoint".into());
    if !path.is_absolute() {
        return Err(deny());
    }
    let mut current = PathBuf::new();
    let mut identities = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component),
            _ => return Err(deny()),
        }
        let meta = std::fs::symlink_metadata(&current).map_err(runtime_error)?;
        let last = current == path;
        if meta.file_type().is_symlink()
            || meta.mode() & 0o022 != 0
            || (meta.uid() != 0 && meta.uid() != uid)
            || (last && (!meta.file_type().is_socket() || meta.uid() != uid))
            || (!last && !meta.is_dir())
        {
            return Err(deny());
        }
        identities.push((meta.dev(), meta.ino()));
    }
    Ok(identities)
}

#[cfg(windows)]
pub async fn connect(endpoint: &LocalEndpoint) -> Result<ClientStream, SdkError> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let name = pipe_name(endpoint.path());
    for attempt in 0..100 {
        match ClientOptions::new().open(&name) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if attempt < 99
                    && matches!(error.raw_os_error(), Some(2) | Some(231) | Some(536)) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => return Err(runtime_error(error)),
        }
    }
    unreachable!("named-pipe retry loop always returns")
}

#[cfg(unix)]
pub struct LocalListener(tokio::net::UnixListener);

#[cfg(unix)]
impl LocalListener {
    pub fn bind(endpoint: &LocalEndpoint) -> Result<Self, SdkError> {
        use std::os::unix::fs::PermissionsExt;

        if endpoint.path().exists() {
            return Err(SdkError::Runtime(format!(
                "IPC socket already exists: {}",
                endpoint.path().display()
            )));
        }
        let listener = tokio::net::UnixListener::bind(endpoint.path()).map_err(runtime_error)?;
        std::fs::set_permissions(endpoint.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(runtime_error)?;
        Ok(Self(listener))
    }

    pub async fn accept(&mut self) -> Result<ServerStream, SdkError> {
        self.accept_with_peer_policy(LocalPeerPolicy::OwnerOnly)
            .await
            .map(|(stream, _)| stream)
    }

    pub async fn accept_with_peer_policy(
        &mut self,
        policy: LocalPeerPolicy,
    ) -> Result<(ServerStream, LocalPeer), SdkError> {
        loop {
            let (stream, _) = self.0.accept().await.map_err(runtime_error)?;
            // Credentials belong to this connection, not the listener. macOS
            // can return ENOTCONN if a probe closes before we inspect its PID.
            // Reject that stream and keep accepting authenticated clients.
            let Ok(credentials) = stream.peer_cred() else {
                continue;
            };
            let uid = credentials.uid();
            let peer = LocalPeer {
                uid,
                owner_uid: rustix::process::getuid().as_raw(),
            };
            if peer.is_owner() || (policy == LocalPeerPolicy::OwnerOrRoot && uid == 0) {
                return Ok((stream, peer));
            }
        }
    }
}

#[cfg(windows)]
pub struct LocalListener {
    name: String,
    security: windows_security::PipeSecurity,
    pending: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
impl LocalListener {
    pub fn bind(endpoint: &LocalEndpoint) -> Result<Self, SdkError> {
        let name = pipe_name(endpoint.path());
        let security = windows_security::PipeSecurity::current_user()?;
        let pending = create_pipe(&name, &security, true)?;
        Ok(Self {
            name,
            security,
            pending,
        })
    }

    pub async fn accept(&mut self) -> Result<ServerStream, SdkError> {
        loop {
            self.pending.connect().await.map_err(runtime_error)?;
            let replacement = create_pipe(&self.name, &self.security, false)?;
            let connected = std::mem::replace(&mut self.pending, replacement);
            if self.security.client_is_current_user(&connected)? {
                return Ok(connected);
            }
            connected.disconnect().map_err(runtime_error)?;
        }
    }
}

#[cfg(windows)]
fn create_pipe(
    name: &str,
    security: &windows_security::PipeSecurity,
    first: bool,
) -> Result<ServerStream, SdkError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .in_buffer_size(crate::ipc::MAX_FRAME_BYTES as u32)
        .out_buffer_size(crate::ipc::MAX_FRAME_BYTES as u32);
    // The security descriptor remains owned by `security` for the duration of
    // CreateNamedPipeW; Windows copies it into the new kernel object.
    unsafe {
        options
            .create_with_security_attributes_raw(name, security.attributes())
            .map_err(runtime_error)
    }
}

#[cfg(unix)]
fn prepare_server(path: &Path) -> Result<(), SdkError> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(runtime_error)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(runtime_error)?;
        }
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(runtime_error(error)),
    };
    if !metadata.file_type().is_socket() {
        return Err(SdkError::Runtime(format!(
            "refusing to replace non-socket IPC path: {}",
            path.display()
        )));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(SdkError::Runtime(format!(
            "IPC socket is already active: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path).map_err(runtime_error)
        }
        Err(error) => Err(runtime_error(error)),
    }
}

#[cfg(windows)]
fn prepare_server(_path: &Path) -> Result<(), SdkError> {
    Ok(())
}

#[cfg(unix)]
fn cleanup(path: &Path) -> Result<(), SdkError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(runtime_error(error)),
    }
}

#[cfg(windows)]
fn cleanup(_path: &Path) -> Result<(), SdkError> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn pipe_name(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut hash = 0xcbf29ce484222325u64;
    for unit in path.as_os_str().encode_wide().map(|unit| {
        if unit == u16::from(b'/') {
            u16::from(b'\\')
        } else {
            unit
        }
    }) {
        for byte in unit.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    let label = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    format!(r"\\.\pipe\gc-sdk-{label}-{hash:016x}")
}

fn runtime_error(error: std::io::Error) -> SdkError {
    SdkError::Runtime(error.to_string())
}

#[cfg(windows)]
mod windows_security {
    use super::runtime_error;
    use crate::SdkError;
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, RevertToSelf, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    pub(super) struct PipeSecurity {
        descriptor: *mut c_void,
        attributes: SECURITY_ATTRIBUTES,
        process_sid: Vec<u8>,
    }

    // SECURITY_ATTRIBUTES only points into this value's descriptor and is
    // consumed synchronously while creating a pipe instance.
    unsafe impl Send for PipeSecurity {}

    impl PipeSecurity {
        pub(super) fn current_user() -> Result<Self, SdkError> {
            let process_token = open_process_token()?;
            let process_sid = token_user(process_token);
            unsafe { CloseHandle(process_token) };
            let process_sid = process_sid?;
            let sid = sid_string(process_sid.as_ptr().cast_mut().cast())?;
            let sddl = format!("O:{sid}D:P(A;;GA;;;{sid})");
            let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(runtime_error(std::io::Error::last_os_error()));
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            Ok(Self {
                descriptor,
                attributes,
                process_sid,
            })
        }

        pub(super) fn attributes(&self) -> *mut c_void {
            (&self.attributes as *const SECURITY_ATTRIBUTES)
                .cast_mut()
                .cast()
        }

        pub(super) fn client_is_current_user(
            &self,
            pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
        ) -> Result<bool, SdkError> {
            let handle = pipe.as_raw_handle() as HANDLE;
            if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
                return Err(runtime_error(std::io::Error::last_os_error()));
            }
            let mut token = null_mut();
            let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
            let open_error = std::io::Error::last_os_error();
            if unsafe { RevertToSelf() } == 0 {
                let revert_error = std::io::Error::last_os_error();
                if opened != 0 {
                    unsafe { CloseHandle(token) };
                }
                return Err(runtime_error(revert_error));
            }
            if opened == 0 {
                return Err(runtime_error(open_error));
            }
            let client_sid = token_user(token);
            unsafe { CloseHandle(token) };
            let client_sid = client_sid?;
            Ok(unsafe {
                EqualSid(
                    self.process_sid.as_ptr().cast_mut().cast(),
                    client_sid.as_ptr().cast_mut().cast(),
                ) != 0
            })
        }

        #[cfg(test)]
        pub(super) fn is_current_user_only(&self) -> bool {
            use windows_sys::Win32::Security::{
                AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
                ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION,
            };
            use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = null_mut();
            if unsafe {
                GetSecurityDescriptorDacl(self.descriptor, &mut present, &mut dacl, &mut defaulted)
            } == 0
                || present == 0
                || dacl.is_null()
            {
                return false;
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
                || information.AceCount != 1
            {
                return false;
            }
            let mut ace = null_mut();
            if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
                return false;
            }
            let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
            allowed.Header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8
                && allowed.Mask == windows_sys::Win32::Foundation::GENERIC_ALL
                && unsafe {
                    EqualSid(
                        (&allowed.SidStart as *const u32).cast_mut().cast(),
                        self.process_sid.as_ptr().cast_mut().cast(),
                    ) != 0
                }
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            unsafe { LocalFree(self.descriptor) };
        }
    }

    fn open_process_token() -> Result<HANDLE, SdkError> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(runtime_error(std::io::Error::last_os_error()));
        }
        Ok(token)
    }

    fn token_user(token: HANDLE) -> Result<Vec<u8>, SdkError> {
        let mut length = 0;
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length) };
        if length == 0 {
            return Err(runtime_error(std::io::Error::last_os_error()));
        }
        let mut bytes = vec![0u8; length as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                bytes.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(runtime_error(std::io::Error::last_os_error()));
        }
        let user = unsafe { &*(bytes.as_ptr().cast::<TOKEN_USER>()) };
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(user.User.Sid) };
        let mut sid = vec![0u8; sid_length as usize];
        if unsafe {
            windows_sys::Win32::Security::CopySid(
                sid_length,
                sid.as_mut_ptr().cast(),
                user.User.Sid,
            )
        } == 0
        {
            return Err(runtime_error(std::io::Error::last_os_error()));
        }
        Ok(sid)
    }

    fn sid_string(sid: *mut c_void) -> Result<String, SdkError> {
        let mut string = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut string) } == 0 {
            return Err(runtime_error(std::io::Error::last_os_error()));
        }
        let mut length = 0;
        while unsafe { *string.add(length) } != 0 {
            length += 1;
        }
        let result = String::from_utf16(unsafe { std::slice::from_raw_parts(string, length) })
            .map_err(|error| SdkError::Runtime(error.to_string()));
        unsafe { LocalFree(string.cast()) };
        result
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn pipe_names_are_stable_distinct_and_sanitized() {
        let first = pipe_name(Path::new(r"C:\Users\alice\gc daemon.sock"));
        assert_eq!(
            first,
            pipe_name(Path::new(r"C:\Users\alice\gc daemon.sock"))
        );
        assert_ne!(
            first,
            pipe_name(Path::new(r"D:\Users\alice\gc daemon.sock"))
        );
        assert!(first.starts_with(r"\\.\pipe\gc-sdk-gc_daemon.sock-"));
        assert_eq!(
            first,
            pipe_name(Path::new(r"C:/Users/alice/gc daemon.sock")),
            "Windows-equivalent path separators must map to the same pipe"
        );
        assert!(first.len() < 256);
    }

    #[test]
    fn current_user_security_descriptor_can_be_built() {
        let security = windows_security::PipeSecurity::current_user().unwrap();
        assert!(!security.attributes().is_null());
        assert!(security.is_current_user_only());
    }
}
