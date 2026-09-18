//! Versioned, owner-authenticated local host control. Never exposed over the network.
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};
pub const VERSION: u16 = 1;
const LIMIT: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileConfig {
    pub application: String,
    pub profile: PathBuf,
    pub listen: std::net::SocketAddr,
    pub fixture: bool,
    pub advertise: Option<std::net::SocketAddr>,
    pub relay: Option<Vec<u8>>,
    pub network: Option<Vec<u8>>,
    pub network_recovery: bool,
    pub providers: Vec<String>,
}
impl Drop for ProfileConfig {
    fn drop(&mut self) {
        if let Some(relay) = &mut self.relay {
            relay.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
pub enum Request {
    Ping,
    Open {
        config: ProfileConfig,
        token: [u8; 32],
        secret: String,
        create: bool,
    },
    Stop {
        profile: PathBuf,
        token: [u8; 32],
    },
}
impl Zeroize for Request {
    fn zeroize(&mut self) {
        match self {
            Self::Open { token, secret, .. } => {
                token.zeroize();
                secret.zeroize();
            }
            Self::Stop { token, .. } => token.zeroize(),
            Self::Ping => {}
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Reply {
    pub version: u16,
    pub result: Result<Option<Attachment>, String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub endpoint: PathBuf,
    pub safety_number: String,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u16,
    request: Request,
}
impl Zeroize for Envelope {
    fn zeroize(&mut self) {
        self.request.zeroize();
    }
}

pub async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Zeroizing<Request>, String> {
    let data = read_bytes(stream).await?;
    let (envelope, rest): (Envelope, _) =
        postcard::take_from_bytes(&data).map_err(|_| "invalid control frame")?;
    let mut envelope = Zeroizing::new(envelope);
    if !rest.is_empty() || envelope.version != VERSION {
        return Err("incompatible GComs daemon control version".into());
    }
    Ok(Zeroizing::new(std::mem::replace(
        &mut envelope.request,
        Request::Ping,
    )))
}
pub async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: &Reply,
) -> Result<(), String> {
    write_bytes(
        stream,
        &postcard::to_allocvec(reply).map_err(|e| e.to_string())?,
    )
    .await
}
pub async fn exchange(endpoint: &Path, request: Request) -> Result<Option<Attachment>, String> {
    let envelope = Zeroizing::new(Envelope {
        version: VERSION,
        request,
    });
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        gcoms_private_fs::validate_private_parent(endpoint, "GComs control")?;
        let local = gcoms_sdk::LocalEndpoint::new(endpoint);
        #[cfg(unix)]
        let mut stream = gcoms_sdk::local::connect(&local)
            .await
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let meta = std::fs::symlink_metadata(endpoint).map_err(|e| e.to_string())?;
            if !meta.file_type().is_socket()
                || meta.uid() != rustix::process::getuid().as_raw()
                || stream.peer_cred().map_err(|e| e.to_string())?.uid() != meta.uid()
            {
                return Err("GComs control owner mismatch".into());
            }
        }
        #[cfg(windows)]
        let mut stream = gcoms_sdk::local::connect(&local)
            .await
            .map_err(|e| e.to_string())?;
        let bytes = Zeroizing::new(postcard::to_allocvec(&*envelope).map_err(|e| e.to_string())?);
        write_bytes(&mut stream, &bytes).await?;
        let bytes = read_bytes(&mut stream).await?;
        let (reply, rest): (Reply, _) =
            postcard::take_from_bytes(&bytes).map_err(|_| "invalid control reply")?;
        if !rest.is_empty() || reply.version != VERSION {
            return Err("incompatible GComs daemon; update the bundled service".into());
        }
        reply.result
    })
    .await
    .map_err(|_| "GComs daemon control timed out".to_string())?;
    result
}
async fn read_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Zeroizing<Vec<u8>>, String> {
    let size = stream.read_u32().await.map_err(|e| e.to_string())? as usize;
    if size > LIMIT {
        return Err("control frame exceeds limit".into());
    }
    let mut data = Zeroizing::new(vec![0; size]);
    stream
        .read_exact(&mut data)
        .await
        .map_err(|e| e.to_string())?;
    Ok(data)
}
async fn write_bytes<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<(), String> {
    if data.len() > LIMIT {
        return Err("control frame exceeds limit".into());
    }
    stream
        .write_u32(data.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())
}
pub(crate) fn private_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => gcoms_private_fs::validate_private_dir(path, "GComs directory"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
            gcoms_private_fs::make_private(path, true)
        }
        Err(e) => Err(e.to_string()),
    }
}
/// App identity and credential are fixed when a profile is registered.
#[derive(Serialize, Deserialize)]
struct Registration {
    application: String,
    token: [u8; 32],
}
pub(crate) fn registration(profile: &Path, application: &str) -> Result<[u8; 32], String> {
    let path = sidecar(profile, "gcoms-registration");
    let parent = path.parent().ok_or("profile needs a private parent")?;
    private_directory(parent)?;
    let load = || -> Result<[u8; 32], String> {
        gcoms_private_fs::validate_private_file(&path, "application registration")?;
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 4096 {
            return Err("application registration exceeds limit".into());
        }
        let value: Registration =
            serde_json::from_slice(&bytes).map_err(|_| "invalid application registration")?;
        if value.application != application {
            return Err("profile belongs to a different application".into());
        }
        Ok(value.token)
    };
    match std::fs::symlink_metadata(&path) {
        Ok(_) => return load(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let value = Registration {
        application: application.into(),
        token: rand::random(),
    };
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    gcoms_private_fs::make_private(file.path(), false)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&value).map_err(|e| e.to_string())?);
    file.write_all(&bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    match file.persist_noclobber(&path) {
        Ok(_) => {
            #[cfg(unix)]
            std::fs::File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(value.token)
        }
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => load(),
        Err(e) => Err(e.error.to_string()),
    }
}
#[cfg(all(feature = "embedded", feature = "ipc"))]
pub(crate) fn credentials_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
}
#[cfg(feature = "ipc")]
pub(crate) fn capabilities() -> Vec<gcoms_sdk::ipc::Capability> {
    use gcoms_sdk::ipc::Capability::*;
    vec![
        IdentityRead,
        DirectMessage,
        ChannelMember,
        ChannelAdmin,
        EventRead,
        DurableApplication,
        OpaqueTransfer,
        CatalogAccess,
        ProfileAdmin,
    ]
}

pub(crate) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(feature = "ipc")]
pub(crate) fn private_lock(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => {
            gcoms_private_fs::make_private(path, false)?;
            file
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            gcoms_private_fs::validate_private_file(path, "GComs lock")?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|e| e.to_string())?
        }
        Err(e) => return Err(e.to_string()),
    };
    gcoms_private_fs::validate_private_file(path, "GComs lock")?;
    Ok(file)
}
