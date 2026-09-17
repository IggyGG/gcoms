//! Shared native full-node listener selection. A selected socket is never closed
//! for a second bind. Router grants are candidates, never reachability evidence.
pub mod nat;
mod runtime;
pub(crate) use runtime::{spawn, RuntimeTask};

use gcoms_transport::server::Tp1Server;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    fs::File,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

/// Persistence is owned by the embedding profile, independently of message archives.
pub trait ListenerStateStore: Send + Sync {
    fn load_port(&self) -> Result<Option<u16>, String>;
    fn save_port(&self, port: u16) -> Result<(), String>;
}

/// Presence of this configuration opts a full native node into automatic listening.
/// `None` on RoutingConfig preserves the exact explicitly configured listener.
#[derive(Clone)]
pub struct ConnectivityConfig {
    pub previous_port: Option<u16>,
    pub state: Option<Arc<dyn ListenerStateStore>>,
    pub mapping: bool,
    pub nat: nat::NatConfig,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            previous_port: None,
            state: None,
            mapping: true,
            nat: nat::NatConfig::default(),
        }
    }
}

impl ConnectivityConfig {
    pub(crate) fn bind(&self, address: SocketAddr) -> Result<TcpListener, String> {
        let saved = match &self.state {
            Some(store) => store.load_port()?,
            None => None,
        };
        let previous = saved.or(self.previous_port);
        let listener = select_listener(address, previous, Tp1Server::bind_listener)
            .map_err(|e| format!("automatic listener: {e}"))?;
        if let Some(store) = &self.state {
            store.save_port(listener.local_addr().map_err(|e| e.to_string())?.port())?;
        }
        Ok(listener)
    }
}

fn select_listener<T>(
    address: SocketAddr,
    previous: Option<u16>,
    mut bind: impl FnMut(SocketAddr) -> io::Result<T>,
) -> io::Result<T> {
    let mut ports = Vec::with_capacity(5);
    for port in previous
        .into_iter()
        .filter(|p| *p != 0)
        .chain([443, 8443, 4433, 0])
    {
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    let mut last_error = None;
    for port in ports {
        match bind(SocketAddr::new(address.ip(), port)) {
            Ok(listener) => return Ok(listener),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::AddrNotAvailable
                ) =>
            {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no listener candidate")))
}

/// An authenticated, private port preference with an exclusive profile writer.
/// A corrupt retained preference fails without replacing it or any identity state.
pub struct PortState {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    _lock: File,
}

impl PortState {
    pub fn open(directory: &Path, identity_seed: &[u8; 32]) -> Result<Self, String> {
        crate::routing_cache::private_directory(directory).map_err(|e| e.to_string())?;
        let lock_path = directory.join("connectivity.lock");
        let lock = crate::routing_cache::options(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| e.to_string())?;
        gcoms_private_fs::make_private(&lock_path, false).map_err(|e| e.to_string())?;
        gcoms_private_fs::validate_private_file(&lock_path, "listener state lock")
            .map_err(|e| e.to_string())?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| "listener state has another writer")?;
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(None, identity_seed)
            .expand(b"ghost.native.listener-state.v1", &mut *key)
            .map_err(|_| "listener state key")?;
        Ok(Self {
            path: directory.join("connectivity.port"),
            key,
            _lock: lock,
        })
    }
}

impl ListenerStateStore for PortState {
    fn load_port(&self) -> Result<Option<u16>, String> {
        let Some(bytes) =
            crate::routing_cache::read_optional(&self.path, 40).map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        if bytes.len() != 40 || &bytes[..6] != b"GCLP\0\x01" {
            return Err("invalid listener state".into());
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&bytes[..8]);
        mac.verify_slice(&bytes[8..])
            .map_err(|_| "listener state authentication failed")?;
        let port = u16::from_be_bytes([bytes[6], bytes[7]]);
        if port == 0 {
            return Err("invalid saved listener port".into());
        }
        Ok(Some(port))
    }
    fn save_port(&self, port: u16) -> Result<(), String> {
        if port == 0 {
            return Err("cannot save an unbound listener".into());
        }
        let mut bytes = b"GCLP\0\x01".to_vec();
        bytes.extend(port.to_be_bytes());
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&bytes);
        bytes.extend(mac.finalize().into_bytes());
        crate::routing_cache::replace(&self.path, &bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn occupied_candidates_fall_through_to_a_held_os_port() {
        let mut occupied = Vec::new();
        let ip = "127.238.23.81".parse().unwrap();
        for port in [443, 8443, 4433] {
            match Tp1Server::bind_listener(SocketAddr::new(ip, port)) {
                Ok(socket) => occupied.push(socket),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
                    ) => {}
                Err(e) => panic!("fixture collision: {e}"),
            }
        }
        let selected = ConnectivityConfig::default()
            .bind(SocketAddr::new(ip, 0))
            .unwrap();
        let address = selected.local_addr().unwrap();
        assert_ne!(address.port(), 0);
        assert!(![443, 8443, 4433].contains(&address.port()));
        assert!(
            Tp1Server::bind_listener(address).is_err(),
            "selected port must remain owned"
        );
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (_, peer) = selected.accept().await.unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
    }
    #[tokio::test]
    async fn prior_os_selected_port_is_reused_and_exclusively_retained() {
        let ip = "127.238.23.82".parse().unwrap();
        let initial = Tp1Server::bind_listener(SocketAddr::new(ip, 0)).unwrap();
        let address = initial.local_addr().unwrap();
        drop(initial);
        let selected = ConnectivityConfig {
            previous_port: Some(address.port()),
            mapping: false,
            state: None,
            nat: nat::NatConfig::default(),
        }
        .bind(SocketAddr::new(ip, 0))
        .unwrap();
        assert_eq!(selected.local_addr().unwrap(), address);
        assert!(Tp1Server::bind_listener(address).is_err());
    }
    #[test]
    fn denied_privilege_skips_without_escalation_and_duplicates_are_not_retried() {
        let mut attempts = Vec::new();
        let selected = select_listener("0.0.0.0:0".parse().unwrap(), Some(443), |address| {
            attempts.push(address.port());
            if address.port() == 443 {
                Err(io::ErrorKind::PermissionDenied.into())
            } else if address.port() == 8443 {
                Err(io::ErrorKind::AddrInUse.into())
            } else {
                Ok(address)
            }
        })
        .unwrap();
        assert_eq!(attempts, [443, 8443, 4433]);
        assert_eq!(selected.port(), 4433);
    }
    #[test]
    fn resource_exhaustion_is_not_masked_by_more_bind_attempts() {
        let mut attempts = 0;
        assert!(
            select_listener("0.0.0.0:0".parse().unwrap(), None, |_| -> io::Result<()> {
                attempts += 1;
                Err(io::Error::other("descriptor limit"))
            })
            .is_err()
        );
        assert_eq!(attempts, 1);
    }
    #[test]
    fn port_state_survives_restart_and_rejects_identity_change_and_corruption() {
        let path =
            std::env::temp_dir().join(format!("gc-port-state-{:016x}", rand::random::<u64>()));
        let state = PortState::open(&path, &[9; 32]).unwrap();
        assert!(state.load_port().unwrap().is_none());
        state.save_port(19731).unwrap();
        assert!(PortState::open(&path, &[9; 32]).is_err());
        drop(state);
        let state = PortState::open(&path, &[9; 32]).unwrap();
        assert_eq!(state.load_port().unwrap(), Some(19731));
        drop(state);
        assert!(PortState::open(&path, &[8; 32])
            .unwrap()
            .load_port()
            .is_err());
        std::fs::write(path.join("connectivity.port"), b"bad").unwrap();
        assert!(PortState::open(&path, &[9; 32])
            .unwrap()
            .load_port()
            .is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[cfg(test)]
mod privilege_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "run in an isolated namespace with ip_unprivileged_port_start=1024 and no NET_BIND_SERVICE"]
    async fn real_denied_low_port_falls_back_without_privileges() {
        let denied = Tp1Server::bind_listener("0.0.0.0:443".parse().unwrap()).unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        let listener = ConnectivityConfig {
            mapping: false,
            ..Default::default()
        }
        .bind("0.0.0.0:0".parse().unwrap())
        .unwrap();
        assert_eq!(listener.local_addr().unwrap().port(), 8443);
        assert!(Tp1Server::bind_listener(listener.local_addr().unwrap()).is_err());
    }
}
