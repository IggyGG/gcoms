//! Constructor ownership until the transport is transferred to NodeHandle.
use super::{api::TransportTask, Tp1Server};

pub(super) struct StartupTransport {
    transport: Option<TransportTask>,
}

impl StartupTransport {
    pub(super) fn spawn(server: Tp1Server) -> Self {
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let _ = server
                .run_until(async {
                    while !*stopped.borrow_and_update() {
                        if stopped.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
        });
        Self {
            transport: Some(TransportTask { stop, task }),
        }
    }

    pub(super) async fn stop(&mut self) {
        if let Some(transport) = self.transport.as_mut() {
            let _ = transport.stop.send(true);
            // Keep the guard armed if the constructor is cancelled during drain.
            let _ = (&mut transport.task).await;
        }
        self.transport.take();
    }

    pub(super) fn take(&mut self) -> TransportTask {
        self.transport.take().expect("constructor owns transport")
    }
}

impl Drop for StartupTransport {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            let _ = transport.stop.send(true);
            // Cancellation cannot await. Aborting drops the server's owned
            // connection/request JoinSets when Tokio next polls cancellation.
            // Explicit initialization errors instead await stop() above.
            transport.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{
        self, CellHandler, NodeConfig, NodeInfo, NodeProfile, StreamHandler, TlsIdentity,
    };
    use gcoms_transport::TokenRegistry;
    use std::{net::SocketAddr, sync::Arc, time::Duration};
    use tokio::io::AsyncReadExt;

    fn config() -> NodeConfig {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = reservation.local_addr().unwrap();
        NodeConfig {
            seed: [91; 32],
            listen,
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        }
    }

    fn assert_released(address: SocketAddr) {
        let _listener = std::net::TcpListener::bind(address)
            .expect("constructor must release listener before returning its error");
    }

    #[tokio::test]
    async fn early_missing_provision_releases_listener_before_return() {
        let mut cfg = config();
        let address = cfg.listen;
        cfg.inbox_relay = Some(NodeInfo {
            identity_pk: vec![],
            bundle: vec![],
            aliases: vec![],
            provisioning: None,
        });
        let error = node::start(cfg)
            .await
            .err()
            .expect("missing provision must fail");
        assert_eq!(error, "relay card has no private provisioning fields");
        assert_released(address);
    }

    #[tokio::test]
    async fn early_missing_aliases_releases_listener_before_return() {
        let mut cfg = config();
        let address = cfg.listen;
        cfg.inbox_relay = Some(NodeInfo {
            identity_pk: vec![],
            bundle: vec![],
            aliases: vec![],
            provisioning: Some(node::RelayProvision {
                aliases: vec![],
                frwd_path: String::new(),
                hop_key: [0; 32],
            }),
        });
        let error = node::start(cfg)
            .await
            .err()
            .expect("missing aliases must fail");
        assert_eq!(
            error,
            "relay provisioning requires normal and control aliases"
        );
        assert_released(address);
    }

    #[cfg(feature = "client-persist")]
    #[tokio::test]
    async fn late_persistence_error_releases_listener_and_state_before_return() {
        let cfg = config();
        let address = cfg.listen;
        let owned = Arc::new(());
        let weak = Arc::downgrade(&owned);
        let sink = Arc::new(move |_| {
            let _keep = &owned;
            Err("constructor persistence failure".to_string())
        });
        let error = node::start_persistent(cfg, sink)
            .await
            .err()
            .expect("sink must fail");
        assert_eq!(error, "constructor persistence failure");
        assert!(weak.upgrade().is_none(), "failed state retained its sink");
        assert_released(address);
    }

    async fn callback_owner() -> (StartupTransport, SocketAddr, std::sync::Weak<()>) {
        let owned = Arc::new(());
        let weak = Arc::downgrade(&owned);
        let cells: CellHandler = Arc::new(move |_, _| {
            let _keep = &owned;
            Ok(None)
        });
        let streams: StreamHandler = Arc::new(|_| None);
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            TokenRegistry::new(),
            cells,
            streams,
            &TlsIdentity::generate().unwrap(),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        (StartupTransport::spawn(server), address, weak)
    }

    #[tokio::test]
    async fn explicit_stop_drains_callback_owner_and_partial_handshake() {
        let (mut owner, address, weak) = callback_owner().await;
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::timeout(Duration::from_secs(5), owner.stop())
            .await
            .unwrap();
        assert!(
            weak.upgrade().is_none(),
            "server callback owner survived drain"
        );
        assert_released(address);
        let mut byte = [0];
        let end = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(end, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn cancellation_requests_cleanup_on_live_runtime() {
        let (owner, address, weak) = callback_owner().await;
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::task::yield_now().await;
        drop(owner);
        // Drop requests cancellation; unlike explicit errors it cannot await it.
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_released(address);
        let mut byte = [0];
        let end = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(end, Ok(0) | Err(_)));
    }
}
