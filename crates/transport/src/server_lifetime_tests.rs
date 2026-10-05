//! Expired private paths must not hold every unauthenticated source slot forever.
use super::*;
use crate::{tls::TlsIdentity, HopOutcome, Tp1Client};
use std::sync::atomic::AtomicUsize;
use tokio::time::{advance, pause, resume, timeout};

struct RetainedConnection {
    sender: h2::client::SendRequest<Bytes>,
    driver: tokio::task::JoinHandle<()>,
}

impl RetainedConnection {
    async fn connect(address: SocketAddr, service: [u8; 32]) -> Self {
        let tcp = TcpStream::connect(address).await.unwrap();
        let tls =
            tokio_rustls::TlsConnector::from(Arc::new(tls::client_config_pinned(service).unwrap()))
                .connect(tls::server_name_ip(address.ip()), tcp)
                .await
                .unwrap();
        let (sender, connection) = h2::client::handshake(tls).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self { sender, driver }
    }

    async fn unknown(&self, address: SocketAddr, wire: Bytes) {
        let mut sender = self.sender.clone().ready().await.unwrap();
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("https://{address}/erased-queue-path"))
            .body(())
            .unwrap();
        let (response, mut send) = sender.send_request(request, false).unwrap();
        send.send_data(wire, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        read_body(&mut response.into_body(), MAX_BODY)
            .await
            .unwrap();
    }
}

impl Drop for RetainedConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[tokio::test]
async fn active_unknown_paths_expire_without_extending_source_admission() {
    let identity = TlsIdentity::generate().unwrap();
    let registry = TokenRegistry::new();
    registry.insert_post("fresh-private-path");
    let opened = Arc::new(AtomicUsize::new(0));
    let observed = opened.clone();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Arc::new(|_, cell| Ok(Some(cell))),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap()
    .with_dispatch_factory(Arc::new(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        Arc::new(|_, _| Dispatch::Pass)
    }));
    let address = server.local_addr().unwrap();
    let service = identity.service_id();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let wire = Bytes::from(
        Cell::new(CellType::Msg, 0, 0, vec![7; 128])
            .encode_wire()
            .unwrap(),
    );
    let authenticated = Tp1Client::new().unwrap();
    assert!(matches!(
        authenticated
            .post_cell_pinned(address, service, "fresh-private-path", wire.clone())
            .await
            .unwrap(),
        HopOutcome::Accepted(Some(_))
    ));
    let mut stale = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_IP {
        // Deliberately retain a legacy client's connection after 404. Current
        // client-side pool retirement must not hide the server admission bug.
        let client = RetainedConnection::connect(address, service).await;
        client.unknown(address, wire.clone()).await;
        stale.push(client);
    }
    assert_eq!(opened.load(Ordering::SeqCst), 1 + MAX_CONNECTIONS_PER_IP);
    let recovery = Tp1Client::new().unwrap();
    assert!(
        timeout(
            std::time::Duration::from_secs(5),
            recovery.post_cell_pinned(address, service, "fresh-private-path", wire.clone())
        )
        .await
        .unwrap()
        .is_err(),
        "eight unknown paths retain the original source cap"
    );

    // Establish real TLS/HTTP2 first. Advance only the server's existing
    // two-minute lifetime, keeping every connection active within its idle
    // timeout. A runnable task prevents virtual time auto-advancing during I/O.
    pause();
    let clock_guard = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    for _ in 0..5 {
        advance(IDLE_TIMEOUT / 6).await;
        for client in &stale {
            client.unknown(address, wire.clone()).await;
        }
        assert!(matches!(
            authenticated
                .post_cell_pinned(address, service, "fresh-private-path", wire.clone())
                .await
                .unwrap(),
            HopOutcome::Accepted(Some(_))
        ));
    }
    advance(IDLE_TIMEOUT / 6 + std::time::Duration::from_secs(1)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    resume();
    clock_guard.abort();
    let _ = clock_guard.await;
    assert!(matches!(
        authenticated
            .post_cell_pinned(address, service, "fresh-private-path", wire.clone())
            .await
            .unwrap(),
        HopOutcome::Accepted(Some(_))
    ));
    assert_eq!(
        opened.load(Ordering::SeqCst),
        1 + MAX_CONNECTIONS_PER_IP,
        "authenticated connection survives on its original HTTP2 session"
    );
    let restored = timeout(
        std::time::Duration::from_secs(5),
        recovery.post_cell_pinned(address, service, "fresh-private-path", wire),
    )
    .await
    .expect("fresh recovery admission must remain bounded")
    .expect("active unknown paths must release source slots at their original deadline");
    assert!(matches!(restored, HopOutcome::Accepted(Some(_))));
    assert_eq!(opened.load(Ordering::SeqCst), 2 + MAX_CONNECTIONS_PER_IP);
    stop.send(()).unwrap();
    timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
