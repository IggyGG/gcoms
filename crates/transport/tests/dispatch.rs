use bytes::Bytes;
use gcoms_core::{Cell, CellType};
use gcoms_transport::{
    server::{AcceptedDuplex, Dispatch, ServerLimits, Tp1Server},
    tls::TlsIdentity,
    TokenRegistry, Tp1Client,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};

async fn retained_post(
    sender: &h2::client::SendRequest<Bytes>,
    address: std::net::SocketAddr,
    path: &str,
    cell: Bytes,
) -> (http::StatusCode, Bytes) {
    let mut sender = sender.clone().ready().await.unwrap();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{address}/{path}"))
        .body(())
        .unwrap();
    let (response, mut send) = sender.send_request(request, false).unwrap();
    send.send_data(cell, true).unwrap();
    let response = response.await.unwrap();
    let status = response.status();
    let body = gcoms_transport::server::read_body(&mut response.into_body(), 16 * 1024)
        .await
        .unwrap();
    (status, body)
}

fn echo() -> AcceptedDuplex {
    Box::new(|mut body, mut respond| {
        Box::pin(async move {
            let bytes = gcoms_transport::server::read_body(&mut body, 16 * 1024)
                .await
                .unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(bytes, true).unwrap();
        })
    })
}

#[tokio::test]
async fn rejection_precedes_all_handlers_and_does_not_promote_source_admission() {
    let identity = TlsIdentity::generate().unwrap();
    let registry = TokenRegistry::new();
    registry.insert_post("registered-denied");
    registry.insert_post("registered-pass");
    let registered_calls = Arc::new(AtomicUsize::new(0));
    let observed = registered_calls.clone();
    let duplex_calls = Arc::new(AtomicUsize::new(0));
    let observed_duplex = duplex_calls.clone();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Arc::new(move |_, cell| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(Some(cell))
        }),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap()
    .with_limits(ServerLimits {
        max_connections: 2,
        max_connections_per_ip: 1,
    })
    .with_duplex(Arc::new(move |path| {
        observed_duplex.fetch_add(1, Ordering::SeqCst);
        matches!(path, "legacy-denied" | "legacy-pass").then(echo)
    }))
    .with_dispatch_factory(Arc::new(|| {
        Arc::new(|path, registered| match path {
            "registered-pass" => {
                assert!(registered);
                Dispatch::Pass
            }
            "legacy-pass" => {
                assert!(!registered);
                Dispatch::Pass
            }
            "dispatch-authenticated" => Dispatch::Accepted(echo()),
            _ => Dispatch::Rejected,
        })
    }));
    let address = server.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    // Retain a raw connection across decoy responses: the client pool now
    // retires 404 connections, but server authentication must remain independent.
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        gcoms_transport::tls::client_config_pinned(identity.service_id()).unwrap(),
    ))
    .connect(gcoms_transport::tls::server_name_ip(address.ip()), tcp)
    .await
    .unwrap();
    let (first, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let cell = Bytes::from(
        Cell::new(CellType::Msg, 0, 0, vec![7; 128])
            .encode_wire()
            .unwrap(),
    );
    for path in ["registered-denied", "legacy-denied", "unknown"] {
        assert_eq!(
            retained_post(&first, address, path, cell.clone()).await.0,
            http::StatusCode::NOT_FOUND
        );
    }
    assert_eq!(registered_calls.load(Ordering::SeqCst), 0);
    assert_eq!(duplex_calls.load(Ordering::SeqCst), 0);
    // The rejected connection still occupies the one unauthenticated source
    // slot, even though one of its paths exists in the private registry.
    let refused = Tp1Client::new().unwrap();
    assert!(timeout(
        Duration::from_secs(2),
        refused.get_pinned(address, identity.service_id(), "/")
    )
    .await
    .unwrap()
    .is_err());
    assert_eq!(
        retained_post(&first, address, "dispatch-authenticated", cell.clone()).await,
        (http::StatusCode::OK, cell.clone())
    );
    let admitted = Tp1Client::new().unwrap();
    assert!(admitted
        .get_pinned(address, identity.service_id(), "/")
        .await
        .is_ok());
    for path in ["registered-pass", "legacy-pass"] {
        assert_eq!(
            retained_post(&first, address, path, cell.clone()).await,
            (http::StatusCode::OK, cell.clone())
        );
    }
    assert_eq!(registered_calls.load(Ordering::SeqCst), 1);
    assert_eq!(duplex_calls.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.await.unwrap();
}
