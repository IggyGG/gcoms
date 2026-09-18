use bytes::Bytes;
use gcoms_transport::{
    server::{AcceptedDuplex, DuplexHandler, DuplexHandlerFactory, Tp1Server},
    tls::{self, TlsIdentity},
    TokenRegistry,
};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
};
use tokio_rustls::TlsConnector;

async fn connect(
    address: std::net::SocketAddr,
    pin: [u8; 32],
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let stream = TcpStream::connect(address).await.unwrap();
    let tls = TlsConnector::from(Arc::new(tls::client_config_pinned(pin).unwrap()))
        .connect(tls::server_name_ip(address.ip()), stream)
        .await
        .unwrap();
    let (sender, driver) = h2::client::handshake(tls).await.unwrap();
    (sender, tokio::spawn(driver))
}

async fn request(
    sender: &mut h2::client::SendRequest<Bytes>,
    path: &str,
) -> (http::Response<h2::RecvStream>, h2::SendStream<Bytes>) {
    std::future::poll_fn(|cx| sender.poll_ready(cx))
        .await
        .unwrap();
    let (response, send) = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri(format!("https://localhost/{path}"))
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    (response.await.unwrap(), send)
}

#[tokio::test]
async fn duplex_paths_share_connection_budget_and_shutdown_releases_every_context() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let observed = contexts.clone();
    let factory: DuplexHandlerFactory = Arc::new(move || {
        let budget = Arc::new(Semaphore::new(1));
        observed.lock().unwrap().push(Arc::downgrade(&budget));
        Arc::new(move |path: &str| {
            // Private-path authentication still precedes budget admission.
            if !matches!(path, "fixture-interactive" | "fixture-bulk") {
                return None;
            }
            let permit = budget.clone().try_acquire_owned();
            Some(Box::new(
                move |mut body: h2::RecvStream, mut respond: h2::server::SendResponse<Bytes>| {
                    Box::pin(async move {
                        let Ok(_permit) = permit else {
                            let _ = respond.send_response(
                                http::Response::builder().status(409).body(()).unwrap(),
                                true,
                            );
                            return;
                        };
                        let Ok(mut send) = respond.send_response(http::Response::new(()), false)
                        else {
                            return;
                        };
                        // Keep the context allowance occupied until cancellation.
                        while let Some(Ok(bytes)) = body.data().await {
                            body.flow_control().release_capacity(bytes.len()).unwrap();
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    })
                        as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                },
            ) as AcceptedDuplex)
        }) as DuplexHandler
    });
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap()
    .with_duplex_factory(factory);
    let address = server.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));

    let mut probe = TcpStream::connect(address).await.unwrap();
    probe.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        probe.read_to_end(&mut Vec::new()),
    )
    .await
    .unwrap();
    assert!(
        contexts.lock().unwrap().is_empty(),
        "failed handshakes allocate no service context"
    );

    let (mut first, first_driver) = connect(address, identity.service_id()).await;
    let (held, mut held_send) = request(&mut first, "fixture-interactive").await;
    assert_eq!(held.status(), 200);
    let (overloaded, _) = request(&mut first, "fixture-bulk").await;
    assert_eq!(overloaded.status(), 409, "both paths must share one budget");
    let (unknown, _) = request(&mut first, "unknown").await;
    assert_eq!(
        unknown.status(),
        404,
        "unknown paths retain the decoy response"
    );

    let (mut second, second_driver) = connect(address, identity.service_id()).await;
    let (independent, _independent_send) = request(&mut second, "fixture-bulk").await;
    assert_eq!(
        independent.status(),
        200,
        "a different connection has its own budget"
    );
    assert_eq!(contexts.lock().unwrap().len(), 2);

    held_send.send_reset(h2::Reason::CANCEL);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if contexts.lock().unwrap()[0]
                .upgrade()
                .unwrap()
                .available_permits()
                == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (reused, _reused_send) = request(&mut first, "fixture-bulk").await;
    assert_eq!(
        reused.status(),
        200,
        "cancellation returns the shared allowance"
    );

    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(contexts
        .lock()
        .unwrap()
        .iter()
        .all(|context| context.upgrade().is_none()));
    let _ = first_driver.await;
    let _ = second_driver.await;
}
