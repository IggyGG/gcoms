use gcoms_transport::duplex::{H2Stream, MAX_WRITE_CHUNK};
use std::{pin::Pin, task::Poll, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

type Drivers = (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>);

async fn pair(window: u32) -> (H2Stream, H2Stream, Drivers) {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let (accepted, receive) = tokio::sync::oneshot::channel();
    let server_driver = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(window)
            .handshake(server_io)
            .await
            .unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        let send = response
            .send_response(http::Response::new(()), false)
            .unwrap();
        accepted
            .send(H2Stream::new(request.into_body(), send))
            .ok()
            .unwrap();
        while connection.accept().await.is_some() {}
    });
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(window)
        .handshake(client_io)
        .await
        .unwrap();
    let client_driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    std::future::poll_fn(|cx| sender.poll_ready(cx))
        .await
        .unwrap();
    let (response, send) = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("https://fixture/duplex")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    let receive_body = response.await.unwrap().into_body();
    (
        H2Stream::new(receive_body, send),
        receive.await.unwrap(),
        (client_driver, server_driver),
    )
}

async fn stop((client, server): Drivers) {
    client.abort();
    server.abort();
    let _ = client.await;
    let _ = server.await;
}

#[tokio::test]
async fn unread_data_holds_credit_and_half_close_keeps_the_reply_direction_open() {
    let (mut client, mut server, drivers) = pair(64).await;
    let payload = (0..513).map(|i| i as u8).collect::<Vec<_>>();
    let sent = client.write(&payload).await.unwrap();
    assert_eq!(sent, 64);
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut client)
            .poll_write(cx, &payload[sent..])
            .is_pending());
        Poll::Ready(())
    })
    .await;

    let mut received = vec![0; 32];
    server.read_exact(&mut received).await.unwrap();
    let extra = tokio::time::timeout(Duration::from_secs(2), client.write(&payload[sent..]))
        .await
        .unwrap()
        .unwrap();
    assert!(
        (1..=32).contains(&extra),
        "only consumed bytes return credit"
    );

    let exchange = async {
        let send = async {
            client.write_all(&payload[sent + extra..]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply after request EOF");
        };
        let receive = async {
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            server.write_all(b"reply after request EOF").await.unwrap();
            server.shutdown().await.unwrap();
        };
        tokio::join!(send, receive);
    };
    tokio::time::timeout(Duration::from_secs(2), exchange)
        .await
        .unwrap();
    stop(drivers).await;
}

#[tokio::test]
async fn writes_are_bounded_and_dropping_a_stream_cancels_its_peer() {
    let (mut client, mut server, drivers) = pair(65535).await;
    let count = client.write(&vec![9; MAX_WRITE_CHUNK * 2]).await.unwrap();
    assert_eq!(count, MAX_WRITE_CHUNK);
    let mut received = vec![0; count];
    server.read_exact(&mut received).await.unwrap();
    assert!(received.iter().all(|byte| *byte == 9));
    drop(client);
    let result = tokio::time::timeout(Duration::from_secs(2), server.read_u8())
        .await
        .unwrap();
    assert!(
        result.is_err(),
        "drop must reset the unfinished logical stream"
    );
    stop(drivers).await;
}

#[tokio::test]
async fn reset_is_observable_without_consuming_application_bytes() {
    let (mut client, mut server, drivers) = pair(65535).await;
    client.write_all(b"queued application bytes").await.unwrap();
    std::future::poll_fn(|cx| {
        assert!(server.poll_reset(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let mut bytes = [0; 24];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"queued application bytes");
    drop(client);
    let reason = tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| server.poll_reset(cx)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reason, h2::Reason::CANCEL);
    stop(drivers).await;
}
