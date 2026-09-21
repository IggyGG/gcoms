use bytes::Bytes;
use gcoms_core::{Cell, CellType};
use gcoms_transport::server::{
    CellHandler, QueueCellHandler, QueueReject, StreamHandler, Tp1Server,
};
use gcoms_transport::tls::TlsIdentity;
use gcoms_transport::{generate_token, HopOutcome, TokenRegistry, Tp1Client};
use http::{Method, Request, Response, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn echo_handler() -> CellHandler {
    Arc::new(|_t: &str, cell: Cell| Ok(Some(cell)))
}

fn no_streams() -> StreamHandler {
    Arc::new(|_body: &[u8]| None)
}

fn sample_cell() -> Vec<u8> {
    Cell::new(CellType::Msg, 0, 7, (0..100u16).map(|i| i as u8).collect())
        .encode_wire()
        .unwrap()
}

fn relay_cell(cell_type: CellType, payload: Vec<u8>) -> Vec<u8> {
    Cell::new(cell_type, 0, 0, payload).encode_wire().unwrap()
}

type Endpoint = (std::net::SocketAddr, [u8; 32]);

async fn spawn_queue_server(
    registry: TokenRegistry,
    on_queue_cell: QueueCellHandler,
    on_stream: StreamHandler,
) -> Endpoint {
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity_and_queue(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        echo_handler(),
        on_stream,
        on_queue_cell,
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    (addr, identity.service_id())
}

async fn spawn_server(
    registry: TokenRegistry,
    handler: CellHandler,
    on_stream: StreamHandler,
) -> Endpoint {
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        handler,
        on_stream,
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    (addr, identity.service_id())
}

async fn spawn_post_server(handler: CellHandler) -> Endpoint {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    spawn_server(registry, handler, no_streams()).await
}

async fn post(client: &Tp1Client, endpoint: Endpoint, token: &str, body: Vec<u8>) -> HopOutcome {
    client
        .post_cell_pinned(endpoint.0, endpoint.1, token, Bytes::from(body))
        .await
        .unwrap()
}

#[tokio::test]
async fn stalled_handshake_does_not_block_an_unrelated_destination() {
    let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    let client = Arc::new(Tp1Client::new().unwrap());
    let stalled_client = client.clone();
    let stalled = tokio::spawn(async move {
        stalled_client
            .get_pinned(blackhole_addr, [0; 32], "/")
            .await
    });
    let (_held_connection, _) = blackhole.accept().await.unwrap();

    let (responsive_addr, responsive_id) = spawn_post_server(echo_handler()).await;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.get_pinned(responsive_addr, responsive_id, "/"),
    )
    .await
    .expect("an unrelated request is not blocked by the stalled handshake")
    .unwrap();
    assert_eq!(response.0, StatusCode::OK);
    stalled.abort();
}

#[tokio::test(start_paused = true)]
async fn finite_request_deadline_includes_response_body() {
    let identity = TlsIdentity::generate().unwrap();
    let service_id = identity.service_id();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tls.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let _unfinished_body = respond.send_response(response, false).unwrap();
        while connection.accept().await.is_some() {}
    });

    let client = Tp1Client::new().unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(61),
        client.get_pinned(addr, service_id, "/"),
    )
    .await
    .expect("the client's own deadline fires before the test guard")
    .unwrap_err();
    assert_eq!(result.to_string(), "transport request timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn stream_body_lifetime_is_not_a_finite_request_deadline() {
    let registry = TokenRegistry::new();
    let stream_token = generate_token();
    registry.insert_stream(&stream_token);
    let identity = TlsIdentity::generate().unwrap();
    let service_id = identity.service_id();
    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel();
    let on_stream: StreamHandler = Arc::new(move |_| {
        let sink_tx = sink_tx.clone();
        Some(Box::new(move |sink| {
            sink_tx.send(sink).unwrap();
        }))
    });
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        echo_handler(),
        on_stream,
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    let expected = Cell::new(CellType::Msg, 0, 9, vec![4; 100]);

    let client = Tp1Client::new().unwrap();
    let mut stream = client
        .open_stream_body_pinned(addr, service_id, &stream_token, None)
        .await
        .unwrap();
    let sink = sink_rx.recv().await.unwrap();
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    tokio::time::resume();
    let delayed = expected.clone();
    let delivery = tokio::spawn(async move { sink.send(delayed).await });
    let received = tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv())
        .await
        .expect("stream reads remain live beyond the finite request deadline")
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
    assert!(delivery.await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn server_drops_a_silent_peer_after_the_handshake_deadline() {
    let (addr, _) = spawn_server(TokenRegistry::new(), echo_handler(), no_streams()).await;
    let mut silent_peer = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::task::yield_now().await;

    let mut byte = [0];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        silent_peer.read(&mut byte),
    )
    .await
    .expect("the server's own handshake deadline fires before the test guard")
    .unwrap();
    assert_eq!(read, 0);
}

// Real sockets must deliver the queued headers before the server starts its
// body timer. A paused runtime can advance the guard ahead of that OS I/O.
#[tokio::test]
async fn server_deadline_bounds_an_unfinished_request_body() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        echo_handler(),
        no_streams(),
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(
        gcoms_transport::tls::client_config_pinned(identity.service_id()).unwrap(),
    ))
    .connect(gcoms_transport::tls::server_name_ip(addr.ip()), tcp)
    .await
    .unwrap();
    let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender = sender.ready().await.unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/{token}"))
        .body(())
        .unwrap();
    let (response, _unfinished_body) = sender.send_request(request, false).unwrap();

    let response = tokio::time::timeout(std::time::Duration::from_secs(31), response)
        .await
        .expect("the server's body deadline fires before the test guard");
    if let Ok(response) = response {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn decoy_get_root() {
    let (addr, id) = spawn_post_server(echo_handler()).await;
    let client = Tp1Client::new().unwrap();
    let (status, body) = client.get_pinned(addr, id, "/").await.unwrap();
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("Device"));
}

#[tokio::test]
async fn decoy_get_unknown_path() {
    let (addr, id) = spawn_post_server(echo_handler()).await;
    let client = Tp1Client::new().unwrap();
    let (status, _) = client.get_pinned(addr, id, "/nope").await.unwrap();
    assert_eq!(status, 404);
}

#[tokio::test]
async fn post_unknown_token_gets_decoy() {
    let endpoint = spawn_post_server(echo_handler()).await;
    let client = Tp1Client::new().unwrap();
    let outcome = post(
        &client,
        endpoint,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        sample_cell(),
    )
    .await;
    assert_eq!(outcome, HopOutcome::Decoy(404));
}

#[tokio::test]
async fn post_valid_token_roundtrips_cell() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let endpoint = spawn_server(registry, echo_handler(), no_streams()).await;

    let cell_buf = sample_cell();
    let sent = gcoms_core::decode(&cell_buf).unwrap();

    let client = Tp1Client::new().unwrap();
    let outcome = post(&client, endpoint, &token, cell_buf).await;
    assert_eq!(outcome, HopOutcome::Accepted(Some(sent)));
}

#[tokio::test]
async fn pinned_client_accepts_right_pin_and_rejects_wrong_pin() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let identity = TlsIdentity::generate().unwrap();
    let service_id = identity.service_id();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        echo_handler(),
        no_streams(),
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let client = Tp1Client::new().unwrap();
    let outcome = client
        .post_cell_pinned(addr, service_id, &token, Bytes::from(sample_cell()))
        .await
        .unwrap();
    assert!(outcome.is_accepted());

    let mut wrong_pin = service_id;
    wrong_pin[0] ^= 1;
    assert!(client.get_pinned(addr, wrong_pin, "/").await.is_err());
}

#[tokio::test]
async fn pooled_connection_is_not_reused_for_a_different_pin_at_same_addr() {
    let identity = TlsIdentity::generate().unwrap();
    let service_id = identity.service_id();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        TokenRegistry::new(),
        echo_handler(),
        no_streams(),
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let client = Tp1Client::new().unwrap();
    assert_eq!(
        client.get_pinned(addr, service_id, "/").await.unwrap().0,
        200
    );

    let mut wrong_pin = service_id;
    wrong_pin[31] ^= 1;
    assert!(client.get_pinned(addr, wrong_pin, "/").await.is_err());
}

#[tokio::test]
async fn server_exposes_stable_identity_service_id() {
    let identity = TlsIdentity::generate().unwrap();
    let expected = identity.service_id();
    let first = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        TokenRegistry::new(),
        echo_handler(),
        no_streams(),
        &identity,
    )
    .await
    .unwrap();
    let second = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        TokenRegistry::new(),
        echo_handler(),
        no_streams(),
        &identity,
    )
    .await
    .unwrap();

    assert_eq!(first.service_id(), expected);
    assert_eq!(second.service_id(), expected);
}

#[tokio::test]
async fn post_garbage_bucket_is_indistinguishable_from_unknown_path() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let endpoint = spawn_server(registry, echo_handler(), no_streams()).await;

    let client = Tp1Client::new().unwrap();
    let outcome = post(&client, endpoint, &token, vec![0u8; 999]).await;
    assert_eq!(outcome, HopOutcome::Decoy(404));
}

#[tokio::test]
async fn handler_none_yields_uniform_accepted_reply() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let endpoint = spawn_server(
        registry,
        Arc::new(|_t: &str, _cell: Cell| Ok(None)),
        no_streams(),
    )
    .await;

    let client = Tp1Client::new().unwrap();
    let outcome = post(&client, endpoint, &token, sample_cell()).await;
    assert_eq!(outcome, HopOutcome::Accepted(None));
}

#[tokio::test]
async fn every_authenticated_outcome_is_one_uniform_wire_cell() {
    // Drive each handler result through a raw h2 client and confirm the
    // HTTP status and the body length are identical for all of them.
    let outcomes: Vec<(&str, CellHandler)> = vec![
        ("data", echo_handler()),
        ("accepted", Arc::new(|_t: &str, _c: Cell| Ok(None))),
        (
            "conflict",
            Arc::new(|_t: &str, _c: Cell| Err(QueueReject::Conflict)),
        ),
        (
            "overloaded",
            Arc::new(|_t: &str, _c: Cell| Err(QueueReject::Overloaded)),
        ),
    ];
    let mut shapes = Vec::new();
    for (name, handler) in outcomes {
        let registry = TokenRegistry::new();
        let token = generate_token();
        registry.insert_post(&token);
        let identity = TlsIdentity::generate().unwrap();
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            registry,
            handler,
            no_streams(),
            &identity,
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = TlsConnector::from(Arc::new(
            gcoms_transport::tls::client_config_pinned(identity.service_id()).unwrap(),
        ))
        .connect(gcoms_transport::tls::server_name_ip(addr.ip()), tcp)
        .await
        .unwrap();
        let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender = sender.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{addr}/{token}"))
            .body(())
            .unwrap();
        let (response, mut body) = sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from(sample_cell()), true).unwrap();
        let response = response.await.unwrap();
        let status = response.status();
        let mut recv = response.into_body();
        let mut total = 0usize;
        let mut frames = 0usize;
        while let Some(chunk) = std::future::poll_fn(|cx| recv.poll_data(cx)).await {
            let chunk = chunk.unwrap();
            total += chunk.len();
            frames += 1;
        }
        shapes.push((name, status, total, frames));
    }
    for (name, status, total, frames) in &shapes {
        assert_eq!(*status, StatusCode::OK, "{name}");
        assert_eq!(*total, 4096, "{name}");
        assert_eq!(*frames, 1, "{name}: one DATA frame per reply");
    }
}

#[tokio::test]
async fn valid_post_token_handler_unauthorized_is_not_successful() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let endpoint = spawn_server(
        registry,
        Arc::new(|_t: &str, _cell: Cell| Err(QueueReject::Unauthorized)),
        no_streams(),
    )
    .await;

    let client = Tp1Client::new().unwrap();
    let outcome = post(&client, endpoint, &token, sample_cell()).await;
    assert_eq!(outcome, HopOutcome::Decoy(404));
}

#[tokio::test]
async fn valid_post_token_handler_overloaded_is_in_band() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let endpoint = spawn_server(
        registry,
        Arc::new(|_t: &str, _cell: Cell| Err(QueueReject::Overloaded)),
        no_streams(),
    )
    .await;

    let client = Tp1Client::new().unwrap();
    let outcome = post(&client, endpoint, &token, sample_cell()).await;
    assert_eq!(outcome, HopOutcome::Overloaded);
}

#[tokio::test]
async fn queue_token_accepts_push_and_subscribe_on_same_path() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    assert!(registry.insert_queue(&token));
    let pushes = Arc::new(AtomicUsize::new(0));
    let subscriptions = Arc::new(AtomicUsize::new(0));
    let on_queue_cell: QueueCellHandler = {
        let pushes = pushes.clone();
        let expected_token = token.clone();
        Arc::new(move |received_token, cell| {
            assert_eq!(received_token, expected_token);
            assert_eq!(cell.cell_type(), Some(CellType::RelayPush));
            pushes.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        })
    };
    let on_stream: StreamHandler = {
        let subscriptions = subscriptions.clone();
        Arc::new(move |body| {
            let cell = gcoms_core::decode(body).ok()?;
            (cell.cell_type() == Some(CellType::RelaySub)).then(|| {
                subscriptions.fetch_add(1, Ordering::SeqCst);
                Box::new(|_sink| {}) as gcoms_transport::server::AcceptedStream
            })
        })
    };
    let (addr, id) = spawn_queue_server(registry, on_queue_cell, on_stream).await;
    let client = Tp1Client::new().unwrap();

    let sub = relay_cell(CellType::RelaySub, vec![1; 32]);
    let _stream = client
        .open_stream_body_pinned(addr, id, &token, Some(&sub))
        .await
        .unwrap();
    let push = relay_cell(CellType::RelayPush, vec![2; 32]);
    let outcome = post(&client, (addr, id), &token, push).await;

    assert_eq!(outcome, HopOutcome::Accepted(None));
    assert_eq!(subscriptions.load(Ordering::SeqCst), 1);
    assert_eq!(pushes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn queue_sub_authentication_precedes_success_response() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    assert!(registry.insert_queue(&token));
    let (addr, id) =
        spawn_queue_server(registry, Arc::new(|_, _| Ok(None)), Arc::new(|_| None)).await;
    let client = Tp1Client::new().unwrap();
    let sub = relay_cell(CellType::RelaySub, vec![3; 32]);

    let error = client
        .open_stream_body_pinned(addr, id, &token, Some(&sub))
        .await
        .err()
        .expect("unauthorized queue subscription is rejected");
    assert!(error.to_string().contains("404 Not Found"));
}

#[tokio::test]
async fn unauthorized_queue_push_is_not_successful() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    assert!(registry.insert_queue(&token));
    let endpoint = spawn_queue_server(
        registry,
        Arc::new(|_, _| Err(QueueReject::Unauthorized)),
        no_streams(),
    )
    .await;
    let client = Tp1Client::new().unwrap();
    let push = relay_cell(CellType::RelayPush, vec![4; 32]);

    let outcome = post(&client, endpoint, &token, push).await;
    assert_eq!(outcome, HopOutcome::Decoy(404));
}

#[tokio::test]
async fn queue_rejects_non_relay_cell_types() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    assert!(registry.insert_queue(&token));
    let calls = Arc::new(AtomicUsize::new(0));
    let on_queue_cell: QueueCellHandler = {
        let calls = calls.clone();
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        })
    };
    let endpoint = spawn_queue_server(registry, on_queue_cell, no_streams()).await;
    let client = Tp1Client::new().unwrap();

    let outcome = post(&client, endpoint, &token, sample_cell()).await;
    assert_eq!(outcome, HopOutcome::Decoy(404));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn removed_queue_token_stops_dispatching() {
    let registry = TokenRegistry::new();
    let token = generate_token();
    assert!(registry.insert_queue(&token));
    let endpoint =
        spawn_queue_server(registry.clone(), Arc::new(|_, _| Ok(None)), no_streams()).await;
    let client = Tp1Client::new().unwrap();
    let push = relay_cell(CellType::RelayPush, vec![5; 32]);

    assert_eq!(
        post(&client, endpoint, &token, push.clone()).await,
        HopOutcome::Accepted(None)
    );
    registry.remove_queue(&token);
    assert_eq!(
        post(&client, endpoint, &token, push).await,
        HopOutcome::Decoy(404)
    );
}

#[tokio::test]
async fn stream_delivers_cells_with_uniform_frames() {
    let registry = TokenRegistry::new();
    let stream_token = generate_token();
    registry.insert_stream(&stream_token);
    let on_stream: StreamHandler = Arc::new(|_body| {
        Some(Box::new(|sink| {
            tokio::spawn(async move {
                sink.send(Cell::new(CellType::Msg, 0, 1, vec![9; 100]))
                    .await;
                sink.send(Cell::new(CellType::Msg, 0, 2, vec![7; 300]))
                    .await;
                let _ = sink
                    .send(Cell::new(CellType::Presence, 0, 3, vec![3; 5000]))
                    .await;
            });
        }))
    });
    let (addr, id) =
        spawn_server(registry, Arc::new(|_t: &str, _c: Cell| Ok(None)), on_stream).await;

    let client = Tp1Client::new().unwrap();
    let mut stream = client
        .open_stream_body_pinned(addr, id, &stream_token, None)
        .await
        .unwrap();

    let first = stream.recv().await.unwrap().unwrap();
    assert_eq!(first.cell_type(), Some(CellType::Msg));
    assert_eq!(first.payload, vec![9; 100]);
    assert_eq!(stream.last_frame_len(), 4096);

    let second = stream.recv().await.unwrap().unwrap();
    assert_eq!(second.payload, vec![7; 300]);
    assert_eq!(stream.last_frame_len(), 4096);

    let third = stream.recv().await.unwrap().unwrap();
    assert_eq!(third.cell_type(), Some(CellType::Presence));
    assert_eq!(third.payload, vec![3; 5000]);
    assert_eq!(stream.last_frame_len(), 16384);
}

#[tokio::test]
async fn stream_auth_rejection_precedes_success_response() {
    let registry = TokenRegistry::new();
    let stream_token = generate_token();
    registry.insert_stream(&stream_token);
    let identity = TlsIdentity::generate().unwrap();
    let service_id = identity.service_id();
    let on_stream: StreamHandler = Arc::new(|body| {
        (body == b"allowed")
            .then(|| Box::new(|_sink| {}) as gcoms_transport::server::AcceptedStream)
    });
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Arc::new(|_t: &str, _c: Cell| Ok(None)),
        on_stream,
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let client = Tp1Client::new().unwrap();
    let error = client
        .open_stream_body_pinned(addr, service_id, &stream_token, Some(b"denied"))
        .await
        .err()
        .expect("unauthorized stream is rejected");
    assert!(error.to_string().contains("404 Not Found"));
}

#[tokio::test]
async fn stream_sink_send_acknowledges_delivery() {
    let registry = TokenRegistry::new();
    let stream_token = generate_token();
    registry.insert_stream(&stream_token);
    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel();
    let on_stream: StreamHandler = Arc::new(move |_body| {
        let sink_tx = sink_tx.clone();
        Some(Box::new(move |sink| {
            sink_tx.send(sink).unwrap();
        }))
    });
    let (addr, id) =
        spawn_server(registry, Arc::new(|_t: &str, _c: Cell| Ok(None)), on_stream).await;

    let client = Tp1Client::new().unwrap();
    let mut stream = client
        .open_stream_body_pinned(addr, id, &stream_token, None)
        .await
        .unwrap();
    let sink = sink_rx.recv().await.unwrap();
    let cell = Cell::new(CellType::Msg, 0, 1, vec![1; 100]);
    let delivered =
        tokio::time::timeout(std::time::Duration::from_secs(5), sink.send(cell.clone()))
            .await
            .expect("send acknowledgement does not hang");
    assert!(delivered);
    assert_eq!(stream.recv().await.unwrap().unwrap(), cell);
}

#[tokio::test]
async fn stream_sink_send_returns_false_after_disconnect_without_hanging() {
    let registry = TokenRegistry::new();
    let stream_token = generate_token();
    registry.insert_stream(&stream_token);
    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel();
    let on_stream: StreamHandler = Arc::new(move |_body| {
        let sink_tx = sink_tx.clone();
        Some(Box::new(move |sink| {
            sink_tx.send(sink).unwrap();
        }))
    });
    let (addr, id) =
        spawn_server(registry, Arc::new(|_t: &str, _c: Cell| Ok(None)), on_stream).await;

    let client = Tp1Client::new().unwrap();
    let mut stream = client
        .open_stream_body_pinned(addr, id, &stream_token, None)
        .await
        .unwrap();
    let sink = sink_rx.recv().await.unwrap();
    let first = Cell::new(CellType::Msg, 0, 1, vec![1]);
    assert!(sink.send(first).await);
    stream.recv().await.unwrap().unwrap();
    drop(stream);
    drop(client);

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if !sink
                .send(Cell::new(CellType::Msg, 0, 2, vec![2; 100]))
                .await
            {
                break false;
            }
        }
    })
    .await
    .expect("disconnect acknowledgement does not hang");
    assert!(!delivered);
}

#[tokio::test]
async fn per_source_connection_cap_closes_excess_without_handshake() {
    use tokio::io::AsyncReadExt as _;
    let (addr, _) = spawn_server(TokenRegistry::new(), echo_handler(), no_streams()).await;
    let mut held = Vec::new();
    for _ in 0..gcoms_transport::server::MAX_CONNECTIONS_PER_IP {
        held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
    }
    tokio::task::yield_now().await;
    let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), excess.read(&mut byte))
        .await
        .expect("excess connection is closed promptly")
        .unwrap();
    assert_eq!(read, 0, "over-limit source is closed before any TLS byte");
    drop(held);
}

#[tokio::test]
async fn pool_keeps_busy_connections_and_evicts_idle_ones_lru() {
    let mut endpoints = Vec::new();
    for _ in 0..(gcoms_transport::client::MAX_POOLED_CONNECTIONS + 2) {
        endpoints.push(spawn_post_server(echo_handler()).await);
    }
    let client = Tp1Client::new().unwrap();
    for (addr, id) in &endpoints {
        client.warm(*addr, *id).await.unwrap();
    }
    assert!(client.pooled_connections().await <= gcoms_transport::client::MAX_POOLED_CONNECTIONS);
}

#[tokio::test]
async fn owned_server_stop_releases_live_connection_handlers_before_return() {
    use tokio::io::AsyncWriteExt;
    let retained = Arc::new(());
    let released = Arc::downgrade(&retained);
    let handler: CellHandler = Arc::new(move |_, cell| {
        let _keep_owner = &retained;
        Ok(Some(cell))
    });
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        handler,
        no_streams(),
        &identity,
    )
    .await
    .unwrap();
    let endpoint = (server.local_addr().unwrap(), identity.service_id());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let client = Tp1Client::new().unwrap();
    assert!(matches!(
        post(&client, endpoint, &token, sample_cell()).await,
        HopOutcome::Accepted(Some(_))
    ));
    let mut partial = tokio::net::TcpStream::connect(endpoint.0).await.unwrap();
    partial.write_all(&[0x16, 0x03]).await.unwrap();
    assert!(released.upgrade().is_some());
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The client/pool stays alive: success cannot depend on its Drop closing the connection.
    assert!(released.upgrade().is_none());
    let mut byte = [0];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), partial.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    drop(client);
}

#[tokio::test]
async fn finite_bulk_is_bounded_reserves_interactive_and_reuses_one_connection() {
    use gcoms_core::TrafficClass;
    use std::time::Duration;
    let identity = TlsIdentity::generate().unwrap();
    let pin = identity.service_id();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let (arrivals, mut arrived) = mpsc::channel(16);
    let server = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let arrivals = arrivals.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    let arrivals = arrivals.clone();
                    tokio::spawn(async move {
                        let name = request.uri().path().to_owned();
                        let mut body = request.into_body();
                        while let Some(Ok(bytes)) = body.data().await {
                            body.flow_control().release_capacity(bytes.len()).unwrap();
                        }
                        let send = reply.send_response(Response::new(()), false).unwrap();
                        let _ = arrivals.send((name, send)).await;
                    });
                }
            });
        }
    });
    let client = Arc::new(Tp1Client::new().unwrap());
    let mut bulk = Vec::new();
    for index in 0..8 {
        let client = client.clone();
        bulk.push(tokio::spawn(async move {
            client
                .post_cell_with_class(
                    addr,
                    pin,
                    &format!("bulk{index}"),
                    Bytes::from(sample_cell()),
                    &[],
                    TrafficClass::Bulk,
                )
                .await
        }));
    }
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(
            tokio::time::timeout(Duration::from_secs(5), arrived.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), arrived.recv())
            .await
            .is_err()
    );
    let interactive_client = client.clone();
    let interactive = tokio::spawn(async move {
        interactive_client
            .post_cell_with_class(
                addr,
                pin,
                "interactive",
                Bytes::from(sample_cell()),
                &[],
                TrafficClass::Interactive,
            )
            .await
    });
    let (name, mut reply) = tokio::time::timeout(Duration::from_secs(2), arrived.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(name, "/interactive");
    reply.send_data(Bytes::from(sample_cell()), true).unwrap();
    assert!(interactive.await.unwrap().unwrap().is_accepted());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), arrived.recv())
            .await
            .is_err()
    );
    // Cancellation releases the bulk slot, including after response headers.
    let canceled = held[0]
        .0
        .trim_start_matches("/bulk")
        .parse::<usize>()
        .unwrap();
    bulk[canceled].abort();
    let next = tokio::time::timeout(Duration::from_secs(2), arrived.recv())
        .await
        .unwrap()
        .unwrap();
    held.push(next);
    // The active finite responses must survive LRU pressure.
    for _ in 0..gcoms_transport::client::MAX_POOLED_CONNECTIONS {
        let other = spawn_post_server(echo_handler()).await;
        client.warm(other.0, other.1).await.unwrap();
    }
    client.warm(addr, pin).await.unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    for task in bulk {
        task.abort();
    }
    drop(held);
    server.abort();
}
