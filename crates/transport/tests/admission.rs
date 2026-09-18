use bytes::Bytes;
use gcoms_core::{Cell, CellType, TrafficClass};
use gcoms_transport::{tls::TlsIdentity, HopOutcome, HopReply, Tp1Client};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn preparation_waits_for_credit_and_reconnect_reuses_the_same_bytes() {
    let identity = TlsIdentity::generate().unwrap();
    let pin = identity.service_id();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let (held_tx, mut held_rx) = mpsc::channel(4);
    let (posted_tx, mut posted_rx) = mpsc::channel(2);
    let posts = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let held_tx = held_tx.clone();
            let posted_tx = posted_tx.clone();
            let posts = posts.clone();
            connections.spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    let hold = request.uri().path() == "/hold";
                    let held_tx = held_tx.clone();
                    let posted_tx = posted_tx.clone();
                    let posts = posts.clone();
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut wire = Vec::new();
                        while let Some(Ok(bytes)) = body.data().await {
                            body.flow_control().release_capacity(bytes.len()).unwrap();
                            wire.extend_from_slice(&bytes);
                        }
                        if hold {
                            let send = reply.send_response(http::Response::new(()), false).unwrap();
                            held_tx.send(send).await.unwrap();
                            return;
                        }
                        posted_tx.send(wire).await.unwrap();
                        if posts.fetch_add(1, Ordering::SeqCst) == 0 {
                            reply.send_reset(h2::Reason::REFUSED_STREAM);
                            return;
                        }
                        let mut send = reply.send_response(http::Response::new(()), false).unwrap();
                        send.send_data(
                            Bytes::from(HopReply::Accepted.cell().encode_wire().unwrap()),
                            true,
                        )
                        .unwrap();
                    });
                }
            });
        }
    });
    let client = Arc::new(Tp1Client::new().unwrap());
    let mut requests = Vec::new();
    for _ in 0..4 {
        let client = client.clone();
        requests.push(tokio::spawn(async move {
            client.get_pinned(addr, pin, "/hold").await
        }));
    }
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            tokio::time::timeout(Duration::from_secs(5), held_rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let preparations = Arc::new(AtomicUsize::new(0));
    let phase = Arc::new(AtomicUsize::new(0));
    let post = {
        let client = client.clone();
        let preparations = preparations.clone();
        let phase = phase.clone();
        tokio::spawn(async move {
            client
                .post_cell_prepared(
                    addr,
                    pin,
                    "post",
                    &[],
                    TrafficClass::Interactive,
                    move || {
                        preparations.fetch_add(1, Ordering::SeqCst);
                        Ok(Bytes::from(
                            Cell::new(
                                CellType::Msg,
                                0,
                                0,
                                vec![phase.load(Ordering::SeqCst) as u8],
                            )
                            .encode_wire()?,
                        ))
                    },
                )
                .await
        })
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(50), posted_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(preparations.load(Ordering::SeqCst), 0);
    phase.store(1, Ordering::SeqCst);
    // Cancellation of one response body returns one complete-request credit.
    let mut released = held.pop().unwrap();
    released.send_reset(h2::Reason::CANCEL);
    drop(released);
    let first = tokio::time::timeout(Duration::from_secs(5), posted_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let retry = tokio::time::timeout(Duration::from_secs(5), posted_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gcoms_core::decode(&first).unwrap().payload, [1]);
    assert_eq!(retry, first);
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), post)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        HopOutcome::Accepted(None)
    ));
    for request in requests {
        request.abort();
        let _ = request.await;
    }
    drop(held);
    server.abort();
}
