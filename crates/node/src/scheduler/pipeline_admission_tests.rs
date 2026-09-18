use super::*;
use bytes::Bytes;
use gcoms_transport::{tls::TlsIdentity, HopReply};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn hop_expiry_starts_after_transport_credit_is_available() {
    let identity = TlsIdentity::generate().unwrap();
    let pin = identity.service_id();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let (held_tx, mut held_rx) = mpsc::channel(4);
    let (post_tx, mut post_rx) = mpsc::channel(1);
    let cap = [9; 32];
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        while let Some(Ok((request, mut reply))) = connection.accept().await {
            let hold = request.uri().path() == "/hold";
            let held_tx = held_tx.clone();
            let post_tx = post_tx.clone();
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut wire = Vec::new();
                while let Some(Ok(bytes)) = body.data().await {
                    body.flow_control().release_capacity(bytes.len()).unwrap();
                    wire.extend_from_slice(&bytes);
                }
                let mut send: h2::SendStream<Bytes> =
                    reply.send_response(http::Response::new(()), false).unwrap();
                if hold {
                    held_tx.send(send).await.unwrap();
                } else {
                    let cell = gcoms_core::decode(&wire).unwrap();
                    let push = RelayPush::decode_from_cell(&cell, &cap, &pin, now_unix()).unwrap();
                    post_tx.send(push).await.unwrap();
                    send.send_data(
                        Bytes::from(HopReply::Accepted.cell().encode_wire().unwrap()),
                        true,
                    )
                    .unwrap();
                }
            });
        }
    });
    let client = Arc::new(Tp1Client::new().unwrap());
    let mut stalled = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let client = client.clone();
        stalled.spawn(async move { client.get_pinned(addr, pin, "/hold").await });
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
    let scheduler =
        RelayScheduler::with_profile(client, SchedulerProfile::fixture().with_pipelining());
    scheduler.enable_diagnostics();
    let receipt = scheduler
        .push(
            ProducerClass::Direct,
            AliasContact {
                target: RelayTarget {
                    address: addr,
                    relay_service_id: pin,
                },
                queue_id: [2; 32],
                epoch: 1,
                push_cap: cap,
                expiry: now_unix() + 3600,
            },
            Cell::new(CellType::Msg, 0, 0, vec![42]),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while scheduler.diagnostics_snapshot().dispatched == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let dispatched = now_unix();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(post_rx.try_recv().is_err());
    held.pop().unwrap().send_reset(h2::Reason::CANCEL);
    let push = tokio::time::timeout(Duration::from_secs(5), post_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        push.push_expiry > dispatched + 60,
        "authorization must not age while waiting for request credit"
    );
    assert_eq!(push.msg.unwrap().payload, [42]);
    assert!(matches!(
        receipt.completion().await,
        JobResult::HopAccepted(_)
    ));
    scheduler.shutdown();
    stalled.abort_all();
    while stalled.join_next().await.is_some() {}
    drop(held);
    server.abort();
}

#[test]
fn delayed_preparation_cannot_extend_expired_authority() {
    let contact = AliasContact {
        target: RelayTarget {
            address: "127.0.0.1:1234".parse().unwrap(),
            relay_service_id: [1; 32],
        },
        queue_id: [2; 32],
        epoch: 1,
        push_cap: [3; 32],
        expiry: now_unix().saturating_sub(1),
    };
    let data = PendingRequest::semantic(
        SemanticJob::Push {
            contact: contact.clone(),
            inner: Cell::new(CellType::Msg, 0, 0, vec![42]),
        },
        1,
        [1; 32],
    )
    .unwrap();
    let cover = PendingRequest::cover(LaneAuth::Push { contact }, 1, [2; 32]);
    assert!((data.make)().unwrap_err().contains("expired"));
    assert!((cover.make)().unwrap_err().contains("expired"));
}
