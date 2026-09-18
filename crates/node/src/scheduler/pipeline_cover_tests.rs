use super::*;
use bytes::Bytes;
use gcoms_transport::tls::TlsIdentity;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn saturated_payload_budget_keeps_cover_and_bounds_each_cover_lane() {
    let identity = TlsIdentity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let cap = [4; 32];
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let pin = target.relay_service_id;
    let (arrivals, mut arrived) = mpsc::channel(8);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        while let Some(Ok((request, mut reply))) = connection.accept().await {
            let arrivals = arrivals.clone();
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut wire = Vec::new();
                while let Some(Ok(bytes)) = body.data().await {
                    body.flow_control().release_capacity(bytes.len()).unwrap();
                    wire.extend_from_slice(&bytes);
                }
                let cell = gcoms_core::decode(&wire).unwrap();
                let push = RelayPush::decode_from_cell(&cell, &cap, &pin, now_unix()).unwrap();
                assert!(push.msg.is_none());
                let send: h2::SendStream<Bytes> =
                    reply.send_response(http::Response::new(()), false).unwrap();
                arrivals.send((push.queue_id, send)).await.unwrap();
            });
        }
    });
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        SchedulerProfile::compressed_production(42).with_pipelining(),
    );
    scheduler.enable_diagnostics();
    let payload = scheduler
        .inner
        .budget
        .reserve(MAX_QUEUED_BYTES - MAX_LANES * 16384, None)
        .unwrap();
    assert!(matches!(
        scheduler.inner.budget.reserve(1, None),
        Err(EnqueueError::Full)
    ));
    for marker in 1..=2 {
        scheduler
            .open_lane(
                LaneAuth::Push {
                    contact: AliasContact {
                        target: target.clone(),
                        queue_id: [marker; 32],
                        epoch: 1,
                        push_cap: cap,
                        expiry: now_unix() + 3600,
                    },
                },
                true,
            )
            .unwrap();
    }
    let mut held = Vec::new();
    let mut queues = std::collections::HashSet::new();
    for _ in 0..2 {
        let (queue, send) = tokio::time::timeout(Duration::from_secs(5), arrived.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(queues.insert(queue));
        held.push(send);
    }
    // Observe multiple actual schedule ticks, rather than assuming the runtime
    // got CPU time during a short sleep. Pending cover responses retain credit.
    tokio::time::timeout(Duration::from_secs(5), async {
        while scheduler.diagnostics_snapshot().data_ticks < 40 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(arrived.try_recv().is_err());
    assert_eq!(scheduler.diagnostics_snapshot().cover_attempts, 2);
    assert_eq!(scheduler.resource_snapshot().jobs, 3);
    assert!(scheduler.resource_snapshot().peak_bytes <= MAX_QUEUED_BYTES);
    drop(payload);
    scheduler.shutdown();
    tokio::time::timeout(Duration::from_secs(5), async {
        while scheduler.resource_snapshot().jobs != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(scheduler.resource_snapshot().bytes, 0);
    drop(held);
    server.abort();
}
