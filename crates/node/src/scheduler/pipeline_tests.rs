use super::*;
use bytes::Bytes;
use gcoms_transport::tls::TlsIdentity;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

/// Hold HTTP response bodies open to model a congested hop without blocking a
/// runtime thread or relying on a timed artificial service delay.
#[tokio::test]
async fn dispatch_continues_while_replies_wait_and_shutdown_releases_credit() {
    let identity = TlsIdentity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
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
                let send = reply.send_response(http::Response::new(()), false).unwrap();
                let _ = arrivals.send((cell.payload[0], send)).await;
            });
        }
    });
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        SchedulerProfile::fixture().with_pipelining(),
    );
    scheduler.enable_diagnostics();
    let mut receipts = Vec::new();
    for marker in 0..6 {
        receipts.push(
            scheduler
                .admin_post(
                    target.clone(),
                    "same-lane".into(),
                    Cell::new(CellType::Msg, 0, 0, vec![marker]),
                )
                .unwrap(),
        );
    }
    let duplicate = scheduler.admin_post(
        target.clone(),
        "same-lane".into(),
        Cell::new(CellType::Msg, 0, 0, vec![0]),
    );
    assert!(matches!(duplicate, Err(EnqueueError::Pending)));
    let mut held = Vec::new();
    for marker in 0..4 {
        let (actual, send) = tokio::time::timeout(Duration::from_secs(5), arrived.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual, marker);
        held.push(send);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(60), arrived.recv())
            .await
            .is_err()
    );
    assert_eq!(
        scheduler.resource_snapshot().jobs,
        6,
        "credit follows dispatched jobs"
    );
    // Completing a later request frees dispatch without waiting for the first.
    held[3]
        .send_data(
            Bytes::from(
                gcoms_transport::HopReply::Accepted
                    .cell()
                    .encode_wire()
                    .unwrap(),
            ),
            true,
        )
        .unwrap();
    let (marker, send) = tokio::time::timeout(Duration::from_secs(5), arrived.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(marker, 4);
    held.push(send);
    assert_eq!(scheduler.resource_snapshot().jobs, 5);
    scheduler.shutdown();
    let mut accepted = 0;
    for receipt in receipts {
        match tokio::time::timeout(Duration::from_secs(5), receipt.completion())
            .await
            .unwrap()
        {
            JobResult::HopAccepted(_) => accepted += 1,
            JobResult::Shutdown => {}
            _ => panic!("unexpected completion"),
        }
    }
    assert_eq!(accepted, 1);
    // The worker joins its aborted attempts; the last permit may release just
    // after its receipt sender is dropped.
    tokio::time::timeout(Duration::from_secs(5), async {
        while scheduler.resource_snapshot().jobs != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(scheduler.resource_snapshot().bytes, 0);
    assert_eq!(scheduler.diagnostics_snapshot().rejected_pending, 1);
    server.abort();
}

#[test]
fn producers_share_a_class_and_bulk_cannot_use_reserved_credit() {
    let mut queue = FairQueue::new(16);
    for marker in 1..=4 {
        let (class, mut job) = super::tests::queued(marker, ProducerClass::Direct);
        job.traffic = TrafficClass::Bulk;
        job.producer = [1; 32];
        assert!(queue.push(class, job));
    }
    let (class, mut job) = super::tests::queued(5, ProducerClass::Direct);
    job.producer = [2; 32];
    assert!(queue.push(class, job));
    assert_eq!(super::tests::marker(&queue.pop().unwrap()), 1);
    assert_eq!(super::tests::marker(&queue.pop().unwrap()), 5);
    assert!(queue.pop_eligible(false).is_none());
    assert_eq!(super::tests::marker(&queue.pop().unwrap()), 2);
}

#[test]
fn deep_bulk_backlog_cannot_starve_a_late_interactive_job() {
    let mut queue = FairQueue::new(128);
    for marker in 1..=32 {
        let (class, mut job) = super::tests::queued(marker, ProducerClass::Direct);
        job.traffic = TrafficClass::Bulk;
        job.producer = [1; 32];
        assert!(queue.push(class, job));
    }
    let (class, mut job) = super::tests::queued(99, ProducerClass::Direct);
    job.producer = [2; 32];
    assert!(queue.push(class, job));
    // The byte-charged deficit round robin rotates producers, so a late
    // interactive job is selected within one bulk quantum no matter how deep
    // the bulk backlog is. This is the control-fairness invariant the GC/2
    // reservation policy relies on; control records use the interactive class.
    assert_eq!(super::tests::marker(&queue.pop().unwrap()), 1);
    assert_eq!(super::tests::marker(&queue.pop().unwrap()), 99);
    // While bulk is not allowed only the interactive producer can proceed.
    assert!(queue.pop_eligible(false).is_none());
}

#[test]
fn attempt_identity_includes_semantic_headers() {
    let target = RelayTarget {
        address: "127.0.0.1:1234".parse().unwrap(),
        relay_service_id: [1; 32],
    };
    let attempt = |flags| {
        let job = SemanticJob::AdminPost {
            target: target.clone(),
            token: "token".into(),
            cell: Cell::new(CellType::Msg, flags, 0, vec![0]),
        };
        job.attempt(job.producer())
    };
    assert_ne!(attempt(0), attempt(1));
}

#[tokio::test]
async fn closing_a_lane_cancels_pending_connection_warmup() {
    use gcoms_transport::connector::{ConnectFuture, Connector};
    struct Stalled(Arc<Notify>);
    impl Connector for Stalled {
        fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
            Box::pin(async move {
                self.0.notify_one();
                std::future::pending().await
            })
        }
    }
    let started = Arc::new(Notify::new());
    let client = Tp1Client::with_connector(Arc::new(Stalled(started.clone()))).unwrap();
    let scheduler = RelayScheduler::with_profile(
        Arc::new(client),
        SchedulerProfile::fixture().with_pipelining(),
    );
    let contact = AliasContact {
        target: RelayTarget {
            address: "192.0.2.1:443".parse().unwrap(),
            relay_service_id: [1; 32],
        },
        queue_id: [2; 32],
        epoch: 1,
        push_cap: [3; 32],
        expiry: u64::MAX,
    };
    let receipt = scheduler
        .push(
            ProducerClass::Direct,
            contact.clone(),
            Cell::new(CellType::Msg, 0, 0, vec![1]),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    scheduler.close_lane(&LaneAuth::Push { contact });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), receipt.completion())
            .await
            .unwrap()
            .state(),
        CompletionState::Shutdown
    );
    assert_eq!(scheduler.resource_snapshot().jobs, 0);
    scheduler.shutdown();
}

#[test]
fn retained_allocation_capacity_counts_against_memory_admission() {
    let mut payload = Vec::with_capacity(MAX_QUEUED_BYTES);
    payload.push(1);
    let job = SemanticJob::AdminPost {
        target: RelayTarget {
            address: "127.0.0.1:1234".parse().unwrap(),
            relay_service_id: [1; 32],
        },
        token: "token".into(),
        cell: Cell::new(CellType::Msg, 0, 0, payload),
    };
    let budget = budget::Budget::default();
    assert!(matches!(
        budget.reserve(job.accounted_bytes(), None),
        Err(EnqueueError::Full)
    ));
    assert_eq!(budget.snapshot().bytes, 0);
}
