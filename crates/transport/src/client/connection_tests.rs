use super::*;
use crate::connector::ConnectFuture;
use std::io::{Error as IoError, ErrorKind};

struct RefusingConnector {
    calls: AtomicUsize,
    kind: ErrorKind,
}

impl Connector for RefusingConnector {
    fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(IoError::new(self.kind, "diagnostic dial failure").into())
        })
    }

    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        pin: [u8; 32],
        _: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        self.connect(addr, pin)
    }
}

#[tokio::test]
async fn queued_posts_wait_out_a_known_dial_cooldown_without_resubmission() {
    use crate::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};
    use gcoms_core::{Cell, CellType};
    use std::time::Duration;

    struct RefuseOnce(AtomicUsize);
    impl Connector for RefuseOnce {
        fn connect(&self, addr: SocketAddr, pin: [u8; 32]) -> ConnectFuture<'_> {
            Box::pin(async move {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(
                        IoError::new(ErrorKind::ConnectionRefused, "restarting relay").into(),
                    );
                }
                DirectConnector.connect(addr, pin).await
            })
        }
    }

    let identity = TlsIdentity::generate().unwrap();
    let registry = TokenRegistry::new();
    registry.insert_post("retained-control");
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Arc::new(|_, cell| Ok(Some(cell))),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    let pin = identity.service_id();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let connector = Arc::new(RefuseOnce(AtomicUsize::new(0)));
    let client = Arc::new(Tp1Client::with_connector(connector.clone()).unwrap());
    let started = tokio::time::Instant::now();
    assert!(client.warm(address, pin).await.is_err());
    let preparations = Arc::new(AtomicUsize::new(0));
    let mut posts = tokio::task::JoinSet::new();
    for index in 0..8u8 {
        let client = client.clone();
        let preparations = preparations.clone();
        posts.spawn(async move {
            let cell = Cell::new(CellType::Msg, 0, 0, vec![index; 32]);
            let expected = cell.clone();
            let result = client
                .post_cell_prepared(
                    address,
                    pin,
                    "retained-control",
                    &[],
                    TrafficClass::Interactive,
                    move || {
                        preparations.fetch_add(1, Ordering::SeqCst);
                        Ok(Bytes::from(cell.encode_wire().unwrap()))
                    },
                )
                .await;
            assert!(
                matches!(result, Ok(HopOutcome::Accepted(Some(ref cell))) if cell == &expected),
                "queued recovery control was discarded by the negative dial cache: {result:?}"
            );
        });
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(connector.0.load(Ordering::SeqCst), 1);
    assert_eq!(preparations.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(result) = posts.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("original bounded recovery request");
    assert!(started.elapsed() >= CONNECT_FAILURE_COOLDOWN);
    assert_eq!(connector.0.load(Ordering::SeqCst), 2);
    assert_eq!(preparations.load(Ordering::SeqCst), 8);
    assert_eq!(client.pooled_connections().await, 1);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn offline_backlog_does_not_repeat_failed_dials_and_retries_after_cooldown() {
    let connector = Arc::new(RefusingConnector {
        calls: AtomicUsize::new(0),
        kind: ErrorKind::ConnectionRefused,
    });
    let client = Tp1Client::with_connector(connector.clone()).unwrap();
    let addr = "127.0.0.1:443".parse().unwrap();
    assert!(client.warm(addr, [1; 32]).await.is_err());
    for _ in 0..2000 {
        assert!(client.get_pinned(addr, [1; 32], "/").await.is_err());
    }
    assert_eq!(connector.calls.load(Ordering::Relaxed), 1);
    tokio::time::advance(CONNECT_FAILURE_COOLDOWN).await;
    assert!(client.warm(addr, [1; 32]).await.is_err());
    assert_eq!(connector.calls.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn refusal_is_scoped_to_address_pin_and_route_exclusions() {
    let connector = Arc::new(RefusingConnector {
        calls: AtomicUsize::new(0),
        kind: ErrorKind::ConnectionRefused,
    });
    let client = Tp1Client::with_connector(connector.clone()).unwrap();
    let addr = "127.0.0.1:443".parse().unwrap();
    let excluded = [("127.0.0.2:443".parse().unwrap(), [3; 32])];
    for (address, pin, exclusions) in [
        (addr, [1; 32], &[][..]),
        (addr, [2; 32], &[][..]),
        ("127.0.0.1:444".parse().unwrap(), [1; 32], &[][..]),
        (addr, [1; 32], &excluded[..]),
    ] {
        for _ in 0..2 {
            assert!(client
                .connection(
                    Route {
                        addr: address,
                        service_id: pin,
                        excluded: exclusions
                    },
                    TrafficClass::Interactive
                )
                .await
                .is_err());
        }
    }
    assert_eq!(connector.calls.load(Ordering::Relaxed), 4);
}

#[tokio::test(start_paused = true)]
async fn arbitrary_connector_failures_are_not_cached() {
    let connector = Arc::new(RefusingConnector {
        calls: AtomicUsize::new(0),
        kind: ErrorKind::InvalidData,
    });
    let client = Tp1Client::with_connector(connector.clone()).unwrap();
    for _ in 0..2 {
        assert!(client
            .warm("127.0.0.1:443".parse().unwrap(), [1; 32])
            .await
            .is_err());
    }
    assert_eq!(connector.calls.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn refusal_cache_is_bounded_and_expired_entries_are_reclaimed() {
    let mut pool = Pool::default();
    for port in 1..=MAX_FAILED_ROUTES as u16 + 32 {
        pool.dial_failed((
            SocketAddr::from(([127, 0, 0, 1], port)),
            [1; 32],
            [0; 32],
            None,
            0,
        ));
        assert!(pool.failed.len() <= MAX_FAILED_ROUTES);
    }
    tokio::time::advance(CONNECT_FAILURE_COOLDOWN).await;
    assert!(pool
        .cooling_down(("127.0.0.1:1".parse().unwrap(), [1; 32], [0; 32], None, 0))
        .is_none());
    assert!(pool.failed.is_empty());
}

#[tokio::test(start_paused = true)]
async fn cooldown_wait_cancels_before_preparation_and_keeps_original_cache_deadline() {
    use std::time::Duration;
    let connector = Arc::new(RefusingConnector {
        calls: AtomicUsize::new(0),
        kind: ErrorKind::ConnectionRefused,
    });
    let client = Tp1Client::with_connector(connector.clone()).unwrap();
    let address = "127.0.0.1:443".parse().unwrap();
    let started = tokio::time::Instant::now();
    assert!(client.warm(address, [1; 32]).await.is_err());
    let preparations = AtomicUsize::new(0);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        client.post_cell_prepared(
            address,
            [1; 32],
            "private",
            &[],
            TrafficClass::Interactive,
            || {
                preparations.fetch_add(1, Ordering::Relaxed);
                Ok(Bytes::new())
            },
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "cached refusal is a cancellable wait for posted work"
    );
    assert_eq!(preparations.load(Ordering::Relaxed), 0);
    assert_eq!(connector.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        client.connection_attempts.available_permits(),
        MAX_CONNECTION_ATTEMPTS
    );
    assert_eq!(
        client.connection_slots.available_permits(),
        MAX_ACTIVE_CONNECTIONS
    );
    tokio::time::sleep_until(started + CONNECT_FAILURE_COOLDOWN).await;
    assert!(client.warm(address, [1; 32]).await.is_err());
    assert_eq!(
        connector.calls.load(Ordering::Relaxed),
        2,
        "cancellation cannot renew the negative cache"
    );
}

#[tokio::test(start_paused = true)]
async fn posted_cooldown_wait_cannot_extend_original_request_deadline() {
    let connector = Arc::new(RefusingConnector {
        calls: AtomicUsize::new(0),
        kind: ErrorKind::ConnectionRefused,
    });
    let client = Tp1Client::with_connector(connector.clone()).unwrap();
    let address = "127.0.0.1:443".parse().unwrap();
    let started = tokio::time::Instant::now();
    // Exercise the outer deadline independently of the shorter normal5s cache.
    client.connections.lock().await.failed.insert(
        (address, [1; 32], [0; 32], None, 0),
        started + REQUEST_TIMEOUT * 2,
    );
    let preparations = AtomicUsize::new(0);
    let result = client
        .post_cell_prepared(
            address,
            [1; 32],
            "private",
            &[],
            TrafficClass::Interactive,
            || {
                preparations.fetch_add(1, Ordering::Relaxed);
                Ok(Bytes::new())
            },
        )
        .await;
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert_eq!(started.elapsed(), REQUEST_TIMEOUT);
    assert_eq!(preparations.load(Ordering::Relaxed), 0);
    assert_eq!(connector.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        client.connection_attempts.available_permits(),
        MAX_CONNECTION_ATTEMPTS
    );
    assert_eq!(
        client.connection_slots.available_permits(),
        MAX_ACTIVE_CONNECTIONS
    );
}

#[tokio::test(start_paused = true)]
async fn warming_has_a_deadline_and_releases_connection_credit() {
    struct Pending;
    impl Connector for Pending {
        fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
            Box::pin(std::future::pending())
        }
    }
    let client = Tp1Client::with_connector(Arc::new(Pending)).unwrap();
    let started = tokio::time::Instant::now();
    let error = client
        .warm("127.0.0.1:443".parse().unwrap(), [1; 32])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("warming timed out"));
    assert_eq!(started.elapsed(), REQUEST_TIMEOUT);
    assert_eq!(
        client.connection_attempts.available_permits(),
        MAX_CONNECTION_ATTEMPTS
    );
}
