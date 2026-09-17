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
                .connection(Route {
                    addr: address,
                    service_id: pin,
                    excluded: exclusions
                })
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
        pool.dial_failed((SocketAddr::from(([127, 0, 0, 1], port)), [1; 32], [0; 32]));
        assert!(pool.failed.len() <= MAX_FAILED_ROUTES);
    }
    tokio::time::advance(CONNECT_FAILURE_COOLDOWN).await;
    assert!(!pool.cooling_down(("127.0.0.1:1".parse().unwrap(), [1; 32], [0; 32])));
    assert!(pool.failed.is_empty());
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
