use super::*;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct ReadFailures {
    inner: Arc<TransportFixture>,
    calls: AtomicUsize,
    deny: bool,
    failures: usize,
    unavailable_until: Option<tokio::time::Instant>,
}
#[async_trait]
impl Transport for ReadFailures {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        let snapshot = matches!(operation, wire::Operation::Snapshot { .. });
        let reply = self.inner.exchange(channel, operation).await?;
        if snapshot {
            let previous = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.deny {
                return Ok(wire::Reply::Fault(wire::Fault {
                    code: wire::FaultCode::Unauthorized,
                    message: "admission refused".into(),
                }));
            }
            if previous < self.failures
                || self
                    .unavailable_until
                    .is_some_and(|until| tokio::time::Instant::now() < until)
            {
                return Err("injected closed circuit after authenticated snapshot read".into());
            }
        }
        Ok(reply)
    }
}

#[tokio::test]
async fn snapshot_read_recovers_closed_circuits_without_repeating_membership() {
    let server = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let inner = service(server.path());
    let alice = owner(alice_dir.path(), inner.clone()).await;
    let channel = alice.archive.channel;
    drop(alice);
    let transport = Arc::new(ReadFailures {
        inner,
        calls: AtomicUsize::new(0),
        deny: false,
        failures: 2,
        unavailable_until: None,
    });
    let mut bob = joining(channel, "bob", bob_dir.path(), transport.clone()).await;
    assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
    assert!(!bob.view().active);
    assert!(bob.flush_one().await.unwrap());
    assert!(bob.view().active);
    assert_eq!(
        bob.archive.cursor, 1,
        "one accepted external membership change"
    );
    assert!(!bob.flush_one().await.unwrap());
}

#[tokio::test]
async fn snapshot_authority_refusal_is_not_retried_as_transport_failure() {
    let server = private_dir();
    let alice_dir = private_dir();
    let inner = service(server.path());
    let alice = owner(alice_dir.path(), inner.clone()).await;
    let channel = alice.archive.channel;
    let transport = ReadFailures {
        inner,
        calls: AtomicUsize::new(0),
        deny: true,
        failures: 0,
        unavailable_until: None,
    };
    let prepared = PreparedHostedJoin::new("denied").unwrap();
    let error = snapshot(&transport, channel, SnapshotAuthority::Joining(&prepared))
        .await
        .err()
        .unwrap();
    assert!(error.contains("admission refused"));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn snapshot_transport_retries_stop_after_four_attempts() {
    let server = private_dir();
    let alice_dir = private_dir();
    let inner = service(server.path());
    let alice = owner(alice_dir.path(), inner.clone()).await;
    let channel = alice.archive.channel;
    let transport = ReadFailures {
        inner,
        calls: AtomicUsize::new(0),
        deny: false,
        failures: usize::MAX,
        unavailable_until: None,
    };
    let prepared = PreparedHostedJoin::new("bounded").unwrap();
    let error = snapshot(&transport, channel, SnapshotAuthority::Joining(&prepared))
        .await
        .err()
        .unwrap();
    assert!(error.contains("injected closed circuit"));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 4);
    assert_eq!(alice.archive.cursor, 0);
}

#[tokio::test(start_paused = true)]
async fn snapshot_read_waits_for_background_route_recovery_before_single_admission() {
    let server = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let inner = service(server.path());
    let alice = owner(alice_dir.path(), inner.clone()).await;
    let channel = alice.archive.channel;
    let transport = Arc::new(ReadFailures {
        inner,
        calls: AtomicUsize::new(0),
        deny: false,
        failures: 0,
        unavailable_until: Some(tokio::time::Instant::now() + Duration::from_secs(4)),
    });
    let mut bob = joining(channel, "bob", bob_dir.path(), transport.clone()).await;
    assert_eq!(transport.calls.load(Ordering::SeqCst), 4);
    assert!(!bob.view().active);
    assert_eq!(alice.archive.cursor, 0);
    assert!(bob.flush_one().await.unwrap());
    assert!(bob.view().active);
    assert_eq!(bob.archive.cursor, 1);
    assert!(!bob.flush_one().await.unwrap());
}
