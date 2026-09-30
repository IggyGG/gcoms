use super::*;
use std::sync::atomic::AtomicUsize;

struct LoseFetch {
    inner: Arc<TransportFixture>,
    reads: AtomicUsize,
}
#[async_trait]
impl Transport for LoseFetch {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        let fetching = matches!(operation, wire::Operation::Fetch { .. });
        let reply = self.inner.exchange(channel, operation).await?;
        if fetching && self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err("injected lost second deferred fetch".into());
        }
        Ok(reply)
    }
}
async fn admit(channel: [u8; 32], dirs: &[tempfile::TempDir], transport: Arc<TransportFixture>) {
    for (index, dir) in dirs.iter().enumerate() {
        let mut client = joining(
            channel,
            &format!("batch-{index}"),
            dir.path(),
            transport.clone(),
        )
        .await;
        assert!(client.flush_one().await.unwrap());
        assert!(client.view().active);
    }
}
fn restore(dir: &Path, channel: [u8; 32], transport: Arc<TransportFixture>) -> Client {
    let (storage, bytes) =
        storage::Storage::open(&dir.join(filename(channel)), [99; 32], channel).unwrap();
    Client::restore(&bytes.unwrap(), channel, storage, [99; 32], transport).unwrap()
}

#[tokio::test]
async fn hosted_checkpoint_batches_survive_lost_prefetch_and_reopen_without_per_record_writes() {
    let server = private_dir();
    let a = private_dir();
    let members: Vec<_> = (0..24).map(|_| private_dir()).collect();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    admit(channel, &members, transport.clone()).await;
    let path = a.path().join(filename(channel));
    let before = std::fs::read(&path).unwrap();
    let writes = alice.checkpoint_count();
    alice.transport = Arc::new(LoseFetch {
        inner: transport.clone(),
        reads: AtomicUsize::new(0),
    });
    assert!(alice
        .sync_page()
        .await
        .unwrap_err()
        .contains("second deferred fetch"));
    assert_eq!(
        alice.archive.cursor, 0,
        "prefetch must not expose a speculative prefix"
    );
    assert_eq!(alice.checkpoint_count(), writes);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(alice);
    let mut alice = restore(a.path(), channel, transport.clone());
    assert!(alice.sync_page().await.unwrap());
    assert_eq!(alice.archive.cursor, 24);
    assert_eq!(alice.view().members.len(), 25);
    assert!(
        alice.checkpoint_count() < 12,
        "amortize the 24 full-state writes; observed {}",
        alice.checkpoint_count()
    );
    let events = alice.events(0, 256).unwrap();
    assert!(!events.is_empty());
    drop(alice);
    let alice = restore(a.path(), channel, transport);
    assert_eq!(alice.archive.cursor, 24);
    assert_eq!(alice.view().members.len(), 25);
    assert_eq!(alice.events(0, 256).unwrap(), events);
}

#[tokio::test]
async fn hosted_failed_batch_checkpoint_exposes_no_unpersisted_events_and_reopens_old_prefix() {
    let server = private_dir();
    let a = private_dir();
    let members: Vec<_> = (0..3).map(|_| private_dir()).collect();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    admit(channel, &members, transport.clone()).await;
    let path = a.path().join(filename(channel));
    let saved = path.with_extension("retained-fixture");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(alice.sync_page().await.is_err());
    assert!(alice.events(0, 256).is_err());
    assert!(alice
        .queue_send(api::Content::Text(
            "must not escape failed checkpoint".into()
        ))
        .is_err());
    drop(alice);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    let mut alice = restore(a.path(), channel, transport);
    assert_eq!(alice.archive.cursor, 0);
    assert!(alice.sync_page().await.unwrap());
    assert_eq!(alice.archive.cursor, 3);
    assert_eq!(alice.view().members.len(), 4);
}
