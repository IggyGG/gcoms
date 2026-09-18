use super::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_in_flight_save_before_releasing_profile() {
    let dir = tempfile::tempdir().unwrap();
    crate::private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("protocol");
    let runtime = ProtocolRuntime::create_fixture(
        &path,
        "test-only-passphrase",
        "127.0.0.1:0".parse().unwrap(),
        None,
        None,
        &[],
    )
    .await
    .unwrap();
    let previous_owner = Arc::downgrade(&runtime.0);
    let retained = runtime.clone();

    // Hold a save in flight through the real event-forwarding path. The worker
    // upgrades its weak capture before waiting for the save lock, so merely
    // dropping the host cannot release its encrypted profile.
    let save = retained.0.save_lock.lock().await;
    let (source, events) = mpsc::channel(1);
    let subscriber = runtime.forward_events(events, None);
    source
        .send(ClientEvent::EventsLagged { skipped: 1 })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while previous_owner.strong_count() < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("event persistence keeps an in-flight runtime reference");

    let shutdown = tokio::spawn(runtime.shutdown());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !subscriber.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown cancels the in-flight worker before its final save");
    drop(save);
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown finishes after the final save")
        .unwrap()
        .unwrap();
    assert!(subscriber.is_closed(), "shutdown joined the forwarder");
    assert!(source.is_closed(), "shutdown dropped the event source");
    assert!(
        retained.sdk_client().subscribe_events().is_closed(),
        "a stopped runtime cannot start a new forwarding task"
    );
    drop(retained);
    assert!(
        previous_owner.upgrade().is_none(),
        "workers released the profile"
    );
    let (_store, _data) = ProtocolStore::open(&path, "test-only-passphrase")
        .expect("the encrypted profile can be reopened immediately");
}
