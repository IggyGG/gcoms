use super::*;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct HeldBlobs {
    service: Arc<TransportFixture>,
    entered: AtomicUsize,
    release: tokio::sync::Semaphore,
}
#[async_trait]
impl Transport for HeldBlobs {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        let blob = matches!(
            &operation,
            wire::Operation::PutBlob { .. } | wire::Operation::GetBlob { .. }
        );
        let reply = self.service.exchange(channel, operation).await?;
        if blob {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.release.acquire().await.unwrap().forget();
        }
        Ok(reply)
    }
}
fn initialized() -> Result<HostedChannels, String> {
    panic!("already initialized")
}
async fn entered(held: &HeldBlobs, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while held.entered.load(Ordering::SeqCst) < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("independent blob requests must enter the transport");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_blob_window_bounds_io_preserves_chat_and_rechecks_revocation() {
    run(true).await;
    run(false).await;
}

async fn run(revoke: bool) {
    let server = private_dir();
    let a = private_dir();
    let profile = private_dir();
    let service = service(server.path());
    let mut alice = owner(a.path(), service.clone()).await;
    let channel = alice.view().id;
    let member = alice.view().self_member;
    let held = Arc::new(HeldBlobs {
        service,
        entered: AtomicUsize::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    alice.transport = held.clone();
    let runtime = crate::ProtocolRuntime::open_options(
        &profile.path().join("profile"),
        "blob-concurrency-test",
        true,
        crate::RuntimeOptions {
            durable_channel_inbox: true,
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            relay: None,
            fixture: true,
            carrier: Default::default(),
            network: None,
        },
    )
    .await
    .unwrap();
    let manager = Arc::new(super::super::owner::Owner::default());
    let initial = HostedChannels {
        directory: a.path().into(),
        key: Zeroizing::new([99; 32]),
        network: Arc::new(runtime.sdk_client()),
        channels: BTreeMap::from([(channel, alice)]),
    };
    manager
        .request(api::Request::List, || Ok(initial))
        .await
        .unwrap();
    let reference = wire::BlobRef {
        owner: member,
        file: [77; 16],
        piece: 0,
    };
    let spawn = |request| {
        let manager = manager.clone();
        tokio::spawn(async move { manager.request(request, initialized).await })
    };
    let mut uploads = Vec::new();
    for piece in 0..2 {
        let mut reference = reference;
        reference.piece = piece;
        uploads.push(spawn(api::Request::PutBlob {
            channel,
            reference,
            bytes: vec![61; 2048],
        }));
    }
    entered(&held, 2).await;
    let mut third = reference;
    third.piece = 2;
    uploads.push(spawn(api::Request::PutBlob {
        channel,
        reference: third,
        bytes: vec![62; 2048],
    }));
    // A stalled bulk transfer must neither own mutable channel state nor be
    // cancelled by a queued message or covered poll.
    tokio::time::timeout(
        Duration::from_millis(200),
        manager.request(
            api::Request::Send {
                channel,
                content: api::Content::Text("chat during two held uploads".into()),
            },
            initialized,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        manager.request(api::Request::Sync { channel }, initialized),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        held.entered.load(Ordering::SeqCst),
        2,
        "at most two bulk exchanges"
    );
    assert!(uploads.iter().all(|task| !task.is_finished()));
    held.release.add_permits(3);
    for task in uploads {
        assert!(matches!(task.await.unwrap().unwrap(), api::Reply::Done));
    }
    let pending = spawn(api::Request::GetBlob { channel, reference });
    entered(&held, 4).await;
    if revoke {
        manager
            .request(
                api::Request::Change {
                    channel,
                    change: api::Change::Close,
                    reason: "test revocation during read".into(),
                },
                initialized,
            )
            .await
            .unwrap();
        manager
            .request(api::Request::Sync { channel }, initialized)
            .await
            .unwrap();
        held.release.add_permits(1);
        assert!(
            pending.await.unwrap().is_err(),
            "do not expose a previously authorized response after learned revocation"
        );
    } else {
        tokio::time::timeout(Duration::from_millis(200), manager.close())
            .await
            .expect("shutdown must cancel detached bulk I/O");
        assert!(pending.await.unwrap().is_err());
    }
    manager.close().await;
    runtime.shutdown().await.unwrap();
}
