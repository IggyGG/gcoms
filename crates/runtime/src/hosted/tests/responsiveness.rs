use super::*;
use std::time::Duration;

struct HeldResponse {
    service: Arc<TransportFixture>,
    append: AtomicBool,
    read: AtomicBool,
    entered: tokio::sync::Notify,
}
#[async_trait]
impl Transport for HeldResponse {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        let hold = match &operation {
            wire::Operation::Append(wire::Append::Message(_)) => {
                self.append.swap(false, Ordering::SeqCst)
            }
            wire::Operation::Read { .. } => self.read.swap(false, Ordering::SeqCst),
            _ => false,
        };
        let reply = self.service.exchange(channel, operation).await?;
        if hold {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(reply)
    }
}
fn initialized() -> Result<HostedChannels, String> {
    panic!("owner was already initialized")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_local_send_preempts_a_lost_network_reply_without_losing_or_duplicating_delivery() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let profile = private_dir();
    let service = service(server.path());
    let mut alice = owner(a.path(), service.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", b.path(), service.clone()).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let held = Arc::new(HeldResponse {
        service: service.clone(),
        append: AtomicBool::new(false),
        read: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
    });
    alice.transport = held.clone();
    // Only the ordinary route handle is needed by this owner. The two actual
    // clients use the ciphertext-service transport above; no fake MLS state.
    let runtime = crate::ProtocolRuntime::open_options(
        &profile.path().join("profile"),
        "responsive-hosted-test",
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
    let api::Reply::Queued(first) = manager
        .request(
            api::Request::Send {
                channel,
                content: api::Content::Text("first".into()),
            },
            initialized,
        )
        .await
        .unwrap()
    else {
        panic!("queued first");
    };
    held.append.store(true, Ordering::SeqCst);
    let background = {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .request(api::Request::Sync { channel }, initialized)
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), held.entered.notified())
        .await
        .unwrap();
    // The service has fsynced the first append but its reply never arrives.
    // A local send must still persist and acknowledge its own queue admission.
    let api::Reply::Queued(second) = tokio::time::timeout(
        Duration::from_millis(200),
        manager.request(
            api::Request::Send {
                channel,
                content: api::Content::Text("second".into()),
            },
            initialized,
        ),
    )
    .await
    .expect("local feedback must not wait for the network")
    .unwrap() else {
        panic!("queued second");
    };
    assert_ne!(first, second);
    tokio::time::timeout(Duration::from_secs(5), background)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    for _ in 0..3 {
        manager
            .request(api::Request::Sync { channel }, initialized)
            .await
            .unwrap();
    }
    let api::Reply::Events(events) = manager
        .request(
            api::Request::Events {
                channel,
                after: 0,
                limit: 256,
            },
            initialized,
        )
        .await
        .unwrap()
    else {
        panic!("events");
    };
    for id in [first, second] {
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e.kind,api::EventKind::Message { id: got,.. } if got==id))
                .count(),
            1
        );
        assert!(!events.iter().any(|e| matches!(e.kind,api::EventKind::Delivery { id:got,state:api::Delivery::Delivered } if got==id)));
    }
    held.read.store(true, Ordering::SeqCst);
    let background = {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .request(api::Request::Sync { channel }, initialized)
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), held.entered.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(200), manager.close())
        .await
        .expect("shutdown cancels network waits");
    assert!(background.await.unwrap().is_err());
    assert!(manager
        .request(api::Request::List, initialized)
        .await
        .is_err());
    let (storage, bytes) =
        storage::Storage::open(&a.path().join(filename(channel)), [99; 32], channel).unwrap();
    let mut alice = Client::restore(&bytes.unwrap(), channel, storage, [99; 32], service).unwrap();
    pump(&mut bob).await;
    assert_eq!(
        messages(&bob)
            .iter()
            .filter(|e| matches!(
                &e.kind,
                api::EventKind::Message {
                    content: api::Content::Text(_),
                    ..
                }
            ))
            .count(),
        2
    );
    let events = bob.events(0, 256).unwrap();
    bob.commit_events(events.last().unwrap().sequence).unwrap();
    pump(&mut bob).await;
    pump(&mut alice).await;
    for id in [first, second] {
        assert!(alice.events(0,256).unwrap().iter().any(|e| matches!(e.kind,api::EventKind::Delivery { id:got,state:api::Delivery::Delivered } if got==id)));
    }
    runtime.shutdown().await.unwrap();
}
