use super::*;
use crate::ProtocolRuntime;
use gcoms_sdk::{
    sharing::{Reply, Request, Scope, Status},
    ChannelVisibility,
};

async fn peer(path: &Path) -> ProtocolRuntime {
    gcoms_private_fs::make_private(path, true).unwrap();
    ProtocolRuntime::create_fixture(
        &path.join("profile"),
        "file-receipt-test",
        "127.0.0.1:0".parse().unwrap(),
        None,
        None,
        &[],
    )
    .await
    .unwrap()
}
async fn snapshot(client: &impl GcClient) -> api::Snapshot {
    match client.sharing(Request::List).await.unwrap() {
        Reply::Snapshot(value) => value,
        _ => panic!("wrong reply"),
    }
}
#[tokio::test]
async fn incoming_file_completes_while_outbound_receipts_are_stalled() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ar = peer(a.path()).await;
    let br = peer(b.path()).await;
    let owner = ar.sdk_client();
    let joiner = br.sdk_client();
    let channel = owner
        .create_channel("receipts", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let join = joiner.prepare_channel_join("peer").await.unwrap();
    let package = joiner.channel_key_package(join).await.unwrap();
    let welcome = owner
        .admit_channel("receipts", &package, "peer")
        .await
        .unwrap();
    joiner
        .join_channel(join, "receipts", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    let receiver = br.files().await.unwrap();
    let gate = Arc::new(ReceiptGate {
        entered: std::sync::atomic::AtomicUsize::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *receiver.receipt_gate.lock().unwrap() = Some(gate.clone());
    ar.files().await.unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        while gate.entered.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("outgoing discovery receipt is held");
    let id = [0x81; 16];
    let bytes = vec![0x7b; 1024];
    owner
        .sharing(Request::Prepare {
            id,
            scope: Scope {
                channel: channel.0,
                participants: vec![],
            },
            name: "receipt.bin".into(),
            size_bytes: bytes.len() as u64,
        })
        .await
        .unwrap();
    owner
        .sharing(Request::WritePiece {
            id,
            piece: 0,
            bytes: bytes.clone(),
        })
        .await
        .unwrap();
    owner.sharing(Request::Commit { id }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut accepted = false;
        loop {
            if let Some(file) = snapshot(&joiner).await.files.iter().find(|f| f.id == id) {
                if file.status == Status::Complete {
                    break;
                }
                if !accepted {
                    assert_eq!(file.status, Status::Offered);
                    joiner.sharing(Request::Accept { id }).await.unwrap();
                    accepted = true;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("incoming transfer progresses despite delayed receipts");
    assert_eq!(
        joiner
            .sharing(Request::ReadPiece { id, piece: 0 })
            .await
            .unwrap(),
        Reply::Piece(bytes)
    );
    gate.release.add_permits(100);
    drop(receiver);
    ar.shutdown().await.unwrap();
    br.shutdown().await.unwrap();
}

#[tokio::test]
async fn locking_during_send_completion_does_not_lose_download_retry() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(source.path(), true).unwrap();
    let ar = peer(a.path()).await;
    let br = peer(b.path()).await;
    let owner = ar.sdk_client();
    let joiner = br.sdk_client();
    let channel = owner
        .create_channel("retry", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let join = joiner.prepare_channel_join("peer").await.unwrap();
    let package = joiner.channel_key_package(join).await.unwrap();
    let welcome = owner
        .admit_channel("retry", &package, "peer")
        .await
        .unwrap();
    joiner
        .join_channel(join, "retry", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    let sender = owner
        .channel_roster("retry")
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.is_self)
        .unwrap()
        .member_id;
    let receiver = br.files().await.unwrap();
    let gate = Arc::new(ReceiptGate {
        entered: std::sync::atomic::AtomicUsize::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *receiver.receipt_gate.lock().unwrap() = Some(gate.clone());
    let id = [0x82; 16];
    let mut cache = Cache::open(source.path(), [9; 32], Default::default()).unwrap();
    let manifest = cache
        .import(
            id,
            swarm::Scope {
                channel: channel.0,
                participants: vec![],
            },
            "retry.bin".into(),
            1,
            &mut std::io::Cursor::new([7]),
            now(),
        )
        .unwrap();
    {
        let mut inner = receiver.inner.lock().unwrap();
        let engine = &mut inner.as_mut().unwrap().engine;
        let peer = Peer {
            channel: channel.0,
            member: sender,
        };
        engine
            .receive(
                peer,
                swarm::Message::Offers {
                    manifests: vec![manifest],
                    next: None,
                },
                now(),
            )
            .unwrap();
        engine.accept(id, now()).unwrap();
        engine
            .receive(
                peer,
                swarm::Message::Have {
                    id,
                    start: 0,
                    pieces: vec![true],
                },
                now(),
            )
            .unwrap();
    }
    // The source's file service is deliberately closed, so the Want is accepted
    // by transport but receives no piece. Hold its transport completion at lock.
    tokio::time::timeout(Duration::from_secs(12), async {
        while gate.entered.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("discovery, inventory and Want reach transport completion");
    receiver.request(Request::SetEnabled(false)).await.unwrap();
    let completed = || {
        let inner = receiver.inner.lock().unwrap();
        let d = inner.as_ref().unwrap().engine.diagnostics();
        d.hop_accepted + d.outcome_unknown + d.not_sent
    };
    let before = completed();
    gate.release.add_permits(100);
    tokio::time::timeout(Duration::from_secs(3), async {
        while completed() < before + 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("locking must still settle outstanding transport attempts");
    receiver.request(Request::SetEnabled(true)).await.unwrap();
    {
        let mut inner = receiver.inner.lock().unwrap();
        let actions = inner.as_mut().unwrap().engine.tick(now() + 3600).unwrap();
        assert!(
            actions.iter().any(
                |a| matches!(a.message, swarm::Message::Want { id: share, .. } if share == id)
            ),
            "resumed transfer retries the unacknowledged piece without another Accept"
        );
    }
    drop(receiver);
    ar.shutdown().await.unwrap();
    br.shutdown().await.unwrap();
}
