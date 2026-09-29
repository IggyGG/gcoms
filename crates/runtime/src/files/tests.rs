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

/// Controlled transport model for the host's actual send-admission bound. This
/// isolates latency from encryption correctness and does not qualify a network
/// or Windows artifact. Each endpoint holds its slot until its real completion;
/// delivery and the receipt occur together after a 450 ms hop.
#[test]
fn retained_file_window_has_room_for_recovery_under_delayed_hop_receipts() {
    use std::io::Cursor;
    let sender_dir = tempfile::tempdir().unwrap();
    let receiver_dir = tempfile::tempdir().unwrap();
    for dir in [&sender_dir, &receiver_dir] {
        gcoms_private_fs::make_private(dir.path(), true).unwrap();
    }
    let mut sender_cache = Cache::open(sender_dir.path(), [7; 32], Default::default()).unwrap();
    let mut receiver_cache = Cache::open(receiver_dir.path(), [8; 32], Default::default()).unwrap();
    let bytes = vec![0x5a; 16 * 1024 * 1024];
    let channel = [0x77; 32];
    let members = [[1; 32], [2; 32]];
    let manifest = sender_cache
        .import(
            [0x83; 16],
            swarm::Scope {
                channel,
                participants: vec![],
            },
            "latency.bin".into(),
            bytes.len() as u64,
            &mut Cursor::new(&bytes),
            100,
        )
        .unwrap();
    receiver_cache.offer(manifest.clone(), 100).unwrap();
    receiver_cache.accept(manifest.id, 100).unwrap();
    let (proof, ciphertext) = sender_cache.read_piece(manifest.id, 0).unwrap();
    receiver_cache
        .put(manifest.id, 0, &ciphertext, &proof, 100)
        .unwrap();
    drop(receiver_cache);
    let reopened = Cache::open(receiver_dir.path(), [8; 32], Default::default()).unwrap();
    let mut engines = [Engine::new(sender_cache), Engine::new(reopened)];
    for (i, engine) in engines.iter_mut().enumerate() {
        engine.set_members(channel, members[i], members);
    }
    let mut queued: [VecDeque<Action>; 2] = Default::default();
    let mut in_flight: [VecDeque<(u64, Action)>; 2] = Default::default();
    // Reserve sixty seconds of the release's 180-second budget for reconnect /
    // source discovery. This is a declared latency model, not a wall-clock claim.
    let mut completed = None;
    for slot in 1200..3600u64 {
        let now = 100 + slot / 20;
        for from in 0..2 {
            while in_flight[from].front().is_some_and(|(due, _)| *due <= slot) {
                let (_, action) = in_flight[from].pop_front().unwrap();
                assert!(engines[from].action_allowed(&action));
                engines[from].send_finished(action.send_token(), SendOutcome::HopAccepted, now);
                let peer = Peer {
                    channel,
                    member: members[from],
                };
                let message = swarm::Message::decode(&action.message.encode().unwrap()).unwrap();
                let replies = engines[1 - from].receive(peer, message, now).unwrap();
                queued[1 - from].extend(replies);
            }
        }
        for from in 0..2 {
            queued[from].extend(engines[from].tick(now).unwrap());
            while in_flight[from].len() < FILE_SEND_CONCURRENCY {
                let Some(action) = queued[from].pop_front() else {
                    break;
                };
                if engines[from].action_allowed(&action) {
                    in_flight[from].push_back((slot + 9, action));
                } else {
                    engines[from].send_finished(
                        action.send_token(),
                        SendOutcome::DefinitelyNotSent,
                        now,
                    );
                }
            }
            assert!(queued[from].len() <= 128, "host pending-action budget");
            assert!(engines[from].buffered_bytes() <= swarm::PAYLOAD_BUDGET);
        }
        if engines[1].cache.get(manifest.id).unwrap().status == swarm::Status::Complete {
            completed = Some(slot as f64 / 20.0);
            break;
        }
    }
    let elapsed = completed
        .expect("bounded file window must leave room for reconnect at observed hop latency");
    let mut output = Vec::new();
    engines[1].cache.export(manifest.id, &mut output).unwrap();
    assert_eq!(output, bytes);
    println!("16 MiB retained model: {elapsed:.2}s including 60s recovery; {FILE_SEND_CONCURRENCY} sends/endpoint");
}
