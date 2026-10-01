use super::*;
use crate::{ProtocolRuntime, RuntimeOptions};
async fn runtime(path: &Path, create: bool) -> ProtocolRuntime {
    gcoms_private_fs::make_private(path, true).unwrap();
    let runtime = ProtocolRuntime::open_options(
        &path.join("profile"),
        "modern-file-fixture",
        create,
        RuntimeOptions {
            durable_channel_inbox: true,
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            relay: None,
            fixture: true,
            carrier: gcoms_sdk::CarrierProfile::default(),
            network: None,
        },
    )
    .await
    .unwrap();
    runtime.enable_durable_applications().await.unwrap();
    runtime.sdk_client().embedded().node().enable_diagnostics();
    runtime
}
async fn snapshot(sdk: &impl GcClient) -> api::Snapshot {
    let api::Reply::Snapshot(snapshot) = sdk.sharing_v2(api::Request::List).await.unwrap() else {
        panic!("snapshot")
    };
    snapshot
}
async fn authorize(a: &impl GcClient, b: &impl GcClient) {
    a.sharing_v2(api::Request::Contacts(vec![
        b.refresh_identity().await.unwrap().contact_card,
    ]))
    .await
    .unwrap();
    b.sharing_v2(api::Request::Contacts(vec![
        a.refresh_identity().await.unwrap().contact_card,
    ]))
    .await
    .unwrap();
}
#[tokio::test]
async fn modern_contact_file_verifies_resumes_and_revokes_without_a_channel() {
    let diagnostics = tempfile::tempdir().unwrap();
    let metrics = diagnostics.path().join("metrics.jsonl");
    gcoms_node::metrics::init(&metrics).unwrap();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ar = runtime(a.path(), true).await;
    let br = runtime(b.path(), true).await;
    let owner = ar.sdk_client();
    let receiver = br.sdk_client();
    authorize(&owner, &receiver).await;
    assert!(owner.list_channels().await.unwrap().is_empty());
    let peer = hash(
        &owner
            .resolve_contact_identity(&receiver.identity().contact_card)
            .await
            .unwrap(),
    );
    let id = [0xa7; 16];
    let bytes: Vec<_> = (0..(2 * legacy::PIECE_BYTES + 41))
        .map(|i| (i % 251) as u8)
        .collect();
    owner
        .sharing_v2(api::Request::Prepare {
            id,
            scope: api::Scope::Contact { peer },
            name: "private.bin".into(),
            size_bytes: bytes.len() as u64,
        })
        .await
        .unwrap();
    for (piece, bytes) in bytes.chunks(legacy::PIECE_BYTES).enumerate() {
        owner
            .sharing_v2(api::Request::WritePiece {
                id,
                piece: piece as u32,
                bytes: bytes.to_vec(),
            })
            .await
            .unwrap();
    }
    owner.sharing_v2(api::Request::Commit { id }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if snapshot(&receiver).await.files.iter().any(|f| f.id == id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("durable contact offer");
    receiver
        .sharing_v2(api::Request::Accept { id })
        .await
        .unwrap();
    // This is a bounded correctness/restart gate on the legacy fixture.
    // The original 40-second failure and the three-pull 240-second failure
    // remain retained; this does not qualify GC/2 throughput or latency.
    let progress = tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            if snapshot(&receiver)
                .await
                .files
                .iter()
                .any(|f| f.id == id && f.verified_bytes >= legacy::PIECE_BYTES as u64)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if progress.is_err() {
        let source = ar.modern_files().await.unwrap();
        let target = br.modern_files().await.unwrap();
        let a = source.backend.lock().await;
        let b = target.backend.lock().await;
        eprintln!(
            "source error {:?}, diag {:?}, pending {}",
            a.as_ref().unwrap().error,
            a.as_ref().unwrap().engine.diagnostics(),
            a.as_ref().unwrap().pending.len()
        );
        eprintln!(
            "target error {:?}, diag {:?}, pending {}",
            b.as_ref().unwrap().error,
            b.as_ref().unwrap().engine.diagnostics(),
            b.as_ref().unwrap().pending.len()
        );
    }
    progress.expect("first verified piece");
    receiver
        .sharing_v2(api::Request::Pause { id })
        .await
        .unwrap();
    let retained = snapshot(&receiver)
        .await
        .files
        .into_iter()
        .find(|f| f.id == id)
        .unwrap()
        .verified_bytes;
    receiver
        .sharing_v2(api::Request::Contacts(vec![]))
        .await
        .unwrap();
    assert!(receiver
        .sharing_v2(api::Request::Resume { id })
        .await
        .is_err());
    drop(receiver);
    br.shutdown().await.unwrap();
    let br = runtime(b.path(), false).await;
    let receiver = br.sdk_client();
    let before = snapshot(&receiver).await;
    assert_eq!(
        before
            .files
            .iter()
            .find(|f| f.id == id)
            .unwrap()
            .verified_bytes,
        retained
    );
    assert!(
        receiver
            .sharing_v2(api::Request::Resume { id })
            .await
            .is_err(),
        "reopen needs explicit contact registration"
    );
    authorize(&owner, &receiver).await;
    receiver
        .sharing_v2(api::Request::Resume { id })
        .await
        .unwrap();
    let resume_started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let resumed = tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            if snapshot(&receiver)
                .await
                .files
                .iter()
                .any(|f| f.id == id && f.status == legacy::Status::Complete)
                && snapshot(&owner)
                    .await
                    .files
                    .iter()
                    .any(|f| f.id == id && f.completed_by == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if resumed.is_err() {
        eprintln!("source node: {:?}", owner.embedded().node().diagnostics());
        eprintln!(
            "target node: {:?}",
            receiver.embedded().node().diagnostics()
        );
        let log = std::fs::read_to_string(&metrics).unwrap();
        let mut events = BTreeMap::<String, usize>::new();
        let mut frame_errors = Vec::new();
        for line in log.lines() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                let label = format!(
                    "{} {}",
                    value["event"],
                    value.get("e").unwrap_or(&serde_json::Value::Null)
                );
                *events.entry(label).or_default() += 1;
                if value["event"] == "frame_error" && frame_errors.len() < 16 {
                    frame_errors.push(value);
                }
            }
        }
        eprintln!("node events: {events:?}");
        eprintln!("resume started at {resume_started_ms} ms; frame errors: {frame_errors:?}");
        eprintln!("resumed source snapshot: {:?}", snapshot(&owner).await);
        eprintln!("resumed target snapshot: {:?}", snapshot(&receiver).await);
        let source = ar.modern_files().await.unwrap();
        let target = br.modern_files().await.unwrap();
        eprintln!(
            "resumed source diag: {:?}",
            source
                .backend
                .lock()
                .await
                .as_ref()
                .unwrap()
                .engine
                .diagnostics()
        );
        eprintln!(
            "resumed target diag: {:?}",
            target
                .backend
                .lock()
                .await
                .as_ref()
                .unwrap()
                .engine
                .diagnostics()
        );
    }
    resumed.expect("verified resumed file and authenticated completion");
    let mut actual = Vec::new();
    for piece in 0..3 {
        let api::Reply::Piece(bytes) = receiver
            .sharing_v2(api::Request::ReadPiece { id, piece })
            .await
            .unwrap()
        else {
            panic!("piece")
        };
        actual.extend(bytes);
    }
    assert_eq!(hash(&actual), hash(&bytes));
    assert_eq!(actual, bytes);
    assert!(receiver.list_channels().await.unwrap().is_empty());
    receiver
        .sharing_v2(api::Request::SetEnabled(false))
        .await
        .unwrap();
    assert!(receiver
        .sharing_v2(api::Request::ReadPiece { id, piece: 0 })
        .await
        .is_err());
    ar.shutdown().await.unwrap();
    br.shutdown().await.unwrap();
}
