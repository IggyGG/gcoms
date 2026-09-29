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
    runtime
}
async fn snapshot(sdk: &impl GcClient) -> api::Snapshot {
    let api::Reply::Snapshot(snapshot) = sdk.sharing_v2(api::Request::List).await.unwrap() else {
        panic!("snapshot")
    };
    snapshot
}
async fn authorize(a: &impl GcClient, b: &impl GcClient) {
    a.sharing_v2(api::Request::Contacts(vec![b.identity().contact_card]))
        .await
        .unwrap();
    b.sharing_v2(api::Request::Contacts(vec![a.identity().contact_card]))
        .await
        .unwrap();
}
#[tokio::test]
async fn modern_contact_file_verifies_resumes_and_revokes_without_a_channel() {
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
    tokio::time::timeout(Duration::from_secs(40), async {
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
    .await
    .expect("first verified piece");
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
    tokio::time::timeout(Duration::from_secs(70), async {
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
    .await
    .expect("verified resumed file and authenticated completion");
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
