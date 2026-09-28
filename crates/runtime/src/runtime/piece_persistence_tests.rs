use super::*;
use gcoms_file_transfer::swarm;
use std::{collections::HashSet, time::Duration};

async fn receive_piece(
    events: &mut mpsc::Receiver<ClientEvent>,
    expected_id: MessageId,
    expected_body: &[u8],
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events
                .recv()
                .await
                .expect("receiver event stream remains open")
            {
                ClientEvent::ChannelDirectMessage {
                    message_id, body, ..
                } if message_id == expected_id => {
                    let app = gcoms_sdk::ApplicationMessage::decode(&body).unwrap();
                    assert_eq!(app.content_type, swarm::CONTENT_TYPE);
                    assert_eq!(app.body, expected_body);
                    break;
                }
                ClientEvent::EventsLagged { .. } => panic!("lost piece observation"),
                _ => {}
            }
        }
    })
    .await
    .expect("authenticated piece received within the original deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn piece_transport_does_not_rewrite_profiles_or_require_wrapper_saves() {
    let dir = tempfile::tempdir().unwrap();
    crate::private_fs::make_private(dir.path(), true).unwrap();
    let mut peers = Vec::new();
    for name in ["sender", "receiver"] {
        peers.push(
            ProtocolRuntime::create_fixture(
                &dir.path().join(name),
                "piece-storage-fixture",
                "127.0.0.1:0".parse().unwrap(),
                None,
                None,
                &["127.0.0.0/8".to_owned()],
            )
            .await
            .unwrap(),
        );
    }
    let sender = &peers[0];
    let receiver = &peers[1];
    let a = sender.sdk_client();
    let b = receiver.sdk_client();
    a.create_channel("pieces", "sender", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let join = b.prepare_channel_join("receiver").await.unwrap();
    let package = b.channel_key_package(join).await.unwrap();
    let mut receipts = a.subscribe_events();
    let welcome = a
        .admit_channel("pieces", &package, "receiver")
        .await
        .unwrap();
    b.join_channel(join, "pieces", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    let warm = a.send_channel_tracked("pieces", b"warmup").await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut delivered = HashSet::new();
        while delivered.len() < 2 || !delivered.contains(&warm.0) {
            match receipts.recv().await.unwrap() {
                ClientEvent::ChannelDelivered { message_id, .. } => {
                    delivered.insert(message_id.0);
                }
                ClientEvent::EventsLagged { .. } => panic!("lost warmup receipt"),
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    let recipient = a
        .channel_roster("pieces")
        .await
        .unwrap()
        .into_iter()
        .find(|m| !m.is_self)
        .unwrap()
        .member_id;
    let mut events = b.subscribe_events();
    let before_a = sender.persistence_diagnostics();
    let before_b = receiver.persistence_diagnostics();
    let mut ids = HashSet::new();
    for index in 0..16u8 {
        let body = swarm::Message::Data {
            id: [0x73; 16],
            piece: u32::from(index),
            offset: 0,
            request: [index + 1; 16],
            proof: vec![],
            bytes: vec![index; 4096],
        }
        .encode()
        .unwrap();
        let id = a
            .send_channel_application("pieces", recipient, swarm::CONTENT_TYPE, &body)
            .await
            .unwrap();
        assert!(
            ids.insert(id.0),
            "independent application message identities"
        );
        receive_piece(&mut events, id, &body).await;
    }
    let after_a = sender.persistence_diagnostics();
    let after_b = receiver.persistence_diagnostics();
    println!(
        "{}",
        serde_json::json!({
            "event":"piece_profile_write_measurement", "blocks":16, "payload_bytes":65536,
            "sender_wrapper_saves":after_a.calls["explicit"].completed-before_a.calls["explicit"].completed,
            "receiver_event_saves":after_b.calls["event"].completed-before_b.calls["event"].completed,
            "sender_profile_bytes":after_a.profile.committed_bytes-before_a.profile.committed_bytes,
            "receiver_profile_bytes":after_b.profile.committed_bytes-before_b.profile.committed_bytes,
        })
    );
    assert_eq!(
        after_a.calls["explicit"].requested, before_a.calls["explicit"].requested,
        "piece transport must not request a whole-profile wrapper save"
    );
    assert_eq!(
        after_b.calls["event"].requested, before_b.calls["event"].requested,
        "piece events use the separate verified piece journal"
    );

    // Existing channel keys and roster are already durable. Fail only profile
    // replacement: transporting another file record must not require a new
    // profile save or manufacture a text delivery ACK. The piece cache remains
    // responsible for validating/journaling data before file completion.
    let mut retained = Vec::new();
    for name in ["sender", "receiver"] {
        let path = dir.path().join(name);
        let saved = dir.path().join(format!("{name}-retained"));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        retained.push((path, saved, bytes));
    }
    let body = swarm::Message::Discover { after: None }.encode().unwrap();
    let id = a
        .send_channel_application("pieces", recipient, swarm::CONTENT_TYPE, &body)
        .await
        .unwrap();
    receive_piece(&mut events, id, &body).await;
    while let Ok(event) = receipts.try_recv() {
        assert!(
            !matches!(event, ClientEvent::ChannelDirectDelivered { message_id, .. } if ids.contains(&message_id.0) || message_id == id),
            "hop acceptance is not an authenticated file-completion receipt"
        );
    }
    let ordinary_before = sender.persistence_diagnostics();
    assert!(
        a.send_channel_direct("pieces", recipient, b"ordinary private text")
            .await
            .is_err(),
        "ordinary private text keeps the fallible profile barrier"
    );
    let ordinary_after = sender.persistence_diagnostics();
    assert_eq!(
        ordinary_after.calls["explicit"].failed,
        ordinary_before.calls["explicit"].failed + 1
    );
    drop(a);
    drop(b);
    for peer in peers {
        assert!(
            peer.shutdown().await.is_err(),
            "explicit shutdown storage failure remains visible"
        );
    }
    for (path, saved, bytes) in retained {
        assert_eq!(std::fs::read(&saved).unwrap(), bytes);
        std::fs::remove_dir(path).unwrap();
    }
}
