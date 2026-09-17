#![cfg(all(unix, feature = "ipc", feature = "client-persist"))]
use gcoms_node::node::{start_persistent, NodeConfig, NodeProfile};
use gcoms_sdk::{
    ipc::Capability, serve_unix, ChannelVisibility, ClientEvent, EmbeddedClient, GcClient,
    IpcClient, MessageId,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

async fn peer(seed: u8) -> (EmbeddedClient, Arc<Mutex<Vec<Vec<u8>>>>) {
    let saved = Arc::new(Mutex::new(Vec::new()));
    let capture = saved.clone();
    let node = start_persistent(
        NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        Arc::new(move |bytes| {
            capture.lock().unwrap().push(bytes);
            Ok(())
        }),
    )
    .await
    .unwrap();
    (EmbeddedClient::new(node), saved)
}

async fn event(
    events: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    mut accepts: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let next = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("native event deadline")
            .expect("event stream closed");
        if accepts(&next) {
            return next;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tracked_ipc_native_ids_match_received_messages_and_authenticated_acks() {
    let (sender, saved) = peer(0x37).await;
    let (receiver, _) = peer(0x38).await;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("tracked.sock");
    let backend = sender.clone();
    let path = socket.clone();
    let server = tokio::spawn(async move {
        serve_unix(
            &path,
            backend,
            vec![
                Capability::IdentityRead,
                Capability::DirectMessage,
                Capability::ChannelMember,
                Capability::EventRead,
            ],
        )
        .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let ipc = IpcClient::connect(
        &socket,
        "tracked-test",
        vec![
            Capability::IdentityRead,
            Capability::DirectMessage,
            Capability::ChannelMember,
            Capability::EventRead,
        ],
    )
    .await
    .unwrap();
    let mut sender_events = ipc.subscribe_events();
    let mut receiver_events = receiver.subscribe_events();
    // Subscription handshake completes before sending. The native ACK may be
    // delivered before the caller handles the send response; its ID still matches.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let before = saved.lock().unwrap().len();
    let direct = ipc
        .send_direct_tracked(&receiver.identity().contact_card, b"tracked direct", None)
        .await
        .unwrap();
    assert_ne!(direct, MessageId([0; 16]));
    assert!(saved.lock().unwrap().len() > before);
    assert!(
        matches!(event(&mut receiver_events, |e| matches!(e, ClientEvent::DirectMessage {..})).await,
        ClientEvent::DirectMessage {message_id, body, ..} if message_id==direct && body==b"tracked direct")
    );
    event(&mut sender_events, |e| matches!(e, ClientEvent::DirectDelivered {peer_identity, message_id} if peer_identity==&receiver.node().info.identity_pk && message_id==&direct)).await;

    sender
        .create_channel("tracked-room", "sender", 4, ChannelVisibility::Private)
        .await
        .unwrap();
    let join = receiver.prepare_channel_join("receiver").await.unwrap();
    let package = receiver.channel_key_package(join).await.unwrap();
    let welcome = sender
        .admit_channel("tracked-room", &package, "receiver")
        .await
        .unwrap();
    receiver
        .join_channel(join, "tracked-room", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = saved.lock().unwrap().len();
    let channel = ipc
        .send_channel_tracked("tracked-room", b"tracked channel")
        .await
        .unwrap();
    assert_ne!(channel, direct);
    assert!(saved.lock().unwrap().len() > before);
    assert!(
        matches!(event(&mut receiver_events, |e| matches!(e, ClientEvent::ChannelMessage {body, ..} if body==b"tracked channel")).await,
        ClientEvent::ChannelMessage {message_id, ..} if message_id==channel)
    );
    event(&mut sender_events, |e| matches!(e, ClientEvent::ChannelDelivered {channel: name, message_id} if name=="tracked-room" && message_id==&channel)).await;
    drop(ipc);
    server.abort();
    let _ = server.await;
    sender.node().shutdown().await;
    receiver.node().shutdown().await;
}
