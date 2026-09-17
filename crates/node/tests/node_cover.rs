//! Aggregate cover-vs-real behavior at a subscriber's inbox queue.
//!
//! `node_alias::cover_deposit_is_accepted_and_never_delivered` proves the
//! single-deposit invariant; this file proves the aggregate one the friend
//! group depends on: with many authenticated cover deposits interleaved with a
//! handful of real messages on the SAME queue, the subscriber receives exactly
//! the real messages — no cover leaks through, and cover never crowds out or
//! blocks a real delivery. Cover freshness/shape/replay accounting is proven by
//! the lib-level `scheduler::tests` cover tests; this is the end-to-end view.

use gcoms_node::node::{start, Ev, NodeConfig, NodeHandle, NodeProfile};
use gcoms_node::relay::RelayPush;
use gcoms_transport::{HopOutcome, Tp1Client};

async fn spawn(seed: u8) -> NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_cover_deposits_never_surface_and_real_messages_all_arrive() {
    let relay = spawn(0x81).await;
    let card = relay
        .provision_client_relay()
        .await
        .expect("relay provisioning card");
    let provision = card
        .provisioning
        .clone()
        .expect("private provisioning fields");
    let owned = provision.aliases[0].clone();

    // The receiver subscribes to the relay-backed inbox; the sender delivers
    // real 1:1 messages to it. We hold `provision` so we can also inject cover.
    let receiver = start(NodeConfig {
        seed: [0x82; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: Some(card.clone()),
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("receiver start");
    let sender = spawn(0x83).await;

    // Let the receiver attach its held-open subscription.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let client = Tp1Client::new().expect("client");
    let queue_path = gcoms_transport::encode_b64url(&owned.contact.queue_id);

    // Interleave: 8 cover deposits per real message, 5 real messages => 40
    // cover slots against 5 real deposits.
    let receiver_info = receiver.current_info().await.expect("receiver info");
    let real_texts: Vec<String> = (0..5).map(|i| format!("real-{i}")).collect();
    let mut cover_nonce = 1u8;

    for text in &real_texts {
        for _ in 0..8 {
            let cover = RelayPush::cover(
                owned.contact.queue_id,
                owned.contact.epoch,
                [cover_nonce; 16],
                owned.contact.expiry,
            )
            .encode_into_cell(
                &owned.capabilities.push,
                &owned.contact.target.relay_service_id,
            )
            .expect("encode cover")
            .encode_wire()
            .expect("wire");
            cover_nonce = cover_nonce.wrapping_add(1);
            let outcome = client
                .post_cell_pinned(
                    owned.contact.target.address,
                    owned.contact.target.relay_service_id,
                    &queue_path,
                    bytes::Bytes::from(cover),
                )
                .await
                .expect("post cover");
            // A cover deposit gets the identical receipt as a real one.
            assert_eq!(outcome, HopOutcome::Accepted(None), "cover not accepted");
        }
        sender
            .send_1to1(&receiver_info, text.as_bytes(), None)
            .await
            .expect("send real 1to1");
    }

    // Collect exactly the real messages; assert cover never appears as one.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    while seen.len() < real_texts.len() {
        let ev = tokio::time::timeout_at(deadline, receiver.next_event())
            .await
            .expect("timed out before all real messages arrived")
            .expect("event stream closed");
        if let Ev::Message { text, .. } = ev {
            assert!(
                real_texts.iter().any(|t| t.as_bytes() == text.as_slice()),
                "a non-real (cover?) payload surfaced as a message: {text:?}"
            );
            if !seen.contains(&text) {
                seen.push(text);
            }
        }
    }

    // All five real texts arrived exactly once each…
    let mut got: Vec<String> = seen
        .iter()
        .map(|b| String::from_utf8(b.clone()).unwrap())
        .collect();
    got.sort();
    assert_eq!(got, real_texts, "not exactly the real messages");

    // …and no further (cover) message shows up in a quiet drain window.
    let extra = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match receiver.next_event().await {
                Some(Ev::Message { text, .. }) => break Some(text),
                Some(_) => continue,
                None => break None,
            }
        }
    })
    .await;
    assert!(
        extra.is_err(),
        "an extra message surfaced after the real set: {extra:?}"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    relay.shutdown().await;
}
