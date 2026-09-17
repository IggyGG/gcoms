use gcoms_node::node::{start, Ev, NodeConfig, Reachability};
use gcoms_node::proto::{NodeInfo, PresenceMode};

use std::sync::Arc;

#[cfg(feature = "client-persist")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "client-persist")]
use std::sync::Mutex;

async fn spawn(seed: u8) -> gcoms_node::NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start")
}

#[cfg(feature = "client-persist")]
async fn spawn_persistent(seed: u8, snapshots: Arc<Mutex<Vec<Vec<u8>>>>) -> gcoms_node::NodeHandle {
    let node = gcoms_node::node::start_persistent(
        NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        Arc::new(move |state| {
            snapshots.lock().unwrap().push(state);
            Ok(())
        }),
    )
    .await
    .expect("persistent node start");
    node.enable_durable_applications().await.unwrap();
    node
}

struct Seen {
    session: Option<(Vec<u8>, String)>,
    message: Option<MessageSeen>,
}

struct MessageSeen {
    peer_pk: Vec<u8>,
    message_id: [u8; 16],
    latency_ms: u64,
}

async fn await_delivery(h: &gcoms_node::NodeHandle, want: &str) -> Seen {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut seen = Seen {
        session: None,
        message: None,
    };
    loop {
        let ev = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for delivery: {want}"))
            .expect("node ended");
        match ev {
            Ev::IdentityUpdated { .. } => {}
            Ev::SessionOpened {
                peer_pk,
                safety_number,
            } => {
                seen.session = Some((peer_pk, safety_number));
            }
            Ev::Message {
                peer_pk,
                msg_id,
                text,
                latency_hint_ms,
                ..
            } => {
                if text == want.as_bytes() {
                    seen.message = Some(MessageSeen {
                        peer_pk,
                        message_id: msg_id,
                        latency_ms: latency_hint_ms,
                    });
                    return seen;
                }
            }
            Ev::DirectDelivery { .. }
            | Ev::PresenceChanged { .. }
            | Ev::ChannelPresenceChanged { .. }
            | Ev::ChannelMessage { .. }
            | Ev::ChannelRemoved { .. } => {}
            Ev::ChannelDelivery { .. }
            | Ev::ChannelRosterChanged { .. }
            | Ev::ChannelDirectMessage { .. }
            | Ev::ChannelDirectDelivery { .. } => {}
            Ev::VolatileApplication { .. } => {
                panic!("legacy direct test received volatile traffic")
            }
            Ev::Lagged { skipped } => panic!("event consumer lagged by {skipped}"),
        }
    }
}

async fn await_receipt(h: &gcoms_node::NodeHandle, peer: &[u8], message_id: [u8; 16]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let event = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .expect("timeout waiting for recipient ACK")
            .expect("node ended");
        if let Ev::DirectDelivery { peer_pk, msg_id } = event {
            if peer_pk == peer && msg_id == message_id {
                return;
            }
        }
    }
}

async fn await_presence(h: &gcoms_node::NodeHandle, peer: &[u8], want: Reachability) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let event = tokio::time::timeout_at(deadline, h.next_event())
            .await
            .expect("timeout waiting for presence")
            .expect("node ended");
        if let Ev::PresenceChanged {
            peer_pk,
            reachability,
        } = event
        {
            if peer_pk == peer && reachability == want {
                return;
            }
        }
    }
}

async fn assert_no_event(h: &gcoms_node::NodeHandle, duration: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        match tokio::time::timeout_at(deadline, h.next_event()).await {
            Err(_) => return,
            Ok(Some(Ev::Message { .. })) => {
                panic!("replayed direct record emitted a duplicate message")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("node ended"),
        }
    }
}

async fn assert_no_presence_event(h: &gcoms_node::NodeHandle, duration: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        match tokio::time::timeout_at(deadline, h.next_event()).await {
            Err(_) => return,
            Ok(Some(Ev::PresenceChanged { .. })) => panic!("unexpected direct presence event"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("node ended"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_first_messages_converge_and_continue_exactly_once() {
    let a = spawn(0xC1).await;
    let b = spawn(0xC2).await;
    let a_info = a.info.clone();
    let b_info = b.info.clone();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let send_a = {
        let a = a.clone();
        let b_info = b_info.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            a.send_1to1(&b_info, b"simultaneous from a", None).await
        })
    };
    let send_b = {
        let b = b.clone();
        let a_info = a_info.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            b.send_1to1(&a_info, b"simultaneous from b", None).await
        })
    };
    barrier.wait().await;
    send_a.await.unwrap().unwrap();
    send_b.await.unwrap().unwrap();

    let at_a = await_delivery(&a, "simultaneous from b")
        .await
        .message
        .unwrap();
    let at_b = await_delivery(&b, "simultaneous from a")
        .await
        .message
        .unwrap();
    await_receipt(&a, &b_info.identity_pk, at_b.message_id).await;
    await_receipt(&b, &a_info.identity_pk, at_a.message_id).await;

    a.send_1to1(&b_info, b"after convergence a", None)
        .await
        .unwrap();
    b.send_1to1(&a_info, b"after convergence b", None)
        .await
        .unwrap();
    await_delivery(&a, "after convergence b").await;
    await_delivery(&b, "after convergence a").await;
    assert_no_event(&a, std::time::Duration::from_millis(250)).await;
    assert_no_event(&b, std::time::Duration::from_millis(250)).await;

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_presence_is_encrypted_withdrawable_and_refreshed_by_authenticated_traffic() {
    let a = spawn(0xD1).await;
    let b = spawn(0xD2).await;

    assert!(a
        .send_direct_presence(&b.info, PresenceMode::Away, 30, None)
        .await
        .is_err());
    a.set_direct_presence_opt_in(&b.info, true, None)
        .await
        .expect("sender opt in");
    a.send_direct_presence(&b.info, PresenceMode::Away, 30, None)
        .await
        .expect("send one-sided lease");
    assert_no_presence_event(&b, std::time::Duration::from_millis(250)).await;
    b.set_direct_presence_opt_in(&a.info, true, None)
        .await
        .expect("receiver opt in");
    a.send_direct_presence(&b.info, PresenceMode::Away, 30, None)
        .await
        .expect("send away lease");
    await_presence(&b, &a.info.identity_pk, Reachability::Away).await;

    a.send_1to1(&b.info, b"passive reachability", None)
        .await
        .expect("send direct message");
    await_presence(&b, &a.info.identity_pk, Reachability::RecentlyReachable).await;

    a.set_direct_presence_opt_in(&b.info, false, None)
        .await
        .expect("withdraw presence");
    await_presence(&b, &a.info.identity_pk, Reachability::Unknown).await;

    a.send_1to1(&b.info, b"after withdrawal", None)
        .await
        .expect("send direct message");
    await_delivery(&b, "after withdrawal").await;
    assert_no_presence_event(&b, std::time::Duration::from_millis(250)).await;

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_to_one_via_intermediary() {
    let a = spawn(0xA1).await;
    let i = spawn(0x11).await;
    let b = spawn(0xB2).await;

    let b_info: NodeInfo = b.info.clone();
    let a_info: NodeInfo = a.info.clone();
    let i_info = i
        .provision_client_relay()
        .await
        .expect("private intermediary provision");

    a.send_1to1(&b_info, b"hello via intermediary", Some(i_info.clone()))
        .await
        .expect("send via frwd");

    let seen = await_delivery(&b, "hello via intermediary").await;
    let (peer_pk, safety) = seen.session.expect("session opened event");
    assert_eq!(peer_pk, a_info.identity_pk);
    assert_eq!(safety, a.safety_number);
    let message = seen.message.expect("message");
    assert_eq!(message.peer_pk, a_info.identity_pk);
    assert!(
        message.latency_ms < 90_000,
        "latency {}ms",
        message.latency_ms
    );
    await_receipt(&a, &b_info.identity_pk, message.message_id).await;

    b.send_1to1(&a_info, b"reply direct", None)
        .await
        .expect("reply");
    let seen = await_delivery(&a, "reply direct").await;
    assert_eq!(seen.message.unwrap().peer_pk, b_info.identity_pk);

    a.send_1to1(
        &b_info,
        b"second message same session",
        Some(i_info.clone()),
    )
    .await
    .expect("second send");
    await_delivery(&b, "second message same session").await;

    for _ in 0..5 {
        a.send_1to1(&b_info, b"burst", Some(i_info.clone()))
            .await
            .unwrap();
        await_delivery(&b, "burst").await;
    }

    let error = a
        .send_1to1(
            &b_info,
            b"must not use public relay card",
            Some(i.info.clone()),
        )
        .await
        .expect_err("public via card must fail closed");
    assert!(error.contains("private relay provisioning"));

    a.shutdown().await;
    b.shutdown().await;
    i.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_renewal_survives_expired_caller_card_without_exchange() {
    let a = spawn(0xA7).await;
    let b = spawn(0xB8).await;
    let mut stale_b_info = b.info.clone();
    a.send_1to1(&stale_b_info, b"establish", None)
        .await
        .unwrap();
    await_delivery(&b, "establish").await;
    let old_expiry = b.current_info().await.unwrap().primary().unwrap().expiry;
    b.renew_contacts_now().await.unwrap();
    assert!(b.current_info().await.unwrap().primary().unwrap().expiry > old_expiry);
    // Observe a reverse application frame after the signed route update. Do
    // not depend on a three-second wall-clock window while parallel TLS tests
    // contend for CPU. The caller then presents an actually expired old card.
    b.send_1to1(&a.info, b"renewal published", None)
        .await
        .unwrap();
    await_delivery(&a, "renewal published").await;
    for alias in &mut stale_b_info.aliases {
        alias.expiry = 1;
    }

    a.send_1to1(&stale_b_info, b"after old card expiry", None)
        .await
        .expect("authenticated route must override stale caller card");
    await_delivery(&b, "after old card expiry").await;

    a.shutdown().await;
    b.shutdown().await;
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread")]
async fn failed_opt_out_persistence_still_disables_sharing_in_memory() {
    let fail = Arc::new(AtomicBool::new(false));
    let sink_fail = fail.clone();
    let a = gcoms_node::node::start_persistent(
        NodeConfig {
            seed: [0xA6; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        Arc::new(move |_| {
            if sink_fail.load(Ordering::SeqCst) {
                Err("injected sink failure".into())
            } else {
                Ok(())
            }
        }),
    )
    .await
    .unwrap();
    let b = spawn(0xB7).await;
    a.set_direct_presence_opt_in(&b.info, true, None)
        .await
        .unwrap();

    fail.store(true, Ordering::SeqCst);
    assert!(a
        .set_direct_presence_opt_in(&b.info, false, None)
        .await
        .unwrap_err()
        .contains("injected sink failure"));
    assert!(a
        .send_direct_presence(&b.info, PresenceMode::Away, 30, None)
        .await
        .unwrap_err()
        .contains("not opted in"));

    a.shutdown().await;
    b.shutdown().await;
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread")]
async fn direct_presence_opt_in_survives_restart() {
    let a_snapshots = Arc::new(Mutex::new(Vec::new()));
    let b_snapshots = Arc::new(Mutex::new(Vec::new()));
    let mut a = spawn_persistent(0xA4, a_snapshots.clone()).await;
    let b = spawn_persistent(0xB5, b_snapshots).await;

    a.set_direct_presence_opt_in(&b.info, true, None)
        .await
        .unwrap();
    b.set_direct_presence_opt_in(&a.info, true, None)
        .await
        .unwrap();
    let persisted = a_snapshots.lock().unwrap().last().cloned().unwrap();
    a.shutdown().await;

    a = gcoms_node::node::start_persistent_restored(
        NodeConfig {
            seed: [0xA4; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(move |bytes| {
            a_snapshots.lock().unwrap().push(bytes);
            Ok(())
        }),
        Some(&persisted),
    )
    .await
    .unwrap();
    a.send_direct_presence(&b.info, PresenceMode::Away, 30, None)
        .await
        .expect("restored opt-in permits presence");
    await_presence(&b, &a.info.identity_pk, Reachability::Away).await;

    a.shutdown().await;
    b.shutdown().await;
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread")]
async fn restored_direct_session_propagates_fresh_route_without_card_exchange() {
    let a_snapshots = Arc::new(Mutex::new(Vec::new()));
    let b_snapshots = Arc::new(Mutex::new(Vec::new()));
    let a = spawn_persistent(0xA3, a_snapshots).await;
    let mut b = spawn_persistent(0xB4, b_snapshots.clone()).await;
    let a_info = a.info.clone();
    let original_b_info = b.info.clone();

    a.send_1to1(&original_b_info, b"before restart", None)
        .await
        .unwrap();
    await_delivery(&b, "before restart").await;

    let persisted_b = b_snapshots
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("receiver transaction was persisted before delivery");
    assert_eq!(&persisted_b[..6], b"GCNSTI");
    b.shutdown().await;

    b_snapshots.lock().unwrap().clear();
    b = gcoms_node::node::start_persistent_restored(
        NodeConfig {
            seed: [0xB4; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(move |bytes| {
            b_snapshots.lock().unwrap().push(bytes);
            Ok(())
        }),
        Some(&persisted_b),
    )
    .await
    .unwrap();
    assert_eq!(b.info.identity_pk, original_b_info.identity_pk);

    // Constructor restore retains/adopts the authenticated owner routes. No
    // manual renewal command or remote card exchange is allowed here.
    let refreshed_b_info = b.info.clone();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    a.send_1to1(&original_b_info, b"after restart", None)
        .await
        .unwrap();
    await_delivery(&b, "after restart").await;

    // This application frame must not overtake either persisted or newly
    // generated ACK records on the same reverse ratchet chain.
    b.send_1to1(&a_info, b"reverse after restore", None)
        .await
        .unwrap();
    let reverse = await_delivery(&a, "reverse after restore")
        .await
        .message
        .unwrap();
    assert_eq!(reverse.peer_pk, refreshed_b_info.identity_pk);
    await_receipt(&b, &a_info.identity_pk, reverse.message_id).await;
    assert_no_event(&a, std::time::Duration::from_millis(250)).await;

    a.shutdown().await;
    b.shutdown().await;
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restored_start_rejects_corruption_before_writing_or_accepting_work() {
    let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = writes.clone();
    let config = NodeConfig {
        seed: [0xa8; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    };
    let result = gcoms_node::node::start_persistent_restored(
        config,
        None,
        Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        Some(b"corrupt saved protocol state"),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        writes.load(Ordering::SeqCst),
        0,
        "a corrupt profile must never be replaced with an empty snapshot"
    );
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_submission_accepts_locally_while_hop_is_down_and_bounds_each_peer() {
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    let sender = spawn_persistent(0xb1, snapshots.clone()).await;
    let receiver = spawn(0xb2).await;
    let other = spawn(0xb3).await;
    let hop = spawn(0xb4).await;
    let via = hop.provision_client_relay().await.unwrap();
    hop.shutdown().await;
    // A dead first hop cannot turn durable local acceptance into a transport
    // error or monopolize the IPC caller while its network receipt times out.
    for _ in 0..32 {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sender.send_durable_1to1(
                &receiver.info,
                b"retained application job",
                Some(via.clone()),
            ),
        )
        .await
        .expect("local durable acceptance waited for a network hop")
        .unwrap();
    }
    assert!(sender
        .send_durable_1to1(&receiver.info, b"over peer quota", Some(via.clone()))
        .await
        .is_err());
    sender
        .send_durable_1to1(&other.info, b"another peer still progresses", Some(via))
        .await
        .unwrap();
    assert!(snapshots.lock().unwrap().len() >= 33);
    sender.shutdown().await;
    receiver.shutdown().await;
    other.shutdown().await;
}

#[cfg(feature = "client-persist")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unconfirmed_initiator_restart_refreshes_its_route_before_waiting_for_a_reply() {
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    let saved = snapshots.clone();
    let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = writes.clone();
    let config = || NodeConfig {
        seed: [0xc1; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    };
    let a = gcoms_node::node::start_persistent(
        config(),
        Arc::new(move |bytes| {
            // Persist boot and the initial send; refuse every incoming ACK commit.
            if count.fetch_add(1, Ordering::SeqCst) >= 2 {
                return Err("injected acknowledgement write failure".into());
            }
            saved.lock().unwrap().push(bytes);
            Ok(())
        }),
    )
    .await
    .unwrap();
    let b = spawn(0xc2).await;
    let original_a = a.info.clone();
    a.send_1to1(&b.info, b"unconfirmed before restart", None)
        .await
        .unwrap();
    await_delivery(&b, "unconfirmed before restart").await;
    let snapshot = snapshots.lock().unwrap().last().unwrap().clone();
    a.shutdown().await;
    let a = gcoms_node::node::start_persistent_restored(
        config(),
        None,
        Arc::new(|_| Ok(())),
        Some(&snapshot),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // This uses the obsolete card. The restored initiator must advertise its
    // fresh route even though the archived session was never confirmed.
    let _ = b
        .send_1to1(&original_a, b"reply after initiator restart", None)
        .await;
    await_delivery(&a, "reply after initiator restart").await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presence_ack_reports_each_authenticated_contact_without_remote_opt_in() {
    let a = spawn(0xE1).await;
    let b = spawn(0xE2).await;
    a.set_direct_presence_opt_in(&b.info, true, None)
        .await
        .unwrap();
    let mut ids = std::collections::HashSet::new();
    for _ in 0..2 {
        a.send_direct_presence(&b.info, PresenceMode::RecentlyReachable, 30, None)
            .await
            .unwrap();
        let id = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Some(Ev::DirectDelivery { peer_pk, msg_id }) = a.next_event().await {
                    assert_eq!(peer_pk, b.info.identity_pk);
                    break msg_id;
                }
            }
        })
        .await
        .expect("authenticated presence ACK");
        assert!(ids.insert(id), "refresh must acknowledge new pending work");
    }
    b.shutdown().await;
    // Offline submission may fail or remain pending; neither is peer evidence.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        a.send_direct_presence(&b.info, PresenceMode::RecentlyReachable, 30, None),
    )
    .await;
    let unexpected = tokio::time::timeout(std::time::Duration::from_millis(750), async {
        loop {
            if let Some(Ev::DirectDelivery { .. }) = a.next_event().await {
                break;
            }
        }
    })
    .await;
    assert!(
        unexpected.is_err(),
        "local send or retry cannot fabricate an ACK"
    );
    a.shutdown().await;
}
