#![cfg(all(feature = "experimental-gc2", feature = "client-persist"))]
use gcoms_node::{
    node::{start_persistent_restored, Ev, NodeConfig, NodeProfile},
    NodeHandle,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

type Archive = Arc<Mutex<Vec<u8>>>;
async fn endpoint_with_profile(
    seed: u8,
    archive: Archive,
    restore: Option<&[u8]>,
    profile: NodeProfile,
) -> NodeHandle {
    let node = start_persistent_restored(
        NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile,
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(move |bytes| {
            *archive.lock().unwrap() = bytes;
            Ok(())
        }),
        restore,
    )
    .await
    .unwrap();
    node.enable_durable_applications().await.unwrap();
    node
}

async fn endpoint(seed: u8, archive: Archive, restore: Option<&[u8]>) -> NodeHandle {
    endpoint_with_profile(seed, archive, restore, NodeProfile::gc2_session_fixture()).await
}

async fn receive(node: &NodeHandle, expected: usize) -> Vec<gcoms_node::node::ApplicationDelivery> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let messages = node.application_inbox(0, 32).await.unwrap();
            if messages.len() == expected {
                return messages;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("GC2 application delivery timeout")
}
async fn receipt(node: &NodeHandle, id: [u8; 16]) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if matches!(node.next_event().await,Some(Ev::DirectDelivery{msg_id,..}) if msg_id==id) {
                return;
            }
        }
    })
    .await
    .expect("GC2 application ACK timeout");
}

async fn media(node: &NodeHandle, expected: &[u8]) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(Ev::VolatileApplication { body, .. }) = node.next_event().await {
                assert_eq!(body, expected);
                return;
            }
        }
    })
    .await
    .expect("GC2 volatile event timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gc2_sessions_carry_durable_applications_over_tls_and_resume_after_restart() {
    let aa = Archive::default();
    let ba = Archive::default();
    let a = endpoint(61, aa.clone(), None).await;
    let mut b = endpoint(62, ba.clone(), None).await;
    let original = b.current_info().await.unwrap();
    for index in 0..8u8 {
        a.send_durable_1to1(&original, &vec![index; 11 * 1024], None)
            .await
            .unwrap();
    }
    let delivered = receive(&b, 8).await;
    assert_eq!(
        delivered.iter().map(|m| m.body[0]).collect::<Vec<_>>(),
        (0..8u8).collect::<Vec<_>>()
    );
    receipt(&a, delivered.last().unwrap().message_id).await;
    let transient = vec![0xa7; 1024];
    a.send_volatile_application(&original, &transient)
        .await
        .unwrap();
    media(&b, &transient).await;
    assert_eq!(b.application_inbox(0, 32).await.unwrap().len(), 8);
    let saved = ba.lock().unwrap().clone();
    assert_eq!(&saved[..6], b"GCNSTL");
    b.shutdown().await;
    b = endpoint(62, ba, Some(&saved)).await;
    assert_eq!(b.info.identity_pk, original.identity_pk);
    let restored = receive(&b, 8).await;
    assert_eq!(
        restored.iter().map(|m| m.message_id).collect::<Vec<_>>(),
        delivered.iter().map(|m| m.message_id).collect::<Vec<_>>()
    );
    // Publish the renewed authenticated route in a reverse application frame.
    b.send_durable_1to1(&a.info, b"resumed GC2", None)
        .await
        .unwrap();
    let reverse = receive(&a, 1).await;
    assert_eq!(reverse[0].body, b"resumed GC2");
    receipt(&b, reverse[0].message_id).await;
    a.send_durable_1to1(&original, b"old caller contact, current session", None)
        .await
        .unwrap();
    let final_delivery = receive(&b, 9).await;
    assert_eq!(
        final_delivery[8].body,
        b"old caller contact, current session"
    );
    receipt(&a, final_delivery[8].message_id).await;
    b.send_volatile_application(&a.info, b"volatile after restart")
        .await
        .unwrap();
    media(&a, b"volatile after restart").await;
    assert_eq!(a.application_inbox(0, 32).await.unwrap().len(), 1);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gc2_natural_carrier_delivers_durable_applications_both_ways() {
    let aa = Archive::default();
    let ba = Archive::default();
    let a = endpoint_with_profile(71, aa, None, NodeProfile::gc2_carrier_fixture(None, 1)).await;
    let b = endpoint_with_profile(72, ba, None, NodeProfile::gc2_carrier_fixture(None, 1)).await;
    let original = b.current_info().await.unwrap();
    a.send_durable_1to1(&original, b"natural carrier delivery", None)
        .await
        .unwrap();
    let delivered = receive(&b, 1).await;
    assert_eq!(delivered[0].body, b"natural carrier delivery");
    receipt(&a, delivered[0].message_id).await;
    b.send_durable_1to1(&a.info, b"natural reverse", None)
        .await
        .unwrap();
    let reverse = receive(&a, 1).await;
    assert_eq!(reverse[0].body, b"natural reverse");
    receipt(&b, reverse[0].message_id).await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gc2_carrier_archive_cannot_restore_under_a_gc1_profile() {
    let aa = Archive::default();
    let a = endpoint_with_profile(
        73,
        aa.clone(),
        None,
        NodeProfile::gc2_carrier_fixture(None, 1),
    )
    .await;
    let b = endpoint_with_profile(
        74,
        Archive::default(),
        None,
        NodeProfile::gc2_carrier_fixture(None, 1),
    )
    .await;
    let original = b.current_info().await.unwrap();
    a.send_durable_1to1(&original, b"seed the archive", None)
        .await
        .unwrap();
    let _ = receive(&b, 1).await;
    a.shutdown().await;
    let archive = aa.lock().unwrap().clone();
    assert_eq!(&archive[..6], b"GCNSTL");
    let error = start_persistent_restored(
        NodeConfig {
            seed: [73; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(|_| Ok(())),
        Some(&archive),
    )
    .await
    .err()
    .expect("a GC/1 profile must not restore a GC/2 carrier archive");
    assert!(error.contains("GC/2"), "{error}");
    b.shutdown().await;
}
