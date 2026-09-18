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
async fn endpoint(seed: u8, archive: Archive, restore: Option<&[u8]>) -> NodeHandle {
    let node = start_persistent_restored(
        NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::gc2_session_fixture(),
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
    let saved = ba.lock().unwrap().clone();
    assert_eq!(&saved[..6], b"GCNSTK");
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
    a.shutdown().await;
    b.shutdown().await;
}
