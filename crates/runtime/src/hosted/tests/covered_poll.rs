use super::*;
use std::sync::Mutex;

struct Counting {
    inner: Arc<TransportFixture>,
    operations: Mutex<Vec<wire::Operation>>,
    legacy: bool,
}
#[async_trait]
impl Transport for Counting {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        self.operations.lock().unwrap().push(operation.clone());
        let mut reply = self.inner.exchange(channel, operation).await?;
        if self.legacy {
            if let wire::Reply::Info(info) = &mut reply {
                info.extensions.retain(|e| e != "covered-poll-v1");
            }
        }
        Ok(reply)
    }
}
impl Counting {
    fn take(&self) -> Vec<wire::Operation> {
        std::mem::take(&mut *self.operations.lock().unwrap())
    }
    fn one_poll(&self, acknowledgments: usize) {
        let operations = self.take();
        assert_eq!(
            operations.len(),
            1,
            "one covered exchange per steady-state cycle"
        );
        assert!(!operations[0].requires_bulk());
        assert!(
            matches!(&operations[0], wire::Operation::Poll { acknowledgments: a, .. } if a.len()==acknowledgments)
        );
    }
}
fn commit(client: &mut Client) {
    if let Some(event) = client.events(0, 256).unwrap().last() {
        client.commit_events(event.sequence).unwrap();
    }
}
fn delivered(client: &Client, id: [u8; 32]) -> bool {
    client.events(0, 256).unwrap().iter().any(|event| {
        matches!(event.kind,
        api::EventKind::Delivery { id: got, state: api::Delivery::Delivered } if got == id)
    })
}
async fn journey(legacy: bool) {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let transport = Arc::new(Counting {
        inner: service(server.path()),
        operations: Mutex::new(Vec::new()),
        legacy,
    });
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", b.path(), transport.clone()).await;
    for _ in 0..3 {
        pump(&mut alice).await;
        pump(&mut bob).await;
        commit(&mut alice);
        commit(&mut bob);
    }
    let id = alice
        .queue_send(api::Content::Text("combined covered poll".into()))
        .unwrap();
    assert!(alice.flush_one().await.unwrap());
    transport.take();
    bob.sync_page().await.unwrap();
    if !legacy {
        transport.one_poll(0);
    }
    assert!(messages(&bob).iter().any(|event| matches!(&event.kind,
        api::EventKind::Message { content: api::Content::Text(text), .. } if text=="combined covered poll")));
    alice.sync_page().await.unwrap();
    assert!(
        !delivered(&alice, id),
        "uncommitted consumer events must not be acknowledged"
    );
    commit(&mut bob);
    if !legacy {
        transport.take();
    }
    bob.sync_page().await.unwrap();
    if !legacy {
        transport.one_poll(1);
    }
    alice.sync_page().await.unwrap();
    assert!(delivered(&alice, id));
    if !legacy {
        transport.one_poll(0);
    } else {
        let operations = transport.take();
        assert!(!operations
            .iter()
            .any(|o| matches!(o, wire::Operation::Poll { .. })));
        assert!(operations
            .iter()
            .any(|o| matches!(o, wire::Operation::Read { .. })));
        assert!(operations
            .iter()
            .any(|o| matches!(o, wire::Operation::Receipts { .. })));
        assert!(operations
            .iter()
            .any(|o| matches!(o, wire::Operation::Acknowledge { .. })));
    }
}
#[tokio::test]
async fn covered_poll_combines_recovery_only_after_durable_consumer_commit() {
    journey(false).await;
}
#[tokio::test]
async fn covered_poll_preserves_older_service_receipt_flow() {
    journey(true).await;
}

#[tokio::test]
async fn covered_poll_rejects_wrong_receipt_scope_before_accepting_acknowledgments() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", b.path(), transport.clone()).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let id = alice
        .queue_send(api::Content::Text("scope control".into()))
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    let query = wire::ReadQuery {
        after: bob.archive.cursor - 1,
        through: None,
        limit: 1,
    };
    let proof = encode(
        &bob.session
            .read_proof(
                HostedReadScope::Records,
                public::query_hash(query),
                now() + 120,
            )
            .unwrap()
            .encode()
            .unwrap(),
    );
    let wire::Reply::Records(page) = transport
        .exchange(
            channel,
            wire::Operation::Read {
                query,
                proof: proof.clone(),
            },
        )
        .await
        .unwrap()
    else {
        panic!("record");
    };
    let wire::RecordItem::Inline(bytes) = &page.records[0] else {
        panic!("small message");
    };
    let record = gcoms_channel_service::Record::decode(&decode(bytes).unwrap()).unwrap();
    let receipt = encode(
        &bob.session
            .receipt(alice.session.member_id(), record.id(), record.sequence)
            .unwrap()
            .encode()
            .unwrap(),
    );
    let request = wire::Operation::Poll {
        query,
        proof: proof.clone(),
        acknowledgments: vec![receipt.clone()],
        receipts: Some(wire::ReceiptQuery {
            query,
            proof: proof.clone(),
        }),
    };
    assert!(!request.requires_bulk());
    assert!(matches!(
        transport.exchange(channel, request).await.unwrap(),
        wire::Reply::Fault(_)
    ));
    alice.sync_page().await.unwrap();
    assert!(!delivered(&alice, id));
    let oversized = wire::Operation::Poll {
        query,
        proof: proof.clone(),
        acknowledgments: vec![receipt.clone(); 17],
        receipts: None,
    };
    assert!(matches!(
        transport.exchange(channel, oversized).await.unwrap(),
        wire::Reply::Fault(_)
    ));
    assert!(matches!(
        transport
            .exchange(
                channel,
                wire::Operation::Poll {
                    query,
                    proof,
                    acknowledgments: vec![receipt],
                    receipts: None
                }
            )
            .await
            .unwrap(),
        wire::Reply::Polled {
            acknowledged: 1,
            ..
        }
    ));
    alice.sync_page().await.unwrap();
    assert!(delivered(&alice, id));
}
