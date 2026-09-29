use super::*;
use async_trait::async_trait;
use gcoms_channel_service::api::{Config, CreationPolicy, Service};
use gcoms_sdk::hosted as wire;
use std::sync::atomic::{AtomicBool, Ordering};

struct TransportFixture {
    service: Service,
    lose_acceptance: AtomicBool,
    lose_acknowledgment: AtomicBool,
}
#[async_trait]
impl Transport for TransportFixture {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        let reply = self.service.request(
            wire::Request {
                version: wire::VERSION,
                channel,
                operation,
            },
            now(),
        );
        if matches!(reply, wire::Reply::Accepted(_))
            && self.lose_acceptance.swap(false, Ordering::SeqCst)
        {
            return Err("injected lost response after fsync".into());
        }
        if matches!(reply, wire::Reply::Acknowledged)
            && self.lose_acknowledgment.swap(false, Ordering::SeqCst)
        {
            return Err("injected lost recipient receipt response after fsync".into());
        }
        Ok(reply)
    }
}
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    crate::private_fs::make_private(dir.path(), true).unwrap();
    dir
}
fn service(dir: &Path) -> Arc<TransportFixture> {
    Arc::new(TransportFixture {
        service: Service::open(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            directory: dir.into(),
            tls_terminated_upstream: false,
            creation: CreationPolicy::Public,
            max_channels: 5,
            max_total_bytes: 128 * 1024 * 1024,
            channel_bytes: 64 * 1024 * 1024,
            channel_records: 1000,
            requests_per_second: 100,
            source_requests_per_second: 100,
            blocked_channels: vec![],
            blocked_sources: vec![],
            motd: String::new(),
            rules: String::new(),
            operator_contact: String::new(),
        })
        .unwrap(),
        lose_acceptance: AtomicBool::new(false),
        lose_acknowledgment: AtomicBool::new(false),
    })
}
fn new_client(
    session: HostedSession,
    phase: Phase,
    pending: Pending,
    dir: &Path,
    transport: Arc<dyn Transport>,
    link: Option<api::InviteLink>,
) -> Client {
    let channel = session.policy().channel_id();
    let (storage, existing) =
        storage::Storage::open(&dir.join(filename(channel)), [99; 32], channel).unwrap();
    assert!(existing.is_none());
    Client::new(
        session,
        state::NewClient {
            alias: "test".into(),
            endpoint: "https://example.invalid/v1/hosted".into(),
            phase,
            pending,
            access_code: None,
            join_link: link,
        },
        storage,
        [99; 32],
        transport,
    )
    .unwrap()
}
async fn owner(dir: &Path, transport: Arc<dyn Transport>) -> Client {
    let session = HostedSession::create(&IdentityKeypair::generate(), "owner", 500, true).unwrap();
    let pending = Pending::Create {
        policy: encode(&session.policy().encode().unwrap()),
        genesis: encode(&session.export_group_info().unwrap()),
    };
    let mut client = new_client(session, Phase::Creating, pending, dir, transport, None);
    client.flush_one().await.unwrap();
    client
}
async fn joining(
    channel: [u8; 32],
    nickname: &str,
    dir: &Path,
    transport: Arc<dyn Transport>,
) -> Client {
    let link = Link {
        channel,
        endpoint: "https://example.invalid/v1/hosted".into(),
        secret: vec![],
        single_use: false,
        expires_at: 0,
    };
    let (session, commit) = prepare_join(
        transport.as_ref(),
        &link,
        PreparedHostedJoin::new(nickname).unwrap(),
        nickname,
    )
    .await
    .unwrap();
    let info = session.proposed_group_info().unwrap().to_vec();
    new_client(
        session,
        Phase::Joining,
        Pending::Membership {
            commit,
            info,
            joining: true,
        },
        dir,
        transport,
        Some(link.export().unwrap()),
    )
}
async fn pump(client: &mut Client) {
    for _ in 0..5 {
        client.flush_one().await.unwrap();
        client.sync_page().await.unwrap();
    }
}
fn messages(client: &Client) -> Vec<api::Event> {
    client
        .events(0, 256)
        .unwrap()
        .into_iter()
        .filter(|e| matches!(e.kind, api::EventKind::Message { .. }))
        .collect()
}

#[tokio::test]
async fn lost_acceptance_restart_and_offline_receiver_preserve_exactly_one_message() {
    let server_dir = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let transport = service(server_dir.path());
    let mut alice = owner(alice_dir.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", bob_dir.path(), transport.clone()).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let id = alice
        .queue_send(api::Content::Text("private restart message".into()))
        .unwrap();
    transport.lose_acceptance.store(true, Ordering::SeqCst);
    assert!(alice.flush_one().await.is_err());
    assert_eq!(messages(&alice).len(), 1);
    drop(alice);
    let path = alice_dir.path().join(filename(channel));
    let disk = std::fs::read(&path).unwrap();
    assert!(!disk
        .windows(b"private restart message".len())
        .any(|w| w == b"private restart message"));
    let (storage, data) = storage::Storage::open(&path, [99; 32], channel).unwrap();
    let mut alice = Client::restore(
        &data.unwrap(),
        channel,
        storage,
        [99; 32],
        transport.clone(),
    )
    .unwrap();
    pump(&mut alice).await;
    assert_eq!(messages(&alice).len(), 1);
    assert!(alice.events(0,256).unwrap().iter().any(|e| matches!(e.kind, api::EventKind::Delivery { id: actual, state: api::Delivery::ServiceAccepted {..} } if actual == id)));
    assert!(!alice.events(0, 256).unwrap().iter().any(|e| matches!(
        e.kind,
        api::EventKind::Delivery {
            state: api::Delivery::Delivered,
            ..
        }
    )));
    assert!(messages(&bob).is_empty());
    pump(&mut bob).await;
    pump(&mut alice).await;
    assert!(
        !alice.events(0, 256).unwrap().iter().any(|e| matches!(
            e.kind,
            api::EventKind::Delivery {
                state: api::Delivery::Delivered,
                ..
            }
        )),
        "decrypt alone cannot acknowledge before application archive commit"
    );
    assert_eq!(messages(&bob).len(), 1);
    let events = bob.events(0, 256).unwrap();
    let through = events.last().unwrap().sequence;
    drop(bob);
    let path = bob_dir.path().join(filename(channel));
    let (storage, data) = storage::Storage::open(&path, [99; 32], channel).unwrap();
    let mut bob = Client::restore(&data.unwrap(), channel, storage, [99; 32], transport).unwrap();
    assert_eq!(bob.events(0, 256).unwrap(), events);
    bob.commit_events(through).unwrap();
    pump(&mut bob).await;
    assert!(bob.events(0, 256).unwrap().is_empty());
    pump(&mut alice).await;
    assert!(alice.events(0,256).unwrap().iter().any(|e| matches!(e.kind, api::EventKind::Delivery { id: actual, state: api::Delivery::Delivered } if actual == id)));
}

#[tokio::test]
async fn competing_admissions_and_stale_message_recover_without_changing_identity() {
    let server = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let carol_dir = private_dir();
    let transport = service(server.path());
    let mut alice = owner(alice_dir.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let id = alice
        .queue_send(api::Content::Text("queued before churn".into()))
        .unwrap();
    let mut bob = joining(channel, "bob", bob_dir.path(), transport.clone()).await;
    let mut carol = joining(channel, "carol", carol_dir.path(), transport).await;
    let carol_id = carol.session.member_id();
    pump(&mut bob).await;
    pump(&mut carol).await;
    assert_eq!(carol.session.member_id(), carol_id);
    pump(&mut alice).await;
    pump(&mut bob).await;
    pump(&mut carol).await;
    assert_eq!(alice.view().members.len(), 3);
    for member in [&bob, &carol] {
        let incoming = messages(member);
        assert_eq!(incoming.len(), 1);
        assert!(
            matches!(incoming[0].kind, api::EventKind::Message { id: actual, .. } if actual == id)
        );
    }
}

#[tokio::test]
async fn queued_control_rebases_and_revoked_sender_fails_with_authenticated_activity() {
    let server = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let transport = service(server.path());
    let mut alice = owner(alice_dir.path(), transport.clone()).await;
    let mut bob = joining(alice.archive.channel, "bob", bob_dir.path(), transport).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let id = bob
        .queue_send(api::Content::Text("queued before moderation".into()))
        .unwrap();
    alice
        .queue_control(
            HostedPolicyChange::Mode(HostedMode::Moderated, 1),
            "meeting started",
        )
        .unwrap();
    alice
        .queue_control(HostedPolicyChange::Capacity(40), "capacity changed")
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert_eq!(alice.view().capacity, 40);
    assert_eq!(bob.view().capacity, 40);
    let events = bob.events(0, 256).unwrap();
    assert!(events.iter().any(|e| matches!(&e.kind, api::EventKind::Activity { actor, reason: Some(reason), .. } if *actor == alice.session.member_id() && reason == "meeting started")));
    assert!(events.iter().any(|e| matches!(e.kind, api::EventKind::Delivery { id: actual, state: api::Delivery::Failed {..} } if actual == id)));
    assert_eq!(bob.view().pending, 0);
    assert!(messages(&alice).is_empty());
}

#[tokio::test]
async fn profile_lock_authentication_and_uncertain_save_fail_closed() {
    let server = private_dir();
    let alice_dir = private_dir();
    let transport = service(server.path());
    let mut alice = owner(alice_dir.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let path = alice_dir.path().join(filename(channel));
    assert!(storage::Storage::open(&path, [99; 32], channel).is_err());
    // Removing the parent forces atomic replacement failure after ratchet advance.
    std::fs::rename(alice_dir.path(), alice_dir.path().with_extension("moved")).unwrap();
    assert!(alice
        .queue_send(api::Content::Text("save fails".into()))
        .is_err());
    assert!(alice
        .queue_send(api::Content::Text("must not advance again".into()))
        .is_err());
    assert!(alice.flush_one().await.is_err());
    std::fs::rename(alice_dir.path().with_extension("moved"), alice_dir.path()).unwrap();
    drop(alice);
    assert!(storage::Storage::open(&path, [98; 32], channel).is_err());
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    std::fs::write(&path, raw).unwrap();
    assert!(storage::Storage::open(&path, [99; 32], channel).is_err());
}

#[tokio::test]
async fn covered_receipts_require_every_original_recipient_and_survive_lost_reply_and_service_restart(
) {
    let server_dir = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let carol_dir = private_dir();
    let transport = service(server_dir.path());
    let mut alice = owner(alice_dir.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", bob_dir.path(), transport.clone()).await;
    pump(&mut bob).await;
    let mut carol = joining(channel, "carol", carol_dir.path(), transport.clone()).await;
    pump(&mut carol).await;
    pump(&mut alice).await;
    pump(&mut bob).await;
    let id = alice
        .queue_send(api::Content::Notice("acknowledge once".into()))
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    let events = bob.events(0, 256).unwrap();
    bob.commit_events(events.last().unwrap().sequence).unwrap();
    transport.lose_acknowledgment.store(true, Ordering::SeqCst);
    assert!(bob.sync_page().await.is_err());
    pump(&mut bob).await;
    pump(&mut alice).await;
    assert!(!alice.events(0, 256).unwrap().iter().any(|e| matches!(
        e.kind,
        api::EventKind::Delivery {
            state: api::Delivery::Delivered,
            ..
        }
    )));
    // A wrong scope or changed query must not expose another sender's ledger.
    let query = wire::ReadQuery {
        after: 0,
        through: None,
        limit: 32,
    };
    let wrong = bob
        .session
        .read_proof(
            HostedReadScope::Records,
            public::query_hash(query),
            now() + 120,
        )
        .unwrap();
    let operation = wire::Operation::Receipts {
        query,
        proof: encode(&wrong.encode().unwrap()),
    };
    assert!(!operation.requires_bulk());
    assert!(matches!(
        transport.exchange(channel, operation).await.unwrap(),
        wire::Reply::Fault(_)
    ));
    let bad = carol
        .session
        .receipt(alice.session.member_id(), [0; 32], 1)
        .unwrap();
    let operation = wire::Operation::Acknowledge {
        receipts: vec![encode(&bad.encode().unwrap())],
    };
    assert!(!operation.requires_bulk());
    assert!(matches!(
        transport.exchange(channel, operation).await.unwrap(),
        wire::Reply::Fault(_)
    ));
    let mut forged = bad.encode().unwrap();
    *forged.last_mut().unwrap() ^= 1;
    assert!(HostedReceipt::decode(&forged)
        .unwrap()
        .verify(channel)
        .is_err());
    drop(alice);
    drop(bob);
    drop(carol);
    drop(transport);
    let transport = service(server_dir.path());
    let restore = |dir: &Path| {
        let (storage, bytes) =
            storage::Storage::open(&dir.join(filename(channel)), [99; 32], channel).unwrap();
        Client::restore(
            &bytes.unwrap(),
            channel,
            storage,
            [99; 32],
            transport.clone(),
        )
        .unwrap()
    };
    let mut alice = restore(alice_dir.path());
    let mut carol = restore(carol_dir.path());
    pump(&mut carol).await;
    let events = carol.events(0, 256).unwrap();
    carol
        .commit_events(events.last().unwrap().sequence)
        .unwrap();
    pump(&mut carol).await;
    pump(&mut alice).await;
    assert_eq!(alice.events(0,256).unwrap().iter().filter(|e| matches!(e.kind, api::EventKind::Delivery { id: actual, state: api::Delivery::Delivered } if actual == id)).count(), 1);
    assert_eq!(messages(&alice).len(), 1);
    assert_eq!(messages(&carol).len(), 0);
}

#[tokio::test]
async fn presence_renews_only_after_opt_in_and_off_persists_without_receipt_fanout() {
    let server_dir = private_dir();
    let alice_dir = private_dir();
    let transport = service(server_dir.path());
    let mut alice = owner(alice_dir.path(), transport).await;
    alice.renew_presence(now() + 1000).unwrap();
    assert!(messages(&alice).is_empty());
    alice
        .set_presence(
            true,
            api::Presence::Away {
                reason: "lunch".into(),
            },
        )
        .unwrap();
    pump(&mut alice).await;
    assert!(alice.view().presence_opt_in);
    let count = messages(&alice).len();
    alice.renew_presence(now() + 500).unwrap();
    assert_eq!(messages(&alice).len(), count + 1);
    pump(&mut alice).await;
    alice.set_presence(false, api::Presence::Available).unwrap();
    pump(&mut alice).await;
    let count = messages(&alice).len();
    alice.renew_presence(now() + 10000).unwrap();
    assert!(!alice.view().presence_opt_in);
    assert_eq!(messages(&alice).len(), count);
    assert_eq!(alice.view().members[0].presence, api::Presence::Unknown);
}

#[tokio::test]
async fn offline_join_shows_pending_topic_until_authorized_encrypted_handoff() {
    let server_dir = private_dir();
    let alice_dir = private_dir();
    let bob_dir = private_dir();
    let transport = service(server_dir.path());
    let mut alice = owner(alice_dir.path(), transport.clone()).await;
    alice
        .queue_send(api::Content::Topic("private current topic".into()))
        .unwrap();
    pump(&mut alice).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", bob_dir.path(), transport.clone()).await;
    pump(&mut bob).await;
    assert!(bob.view().topic_pending);
    assert!(bob.view().topic.is_empty());
    drop(bob);
    let (storage, bytes) =
        storage::Storage::open(&bob_dir.path().join(filename(channel)), [99; 32], channel).unwrap();
    let mut bob = Client::restore(&bytes.unwrap(), channel, storage, [99; 32], transport).unwrap();
    assert!(bob.view().topic_pending);
    assert!(bob
        .queue_send(api::Content::TopicState {
            topic: "forged".into(),
            through: bob.archive.cursor,
            source: 1
        })
        .is_err());
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert!(!bob.view().topic_pending);
    assert_eq!(bob.view().topic, "private current topic");
    alice
        .queue_send(api::Content::Topic("new topic".into()))
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    alice
        .queue_send(api::Content::TopicState {
            topic: "stale handoff".into(),
            through: alice.archive.cursor,
            source: 1,
        })
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert_eq!(
        bob.view().topic,
        "new topic",
        "a handoff cannot overwrite an observed topic update"
    );
    let stored = std::fs::read(
        server_dir
            .path()
            .join(filename(channel))
            .with_extension("gch"),
    )
    .unwrap();
    assert!(!stored.windows(21).any(|w| w == b"private current topic"));
}

#[tokio::test]
async fn ciphertext_piece_operations_are_scoped_bounded_and_do_not_create_chat_receipts() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let mut bob = joining(alice.archive.channel, "bob", b.path(), transport).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let reference = wire::BlobRef {
        owner: alice.session.member_id(),
        file: [31; 16],
        piece: 0,
    };
    let ciphertext = vec![47; 128 * 1024];
    let before = alice.events(0, 256).unwrap();
    assert!(matches!(
        alice
            .blob(reference, Some(ciphertext.clone()))
            .await
            .unwrap(),
        api::Reply::Done
    ));
    assert!(bob.blob(reference, Some(ciphertext.clone())).await.is_err());
    assert_eq!(
        bob.blob(reference, None).await.unwrap(),
        api::Reply::Blob(ciphertext.clone())
    );
    assert_eq!(alice.events(0, 256).unwrap(), before);
    assert!(alice
        .blob(reference, Some(vec![0; wire::MAX_BLOB_BYTES + 1]))
        .await
        .is_err());
    alice
        .queue_control(HostedPolicyChange::Kick(bob.session.member_id()), "removed")
        .unwrap();
    alice.flush_one().await.unwrap();
    assert!(bob.blob(reference, None).await.is_err());
    assert_eq!(
        alice.blob(reference, None).await.unwrap(),
        api::Reply::Blob(ciphertext)
    );
}

#[tokio::test]
async fn file_inbox_survives_chat_commit_and_restart_and_identified_send_retries() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", b.path(), transport.clone()).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let content = api::Content::File {
        content_type: gcoms_sdk::sharing_v2::OFFER_TYPE.into(),
        body: b"encrypted transport descriptor".to_vec(),
    };
    let id = [77; 32];
    alice.queue_send_identified(id, content.clone()).unwrap();
    transport.lose_acceptance.store(true, Ordering::SeqCst);
    assert!(alice.flush_one().await.is_err());
    alice.queue_send_identified(id, content.clone()).unwrap();
    assert!(alice
        .queue_send_identified(id, api::Content::Text("changed".into()))
        .is_err());
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert_eq!(alice.file_events(256).unwrap().len(), 1);
    let events = bob.events(0, 256).unwrap();
    bob.commit_events(events.last().unwrap().sequence).unwrap();
    assert!(bob.events(0, 256).unwrap().is_empty());
    assert_eq!(bob.file_events(256).unwrap().len(), 1);
    drop(bob);
    let (storage, data) =
        storage::Storage::open(&b.path().join(filename(channel)), [99; 32], channel).unwrap();
    let mut bob = Client::restore(&data.unwrap(), channel, storage, [99; 32], transport).unwrap();
    let files = bob.file_events(256).unwrap();
    assert_eq!(files.len(), 1);
    assert!(
        matches!(&files[0].kind, api::EventKind::Message { id: actual, content: body, .. } if *actual == id && *body == content)
    );
    assert!(bob.commit_file_events(bob.archive.cursor + 1).is_err());
    bob.commit_file_events(files[0].sequence).unwrap();
    assert!(bob.file_events(256).unwrap().is_empty());
    alice.queue_send_identified(id, content).unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert!(bob.file_events(256).unwrap().is_empty());
}

#[tokio::test]
async fn file_completion_is_covered_authenticated_and_allowed_without_voice() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let mut bob = joining(alice.archive.channel, "bob", b.path(), transport).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    alice
        .queue_control(HostedPolicyChange::Mode(HostedMode::Moderated, 1), "")
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert!(bob
        .queue_send(api::Content::Text("not voiced".into()))
        .is_err());
    let completion = gcoms_sdk::sharing_v2::Completion {
        publisher: alice.session.member_id(),
        file: [9; 16],
        sha256: [8; 32],
    };
    let content = api::Content::File {
        content_type: gcoms_sdk::sharing_v2::COMPLETION_TYPE.into(),
        body: postcard::to_allocvec(&completion).unwrap(),
    };
    assert_eq!(state::kind(&content), HostedMessageKind::Receipt);
    let mut invalid = content.clone();
    if let api::Content::File { body, .. } = &mut invalid {
        body.push(0);
    }
    assert!(bob.queue_send(invalid).is_err());
    bob.queue_send(content).unwrap();
    pump(&mut bob).await;
    pump(&mut alice).await;
    assert_eq!(alice.file_events(256).unwrap().len(), 1);
    let before = alice.archive.cursor;
    let events = alice.events(0, 256).unwrap();
    alice
        .commit_events(events.last().unwrap().sequence)
        .unwrap();
    pump(&mut alice).await;
    assert_eq!(
        before, alice.archive.cursor,
        "completion creates no receipt fanout"
    );
}

#[cfg(feature = "files")]
mod modern_files;

#[tokio::test]
async fn hosted_directory_publication_is_operator_authenticated_and_receivers_apply_privacy() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", b.path(), transport.clone()).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    assert!(bob
        .queue_control(HostedPolicyChange::Listing(b"#forged".to_vec().into()), "")
        .is_err());
    for invalid in ["bad name", "bad\nname", &"a".repeat(65)] {
        assert!(alice
            .queue_control(
                HostedPolicyChange::Listing(invalid.as_bytes().to_vec().into()),
                ""
            )
            .is_err());
    }
    alice
        .queue_control(HostedPolicyChange::Listing(b"#public".to_vec().into()), "")
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    assert_eq!(bob.view().discovery, api::Discovery::Public);
    assert!(bob.events(0, 256).unwrap().iter().any(|event| matches!(&event.kind, api::EventKind::Activity { change: api::Change::Listing(name), .. } if name == "#public")));
    let wire::Reply::Directory { entries, .. } = transport
        .exchange(
            [0; 32],
            wire::Operation::Directory {
                after: None,
                limit: 16,
            },
        )
        .await
        .unwrap()
    else {
        panic!("directory")
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].channel, channel);
    alice
        .queue_control(HostedPolicyChange::Discovery(HostedDiscovery::Private), "")
        .unwrap();
    pump(&mut alice).await;
    pump(&mut bob).await;
    let wire::Reply::Directory { entries, .. } = transport
        .exchange(
            [0; 32],
            wire::Operation::Directory {
                after: None,
                limit: 16,
            },
        )
        .await
        .unwrap()
    else {
        panic!("directory")
    };
    assert!(entries.is_empty());
    assert_eq!(bob.view().discovery, api::Discovery::Private);
}

mod capacity;
