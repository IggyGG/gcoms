use super::*;
use async_trait::async_trait;
use gcoms_channel_service::api::{Config, CreationPolicy, Service};
use gcoms_sdk::hosted as wire;
use std::sync::atomic::{AtomicBool, Ordering};

struct TransportFixture {
    service: Service,
    lose_acceptance: AtomicBool,
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
