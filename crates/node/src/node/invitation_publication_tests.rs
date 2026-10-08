use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_network::{Founder, NetworkDefaults, NetworkIdentity, SignedNetworkDefaults};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Fixture {
    node: NodeHandle,
    id: [u8; 16],
    writes: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
    saved: Arc<Mutex<Vec<u8>>>,
    _home: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let writes = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    let saved = Arc::new(Mutex::new(Vec::new()));
    let (count, failure, bytes) = (writes.clone(), fail.clone(), saved.clone());
    let node = start_persistent_restored(
        NodeConfig {
            seed: [91; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(move |snapshot| {
            count.fetch_add(1, Ordering::SeqCst);
            if failure.load(Ordering::SeqCst) {
                return Err("publication storage failpoint".into());
            }
            *bytes.lock().unwrap() = snapshot;
            Ok(())
        }),
        None,
    )
    .await
    .unwrap();
    node.create_channel(
        "friends",
        "owner",
        8,
        crate::channel::ChannelVisibility::Private,
    )
    .await
    .unwrap();
    let issued = node
        .create_reusable_invitation(
            "friends",
            gcoms_core::invitation::InvitationPolicy {
                expires_at: None,
                max_admissions: None,
            },
        )
        .await
        .unwrap();
    let root = IdentityKeypair::from_seed([93; 32]);
    let now = now_unix();
    let network = NetworkIdentity {
        trusted_key_b64: URL_SAFE_NO_PAD.encode(root.public_bytes()),
        signed_defaults: SignedNetworkDefaults::sign(
            NetworkDefaults {
                version: 1,
                network_id: "fixture.example".into(),
                sequence: 1,
                issued_at: now,
                expires_at: now + 3600,
                provider_urls: vec!["https://provider.fixture.example/".into()],
                founders: vec![Founder {
                    name: "r1.relays.fixture.example".into(),
                    service_id: [5; 32],
                    address_hints: vec!["127.0.0.1:443".parse().unwrap()],
                }],
                dns_domain: "fixture.example".into(),
            },
            &root,
            vec![],
        )
        .unwrap(),
    };
    let home = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(home.path(), true).unwrap();
    node.configure_invitation_directory(
        gcoms_network_client::NetworkClient::open(
            &home.path().join("network"),
            gcoms_network_client::InstalledNetwork {
                trusted_key_b64: network.trusted_key_b64,
                signed_defaults: network.signed_defaults,
            },
        )
        .unwrap(),
    )
    .unwrap();
    // No grant: the real publication path fails locally before any HTTP request.
    Fixture {
        node,
        id: issued.summary.id,
        writes,
        fail,
        saved,
        _home: home,
    }
}

fn publication(f: &Fixture) -> Publication {
    f.node.state.upgrade().unwrap().lock().unwrap().channels["friends"]
        .invitations
        .records[0]
        .publication
        .clone()
        .unwrap()
}

#[tokio::test]
async fn failed_publication_retries_reuse_durable_ciphertext_without_profile_writes() {
    let f = fixture().await;
    let before = f.writes.load(Ordering::SeqCst);
    let error = publish(&f.node, "friends", f.id).await.unwrap_err();
    assert!(error.contains("network grant"), "{error}");
    assert_eq!(
        f.writes.load(Ordering::SeqCst) - before,
        1,
        "only the new descriptor needs a durable write; failure status is volatile"
    );
    let original = publication(&f);
    let saved = f.saved.lock().unwrap().clone();
    for _ in 0..64 {
        assert!(publish(&f.node, "friends", f.id)
            .await
            .unwrap_err()
            .contains("network grant"));
    }
    assert_eq!(
        f.writes.load(Ordering::SeqCst) - before,
        1,
        "offline retries must not rewrite the complete profile"
    );
    let retried = publication(&f);
    assert!(retried.descriptor == original.descriptor);
    assert_eq!(
        retried.reference.encode().unwrap(),
        original.reference.encode().unwrap()
    );
    assert_eq!(retried.published_until, None);
    assert!(retried.last_error.is_some());
    assert_eq!(*f.saved.lock().unwrap(), saved);
    f.node.shutdown().await;
}

#[tokio::test]
async fn failed_descriptor_checkpoint_rolls_back_before_publication() {
    let f = fixture().await;
    let saved = f.saved.lock().unwrap().clone();
    f.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        publish(&f.node, "friends", f.id).await.unwrap_err(),
        "publication storage failpoint"
    );
    assert!(
        f.node.state.upgrade().unwrap().lock().unwrap().channels["friends"]
            .invitations
            .records[0]
            .publication
            .is_none()
    );
    assert_eq!(*f.saved.lock().unwrap(), saved);
    f.fail.store(false, Ordering::SeqCst);
    f.node.shutdown().await;
}

#[tokio::test]
async fn confirmed_publication_is_saved_once_and_late_failure_cannot_undo_it() {
    let f = fixture().await;
    assert!(publish(&f.node, "friends", f.id).await.is_err());
    let pending = publication(&f);
    let before = f.writes.load(Ordering::SeqCst);
    {
        let state = f.node.state.upgrade().unwrap();
        let mut st = state.lock().unwrap();
        finish_publication(&mut st, "friends", f.id, &pending.descriptor, &Ok(())).unwrap();
        finish_publication(&mut st, "friends", f.id, &pending.descriptor, &Ok(())).unwrap();
        finish_publication(
            &mut st,
            "friends",
            f.id,
            &pending.descriptor,
            &Err("late offline result".into()),
        )
        .unwrap();
    }
    assert_eq!(f.writes.load(Ordering::SeqCst) - before, 1);
    let confirmed = publication(&f);
    assert_eq!(
        confirmed.published_until,
        Some(pending.descriptor.body.expires_at)
    );
    assert!(confirmed.last_error.is_none());
    // The actual API must now reuse the confirmation despite the missing grant.
    assert_eq!(
        f.node
            .share_reusable_invitation("friends", f.id)
            .await
            .unwrap(),
        pending.reference.encode().unwrap()
    );
    assert_eq!(f.writes.load(Ordering::SeqCst) - before, 1);
    f.node.shutdown().await;
}

#[tokio::test]
async fn confirmation_storage_failure_remains_pending_until_saved() {
    let f = fixture().await;
    assert!(publish(&f.node, "friends", f.id).await.is_err());
    let pending = publication(&f);
    let saved = f.saved.lock().unwrap().clone();
    let state = f.node.state.upgrade().unwrap();
    {
        let mut st = state.lock().unwrap();
        f.fail.store(true, Ordering::SeqCst);
        assert_eq!(
            finish_publication(&mut st, "friends", f.id, &pending.descriptor, &Ok(())).unwrap_err(),
            "publication storage failpoint"
        );
    }
    assert_eq!(publication(&f).published_until, None);
    assert_eq!(*f.saved.lock().unwrap(), saved);
    f.fail.store(false, Ordering::SeqCst);
    finish_publication(
        &mut state.lock().unwrap(),
        "friends",
        f.id,
        &pending.descriptor,
        &Ok(()),
    )
    .unwrap();
    assert_eq!(
        publication(&f).published_until,
        Some(pending.descriptor.body.expires_at)
    );
    assert_ne!(*f.saved.lock().unwrap(), saved);
    f.node.shutdown().await;
}

#[tokio::test]
async fn replacement_descriptor_and_revision_guards_survive_retry_deduplication() {
    let f = fixture().await;
    assert!(publish(&f.node, "friends", f.id).await.is_err());
    let old = publication(&f);
    let mut replacement = old.clone();
    let now = now_unix();
    let resolved = old.descriptor.open(&old.reference, now, 0).unwrap();
    replacement.descriptor = Descriptor::seal(
        &old.reference,
        &resolved,
        &IdentityKeypair::from_seed([91; 32]),
        old.descriptor.body.sequence + 1,
        now,
        now + 300,
    )
    .unwrap();
    let state = f.node.state.upgrade().unwrap();
    let before = f.writes.load(Ordering::SeqCst);
    {
        let mut st = state.lock().unwrap();
        let record = st.channels["friends"].invitations.records[0].clone();
        stage_publication(&mut st, "friends", &record, &replacement).unwrap();
        assert_eq!(f.writes.load(Ordering::SeqCst) - before, 1);
        finish_publication(&mut st, "friends", f.id, &old.descriptor, &Ok(())).unwrap();
        assert!(stage_publication(&mut st, "friends", &record, &old).is_err());
    }
    assert!(publication(&f).descriptor == replacement.descriptor);
    assert_eq!(publication(&f).published_until, None);
    let record = state.lock().unwrap().channels["friends"]
        .invitations
        .records[0]
        .clone();
    f.node.revoke_invitation("friends", f.id).await.unwrap();
    assert!(
        stage_publication(&mut state.lock().unwrap(), "friends", &record, &replacement).is_err()
    );
    f.node.shutdown().await;
}

#[test]
fn sustained_publication_failure_has_a_bounded_recovery_delay() {
    use std::time::Duration;
    let start = tokio::time::Instant::now();
    let mut now = start;
    let mut retry = Retry {
        failures: 0,
        next_attempt: now,
    };
    let mut attempts = 0;
    while now - start < Duration::from_secs(3600) {
        retry.failed(now);
        let delay = retry.next_attempt - now;
        assert!((Duration::from_secs(30)..=Duration::from_secs(300)).contains(&delay));
        now = retry.next_attempt;
        attempts += 1;
    }
    assert!(
        attempts < 20,
        "an unavailable provider must not be polled every 30 seconds"
    );
    retry.failures = u32::MAX;
    retry.failed(now);
    assert!(
        retry.next_attempt - now <= Duration::from_secs(300),
        "connectivity recovery must still be retried within five minutes"
    );
}
