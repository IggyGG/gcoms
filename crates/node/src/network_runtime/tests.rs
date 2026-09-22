use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst},
    Arc,
};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

// Configuration is explicitly supplied; these tests never use GChat's network.
fn network_config(directory: &Path) -> PathBuf {
    let signer = gcoms_crypto::IdentityKeypair::from_seed([7; 32]);
    let now = gcoms_network_client::now_unix();
    let defaults = gcoms_network::NetworkDefaults {
        version: 1,
        network_id: "example.test".into(),
        sequence: 1,
        issued_at: now - 10,
        expires_at: now + 3600,
        provider_urls: vec!["https://bootstrap.example/".into()],
        founders: vec![gcoms_network::Founder {
            name: "r1.relays.example.test".into(),
            service_id: [3; 32],
            address_hints: vec!["8.8.8.8:443".parse().unwrap()],
        }],
        dns_domain: "example.test".into(),
    };
    let installed = gcoms_network_client::InstalledNetwork {
        trusted_key_b64: gcoms_transport::encode_b64url(&signer.public_bytes()),
        signed_defaults: gcoms_network::SignedNetworkDefaults::sign(defaults, &signer, vec![])
            .unwrap(),
    };
    let path = directory.join("installed.json");
    std::fs::write(&path, serde_json::to_vec(&installed).unwrap()).unwrap();
    path
}

#[test]
fn flags_validate_before_network_state_changes() {
    for values in [
        vec!["--network-config"],
        vec!["--network-config", "a", "--network-config", "b"],
        vec!["--dns-opt-in", "--dns-opt-out"],
        vec!["--dns-opt-in", "--dns-opt-in"],
        vec!["--dns-server-label", "r9"],
        vec!["--dns-server-label"],
        vec!["--network-invitation-file", "--dns-opt-in"],
        vec!["--dns-server-label", "r1", "--dns-server-label", "r2"],
    ] {
        assert!(Selection::parse(&arguments(&values)).is_err());
    }
    assert!(Selection::parse(&arguments(&[
        "serve",
        "--keystore",
        "profile",
        "--dns-server-label",
        "r8",
        "--dns-opt-in"
    ]))
    .is_ok());
}

#[test]
fn consent_and_server_selection_survive_restart_and_explicit_opt_out() {
    let directory = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(directory.path(), true).unwrap();
    let profile = directory.path().join("identity");
    let config = network_config(directory.path());
    let default = || Selection {
        network_config: Some(config.clone()),
        ..Default::default()
    };
    let network = default().open(&profile).unwrap();
    let initial = network.name_status().unwrap();
    assert!(!initial.opted_in);
    assert!(initial.server_label.is_none());
    drop(network);

    let mut selection =
        Selection::parse(&arguments(&["--dns-server-label", "r1", "--dns-opt-in"])).unwrap();
    selection.network_config = Some(config.clone());
    selection.open(&profile).unwrap();
    let retained = default().open(&profile).unwrap().name_status().unwrap();
    assert!(retained.opted_in);
    assert_eq!(retained.server_label.as_deref(), Some("r1"));
    let mut withdrawal = Selection::parse(&arguments(&["--dns-opt-out"])).unwrap();
    withdrawal.network_config = Some(config.clone());
    let withdrawn = withdrawal.open(&profile).unwrap().name_status().unwrap();
    assert!(!withdrawn.opted_in);
    assert_eq!(withdrawn.server_label, retained.server_label);
}

#[test]
fn consent_withdrawal_survives_unreadable_invitation() {
    let directory = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(directory.path(), true).unwrap();
    let profile = directory.path().join("identity");
    let config = network_config(directory.path());
    let default = || Selection {
        network_config: Some(config.clone()),
        ..Default::default()
    };
    let network = default().open(&profile).unwrap();
    network.configure_opt_in(true).unwrap();
    let selection = Selection {
        invitation: Some(directory.path().join("missing")),
        network_config: Some(config),
        opted_in: Some(false),
        ..Default::default()
    };
    assert!(selection.open(&profile).is_ok());
    assert!(!network.name_status().unwrap().opted_in);
}

#[derive(Default)]
struct Calls {
    #[cfg(feature = "experimental-gc2")]
    current: AtomicBool,
    #[cfg(feature = "experimental-gc2")]
    current_fetch: AtomicUsize,
    #[cfg(feature = "experimental-gc2")]
    current_fetch_error: AtomicBool,
    opted_in: AtomicBool,
    invitation: AtomicBool,
    cached: AtomicBool,
    reachable: AtomicBool,
    published: AtomicBool,
    installed: AtomicBool,
    fetch: AtomicUsize,
    flush: AtomicUsize,
    update: AtomicUsize,
    inbox: AtomicUsize,
    introduction: AtomicUsize,
    block_fetch: AtomicBool,
    block_flush: AtomicBool,
    cancelled: AtomicUsize,
    lease_expires: AtomicU64,
    name_pending: AtomicBool,
}

#[derive(Clone, Default)]
struct Fixture(Arc<Calls>);

struct Cancelled(Arc<Calls>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.cancelled.fetch_add(1, SeqCst);
    }
}

impl Network for Fixture {
    fn has_invitation(&self) -> Result<bool> {
        Ok(self.0.invitation.load(SeqCst))
    }
    fn opted_in(&self) -> Result<bool> {
        Ok(self.0.opted_in.load(SeqCst))
    }
    fn name_wake(&self) -> Result<Option<Duration>> {
        let expires = self.0.lease_expires.load(SeqCst);
        Ok(lease_wake(
            (expires != 0).then_some(expires),
            self.0.name_pending.load(SeqCst),
            gcoms_network_client::now_unix(),
        ))
    }
    async fn fetch(&self, _: Instant) -> Result<BootstrapBundle> {
        let _cancelled = Cancelled(self.0.clone());
        self.0.fetch.fetch_add(1, SeqCst);
        if self.0.block_fetch.load(SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(BootstrapBundle { relays: vec![] })
    }
    #[cfg(feature = "experimental-gc2")]
    async fn fetch_current(
        &self,
        _: Instant,
    ) -> Result<gcoms_routing::gc2::directory::BootstrapBundle> {
        self.0.current_fetch.fetch_add(1, SeqCst);
        if self.0.current_fetch_error.load(SeqCst) {
            return Err("current provider unavailable".into());
        }
        Ok(gcoms_routing::gc2::directory::BootstrapBundle { relays: vec![] })
    }
    async fn flush(&self, _: Instant) -> Result<()> {
        let _cancelled = Cancelled(self.0.clone());
        self.0.flush.fetch_add(1, SeqCst);
        if self.0.block_flush.load(SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn update(&self, _: BootstrapBundle, _: Instant) -> Result<()> {
        self.0.update.fetch_add(1, SeqCst);
        Ok(())
    }
}

impl Node for Fixture {
    #[cfg(feature = "experimental-gc2")]
    fn current(&self) -> bool {
        self.0.current.load(SeqCst)
    }
    #[cfg(feature = "experimental-gc2")]
    fn install_current(&self, _: &gcoms_routing::gc2::directory::BootstrapBundle) -> Result<()> {
        self.0.installed.store(true, SeqCst);
        Ok(())
    }
    fn cached(&self) -> bool {
        self.0.cached.load(SeqCst)
    }
    fn introduction(&self) -> Result<Option<BootstrapBundle>> {
        self.0.introduction.fetch_add(1, SeqCst);
        Ok(self
            .0
            .published
            .load(SeqCst)
            .then(|| BootstrapBundle { relays: vec![] }))
    }
    async fn inbox(&self, _: Instant) -> Result<()> {
        self.0.inbox.fetch_add(1, SeqCst);
        if self.0.reachable.load(SeqCst) || self.0.installed.load(SeqCst) {
            Ok(())
        } else {
            Err("fixture inbox unavailable".into())
        }
    }
    async fn install(&self, _: BootstrapBundle) -> Result<()> {
        self.0.installed.store(true, SeqCst);
        Ok(())
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[tokio::test]
async fn reachable_cache_avoids_provider_and_opt_out_still_flushes() {
    let fixture = Fixture::default();
    fixture.0.cached.store(true, SeqCst);
    fixture.0.reachable.store(true, SeqCst);
    fixture.0.invitation.store(true, SeqCst);
    bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .unwrap();
    names_cycle(&fixture, &fixture, deadline()).await.unwrap();
    assert_eq!(fixture.0.inbox.load(SeqCst), 1);
    assert_eq!(fixture.0.fetch.load(SeqCst), 0);
    assert_eq!(fixture.0.flush.load(SeqCst), 1);
    assert_eq!(fixture.0.introduction.load(SeqCst), 0);
    assert_eq!(fixture.0.update.load(SeqCst), 0);
}

#[tokio::test]
async fn unreachable_cache_recovers_without_dns_consent() {
    let fixture = Fixture::default();
    fixture.0.cached.store(true, SeqCst);
    fixture.0.invitation.store(true, SeqCst);
    bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .unwrap();
    assert!(!fixture.0.opted_in.load(SeqCst));
    assert_eq!(fixture.0.fetch.load(SeqCst), 1);
    assert!(fixture.0.installed.load(SeqCst));
    assert_eq!(fixture.0.inbox.load(SeqCst), 2);
}

#[tokio::test]
async fn name_updates_require_consent_and_own_published_listener() {
    let fixture = Fixture::default();
    fixture.0.opted_in.store(true, SeqCst);
    names_cycle(&fixture, &fixture, deadline()).await.unwrap();
    assert_eq!(fixture.0.flush.load(SeqCst), 1);
    assert_eq!(fixture.0.update.load(SeqCst), 0);
    fixture.0.published.store(true, SeqCst);
    names_cycle(&fixture, &fixture, deadline()).await.unwrap();
    assert_eq!(fixture.0.update.load(SeqCst), 1);
    fixture.0.opted_in.store(false, SeqCst);
    names_cycle(&fixture, &fixture, deadline()).await.unwrap();
    assert_eq!(fixture.0.flush.load(SeqCst), 3);
    assert_eq!(fixture.0.update.load(SeqCst), 1);
}

#[tokio::test]
async fn owned_worker_runs_both_lanes_and_reaps_blocked_io() {
    let fixture = Fixture::default();
    fixture.0.invitation.store(true, SeqCst);
    fixture.0.block_fetch.store(true, SeqCst);
    fixture.0.block_flush.store(true, SeqCst);
    let worker = Worker::spawn(fixture.clone(), fixture.clone());
    tokio::time::timeout_at(deadline(), async {
        while fixture.0.fetch.load(SeqCst) == 0 || fixture.0.flush.load(SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.shutdown().await;
    assert_eq!(fixture.0.cancelled.load(SeqCst), 2);
    assert!(!fixture.0.installed.load(SeqCst));
    assert_eq!(fixture.0.update.load(SeqCst), 0);
}

#[tokio::test]
async fn provider_timeout_cancels_without_installing_partial_bootstrap() {
    let fixture = Fixture::default();
    fixture.0.invitation.store(true, SeqCst);
    fixture.0.block_fetch.store(true, SeqCst);
    let deadline = Instant::now() + Duration::from_millis(10);
    assert!(
        tokio::time::timeout_at(deadline, bootstrap_cycle(&fixture, &fixture, deadline))
            .await
            .is_err()
    );
    assert_eq!(fixture.0.cancelled.load(SeqCst), 1);
    assert!(!fixture.0.installed.load(SeqCst));
}

#[test]
fn retry_delay_is_bounded_and_success_resets_it() {
    let mut retry = Retry::default();
    for _ in 0..100 {
        let delay = retry.delay(false);
        assert!((Duration::from_secs(5)..=Duration::from_secs(375)).contains(&delay));
    }
    assert!(retry.delay(true) <= Duration::from_millis(37500));
    assert!(retry.delay(false) <= Duration::from_millis(6250));
}

#[tokio::test]
async fn short_name_lease_wakes_before_healthy_bootstrap() {
    let fixture = Fixture::default();
    fixture.0.cached.store(true, SeqCst);
    fixture.0.reachable.store(true, SeqCst);
    fixture.0.published.store(true, SeqCst);
    fixture.0.opted_in.store(true, SeqCst);
    fixture
        .0
        .lease_expires
        .store(gcoms_network_client::now_unix() + 10, SeqCst);
    bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .unwrap();
    names_cycle(&fixture, &fixture, deadline()).await.unwrap();
    assert_eq!(fixture.0.fetch.load(SeqCst), 0);
    let mut retry = Retry::default();
    assert!(name_delay(&fixture, &mut retry, true) <= Duration::from_secs(5));
    for _ in 0..10 {
        assert!(name_delay(&fixture, &mut retry, false) <= Duration::from_secs(5));
    }
    assert!(Retry::default().delay(true) >= Duration::from_secs(30));
}

#[test]
fn pending_and_expired_name_work_stays_bounded() {
    assert_eq!(
        lease_wake(Some(1010), false, 1000),
        Some(Duration::from_secs(5))
    );
    assert_eq!(
        lease_wake(Some(1600), false, 1000),
        Some(Duration::from_secs(300))
    );
    assert_eq!(
        lease_wake(Some(999), false, 1000),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        lease_wake(Some(1600), true, 1000),
        Some(Duration::from_secs(5))
    );
    assert_eq!(lease_wake(None, true, 1000), Some(Duration::from_secs(5)));
    assert_eq!(lease_wake(None, false, 1000), None);
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn current_relay_refreshes_typed_referrals_even_with_a_usable_inbox() {
    let fixture = Fixture::default();
    fixture.0.current.store(true, SeqCst);
    fixture.0.invitation.store(true, SeqCst);
    // Startup and a later ready-inbox cycle must both replenish the explicitly
    // advertised peer directory, not only the private client guard directory.
    bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .unwrap();
    fixture.0.cached.store(true, SeqCst);
    fixture.0.reachable.store(true, SeqCst);
    bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .unwrap();
    assert_eq!(fixture.0.current_fetch.load(SeqCst), 2);
    assert_eq!(
        fixture.0.fetch.load(SeqCst),
        0,
        "no legacy provider fallback"
    );
    assert!(fixture.0.installed.load(SeqCst));
    fixture.0.invitation.store(false, SeqCst);
    bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .unwrap();
    assert_eq!(
        fixture.0.current_fetch.load(SeqCst),
        2,
        "no provisioning without a grant"
    );
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn current_provider_failure_never_falls_back_to_legacy() {
    let fixture = Fixture::default();
    fixture.0.current.store(true, SeqCst);
    fixture.0.invitation.store(true, SeqCst);
    fixture.0.current_fetch_error.store(true, SeqCst);
    assert!(bootstrap_cycle(&fixture, &fixture, deadline())
        .await
        .is_err());
    assert_eq!(fixture.0.current_fetch.load(SeqCst), 1);
    assert_eq!(fixture.0.fetch.load(SeqCst), 0);
    assert!(!fixture.0.installed.load(SeqCst));
}
