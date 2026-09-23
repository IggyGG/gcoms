//! Background ownership of a bounded, preconnected GC/2 entry set. Application
//! requests have no handle capable of dialing or waking this owner's timers.
use super::{
    directory::{Directory, Introduction, MAX_GUARDS},
    discovery,
    entry::{self, EntryCarrier},
    CandidateProfile,
};
use crate::{route::now_unix, wire::Target, Result};
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use gcoms_core::TrafficClass;
use gcoms_transport::{
    connector::{BoxStream, ConnectFuture, Connector, DirectConnector},
    Tp1Client,
};
use rand::{seq::SliceRandom, Rng};
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{oneshot, Notify},
    time::{interval, sleep_until, timeout, Instant, MissedTickBehavior},
};

const RETRY_PERIOD: Duration = Duration::from_secs(30);
const DISCOVERY_PERIOD: Duration = Duration::from_secs(300);
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
type EntryTask = Pin<Box<dyn Future<Output = [u8; 32]> + Send>>;
struct ActiveEntry {
    addr: SocketAddr,
    cancel: Option<oneshot::Sender<()>>,
}
struct Renewal {
    next: Instant,
    failures: u8,
}

fn renewal_delay(
    normal: Duration,
    expiry: Option<u64>,
    wall_now: SystemTime,
    expiry_jitter: Duration,
) -> Duration {
    expiry.map_or(normal, |expiry| {
        normal.min(super::remaining_authority_at(expiry, wall_now) + expiry_jitter)
    })
}

#[derive(Clone)]
struct ReadyEntry {
    introduction: Introduction,
    carrier: EntryCarrier,
}
#[derive(Default)]
struct ReadyState {
    entries: RwLock<Vec<ReadyEntry>>,
    revision: std::sync::atomic::AtomicU64,
}

/// A class-bound connector that selects only existing entries. Acquiring a new
/// middle/terminal circuit uses that entry's established protected schedule.
pub struct ReadyConnector {
    directory: Arc<Directory>,
    state: Arc<ReadyState>,
}
impl ReadyConnector {
    /// Read-only route eligibility; does not dial, open a circuit or wake the owner.
    pub fn can_route(&self, terminal: (SocketAddr, [u8; 32])) -> bool {
        self.select(
            &Target::Relay {
                addr: terminal.0,
                service_id: terminal.1,
            },
            &[],
        )
        .is_ok()
    }

    /// Open an allowlisted HTTPS origin through an existing entry. Only the
    /// last relay resolves the hostname; the caller must authenticate WebPKI.
    /// An unavailable route never triggers an entry dial or legacy fallback.
    pub async fn connect_https(&self, host: &str, allowed_origins: &[String]) -> Result<BoxStream> {
        if !crate::wire::valid_host(host) || !allowed_origins.iter().any(|origin| origin == host) {
            return Err("catalog origin is not configured".into());
        }
        let target = Target::Https {
            host: host.into(),
            port: 443,
        };
        let (entry, middle) = self.select(&target, &[])?;
        timeout(
            Duration::from_secs(45),
            entry.connect_via(TrafficClass::Interactive, &middle, &target, &[]),
        )
        .await
        .map_err(|_| "catalog circuit construction deadline exceeded")?
    }

    /// Published ready-set changes only; failed unpublished attempts do not
    /// advance this revision. Applications cannot wake the entry owner.
    pub fn readiness_revision(&self) -> u64 {
        self.state
            .revision
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Observe usable-route eligibility and its published entry-set revision
    /// under one read lock. This is a local point-in-time observation, not proof
    /// of terminal availability or of which route a later request will use.
    pub fn route_revision(&self, terminal: (SocketAddr, [u8; 32])) -> Option<u64> {
        let entries = self.state.entries.read().unwrap_or_else(|p| p.into_inner());
        self.select_from(
            &entries,
            &Target::Relay {
                addr: terminal.0,
                service_id: terminal.1,
            },
            &[],
        )
        .ok()?;
        Some(
            self.state
                .revision
                .load(std::sync::atomic::Ordering::Acquire),
        )
    }

    /// Local aggregate only; this is not a promise that a particular excluded
    /// terminal has an independent, fresh route through the current set.
    pub fn ready_entries(&self) -> usize {
        self.state
            .entries
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    fn select(
        &self,
        target: &Target,
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<(EntryCarrier, super::path::MiddlePath)> {
        let entries = self.state.entries.read().unwrap_or_else(|p| p.into_inner());
        self.select_from(&entries, target, excluded)
    }

    fn select_from(
        &self,
        ready: &[ReadyEntry],
        target: &Target,
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<(EntryCarrier, super::path::MiddlePath)> {
        if excluded.len() > 64 {
            return Err("too many GC/2 route exclusions".into());
        }
        Target::decode(&target.encode())?;
        let now = now_unix();
        let mut available = self.directory.eligible(excluded, now)?;
        if let Target::Relay { addr, service_id } = target {
            available.retain(|relay| !relay.conflicts(*addr, *service_id));
        }
        let mut entries = ready.to_vec();
        // Random tie order spreads circuits over the already fixed entry set.
        // Neither load nor traffic can increase that set or restart a carrier.
        entries.shuffle(&mut rand::thread_rng());
        entries.sort_by_key(|entry| entry.carrier.active_circuits());
        available.shuffle(&mut rand::thread_rng());
        for entry in entries {
            // A directory/own-address update must not make an old live carrier
            // eligible at its former address or on a no-longer-retained guard.
            if !self
                .directory
                .guards()
                .contains(&entry.introduction.service_id)
                || entry.introduction.entry(now).is_err()
                || !available.iter().any(|relay| {
                    relay.service_id == entry.introduction.service_id
                        && relay.addr == entry.introduction.addr
                })
            {
                continue;
            }
            if let Some(middles) = super::path::select(
                &available,
                (entry.introduction.addr, entry.introduction.service_id),
                now,
            )? {
                return Ok((entry.carrier, middles));
            }
        }
        Err("no ready independent GC/2 route".into())
    }
}
impl Connector for ReadyConnector {
    fn binds_traffic_class(&self) -> bool {
        true
    }
    fn connect(&self, addr: SocketAddr, pin: [u8; 32]) -> ConnectFuture<'_> {
        self.connect_with_class_excluding(addr, pin, &[], TrafficClass::Interactive)
    }
    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        pin: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        self.connect_with_class_excluding(addr, pin, excluded, TrafficClass::Interactive)
    }
    fn connect_with_class_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        pin: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
        class: TrafficClass,
    ) -> ConnectFuture<'a> {
        Box::pin(async move {
            let target = Target::Relay {
                addr,
                service_id: pin,
            };
            let (entry, middle) = self.select(&target, excluded)?;
            entry.connect_via(class, &middle, &target, excluded).await
        })
    }
}

/// Experimental connected-period owner. One to three physical entries multiply
/// the selected profile's cover cost; no count/profile adapts to chat or quotas.
/// Retained guards live in the caller's private directory; archive migration and
/// OS suspend/resume policy belong to the runtime that will eventually adopt it.
pub struct EntryOwner {
    directory: Arc<Directory>,
    state: Arc<ReadyState>,
    dial: Arc<dyn Connector>,
    control: Tp1Client,
    profile: CandidateProfile,
    entries: usize,
    refreshed: Notify,
}
impl EntryOwner {
    pub fn new(
        directory: Arc<Directory>,
        profile: CandidateProfile,
        entries: usize,
    ) -> Result<(Self, Arc<ReadyConnector>)> {
        Self::with_entry_connector(directory, profile, entries, Arc::new(DirectConnector))
    }
    /// Explicit socket provider for background entry and retained-guard renewal
    /// only. This provider is never exposed to the application connector.
    pub fn with_entry_connector(
        directory: Arc<Directory>,
        profile: CandidateProfile,
        entries: usize,
        dial: Arc<dyn Connector>,
    ) -> Result<(Self, Arc<ReadyConnector>)> {
        if !(1..=MAX_GUARDS).contains(&entries) {
            return Err("GC/2 entry count must be one to three".into());
        }
        let state = Arc::new(ReadyState::default());
        let ready = Arc::new(ReadyConnector {
            directory: directory.clone(),
            state: state.clone(),
        });
        let control = Tp1Client::with_connector(dial.clone())?;
        Ok((
            Self {
                directory,
                state,
                dial,
                control,
                profile,
                entries,
                refreshed: Notify::new(),
            },
            ready,
        ))
    }

    /// No detached tasks. Dropping this future drops all connecting/ready entry
    /// drivers, nested circuits and the private control connection pool.
    pub async fn run(self) -> Result<()> {
        tokio::select! { result = self.entries_loop() => result, result = self.discovery_loop() => result }
    }

    // Pick guards without any application event. Never rotate retained guards
    // merely because they are expired or a connection attempt failed.
    fn retain_guards(&self) -> Result<()> {
        self.directory.check_persistence()?;
        let mut candidates = self.directory.reentry_candidates();
        candidates.shuffle(&mut rand::thread_rng());
        for candidate in candidates {
            if self.directory.guards().len() == MAX_GUARDS {
                break;
            }
            self.directory.retain_guard(candidate.service_id)?;
        }
        Ok(())
    }

    async fn discovery_loop(&self) -> Result<()> {
        let mut schedule = HashMap::<[u8; 32], Renewal>::new();
        loop {
            self.retain_guards()?;
            let guards = self.directory.guards();
            let candidates: Vec<_> = self
                .directory
                .reentry_candidates()
                .into_iter()
                .filter(|seed| guards.contains(&seed.service_id))
                .collect();
            schedule.retain(|pin, _| candidates.iter().any(|seed| &seed.service_id == pin));
            for seed in candidates {
                if schedule
                    .get(&seed.service_id)
                    .is_some_and(|state| state.next > Instant::now())
                {
                    continue;
                }
                // Recheck after any preceding network wait: an owner/address
                // update must not send another stale, now excluded dial.
                if !self.directory.guards().contains(&seed.service_id)
                    || !self.directory.reentry_candidates().iter().any(|current| {
                        current.service_id == seed.service_id && current.addr == seed.addr
                    })
                {
                    schedule.remove(&seed.service_id);
                    continue;
                }
                // Direct renewal is deliberately limited to retained guards
                // on this background timer. No request-time fallback exists.
                let mut renewed = None;
                if let Ok(Ok(bundle)) =
                    timeout(DIAL_TIMEOUT, discovery::refresh(&self.control, &seed, &[])).await
                {
                    if self.directory.remember(&bundle, now_unix()).is_ok() {
                        // A background renewal may remove a startup barrier
                        // immediately, without waiting for the next retry tick.
                        // Application requests cannot signal this notification.
                        self.refreshed.notify_one();
                        renewed = bundle
                            .relays
                            .iter()
                            .find(|relay| relay.service_id == seed.service_id)
                            .map(|relay| relay.expires_at);
                    }
                }
                let failures = if renewed.is_some() {
                    0
                } else {
                    schedule
                        .get(&seed.service_id)
                        .map_or(1, |old| old.failures.saturating_add(1).min(4))
                };
                let seconds = if renewed.is_some() {
                    DISCOVERY_PERIOD.as_secs()
                } else {
                    (60 * (1u64 << (failures - 1))).min(DISCOVERY_PERIOD.as_secs())
                };
                // Positive jitter prevents synchronized fleet refresh bursts;
                // it never depends on message arrivals, class or byte quotas.
                let jitter = rand::thread_rng().gen_range(0..=seconds * 100);
                let normal = Duration::from_secs(seconds) + Duration::from_millis(jitter);
                // Hourly expiry may arrive before the usual five-minute
                // refresh. Wake just after it, when the new epoch is available,
                // instead of leaving an expired guard asleep for that period.
                let expiry_jitter = Duration::from_millis(rand::thread_rng().gen_range(0..=1000));
                let now = Instant::now();
                let delay = renewal_delay(normal, renewed, SystemTime::now(), expiry_jitter);
                schedule.insert(
                    seed.service_id,
                    Renewal {
                        failures,
                        next: now + delay,
                    },
                );
            }
            let next = schedule
                .values()
                .map(|state| state.next)
                .min()
                .unwrap_or_else(|| Instant::now() + RETRY_PERIOD)
                .min(Instant::now() + RETRY_PERIOD);
            // Expired entries removed during a round must not create a spin.
            sleep_until(next.max(Instant::now() + Duration::from_millis(1))).await;
        }
    }

    async fn entries_loop(&self) -> Result<()> {
        let mut tick = interval(RETRY_PERIOD);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut tasks = FuturesUnordered::<EntryTask>::new();
        let mut active = HashMap::<[u8; 32], ActiveEntry>::new();
        let mut cursor = 0usize;
        loop {
            tokio::select! {
                Some(pin) = tasks.next(), if !tasks.is_empty() => { active.remove(&pin); },
                _ = async { tokio::select! {
                    _ = tick.tick() => (),
                    _ = self.refreshed.notified() => (),
                }} => {
                    self.retain_guards()?;
                    let guards = self.directory.guards();
                    let eligible = self.directory.eligible(&[], now_unix())?;
                    for (pin, attempt) in &mut active {
                        if !guards.contains(pin) || !eligible.iter().any(|relay| &relay.service_id == pin && relay.addr == attempt.addr) {
                            attempt.cancel.take();
                        }
                    }
                    // Canceled drivers still count until polled to completion;
                    // a configuration change cannot transiently double entries.
                    // Renewal and expiry may become ready in the same poll.
                    // Reap completed/canceled drivers before consuming the
                    // renewal wakeup, so their old slots cannot defer new
                    // authority until another 30-second retry opportunity.
                    while let Some(Some(pin)) = tasks.next().now_or_never() {
                        active.remove(&pin);
                    }
                    let start = cursor;
                    for offset in 0..guards.len() {
                        if active.len() == self.entries { break; }
                        let index = start.wrapping_add(offset) % guards.len();
                        let pin = guards[index];
                        if active.contains_key(&pin) { continue; }
                        let Some(introduction) = eligible.iter().find(|relay| relay.service_id == pin).cloned() else { continue; };
                        let (cancel, canceled) = oneshot::channel();
                        active.insert(pin, ActiveEntry { addr: introduction.addr, cancel: Some(cancel) });
                        cursor = (index + 1) % guards.len();
                        let dial = self.dial.clone();
                        let state = self.state.clone();
                        let profile = self.profile;
                        tasks.push(Box::pin(async move {
                            let _slot = ReadySlot { state: state.clone(), pin };
                            tokio::select! {
                                biased;
                                _ = canceled => (),
                                _ = maintain_entry(dial, state, introduction, profile) => (),
                            }
                            pin
                        }));
                    }
                },
            }
        }
    }
}
struct ReadySlot {
    state: Arc<ReadyState>,
    pin: [u8; 32],
}
impl Drop for ReadySlot {
    fn drop(&mut self) {
        let mut entries = self
            .state
            .entries
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let before = entries.len();
        entries.retain(|entry| entry.introduction.service_id != self.pin);
        if entries.len() != before {
            // Publish removal and revision together. A failed dial/handshake
            // that never made the ready set says nothing about healthy routes.
            self.state
                .revision
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
    }
}
async fn maintain_entry(
    dial: Arc<dyn Connector>,
    state: Arc<ReadyState>,
    introduction: Introduction,
    profile: CandidateProfile,
) -> Result<()> {
    let descriptor = introduction.entry(now_unix())?;
    let socket = timeout(
        DIAL_TIMEOUT,
        dial.connect(descriptor.addr, descriptor.service_id),
    )
    .await??;
    let (send, ready) = oneshot::channel();
    let driver = entry::run(socket, descriptor, profile, send);
    tokio::pin!(driver);
    let carrier = tokio::select! { result = &mut driver => return result, ready = ready => ready? };
    {
        let mut entries = state.entries.write().unwrap_or_else(|p| p.into_inner());
        entries.push(ReadyEntry {
            introduction,
            carrier,
        });
        state
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }
    driver.await
}

#[cfg(test)]
#[path = "owner_expiry_tests.rs"]
mod expiry_tests;

#[cfg(test)]
mod tests {
    use super::super::directory::BootstrapBundle;
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use tokio::time::Instant;

    #[test]
    fn renewal_honors_near_expiry_without_shortening_failure_backoff() {
        let now = std::time::UNIX_EPOCH + Duration::from_millis(9750);
        let normal = Duration::from_secs(315);
        assert_eq!(
            renewal_delay(normal, Some(10), now, Duration::from_millis(500)),
            Duration::from_millis(750)
        );
        assert_eq!(
            renewal_delay(normal, Some(1000), now, Duration::from_secs(1)),
            normal
        );
        assert_eq!(
            renewal_delay(Duration::from_secs(66), None, now, Duration::from_secs(1)),
            Duration::from_secs(66)
        );
        assert_eq!(
            renewal_delay(normal, Some(9), now, Duration::from_millis(500)),
            Duration::from_millis(500)
        );
    }

    struct GatedFailure {
        entered: Arc<AtomicUsize>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
    }
    impl Connector for GatedFailure {
        fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
            Box::pin(async move {
                self.entered.fetch_add(1, Ordering::SeqCst);
                let wait = self.release.lock().unwrap().take();
                if let Some(wait) = wait {
                    let _ = wait.await;
                }
                Err("fixture entry ended at renewal".into())
            })
        }
    }
    #[tokio::test(start_paused = true)]
    async fn simultaneous_renewal_and_entry_completion_cannot_lose_the_ready_slot() {
        // Exercise both orders of Tokio's randomized select polling while
        // keeping the background retry clock stationary throughout each case.
        for _ in 0..32 {
            let entered = Arc::new(AtomicUsize::new(0));
            let (release, released) = oneshot::channel();
            let (owner, _) = EntryOwner::with_entry_connector(
                directory(),
                CandidateProfile::new(4096, 1000).unwrap(),
                1,
                Arc::new(GatedFailure {
                    entered: entered.clone(),
                    release: Mutex::new(Some(released)),
                }),
            )
            .unwrap();
            let owner = Arc::new(owner);
            let running = owner.clone();
            let task = tokio::spawn(async move { running.entries_loop().await });
            settle().await;
            assert_eq!(entered.load(Ordering::SeqCst), 1);
            let before = Instant::now();
            release.send(()).unwrap();
            owner.refreshed.notify_one();
            settle().await;
            assert_eq!(entered.load(Ordering::SeqCst), 2);
            assert_eq!(Instant::now(), before);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    }

    struct FailingDial {
        attempts: Arc<Mutex<Vec<Instant>>>,
    }
    impl Connector for FailingDial {
        fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
            Box::pin(async move {
                self.attempts.lock().unwrap().push(Instant::now());
                Err("fixture offline".into())
            })
        }
    }
    fn directory() -> Arc<Directory> {
        let directory = Arc::new(Directory::for_loopback_fixture());
        directory
            .remember(
                &BootstrapBundle {
                    relays: vec![Introduction {
                        addr: "127.0.0.1:443".parse().unwrap(),
                        service_id: [1; 32],
                        reentry_cap: [2; 32],
                        entry_cap: [3; 32],
                        transit_cap: [4; 32],
                        expires_at: now_unix() + 3600,
                    }],
                },
                now_unix(),
            )
            .unwrap();
        directory
    }
    async fn settle() {
        for _ in 0..30 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_unpublished_dials_do_not_change_ready_revision() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (owner, ready) = EntryOwner::with_entry_connector(
            directory(),
            CandidateProfile::file_transfer(),
            1,
            Arc::new(FailingDial {
                attempts: attempts.clone(),
            }),
        )
        .unwrap();
        let before = ready.readiness_revision();
        // Only retry/setup timers advance; this test does not simulate a
        // SystemTime credential epoch or claim real carrier-expiry coverage.
        let task = tokio::spawn(async move { owner.entries_loop().await });
        settle().await;
        for _ in 0..2 {
            tokio::time::advance(RETRY_PERIOD).await;
            settle().await;
        }
        assert_eq!(attempts.lock().unwrap().len(), 3);
        assert_eq!(ready.ready_entries(), 0);
        assert_eq!(
            ready.readiness_revision(),
            before,
            "failed unpublished entries must not masquerade as ready-route changes"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn unsaved_guards_cannot_trigger_entry_or_control_dials() {
        let directory = Arc::try_unwrap(directory()).ok().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let count = writes.clone();
        let directory = Arc::new(
            directory
                .with_checkpoint(Arc::new(move |_| {
                    if count.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err("fixture disk full".into())
                    }
                }))
                .unwrap(),
        );
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (owner, ready) = EntryOwner::with_entry_connector(
            directory.clone(),
            CandidateProfile::new(4096, 1000).unwrap(),
            1,
            Arc::new(FailingDial {
                attempts: attempts.clone(),
            }),
        )
        .unwrap();
        // Test both independently: the combined owner may poll either first.
        assert!(owner.entries_loop().await.is_err());
        assert!(owner.discovery_loop().await.is_err());
        assert!(attempts.lock().unwrap().is_empty());
        assert!(directory.guards().is_empty());
        assert_eq!(ready.ready_entries(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn message_requests_cannot_dial_or_advance_background_retry_schedule() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (owner, ready) = EntryOwner::with_entry_connector(
            directory(),
            CandidateProfile::new(4096, 1000).unwrap(),
            1,
            Arc::new(FailingDial {
                attempts: attempts.clone(),
            }),
        )
        .unwrap();
        let terminal = "127.0.0.9:443".parse().unwrap();
        let origins = vec!["catalog.test".to_string()];
        assert!(ready.connect(terminal, [9; 32]).await.is_err());
        assert!(ready.connect_https("catalog.test", &origins).await.is_err());
        assert!(attempts.lock().unwrap().is_empty());
        let task = tokio::spawn(owner.run());
        settle().await;
        let initial = attempts.lock().unwrap().len();
        assert!(initial >= 2); // independently owned renewal and entry acquisition
        for _ in 0..20 {
            assert!(ready.connect_https("catalog.test", &origins).await.is_err());
            for class in [TrafficClass::Interactive, TrafficClass::Bulk] {
                assert!(ready
                    .connect_with_class_excluding(terminal, [9; 32], &[], class)
                    .await
                    .is_err());
            }
        }
        tokio::time::advance(RETRY_PERIOD - Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(attempts.lock().unwrap().len(), initial);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(attempts.lock().unwrap().len(), initial + 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let stopped = attempts.lock().unwrap().len();
        tokio::time::advance(DISCOVERY_PERIOD).await;
        assert!(ready.connect(terminal, [9; 32]).await.is_err());
        assert!(ready.connect_https("catalog.test", &origins).await.is_err());
        assert_eq!(attempts.lock().unwrap().len(), stopped);
        assert_eq!(ready.ready_entries(), 0);
    }

    struct PendingDial {
        active: Arc<AtomicUsize>,
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_backoff_survives_intermediate_maintenance_wakeups() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (owner, _) = EntryOwner::with_entry_connector(
            directory(),
            CandidateProfile::new(4096, 1000).unwrap(),
            1,
            Arc::new(FailingDial {
                attempts: attempts.clone(),
            }),
        )
        .unwrap();
        let task = tokio::spawn(async move { owner.discovery_loop().await });
        settle().await;
        let initial = attempts.lock().unwrap().len();
        assert!(initial > 0);
        tokio::time::advance(Duration::from_secs(30)).await;
        settle().await;
        tokio::time::advance(Duration::from_secs(29)).await;
        settle().await;
        assert_eq!(attempts.lock().unwrap().len(), initial);
        tokio::time::advance(Duration::from_secs(7)).await;
        settle().await;
        let retried = attempts.lock().unwrap().len();
        assert!(retried > initial);
        // The second failure waits at least 120 seconds. Periodic wakes that
        // notice unchanged guards must neither erase nor restart that deadline.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(30)).await;
            settle().await;
            assert_eq!(attempts.lock().unwrap().len(), retried);
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    struct ActiveDial(Arc<AtomicUsize>);
    impl Drop for ActiveDial {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl Connector for PendingDial {
        fn connect(&self, _: SocketAddr, _: [u8; 32]) -> ConnectFuture<'_> {
            Box::pin(async move {
                self.active.fetch_add(1, Ordering::SeqCst);
                let _active = ActiveDial(self.active.clone());
                std::future::pending().await
            })
        }
    }
    #[tokio::test(start_paused = true)]
    async fn dropping_owner_cancels_in_progress_entry_and_private_renewal_dials() {
        let active = Arc::new(AtomicUsize::new(0));
        let (owner, ready) = EntryOwner::with_entry_connector(
            directory(),
            CandidateProfile::new(4096, 1000).unwrap(),
            1,
            Arc::new(PendingDial {
                active: active.clone(),
            }),
        )
        .unwrap();
        let task = tokio::spawn(owner.run());
        settle().await;
        assert_eq!(active.load(Ordering::SeqCst), 2);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(ready.ready_entries(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_entry_count_bounds_background_attempts_and_preserves_guards() {
        let directory = directory();
        let first = directory.reentry_candidates()[0].clone();
        for index in 2..=6 {
            let mut next = first.clone();
            next.addr = format!("127.0.0.{index}:443").parse().unwrap();
            next.service_id = [index; 32];
            directory
                .remember(&BootstrapBundle { relays: vec![next] }, now_unix())
                .unwrap();
        }
        directory
            .set_guards(vec![[1; 32], [2; 32], [3; 32]])
            .unwrap();
        let profile = CandidateProfile::new(4096, 1000).unwrap();
        assert!(EntryOwner::new(directory.clone(), profile, 0).is_err());
        assert!(EntryOwner::new(directory.clone(), profile, 4).is_err());
        let active = Arc::new(AtomicUsize::new(0));
        let (owner, ready) = EntryOwner::with_entry_connector(
            directory.clone(),
            profile,
            3,
            Arc::new(PendingDial {
                active: active.clone(),
            }),
        )
        .unwrap();
        let task = tokio::spawn(owner.run());
        settle().await;
        // Three entry dials plus exactly one serialized control dial. The
        // other eligible referrals cannot increase or replace retained guards.
        assert_eq!(active.load(Ordering::SeqCst), 4);
        for _ in 0..3 {
            tokio::time::advance(RETRY_PERIOD).await;
            settle().await;
            assert!(active.load(Ordering::SeqCst) <= 4);
            assert_eq!(directory.guards(), vec![[1; 32], [2; 32], [3; 32]]);
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(ready.ready_entries(), 0);
    }
}
