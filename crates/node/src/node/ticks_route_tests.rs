//! Exercise the real subscription pumps across changes to the ready entry set.

use super::*;
use gcoms_core::{gc2::NaturalCell, TrafficClass};
use gcoms_protocol::relay::gc2::Subscription;
use gcoms_routing::{
    gc2::{
        directory::{BootstrapBundle, Directory as CarrierDirectory},
        owner::{EntryOwner, ReadyConnector},
        CandidateProfile,
    },
    RelayService, ServicePolicy,
};
use gcoms_transport::server::{AcceptedDuplex, Dispatch, DuplexHandler};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::{
    sync::{oneshot, watch},
    task::JoinSet,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(20);

struct Attempt {
    subscription: Subscription,
    respond: oneshot::Sender<bool>,
}

struct EntryConnection {
    selected: AtomicBool,
    closed: Arc<AtomicUsize>,
}
impl EntryConnection {
    fn selected(&self) {
        self.selected.store(true, Ordering::SeqCst);
    }
}
impl Drop for EntryConnection {
    fn drop(&mut self) {
        if self.selected.load(Ordering::SeqCst) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct Fixture {
    tasks: JoinSet<()>,
    ready: Arc<ReadyConnector>,
    second_entry: watch::Sender<Option<bool>>,
    second_entry_closed: Arc<AtomicUsize>,
    scheduler: RelayScheduler,
    state: Arc<Mutex<NodeState>>,
    runtime: Arc<super::super::super::routing::RoutingRuntime>,
    attempts: mpsc::Receiver<Attempt>,
    pumps: Vec<super::super::super::api::ShutdownTask>,
    inbox: RelayProvision,
    channel: Vec<OwnedAlias>,
}

impl Fixture {
    async fn new(two_entries: bool) -> Self {
        let mut tasks = JoinSet::new();
        let (second_entry, held_entry) = watch::channel(None);
        let second_entry_closed = Arc::new(AtomicUsize::new(0));
        let mut introductions = Vec::new();
        // Two entry guards plus three distinct middle candidates are required
        // by the production five-relay path. Keep the second guard held below.
        for (index, ip) in [
            "127.0.0.102",
            "127.0.0.103",
            "127.0.0.105",
            "127.0.0.106",
            "127.0.0.107",
        ]
        .into_iter()
        .enumerate()
        {
            let identity = TlsIdentity::generate().unwrap();
            let server = bind(ip, &identity).await;
            let relay = RelayService::new(
                server.local_addr().unwrap(),
                identity.service_id(),
                [index as u8 + 1; 32],
                Arc::new(gcoms_routing::Directory::new()),
                ServicePolicy {
                    target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                    ..Default::default()
                },
            )
            .unwrap();
            let introduction = relay.gc2_introduction(now_unix());
            let entry_path = encode_b64url(&introduction.entry_cap);
            introductions.push(introduction);
            let factory = relay.gc2_handler_factory();
            let held = held_entry.clone();
            let closed = second_entry_closed.clone();
            let server = server.with_dispatch_factory(Arc::new(move || {
                let handler = factory();
                let entry_path = entry_path.clone();
                let held = held.clone();
                let connection = EntryConnection {
                    selected: AtomicBool::new(false),
                    closed: closed.clone(),
                };
                Arc::new(move |path, registered| {
                    let dispatch = handler(path, registered);
                    if index != 1 || path != entry_path {
                        return dispatch;
                    }
                    connection.selected();
                    match dispatch {
                        Dispatch::Accepted(accepted) => {
                            let mut held = held.clone();
                            Dispatch::Accepted(Box::new(move |body, mut response| {
                                Box::pin(async move {
                                    while held.borrow_and_update().is_none() {
                                        if held.changed().await.is_err() {
                                            return;
                                        }
                                    }
                                    if *held.borrow() == Some(false) {
                                        let _ = response.send_response(
                                            http::Response::builder().status(404).body(()).unwrap(),
                                            true,
                                        );
                                        return;
                                    }
                                    accepted(body, response).await;
                                })
                            }))
                        }
                        other => other,
                    }
                })
            }));
            tasks.spawn(async move { server.run().await.unwrap() });
        }
        let directory = Arc::new(CarrierDirectory::for_loopback_fixture());
        directory
            .remember(
                &BootstrapBundle {
                    relays: introductions.clone(),
                },
                now_unix(),
            )
            .unwrap();
        directory
            .set_guards(
                introductions
                    .iter()
                    .take(2)
                    .map(|intro| intro.service_id)
                    .collect(),
            )
            .unwrap();
        let (owner, ready) = EntryOwner::new(
            directory,
            CandidateProfile::file_transfer(),
            if two_entries { 2 } else { 1 },
        )
        .unwrap();
        tasks.spawn(async move { owner.run().await.unwrap() });

        let identity = TlsIdentity::generate().unwrap();
        let terminal = bind("127.0.0.104", &identity).await;
        let target = RelayTarget {
            address: terminal.local_addr().unwrap(),
            relay_service_id: identity.service_id(),
        };
        let scheduler = RelayScheduler::gc2(ready.clone()).unwrap();
        let runtime = super::super::super::routing::RoutingRuntime::new(
            RoutingConfig::default(),
            gcoms_routing::Directory::new(),
            true,
        )
        .unwrap();
        runtime.recovering_owner.store(false, Ordering::Release);
        runtime.channel_ready.lock().unwrap().insert("files".into());
        let mut node = persist::tests::state();
        node.scheduler = scheduler.clone();
        node.gc2_carrier = Some(ready.clone());
        node.routing = Some(runtime.clone());
        node.channels.insert(
            "files".into(),
            persist::tests::established_owner_fixture("files"),
        );
        let mut store = LeaseStore::new(target.relay_service_id, StoreConfig::default()).unwrap();
        for alias in node.client_relay.aliases.iter_mut().chain(
            node.channels
                .get_mut("files")
                .unwrap()
                .own_route
                .aliases
                .iter_mut(),
        ) {
            provision(alias, &target, &mut store);
        }
        let inbox = node.client_relay.clone();
        let channel = node.channels["files"].own_route.aliases.clone();
        let aliases: HashMap<_, _> = inbox
            .aliases
            .iter()
            .chain(&channel)
            .map(|alias| {
                (
                    crate::gc2::queue_token(&alias.contact.queue_id),
                    alias.clone(),
                )
            })
            .collect();
        let store = Arc::new(Mutex::new(store));
        let (observed, attempts) = mpsc::channel(16);
        let handler: DuplexHandler = Arc::new(move |token| {
            let alias = aliases.get(token)?.clone();
            let observed = observed.clone();
            let store = store.clone();
            let accepted: AcceptedDuplex = Box::new(move |mut body, mut response| {
                Box::pin(async move {
                    let wire =
                        gcoms_transport::server::read_body(&mut body, gcoms_core::gc2::MAX_CELL)
                            .await
                            .unwrap();
                    let cell = NaturalCell::decode(&wire).unwrap();
                    let subscription = Subscription::decode(
                        &cell,
                        &alias.capabilities.sub,
                        &alias.contact.target.relay_service_id,
                        now_unix(),
                    )
                    .unwrap();
                    assert_eq!(subscription.queue_id, alias.contact.queue_id);
                    assert_eq!(subscription.epoch, alias.contact.epoch);
                    assert!(subscription.expiry <= alias.contact.expiry);
                    let _authenticated = store
                        .lock()
                        .unwrap()
                        .authenticate_sub_gc2(&cell, now_unix())
                        .unwrap();
                    let (respond, decision) = oneshot::channel();
                    if observed
                        .send(Attempt {
                            subscription,
                            respond,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if !decision.await.unwrap_or(false) {
                        let _ = response.send_response(
                            http::Response::builder().status(404).body(()).unwrap(),
                            true,
                        );
                        return;
                    }
                    let mut send = response
                        .send_response(
                            http::Response::builder()
                                .header("content-type", "application/octet-stream")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    send.send_data(
                        Bytes::from(
                            gcoms_transport::gc2::status_cell(gcoms_transport::HopReply::Accepted)
                                .encode(),
                        ),
                        false,
                    )
                    .unwrap();
                    // Keep accepted subscriptions alive until fixture teardown.
                    std::future::pending::<()>().await;
                    drop((body, send));
                })
            });
            Some(accepted)
        });
        tasks.spawn(async move { terminal.with_duplex(handler).run().await.unwrap() });
        timeout(WAIT, async {
            while ready.ready_entries() != 1
                || !ready.can_route((target.address, target.relay_service_id))
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first protected entry ready while second entry handshake is held");
        let state = Arc::new(Mutex::new(node));
        let (events, _) = broadcast::channel(4);
        let contact = spawn_contact_subscription_pump(
            state.clone(),
            scheduler.clone(),
            events.clone(),
            Duration::from_millis(10),
        );
        let channels = spawn_channel_subscription_pump(state.clone(), scheduler.clone(), events);
        Self {
            tasks,
            ready,
            second_entry,
            second_entry_closed,
            scheduler,
            state,
            runtime,
            attempts,
            pumps: vec![contact, channels],
            inbox,
            channel,
        }
    }

    async fn subscriptions(&mut self) -> Vec<Attempt> {
        timeout(WAIT, async {
            let mut attempts = Vec::new();
            let mut keys = HashSet::new();
            for _ in 0..(self.inbox.aliases.len() + self.channel.len()) * 2 {
                let attempt = self.attempts.recv().await.expect("subscription request");
                assert!(keys.insert((attempt.subscription.queue_id, attempt.subscription.class)));
                attempts.push(attempt);
            }
            for alias in self.inbox.aliases.iter().chain(&self.channel) {
                for class in [TrafficClass::Interactive, TrafficClass::Bulk] {
                    assert!(keys.contains(&(alias.contact.queue_id, class)));
                }
            }
            attempts
        })
        .await
        .expect("both classes of every inbox and channel alias reached the terminal")
    }

    fn assert_authority(&self) {
        let node = self.state.lock().unwrap();
        assert_eq!(node.client_relay, self.inbox);
        assert_eq!(node.channels["files"].own_route.aliases, self.channel);
    }

    async fn finish(mut self) {
        for pump in self.pumps.drain(..) {
            pump.stop.send(true).unwrap();
            timeout(WAIT, pump.task).await.unwrap().unwrap();
        }
        self.scheduler.shutdown();
        self.tasks.shutdown().await;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for pump in &self.pumps {
            let _ = pump.stop.send(true);
            pump.task.abort();
        }
        self.scheduler.shutdown();
        // JoinSet owns all entry-owner, relay and terminal tasks.
    }
}

async fn bind(ip: &str, identity: &TlsIdentity) -> Tp1Server {
    Tp1Server::bind_with_identity(
        format!("{ip}:0").parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        identity,
    )
    .await
    .unwrap()
}

fn provision(alias: &mut OwnedAlias, target: &RelayTarget, store: &mut LeaseStore) {
    let now = now_unix();
    let grant = store
        .issue_grant(
            GrantRequest {
                queue_id: alias.contact.queue_id,
                epoch: alias.contact.epoch,
                limits: alias.limits,
            },
            now,
        )
        .unwrap();
    alias.contact.target = target.clone();
    alias.contact.expiry = now + 300;
    let create = LeaseCreate {
        queue_id: alias.contact.queue_id,
        epoch: alias.contact.epoch,
        lease_expiry: alias.contact.expiry,
        queue_cells: alias.limits.max_queue_cells,
        queue_bytes: alias.limits.max_queue_bytes,
        capabilities: alias.capabilities,
        nonce: rand::random(),
        grant: grant.wire,
    };
    let wire = create.encode(&target.relay_service_id).unwrap();
    store.create_lease(&wire, now).unwrap();
    alias.create_path = encode_b64url(&grant.wire[49..81]);
    alias.lease_create = Cell::new(CellType::RelaySub, 0, 0, wire.to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_ready_revision_retries_identical_subscription_authority() {
    let mut fixture = Fixture::new(true).await;
    let first = fixture.subscriptions().await;
    let before = fixture.ready.readiness_revision();
    let target = fixture.inbox.aliases[0].contact.target.clone();
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    assert!(fixture.state.lock().unwrap().subscribed_classes.is_empty());
    // Every original request is already in flight, and its response is held.
    // Complete a second real entry handshake without losing the original route.
    fixture.second_entry.send(Some(true)).unwrap();
    timeout(WAIT, async {
        while fixture.ready.ready_entries() != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_ne!(fixture.ready.readiness_revision(), before);
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    let original: HashMap<_, _> = first
        .iter()
        .map(|attempt| {
            (
                (attempt.subscription.queue_id, attempt.subscription.class),
                attempt.subscription.clone(),
            )
        })
        .collect();
    for attempt in first {
        attempt.respond.send(false).unwrap();
    }
    let retried = fixture.subscriptions().await;
    assert!(!fixture.runtime.recovering_owner.load(Ordering::Acquire));
    assert!(fixture
        .runtime
        .channel_ready
        .lock()
        .unwrap()
        .contains("files"));
    fixture.assert_authority();
    for attempt in retried {
        let prior = &original[&(attempt.subscription.queue_id, attempt.subscription.class)];
        assert_eq!(attempt.subscription.epoch, prior.epoch);
        assert_ne!(attempt.subscription.nonce, prior.nonce);
        attempt.respond.send(true).unwrap();
    }
    timeout(WAIT, async {
        loop {
            let all = {
                let node = fixture.state.lock().unwrap();
                node.subscribed_classes.len() == original.len()
                    && node.subscribed_contact_aliases.len() == fixture.inbox.aliases.len()
            };
            if all {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("same authority resubscribed successfully for both classes");
    fixture.assert_authority();
    assert!(!fixture.runtime.recovering_owner.load(Ordering::Acquire));
    assert!(fixture
        .runtime
        .channel_ready
        .lock()
        .unwrap()
        .contains("files"));
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_ready_route_failure_requests_inbox_and_channel_recovery() {
    let mut fixture = Fixture::new(false).await;
    let first = fixture.subscriptions().await;
    let revision = fixture.ready.readiness_revision();
    let target = fixture.inbox.aliases[0].contact.target.clone();
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    for attempt in first {
        attempt.respond.send(false).unwrap();
    }
    timeout(WAIT, async {
        while !fixture.runtime.recovering_owner.load(Ordering::Acquire)
            || fixture
                .runtime
                .channel_ready
                .lock()
                .unwrap()
                .contains("files")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("usable unchanged route must not suppress ordinary authority recovery");
    assert_eq!(fixture.ready.readiness_revision(), revision);
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    fixture.assert_authority();
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_unpublished_entry_cannot_suppress_subscription_recovery() {
    let mut fixture = Fixture::new(true).await;
    let first = fixture.subscriptions().await;
    let revision = fixture.ready.readiness_revision();
    let target = fixture.inbox.aliases[0].contact.target.clone();
    assert_eq!(fixture.ready.ready_entries(), 1);
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    // Fail the other entry's held handshake while every inbox/channel class
    // subscription is in flight through the retained healthy entry.
    fixture.second_entry.send(Some(false)).unwrap();
    timeout(WAIT, async {
        while fixture.second_entry_closed.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("unpublished entry connection ended");
    assert_eq!(fixture.ready.ready_entries(), 1);
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    for attempt in first {
        attempt.respond.send(false).unwrap();
    }
    timeout(WAIT, async {
        while !fixture.runtime.recovering_owner.load(Ordering::Acquire)
            || fixture
                .runtime
                .channel_ready
                .lock()
                .unwrap()
                .contains("files")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("failed unpublished entry must not suppress ordinary subscription recovery");
    assert_eq!(fixture.ready.readiness_revision(), revision);
    assert!(fixture
        .ready
        .can_route((target.address, target.relay_service_id)));
    fixture.assert_authority();
    fixture.finish().await;
}
