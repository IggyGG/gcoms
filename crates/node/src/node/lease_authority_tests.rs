use super::*;
use crate::scheduler::JobResult;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const QUEUE: [u8; 32] = [21; 32];
const CAPS: Capabilities = Capabilities {
    push: [22; 32],
    sub: [23; 32],
    admin: [24; 32],
};

struct Fixture {
    store: Arc<Mutex<LeaseStore>>,
    contact: AliasContact,
    queries: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    relay_scheduler: RelayScheduler,
}

impl Fixture {
    async fn new(renewed: bool, tamper: bool) -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let service_id = identity.service_id();
        let config = StoreConfig::default();
        let mut store = LeaseStore::new(service_id, config).unwrap();
        let now = now_unix();
        let grant = store
            .issue_grant(
                GrantRequest {
                    queue_id: QUEUE,
                    epoch: 1,
                    limits: config.relay_limits,
                },
                now - 300,
            )
            .unwrap();
        let create = LeaseCreate {
            queue_id: QUEUE,
            epoch: 1,
            lease_expiry: now - 60,
            queue_cells: config.relay_limits.max_queue_cells,
            queue_bytes: config.relay_limits.max_queue_bytes,
            capabilities: CAPS,
            nonce: [25; 16],
            grant: grant.wire,
        };
        store
            .create_lease(&create.encode(&service_id).unwrap(), now - 300)
            .unwrap();
        if renewed {
            let renew = LeaseRenew {
                queue_id: QUEUE,
                epoch: 1,
                lease_expiry: now + 3600,
                nonce: [26; 16],
            };
            store
                .renew(&renew.encode(&CAPS.admin, &service_id).unwrap(), now - 120)
                .unwrap();
        }
        let store = Arc::new(Mutex::new(store));
        let registry = TokenRegistry::new();
        registry.insert_queue(&encode_b64url(&QUEUE));
        registry.insert_queue(&encode_b64url(&[27; 32]));
        let relay_scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        let (on_cell, on_queue, on_stream) = build_handlers(
            &store,
            &registry,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(ProvisionAuthorities::default())),
            &relay_scheduler,
            &FrwdTargetPolicy::new(true),
            service_id,
            StreamEmission {
                slot_interval: Duration::from_millis(10),
                emission_probability: 1.0,
                emit_cover: false,
            },
        );
        let queries = Arc::new(AtomicUsize::new(0));
        let count = queries.clone();
        let on_queue: QueueCellHandler = Arc::new(move |path, cell| {
            let query = cell.cell_type() == Some(CellType::RelayPush)
                && UnauthenticatedRelayPush::parse(cell.clone())
                    .unwrap()
                    .authenticate(&CAPS.push, &service_id, now_unix())
                    .is_ok_and(|push| push.msg.is_none());
            if query {
                count.fetch_add(1, Ordering::SeqCst);
            }
            let mut result = on_queue(path, cell)?;
            if tamper && query {
                result = Some(Cell::new(CellType::Ack, 0, 0, vec![1, 2, 3]));
            }
            Ok(result)
        });
        let server = Tp1Server::bind_with_identity_and_queue(
            "127.0.0.1:0".parse().unwrap(),
            registry,
            on_cell,
            on_stream,
            on_queue,
            &identity,
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        #[cfg(feature = "experimental-gc2")]
        let server = {
            let service = gcoms_routing::RelayService::new(
                address,
                service_id,
                [28; 32],
                Arc::new(gcoms_routing::Directory::new()),
                gcoms_routing::ServicePolicy::default(),
            )
            .unwrap();
            server.with_dispatch_factory(service.gc2_handler_factory_with_terminal(
                crate::gc2::QueueService::new(store.clone()).handler(),
            ))
        };
        let server = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        Self {
            store,
            contact: AliasContact {
                target: RelayTarget {
                    address,
                    relay_service_id: service_id,
                },
                queue_id: QUEUE,
                epoch: 1,
                push_cap: CAPS.push,
                expiry: now - 60,
            },
            queries,
            server,
            relay_scheduler,
        }
    }

    fn queued(&self) -> usize {
        self.store.lock().unwrap().queue_len(&QUEUE, now_unix())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        self.relay_scheduler.shutdown();
    }
}

async fn send(scheduler: &RelayScheduler, contact: AliasContact, marker: u8) -> JobResult {
    let receipt = scheduler
        .push(
            ProducerClass::ChannelControl,
            contact,
            Cell::new(CellType::Msg, 0, 0, vec![marker]),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), receipt.completion())
        .await
        .unwrap()
}

#[tokio::test]
async fn expired_descriptor_reaches_owner_renewed_inbox_over_real_tls() {
    let fixture = Fixture::new(true, false).await;
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        SchedulerProfile::fixture().with_pipelining(),
    );
    let (a, b, c) = tokio::join!(
        send(&scheduler, fixture.contact.clone(), 1),
        send(&scheduler, fixture.contact.clone(), 2),
        send(&scheduler, fixture.contact.clone(), 3)
    );
    for result in [a, b, c] {
        match result {
            JobResult::HopAccepted(_) => (),
            JobResult::Failed(error) => panic!("{error}"),
            _ => panic!("unexpected completion"),
        }
    }
    assert_eq!(fixture.queued(), 3);
    assert_eq!(
        fixture.queries.load(Ordering::SeqCst),
        1,
        "concurrent sends share one proof"
    );
    assert!(
        fixture.contact.expiry < now_unix(),
        "saved signed route was not rewritten"
    );
    scheduler.shutdown();
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn natural_authority_probe_and_data_never_use_legacy_cells() {
    let fixture = Fixture::new(true, false).await;
    let scheduler = RelayScheduler::with_gc2_client(Arc::new(Tp1Client::new().unwrap()));
    assert!(matches!(
        send(&scheduler, fixture.contact.clone(), 1).await,
        JobResult::HopAccepted(_)
    ));
    assert!(matches!(
        send(&scheduler, fixture.contact.clone(), 2).await,
        JobResult::HopAccepted(_)
    ));
    assert_eq!(fixture.queued(), 2);
    assert_eq!(fixture.queries.load(Ordering::SeqCst), 0);
    scheduler.shutdown();
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn expired_route_refresh_and_gc2_data_cross_entry_three_middles_and_inbox() {
    use gcoms_routing::{
        gc2::{connector::PreparedConnector, entry, CandidateProfile},
        Directory, RelayService, ServicePolicy,
    };
    let fixture = Fixture::new(true, false).await;
    let mut tasks = tokio::task::JoinSet::new();
    let mut relays = Vec::new();
    let mut connections = Vec::new();
    for ip in ["127.0.0.111", "127.0.0.112", "127.0.0.113", "127.0.0.114"] {
        let identity = TlsIdentity::generate().unwrap();
        let server = Tp1Server::bind_with_identity(
            format!("{ip}:0").parse().unwrap(),
            TokenRegistry::new(),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap();
        let relay = RelayService::new(
            server.local_addr().unwrap(),
            identity.service_id(),
            [30; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        let factory = relay.gc2_handler_factory();
        let count = Arc::new(AtomicUsize::new(0));
        connections.push(count.clone());
        let server = server.with_dispatch_factory(Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            factory()
        }));
        tasks.spawn(async move {
            server.run().await.unwrap();
        });
        relays.push(relay);
    }
    let descriptor = relays[0].gc2_entry_descriptor(now_unix());
    let socket = tokio::net::TcpStream::connect(descriptor.addr)
        .await
        .unwrap();
    socket.set_nodelay(true).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        entry::run(
            Box::new(socket),
            descriptor,
            CandidateProfile::new(4096, 250).unwrap(),
            tx,
        )
        .await
        .unwrap();
    });
    let entry = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .unwrap()
        .unwrap();
    let client = Tp1Client::with_connector(Arc::new(PreparedConnector::new(
        entry,
        [
            relays[1].gc2_transit_descriptor(now_unix()),
            relays[2].gc2_transit_descriptor(now_unix()),
            relays[3].gc2_transit_descriptor(now_unix()),
        ],
    )))
    .unwrap();
    let scheduler = RelayScheduler::with_gc2_client(Arc::new(client));
    let result = send(&scheduler, fixture.contact.clone(), 1).await;
    match result {
        JobResult::HopAccepted(_) => (),
        JobResult::Failed(e) => panic!("{e}"),
        _ => panic!("unexpected completion"),
    }
    assert_eq!(fixture.queued(), 1);
    assert_eq!(fixture.queries.load(Ordering::SeqCst), 0);
    for count in connections {
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    scheduler.shutdown();
    tasks.abort_all();
}

#[tokio::test]
async fn expired_lease_and_tampered_proof_fail_closed_with_bounded_retries() {
    for (renewed, tamper) in [(false, false), (true, true)] {
        let fixture = Fixture::new(renewed, tamper).await;
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture().with_pipelining(),
        );
        for marker in 1..=3 {
            assert!(matches!(
                send(&scheduler, fixture.contact.clone(), marker).await,
                JobResult::Failed(_)
            ));
        }
        assert_eq!(fixture.queued(), 0);
        assert_eq!(fixture.queries.load(Ordering::SeqCst), 1);
        scheduler.shutdown();
    }
}

#[tokio::test]
async fn authority_probe_is_bound_to_queue_path_and_never_subscribes() {
    let fixture = Fixture::new(true, false).await;
    let cell = crate::relay::RelayPush {
        queue_id: QUEUE,
        epoch: 1,
        push_expiry: now_unix() + 30,
        push_nonce: [29; 16],
        msg: None,
    }
    .encode_into_cell(&CAPS.push, &fixture.contact.target.relay_service_id)
    .unwrap();
    let client = Tp1Client::new().unwrap();
    for (path, valid) in [(QUEUE, true), ([27; 32], false)] {
        let result = client
            .post_cell_pinned(
                fixture.contact.target.address,
                fixture.contact.target.relay_service_id,
                &encode_b64url(&path),
                bytes::Bytes::from(cell.encode_wire().unwrap()),
            )
            .await
            .unwrap()
            .into_accepted();
        if valid {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.is_err());
        }
    }
    assert_eq!(fixture.queued(), 0);
}

#[tokio::test]
async fn changed_capability_or_epoch_cannot_reuse_cached_authority() {
    let fixture = Fixture::new(true, false).await;
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        SchedulerProfile::fixture().with_pipelining(),
    );
    assert!(matches!(
        send(&scheduler, fixture.contact.clone(), 1).await,
        JobResult::HopAccepted(_)
    ));
    let mut wrong_cap = fixture.contact.clone();
    wrong_cap.push_cap[0] ^= 1;
    let mut wrong_epoch = fixture.contact.clone();
    wrong_epoch.epoch += 1;
    for changed in [wrong_cap, wrong_epoch] {
        assert!(matches!(
            send(&scheduler, changed, 2).await,
            JobResult::Failed(_)
        ));
        assert_eq!(fixture.queued(), 1);
    }
    assert!(matches!(
        send(&scheduler, fixture.contact.clone(), 3).await,
        JobResult::HopAccepted(_)
    ));
    assert_eq!(fixture.queued(), 2);
    scheduler.shutdown();
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test]
async fn natural_authority_probe_refuses_expired_lease_and_wrong_capability() {
    for renewed in [false, true] {
        let fixture = Fixture::new(renewed, false).await;
        let scheduler = RelayScheduler::with_gc2_client(Arc::new(Tp1Client::new().unwrap()));
        let mut contact = fixture.contact.clone();
        if renewed {
            contact.push_cap[0] ^= 1;
        }
        for marker in 1..=3 {
            assert!(matches!(
                send(&scheduler, contact.clone(), marker).await,
                JobResult::Failed(_)
            ));
        }
        assert_eq!(fixture.queued(), 0);
        assert_eq!(
            fixture.queries.load(Ordering::SeqCst),
            0,
            "GC/2 never falls back to a legacy probe"
        );
        scheduler.shutdown();
    }
}
