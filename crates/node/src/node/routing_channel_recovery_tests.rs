//! A deferred channel must not keep unrelated retained channels unrecovered.
use super::*;
use crate::node::persist::tests::{
    established_owner_fixture, owned_channel_route, state, valid_alias,
};
use gcoms_transport::{tls::TlsIdentity, Tp1Client};
use std::time::Duration;

struct TransportFixture {
    server: tokio::task::JoinHandle<()>,
    scheduler: RelayScheduler,
    queues: Arc<Mutex<HashMap<String, OwnedAlias>>>,
    subscriptions: tokio::sync::mpsc::Receiver<[u8; 32]>,
}

impl Drop for TransportFixture {
    fn drop(&mut self) {
        self.server.abort();
        self.scheduler.shutdown();
    }
}

async fn accepting_owned_queue_transport() -> (RelayTarget, TransportFixture) {
    let identity = TlsIdentity::generate().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let queues = Arc::new(Mutex::new(HashMap::<String, OwnedAlias>::new()));
    let known_queues = queues.clone();
    let (observed, subscriptions) = tokio::sync::mpsc::channel(16);
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let queues = known_queues.clone();
            let observed = observed.clone();
            connections.spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut h2 = h2::server::handshake(tls).await.unwrap();
                let mut requests = tokio::task::JoinSet::new();
                while let Some(Ok((request, mut reply))) = h2.accept().await {
                    let alias = queues.lock().unwrap().get(request.uri().path()).cloned();
                    let observed = observed.clone();
                    requests.spawn(async move {
                        let mut body = request.into_body();
                        let mut wire = Vec::new();
                        while let Some(Ok(bytes)) = body.data().await {
                            assert!(wire.len() + bytes.len() <= 1024 * 1024);
                            body.flow_control().release_capacity(bytes.len()).unwrap();
                            wire.extend_from_slice(&bytes);
                        }
                        let cell = gcoms_core::decode(&wire).unwrap();
                        if cell.cell_type().unwrap() == gcoms_core::CellType::RelaySub {
                            let alias = alias.expect("only a registered owned queue can subscribe");
                            let sub = crate::relay::RelaySub::decode_from_cell(
                                &cell,
                                &alias.capabilities.sub,
                                &alias.contact.target.relay_service_id,
                                now_unix(),
                            )
                            .unwrap();
                            assert_eq!(sub.queue_id, alias.contact.queue_id);
                            assert_eq!(sub.epoch, alias.contact.epoch);
                            let _stream =
                                reply.send_response(http::Response::new(()), false).unwrap();
                            observed.send(sub.queue_id).await.unwrap();
                            std::future::pending::<()>().await;
                            return;
                        }
                        // Acknowledge queue-cover transport only, never application
                        // or membership delivery. Subscription streams stay open.
                        assert_eq!(cell.cell_type().unwrap(), gcoms_core::CellType::RelayPush);
                        let mut response =
                            reply.send_response(http::Response::new(()), false).unwrap();
                        response
                            .send_data(
                                bytes::Bytes::from(
                                    gcoms_transport::HopReply::Accepted
                                        .cell()
                                        .encode_wire()
                                        .unwrap(),
                                ),
                                true,
                            )
                            .unwrap();
                    });
                }
            });
        }
    });
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        crate::scheduler::SchedulerProfile::compressed_production(94),
    );
    (
        target,
        TransportFixture {
            server,
            scheduler,
            queues,
            subscriptions,
        },
    )
}

fn live_owned_route(
    mut route: crate::channel::OwnedChannelRoute,
    target: &RelayTarget,
    byte: u8,
) -> crate::channel::OwnedChannelRoute {
    let expiry = now_unix() + 3600;
    route.public.data.target = target.clone();
    route.public.control.target = target.clone();
    route.public.data.expiry = expiry;
    route.public.control.expiry = expiry;
    route.aliases = vec![
        valid_alias(route.public.data.clone(), byte),
        valid_alias(route.public.control.clone(), byte.wrapping_add(20)),
    ];
    route
}

#[tokio::test]
async fn expired_prepared_routes_do_not_starve_other_retained_preparations() {
    let (target, transport) = accepting_owned_queue_transport().await;
    let mut node = state();
    node.scheduler.shutdown();
    node.scheduler = transport.scheduler.clone();
    let runtime = RoutingRuntime::new(RoutingConfig::default(), Directory::new(), true).unwrap();
    node.routing = Some(runtime.clone());
    node.client_relay.aliases =
        live_owned_route(owned_channel_route(150, [150; 32], [151; 32]), &target, 150).aliases;
    let mut packages = HashMap::new();
    for id in 0..8u64 {
        let mls = gcoms_mls::ChannelMember::prepare("pending member").unwrap();
        packages.insert(
            id,
            gcoms_mls::ChannelMember::key_package_bytes(&mls).unwrap(),
        );
        let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&mls);
        let byte = 10 + (id as u8) * 2;
        let route = live_owned_route(
            owned_channel_route(byte, pseudonym, [byte; 32]),
            &target,
            byte,
        );
        node.prepared.insert(
            id,
            PreparedChannelJoin {
                mls,
                route,
                display: "pending member".into(),
            },
        );
    }
    let expired: HashSet<_> = node.prepared.keys().take(4).copied().collect();
    let healthy: HashSet<_> = node
        .prepared
        .keys()
        .filter(|id| !expired.contains(*id))
        .copied()
        .collect();
    for id in &expired {
        let route = &mut node.prepared.get_mut(id).unwrap().route;
        route.public.data.expiry = now_unix() - 1;
        route.public.control.expiry = now_unix() - 1;
        for alias in &mut route.aliases {
            alias.contact.expiry = now_unix() - 1;
        }
    }
    node.durable_state_sink = Some(Arc::new(|_| Ok(())));
    let node = Arc::new(Mutex::new(node));
    for _ in 0..3 {
        tokio::time::timeout(
            Duration::from_secs(10),
            recover_channels(&node, &transport.scheduler, &runtime),
        )
        .await
        .unwrap()
        .unwrap();
    }
    let ready = runtime.prepared_ready.lock().unwrap().clone();
    assert!(
        healthy.is_subset(&ready),
        "healthy preparations starved behind expired routes: {ready:?}"
    );
    assert!(expired.is_disjoint(&ready));
    let node = node.lock().unwrap();
    assert_eq!(
        node.prepared.len(),
        packages.len(),
        "recovery cannot consume a prepared join"
    );
    for (id, package) in packages {
        assert_eq!(
            gcoms_mls::ChannelMember::key_package_bytes(&node.prepared[&id].mls).unwrap(),
            package
        );
    }
}

#[tokio::test]
async fn full_channel_controls_do_not_starve_other_retained_channels() {
    channel_recovery_batches(false).await;
}

#[tokio::test]
async fn healthy_first_recovery_batch_does_not_report_unattempted_channel_deferrals() {
    channel_recovery_batches(true).await;
}

async fn channel_recovery_batches(healthy_first: bool) {
    let (target, transport) = accepting_owned_queue_transport().await;
    let mut node = state();
    node.scheduler.shutdown();
    node.scheduler = transport.scheduler.clone();
    let runtime = RoutingRuntime::new(RoutingConfig::default(), Directory::new(), true).unwrap();
    node.routing = Some(runtime.clone());
    node.client_relay.aliases =
        live_owned_route(owned_channel_route(150, [150; 32], [151; 32]), &target, 150).aliases;
    for index in 0..8u8 {
        let name = format!("retained-{index}");
        let mut channel = established_owner_fixture(&name);
        let byte = 10 + index * 2;
        let owned = owned_channel_route(
            byte,
            channel.role.own_pseudonym(),
            channel.own_route.direct_secret,
        );
        channel.own_route = live_owned_route(owned, &target, byte);
        channel
            .directory
            .insert("owner".into(), channel.own_route.public.clone());
        let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
        let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let pseudonym = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
        let member = live_owned_route(
            owned_channel_route(100 + index * 2, pseudonym, [index + 1; 32]),
            &target,
            100 + index * 2,
        );
        super::super::stage_recovery_admission_fixture(
            &mut channel,
            &name,
            &member.public,
            &package,
            "member",
        )
        .unwrap();
        channel
            .directory
            .insert("member".into(), member.public.clone());
        node.channels.insert(name, channel);
    }
    // Preserve the original starvation reproduction against HashMap-first
    // batching. Also cover the seed-independent layout where the new sorted
    // first batch contains only healthy channels and correctly returns success.
    let blocked: HashSet<_> = if healthy_first {
        let mut names: Vec<_> = node.channels.keys().cloned().collect();
        names.sort();
        names.into_iter().skip(4).collect()
    } else {
        node.channels.keys().take(4).cloned().collect()
    };
    let healthy: HashSet<_> = node
        .channels
        .keys()
        .filter(|name| !blocked.contains(*name))
        .cloned()
        .collect();
    let mut retained = HashMap::new();
    let epochs: HashMap<_, _> = node
        .channels
        .iter()
        .map(|(name, cs)| (name.clone(), cs.role.epoch()))
        .collect();
    for name in &blocked {
        let channel = node.channels.get_mut(name).unwrap();
        let recipient = channel.directory["member"].clone();
        for byte in 0..crate::channel::CHANNEL_ACK_LIMIT {
            channel
                .pending_control
                .push_back((recipient.clone(), vec![byte as u8]));
        }
        retained.insert(name.clone(), channel.pending_control.clone());
    }
    let saved = Arc::new(Mutex::new(Vec::new()));
    let sink = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        *sink.lock().unwrap() = bytes;
        Ok(())
    }));
    let node = Arc::new(Mutex::new(node));
    let mut saw_deferred = false;
    for pass in 0..3 {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            recover_channels(&node, &transport.scheduler, &runtime),
        )
        .await
        .expect("bounded recovery pass");
        if healthy_first && pass == 0 {
            assert!(
                result.is_ok(),
                "unattempted channels cannot defer a healthy batch"
            );
        }
        if let Err(error) = result {
            assert_eq!(error, "channel control outbox is full");
            saw_deferred = true;
        }
    }
    assert!(
        saw_deferred,
        "full channels must be attempted and report deferral"
    );
    let ready = runtime.channel_ready.lock().unwrap().clone();
    assert!(
        healthy.is_subset(&ready),
        "healthy retained channels starved behind a full batch: {ready:?}"
    );
    assert!(
        blocked.is_disjoint(&ready),
        "deferred announcements cannot be reported complete"
    );
    let node = node.lock().unwrap();
    for (name, original) in retained {
        assert_eq!(
            node.channels[&name].pending_control, original,
            "existing controls must survive"
        );
    }
    for (name, epoch) in epochs {
        assert_eq!(
            node.channels[&name].role.epoch(),
            epoch,
            "route repair cannot advance membership"
        );
    }
    assert!(
        !saved.lock().unwrap().is_empty(),
        "route changes must cross the durable barrier"
    );
}

#[tokio::test]
async fn recovered_channel_receives_while_its_control_outbox_is_full() {
    blocked_channel_subscription(true, UncommittedRoute::None).await;
}

#[tokio::test]
async fn uncommitted_channel_recovery_cannot_enable_receiving() {
    blocked_channel_subscription(false, UncommittedRoute::None).await;
}

#[tokio::test]
async fn recovered_receiving_proof_cannot_authorize_a_different_channel_route() {
    blocked_channel_subscription(true, UncommittedRoute::Descriptor).await;
}

#[tokio::test]
async fn recovered_receiving_proof_cannot_authorize_changed_subscription_authority() {
    blocked_channel_subscription(true, UncommittedRoute::SubscriptionAuthority).await;
}

#[derive(PartialEq)]
enum UncommittedRoute {
    None,
    Descriptor,
    SubscriptionAuthority,
}

async fn blocked_channel_subscription(
    checkpoint_succeeds: bool,
    replacement_kind: UncommittedRoute,
) {
    let (target, mut transport) = accepting_owned_queue_transport().await;
    let mut node = state();
    node.scheduler.shutdown();
    node.scheduler = transport.scheduler.clone();
    let runtime = RoutingRuntime::new(RoutingConfig::default(), Directory::new(), true).unwrap();
    runtime.recovering_owner.store(false, Ordering::Release);
    node.routing = Some(runtime.clone());
    node.client_relay.aliases =
        live_owned_route(owned_channel_route(150, [150; 32], [151; 32]), &target, 150).aliases;
    let name = "blocked-receiving";
    let mut channel = established_owner_fixture(name);
    channel.own_route = live_owned_route(
        owned_channel_route(
            10,
            channel.role.own_pseudonym(),
            channel.own_route.direct_secret,
        ),
        &target,
        10,
    );
    channel
        .directory
        .insert("owner".into(), channel.own_route.public.clone());
    let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let member = live_owned_route(
        owned_channel_route(
            100,
            gcoms_mls::ChannelMember::prepared_pseudonym(&prepared),
            [101; 32],
        ),
        &target,
        100,
    );
    super::super::stage_recovery_admission_fixture(
        &mut channel,
        name,
        &member.public,
        &package,
        "member",
    )
    .unwrap();
    channel
        .directory
        .insert("member".into(), member.public.clone());
    for byte in 0..crate::channel::CHANNEL_ACK_LIMIT {
        channel
            .pending_control
            .push_back((member.public.clone(), vec![byte as u8]));
    }
    let original = channel.pending_control.clone();
    let epoch = channel.role.epoch();
    let expected: HashSet<_> = channel
        .own_route
        .aliases
        .iter()
        .map(|alias| alias.contact.queue_id)
        .collect();
    for alias in &channel.own_route.aliases {
        transport.queues.lock().unwrap().insert(
            format!(
                "/{}",
                gcoms_transport::encode_b64url(&alias.contact.queue_id)
            ),
            alias.clone(),
        );
    }
    node.channels.insert(name.into(), channel);
    node.durable_state_sink = Some(Arc::new(move |_| {
        if checkpoint_succeeds {
            Ok(())
        } else {
            Err("fixture checkpoint unavailable".into())
        }
    }));
    let state = Arc::new(Mutex::new(node));
    let result = recover_channels(&state, &transport.scheduler, &runtime).await;
    assert!(result.is_err());
    assert!(!runtime.channel_ready.lock().unwrap().contains(name));
    if replacement_kind != UncommittedRoute::None {
        let mut node = state.lock().unwrap();
        let cs = node.channels.get_mut(name).unwrap();
        let replacement = if replacement_kind == UncommittedRoute::SubscriptionAuthority {
            let mut route = cs.own_route.clone();
            route.aliases[0].capabilities.sub = [242; 32];
            route
        } else {
            live_owned_route(
                owned_channel_route(180, cs.role.own_pseudonym(), cs.own_route.direct_secret),
                &target,
                180,
            )
        };
        for alias in &replacement.aliases {
            transport.queues.lock().unwrap().insert(
                format!(
                    "/{}",
                    gcoms_transport::encode_b64url(&alias.contact.queue_id)
                ),
                alias.clone(),
            );
        }
        // An earlier receive proof must not authorize this uncommitted route.
        cs.own_route = replacement;
    }
    let (events, _) = broadcast::channel(4);
    let pump = super::super::ticks::spawn_channel_subscription_pump(
        state.clone(),
        transport.scheduler.clone(),
        events,
    );
    let received = tokio::time::timeout(Duration::from_secs(3), async {
        let mut queues = HashSet::new();
        while queues.len() < expected.len() {
            queues.insert(transport.subscriptions.recv().await.unwrap());
        }
        queues
    })
    .await;
    if checkpoint_succeeds && replacement_kind == UncommittedRoute::None {
        assert_eq!(
            received.expect("a full outgoing control queue must not block authenticated receiving"),
            expected
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if expected.iter().all(|queue| {
                    transport
                        .scheduler
                        .subscription_classes()
                        .iter()
                        .all(|class| {
                            state
                                .lock()
                                .unwrap()
                                .subscribed_classes
                                .contains(&(*queue, *class))
                        })
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the authenticated subscription streams become active");
    } else {
        assert!(
            received.is_err(),
            "failed persistence or another descriptor cannot grant queue readiness"
        );
        assert_eq!(
            state.lock().unwrap().owner_transition_failed,
            !checkpoint_succeeds
        );
    }
    pump.stop.send(true).unwrap_or(());
    pump.task.await.unwrap();
    let node = state.lock().unwrap();
    assert_eq!(node.channels[name].pending_control, original);
    assert_eq!(node.channels[name].role.epoch(), epoch);
    assert!(
        !runtime.channel_ready.lock().unwrap().contains(name),
        "receiving is not announcement completion"
    );
}
