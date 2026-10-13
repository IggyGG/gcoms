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
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            connections.spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut h2 = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((request, mut reply))) = h2.accept().await {
                    let mut body = request.into_body();
                    let mut wire = Vec::new();
                    while let Some(Ok(bytes)) = body.data().await {
                        assert!(wire.len() + bytes.len() <= 1024 * 1024);
                        body.flow_control().release_capacity(bytes.len()).unwrap();
                        wire.extend_from_slice(&bytes);
                    }
                    // This fixture acknowledges queue-cover transport only. It
                    // never manufactures an application or membership receipt.
                    let cell = gcoms_core::decode(&wire).unwrap();
                    assert_eq!(cell.cell_type().unwrap(), gcoms_core::CellType::RelayPush);
                    let mut response = reply.send_response(http::Response::new(()), false).unwrap();
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
                }
            });
        }
    });
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        crate::scheduler::SchedulerProfile::compressed_production(94),
    );
    (target, TransportFixture { server, scheduler })
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
    // Select exactly the old implementation's first batch, irrespective of the
    // HashMap seed. Every member of that batch remains blocked throughout.
    let blocked: HashSet<_> = node.channels.keys().take(4).cloned().collect();
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
    for _ in 0..3 {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            recover_channels(&node, &transport.scheduler, &runtime),
        )
        .await
        .expect("bounded recovery pass");
        assert_eq!(result.unwrap_err(), "channel control outbox is full");
    }
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
