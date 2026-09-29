// Real pinned transport responses exercise the same retained admission and
// durable owner restoration used after repeated recovery failures.
#[tokio::test]
async fn full_inbox_cleanup_retains_authenticated_recovery_after_failover_rounds() {
    use std::time::Duration;
    use tokio::time::timeout;
    let identity = TlsIdentity::generate().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let (observed, mut requests) = tokio::sync::mpsc::channel(32);
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let observed = observed.clone();
            connections.spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut h2 = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((request, mut reply))) = h2.accept().await {
                    let mut body = request.into_body();
                    let mut wire = Vec::new();
                    while let Some(Ok(bytes)) = body.data().await {
                        body.flow_control().release_capacity(bytes.len()).unwrap();
                        wire.extend_from_slice(&bytes);
                    }
                    let cell = gcoms_core::decode(&wire).unwrap();
                    observed.send(cell.cell_type().unwrap()).await.unwrap();
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
    let mut node = state();
    node.scheduler.shutdown();
    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        SchedulerProfile::compressed_production(94),
    );
    node.scheduler = scheduler.clone();
    let runtime = routing::RoutingRuntime::new(
        RoutingConfig::default(),
        gcoms_routing::Directory::new(),
        true,
    )
    .unwrap();
    node.routing = Some(runtime.clone());
    let make_alias = |byte| {
        let mut c = contact(byte);
        c.expiry = now_unix() + 3600;
        c.target = target.clone();
        valid_alias(c, byte)
    };
    node.client_relay.aliases = vec![make_alias(50), make_alias(60)];
    let now = std::time::Instant::now();
    let receive_until = now + Duration::from_secs(300);
    let abandon_at = receive_until + Duration::from_secs(300);
    for byte in 10..14 {
        node.draining_contact_aliases.push(DrainingContactAliases {
            aliases: vec![make_alias(byte)],
            receive_until,
            abandon_at,
            next_revoke: receive_until,
        });
    }
    node.staged_contact_aliases = Some(vec![make_alias(30), make_alias(40)]);
    node.unannounced_old_contact_aliases = Some(vec![make_alias(20)]);
    node.unannounced_contact_deadlines = Some((receive_until, abandon_at));
    let saved = Arc::new(Mutex::new(Vec::new()));
    let sink = saved.clone();
    node.durable_state_sink = Some(Arc::new(move |bytes| {
        *sink.lock().unwrap() = bytes;
        Ok(())
    }));
    let record = |st: &NodeState| {
        let wire = owner_aliases::seal_current(st).unwrap();
        owner_aliases::open_unbound(&wire, &st.identity_seed).unwrap()
    };
    let before = record(&node);
    let state = Arc::new(Mutex::new(node));
    let (events, mut event_rx) = broadcast::channel(8);
    // Replacement has already been allowed after failed retained rounds, but
    // capacity is full. A healthy retained route must still be retried.
    let result = timeout(
        Duration::from_secs(10),
        routing::recover_owner(&state, &scheduler, &events, &runtime, true),
    )
    .await;
    server.abort();
    let _ = server.await;
    scheduler.shutdown();
    assert!(
        matches!(result, Ok(Ok(()))),
        "retained recovery starved: {result:?}"
    );
    let mut types = Vec::new();
    while let Ok(kind) = requests.try_recv() {
        types.push(kind);
    }
    assert_eq!(
        types.iter().filter(|t| **t == CellType::RelaySub).count(),
        2
    );
    assert_eq!(
        types.iter().filter(|t| **t == CellType::RelayPush).count(),
        9
    );
    assert_eq!(
        types.len(),
        11,
        "no replacement provisioning or peer traffic"
    );
    let st = state.lock().unwrap();
    let after = record(&st);
    assert_eq!(before.groups.len(), after.groups.len());
    for (old, new) in before.groups.iter().zip(&after.groups) {
        assert_eq!(old.role, new.role);
        assert_eq!(
            old.provision, new.provision,
            "queue identities and authority retained"
        );
        assert_eq!(old.deadline_ms, new.deadline_ms, "no deadline extension");
        assert_eq!(old.receive_until_ms, new.receive_until_ms);
    }
    assert!(
        !saved.lock().unwrap().is_empty(),
        "restoration must be durably committed"
    );
    assert!(matches!(
        event_rx.try_recv(),
        Ok(Ev::IdentityUpdated { .. })
    ));
    assert!(
        event_rx.try_recv().is_err(),
        "no message delivery manufactured"
    );
    assert!(!st.owner_transition_failed);
}

#[tokio::test]
async fn inbox_recovery_never_bypasses_failed_owner_checkpoint() {
    let mut node = state();
    let runtime = routing::RoutingRuntime::new(
        RoutingConfig::default(),
        gcoms_routing::Directory::new(),
        true,
    )
    .unwrap();
    node.routing = Some(runtime.clone());
    node.owner_transition_failed = true;
    let current = node.client_relay.clone();
    let scheduler = node.scheduler.clone();
    let state = Arc::new(Mutex::new(node));
    let (events, mut rx) = broadcast::channel(4);
    for replacement in [false, true] {
        assert_eq!(
            routing::recover_owner(&state, &scheduler, &events, &runtime, replacement)
                .await
                .unwrap_err(),
            "owner transition requires recovery"
        );
    }
    assert_eq!(state.lock().unwrap().client_relay, current);
    assert!(rx.try_recv().is_err());
    scheduler.shutdown();
}
