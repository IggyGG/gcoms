#[tokio::test]
async fn routed_reopen_preserves_expired_owner_without_publishing_consumed_budget() {
    for expired in [false, true] {
        let mut original = state();
        original.routing = Some(
            routing::RoutingRuntime::new(
                RoutingConfig::default(),
                gcoms_routing::Directory::new(),
                true,
            )
            .unwrap(),
        );
        original.channels.insert(
            "retained-membership".into(),
            established_owner_fixture("retained-membership"),
        );
        let sealed = owner_aliases::seal_current(&original).unwrap();
        let mut record = owner_aliases::open_unbound(&sealed, &TEST_SEED).unwrap();
        if expired {
            // A sealed owner-role budget may end before the public lease. A
            // later public expiry never replenishes that authenticated budget.
            record.groups[0].deadline_ms = record.captured_ms;
            record.groups[0].action_ms = record.captured_ms;
        }
        let clock = owner_aliases::RestoreClock::new(
            record.captured_ms,
            now_ms(),
            std::time::Instant::now(),
        )
        .unwrap();
        record.apply_retained(&mut original, clock, true).unwrap();
        let runtime = original.routing.take();
        assert_eq!(
            owner_aliases::validate_current_live(&original).is_err(),
            expired
        );
        original.routing = runtime;
        let expected_owner = original.client_relay.clone();
        assert!(expected_owner
            .aliases
            .iter()
            .all(|a| a.contact.expiry > now_unix()));
        let bytes = encode_state(&original).unwrap();
        original.scheduler.shutdown();
        let checkpoints = Arc::new(Mutex::new(Vec::new()));
        let captured = checkpoints.clone();
        let result = super::super::start_client_persistent_restored(
            NodeConfig {
                seed: TEST_SEED,
                listen: "127.0.0.1:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: NodeProfile::fixture(),
                alias_lifecycle: Default::default(),
            },
            None,
            Arc::new(move |bytes| {
                captured.lock().unwrap().push(bytes);
                Ok(())
            }),
            Some(&bytes),
            Some(RoutingConfig::default()),
        )
        .await;
        let node = match result {
            Ok(node) => node,
            Err(error) => {
                panic!("offline routed reopen refused retained owner (expired={expired}): {error}")
            }
        };
        {
            let shared = node.state.upgrade().unwrap();
            let state = shared.lock().unwrap();
            assert_eq!(state.client_relay, expected_owner);
            assert_eq!(state.info.aliases.is_empty(), expired);
            assert!(state.channels.contains_key("retained-membership"));
            assert!(!state.owner_transition_failed);
        }
        let saved = checkpoints.lock().unwrap().last().cloned().unwrap();
        let archived = decode_v2(&saved, &TEST_SEED)
            .unwrap()
            .owner_aliases
            .unwrap();
        assert_eq!(archived.groups[0].provision, expected_owner);
        assert!(archived.groups[0].deadline_ms <= record.groups[0].deadline_ms);
        node.shutdown().await;
    }
}
