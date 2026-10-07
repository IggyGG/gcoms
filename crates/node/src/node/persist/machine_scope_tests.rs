fn machine_policy() -> gcoms_core::component::RoutingPolicy {
    gcoms_core::component::RoutingPolicy {
        bootstrap_listeners: Vec::new(),
        components: vec![[0x40; 16]],
        routes: Vec::new(),
    }
}

// The public node verifies host authority before modifying durable ownership.
// Certificate formats and their cryptographic verification belong to the host.
#[derive(Clone)]
struct TestAuthority {
    identity: Vec<u8>,
    components: Vec<[u8; 16]>,
    permitted: bool,
    not_after: u64,
}
impl super::super::ComponentAuthority for TestAuthority {
    fn verify(&self, identity: &[u8], policy: &gcoms_core::component::RoutingPolicy, now: u64) -> Result<(), String> {
        if !self.permitted || self.identity != identity || self.components != policy.components || now > self.not_after {
            return Err("host authority rejected migration".into());
        }
        Ok(())
    }
}
fn machine_binding(seed: [u8; 32]) -> TestAuthority {
    TestAuthority { identity: IdentityKeypair::from_seed(seed).public_bytes(), components: machine_policy().components, permitted: true, not_after: now_unix() + 300 }
}

#[test]
fn machine_scope_ownership_is_sealed_and_old_v15_is_unowned() {
    let mut node = state();
    node.application_inbox.machine_owned = true;
    let bytes = encode_state(&node).unwrap();
    assert!(
        decode_v2(&bytes, &TEST_SEED)
            .unwrap()
            .application_inbox
            .machine_owned
    );
    assert!(decode_v2(&bytes, &[0x91; 32]).is_err());
    let owner_len = 4 + owner_aliases::seal_current(&node).unwrap().len();
    let machine_len = 4 + seal_machine_ownership(true, &TEST_SEED).unwrap().len();
    let mut old = historical_archive(&node, HistoricalArchive::Machine16).unwrap();
    let end = old.len() - owner_len;
    old.drain(end - machine_len..end);
    old[..6].copy_from_slice(MAGIC_V15);
    assert!(
        !decode_v2(&old, &TEST_SEED)
            .unwrap()
            .application_inbox
            .machine_owned
    );
    let mut corrupt = bytes;
    let start = decode_v2(&corrupt, &TEST_SEED)
        .unwrap()
        .layout
        .trailer_start;
    corrupt[start + 4] ^= 1;
    assert!(decode_v2(&corrupt, &TEST_SEED).is_err());
}

#[test]
fn machine_scope_commit_failure_never_publishes_policy_or_ownership() {
    let mut node = state();
    node.durable_state_sink = Some(Arc::new(|_| Err("disk refused".into())));
    assert_eq!(
        super::super::commands::configure_machine_routes(&mut node, machine_policy(), None)
            .unwrap_err(),
        "disk refused"
    );
    assert!(!node.application_inbox.machine_owned);
    assert!(node.application_inbox.routing_policy.is_none());
}

#[test]
fn component_authority_migration_keeps_member_and_refuses_invalid_authority_or_legacy_work() {
    let binding = machine_binding(TEST_SEED);
    for case in 0..8 {
        let (mut node, _, _) = channel_member_fixture("retained");
        node.durable_state_sink = Some(Arc::new(|_| Ok(())));
        let mut selected = binding.clone();
        let mut policy = machine_policy();
        match case {
            0 => selected = machine_binding([0x66; 32]),
            1 => selected = TestAuthority { permitted: false, ..machine_binding(TEST_SEED) },
            2 => selected.permitted = false,
            3 => selected.components = vec![[0x42; 16]],
            4 => policy.components = vec![[0x41; 16]],
            5 => selected.not_after = now_unix() - 1,
            6 => {
                node.application_inbox
                    .stage(
                        &IdentityKeypair::from_seed([0x66; 32]).public_bytes(),
                        [1; 16],
                        now_unix(),
                        b"legacy application",
                    )
                    .unwrap();
            }
            7 => {
                node.application_inbox.central_ownership = Some(
                    application_inbox::CentralOwnership::for_policy(
                        &gcoms_core::component::RoutingPolicy {
                            bootstrap_listeners: Vec::new(),
                            components: vec![[1; 16], [2; 16]],
                            routes: Vec::new(),
                        },
                        vec![[1; 16]],
                    )
                    .unwrap(),
                );
            }
            _ => unreachable!(),
        }
        assert!(
            super::super::commands::configure_machine_routes(&mut node, policy, Some(&selected))
                .is_err(),
            "case {case}"
        );
        assert!(!node.application_inbox.machine_owned);
        assert!(node.application_inbox.routing_policy.is_none());
        assert_eq!(node.channels.len(), 1);
    }
    let (mut node, _, _) = channel_member_fixture("retained");
    node.durable_state_sink = Some(Arc::new(|_| Ok(())));
    assert!(
        super::super::commands::configure_machine_routes(&mut node, machine_policy(), None)
            .is_err()
    );
    super::super::commands::configure_machine_routes(&mut node, machine_policy(), Some(&binding))
        .unwrap();
    assert!(node.application_inbox.machine_owned);
    assert_eq!(node.channels.len(), 1);
}

async fn machine_channel_message(node: &NodeHandle, expected: &[u8]) -> Result<(), String> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let event = node.next_event().await.ok_or("node stopped")?;
            if let Ev::ChannelMessage { channel, text, .. } = event {
                if channel == "General" && text == expected {
                    return Ok(());
                }
            }
        }
    })
    .await
    .map_err(|_| "channel message deadline")?
}
async fn machine_send_ready(node: &NodeHandle, text: &[u8]) -> Result<(), String> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            match node.send_channel_text_tracked("General", text).await {
                Ok(_) => return Ok(()),
                Err(error) if error == "channel recipient route is not ready" => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| "channel route deadline")?
}

type MachineCheckpoint = Arc<Mutex<Option<Vec<u8>>>>;

fn machine_checkpoint_sink() -> (DurableStateSink, MachineCheckpoint) {
    let saved = Arc::new(Mutex::new(None));
    let capture = saved.clone();
    let sink: DurableStateSink = Arc::new(move |bytes| {
        *capture.lock().unwrap() = Some(bytes);
        Ok(())
    });
    (sink, saved)
}

// A live export is a point-in-time snapshot, not a shutdown barrier. A real
// authenticated receive after export persists and sends an MLS ACK before the
// node stops. Restoring the old export reuses that ACK's sender generation.
#[tokio::test]
async fn machine_checkpoint_after_authenticated_post_export_ack_prevents_secret_reuse() {
    let name = "machine-checkpoint";
    let (mut node, mut owner, owner_route) = channel_member_fixture(name);
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("owner".into(), owner_route);
    let (sink, saved) = machine_checkpoint_sink();
    node.durable_state_sink = Some(sink);
    let earlier_export = encode_state(&node).unwrap();
    let incoming = owner
        .send(&crate::channel::encode_text(b"arrived after export", false))
        .unwrap();
    let id = crate::channel::msg_id(name, &incoming);
    let (events, mut received) = broadcast::channel(8);
    assert!(deliver_mls(
        &mut node,
        name,
        &incoming,
        std::time::Instant::now(),
        &events,
    ));
    assert!(matches!(received.try_recv(), Ok(Ev::ChannelMessage { msg_id, .. }) if msg_id == id));
    let ack = &node.channels[name].commit_ack_cache[&id].1;
    assert!(matches!(
        owner.receive_outcome(ack).unwrap(),
        gcoms_mls::ReceiveOutcome::Application { payload, .. }
            if payload == crate::channel::encode_text_ack(id, false)
    ));
    let mut stale = decode_v2(&earlier_export, &TEST_SEED).unwrap();
    let checkpoint = saved.lock().unwrap().take().unwrap();
    let mut current = decode_v2(&checkpoint, &TEST_SEED).unwrap();
    assert!(stale.channels[0].commit_acks.is_empty());
    assert_eq!(current.channels[0].commit_acks.len(), 1);
    let stale_wire = stale.channels[0].role.send(b"after restart").unwrap();
    let error = owner
        .receive_outcome(&stale_wire)
        .err()
        .expect("the earlier export must reuse the already consumed ACK generation");
    assert!(error.to_string().contains("SecretReuse"), "{error}");
    let current_wire = current.channels[0].role.send(b"after restart").unwrap();
    assert!(matches!(
        owner.receive_outcome(&current_wire).unwrap(),
        gcoms_mls::ReceiveOutcome::Application { payload, .. } if payload == b"after restart"
    ));
    node.scheduler.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_authority_actual_signed_join_v15_migration_and_cold_member_reopen() {
    let cfg = |seed| NodeConfig {
        seed,
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    };
    let owner_sink: DurableStateSink = Arc::new(|_| Ok(()));
    let (member_sink, saved_member) = machine_checkpoint_sink();
    let owner = super::super::start_persistent_restored(cfg([0x91; 32]), None, owner_sink, None)
        .await
        .unwrap();
    let member = super::super::start_persistent_restored(cfg(TEST_SEED), None, member_sink.clone(), None)
        .await
        .unwrap();
    let joined: Result<_, String> = async {
        owner
            .create_channel(
                "General",
                "owner",
                8,
                crate::channel::ChannelVisibility::Private,
            )
            .await?;
        let request = member.prepare_channel_join("machine").await?;
        let package = member.channel_key_package(request).await?;
        let welcome = owner.admit_channel("General", &package, "machine").await?;
        member
            .join_channel(
                request,
                "General",
                crate::channel::ChannelVisibility::Private,
                &welcome,
            )
            .await?;
        owner
            .send_channel_text("General", b"owner before cold restart")
            .await?;
        machine_channel_message(&member, b"owner before cold restart").await?;
        machine_send_ready(&member, b"before cold restart").await?;
        machine_channel_message(&owner, b"before cold restart").await?;
        let roster = member.channel_roster("General").await?;
        let views = member.list_channels().await?;
        // Owning a channel remains incompatible even with a matching host authorization.
        let owner_binding = machine_binding([0x91; 32]);
        if owner
            .configure_component_routes_with_authority(machine_policy(), Some(Arc::new(owner_binding)))
            .await
            .is_ok()
        {
            return Err("owner channel adopted as machine".into());
        }
        Ok((roster, views))
    }
    .await;
    member.shutdown().await;
    if joined.is_err() {
        owner.shutdown().await;
    }
    let (roster, views) = joined.unwrap();
    // Shutdown joins ingress/maintenance before selecting the last durable
    // checkpoint. Never roll back a send/ACK that escaped after a live export.
    let checkpoint = saved_member.lock().unwrap().take().expect("member checkpoint");
    let mut bytes = historical_archive_from_unified(
        &checkpoint,
        &TEST_SEED,
        HistoricalArchive::Machine16,
    ).unwrap();
    let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    let original_epoch = archive.channels[0].role.epoch();
    let record = archive.owner_aliases.expect("missing owner record");
    let owner_len =
        4 + owner_aliases::seal(&record, record.active_target().unwrap(), &TEST_SEED).unwrap().len();
    let machine_len = 4 + seal_machine_ownership(false, &TEST_SEED).unwrap().len();
    let end = bytes.len() - owner_len;
    bytes.drain(end - machine_len..end);
    bytes[..6].copy_from_slice(MAGIC_V15);
    let migrated =
        super::super::start_persistent_restored(cfg(TEST_SEED), None, member_sink.clone(), Some(&bytes))
            .await
            .unwrap();
    let migration: Result<(), String> = async {
        if migrated.machine_ownership_required().await? {
            return Err("v15 acquired implicit ownership".into());
        }
        if migrated
            .configure_component_routes(machine_policy())
            .await
            .is_ok()
        {
            return Err("legacy member adopted without witness".into());
        }
        migrated
            .configure_component_routes_with_authority(
                machine_policy(),
                Some(Arc::new(machine_binding(TEST_SEED))),
            )
            .await?;
        if migrated.channel_roster("General").await? != roster
            || migrated.list_channels().await? != views
        {
            return Err("migration changed roster or channel".into());
        }
        Ok(())
    }
    .await;
    migrated.shutdown().await;
    if migration.is_err() {
        owner.shutdown().await;
    }
    migration.unwrap();
    let bytes = saved_member.lock().unwrap().take().expect("migrated checkpoint");
    let reopened =
        super::super::start_persistent_restored(cfg(TEST_SEED), None, member_sink, Some(&bytes))
            .await
            .unwrap();
    let result: Result<(), String> = async {
        if !reopened.machine_ownership_required().await? {
            return Err("cold restart lost machine scope".into());
        }
        // A later normal boot uses the sealed marker, not another migration/issuance.
        reopened
            .configure_component_routes(machine_policy())
            .await?;
        if reopened.channel_roster("General").await? != roster
            || reopened.list_channels().await? != views
        {
            return Err("cold restart changed signed membership".into());
        }
        let archive = decode_v2(&reopened.export_state().await?, &TEST_SEED)?;
        if archive.channels[0].role.epoch() != original_epoch {
            return Err("cold restart reset MLS history epoch".into());
        }
        machine_send_ready(&reopened, b"after cold restart").await?;
        machine_channel_message(&owner, b"after cold restart").await?;
        if reopened
            .configure_central_component_routes(
                gcoms_core::component::RoutingPolicy {
                    bootstrap_listeners: Vec::new(),
                    components: vec![[1; 16], [2; 16]],
                    routes: Vec::new(),
                },
                vec![[1; 16]],
            )
            .await
            .is_ok()
        {
            return Err("machine switched to central ownership".into());
        }
        if reopened.import_state(&bytes).await.is_ok() {
            return Err("machine ownership replaced by public import".into());
        }
        Ok(())
    }
    .await;
    reopened.shutdown().await;
    owner.shutdown().await;
    result.unwrap();
}

#[test]
fn machine_scope_retained_direct_work_and_preconfiguration_ingress_are_fenced() {
    let records = [
        Some(crate::proto::encode_direct_data(
            [1; 16],
            now_ms(),
            false,
            b"ordinary retained message",
        )),
        Some(crate::proto::encode_direct_durable_data(
            [1; 16],
            now_ms(),
            b"legacy durable message",
        )),
        Some(b"malformed".to_vec()),
        None,
    ];
    for retained in [false, true] {
        for (index, record) in records.iter().enumerate() {
            let mut node = state();
            node.application_inbox.machine_owned = retained;
            node.durable_state_sink = Some(Arc::new(|_| Ok(())));
            node.pending_1to1.insert(
                [1; 16],
                PendingDirect {
                    delivery: delivery(3),
                    logical_record: record.clone(),
                    sequence: 1,
                    next_attempt: std::time::Instant::now(),
                    expires: std::time::Instant::now() + std::time::Duration::from_secs(30),
                    application_event: false,
                },
            );
            let result =
                super::super::commands::configure_machine_routes(&mut node, machine_policy(), None);
            assert_eq!(
                result.is_ok(),
                retained && index == 0,
                "retained={retained} case={index}: {result:?}"
            );
            assert_eq!(node.pending_1to1.len(), 1);
            assert_eq!(node.pending_1to1[&[1; 16]].logical_record, *record);
        }
    }
    let mut inbox = application_inbox::ApplicationInbox {
        machine_owned: true,
        ..Default::default()
    };
    assert_eq!(
        inbox
            .stage(
                &IdentityKeypair::from_seed([3; 32]).public_bytes(),
                [1; 16],
                now_unix(),
                b"any"
            )
            .unwrap_err(),
        "machine routing policy not configured"
    );
    assert!(inbox.entries.is_empty());
}
