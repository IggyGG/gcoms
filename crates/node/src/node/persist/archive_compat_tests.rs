// Synthetic historical writer grammars. These fixtures preserve the common
// archived bytes; only version-specific fields are encoded below.
#[derive(Clone, Copy)]
enum HistoricalArchive {
    Owner15,
    Machine16,
    Routed16 { empty_owner: bool },
    Owned17,
    Unified18,
}

fn historical_archive(node: &NodeState, format: HistoricalArchive) -> Result<Vec<u8>, String> {
    let bytes = encode_state(node)?;
    historical_archive_from_unified(&bytes, &node.identity_seed, format)
}

fn historical_archive_from_unified(
    bytes: &[u8],
    seed: &[u8; 32],
    format: HistoricalArchive,
) -> Result<Vec<u8>, String> {
    let archive = decode_v2(bytes, seed)?;
    if matches!(format, HistoricalArchive::Unified18) {
        let mut historical = bytes.to_vec();
        historical[..6].copy_from_slice(MAGIC_V18);
        return Ok(historical);
    }
    let mut output = bytes[..archive.layout.trailer_start].to_vec();
    if matches!(format, HistoricalArchive::Owned17) {
        // The retained writer inserted grants directly after each sealed MLS role.
        for (name, position) in archive.layout.channel_insertions.iter().rev() {
            let channel = archive.channels.iter().find(|c| &c.name == name).unwrap();
            let route = archive
                .channel_routes
                .get(name)
                .ok_or("fixture missing owned route")?;
            let mut fields = Vec::new();
            put_sensitive(
                &mut fields,
                seal_established_route(route, seed, name, &channel.role)?,
            )?;
            if let Some(previous) = archive.previous_channel_routes.get(name) {
                fields.push(1);
                put_sensitive(
                    &mut fields,
                    seal_previous_route(previous, seed, name, &channel.role)?,
                )?;
            } else {
                fields.push(0);
            }
            output.splice(*position..*position, fields);
        }
    }
    if matches!(
        format,
        HistoricalArchive::Machine16 | HistoricalArchive::Owned17
    ) {
        put_sensitive(
            &mut output,
            seal_machine_ownership(archive.application_inbox.machine_owned, seed)?,
        )?;
    }
    if matches!(format, HistoricalArchive::Routed16 { empty_owner: true }) {
        put32(&mut output, &[])?;
    } else {
        let owner = archive
            .owner_aliases
            .as_ref()
            .ok_or("fixture missing owner")?;
        put_sensitive(
            &mut output,
            owner_aliases::seal(owner, owner.active_target()?, seed)?,
        )?;
    }
    if matches!(format, HistoricalArchive::Routed16 { .. }) {
        let directory = archive
            .routing_directory
            .as_ref()
            .ok_or("fixture missing routing")?;
        put_sensitive(
            &mut output,
            seal_bytes(
                &channel_archive_key(seed),
                &routing_context(seed)?,
                &directory.encode_private().map_err(|e| e.to_string())?,
            )?,
        )?;
        put_count(&mut output, archive.channel_routes.len())?;
        for (name, route) in &archive.channel_routes {
            put16(&mut output, name.as_bytes())?;
            put_sensitive(&mut output, seal_prepared_route(route, seed)?)?;
        }
    }
    output[..6].copy_from_slice(match format {
        HistoricalArchive::Owner15 => MAGIC_V15,
        HistoricalArchive::Owned17 => MAGIC_V17,
        HistoricalArchive::Unified18 => unreachable!("handled above"),
        HistoricalArchive::Machine16 | HistoricalArchive::Routed16 { .. } => MAGIC_V16,
    });
    Ok(output)
}

fn compatibility_state() -> NodeState {
    let mut node = state();
    let mut channel = established_owner_fixture("archive-compat");
    channel.previous_own_route = Some(owned_channel_route(
        85,
        channel.role.own_pseudonym(),
        channel.own_route.direct_secret,
    ));
    node.channels.insert("archive-compat".into(), channel);
    node.next_direct_sequence = 77;
    node.local_contact_generation = 19;
    node.application_inbox.next_sequence = 23;
    node
}

#[tokio::test]
async fn archive_compat_old_v16_both_grammars_and_v17_upgrade_offline_without_reset() {
    for format in [
        HistoricalArchive::Owner15,
        HistoricalArchive::Machine16,
        HistoricalArchive::Routed16 { empty_owner: false },
        HistoricalArchive::Routed16 { empty_owner: true },
        HistoricalArchive::Owned17,
        HistoricalArchive::Unified18,
    ] {
        let mut node = compatibility_state();
        let machine = matches!(
            format,
            HistoricalArchive::Machine16 | HistoricalArchive::Owned17
        );
        node.application_inbox.machine_owned = machine;
        if matches!(format, HistoricalArchive::Routed16 { .. }) {
            node.routing = Some(
                routing::RoutingRuntime::new(
                    RoutingConfig::default(),
                    gcoms_routing::Directory::new(),
                    true,
                )
                .unwrap(),
            );
        }
        let old = historical_archive(&node, format).unwrap();
        let before = decode_v2(&old, &TEST_SEED).unwrap();
        assert_eq!(before.application_inbox.machine_owned, machine);
        assert_eq!(
            before.owner_aliases.is_none(),
            matches!(format, HistoricalArchive::Routed16 { empty_owner: true })
        );
        let own = node.channels["archive-compat"].role.own_pseudonym();
        let id = node.channels["archive-compat"].role.channel_id();
        let epoch = node.channels["archive-compat"].role.epoch();
        let mut restored = state();
        restored.routing = Some(
            routing::RoutingRuntime::new(
                RoutingConfig::default(),
                gcoms_routing::Directory::new(),
                true,
            )
            .unwrap(),
        );
        let scheduler = restored.scheduler.clone();
        let restored = Arc::new(Mutex::new(restored));
        decode_state_at_startup(&restored, &scheduler, &old)
            .await
            .unwrap();
        let state = restored.lock().unwrap();
        assert_eq!(state.channels["archive-compat"].role.own_pseudonym(), own);
        assert_eq!(state.channels["archive-compat"].role.channel_id(), id);
        assert_eq!(state.channels["archive-compat"].role.epoch(), epoch);
        assert_eq!(state.next_direct_sequence, 77);
        assert_eq!(state.local_contact_generation, 19);
        assert_eq!(state.application_inbox.next_sequence, 23);
        assert_eq!(state.application_inbox.machine_owned, machine);
        let upgraded = encode_state(&state).unwrap();
        assert_eq!(&upgraded[..6], MAGIC_V19);
        let after = decode_v2(&upgraded, &TEST_SEED).unwrap();
        assert_eq!(after.application_inbox.machine_owned, machine);
        if !matches!(
            format,
            HistoricalArchive::Owner15 | HistoricalArchive::Machine16
        ) {
            assert_eq!(
                after.channel_routes["archive-compat"].public,
                before.channel_routes["archive-compat"].public
            );
            assert_eq!(
                after.channel_routes["archive-compat"].aliases,
                before.channel_routes["archive-compat"].aliases
            );
            assert_eq!(
                after.channel_routes["archive-compat"].direct_secret,
                before.channel_routes["archive-compat"].direct_secret
            );
        } else {
            // Historical v15 and machine v16 did not store channel grants. Preserve the MLS
            // identity and leave admission pending for the routing worker.
            assert!(after.channel_routes.is_empty());
        }
        if matches!(format, HistoricalArchive::Owned17) {
            assert_eq!(
                after.previous_channel_routes["archive-compat"].aliases,
                before.previous_channel_routes["archive-compat"].aliases
            );
        }
        scheduler.shutdown();
    }
}

#[test]
fn archive_compat_authenticated_discrimination_rejects_tamper_truncation_and_splicing() {
    let mut node = compatibility_state();
    node.application_inbox.machine_owned = true;
    let retained = historical_archive(&node, HistoricalArchive::Machine16).unwrap();
    let owned = historical_archive(&node, HistoricalArchive::Owned17).unwrap();
    node.application_inbox.machine_owned = false;
    node.routing = Some(
        routing::RoutingRuntime::new(RoutingConfig::default(), gcoms_routing::Directory::new(), true)
            .unwrap(),
    );
    let routed =
        historical_archive(&node, HistoricalArchive::Routed16 { empty_owner: true }).unwrap();
    let unified = encode_state(&node).unwrap();
    for bytes in [&retained, &routed, &owned, &unified] {
        assert!(decode_v2(bytes, &[0x42; 32]).is_err());
        let archive = decode_v2(bytes, &TEST_SEED).unwrap();
        let start = archive.layout.trailer_start;
        for end in [start, start + 1, bytes.len() - 1] {
            assert!(decode_v2(&bytes[..end], &TEST_SEED).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(decode_v2(&extra, &TEST_SEED).is_err());
        let mut corrupt = bytes.to_vec();
        let mut position = start;
        let first = take32(bytes, &mut position).unwrap();
        if first.is_empty() {
            take32(bytes, &mut position).unwrap(); // authenticated routing seal
        }
        corrupt[position - 1] ^= 1;
        assert!(decode_v2(&corrupt, &TEST_SEED).is_err());
        let mut oversized = bytes.to_vec();
        oversized[start..start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_v2(&oversized, &TEST_SEED).is_err());
    }
    let retained_start = decode_v2(&retained, &TEST_SEED)
        .unwrap()
        .layout
        .trailer_start;
    let routed_start = decode_v2(&routed, &TEST_SEED).unwrap().layout.trailer_start;
    let mut hybrid = retained[..retained_start].to_vec();
    let mut end = retained_start;
    take32(&retained, &mut end).unwrap();
    hybrid.extend_from_slice(&retained[retained_start..end]);
    hybrid.extend_from_slice(&routed[routed_start..]);
    assert!(decode_v2(&hybrid, &TEST_SEED).is_err());
    let mut relabeled = unified;
    relabeled[..6].copy_from_slice(MAGIC_V16);
    assert!(decode_v2(&relabeled, &TEST_SEED).is_err());
}

#[test]
fn archive_compat_v18_preserves_pending_and_previous_only_routes() {
    let mut node = compatibility_state();
    let channel = node.channels.get_mut("archive-compat").unwrap();
    let previous = channel.previous_own_route.as_ref().unwrap().aliases.clone();
    channel.own_route.aliases.clear();
    let encoded = encode_state(&node).unwrap();
    let archive = decode_v2(&encoded, &TEST_SEED).unwrap();
    assert!(archive.channel_routes.is_empty());
    assert_eq!(
        archive.previous_channel_routes["archive-compat"].aliases,
        previous
    );
}

#[test]
fn archive_compat_old15_has_no_machine_scope_or_owned_channel_grants() {
    let node = compatibility_state();
    let bytes = historical_archive(&node, HistoricalArchive::Owner15).unwrap();
    let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    assert!(!archive.application_inbox.machine_owned);
    assert!(archive.channel_routes.is_empty());
    assert!(archive.previous_channel_routes.is_empty());
    assert!(archive.owner_aliases.is_some());
}

#[test]
fn archive_compat_owned_grants_bind_node_channel_role_and_independent_capabilities() {
    let mut node = compatibility_state();
    let channel = &node.channels["archive-compat"];
    let sealed = seal_unified_route(
        &channel.own_route,
        &TEST_SEED,
        "archive-compat",
        &channel.role,
        false,
    )
    .unwrap();
    assert!(
        open_unified_route(&sealed, &[0x42; 32], "archive-compat", &channel.role, false).is_err()
    );
    let other = established_owner_fixture("another-channel");
    assert!(
        open_unified_route(&sealed, &TEST_SEED, "another-channel", &other.role, false).is_err()
    );
    assert!(
        open_unified_route(&sealed, &TEST_SEED, "archive-compat", &channel.role, true).is_err()
    );
    let aliases = channel.own_route.aliases.clone();
    node.channels
        .get_mut("archive-compat")
        .unwrap()
        .own_route
        .aliases[0]
        .capabilities
        .sub = aliases[0].capabilities.push;
    assert!(encode_state(&node).is_err());
    node.channels
        .get_mut("archive-compat")
        .unwrap()
        .own_route
        .aliases = aliases;
    let bytes = encode_state(&node).unwrap();
    let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    let mut position = archive.layout.trailer_start;
    for _ in 0..3 {
        take32(&bytes, &mut position).unwrap();
    }
    let count_position = position;
    assert_eq!(
        take_count(&bytes, &mut position, MAX_CHANNEL_ITEMS).unwrap(),
        1
    );
    let start = position;
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&bytes[start..]);
    duplicate[count_position..count_position + 4].copy_from_slice(&2u32.to_be_bytes());
    assert!(decode_v2(&duplicate, &TEST_SEED).is_err());
    let mut unknown = bytes;
    unknown[start + 2] = b'X';
    assert!(decode_v2(&unknown, &TEST_SEED).is_err());
}
