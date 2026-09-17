// Real MLS commits and authenticated directory messages through the native member receiver.
fn directory_rejoin_fixture() -> (
    NodeState,
    gcoms_mls::OwnerSession,
    crate::channel::ChannelRoute,
) {
    let name = "directory-rejoin";
    let (mut node, mut owner, owner_route) = channel_member_fixture(name);
    let prepared = gcoms_mls::ChannelMember::prepare("returning").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let old_id = gcoms_mls::ChannelMember::prepared_pseudonym(&prepared);
    let invite = owner.sign_invite_key_package(&package, "returning", gcoms_mls::Caps::member(), 3600);
    let admitted = owner.admit(&invite, &package).unwrap();
    let old_member = gcoms_mls::ChannelMember::join(prepared, &admitted.welcome).unwrap();
    assert_eq!(old_member.own_pseudonym(), old_id);
    let old_route = route(47, old_id);
    let (events, _) = broadcast::channel(16);
    process_chan_cell(
        &mut node,
        name,
        admitted.commit,
        std::time::Instant::now(),
        &events,
    );
    let payload = crate::channel::encode_dir_batch(&[
        ("owner".into(), owner_route),
        ("returning".into(), old_route.clone()),
    ])
    .unwrap();
    process_chan_cell(
        &mut node,
        name,
        owner.send(&payload).unwrap(),
        std::time::Instant::now(),
        &events,
    );
    assert_eq!(node.channels[name].directory["returning"], old_route);
    decode_v2(&encode_state(&node).unwrap(), &TEST_SEED).unwrap();
    let removed = owner.stage_remove(old_id).unwrap();
    owner.merge_pending().unwrap();
    process_chan_cell(
        &mut node,
        name,
        removed.commit,
        std::time::Instant::now(),
        &events,
    );
    assert!(node.channels[name]
        .role
        .pseudonym_for_name("returning")
        .is_none());
    let replacement = gcoms_mls::ChannelMember::prepare("returning").unwrap();
    let package = gcoms_mls::ChannelMember::key_package_bytes(&replacement).unwrap();
    let new_id = gcoms_mls::ChannelMember::prepared_pseudonym(&replacement);
    assert_ne!(new_id, old_id);
    let invite = owner.sign_invite_key_package(&package, "returning", gcoms_mls::Caps::member(), 3600);
    let admitted = owner.admit(&invite, &package).unwrap();
    gcoms_mls::ChannelMember::join(replacement, &admitted.welcome).unwrap();
    process_chan_cell(
        &mut node,
        name,
        admitted.commit,
        std::time::Instant::now(),
        &events,
    );
    assert_eq!(
        node.channels[name].role.pseudonym_for_name("returning"),
        Some(new_id)
    );
    (node, owner, old_route)
}

#[tokio::test]
async fn directory_remove_readd_same_name_drops_old_route_before_export() {
    let (mut node, mut owner, _) = directory_rejoin_fixture();
    let name = "directory-rejoin";
    assert!(
        !node.channels[name].directory.contains_key("returning"),
        "removed public directory route survived authenticated commits"
    );
    let bytes = encode_state(&node).unwrap();
    let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    assert_eq!(
        archive.channels[0].role.roster(),
        node.channels[name].role.roster()
    );
    assert_eq!(
        archive.channels[0].role.epoch(),
        node.channels[name].role.epoch()
    );
    let new_id = owner.pseudonym_for_name("returning").unwrap();
    let current = route(48, new_id);
    let wire = owner
        .send(&crate::channel::encode_dir("returning", &current))
        .unwrap();
    let (events, _) = broadcast::channel(16);
    process_chan_cell(&mut node, name, wire, std::time::Instant::now(), &events);
    assert_eq!(node.channels[name].directory["returning"], current);
    decode_v2(&encode_state(&node).unwrap(), &TEST_SEED).unwrap();
}

#[tokio::test]
async fn directory_legacy_stale_route_reopens_without_changing_mls_or_ack_history() {
    let (mut node, mut owner, obsolete) = directory_rejoin_fixture();
    let name = "directory-rejoin";
    // Exact state emitted by the previous writer after Remove + Add and before a new Dir.
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("returning".into(), obsolete);
    let bytes = encode_state(&node).unwrap();
    let original_bytes = bytes.clone();
    let mut archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    assert_eq!(bytes, original_bytes);
    let restored = &mut archive.channels[0];
    let original = &node.channels[name];
    assert!(!restored.directory.contains_key("returning"));
    assert_eq!(restored.role.roster(), original.role.roster());
    assert_eq!(restored.role.own_pseudonym(), original.role.own_pseudonym());
    assert_eq!(restored.role.epoch(), original.role.epoch());
    assert_eq!(
        archive.channel_routes[name].public,
        original.own_route.public
    );
    assert_eq!(
        restored.pending_control,
        original.pending_control.iter().cloned().collect::<Vec<_>>()
    );
    for (id, route, wire) in &restored.commit_acks {
        assert_eq!(
            original.commit_ack_cache.get(id),
            Some(&(route.clone(), wire.clone()))
        );
    }
    assert!(
        matches!(restored.role.receive(&owner.send(b"after directory archive reopen").unwrap()).unwrap(),
        gcoms_mls::ReceiveOutcome::Application { payload, .. } if payload == b"after directory archive reopen")
    );
}

#[tokio::test]
async fn directory_conflicting_public_cache_cannot_activate_another_current_member() {
    let (mut node, _, _) = directory_rejoin_fixture();
    let name = "directory-rejoin";
    let owner = node.channels[name].directory["owner"].clone();
    // A syntactically valid public route for another current member remains
    // unauthorized under this name; reopening must not infer a corrected route.
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("returning".into(), owner);
    let bytes = encode_state(&node).unwrap();
    let archive = decode_v2(&bytes, &TEST_SEED).unwrap();
    assert!(!archive.channels[0].directory.contains_key("returning"));
    assert_eq!(archive.channels[0].directory.len(), 1);
    assert_eq!(
        archive.channels[0].role.roster(),
        node.channels[name].role.roster()
    );
}

fn directory_serialized_entry(bytes: &[u8], target: &str) -> (usize, usize, usize) {
    let decoded = decode_v2(bytes, &TEST_SEED).unwrap();
    let mut position = decoded.layout.channel_insertions[0].1;
    match take_u8(bytes, &mut position).unwrap() {
        0 => {}
        1 => {
            take16(bytes, &mut position).unwrap();
        }
        _ => panic!("fixture own name tag"),
    }
    let count_position = position;
    let count = take_count(bytes, &mut position, MAX_CHANNEL_ITEMS).unwrap();
    for _ in 0..count {
        let start = position;
        let member = take_string16(bytes, &mut position).unwrap();
        take32(bytes, &mut position).unwrap();
        if member == target {
            return (count_position, start, position);
        }
    }
    panic!("fixture directory entry absent")
}

#[tokio::test]
async fn directory_reconciliation_preserves_empty_duplicate_own_and_route_structure_guards() {
    let (mut node, _, obsolete) = directory_rejoin_fixture();
    let name = "directory-rejoin";
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert("returning".into(), obsolete.clone());
    let bytes = encode_state(&node).unwrap();
    let (count_position, start, end) = directory_serialized_entry(&bytes, "returning");
    let mut duplicate = bytes.clone();
    duplicate.splice(end..end, bytes[start..end].iter().copied());
    let count = u32::from_be_bytes(
        bytes[count_position..count_position + 4]
            .try_into()
            .unwrap(),
    );
    duplicate[count_position..count_position + 4].copy_from_slice(&(count + 1).to_be_bytes());
    assert!(
        decode_v2(&duplicate, &TEST_SEED).is_err(),
        "duplicate obsolete names bypassed structure guard"
    );
    let mut position = start;
    take16(&bytes, &mut position).unwrap();
    let route_start = position + 4;
    let own = node.channels[name].own_route.public.encode();
    assert_eq!(own.len(), end - route_start);
    let mut own_entry = bytes.clone();
    own_entry[route_start..end].copy_from_slice(&own);
    assert!(
        decode_v2(&own_entry, &TEST_SEED).is_err(),
        "own route admitted as peer"
    );
    let mut invalid_route = bytes.clone();
    invalid_route[route_start] = 255;
    assert!(
        decode_v2(&invalid_route, &TEST_SEED).is_err(),
        "malformed route survived filtering"
    );
    node.channels
        .get_mut(name)
        .unwrap()
        .directory
        .insert(String::new(), obsolete);
    assert!(
        decode_v2(&encode_state(&node).unwrap(), &TEST_SEED).is_err(),
        "empty stale name survived filtering"
    );
}
