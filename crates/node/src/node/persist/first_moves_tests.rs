#[test]
fn gc2_retired_setup_archive_is_bounded_authenticated_and_bound_to_base() {
    let mut node = gc2_node(105);
    for n in 0..513u64 {
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&n.to_be_bytes());
        node.accepted_first_moves.push_back(hash);
    }
    let encoded = encode_state(&node).unwrap();
    assert_eq!(&encoded[..6], MAGIC_FIRST_MOVES);
    let decoded = decode_v2(&encoded, &node.identity_seed).unwrap();
    assert_eq!(decoded.accepted_first_moves.len(), 512);
    assert_eq!(decoded.accepted_first_moves.front().unwrap()[..8], 1u64.to_be_bytes());
    assert_eq!(decoded.accepted_first_moves.back().unwrap()[..8], 512u64.to_be_bytes());
    assert!(decode_v2(&encoded, &[106; 32]).is_err());
    assert!(decode_v2(&encoded[..encoded.len() - 1], &node.identity_seed).is_err());
    let mut changed = encoded.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(decode_v2(&changed, &node.identity_seed).is_err());
    let mut changed = encoded.clone();
    changed[10 + 6] ^= 1; // Change the base timestamp, retaining the sealed history.
    assert!(decode_v2(&changed, &node.identity_seed).is_err());
    let mut nested = encoded;
    nested[10..16].copy_from_slice(MAGIC_FIRST_MOVES);
    assert!(decode_v2(&nested, &node.identity_seed).is_err());
    node.scheduler.shutdown();
}

#[test]
fn gc2_retired_setup_archive_migrates_existing_and_channel_inbox_snapshots() {
    let mut node = gc2_node(107);
    let old = encode_state(&node).unwrap();
    assert_eq!(&old[..6], MAGIC_V21);
    assert!(decode_v2(&old, &node.identity_seed).unwrap().accepted_first_moves.is_empty());
    node.accepted_first_moves.push_back([1; 32]);
    node.channel_inbox.enabled = true;
    let encoded = encode_state(&node).unwrap();
    assert_eq!(&encoded[..6], MAGIC_CHANNEL_INBOX);
    let decoded = decode_v2(&encoded, &node.identity_seed).unwrap();
    assert_eq!(decoded.accepted_first_moves, node.accepted_first_moves);
    node.scheduler.shutdown();
}
