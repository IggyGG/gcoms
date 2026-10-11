#[test]
fn archive_checkpoint_derives_public_identity_once() {
    let mut node = state();
    for name in ["first-checkpoint-channel", "second-checkpoint-channel"] {
        node.channels
            .insert(name.into(), established_owner_fixture(name));
    }
    node.channel_inbox.enabled = true;
    #[cfg(feature = "experimental-gc2")]
    {
        node.gc2_sessions = true;
        node.accepted_first_moves.push_back([0x42; 32]);
    }
    ARCHIVE_IDENTITY_DERIVATIONS.with(|count| count.set(0));
    let encoded = encode_state(&node).unwrap();
    let derivations = ARCHIVE_IDENTITY_DERIVATIONS.with(|count| count.get());
    assert_eq!(
        derivations, 1,
        "a checkpoint must not regenerate its public identity for each sealed section"
    );
    let decoded = decode_v2(&encoded, &node.identity_seed).unwrap();
    assert_eq!(decoded.channels.len(), 2);
    assert!(decoded.channel_inbox.enabled);
    #[cfg(feature = "experimental-gc2")]
    assert_eq!(decoded.accepted_first_moves, node.accepted_first_moves);
    assert!(decode_v2(&encoded, &[0x73; 32]).is_err());
    let mut modified = encoded;
    *modified.last_mut().unwrap() ^= 1;
    assert!(decode_v2(&modified, &node.identity_seed).is_err());
}
