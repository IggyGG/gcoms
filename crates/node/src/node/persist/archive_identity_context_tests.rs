#[test]
fn archive_cached_identity_preserves_seed_derived_public_material() {
    let first_seed = [0x39; 32];
    let second_seed = [0x73; 32];
    let first = CachedArchiveIdentity::new(&first_seed);
    let second = CachedArchiveIdentity::new(&second_seed);
    let expected = IdentityKeypair::from_seed(first_seed).public_bytes();
    let expected_hash: [u8; 32] = Sha256::digest(&expected).into();
    assert_eq!(first.identity_seed(), &first_seed);
    assert_eq!(first.identity_public_bytes(), expected);
    assert_eq!(first.identity_hash(), expected_hash);
    assert_ne!(first.identity_hash(), second.identity_hash());
}

#[test]
fn archive_cached_contexts_preserve_existing_authenticated_domains() {
    let seed = TEST_SEED;
    let identity = CachedArchiveIdentity::new(&seed);
    let channel = established_owner_fixture("context-binding");
    let role = &channel.role;
    let base = b"exact base archive bytes";
    let contexts = vec![
        (
            routing_context(&seed).unwrap(),
            routing_context(&identity).unwrap(),
        ),
        (
            tls_identity_context(&seed).unwrap(),
            tls_identity_context(&identity).unwrap(),
        ),
        (
            machine_ownership_context(&seed).unwrap(),
            machine_ownership_context(&identity).unwrap(),
        ),
        (
            central_ownership_context(&seed).unwrap(),
            central_ownership_context(&identity).unwrap(),
        ),
        (
            application_inbox_context(&seed).unwrap(),
            application_inbox_context(&identity).unwrap(),
        ),
        (
            channel_inbox_context(&seed, base).unwrap(),
            channel_inbox_context(&identity, base).unwrap(),
        ),
        (
            prepared_route_context(&seed, &role.own_pseudonym()).unwrap(),
            prepared_route_context(&identity, &role.own_pseudonym()).unwrap(),
        ),
        (
            established_route_context(&seed, role).unwrap(),
            established_route_context(&identity, role).unwrap(),
        ),
        (
            previous_route_context(&seed, role).unwrap(),
            previous_route_context(&identity, role).unwrap(),
        ),
    ];
    #[cfg(feature = "experimental-gc2")]
    let contexts = {
        let mut contexts = contexts;
        contexts.push((
            gc2_receipts_context(&seed).unwrap(),
            gc2_receipts_context(&identity).unwrap(),
        ));
        contexts
    };
    let key = channel_archive_key(&seed);
    for (original, cached) in &contexts {
        assert_eq!(context_aad(original), context_aad(cached));
        let sealed = seal_bytes(&key, cached, b"checkpoint authentication control").unwrap();
        assert_eq!(
            open_bytes(&key, original, &sealed).unwrap(),
            b"checkpoint authentication control"
        );
        let mut damaged = sealed;
        *damaged.last_mut().unwrap() ^= 1;
        assert!(open_bytes(&key, original, &damaged).is_err());
    }
    for (index, (_, cached)) in contexts.iter().enumerate() {
        let sealed = seal_bytes(&key, cached, b"domain transplant control").unwrap();
        for (other_index, (other, _)) in contexts.iter().enumerate() {
            if other_index != index {
                assert!(open_bytes(&key, other, &sealed).is_err());
            }
        }
    }
    let sealed = seal_bytes(
        &key,
        &channel_inbox_context(&identity, base).unwrap(),
        b"base binding",
    )
    .unwrap();
    assert!(open_bytes(
        &key,
        &channel_inbox_context(&seed, b"different base").unwrap(),
        &sealed
    )
    .is_err());
}

#[test]
fn archive_cached_owner_lifecycle_remains_readable_with_original_seed_context() {
    let node = state();
    let identity = CachedArchiveIdentity::new(&node.identity_seed);
    let wire = owner_aliases::seal_current_with_identity(&node, &identity).unwrap();
    let decoded = owner_aliases::open_unbound(&wire, &node.identity_seed).unwrap();
    decoded
        .validate(&node.client_relay.aliases[0].contact.target)
        .unwrap();
    assert_eq!(decoded.groups[0].provision, node.client_relay);
    assert!(owner_aliases::open_unbound(&wire, &[0x39; 32]).is_err());
    let mut damaged = wire;
    *damaged.last_mut().unwrap() ^= 1;
    assert!(owner_aliases::open_unbound(&damaged, &node.identity_seed).is_err());
}
