use gcoms_crypto::session::{FirstMove, Frame};
use gcoms_crypto::{CryptoError, IdentityKeypair, LocalSecrets, Session};
use sha2::{Digest, Sha256};

fn setup() -> (
    IdentityKeypair,
    IdentityKeypair,
    LocalSecrets,
    gcoms_crypto::Bundle,
) {
    let alice = IdentityKeypair::from_seed([0xA1; 32]);
    let bob = IdentityKeypair::from_seed([0xB2; 32]);
    let (bundle, secrets) = bob.issue_bundle();
    (alice, bob, secrets, bundle)
}

fn open_channel(
    _alice: &IdentityKeypair,
    bob_pk: &[u8],
    secrets: &LocalSecrets,
    bundle: &gcoms_crypto::Bundle,
) -> (FirstMove, Session, Session, Vec<u8>) {
    let payload0 = b"hello bob, this is alice".to_vec();
    let (fm, a) = gcoms_crypto::initiate(bob_pk, bundle, &payload0).unwrap();
    let (got0, b) = secrets.accept(&fm).unwrap();
    assert_eq!(got0, payload0);
    (fm, a, b, payload0)
}

#[test]
fn handshake_and_conversation() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);

    let f1 = a.send(b"ping").unwrap();
    assert_eq!(b.receive(&f1).unwrap(), b"ping");
    let f2 = b.send(b"pong").unwrap();
    assert_eq!(a.receive(&f2).unwrap(), b"pong");

    for i in 0..20u32 {
        let msg = format!("msg-{i}").into_bytes();
        let fa = a.send(&msg).unwrap();
        assert_eq!(b.receive(&fa).unwrap(), msg);
        let fb = b.send(&msg).unwrap();
        assert_eq!(a.receive(&fb).unwrap(), msg);
    }
    assert_eq!(a.send_ctr(), 22);
    assert_eq!(b.recv_ctr(), 22);
}

#[test]
fn frames_and_firstmove_encode_roundtrip() {
    let (alice, bob, secrets, bundle) = setup();
    let (fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);

    let fm2 = FirstMove::decode(&fm.encode()).unwrap();
    assert_eq!(fm2.encode(), fm.encode());

    let f = a.send(b"wire format").unwrap();
    let f2 = Frame::decode(&f.encode()).unwrap();
    assert_eq!(f2, f);
    assert_eq!(b.receive(&f2).unwrap(), b"wire format");
}

#[test]
fn ciphertexts_differ_for_same_plaintext() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let f1 = a.send(b"same").unwrap();
    let f2 = a.send(b"same").unwrap();
    assert_ne!(f1.ct, f2.ct);
    assert_ne!(f1.ctr, f2.ctr);
    assert_eq!(b.receive(&f1).unwrap(), b"same");
    assert_eq!(b.receive(&f2).unwrap(), b"same");
    let fb = b.send(b"same").unwrap();
    assert_eq!(a.receive(&fb).unwrap(), b"same");
    let f3 = a.send(b"same").unwrap();
    assert_ne!(f3.sender_pub, f1.sender_pub);
    assert_eq!(b.receive(&f3).unwrap(), b"same");
}

#[test]
fn replay_rejected() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let f = a.send(b"once").unwrap();
    b.receive(&f).unwrap();
    assert_eq!(b.receive(&f), Err(CryptoError::Replay));
}

#[test]
fn lost_frame_is_tolerated_and_late_frame_still_decrypts() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let f1 = a.send(b"delayed").unwrap();
    let f2 = a.send(b"second").unwrap();
    assert_eq!(b.receive(&f2).unwrap(), b"second");
    assert_eq!(b.skipped_keys(), 1);
    assert_eq!(b.receive(&f1).unwrap(), b"delayed");
    assert_eq!(b.skipped_keys(), 0);
    assert_eq!(b.receive(&f1), Err(CryptoError::Replay));
    let f3 = a.send(b"third").unwrap();
    assert_eq!(b.receive(&f3).unwrap(), b"third");
}

#[test]
fn out_of_order_burst_within_window_decrypts_across_rotations() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    a.set_pq_policy(7, std::time::Duration::from_secs(3600));
    // Interleave a reply so the sender's DH key rotates mid-burst.
    let mut frames: Vec<Frame> = (0..20)
        .map(|i| a.send(format!("burst-{i}").as_bytes()).unwrap())
        .collect();
    let reply = b.send(b"ack").unwrap();
    a.receive(&reply).unwrap();
    frames.extend((20..40).map(|i| a.send(format!("burst-{i}").as_bytes()).unwrap()));
    // Deliver in reverse order within the window.
    for f in frames.iter().rev() {
        let i: usize = std::str::from_utf8(&b.receive(f).unwrap()).unwrap()[6..]
            .parse()
            .unwrap();
        assert!(i < 40);
    }
    assert_eq!(b.skipped_keys(), 0);
}

#[test]
fn gap_beyond_window_is_rejected_without_state_change() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    for _ in 0..(gcoms_crypto::MAX_SKIP + 1) {
        let _ = a.send(b"lost").unwrap();
    }
    let far = a.send(b"too far").unwrap();
    assert_eq!(b.receive(&far), Err(CryptoError::Gap));
    assert_eq!(b.recv_ctr(), 1);
    assert_eq!(b.skipped_keys(), 0);
}

#[test]
fn forged_header_cannot_consume_skip_window() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let mut f = a.send(b"real").unwrap();
    f.ctr = 40;
    assert_eq!(b.receive(&f), Err(CryptoError::Decrypt));
    assert_eq!(b.skipped_keys(), 0, "unauthenticated gap retained keys");
    f.ctr = 2;
    assert_eq!(b.receive(&f).unwrap(), b"real");
}

#[test]
fn tamper_rejected() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let mut f = a.send(b"integrity").unwrap();
    f.ct[0] ^= 0x01;
    assert_eq!(b.receive(&f), Err(CryptoError::Decrypt));
}

#[test]
fn failed_aead_does_not_advance_ratchet() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);

    let first = b.send(b"establish peer ratchet").unwrap();
    a.receive(&first).unwrap();
    let frame = a.send(b"ratchet transition").unwrap();
    let mut tampered = frame.clone();
    tampered.ct[0] ^= 1;

    assert_eq!(b.receive(&tampered), Err(CryptoError::Decrypt));
    assert_eq!(b.recv_ctr(), 1);
    assert_eq!(b.receive(&frame).unwrap(), b"ratchet transition");
}

#[test]
fn header_tamper_rejected() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let mut f = a.send(b"ad").unwrap();
    f.ctr = 99;
    assert_eq!(b.receive(&f), Err(CryptoError::Gap));
}

#[test]
fn pq_refresh_flows() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    a.set_pq_policy(3, std::time::Duration::from_secs(3600));

    let mut pq_frames = 0;
    for i in 0..12u32 {
        let msg = format!("pq-{i}").into_bytes();
        let fa = a.send(&msg).unwrap();
        if let Some(pq_ct) = &fa.pq_ct {
            pq_frames += 1;
            assert_eq!(pq_ct.len(), 1088);
        }
        assert_eq!(b.receive(&fa).unwrap(), msg);
        let fb = b.send(&msg).unwrap();
        // The responder has not learned the initiator's KEM key yet, so it
        // cannot refresh in this direction.
        assert!(fb.pq_ct.is_none());
        a.receive(&fb).unwrap();
    }
    assert!(
        pq_frames >= 3,
        "expected periodic PQ refresh, got {pq_frames}"
    );
}

#[test]
fn pq_refresh_is_bidirectional_once_keys_are_exchanged() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    // Alice publishes her own bundle; Bob installs its KEM key, Alice her
    // decapsulation key. This is what the KemRefresh control record carries.
    let (alice_bundle, alice_secrets) = alice.issue_bundle();
    b.provide_peer_kem(alice_bundle.kem_pub.clone()).unwrap();
    a.provide_local_kem(alice_secrets.kem_decapsulation_key());
    assert!(b.has_peer_kem());
    assert!(a.can_receive_pq());
    b.set_pq_policy(2, std::time::Duration::from_secs(3600));
    a.set_pq_policy(2, std::time::Duration::from_secs(3600));

    let mut responder_pq = 0;
    let mut initiator_pq = 0;
    for i in 0..10u32 {
        let msg = format!("both-{i}").into_bytes();
        let fb = b.send(&msg).unwrap();
        responder_pq += usize::from(fb.pq_ct.is_some());
        assert_eq!(a.receive(&fb).unwrap(), msg);
        let fa = a.send(&msg).unwrap();
        initiator_pq += usize::from(fa.pq_ct.is_some());
        assert_eq!(b.receive(&fa).unwrap(), msg);
    }
    assert!(
        responder_pq >= 3,
        "responder never refreshed: {responder_pq}"
    );
    assert!(
        initiator_pq >= 3,
        "initiator never refreshed: {initiator_pq}"
    );
    // A garbage key is rejected rather than installed.
    assert_eq!(b.provide_peer_kem(vec![0; 10]), Err(CryptoError::BadKemKey));
}

#[test]
fn receive_counter_does_not_reset_sender_refresh_schedule() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    a.set_pq_policy(4, std::time::Duration::from_secs(3600));
    // Three sends toward a refresh, then a burst of receives must not push
    // the next refresh further away.
    for _ in 0..3 {
        let f = a.send(b"x").unwrap();
        b.receive(&f).unwrap();
    }
    for _ in 0..10 {
        let f = b.send(b"y").unwrap();
        a.receive(&f).unwrap();
    }
    let f = a.send(b"refresh-now").unwrap();
    assert!(f.pq_ct.is_some(), "refresh was delayed by inbound traffic");
    b.receive(&f).unwrap();
}

#[test]
fn simultaneous_sends_use_old_keypair_deque() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);

    let fa1 = a.send(b"a1").unwrap();
    let fb1 = b.send(b"b1").unwrap();
    assert_eq!(a.receive(&fb1).unwrap(), b"b1");
    assert_eq!(b.receive(&fa1).unwrap(), b"a1");

    let fa2 = a.send(b"a2").unwrap();
    let fb2 = b.send(b"b2").unwrap();
    assert_eq!(a.receive(&fb2).unwrap(), b"b2");
    assert_eq!(b.receive(&fa2).unwrap(), b"a2");

    let fa3 = a.send(b"a3").unwrap();
    let fb3 = b.send(b"b3").unwrap();
    assert_eq!(b.receive(&fa3).unwrap(), b"a3");
    assert_eq!(a.receive(&fb3).unwrap(), b"b3");
}

#[test]
fn one_way_burst_of_fifty() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    a.set_pq_policy(7, std::time::Duration::from_secs(3600));
    let frames: Vec<Frame> = (0..50)
        .map(|i| a.send(format!("burst-{i}").as_bytes()).unwrap())
        .collect();
    for (i, f) in frames.iter().enumerate() {
        assert_eq!(b.receive(f).unwrap(), format!("burst-{i}").into_bytes());
    }
}

#[test]
fn wrong_bundle_identity_rejected() {
    let (alice, _bob, _secrets, bundle) = setup();
    let mallory = IdentityKeypair::from_seed([0xDD; 32]);
    let result = gcoms_crypto::initiate(&mallory.public_bytes(), &bundle, b"x");
    assert!(matches!(result, Err(CryptoError::BundleInvalid)));
    let _ = alice;
}

#[test]
fn cross_session_decrypt_fails() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let (_fm2, _a2, mut b2, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let f1 = a.send(b"first").unwrap();
    let f2 = a.send(b"second").unwrap();
    assert_eq!(b.receive(&f1).unwrap(), b"first");
    assert_eq!(b.receive(&f2).unwrap(), b"second");
    assert_eq!(b2.receive(&f1), Err(CryptoError::UnknownMixKey));
    assert_eq!(b2.receive(&f2), Err(CryptoError::UnknownMixKey));
}

#[test]
fn sealed_transactions_are_exact_bound_and_fail_closed() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let key = [0x51; 32];
    let context = gcoms_crypto::SessionContext::new(
        b"machine-1",
        b"sender",
        Sha256::digest(bob.public_bytes()),
        b"conversation-1",
    )
    .unwrap();

    let prepared = a.prepare_send(b"durable", &key, &context).unwrap();
    let exact_wire = prepared.wire().to_vec();
    let sealed = prepared.sealed_state().clone();
    assert_eq!(a.send_ctr(), 1, "prepare must not advance");
    let old_state = a.seal_state(&key, &context).unwrap();
    assert!(matches!(
        Session::open_state_at_least(&old_state, &key, &context, 2, 0),
        Err(CryptoError::StaleTransaction)
    ));

    let mut after_crash = Session::open_state(&sealed, &key, &context).unwrap();
    assert_eq!(after_crash.send_ctr(), 2);
    assert_eq!(
        b.receive(&Frame::decode(&exact_wire).unwrap()).unwrap(),
        b"durable"
    );
    assert_eq!(exact_wire, prepared.wire(), "retry must reuse exact wire");
    a.commit_send(prepared).unwrap();
    assert_eq!(a.send_ctr(), after_crash.send_ctr());

    let wrong_context = gcoms_crypto::SessionContext::new(
        b"machine-1",
        b"receiver",
        Sha256::digest(bob.public_bytes()),
        b"conversation-1",
    )
    .unwrap();
    assert!(matches!(
        Session::open_state(&sealed, &key, &wrong_context),
        Err(CryptoError::StateAuthentication)
    ));
    assert!(matches!(
        Session::open_state(&sealed, &[0x52; 32], &context),
        Err(CryptoError::StateAuthentication)
    ));
    let mut truncated = sealed.as_bytes().to_vec();
    truncated.truncate(truncated.len() - 1);
    let truncated = gcoms_crypto::SealedSession::from_bytes(truncated).unwrap();
    assert!(Session::open_state(&truncated, &key, &context).is_err());

    let receive = after_crash
        .prepare_receive(&b.send(b"reply").unwrap(), &key, &context)
        .unwrap();
    assert_eq!(receive.plaintext(), b"reply");
    assert_eq!(
        after_crash.recv_ctr(),
        0,
        "receive prepare must not advance"
    );
    after_crash.commit_receive(receive).unwrap();
    assert_eq!(after_crash.recv_ctr(), 1);
}

#[test]
fn abandoned_prepare_never_reuses_a_nonce_or_ephemeral() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, mut b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let key = [0x51; 32];
    let context = gcoms_crypto::SessionContext::new(b"m", b"c", b"p", b"x").unwrap();
    // Force the peer key to be known so every send rotates an ephemeral.
    let warm = b.send(b"warm").unwrap();
    a.receive(&warm).unwrap();

    let first = a.prepare_send(b"payload one", &key, &context).unwrap();
    let f1 = Frame::decode(first.wire()).unwrap();
    drop(first); // persist failed; transaction abandoned
    let second = a.prepare_send(b"payload two", &key, &context).unwrap();
    let f2 = Frame::decode(second.wire()).unwrap();
    assert_eq!(f1.ctr, f2.ctr, "same logical slot");
    assert_ne!(
        f1.sender_pub, f2.sender_pub,
        "ephemeral X25519 key was reused"
    );
    assert_ne!(f1.ct, f2.ct);
    // Only the committed one is decryptable by the peer; the abandoned one
    // must not be a valid alternative ciphertext under the committed key.
    a.commit_send(second).unwrap();
    assert_eq!(b.receive(&f2).unwrap(), b"payload two");
    assert_eq!(b.receive(&f1), Err(CryptoError::Replay));
}

#[test]
fn stale_transaction_is_rejected() {
    let (alice, bob, secrets, bundle) = setup();
    let (_fm, mut a, _b, _) = open_channel(&alice, &bob.public_bytes(), &secrets, &bundle);
    let context = gcoms_crypto::SessionContext::new(b"m", b"c", b"p", b"x").unwrap();
    let prepared = a.prepare_send(b"first", &[3; 32], &context).unwrap();
    a.send(b"concurrent").unwrap();
    assert_eq!(a.commit_send(prepared), Err(CryptoError::StaleTransaction));
}

#[test]
fn sealed_types_implement_zeroization_traits() {
    fn assert_traits<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>() {}
    fn assert_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_traits::<gcoms_crypto::SealedSession>();
    assert_drop::<gcoms_crypto::Session>();
    assert_drop::<gcoms_crypto::PreparedSend>();
    assert_drop::<gcoms_crypto::PreparedReceive>();
}
