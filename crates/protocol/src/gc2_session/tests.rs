use super::*;
use crate::{
    flow::{CreditedSession, Purpose, Record, SessionError},
    proto::NodeInfo,
};
use gcoms_crypto::{IdentityKeypair, LocalSecrets, SessionContext};
use rand::{rngs::StdRng, SeedableRng};

fn endpoint(seed: u8) -> (IdentityKeypair, NodeInfo, LocalSecrets) {
    let identity = IdentityKeypair::from_seed([seed; 32]);
    let (bundle, secrets) = identity.issue_bundle();
    let info = NodeInfo {
        identity_pk: identity.public_bytes(),
        bundle: bundle.encode(),
        aliases: vec![],
        provisioning: None,
    };
    (identity, info, secrets)
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn context(peer: &NodeInfo, tag: &[u8; 16]) -> SessionContext {
    use sha2::{Digest, Sha256};
    let peer: [u8; 32] = Sha256::digest(&peer.identity_pk).into();
    SessionContext::new(b"machine", b"gc2-test", peer, tag).unwrap()
}

#[test]
fn authenticated_setup_compact_frame_and_atomic_application_ack() {
    let (alice, ai, akeys) = endpoint(1);
    let (_, bi, bkeys) = endpoint(2);
    let mut rng = StdRng::seed_from_u64(7);
    let mut a = initiate(&alice, &ai, &akeys, &bi, now(), &mut rng).unwrap();
    let packet = Packet::decode(&a.packet).unwrap();
    let mut b = accept(&packet, &bi, &bkeys, now()).unwrap();
    assert_eq!(b.peer, ai);
    let at = context(&bi, packet.tag());
    let bt = context(&ai, packet.tag());
    let credit = a.session.prepare_credit(&b.credit).unwrap().unwrap();
    a.session.commit_credit(credit).unwrap();
    let record = Record::new(Purpose::Interactive, now() + 60, &[5; 128], &mut rng).unwrap();
    let send = a
        .session
        .prepare_send(&record, now(), &[7; 32], &at)
        .unwrap();
    let frame = Frame::decode(send.wire()).unwrap();
    let wire = encode_frame(packet.tag(), &frame).unwrap();
    // The public key and its old kind/length prefix are replaced by 20 bytes.
    assert_eq!(
        crate::proto::encode_frame(&ai.identity_pk, &frame).len() - wire.len(),
        1935
    );
    a.session.commit_send(send).unwrap();
    let frame = Packet::decode(&wire).unwrap().frame().unwrap();
    let received = b.session.prepare_receive(&frame, &[8; 32], &bt).unwrap();
    assert_eq!(received.record().unwrap().body(), &[5; 128]);
    let staged = b.session.stage_received(&received, &[8; 32], &bt).unwrap();
    let ack_body = Record::new(Purpose::Control, 0, b"application accepted ID", &mut rng).unwrap();
    let ack = staged
        .prepare_send(&ack_body, now(), &[8; 32], &bt)
        .unwrap();
    let ack_frame = Frame::decode(ack.wire()).unwrap();
    // The same post-receive/ACK snapshot is restartable before publishing either.
    let recovered =
        CreditedSession::restore(ack.sealed_ratchet(), &ack.private_flow(), &[8; 32], &bt).unwrap();
    let transport_credit = *received.credit();
    b.session.commit_receive(received).unwrap();
    b.session.commit_send(ack).unwrap();
    assert_eq!(
        b.session.window().encode_private(),
        recovered.window().encode_private()
    );
    let c = a
        .session
        .prepare_credit(&transport_credit)
        .unwrap()
        .unwrap();
    a.session.commit_credit(c).unwrap();
    let ack = a
        .session
        .prepare_receive(&ack_frame, &[7; 32], &at)
        .unwrap();
    assert_eq!(ack.record().unwrap().body(), b"application accepted ID");
}

#[test]
fn lost_first_credit_recovers_after_restart_without_reauthentication_or_effects() {
    let (alice, ai, akeys) = endpoint(3);
    let (_, bi, bkeys) = endpoint(4);
    let mut rng = StdRng::seed_from_u64(9);
    let mut a = initiate(&alice, &ai, &akeys, &bi, now(), &mut rng).unwrap();
    let packet = Packet::decode(&a.packet).unwrap();
    let b = accept(&packet, &bi, &bkeys, now()).unwrap();
    let ctx = context(&ai, packet.tag());
    let sealed = b.session.seal_ratchet(&[8; 32], &ctx).unwrap();
    let mut restored = CreditedSession::restore(
        &sealed,
        &b.session.window().encode_private(),
        &[8; 32],
        &ctx,
    )
    .unwrap();
    let retry = restored.prepare_first_move_retry(&packet).unwrap();
    assert!(retry.record().is_none());
    assert!(retry.sealed_ratchet().is_none());
    assert_eq!(retry.credit(), &b.credit);
    let credit = *retry.credit();
    restored.commit_receive(retry).unwrap();
    let prepared = a.session.prepare_credit(&credit).unwrap().unwrap();
    a.session.commit_credit(prepared).unwrap();
    assert_eq!(a.session.window().cached_payload_bytes(), 0);
    let mut changed = a.packet.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(restored
        .prepare_first_move_retry(&Packet::decode(&changed).unwrap())
        .is_err());
    changed = a.packet.clone();
    changed[4] ^= 1;
    assert!(restored
        .prepare_first_move_retry(&Packet::decode(&changed).unwrap())
        .is_err());
}

#[test]
fn setup_authenticates_tag_identity_bundle_and_exact_packet() {
    let (alice, ai, akeys) = endpoint(5);
    let (_, bi, bkeys) = endpoint(6);
    let (_, ci, ckeys) = endpoint(7);
    let mut rng = StdRng::seed_from_u64(11);
    let a = initiate(&alice, &ai, &akeys, &bi, now(), &mut rng).unwrap();
    for index in [
        4,
        19,
        SESSION_HEADER,
        SESSION_HEADER + 34,
        a.packet.len() - 1,
    ] {
        let mut bytes = a.packet.clone();
        bytes[index] ^= 1;
        assert!(
            accept(&Packet::decode(&bytes).unwrap(), &bi, &bkeys, now()).is_err(),
            "offset {index}"
        );
    }
    let packet = Packet::decode(&a.packet).unwrap();
    assert!(accept(&packet, &ci, &ckeys, now()).is_err());
    assert!(accept(&packet, &bi, &ckeys, now()).is_err());
    assert!(initiate(&alice, &ci, &ckeys, &bi, now(), &mut rng).is_err());
    assert!(initiate(&alice, &ai, &ckeys, &bi, now(), &mut rng).is_err());
    assert!(initiate(&alice, &ai, &akeys, &ai, now(), &mut rng).is_err());
    assert!(accept(&packet, &bi, &bkeys, now() + 31 * 86400).is_err());
}

#[test]
fn staged_ack_cannot_cross_session_restore_or_an_intervening_commit() {
    let (alice, ai, akeys) = endpoint(8);
    let (_, bi, bkeys) = endpoint(9);
    let mut rng = StdRng::seed_from_u64(13);
    let a = initiate(&alice, &ai, &akeys, &bi, now(), &mut rng).unwrap();
    let packet = Packet::decode(&a.packet).unwrap();
    let mut b = accept(&packet, &bi, &bkeys, now()).unwrap();
    let ctx = context(&ai, packet.tag());
    let retry = b.session.prepare_first_move_retry(&packet).unwrap();
    let staged = b.session.stage_received(&retry, &[8; 32], &ctx).unwrap();
    let ack = Record::new(Purpose::Control, 0, b"ack", &mut rng).unwrap();
    let prepared = staged.prepare_send(&ack, now(), &[8; 32], &ctx).unwrap();
    let other = b.session.prepare_first_move_retry(&packet).unwrap();
    b.session.commit_receive(other).unwrap();
    assert!(matches!(
        b.session.stage_received(&retry, &[8; 32], &ctx),
        Err(SessionError::StaleTransaction)
    ));
    assert!(matches!(
        b.session.commit_receive(retry),
        Err(SessionError::StaleTransaction)
    ));
    assert!(matches!(
        b.session.commit_send(prepared),
        Err(SessionError::StaleTransaction)
    ));
}

#[test]
fn packet_bounds_and_strict_flags_are_checked_before_allocating() {
    let mut frame = Frame {
        ctr: 1,
        pn: 0,
        sender_pub: [1; 32],
        mixed_with: None,
        pq_ct: None,
        ct: vec![0; 16],
    };
    let tag = [1; 16];
    let bytes = encode_frame(&tag, &frame).unwrap();
    for end in 0..bytes.len() {
        assert!(Packet::decode(&bytes[..end]).is_err());
    }
    for index in [SESSION_HEADER + 48, SESSION_HEADER + 49] {
        let mut bad = bytes.clone();
        bad[index] = 2;
        assert!(Packet::decode(&bad).is_err());
    }
    let mut bad = bytes.clone();
    bad[4..20].fill(0);
    assert!(Packet::decode(&bad).is_err());
    assert!(Packet::decode(&vec![0; MAX_MESSAGE + 1]).is_err());
    frame.pq_ct = Some(vec![0; u16::MAX as usize + 1]);
    assert!(encode_frame(&tag, &frame).is_err());
    frame.pq_ct = None;
    frame.ct.resize(MAX_MESSAGE - SESSION_HEADER - 50, 0);
    assert_eq!(encode_frame(&tag, &frame).unwrap().len(), MAX_MESSAGE);
    frame.ct.push(0);
    assert!(encode_frame(&tag, &frame).is_err());
    assert!(encode_frame(&[0; 16], &frame).is_err());
}

#[test]
fn maximum_record_body_fits_compact_packet_with_full_pq_header() {
    let frame = Frame {
        ctr: 2,
        pn: 1,
        sender_pub: [1; 32],
        mixed_with: Some([2; 32]),
        pq_ct: Some(vec![0; 1088]),
        ct: vec![0; crate::flow::RECORD_HEADER + crate::flow::MAX_RECORD_BODY + 16],
    };
    let packet = encode_frame(&[1; 16], &frame).unwrap();
    assert_eq!(packet.len(), MAX_MESSAGE);
    assert_eq!(
        Packet::decode(&packet).unwrap().frame().unwrap().ct.len(),
        frame.ct.len()
    );
}

#[test]
fn combined_archive_authenticates_tag_ratchet_window_key_and_peer_context() {
    let (alice, ai, akeys) = endpoint(10);
    let (_, bi, _) = endpoint(11);
    let mut rng = StdRng::seed_from_u64(19);
    let a = initiate(&alice, &ai, &akeys, &bi, now(), &mut rng).unwrap();
    let tag = *a.session.window().session();
    let ctx = context(&bi, &tag);
    let ratchet = a.session.seal_ratchet(&[7; 32], &ctx).unwrap();
    let sealed = SealedState::seal_parts(
        &tag,
        &ratchet,
        &a.session.window().encode_private(),
        &[7; 32],
        &mut rng,
    )
    .unwrap();
    let restored = sealed.open(&[7; 32], &ctx).unwrap();
    assert_eq!(restored.window().retries().next().unwrap().2, a.packet);
    assert!(sealed.open(&[8; 32], &ctx).is_err());
    assert!(sealed.open(&[7; 32], &context(&ai, &tag)).is_err());
    for index in [0, 4, 5, 20, 21, 32, 33, sealed.as_bytes().len() - 1] {
        let mut changed = sealed.as_bytes().to_vec();
        changed[index] ^= 1;
        assert!(
            SealedState::from_bytes(changed)
                .and_then(|s| s.open(&[7; 32], &ctx))
                .is_err(),
            "offset {index}"
        );
    }
    for length in [0, 4, 20, 32, 33, sealed.as_bytes().len() - 1] {
        assert!(
            SealedState::from_bytes(sealed.as_bytes()[..length].to_vec())
                .and_then(|s| s.open(&[7; 32], &ctx))
                .is_err()
        );
    }
    let wrong = crate::flow::Window::new(tag).unwrap();
    let mismatch =
        SealedState::seal_parts(&tag, &ratchet, &wrong.encode_private(), &[7; 32], &mut rng)
            .unwrap();
    assert!(mismatch.open(&[7; 32], &ctx).is_err());
}
