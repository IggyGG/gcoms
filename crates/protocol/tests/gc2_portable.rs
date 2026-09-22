#![cfg(feature = "gc2-session")]

use gcoms_crypto::{Frame, IdentityKeypair, LocalSecrets, SessionContext, SessionTime};
use gcoms_protocol::{
    flow::{CreditedSession, Purpose, Record},
    gc2_session::{accept_at, initiate_at, initiate_recovery_at, Packet, SealedState},
    proto::NodeInfo,
};
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use std::time::Duration;

const UNIX: u64 = 1_800_000_000;
const KEY: [u8; 32] = [71; 32];

fn clock() -> SessionTime {
    #[cfg(feature = "std")]
    {
        std::time::Instant::now()
    }
    #[cfg(not(feature = "std"))]
    {
        Duration::from_secs(100)
    }
}

fn endpoint(seed: u8) -> (IdentityKeypair, NodeInfo, LocalSecrets) {
    let identity = IdentityKeypair::from_seed([seed; 32]);
    let mut entropy = StdRng::seed_from_u64(u64::from(seed));
    let (bundle, secrets) = identity.issue_bundle_with_rng(&mut entropy, UNIX).unwrap();
    let info = NodeInfo {
        identity_pk: identity.public_bytes(),
        bundle: bundle.encode(),
        provisioning: None,
        aliases: vec![],
    };
    (identity, info, secrets)
}

fn context(peer: &NodeInfo, tag: &[u8; 16]) -> SessionContext {
    SessionContext::new(
        b"installer",
        b"portable-gc2",
        Sha256::digest(&peer.identity_pk),
        tag,
    )
    .unwrap()
}

fn archive(
    session: &CreditedSession,
    context: &SessionContext,
    now: SessionTime,
    rng: &mut StdRng,
) -> SealedState {
    let ratchet = session.seal_ratchet_at(&KEY, context, now, rng).unwrap();
    SealedState::seal_parts(
        session.window().session(),
        &ratchet,
        &session.window().encode_private(),
        &KEY,
        rng,
    )
    .unwrap()
}

#[test]
fn portable_restart_repairs_lost_credit_without_reapplying_the_message() {
    let (alice, ai, ak) = endpoint(81);
    let (_, bi, bk) = endpoint(82);
    let mut rng = StdRng::seed_from_u64(83);
    let t = clock();
    let mut a = initiate_at(&alice, &ai, &ak, &bi, UNIX, t, &mut rng).unwrap();
    let packet = Packet::decode(&a.packet).unwrap();
    let b = accept_at(&packet, &bi, &bk, UNIX, t, &mut rng).unwrap();
    let ac = context(&bi, packet.tag());
    let bc = context(&ai, packet.tag());
    let state = archive(&b.session, &bc, t, &mut rng);
    let mut b = state
        .open_at(
            &KEY,
            &bc,
            t + Duration::from_secs(2),
            Duration::from_secs(2),
            &mut rng,
        )
        .unwrap();
    let retry = b.prepare_first_move_retry(&packet).unwrap();
    assert!(retry.record().is_none());
    let credit = *retry.credit();
    b.commit_receive(retry).unwrap();
    let received = a.session.prepare_credit(&credit).unwrap().unwrap();
    a.session.commit_credit(received).unwrap();
    assert_eq!(a.session.window().cached_payload_bytes(), 0);

    let t = t + Duration::from_secs(3);
    let body = Record::new(
        Purpose::Interactive,
        UNIX + 60,
        b"download next chunk",
        &mut rng,
    )
    .unwrap();
    let send = a
        .session
        .prepare_send_at(&body, UNIX + 3, &KEY, &ac, t, &mut rng)
        .unwrap();
    let frame = Frame::decode(send.wire()).unwrap();
    a.session.commit_send(send).unwrap();
    let received = b
        .prepare_receive_at(&frame, &KEY, &bc, t, &mut rng)
        .unwrap();
    assert_eq!(received.record().unwrap().body(), b"download next chunk");
    let credit = *received.credit();
    b.commit_receive(received).unwrap();
    let state = archive(&b, &bc, t, &mut rng);
    let mut b = state
        .open_at(
            &KEY,
            &bc,
            t + Duration::from_secs(1),
            Duration::from_secs(1),
            &mut rng,
        )
        .unwrap();
    let duplicate = b
        .prepare_receive_at(&frame, &KEY, &bc, t + Duration::from_secs(1), &mut rng)
        .unwrap();
    assert!(duplicate.record().is_none());
    assert_eq!(duplicate.credit(), &credit);
    b.commit_receive(duplicate).unwrap();
    let mut changed = frame;
    *changed.ct.last_mut().unwrap() ^= 1;
    assert!(b
        .prepare_receive_at(&changed, &KEY, &bc, t + Duration::from_secs(1), &mut rng)
        .is_err());
    let received = a.session.prepare_credit(&credit).unwrap().unwrap();
    a.session.commit_credit(received).unwrap();
    assert_eq!(a.session.window().cached_payload_bytes(), 0);
}

#[test]
fn portable_recovery_authenticates_generation_archive_and_credit() {
    let (alice, ai, ak) = endpoint(84);
    let (_, bi, bk) = endpoint(85);
    let mut rng = StdRng::seed_from_u64(86);
    let t = clock();
    assert!(initiate_recovery_at(&alice, &ai, &ak, &bi, 1, UNIX, t, &mut rng).is_err());
    let mut a = initiate_recovery_at(&alice, &ai, &ak, &bi, 7, UNIX, t, &mut rng).unwrap();
    let b = accept_at(
        &Packet::decode(&a.packet).unwrap(),
        &bi,
        &bk,
        UNIX,
        t,
        &mut rng,
    )
    .unwrap();
    assert!(b.recovery);
    assert_eq!(b.session.window().generation(), 7);
    let before = a.session.window().encode_private();
    let mut forged = b.credit;
    *forged.last_mut().unwrap() ^= 1;
    assert!(a.session.prepare_credit(&forged).is_err());
    assert_eq!(before, a.session.window().encode_private());
    let ac = context(&bi, a.session.window().session());
    let sealed = archive(&a.session, &ac, t, &mut rng);
    let restored = sealed
        .open_at(
            &KEY,
            &ac,
            t + Duration::from_secs(1),
            Duration::from_secs(1),
            &mut rng,
        )
        .unwrap();
    assert_eq!(restored.window().generation(), 7);
    assert_eq!(restored.window().retries().next().unwrap().2, a.packet);
    assert!(sealed
        .open_at(&[0; 32], &ac, t, Duration::ZERO, &mut rng)
        .is_err());
    let wrong_peer = context(&ai, a.session.window().session());
    assert!(sealed
        .open_at(&KEY, &wrong_peer, t, Duration::ZERO, &mut rng)
        .is_err());
    let mut damaged = sealed.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(SealedState::from_bytes(damaged)
        .unwrap()
        .open_at(&KEY, &ac, t, Duration::ZERO, &mut rng)
        .is_err());
    let received = a.session.prepare_credit(&b.credit).unwrap().unwrap();
    a.session.commit_credit(received).unwrap();
}
