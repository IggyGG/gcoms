//! Run both with and without default features. These deterministic RNGs belong
//! only to the test harness; production callers must use operating-system entropy.
use core::time::Duration;
use gcoms_crypto::{initiate_authenticated_with_rng_at, CryptoError, IdentityKeypair, SessionTime};
use rand::{rngs::StdRng, SeedableRng};

fn start() -> SessionTime {
    #[cfg(feature = "std")]
    {
        std::time::Instant::now()
    }
    #[cfg(not(feature = "std"))]
    {
        Duration::ZERO
    }
}

#[test]
fn explicit_entropy_and_clock_preserve_authenticated_bidirectional_pq() {
    let now = start();
    let mut rng = StdRng::from_seed([17; 32]);
    let alice = IdentityKeypair::try_generate(&mut rng).unwrap();
    let bob = IdentityKeypair::try_generate(&mut rng).unwrap();
    assert_ne!(alice.public_bytes(), bob.public_bytes());
    let (ab, aks) = alice.issue_bundle_with_rng(&mut rng, 1_000).unwrap();
    let (bb, bks) = bob.issue_bundle_with_rng(&mut rng, 1_000).unwrap();
    let (fm, mut a) = initiate_authenticated_with_rng_at(
        &alice,
        &bob.public_bytes(),
        &bb,
        b"authenticated contact",
        &mut rng,
        now,
    )
    .unwrap();
    let (payload, mut b) = bks.accept_with_rng_at(&fm, &mut rng, now).unwrap();
    let (body, sig) = gcoms_crypto::split_authenticated_payload(&payload).unwrap();
    assert_eq!(body, b"authenticated contact");
    assert!(gcoms_crypto::verify_first_move_auth(
        &fm,
        &alice.public_bytes(),
        &bob.public_bytes(),
        &bb,
        body,
        sig
    ));
    assert!(!gcoms_crypto::verify_first_move_auth(
        &fm,
        &bob.public_bytes(),
        &bob.public_bytes(),
        &bb,
        body,
        sig
    ));
    a.provide_local_kem(aks.kem_decapsulation_key());
    b.provide_peer_kem(ab.kem_pub).unwrap();
    let mut pq = [0, 0];
    for i in 1u64..=100 {
        let time = now + Duration::from_secs(i * 60);
        let f = a.send_at(&i.to_be_bytes(), time).unwrap();
        pq[0] += usize::from(f.pq_ct.is_some());
        let original = f.encode();
        let mut tampered = gcoms_crypto::Frame::decode(&original).unwrap();
        tampered.ct[0] ^= 1;
        let before = b.recv_ctr();
        assert_eq!(b.receive_at(&tampered, time), Err(CryptoError::Decrypt));
        assert_eq!(b.recv_ctr(), before);
        assert_eq!(b.receive_at(&f, time).unwrap(), i.to_be_bytes());
        assert_eq!(b.receive_at(&f, time), Err(CryptoError::Replay));
        let reply = b.send_at(b"ack", time).unwrap();
        pq[1] += usize::from(reply.pq_ct.is_some());
        assert_eq!(a.receive_at(&reply, time).unwrap(), b"ack");
    }
    assert!(
        pq.iter().all(|n| *n >= 2),
        "both directions must refresh: {pq:?}"
    );
}

#[test]
fn skipped_key_expiry_is_enforced_without_another_in_order_frame() {
    let now = start();
    let mut rng = StdRng::from_seed([18; 32]);
    let alice = IdentityKeypair::try_generate(&mut rng).unwrap();
    let bob = IdentityKeypair::try_generate(&mut rng).unwrap();
    let (bb, bks) = bob.issue_bundle_with_rng(&mut rng, 1_000).unwrap();
    let (fm, mut a) = initiate_authenticated_with_rng_at(
        &alice,
        &bob.public_bytes(),
        &bb,
        b"contact",
        &mut rng,
        now,
    )
    .unwrap();
    let (_, mut b) = bks.accept_with_rng_at(&fm, &mut rng, now).unwrap();
    let late = a.send_at(b"late", now).unwrap();
    let next = a.send_at(b"next", now).unwrap();
    assert_eq!(b.receive_at(&next, now).unwrap(), b"next");
    assert_eq!(b.skipped_keys(), 1);
    assert_eq!(
        b.receive_at(&late, now + gcoms_crypto::SKIP_KEY_TTL),
        Err(CryptoError::Replay)
    );
    assert_eq!(b.skipped_keys(), 0);
}

struct FailedEntropy;
impl rand::CryptoRng for FailedEntropy {}
impl rand::RngCore for FailedEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("must use fallible entropy")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("must use fallible entropy")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("must use fallible entropy")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::from(
            core::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap(),
        ))
    }
}

#[test]
fn platform_entropy_failure_never_creates_an_identity_bundle_or_session() {
    let id = IdentityKeypair::from_seed([1; 32]);
    let mut rng = FailedEntropy;
    assert!(matches!(
        IdentityKeypair::try_generate(&mut rng),
        Err(CryptoError::Entropy)
    ));
    assert!(matches!(
        id.issue_bundle_with_rng(&mut rng, 1_000),
        Err(CryptoError::Entropy)
    ));
    let mut good = StdRng::from_seed([19; 32]);
    let (bundle, _) = id.issue_bundle_with_rng(&mut good, 1_000).unwrap();
    assert!(matches!(
        initiate_authenticated_with_rng_at(
            &id,
            &id.public_bytes(),
            &bundle,
            b"contact",
            &mut rng,
            start()
        ),
        Err(CryptoError::Entropy)
    ));
}
