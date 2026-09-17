//! Deterministic GC/1 cryptographic transcript used by the conformance runner.
//!
//! Gated behind `test-vectors`: it embeds fixed seeds and must not ship in a
//! client build.
#![cfg(any(test, feature = "test-vectors"))]

use crate::session::{initiate_from_material, InitiatorMaterial, ResponderMaterial};
use crate::{CryptoError, IdentityKeypair};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Produce the deterministic crypto values defined by GC/1 conformance vector v1.
pub fn transcript() -> Result<Vec<(&'static str, String)>, CryptoError> {
    let identity = IdentityKeypair::from_seed([0x11; 32]);
    let identity_public = identity.public_bytes();
    let signature = identity.sign(b"GC/1 conformance v1");
    let (bundle, secrets) = identity.issue_bundle_from_material(
        [0x22; 32],
        std::array::from_fn(|i| i as u8),
        0x0102_0304_0506_0708,
    );

    let initiator = InitiatorMaterial {
        eph: [0x33; 32],
        kem_message: [0x44; 32],
        nonce: [0x55; 12],
        ratchet: [0x66; 32],
    };
    let (first_move, mut alice) = initiate_from_material(
        &identity_public,
        &bundle,
        b"first payload",
        &initiator,
        StdRng::from_seed([0x77; 32]),
    )?;
    let responder = ResponderMaterial {
        ratchet: [0x88; 32],
    };
    let (payload, mut bob) =
        secrets.accept_from_material(&first_move, &responder, StdRng::from_seed([0x99; 32]))?;
    if payload != b"first payload" {
        return Err(CryptoError::Decrypt);
    }

    let frame_a = alice.send(b"alice frame")?;
    if bob.receive(&frame_a)? != b"alice frame" {
        return Err(CryptoError::Decrypt);
    }
    let frame_b = bob.send(b"bob frame")?;
    if alice.receive(&frame_b)? != b"bob frame" {
        return Err(CryptoError::Decrypt);
    }
    alice.set_pq_policy(1, std::time::Duration::from_secs(3600));
    let frame_pq = alice.send(b"pq frame")?;
    if frame_pq.pq_ct.is_none() || bob.receive(&frame_pq)? != b"pq frame" {
        return Err(CryptoError::Decrypt);
    }

    Ok(vec![
        ("crypto.identity_public.sha256", digest(&identity_public)),
        ("crypto.signature.sha256", digest(&signature)),
        ("crypto.safety_number", identity.safety_number()),
        ("crypto.bundle.sha256", digest(&bundle.encode())),
        ("crypto.first_move.sha256", digest(&first_move.encode())),
        ("crypto.frame_alice.sha256", digest(&frame_a.encode())),
        ("crypto.frame_bob.sha256", digest(&frame_b.encode())),
        ("crypto.frame_pq.sha256", digest(&frame_pq.encode())),
    ])
}
