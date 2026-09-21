use super::*;
use crate::{
    flow::{CreditedSession, Purpose, Record, SessionError, Window},
    proto::NodeInfo,
};
use gcoms_crypto::{Bundle, CryptoError, IdentityKeypair, LocalSecrets, SessionTime};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

const HELLO_DOMAIN: &[u8] = b"GC2/peer-session\0";
const RECOVERY_DOMAIN: &[u8] = b"GC2/peer-recovery\0";
// ML-DSA-65 signature and the authenticated FirstMove framing. Bound public
// input before any encoder that stores a variable length in a narrow integer.
const SIGNATURE_BYTES: usize = 3309;
const BUNDLE_BYTES: usize = 32 + 2 + 1184 + 8 + 2 + SIGNATURE_BYTES;
const CONTACT_BYTES: usize = 1 + 16 + 2 + 32 + 32 + 8 + 32 + 8;
const INFO_FIXED: usize = 2 + 2 + 1952 + 4 + BUNDLE_BYTES + 1;
const MAX_INFO: usize = MAX_MESSAGE
    - SESSION_HEADER
    - (32 + 2 + 1088 + 12 + 16)
    - (4 + 2 + SIGNATURE_BYTES)
    - crate::flow::RECORD_HEADER
    - RECOVERY_DOMAIN.len()
    - 16
    - 8;

/// A new candidate, not yet durable or published. Persist its ratchet, flow
/// window, peer/tag binding and original packet atomically before sending.
pub struct Initiated {
    pub session: CreditedSession,
    pub packet: Vec<u8>,
}
/// Authentication succeeded, but no application or routing state was changed.
/// The caller must resolve collisions and persist the complete candidate before
/// publishing the peer/tag binding or emitting its non-ratcheted receipt.
pub struct Accepted {
    pub peer: NodeInfo,
    pub session: CreditedSession,
    pub credit: [u8; CREDIT_BYTES],
    /// True only for a signed recovery request with generation >= 2. The caller
    /// must compare generations with its current authenticated peer before use.
    pub recovery: bool,
}

fn bundle(info: &NodeInfo, now: u64) -> Result<Bundle, SessionError> {
    if info.identity_pk.len() != gcoms_crypto::identity::IDENTITY_PK_LEN
        || info.bundle.len() != BUNDLE_BYTES
        || info.aliases.len() > (MAX_INFO - INFO_FIXED) / CONTACT_BYTES
        || info.provisioning.is_some()
    {
        return Err(Error::Length.into());
    }
    let bundle = Bundle::decode(&info.bundle).ok_or(CryptoError::BundleInvalid)?;
    if !bundle.verify_fresh(&info.identity_pk, now) {
        return Err(CryptoError::BundleInvalid.into());
    }
    // The handshake carries public contact information only, in its exact
    // canonical form. It cannot smuggle owner provisioning authority.
    let encoded = info.public().encode();
    let decoded = NodeInfo::decode(&encoded).ok_or(Error::Length)?;
    if decoded != *info || encoded.len() > MAX_INFO {
        return Err(Error::State.into());
    }
    Ok(bundle)
}

#[cfg(feature = "std")]
pub fn initiate(
    identity: &IdentityKeypair,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    peer: &NodeInfo,
    now: u64,
    entropy: &mut (impl RngCore + CryptoRng),
) -> Result<Initiated, SessionError> {
    initiate_at(
        identity,
        own,
        secrets,
        peer,
        now,
        std::time::Instant::now(),
        entropy,
    )
}

pub fn initiate_at(
    identity: &IdentityKeypair,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    peer: &NodeInfo,
    now: u64,
    monotonic: SessionTime,
    entropy: &mut (impl RngCore + CryptoRng),
) -> Result<Initiated, SessionError> {
    initiate_generation(identity, own, secrets, peer, 1, now, monotonic, entropy)
}

/// Explicit identity-authenticated recovery. The caller persists this candidate
/// before sending and must never roll back its peer's emitted generation.
#[cfg(feature = "std")]
pub fn initiate_recovery(
    identity: &IdentityKeypair,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    peer: &NodeInfo,
    generation: u64,
    now: u64,
    entropy: &mut (impl RngCore + CryptoRng),
) -> Result<Initiated, SessionError> {
    initiate_recovery_at(
        identity,
        own,
        secrets,
        peer,
        generation,
        now,
        std::time::Instant::now(),
        entropy,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn initiate_recovery_at(
    identity: &IdentityKeypair,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    peer: &NodeInfo,
    generation: u64,
    now: u64,
    monotonic: SessionTime,
    entropy: &mut (impl RngCore + CryptoRng),
) -> Result<Initiated, SessionError> {
    if generation < 2 {
        return Err(Error::State.into());
    }
    initiate_generation(
        identity, own, secrets, peer, generation, now, monotonic, entropy,
    )
}

#[allow(clippy::too_many_arguments)]
fn initiate_generation(
    identity: &IdentityKeypair,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    peer: &NodeInfo,
    generation: u64,
    now: u64,
    monotonic: SessionTime,
    entropy: &mut (impl RngCore + CryptoRng),
) -> Result<Initiated, SessionError> {
    if identity.public_bytes() != own.identity_pk || own.identity_pk == peer.identity_pk {
        return Err(Error::Authentication.into());
    }
    let local = bundle(own, now)?;
    check_secrets(&local, secrets)?;
    let remote = bundle(peer, now)?;
    let mut tag = [0; 16];
    entropy
        .try_fill_bytes(&mut tag)
        .map_err(|_| CryptoError::Entropy)?;
    if tag == [0; 16] {
        return Err(CryptoError::Entropy.into());
    }
    let domain = if generation == 1 {
        HELLO_DOMAIN
    } else {
        RECOVERY_DOMAIN
    };
    let mut hello = Zeroizing::new(domain.to_vec());
    hello.extend_from_slice(&tag);
    if generation > 1 {
        hello.extend_from_slice(&generation.to_be_bytes());
    }
    hello.extend_from_slice(&own.public().encode());
    let record = Record::new(Purpose::Control, 0, &hello, entropy)?;
    let (first, mut ratchet) = gcoms_crypto::initiate_authenticated_with_rng_at(
        identity,
        &peer.identity_pk,
        &remote,
        &record.encode(),
        entropy,
        monotonic,
    )?;
    ratchet.provide_local_kem(secrets.kem_decapsulation_key());
    let packet = encode_first_move(&tag, &first)?;
    let mut window = Window::new_generation(tag, generation)?;
    window.record_sent(1, &packet, &record, now)?;
    Ok(Initiated {
        session: CreditedSession::from_authenticated(ratchet, window)?,
        packet,
    })
}

#[cfg(feature = "std")]
pub fn accept(
    packet: &Packet<'_>,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    now: u64,
) -> Result<Accepted, SessionError> {
    accept_at(
        packet,
        own,
        secrets,
        now,
        std::time::Instant::now(),
        &mut rand_core::OsRng,
    )
}

pub fn accept_at(
    packet: &Packet<'_>,
    own: &NodeInfo,
    secrets: &LocalSecrets,
    now: u64,
    monotonic: SessionTime,
    entropy: &mut (impl RngCore + CryptoRng),
) -> Result<Accepted, SessionError> {
    let own_bundle = bundle(own, now)?;
    check_secrets(&own_bundle, secrets)?;
    let first = packet.first_move()?;
    let (plain, mut ratchet) = secrets.accept_with_rng_at(&first, entropy, monotonic)?;
    let plain = Zeroizing::new(plain);
    let (signed, signature) =
        gcoms_crypto::split_authenticated_payload(&plain).ok_or(CryptoError::BadEncoding)?;
    let record = Record::decode(signed)?;
    let body = record.body();
    let (domain, recovery) = if body.starts_with(HELLO_DOMAIN) {
        (HELLO_DOMAIN, false)
    } else if body.starts_with(RECOVERY_DOMAIN) {
        (RECOVERY_DOMAIN, true)
    } else {
        return Err(Error::Authentication.into());
    };
    let tag_end = domain.len() + 16;
    if record.purpose() != Purpose::Control
        || record.not_after() != 0
        || body.get(domain.len()..tag_end) != Some(packet.tag().as_slice())
    {
        return Err(Error::Authentication.into());
    }
    let info_start = tag_end + if recovery { 8 } else { 0 };
    let generation = if recovery {
        let bytes = body.get(tag_end..info_start).ok_or(Error::Length)?;
        let value = u64::from_be_bytes(bytes.try_into().map_err(|_| Error::Length)?);
        if value < 2 {
            return Err(Error::State.into());
        }
        value
    } else {
        1
    };
    let encoded = body.get(info_start..).ok_or(Error::Length)?;
    let peer = NodeInfo::decode(encoded).ok_or(Error::Length)?;
    if peer.public().encode() != encoded || peer.identity_pk == own.identity_pk {
        return Err(Error::Authentication.into());
    }
    let peer_bundle = bundle(&peer, now)?;
    if !gcoms_crypto::verify_first_move_auth(
        &first,
        &peer.identity_pk,
        &own.identity_pk,
        &own_bundle,
        signed,
        signature,
    ) {
        return Err(CryptoError::BadSignature.into());
    }
    ratchet.provide_peer_kem(peer_bundle.kem_pub)?;
    let mut window = Window::new_generation(*packet.tag(), generation)?;
    window.record_authenticated(1, packet.bytes(), &record)?;
    let credit = window.credit_for_duplicate(1, packet.bytes())?;
    Ok(Accepted {
        recovery,
        peer,
        session: CreditedSession::from_authenticated(ratchet, window)?,
        credit,
    })
}

fn check_secrets(bundle: &Bundle, secrets: &LocalSecrets) -> Result<(), SessionError> {
    let (ecdh, kem) = secrets.public_material();
    if ecdh != bundle.ecdh_pub || kem != bundle.kem_pub {
        return Err(CryptoError::BundleInvalid.into());
    }
    Ok(())
}
