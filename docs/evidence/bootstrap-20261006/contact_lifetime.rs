use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gc_core::bootstrap::{
    CONTACT_DOMAIN, MAX_CONTACT_LIFETIME_SECONDS, MAX_PROOF_LIFETIME_SECONDS,
    RELAY_ADMISSION_DOMAIN, VERSION,
};
use gc_crypto::IdentityKeypair;
use gc_protocol::{alias::AliasContact, proto::NodeInfo, relay::RelayTarget};
use ghost_bootstrap_protocol::{digest, relay::Admission, ContactRecord, Error, NativeTarget};

const WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";
const PROFILE: &str = "22222222-2222-4222-8222-222222222222";
const REQUEST: &str = "33333333-3333-4333-8333-333333333333";
const NOW: u64 = 100_000;

fn contact() -> (ContactRecord, NodeInfo) {
    let identity = IdentityKeypair::from_seed([27; 32]);
    let (bundle, _) = identity.issue_bundle_from_material([28; 32], [29; 64], NOW);
    let expiry = NOW + MAX_CONTACT_LIFETIME_SECONDS;
    let alias = AliasContact {
        target: RelayTarget {
            address: "127.0.0.1:443".parse().unwrap(),
            relay_service_id: [31; 32],
        },
        queue_id: [32; 32],
        epoch: 1,
        push_cap: [33; 32],
        expiry,
    };
    let info = NodeInfo {
        identity_pk: identity.public_bytes(),
        bundle: bundle.encode(),
        aliases: vec![alias.clone(), alias],
        provisioning: None,
    };
    let record = ContactRecord {
        domain: CONTACT_DOMAIN.into(),
        version: VERSION,
        workspace_id: WORKSPACE.into(),
        profile_id: PROFILE.into(),
        peer_identity_sha256: digest(&info.identity_pk),
        contact: URL_SAFE_NO_PAD.encode(info.encode()),
        created_at_unix: NOW,
        expires_at_unix: expiry,
    };
    (record, info)
}

#[test]
fn contact_accepts_the_full_day_but_not_one_second_more_or_expired_records() {
    assert_eq!(MAX_CONTACT_LIFETIME_SECONDS, 86_400);
    let (mut record, info) = contact();
    for lifetime in [300, 301, MAX_CONTACT_LIFETIME_SECONDS] {
        record.expires_at_unix = NOW + lifetime;
        assert_eq!(
            record.validate(WORKSPACE, PROFILE, &record.peer_identity_sha256, NOW),
            Ok(info.clone())
        );
    }
    record.expires_at_unix += 1;
    assert_eq!(
        record.validate(WORKSPACE, PROFILE, &record.peer_identity_sha256, NOW),
        Err(Error::Expired)
    );
    record.expires_at_unix -= 1;
    assert_eq!(
        record.validate(
            WORKSPACE,
            PROFILE,
            &record.peer_identity_sha256,
            record.expires_at_unix,
        ),
        Err(Error::Expired)
    );
}

#[test]
fn every_alias_must_cover_the_contact_expiry() {
    let (mut record, mut info) = contact();
    assert!(record
        .validate(WORKSPACE, PROFILE, &record.peer_identity_sha256, NOW)
        .is_ok());
    for expiry in [record.expires_at_unix - 1, NOW] {
        info.aliases[1].expiry = expiry;
        record.contact = URL_SAFE_NO_PAD.encode(info.encode());
        assert_eq!(
            record.validate(WORKSPACE, PROFILE, &record.peer_identity_sha256, NOW),
            Err(Error::Unauthorized)
        );
    }
}

#[test]
fn contact_rejects_malformed_bytes_wrong_identity_and_invalid_bundle_signature() {
    let (record, mut info) = contact();
    let mut malformed = record.clone();
    malformed.contact = "*".into();
    assert_eq!(
        malformed.validate(WORKSPACE, PROFILE, &record.peer_identity_sha256, NOW),
        Err(Error::Malformed)
    );
    assert_eq!(
        record.validate(WORKSPACE, PROFILE, &"00".repeat(32), NOW),
        Err(Error::Unauthorized)
    );
    *info.bundle.last_mut().unwrap() ^= 1;
    let mut corrupted = record;
    corrupted.contact = URL_SAFE_NO_PAD.encode(info.encode());
    assert_eq!(
        corrupted.validate(WORKSPACE, PROFILE, &corrupted.peer_identity_sha256, NOW),
        Err(Error::Unauthorized)
    );
}

#[test]
fn relay_admission_keeps_the_five_minute_proof_limit() {
    assert_eq!(MAX_PROOF_LIFETIME_SECONDS, 300);
    let mut proof = Admission {
        domain: RELAY_ADMISSION_DOMAIN.into(),
        version: VERSION,
        operation: "relay-admit".into(),
        workspace_id: WORKSPACE.into(),
        profile_id: PROFILE.into(),
        request_id: REQUEST.into(),
        target: NativeTarget::LinuxX64,
        peer_identity_sha256: "44".repeat(32),
        relay_service_id: "55".repeat(32),
        relay_challenge: "66".repeat(32),
        contact_sha256: "77".repeat(32),
        created_at_unix: NOW,
        expires_at_unix: NOW + 300,
        lease_expires_at_unix: NOW + 18_000,
    };
    assert!(proof
        .validate(WORKSPACE, PROFILE, &[0x55; 32], &[0x66; 32], NOW)
        .is_ok());
    proof.expires_at_unix += 1;
    assert_eq!(
        proof.validate(WORKSPACE, PROFILE, &[0x55; 32], &[0x66; 32], NOW),
        Err(Error::Expired)
    );
}
