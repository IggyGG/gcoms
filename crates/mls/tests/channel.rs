use gcoms_crypto::IdentityKeypair;
use gcoms_mls::{
    ciphersuite_of_key_package, ciphersuite_of_welcome, Caps, ChannelMember, MlsError,
    OwnerSession, CIPHERSUITE_ID, MAX_KEY_PACKAGE_BYTES,
};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, MlsMessageOut, SignaturePublicKey,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as _;

fn owner_identity() -> IdentityKeypair {
    IdentityKeypair::from_seed([0x5A; 32])
}

fn classical_key_package(name: &str) -> Vec<u8> {
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let backend = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
    signer.store(backend.storage()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: SignaturePublicKey::from(signer.to_public_vec()),
    };
    let bundle = KeyPackage::builder()
        .build(suite, &backend, &signer, credential)
        .unwrap();
    MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .unwrap()
}

#[test]
fn channel_full_lifecycle() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    assert_eq!(owner.ciphersuite(), CIPHERSUITE_ID);

    let prepared_red = ChannelMember::prepare("redwing").unwrap();
    let key_package = ChannelMember::key_package_bytes(&prepared_red).unwrap();
    assert_eq!(
        ciphersuite_of_key_package(&key_package),
        Some(CIPHERSUITE_ID)
    );
    assert!(key_package.len() <= MAX_KEY_PACKAGE_BYTES);
    let invite = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared_red).unwrap(),
        "redwing",
        Caps::member(),
        3600,
    );
    let admission = owner
        .admit(
            &invite,
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared_red).unwrap(),
        )
        .unwrap();
    let mut red = ChannelMember::join(prepared_red, &admission.welcome).unwrap();
    assert_eq!(
        ciphersuite_of_welcome(&admission.welcome),
        Some(CIPHERSUITE_ID)
    );
    assert_eq!(red.ciphersuite(), CIPHERSUITE_ID);
    assert!(admission.commit.len() <= gcoms_core::MAX_MESSAGE);

    assert_eq!(owner.roster().len(), 2);
    assert_eq!(red.roster(), owner.roster());
    assert_eq!(owner.epoch(), red.epoch());

    let msg = owner.send(b"first broadcast").unwrap();
    let got = red.receive(&msg).unwrap().unwrap();
    assert_eq!(got.1, b"first broadcast");
    assert_eq!(got.0, 0, "owner is leaf 0");

    let reply = red.send(b"member reply").unwrap();
    let got_back = owner.receive(&reply).unwrap().unwrap();
    assert_eq!(got_back.1, b"member reply");
    assert_eq!(got_back.0, 1, "redwing is leaf 1");

    let old_epoch = red.epoch();
    let update = red.update().unwrap();
    assert!(update.len() <= gcoms_core::MAX_MESSAGE);
    assert!(red.epoch() > old_epoch);
    assert!(owner.receive(&update).unwrap().is_none());
    assert_eq!(owner.epoch(), red.epoch());
}

#[test]
fn rejects_classical_key_packages_and_welcomes() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let oversized = vec![0; MAX_KEY_PACKAGE_BYTES + 1];
    let oversized_invite =
        owner.sign_invite_key_package(&oversized, "oversized", Caps::member(), 3600);
    assert!(matches!(
        owner.admit(&oversized_invite, &oversized),
        Err(MlsError::Encoding)
    ));
    assert_eq!(ciphersuite_of_key_package(&oversized), None);

    let classical = classical_key_package("downgrade");
    assert_eq!(ciphersuite_of_key_package(&classical), Some(0x0001));
    let invite = owner.sign_invite_key_package(&classical, "downgrade", Caps::member(), 3600);
    assert!(matches!(
        owner.admit(&invite, &classical),
        Err(MlsError::UnsupportedCiphersuite(0x0001))
    ));

    let prepared = ChannelMember::prepare("member").unwrap();
    let key_package = ChannelMember::key_package_bytes(&prepared).unwrap();
    let invite = owner.sign_invite_key_package(&key_package, "member", Caps::member(), 3600);
    let mut welcome = owner.admit(&invite, &key_package).unwrap().welcome;
    assert_eq!(&welcome[4..6], &CIPHERSUITE_ID.to_be_bytes());
    welcome[4..6].copy_from_slice(&0x0001u16.to_be_bytes());
    assert_eq!(ciphersuite_of_welcome(&welcome), Some(0x0001));
    assert!(matches!(
        ChannelMember::join(prepared, &welcome),
        Err(MlsError::UnsupportedCiphersuite(0x0001))
    ));
}

#[test]
fn pq_framing_sizes_fit_two_party_transport_boundaries() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let prepared = ChannelMember::prepare("member").unwrap();
    let key_package = ChannelMember::key_package_bytes(&prepared).unwrap();
    let invite = owner.sign_invite_key_package(&key_package, "member", Caps::member(), 3600);
    let admission = owner.admit(&invite, &key_package).unwrap();
    let mut member = ChannelMember::join(prepared, &admission.welcome).unwrap();
    let application = owner
        .send(&vec![0x5a; gcoms_core::APPLICATION_PAYLOAD_LIMIT])
        .unwrap();
    let update = member.update().unwrap();

    assert!(key_package.len() <= MAX_KEY_PACKAGE_BYTES);
    assert!(admission.commit.len() <= gcoms_core::MAX_MESSAGE);
    assert!(application.len() <= gcoms_core::MAX_MESSAGE);
    assert!(update.len() <= gcoms_core::MAX_MESSAGE);
    assert!(admission.welcome.len() < 64 * 1024);
    eprintln!(
        "PQ MLS bytes: key_package={}, welcome={}, add_commit={}, update_commit={}, max_app={}",
        key_package.len(),
        admission.welcome.len(),
        admission.commit.len(),
        update.len(),
        application.len()
    );
}

#[test]
fn pq_membership_framing_crosses_single_cell_boundary() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 8).unwrap();
    let mut maximum_commit = 0;
    let mut maximum_welcome = 0;
    let mut sizes = Vec::new();
    for index in 1..8 {
        let name = format!("member-{index}");
        let prepared = ChannelMember::prepare(&name).unwrap();
        let key_package = ChannelMember::key_package_bytes(&prepared).unwrap();
        let invite = owner.sign_invite_key_package(&key_package, &name, Caps::member(), 3600);
        let admission = owner.admit(&invite, &key_package).unwrap();
        maximum_commit = maximum_commit.max(admission.commit.len());
        maximum_welcome = maximum_welcome.max(admission.welcome.len());
        sizes.push((
            owner.roster().len(),
            admission.commit.len(),
            admission.welcome.len(),
        ));
        let joined = ChannelMember::join(prepared, &admission.welcome).unwrap();
        assert_eq!(joined.ciphersuite(), CIPHERSUITE_ID);
    }

    eprintln!(
        "8-member PQ MLS sizes {sizes:?}; maxima: commit={maximum_commit}, welcome={maximum_welcome}"
    );
    // With the fingerprint group id (32 bytes instead of the 1,984-byte
    // owner key) an 8-member commit fits one cell and the Welcome spills into
    // a second; both stay well inside the bounded fragment budget.
    assert!(maximum_commit <= gcoms_core::MAX_MESSAGE);
    assert!(maximum_welcome > gcoms_core::MAX_MESSAGE);
    assert_eq!(maximum_welcome.div_ceil(gcoms_core::MAX_MESSAGE), 2);
    assert!(maximum_welcome < 64 * 1024);
}

#[test]
fn existing_members_process_admission_commit() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();

    let p1 = ChannelMember::prepare("one").unwrap();
    let inv1 = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&p1).unwrap(),
        "one",
        Caps::member(),
        3600,
    );
    let adm1 = owner
        .admit(
            &inv1,
            &gcoms_mls::ChannelMember::key_package_bytes(&p1).unwrap(),
        )
        .unwrap();
    let mut one = ChannelMember::join(p1, &adm1.welcome).unwrap();

    let p2 = ChannelMember::prepare("two").unwrap();
    let inv2 = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&p2).unwrap(),
        "two",
        Caps::member(),
        3600,
    );
    let adm2 = owner
        .admit(
            &inv2,
            &gcoms_mls::ChannelMember::key_package_bytes(&p2).unwrap(),
        )
        .unwrap();

    let existing_view = one.receive(&adm2.commit).unwrap();
    assert!(existing_view.is_none(), "commit carries no app payload");

    assert_eq!(one.epoch(), owner.epoch());
    assert_eq!(one.roster().len(), 3);
    assert!(one.roster().iter().any(|(_, name)| name == "two"));

    let msg = one.send(b"after admission").unwrap();
    let mut two = ChannelMember::join(p2, &adm2.welcome).unwrap();
    let got = two.receive(&msg).unwrap().unwrap();
    assert_eq!(got.1, b"after admission");
    let _ = owner.receive(&msg).unwrap();
}

#[test]
fn removed_member_cannot_read_new_epoch() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();

    let p = ChannelMember::prepare("sacrificial").unwrap();
    let inv = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&p).unwrap(),
        "sacrificial",
        Caps::member(),
        3600,
    );
    let adm = owner
        .admit(
            &inv,
            &gcoms_mls::ChannelMember::key_package_bytes(&p).unwrap(),
        )
        .unwrap();
    let mut member = ChannelMember::join(p, &adm.welcome).unwrap();
    let member_id = member.own_pseudonym();

    let epoch_before = member.epoch();

    let removal_commit = owner.remove(member_id).unwrap();
    assert!(owner.epoch() > epoch_before);
    assert_eq!(owner.roster().len(), 1);

    let result = member.receive(&removal_commit);
    assert!(matches!(result, Err(MlsError::Removed)));

    let post_removal = owner.send(b"new epoch secret").unwrap();
    assert!(member.receive(&post_removal).is_err());
}

#[test]
fn removal_selects_exact_signature_key() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let first = ChannelMember::prepare("shared").unwrap();
    let first_package = ChannelMember::key_package_bytes(&first).unwrap();
    let first_id = gcoms_mls::pseudonym_of_key_package(&first_package).unwrap();
    let first_invite =
        owner.sign_invite_key_package(&first_package, "shared", Caps::member(), 3600);
    owner.admit(&first_invite, &first_package).unwrap();

    let second = ChannelMember::prepare("other").unwrap();
    let second_package = ChannelMember::key_package_bytes(&second).unwrap();
    let second_id = gcoms_mls::pseudonym_of_key_package(&second_package).unwrap();
    let second_invite =
        owner.sign_invite_key_package(&second_package, "other", Caps::member(), 3600);
    owner.admit(&second_invite, &second_package).unwrap();

    owner.remove(second_id).unwrap();
    let roster = owner.roster_members();
    assert!(roster.iter().any(|member| member.pseudonym == first_id));
    assert!(!roster.iter().any(|member| member.pseudonym == second_id));
}

#[test]
fn names_are_channel_local_pseudonyms() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let prepared = ChannelMember::prepare("zephyr-42").unwrap();
    let invite = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        "zephyr-42",
        Caps::member(),
        3600,
    );
    let admission = owner
        .admit(
            &invite,
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        )
        .unwrap();
    let member = ChannelMember::join(prepared, &admission.welcome).unwrap();

    let names: Vec<String> = owner.roster().into_iter().map(|(_, n)| n).collect();
    assert!(names.contains(&"founder".to_string()));
    assert!(names.contains(&"zephyr-42".to_string()));
    assert_eq!(member.roster(), owner.roster());
}

#[test]
fn invite_gates_enforced() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let other_channel_owner =
        OwnerSession::create(IdentityKeypair::from_seed([0x99; 32]), "other", 64).unwrap();

    let prepared = ChannelMember::prepare("ghost").unwrap();
    let invite = other_channel_owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        "ghost",
        Caps::member(),
        3600,
    );
    assert!(matches!(
        owner.admit(
            &invite,
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap()
        ),
        Err(MlsError::WrongChannel)
    ));

    let invite2 = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        "ghost",
        Caps::member(),
        3600,
    );
    let forged_leaf_invite = gcoms_mls::Invite {
        leaf: [1u8; 32],
        ..invite2.clone()
    };
    assert!(matches!(
        owner.admit(
            &forged_leaf_invite,
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap()
        ),
        Err(MlsError::BadInvite)
    ));

    let mut expired = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        "ghost",
        Caps::member(),
        3600,
    );
    expired.expiry = gcoms_mls::now_unix() - 1;
    assert!(matches!(
        owner.admit(
            &expired,
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap()
        ),
        Err(MlsError::BadInvite)
    ));

    let good = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
        "ghost",
        Caps::member(),
        3600,
    );
    assert!(owner
        .admit(
            &good,
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap()
        )
        .is_ok());
}

#[test]
fn membership_change_is_staged_and_name_bound_before_merge() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let prepared = ChannelMember::prepare("alice").unwrap();
    let key_package = ChannelMember::key_package_bytes(&prepared).unwrap();
    let wrong_name = owner.sign_invite_key_package(&key_package, "bob", Caps::member(), 3600);
    assert!(matches!(
        owner.stage_admit(&wrong_name, &key_package),
        Err(MlsError::BadInvite)
    ));

    let invite = owner.sign_invite_key_package(&key_package, "alice", Caps::member(), 3600);
    let old_epoch = owner.epoch();
    let staged = owner.stage_admit(&invite, &key_package).unwrap();
    assert_eq!(owner.epoch(), old_epoch);
    assert!(!staged.commit.is_empty());
    assert!(!staged.welcome.is_empty());
    owner.merge_pending().unwrap();
    assert_eq!(owner.epoch(), old_epoch + 1);
    assert!(owner.roster().iter().any(|(_, name)| name == "alice"));
}

#[test]
fn capacity_enforced() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 2).unwrap();
    let p1 = ChannelMember::prepare("one").unwrap();
    let inv1 = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&p1).unwrap(),
        "one",
        Caps::member(),
        3600,
    );
    assert!(owner
        .admit(
            &inv1,
            &gcoms_mls::ChannelMember::key_package_bytes(&p1).unwrap()
        )
        .is_ok());

    let p2 = ChannelMember::prepare("two").unwrap();
    let inv2 = owner.sign_invite_key_package(
        &gcoms_mls::ChannelMember::key_package_bytes(&p2).unwrap(),
        "two",
        Caps::member(),
        3600,
    );
    assert!(matches!(
        owner.admit(
            &inv2,
            &gcoms_mls::ChannelMember::key_package_bytes(&p2).unwrap()
        ),
        Err(MlsError::GroupFull)
    ));
}

#[test]
#[ignore = "slow PQ-hybrid capacity stress; run explicitly with --release --ignored"]
fn sixty_four_member_channel() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let mut members: Vec<ChannelMember> = Vec::new();
    let mut maximum_commit = 0;
    let mut maximum_welcome = 0;
    for i in 1..64 {
        let name = format!("m{i}");
        let prepared = ChannelMember::prepare(&name).unwrap();
        let invite = owner.sign_invite_key_package(
            &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
            &name,
            Caps::member(),
            3600,
        );
        let adm = owner
            .admit(
                &invite,
                &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap(),
            )
            .unwrap();
        maximum_commit = maximum_commit.max(adm.commit.len());
        maximum_welcome = maximum_welcome.max(adm.welcome.len());
        let m = ChannelMember::join(prepared, &adm.welcome).unwrap();
        for earlier in members.iter_mut() {
            earlier.receive(&adm.commit).unwrap();
        }
        members.push(m);
    }
    assert_eq!(owner.roster().len(), 64);
    assert!(members.iter().all(|member| member.roster().len() == 64));
    let msg = owner.send(b"all hands").unwrap();
    for m in members.iter_mut() {
        assert_eq!(m.receive(&msg).unwrap().unwrap().1, b"all hands");
    }
    let last = members.last_mut().unwrap();
    let reply = last.send(b"roger").unwrap();
    assert_eq!(owner.receive(&reply).unwrap().unwrap().1, b"roger");
    assert!(maximum_commit <= 16 * 1024 * 1024);
    assert!(maximum_welcome <= 16 * 1024 * 1024);
    eprintln!(
        "64-member PQ MLS maxima: commit={maximum_commit}, welcome={maximum_welcome}, commit_fragments={}",
        maximum_commit.div_ceil(gcoms_core::MAX_MESSAGE)
    );
}

#[test]
fn non_owner_removal_commit_is_rejected_by_other_members() {
    let mut owner = OwnerSession::create(owner_identity(), "founder", 64).unwrap();
    let mut members = Vec::new();
    for name in ["alice", "mallory", "carol"] {
        let prepared = ChannelMember::prepare(name).unwrap();
        let key_package = ChannelMember::key_package_bytes(&prepared).unwrap();
        let invite = owner.sign_invite_key_package(&key_package, name, Caps::member(), 3600);
        let admission = owner.admit(&invite, &key_package).unwrap();
        for existing in members.iter_mut() {
            let _: &mut ChannelMember = existing;
            existing.receive(&admission.commit).unwrap();
        }
        members.push(ChannelMember::join(prepared, &admission.welcome).unwrap());
    }
    let carol_id = members[2].own_pseudonym();
    // Mallory (a plain member) forges a removal of Carol with her own leaf.
    // Every honest party, including the owner, must refuse to merge it.
    let forged = {
        // A member has no `remove` API by design; drive openmls directly
        // through an update-style self-removal is impossible, so emulate the
        // attack by letting Mallory produce a commit through a second owner
        // session bound to the same group is also impossible. The practical
        // attack surface is a member who patched their client: reproduce it
        // with the crate-internal test hook.
        gcoms_mls::session::test_hooks::member_remove_commit(&mut members[1], carol_id)
    };
    assert!(matches!(
        members[0].receive(&forged),
        Err(MlsError::Unauthorized)
    ));
    assert!(matches!(
        owner.receive(&forged),
        Err(MlsError::Unauthorized)
    ));
    assert_eq!(owner.roster().len(), 4);
    // The owner's own removal still merges everywhere.
    let real = owner.remove(carol_id).unwrap();
    assert!(members[0].receive(&real).is_ok());
    assert_eq!(members[0].roster().len(), 3);
}

#[test]
fn group_id_is_the_owner_fingerprint_not_the_key() {
    let identity = owner_identity();
    let owner_pk = identity.public_bytes();
    let owner = OwnerSession::create(identity, "founder", 8).unwrap();
    let prepared = ChannelMember::prepare("m").unwrap();
    let kp = ChannelMember::key_package_bytes(&prepared).unwrap();
    let invite = owner.sign_invite_key_package(&kp, "m", Caps::member(), 3600);
    let mut owner = owner;
    let admission = owner.admit(&invite, &kp).unwrap();
    // The Welcome travels on the wire; the owner's verifying key must not.
    assert!(!admission.welcome.windows(64).any(|w| w == &owner_pk[..64]));
    let member = ChannelMember::join(prepared, &admission.welcome).unwrap();
    assert_eq!(member.stable_channel_id(), owner.stable_channel_id());
    assert_eq!(member.owner_pseudonym(), Some(owner.own_pseudonym()));
}
