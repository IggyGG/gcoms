//! Real persisted nodes with an in-memory encrypted descriptor provider. HTTPS
//! transport, certificate checks and provider failover have separate tests in
//! network-client; this fixture never changes production trust configuration.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_network::channel_invitation::{Descriptor, Reference, ResolvedInvitation};
use gcoms_network::{Founder, NetworkDefaults, NetworkIdentity, SignedNetworkDefaults};
use std::time::Duration;

async fn spawn(seed: u8, port: u16, initial: Option<&[u8]>) -> NodeHandle {
    start_persistent_restored(
        NodeConfig {
            seed: [seed; 32],
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        None,
        Arc::new(|_| Ok(())),
        initial,
    )
    .await
    .unwrap()
}
fn install_provider(node: &NodeHandle, published: Arc<Mutex<Descriptor>>) {
    node.state
        .upgrade()
        .unwrap()
        .lock()
        .unwrap()
        .invitation_resolver = Some(Arc::new(move |reference, floor, previous| {
        let descriptor = published.lock().unwrap().clone();
        let resolved = descriptor.open(reference, now_unix(), floor)?;
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&descriptor).unwrap()).into();
        if descriptor.body.sequence == floor && previous.is_some_and(|old| old != digest) {
            return Err("invitation descriptor equivocation".into());
        }
        Ok((resolved, descriptor))
    }));
}
async fn descriptor(
    owner: &NodeHandle,
    reference: &Reference,
    network: &NetworkIdentity,
    issued: &super::super::IssuedInvitation,
    sequence: u64,
) -> Descriptor {
    let invite = crate::channel_invite::ChannelInvite {
        owner: owner.current_info().await.unwrap(),
        channel: "devices".into(),
        id: issued.summary.id,
        secret: issued.secret,
        expiry: issued.summary.policy.expires_at.unwrap_or(u64::MAX),
    };
    let mut envelope =
        InviteEnvelope::from_link(&owner.channel_invite_link(&invite).unwrap()).unwrap();
    envelope.policy = Some(issued.summary.policy);
    let resolved = ResolvedInvitation {
        network: network.clone(),
        channel_id: reference.channel_id.clone(),
        channel_invitation: envelope.to_link().unwrap(),
    };
    let now = now_unix();
    Descriptor::seal(
        reference,
        &resolved,
        &IdentityKeypair::from_seed([91; 32]),
        sequence,
        now,
        now + 300,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compact_enrollment_reopens_with_the_same_id_and_a_fresh_owner_route() {
    let mut owner = spawn(91, 0, None).await;
    let owner_port = owner.info.aliases[0].target.address.port();
    owner
        .create_channel(
            "devices",
            "operator",
            8,
            crate::channel::ChannelVisibility::Private,
        )
        .await
        .unwrap();
    let issued = owner
        .create_reusable_invitation(
            "devices",
            gcoms_core::invitation::InvitationPreset::Devices
                .policy(now_unix())
                .unwrap(),
        )
        .await
        .unwrap();
    let now = now_unix();
    let root = IdentityKeypair::from_seed([93; 32]);
    let network = NetworkIdentity {
        trusted_key_b64: URL_SAFE_NO_PAD.encode(root.public_bytes()),
        signed_defaults: SignedNetworkDefaults::sign(
            NetworkDefaults {
                version: 1,
                network_id: "fixture.example".into(),
                sequence: 1,
                issued_at: now,
                expires_at: now + 3600,
                provider_urls: vec!["https://provider.fixture.example/".into()],
                founders: vec![Founder {
                    name: "r1.relays.fixture.example".into(),
                    service_id: [5; 32],
                    address_hints: vec!["127.0.0.1:443".parse().unwrap()],
                }],
                dns_domain: "fixture.example".into(),
            },
            &root,
            vec![],
        )
        .unwrap(),
    };
    let channel_id = owner.state.upgrade().unwrap().lock().unwrap().channels["devices"]
        .id
        .0;
    let reference = Reference::new(
        &network,
        &owner.info.identity_pk,
        channel_id,
        issued.summary.id,
        issued.secret,
    )
    .unwrap();
    let link = reference.encode().unwrap();
    let original = descriptor(&owner, &reference, &network, &issued, 1).await;
    let published = Arc::new(Mutex::new(original.clone()));
    let owner_state = owner.export_state().await.unwrap();
    owner.shutdown().await;

    let mut member = spawn(92, 0, None).await;
    let member_port = member.info.aliases[0].target.address.port();
    install_provider(&member, published.clone());
    let operation = member.start_enrollment(&link, "sensor").await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let saved_sequence =
            member.state.upgrade().unwrap().lock().unwrap().enrollments[0].descriptor_sequence;
        if saved_sequence == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "descriptor was not retained"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pending = member.export_state().await.unwrap();
    assert_ne!(
        member.enrollment_status(operation.id).await.unwrap().phase,
        EnrollmentPhase::Joined
    );
    member.shutdown().await;

    owner = spawn(91, owner_port, Some(&owner_state)).await;
    let refreshed = descriptor(&owner, &reference, &network, &issued, 2).await;
    assert_ne!(
        original
            .open(&reference, now_unix(), 0)
            .unwrap()
            .channel_invitation,
        refreshed
            .open(&reference, now_unix(), 0)
            .unwrap()
            .channel_invitation
    );
    *published.lock().unwrap() = refreshed;
    assert_eq!(
        reference.encode().unwrap(),
        link,
        "the distributed invitation must not change"
    );
    member = spawn(92, member_port, Some(&pending)).await;
    install_provider(&member, published);
    assert_eq!(
        member.start_enrollment(&link, "sensor").await.unwrap().id,
        operation.id
    );
    member.resume_enrollment(operation.id).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(75);
    loop {
        let status = member.enrollment_status(operation.id).await.unwrap();
        if status.phase == EnrollmentPhase::Joined {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{status:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        member.state.upgrade().unwrap().lock().unwrap().enrollments[0].descriptor_sequence,
        2
    );
    assert_eq!(
        owner.list_invitations("devices").await.unwrap()[0].admissions,
        1
    );
    assert_eq!(member.list_channels().await.unwrap().len(), 1);
    // A successful, still-current publication must not require another PUT on
    // every maintenance tick. This network client deliberately has no grant:
    // an unnecessary upload would fail instead of returning the existing link.
    let network_home = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(network_home.path(), true).unwrap();
    owner
        .configure_invitation_directory(
            gcoms_network_client::NetworkClient::open(
                &network_home.path().join("network"),
                gcoms_network_client::InstalledNetwork {
                    trusted_key_b64: network.trusted_key_b64.clone(),
                    signed_defaults: network.signed_defaults.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
    let current = descriptor(&owner, &reference, &network, &issued, 3).await;
    let resolved = current.open(&reference, now_unix(), 0).unwrap();
    let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&resolved).unwrap()).into();
    let publication = serde_json::from_value(serde_json::json!({
        "reference": reference, "descriptor": current, "route_digest": digest,
        "published_until": current.body.expires_at, "last_error": null,
    }))
    .unwrap();
    owner
        .state
        .upgrade()
        .unwrap()
        .lock()
        .unwrap()
        .channels
        .get_mut("devices")
        .unwrap()
        .invitations
        .records[0]
        .publication = Some(publication);
    assert_eq!(
        owner
            .share_reusable_invitation("devices", issued.summary.id)
            .await
            .unwrap(),
        link
    );
    owner
        .state
        .upgrade()
        .unwrap()
        .lock()
        .unwrap()
        .channels
        .get_mut("devices")
        .unwrap()
        .invitations
        .records[0]
        .publication
        .as_mut()
        .unwrap()
        .published_until = None;
    assert!(
        owner
            .share_reusable_invitation("devices", issued.summary.id)
            .await
            .is_err(),
        "an unconfirmed publication must still attempt its authenticated upload"
    );
    member.shutdown().await;
    owner.shutdown().await;
}
