#![cfg(feature = "http")]

use gcoms_channel_service::api::{decode, encode, Config, CreationPolicy, Service};
use gcoms_crypto::IdentityKeypair;
use gcoms_mls::hosted::*;
use gcoms_sdk::hosted::*;
use sha2::{Digest, Sha256};

const NOW: u64 = 100;
fn config(path: &std::path::Path) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        directory: path.to_owned(),
        tls_terminated_upstream: false,
        creation: CreationPolicy::Public,
        max_channels: 5,
        max_total_bytes: 128 * 1024 * 1024,
        channel_bytes: 64 * 1024 * 1024,
        channel_records: 1000,
        requests_per_second: 100,
        source_requests_per_second: 10,
        blocked_channels: Vec::new(),
        blocked_sources: Vec::new(),
        motd: "Welcome".into(),
        rules: "Respect members".into(),
        operator_contact: "operator@example.invalid".into(),
    }
}
fn request(service: &Service, channel: [u8; 32], operation: Operation) -> Reply {
    service.request(
        Request {
            version: VERSION,
            channel,
            operation,
        },
        NOW,
    )
}
fn create(service: &Service, owner: &HostedSession) {
    let operation = Operation::Create {
        policy: encode(&owner.policy().encode().unwrap()),
        genesis: encode(&owner.export_group_info().unwrap()),
    };
    assert!(matches!(
        request(service, owner.policy().channel_id(), operation),
        Reply::Created { .. }
    ));
}
fn append(service: &Service, channel: [u8; 32], operation: Append) -> Acceptance {
    match request(service, channel, Operation::Append(operation)) {
        Reply::Accepted(receipt) => receipt,
        other => panic!("append failed: {other:?}"),
    }
}
fn query(after: u64, through: Option<u64>) -> ReadQuery {
    ReadQuery {
        after,
        through,
        limit: 2,
    }
}
fn hash(query: ReadQuery) -> [u8; 32] {
    Sha256::digest(query.authentication_bytes()).into()
}

#[test]
fn private_snapshot_replay_is_scoped_and_code_is_not_message_read_authority() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let service = Service::open(config(dir.path())).unwrap();
    let code = HostedAccessCode::generate().unwrap();
    let root = IdentityKeypair::from_seed([102; 32]);
    let mut owner = HostedSession::create_keyed(&root, "owner", 64, &code).unwrap();
    let channel = owner.policy().channel_id();
    create(&service, &owner);
    let message = owner.send_hosted(b"not visible before admission").unwrap();
    append(
        &service,
        channel,
        Append::Message(encode(&message.encode().unwrap())),
    );
    let control = owner
        .create_control(
            HostedPolicyChange::Mode(HostedMode::Moderated, 1),
            "private reason",
        )
        .unwrap();
    append(
        &service,
        channel,
        Append::Control(encode(&control.encode().unwrap())),
    );
    owner.apply_control(&control).unwrap();
    let control = owner
        .create_control(HostedPolicyChange::Capacity(5), "capacity")
        .unwrap();
    append(
        &service,
        channel,
        Append::Control(encode(&control.encode().unwrap())),
    );
    owner.apply_control(&control).unwrap();
    let prepared = PreparedHostedJoin::new("alice").unwrap();
    let q = query(0, None);
    let unauthorized = prepared.read_proof(channel, hash(q), NOW + 60).unwrap();
    assert!(matches!(
        request(
            &service,
            channel,
            Operation::Snapshot {
                query: q,
                proof: encode(&unauthorized.encode().unwrap())
            }
        ),
        Reply::Fault(Fault {
            code: FaultCode::Unauthorized,
            ..
        })
    ));
    let proof = code.read_proof(channel, hash(q), NOW + 60).unwrap();
    let proof = encode(&proof.encode().unwrap());
    assert!(matches!(
        request(
            &service,
            channel,
            Operation::Read {
                query: q,
                proof: proof.clone()
            }
        ),
        Reply::Fault(Fault {
            code: FaultCode::Unauthorized,
            ..
        })
    ));
    let Reply::Snapshot(page) = request(
        &service,
        channel,
        Operation::Snapshot {
            query: q,
            proof: proof.clone(),
        },
    ) else {
        panic!("snapshot");
    };
    assert_eq!(page.head.sequence, 3);
    assert_eq!(page.next, 2);
    assert_eq!(
        page.public_records.len(),
        1,
        "encrypted applications excluded"
    );
    let mut public = HostedObserver::new(
        HostedPolicy::decode(&decode(page.policy.as_ref().unwrap()).unwrap(), channel).unwrap(),
        channel,
        &decode(page.genesis.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    for record in page.public_records {
        match record.change {
            PublicChange::Control(wire) => public
                .replay_control(&HostedControl::decode(&decode(&wire).unwrap()).unwrap())
                .unwrap(),
            _ => panic!("control expected"),
        }
    }
    let q = query(page.next, Some(page.head.sequence));
    // A captured proof cannot be used for a changed query or scope.
    assert!(matches!(
        request(&service, channel, Operation::Snapshot { query: q, proof }),
        Reply::Fault(_)
    ));
    let proof = encode(
        &code
            .read_proof(channel, hash(q), NOW + 60)
            .unwrap()
            .encode()
            .unwrap(),
    );
    let Reply::Snapshot(page) = request(&service, channel, Operation::Snapshot { query: q, proof })
    else {
        panic!("snapshot continuation");
    };
    for record in page.public_records {
        match record.change {
            PublicChange::Control(wire) => public
                .replay_control(&HostedControl::decode(&decode(&wire).unwrap()).unwrap())
                .unwrap(),
            _ => panic!("control expected"),
        }
    }
    public
        .publish_group_info(&decode(page.group_info.as_ref().unwrap()).unwrap())
        .unwrap();
    assert_eq!(public.rules().revision(), 2);
    assert_eq!(public.rules().capacity(), 5);
    let permit = code
        .permit_for(&public, prepared.member_id(), "alice", NOW + 60)
        .unwrap();
    let (mut alice, commit) = prepared.join(&public, &permit, NOW).unwrap();
    append(
        &service,
        channel,
        Append::Membership {
            commit: encode(&commit),
            info: encode(alice.proposed_group_info().unwrap()),
        },
    );
    alice.accept_join(&commit).unwrap();
    owner.receive(&commit, NOW).unwrap();
    assert!(alice.send_hosted(b"unvoiced").is_err());
    let q = query(3, None);
    let proof = alice
        .read_proof(HostedReadScope::Records, hash(q), NOW + 60)
        .unwrap();
    let Reply::Records(page) = request(
        &service,
        channel,
        Operation::Read {
            query: q,
            proof: encode(&proof.encode().unwrap()),
        },
    ) else {
        panic!("member read");
    };
    assert_eq!(page.records.len(), 1);
    let RecordItem::Deferred {
        sequence,
        hash: expected_hash,
        ..
    } = &page.records[0]
    else {
        panic!("membership must be deferred from covered polling");
    };
    let q = ReadQuery {
        after: sequence - 1,
        through: Some(*sequence),
        limit: 1,
    };
    let proof = encode(
        &alice
            .read_proof(HostedReadScope::Records, hash(q), NOW + 60)
            .unwrap()
            .encode()
            .unwrap(),
    );
    let Reply::Records(full) = request(&service, channel, Operation::Fetch { query: q, proof })
    else {
        panic!("bulk record");
    };
    let RecordItem::Inline(wire) = &full.records[0] else {
        panic!("full record");
    };
    let record = gcoms_channel_service::Record::decode(&decode(wire).unwrap()).unwrap();
    assert_eq!(record.hash().unwrap(), *expected_hash);
    assert_eq!(record.sequence, 4);
    assert_eq!(record.hash().unwrap(), page.head.hash);
}

#[test]
fn departed_reader_recovers_only_through_removal_after_service_restart() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let cfg = config(dir.path());
    let service = Service::open(cfg.clone()).unwrap();
    let root = IdentityKeypair::from_seed([103; 32]);
    let mut owner = HostedSession::create(&root, "owner", 64, true).unwrap();
    let channel = owner.policy().channel_id();
    create(&service, &owner);
    let mut public = HostedObserver::new(
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
    )
    .unwrap();
    let (mut alice, commit) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(&public, &JoinPermit::public(), NOW)
        .unwrap();
    public = public
        .stage_join(&commit, alice.proposed_group_info().unwrap(), NOW)
        .unwrap();
    append(
        &service,
        channel,
        Append::Membership {
            commit: encode(&commit),
            info: encode(alice.proposed_group_info().unwrap()),
        },
    );
    alice.accept_join(&commit).unwrap();
    owner.receive(&commit, NOW).unwrap();
    let kick = owner
        .create_control(
            HostedPolicyChange::Kick(alice.member_id()),
            "departure reason",
        )
        .unwrap();
    append(
        &service,
        channel,
        Append::Control(encode(&kick.encode().unwrap())),
    );
    owner.apply_control(&kick).unwrap();
    let commit = owner.prepare_rekey().unwrap();
    let receipt = append(
        &service,
        channel,
        Append::Membership {
            commit: encode(&commit),
            info: encode(owner.proposed_group_info().unwrap()),
        },
    );
    owner.accept_rekey(&commit).unwrap();
    append(
        &service,
        channel,
        Append::Message(encode(
            &owner
                .send_hosted(b"after removal")
                .unwrap()
                .encode()
                .unwrap(),
        )),
    );
    drop(service);
    let service = Service::open(cfg).unwrap();
    let q = query(1, None);
    let proof = encode(
        &alice
            .read_proof(HostedReadScope::Records, hash(q), NOW + 60)
            .unwrap()
            .encode()
            .unwrap(),
    );
    let Reply::Records(page) = request(&service, channel, Operation::Read { query: q, proof })
    else {
        panic!("retained read");
    };
    assert_eq!(page.head.sequence, receipt.sequence);
    assert_eq!(page.records.len(), 2);
    alice.apply_control(&kick).unwrap();
    assert!(matches!(
        alice.receive(&commit, NOW),
        Err(gcoms_mls::MlsError::Removed)
    ));
    let q = query(1, Some(receipt.sequence + 1));
    let proof = encode(
        &alice
            .read_proof(HostedReadScope::Records, hash(q), NOW + 60)
            .unwrap()
            .encode()
            .unwrap(),
    );
    assert!(matches!(
        request(&service, channel, Operation::Read { query: q, proof }),
        Reply::Fault(_)
    ));
    // Unknown profile never silently selects legacy behavior.
    assert!(matches!(
        service.request(
            Request {
                version: VERSION + 1,
                channel,
                operation: Operation::Info
            },
            NOW
        ),
        Reply::Fault(Fault {
            code: FaultCode::Unsupported,
            ..
        })
    ));
    assert_eq!(public.member_count(), 2);
}

#[tokio::test]
async fn actual_http_contract_is_bounded_versioned_and_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let mut cfg = config(dir.path());
    cfg.source_requests_per_second = 2;
    let service = Service::open(cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(
        axum::serve(
            listener,
            service
                .router()
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .into_future(),
    );
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/hosted");
    let response = client
        .post(&url)
        .json(&Request {
            version: VERSION,
            channel: [0; 32],
            operation: Operation::Info,
        })
        .send()
        .await
        .unwrap();
    let Reply::Info(info) = response.json::<Reply>().await.unwrap() else {
        panic!("info");
    };
    assert_eq!(info.profiles, vec![PROFILE]);
    assert_eq!(info.max_members, 64);
    assert_eq!(info.operator_contact, "operator@example.invalid");
    let oversized = client
        .post(&url)
        .body(vec![b'x'; MAX_HTTP_BYTES + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    assert_eq!(
        client
            .post(&url)
            .body("invalid json")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let mut limited = false;
    for _ in 0..5 {
        if client
            .post(&url)
            .body("invalid json")
            .send()
            .await
            .unwrap()
            .status()
            == 429
        {
            limited = true;
            break;
        }
    }
    assert!(limited);
    task.abort();
    let _ = task.await;
}
use std::future::IntoFuture;

#[test]
fn ciphertext_pieces_bind_writer_body_scope_and_current_membership_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let cfg = config(dir.path());
    let service = Service::open(cfg.clone()).unwrap();
    let root = IdentityKeypair::from_seed([118; 32]);
    let mut owner = HostedSession::create(&root, "owner", 64, true).unwrap();
    let channel = owner.policy().channel_id();
    create(&service, &owner);
    let public = HostedObserver::new(
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
    )
    .unwrap();
    let (mut alice, commit) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(&public, &JoinPermit::public(), NOW)
        .unwrap();
    append(
        &service,
        channel,
        Append::Membership {
            commit: encode(&commit),
            info: encode(alice.proposed_group_info().unwrap()),
        },
    );
    alice.accept_join(&commit).unwrap();
    owner.receive(&commit, NOW).unwrap();
    let reference = BlobRef {
        owner: owner.member_id(),
        file: [7; 16],
        piece: 0,
    };
    let bytes = vec![19; 128 * 1024];
    let proof = |member: &HostedSession, reference: BlobRef, body: Option<&[u8]>| {
        encode(
            &member
                .read_proof(
                    if body.is_some() {
                        HostedReadScope::BlobWrite
                    } else {
                        HostedReadScope::BlobRead
                    },
                    Sha256::digest(
                        reference.authentication_bytes(body.map(|b| Sha256::digest(b).into())),
                    )
                    .into(),
                    NOW + 60,
                )
                .unwrap()
                .encode()
                .unwrap(),
        )
    };
    let upload = Operation::PutBlob {
        reference,
        body: encode(&bytes),
        proof: proof(&owner, reference, Some(&bytes)),
    };
    assert!(upload.requires_bulk());
    assert!(matches!(
        request(&service, channel, upload.clone()),
        Reply::BlobStored
    ));
    assert!(matches!(
        request(&service, channel, upload),
        Reply::BlobStored
    ));
    let attack = Operation::PutBlob {
        reference,
        body: encode(&bytes),
        proof: proof(&alice, reference, Some(&bytes)),
    };
    assert!(matches!(
        request(&service, channel, attack),
        Reply::Fault(Fault {
            code: FaultCode::Unauthorized,
            ..
        })
    ));
    let attack = Operation::PutBlob {
        reference,
        body: encode(b"changed"),
        proof: proof(&owner, reference, Some(&bytes)),
    };
    assert!(matches!(
        request(&service, channel, attack),
        Reply::Fault(Fault {
            code: FaultCode::Unauthorized,
            ..
        })
    ));
    let attack = Operation::PutBlob {
        reference,
        body: encode(b"changed"),
        proof: proof(&owner, reference, Some(b"changed")),
    };
    assert!(matches!(
        request(&service, channel, attack),
        Reply::Fault(Fault {
            code: FaultCode::Invalid,
            ..
        })
    ));
    let get = Operation::GetBlob {
        reference,
        proof: proof(&alice, reference, None),
    };
    assert!(get.requires_bulk());
    let Reply::Blob { body } = request(&service, channel, get.clone()) else {
        panic!("member read");
    };
    assert_eq!(decode(&body).unwrap(), bytes);
    let mode = owner
        .create_control(
            HostedPolicyChange::Mode(HostedMode::Moderated, 1),
            "moderation",
        )
        .unwrap();
    append(
        &service,
        channel,
        Append::Control(encode(&mode.encode().unwrap())),
    );
    owner.apply_control(&mode).unwrap();
    let alice_ref = BlobRef {
        owner: alice.member_id(),
        ..reference
    };
    assert!(matches!(
        request(
            &service,
            channel,
            Operation::PutBlob {
                reference: alice_ref,
                body: encode(&bytes),
                proof: proof(&alice, alice_ref, Some(&bytes))
            }
        ),
        Reply::Fault(Fault {
            code: FaultCode::Unauthorized,
            ..
        })
    ));
    let kick = owner
        .create_control(HostedPolicyChange::Kick(alice.member_id()), "removed")
        .unwrap();
    append(
        &service,
        channel,
        Append::Control(encode(&kick.encode().unwrap())),
    );
    assert!(
        matches!(
            request(&service, channel, get),
            Reply::Fault(Fault {
                code: FaultCode::Unauthorized,
                ..
            })
        ),
        "pending removals revoke blob reads before rekey"
    );
    drop(service);
    let service = Service::open(cfg).unwrap();
    let Reply::Blob { body } = request(
        &service,
        channel,
        Operation::GetBlob {
            reference,
            proof: proof(&owner, reference, None),
        },
    ) else {
        panic!("retained piece");
    };
    assert_eq!(decode(&body).unwrap(), bytes);
    assert_eq!(service.info().requests_per_second, Some(100));
}

#[test]
fn hosted_directory_requires_explicit_publication_and_tracks_privacy_after_restart() {
    fn publish(service: &Service, owner: &mut HostedSession, change: HostedPolicyChange) {
        let control = owner
            .create_control(change, "encrypted operator reason")
            .unwrap();
        append(
            service,
            owner.policy().channel_id(),
            Append::Control(encode(&control.encode().unwrap())),
        );
        owner.apply_control(&control).unwrap();
    }
    fn page(
        service: &Service,
        after: Option<[u8; 32]>,
        limit: u16,
    ) -> (Vec<DirectoryEntry>, Option<[u8; 32]>) {
        let Reply::Directory { entries, next } =
            request(service, [0; 32], Operation::Directory { after, limit })
        else {
            panic!("directory")
        };
        (entries, next)
    }
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let service = Service::open(config(dir.path())).unwrap();
    let mut owners: Vec<_> = (0..3)
        .map(|_| HostedSession::create(&IdentityKeypair::generate(), "owner", 64, true).unwrap())
        .collect();
    for owner in &owners {
        create(&service, owner);
    }
    assert!(page(&service, None, 16).0.is_empty());
    // A discovery flag alone does not publish a local alias or encrypted topic.
    publish(
        &service,
        &mut owners[0],
        HostedPolicyChange::Discovery(HostedDiscovery::Public),
    );
    assert!(page(&service, None, 16).0.is_empty());
    for (n, owner) in owners.iter_mut().enumerate() {
        publish(
            &service,
            owner,
            HostedPolicyChange::Listing(format!("#public-{n}").into_bytes().into()),
        );
    }
    let (first, next) = page(&service, None, 2);
    assert_eq!(first.len(), 2);
    assert_eq!(next, first.last().map(|e| e.channel));
    assert!(first.iter().all(|e| e.public_join && e.members == 1));
    let (last, next) = page(&service, next, 2);
    assert_eq!(last.len(), 1);
    assert!(next.is_none());
    assert!(first.iter().all(|e| e.channel < last[0].channel));
    publish(
        &service,
        &mut owners[0],
        HostedPolicyChange::Discovery(HostedDiscovery::Secret),
    );
    publish(
        &service,
        &mut owners[1],
        HostedPolicyChange::Mode(HostedMode::InviteOnly, 1),
    );
    let visible = page(&service, None, 16).0;
    assert_eq!(visible.len(), 2);
    assert!(
        !visible
            .iter()
            .find(|e| e.channel == owners[1].policy().channel_id())
            .unwrap()
            .public_join
    );
    drop(service);
    let service = Service::open(config(dir.path())).unwrap();
    assert_eq!(page(&service, None, 16).0, visible);
    publish(
        &service,
        &mut owners[1],
        HostedPolicyChange::Listing(Vec::new().into()),
    );
    publish(&service, &mut owners[2], HostedPolicyChange::Close);
    assert!(page(&service, None, 16).0.is_empty());
    assert!(matches!(
        request(
            &service,
            [0; 32],
            Operation::Directory {
                after: None,
                limit: 17
            }
        ),
        Reply::Fault(_)
    ));
    assert!(!Operation::Directory {
        after: None,
        limit: 16
    }
    .requires_bulk());
}
