//! GC/2 scheduler encoding. Authorization is prepared only after admission to a
//! class-bound terminal connection; retries retain those exact bytes.
use super::*;
use gcoms_core::gc2::NaturalCell;
use gcoms_protocol::relay::gc2::{Forward, Push, Subscription, UnverifiedPush};
use gcoms_transport::gc2::{NaturalOutcome, NaturalRoute};

impl PendingRequest {
    pub(super) fn natural(
        semantic: SemanticJob,
        traffic: TrafficClass,
        seed: [u8; 32],
    ) -> Result<Self, String> {
        let (target, token, excluded, subscription) = match &semantic {
            SemanticJob::Push { contact, .. } => (
                contact.target.clone(),
                crate::gc2::queue_token(&contact.queue_id),
                Vec::new(),
                false,
            ),
            SemanticJob::Subscribe(alias) => (
                alias.contact.target.clone(),
                crate::gc2::queue_token(&alias.contact.queue_id),
                Vec::new(),
                true,
            ),
            SemanticJob::Frwd {
                relay, destination, ..
            } => (
                relay
                    .aliases
                    .first()
                    .ok_or("client relay provision has no target")?
                    .contact
                    .target
                    .clone(),
                format!("gc2/{}", relay.frwd_path),
                vec![(
                    destination.target.address,
                    destination.target.relay_service_id,
                )],
                false,
            ),
            // Management has an explicit legacy envelope over the protected
            // connector. Data must never take this path as a fallback.
            SemanticJob::AdminPost { ref cell, .. } => {
                if !matches!(cell.cell_type(), Some(gcoms_core::CellType::RelaySub)) {
                    return Err("GC/2 legacy management only permits lease operations".into());
                }
                return Self::semantic(semantic, 0, seed);
            }
            SemanticJob::Forward { .. } => {
                return Err("GC/1 forwarded data cannot enter GC/2".into())
            }
            SemanticJob::ForwardNatural { target, push } => (
                target.clone(),
                crate::gc2::queue_token(&push.queue_id()),
                Vec::new(),
                false,
            ),
        };
        Ok(Self {
            target,
            token,
            excluded,
            subscription,
            natural: true,
            make: Box::new(move || {
                encode(semantic, traffic, &mut StdRng::from_seed(seed))
                    .map(|cell| bytes::Bytes::from(cell.encode()))
            }),
        })
    }
}

fn message(cell: Cell) -> Result<NaturalCell, String> {
    // Cell is the application's pre-transport representation. This is not a
    // wire decoder and never accepts GC/1 bytes from the network.
    if cell.cell_type() != Some(gcoms_core::CellType::Msg) || cell.round_ctr != 0 {
        return Err("GC/2 requires an unscheduled application MSG".into());
    }
    NaturalCell::new(gcoms_core::CellType::Msg, cell.flags, cell.payload)
        .map_err(|error| error.to_string())
}

fn push(
    contact: &AliasContact,
    inner: Cell,
    traffic: TrafficClass,
    rng: &mut StdRng,
) -> Result<NaturalCell, String> {
    ensure_live_authority(contact.expiry)?;
    Push {
        class: traffic,
        queue_id: contact.queue_id,
        epoch: contact.epoch,
        nonce: random_nonzero_with(rng),
        expiry: now_unix().saturating_add(60).min(contact.expiry),
        msg: Some(message(inner)?),
    }
    .encode(&contact.push_cap, &contact.target.relay_service_id)
    .map_err(|error| error.to_string())
}

fn encode(
    semantic: SemanticJob,
    traffic: TrafficClass,
    rng: &mut StdRng,
) -> Result<NaturalCell, String> {
    match semantic {
        SemanticJob::Push { contact, inner } => push(&contact, inner, traffic, rng),
        SemanticJob::Subscribe(alias) => {
            ensure_live_authority(alias.contact.expiry)?;
            Subscription {
                class: traffic,
                queue_id: alias.contact.queue_id,
                epoch: alias.contact.epoch,
                expiry: now_unix().saturating_add(60).min(alias.contact.expiry),
                nonce: random_nonzero_with(rng),
            }
            .encode(
                &alias.capabilities.sub,
                &alias.contact.target.relay_service_id,
            )
            .map_err(|error| error.to_string())
        }
        SemanticJob::Frwd {
            relay,
            destination,
            inner,
            policy,
        } => {
            let intermediary = &relay
                .aliases
                .first()
                .ok_or("client relay provision has no target")?
                .contact
                .target;
            let push = UnverifiedPush::parse(push(&destination, inner, traffic, rng)?)
                .map_err(|error| error.to_string())?;
            Forward {
                class: traffic,
                target: destination.target,
                expiry: now_unix().saturating_add(30),
                nonce: random_nonzero_with(rng),
                push: Some(push),
            }
            .encode(&relay.hop_key, &intermediary.relay_service_id, &policy)
            .map_err(|error| error.to_string())
        }
        SemanticJob::ForwardNatural { push, .. } => {
            ensure_live_authority(push.expiry())?;
            if push.class() != traffic {
                return Err("GC/2 forwarding changed class".into());
            }
            Ok(push.into_cell())
        }
        _ => Err("unsupported GC/2 job".into()),
    }
}

pub(super) async fn send(
    client: &Tp1Client,
    request: PendingRequest,
    retry_base: Duration,
    traffic: TrafficClass,
) -> JobResult {
    let PendingRequest {
        target,
        token,
        excluded,
        subscription,
        make,
        ..
    } = request;
    let route = NaturalRoute {
        addr: target.address,
        service_id: target.relay_service_id,
        token: &token,
        excluded: &excluded,
        class: traffic,
    };
    let mut make = Some(make);
    let mut wire: Option<bytes::Bytes> = None;
    let mut attempt = 0;
    // This absolute bound also covers a server that accepts but never emits a
    // message. It does not manufacture periodic inner cover while idle.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let prepare = || -> gcoms_transport::client::Result<NaturalCell> {
            if wire.is_none() {
                wire = Some(make
                    .take()
                    .ok_or("request preparation already consumed")?(
                )?);
            }
            Ok(NaturalCell::decode(wire.as_ref().expect("prepared"))?)
        };
        let result = if subscription {
            client
                .open_natural_prepared(route, deadline, prepare)
                .await
                .map(JobResult::NaturalStream)
        } else {
            client
                .post_natural_prepared(route, prepare)
                .await
                .map(|result| match result {
                    NaturalOutcome::Accepted(None) => JobResult::HopAccepted(bytes::Bytes::new()),
                    NaturalOutcome::Accepted(Some(_)) => {
                        JobResult::Failed("unexpected GC/2 relay response".into())
                    }
                    NaturalOutcome::Conflict => JobResult::Failed("GC/2 relay conflict".into()),
                    NaturalOutcome::Overloaded => JobResult::Failed("GC/2 relay overloaded".into()),
                    NaturalOutcome::Internal => {
                        JobResult::Failed("GC/2 relay internal failure".into())
                    }
                    NaturalOutcome::Decoy(status) => {
                        JobResult::Failed(format!("GC/2 relay refused: {status}"))
                    }
                })
        };
        match result {
            Ok(result) => return result,
            Err(error) => {
                let text = error.to_string();
                if attempt < CONNECT_RETRY_ATTEMPTS && is_unsent_connect_error(&text) {
                    attempt += 1;
                    tokio::time::sleep(retry_base * attempt).await;
                } else {
                    return JobResult::Failed(text);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_core::CellType;
    use gcoms_transport::{server::Tp1Server, tls::TlsIdentity, TokenRegistry};

    #[test]
    fn natural_authorization_waits_for_admission_and_legacy_data_has_no_fallback() {
        let contact = AliasContact {
            target: RelayTarget {
                address: "127.0.0.1:443".parse().unwrap(),
                relay_service_id: [2; 32],
            },
            queue_id: [3; 32],
            epoch: 4,
            push_cap: [5; 32],
            expiry: now_unix() - 1,
        };
        let pending = PendingRequest::natural(
            SemanticJob::Push {
                contact: contact.clone(),
                inner: Cell::new(CellType::Msg, 0, 0, vec![9]),
            },
            TrafficClass::Bulk,
            [6; 32],
        )
        .unwrap();
        assert!(pending.natural);
        assert_eq!(pending.token, crate::gc2::queue_token(&contact.queue_id));
        assert!((pending.make)()
            .unwrap_err()
            .contains("expired before transport admission"));
        assert!(PendingRequest::natural(
            SemanticJob::AdminPost {
                target: contact.target,
                token: "unprotected-data".into(),
                cell: Cell::new(CellType::Msg, 0, 0, vec![9]),
            },
            TrafficClass::Interactive,
            [6; 32]
        )
        .is_err());
        let legacy = super::super::tests::forwarded(7);
        assert!(PendingRequest::natural(
            SemanticJob::Forward {
                target: legacy.target,
                push: legacy.relay_push.unwrap(),
            },
            TrafficClass::Interactive,
            [6; 32]
        )
        .is_err());
    }

    #[tokio::test]
    async fn forwarded_buffer_spare_capacity_counts_against_the_node_budget() {
        use gcoms_routing::gc2::{directory::Directory, owner::EntryOwner, CandidateProfile};
        let (_, ready) = EntryOwner::new(
            Arc::new(Directory::for_loopback_fixture()),
            CandidateProfile::new(4096, 250).unwrap(),
            1,
        )
        .unwrap();
        let scheduler = RelayScheduler::gc2(ready).unwrap();
        let target = RelayTarget {
            address: "127.0.0.1:443".parse().unwrap(),
            relay_service_id: [2; 32],
        };
        let push = Push {
            class: TrafficClass::Bulk,
            queue_id: [3; 32],
            epoch: 4,
            nonce: [5; 16],
            expiry: now_unix() + 60,
            msg: Some(NaturalCell::new(CellType::Msg, 0, vec![7]).unwrap()),
        }
        .encode(&[8; 32], &target.relay_service_id)
        .unwrap();
        let mut allocated = Vec::with_capacity(MAX_QUEUED_BYTES);
        allocated.extend_from_slice(push.payload());
        let push =
            UnverifiedPush::parse(NaturalCell::new(CellType::RelayPush, 0, allocated).unwrap())
                .unwrap();
        let result = scheduler.forward_gc2(Forward {
            class: TrafficClass::Bulk,
            target,
            expiry: now_unix() + 30,
            nonce: [9; 16],
            push: Some(push),
        });
        assert!(matches!(result, Err(EnqueueError::Full)));
        assert_eq!(scheduler.resource_snapshot().bytes, 0);
        scheduler.shutdown();
    }

    #[tokio::test]
    async fn unexpected_natural_response_is_not_hop_acceptance() {
        use gcoms_transport::server::AcceptedDuplex;
        let identity = TlsIdentity::generate().unwrap();
        let handler = Arc::new(|_: &str| {
            let accepted: AcceptedDuplex = Box::new(|mut request, mut respond| {
                Box::pin(async move {
                    gcoms_transport::server::read_body(&mut request, 16384)
                        .await
                        .unwrap();
                    let mut response = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    response
                        .send_data(
                            bytes::Bytes::from(
                                NaturalCell::new(CellType::Msg, 0, vec![9])
                                    .unwrap()
                                    .encode(),
                            ),
                            true,
                        )
                        .unwrap();
                })
            });
            Some(accepted)
        });
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            TokenRegistry::new(),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap()
        .with_duplex(handler);
        let address = server.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(server.run_until(async {
            let _ = stopped.await;
        }));
        let request = PendingRequest::natural(
            SemanticJob::Push {
                contact: AliasContact {
                    target: RelayTarget {
                        address,
                        relay_service_id: identity.service_id(),
                    },
                    queue_id: [3; 32],
                    epoch: 4,
                    push_cap: [5; 32],
                    expiry: now_unix() + 60,
                },
                inner: Cell::new(CellType::Msg, 0, 0, vec![7]),
            },
            TrafficClass::Bulk,
            [6; 32],
        )
        .unwrap();
        let result = send(
            &Tp1Client::new().unwrap(),
            request,
            Duration::from_millis(1),
            TrafficClass::Bulk,
        )
        .await;
        assert!(
            matches!(result,JobResult::Failed(ref error) if error == "unexpected GC/2 relay response")
        );
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
