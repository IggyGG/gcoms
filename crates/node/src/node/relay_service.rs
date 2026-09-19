// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

/// Idle lifetime of forwarding authority activated by a consumed provision or
/// refreshed by later administrative traffic on its create paths.
pub(crate) const PROVISION_FRWD_IDLE_SECS: u64 = 24 * 60 * 60;
/// Grace added to the admission-grant lifetime for never-consumed provisions.
pub(crate) const PROVISION_GRANT_MARGIN_SECS: u64 = 60;
/// Maximum simultaneous never-consumed public provisions.
pub(crate) const MAX_PENDING_PROVISIONS: usize = 256;

#[derive(Clone)]
pub(crate) struct FrwdAuthority {
    pub(crate) hop_key: [u8; 32],
    pub(crate) expires_at: Option<u64>,
    pub(crate) create_paths: Vec<String>,
    /// `Some` means a temporary, fixed-lifetime grant to exactly these queues.
    pub(crate) destinations: Option<Vec<AliasContact>>,
}

#[derive(Default)]
pub(crate) struct ProvisionAuthorities {
    /// Full automatic listeners require a current independent probe before
    /// accepting real relay work. Cover/authentication remain unchanged.
    pub(crate) transit_ready: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub(crate) frwd: HashMap<String, FrwdAuthority>,
    pub(crate) by_create_path: HashMap<String, String>,
    pub(crate) pending: std::collections::HashSet<String>,
    /// Real (non-cover) FRWD cells admitted; diagnostics only.
    pub(crate) admitted: Arc<std::sync::atomic::AtomicU64>,
}

impl ProvisionAuthorities {
    pub(crate) fn insert_permanent(&mut self, frwd_path: &str, hop_key: [u8; 32]) {
        self.frwd.insert(
            frwd_path.to_string(),
            FrwdAuthority {
                hop_key,
                expires_at: None,
                create_paths: Vec::new(),
                destinations: None,
            },
        );
    }

    pub(crate) fn ensure_capacity(&self) -> Result<(), String> {
        if self.pending.len() >= MAX_PENDING_PROVISIONS {
            return Err("relay provisioning capacity reached".into());
        }
        Ok(())
    }

    pub(crate) fn register_provision(
        &mut self,
        create_paths: Vec<String>,
        frwd_path: &str,
        hop_key: [u8; 32],
        expires_at: u64,
    ) {
        debug_assert!(!create_paths.is_empty());
        self.frwd.insert(
            frwd_path.to_string(),
            FrwdAuthority {
                hop_key,
                expires_at: Some(expires_at),
                create_paths: create_paths.clone(),
                destinations: None,
            },
        );
        for path in create_paths {
            self.by_create_path.insert(path, frwd_path.to_string());
        }
        self.pending.insert(frwd_path.to_string());
    }

    pub(crate) fn note_admin_use(&mut self, create_path: &str, now: u64) {
        let Some(frwd_path) = self.by_create_path.get(create_path).cloned() else {
            return;
        };
        if let Some(entry) = self.frwd.get_mut(&frwd_path) {
            if entry.destinations.is_some() {
                return;
            }
            if let Some(expires_at) = entry.expires_at.as_mut() {
                *expires_at = (*expires_at).max(now.saturating_add(PROVISION_FRWD_IDLE_SECS));
            }
        }
        self.pending.remove(&frwd_path);
    }

    // This lookup is reached before the cell MAC is checked and must not mutate
    // authority lifetime.
    pub(crate) fn lookup_frwd(&self, frwd_path: &str, now: u64) -> Option<[u8; 32]> {
        let entry = self.frwd.get(frwd_path)?;
        if entry.expires_at.is_some_and(|expires| expires <= now) {
            return None;
        }
        Some(entry.hop_key)
    }

    pub(crate) fn permits_frwd(
        &self,
        path: &str,
        hop_key: &[u8; 32],
        frwd: &crate::relay::Frwd,
        now: u64,
    ) -> bool {
        let Some(entry) = self.frwd.get(path) else {
            return false;
        };
        if &entry.hop_key != hop_key || entry.expires_at.is_some_and(|expiry| expiry <= now) {
            return false;
        }
        let Some(destinations) = entry.destinations.as_ref() else {
            return true;
        };
        let Some(push) = frwd.relay_push.as_ref() else {
            return true;
        };
        destinations.iter().any(|a| {
            a.expiry > now
                && a.target == frwd.target
                && a.queue_id == push.queue_id()
                && a.epoch == push.epoch()
        })
    }

    #[cfg(test)]
    pub(crate) fn register_temporary(
        &mut self,
        create_path: String,
        frwd_path: String,
        hop_key: [u8; 32],
        expires_at: u64,
        destinations: Vec<AliasContact>,
    ) {
        self.by_create_path
            .insert(create_path.clone(), frwd_path.clone());
        self.frwd.insert(
            frwd_path,
            FrwdAuthority {
                hop_key,
                expires_at: Some(expires_at),
                create_paths: vec![create_path],
                destinations: Some(destinations),
            },
        );
    }

    #[cfg(feature = "experimental-gc2")]
    pub(crate) fn permits_gc2_frwd(
        &self,
        path: &str,
        key: &[u8; 32],
        forward: &gcoms_protocol::relay::gc2::Forward,
        now: u64,
    ) -> bool {
        let Some(entry) = self.frwd.get(path) else {
            return false;
        };
        if &entry.hop_key != key || entry.expires_at.is_some_and(|expiry| expiry <= now) {
            return false;
        }
        let (Some(destinations), Some(push)) = (&entry.destinations, &forward.push) else {
            return true;
        };
        destinations.iter().any(|a| {
            a.expiry > now
                && a.target == forward.target
                && a.queue_id == push.queue_id()
                && a.epoch == push.epoch()
        })
    }

    // Extend lifetime only after the authenticated work has entered its
    // bounded scheduler lane. The expected key prevents a stale lookup from
    // touching a replacement entry at the same path.
    pub(crate) fn note_frwd_admitted(
        &mut self,
        frwd_path: &str,
        expected_hop_key: &[u8; 32],
        now: u64,
    ) -> bool {
        let Some(entry) = self.frwd.get_mut(frwd_path) else {
            return false;
        };
        if &entry.hop_key != expected_hop_key
            || entry.expires_at.is_some_and(|expires| expires <= now)
        {
            return false;
        }
        if entry.destinations.is_none() {
            if let Some(expires_at) = entry.expires_at.as_mut() {
                *expires_at = (*expires_at).max(now.saturating_add(PROVISION_FRWD_IDLE_SECS));
            }
        }
        true
    }

    pub(crate) fn sweep(&mut self, now: u64) -> Vec<String> {
        let expired = self
            .frwd
            .iter()
            .filter(|(_, entry)| entry.expires_at.is_some_and(|expires| expires <= now))
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>();
        let mut removed = Vec::new();
        for path in expired {
            if let Some(entry) = self.frwd.remove(&path) {
                removed.push(path.clone());
                removed.extend(entry.create_paths.iter().cloned());
            }
            self.pending.remove(&path);
        }
        self.by_create_path
            .retain(|_, frwd_path| self.frwd.contains_key(frwd_path));
        removed
    }
}

pub(crate) fn admit_frwd_cell(
    token: &str,
    cell: &Cell,
    authorities: &Arc<Mutex<ProvisionAuthorities>>,
    scheduler: &RelayScheduler,
    service_id: &[u8; 32],
    policy: &FrwdTargetPolicy,
) -> Result<Option<Cell>, QueueReject> {
    let now = now_unix();
    let (hop_key, transit_ready) = {
        let authorities = authorities.lock().unwrap_or_else(|p| p.into_inner());
        (
            authorities
                .lookup_frwd(token, now)
                .ok_or(QueueReject::Unauthorized)?,
            authorities.transit_ready.clone(),
        )
    };
    let frwd = decode_authorized_with_policy(cell, &hop_key, service_id, now, policy)
        .ok_or(QueueReject::Unauthorized)?;
    if !authorities
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .permits_frwd(token, &hop_key, &frwd, now)
    {
        return Err(QueueReject::Unauthorized);
    }
    if frwd.is_cover() {
        // Authenticated cover FRWD: same receipt and authority slide as a
        // real hop, but nothing is forwarded and no connection is opened.
        authorities
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .note_frwd_admitted(token, &hop_key, now);
        metrics::log_event("frwd_cover", &[]);
        return Ok(None);
    }
    if transit_ready
        .as_ref()
        .is_some_and(|ready| !ready.load(std::sync::atomic::Ordering::Acquire))
    {
        return Err(QueueReject::Overloaded);
    }
    metrics::log_event("frwd_hop", &[]);
    let forward_port = frwd.target.address.port();
    authorities
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .admitted
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let receipt = match scheduler.forward(frwd) {
        Ok(receipt) => receipt,
        Err(EnqueueError::InvalidCell) => return Err(QueueReject::Unauthorized),
        Err(EnqueueError::Full | EnqueueError::Pending | EnqueueError::Shutdown) => {
            metrics::log_event(
                "frwd_result",
                &[
                    ("ok", "false".to_string()),
                    ("tport", forward_port.to_string()),
                ],
            );
            return Err(QueueReject::Overloaded);
        }
    };
    authorities
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .note_frwd_admitted(token, &hop_key, now);
    tokio::spawn(async move {
        let result = receipt.completion().await;
        let ok = result.state() == crate::scheduler::CompletionState::HopAccepted;
        if ok {
            metrics::log_event("frwd_result", &[("ok", "true".to_string())]);
        } else {
            // Surface the refusal reason (redaction-safe: never contains the
            // forbidden identifiers, and Failed carries the transport error).
            let why = match &result {
                crate::scheduler::JobResult::Failed(error) => error.clone(),
                crate::scheduler::JobResult::Shutdown => "shutdown".to_string(),
                _ => "unexpected".to_string(),
            };
            metrics::log_event(
                "frwd_result",
                &[
                    ("ok", "false".to_string()),
                    ("tport", forward_port.to_string()),
                    ("why", why),
                ],
            );
        }
    });
    Ok(None)
}

pub(crate) fn provision_relay(
    store: &Arc<Mutex<LeaseStore>>,
    registry: &TokenRegistry,
    authorities: &Arc<Mutex<ProvisionAuthorities>>,
    target: &RelayTarget,
    relay_identity_pk: &[u8],
    relay_bundle: &[u8],
    permanent: bool,
) -> Result<NodeInfo, String> {
    let now = now_unix();
    if !permanent {
        authorities
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ensure_capacity()?;
    }
    let limits = LeaseLimits {
        max_queue_cells: crate::queues::DEFAULT_QUEUE_CELLS,
        max_queue_bytes: crate::queues::DEFAULT_QUEUE_BYTES,
    };
    let mut aliases = Vec::with_capacity(2);
    let mut create_paths = Vec::with_capacity(2);
    for _ in 0..2 {
        let queue_id = random_nonzero();
        let epoch = u64::from_be_bytes(random_nonzero());
        let capabilities = Capabilities {
            push: random_nonzero(),
            sub: random_nonzero(),
            admin: random_nonzero(),
        };
        let provision = store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .issue_grant(
                GrantRequest {
                    queue_id,
                    epoch,
                    limits,
                },
                now,
            )
            .map_err(|e| e.to_string())?;
        let expiry = now + 24 * 60 * 60;
        let create = LeaseCreate {
            queue_id,
            epoch,
            lease_expiry: expiry,
            queue_cells: limits.max_queue_cells,
            queue_bytes: limits.max_queue_bytes,
            capabilities,
            nonce: random_nonzero(),
            grant: provision.wire,
        };
        let wire = create
            .encode(&target.relay_service_id)
            .map_err(|e| e.to_string())?;
        // A minted card is only useful when its queue exists. Create the lease
        // and publish the queue token now, so a later client activation is a
        // harmless idempotent replay instead of the only path to a live queue.
        store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .create_lease(&wire, now)
            .map_err(|e| e.to_string())?;
        registry.insert_queue(&encode_b64url(&queue_id));
        let create_path = encode_b64url(&provision.grant.grant_cap);
        registry.insert_post(&create_path);
        create_paths.push(create_path.clone());
        let contact = AliasContact {
            target: target.clone(),
            queue_id,
            epoch,
            push_cap: capabilities.push,
            expiry,
        };
        aliases.push(OwnedAlias {
            contact,
            capabilities,
            limits,
            create_path,
            lease_create: Cell::new(CellType::RelaySub, 0, 0, wire.to_vec()),
        });
    }
    let frwd_path = gcoms_transport::generate_token();
    let hop_key = random_nonzero();
    registry.insert_post(&frwd_path);
    {
        let mut guard = authorities.lock().unwrap_or_else(|p| p.into_inner());
        if permanent {
            guard.insert_permanent(&frwd_path, hop_key);
        } else {
            guard.register_provision(
                create_paths,
                &frwd_path,
                hop_key,
                now + crate::queues::DEFAULT_GRANT_LIFETIME_SECS + PROVISION_GRANT_MARGIN_SECS,
            );
        }
    }
    Ok(NodeInfo {
        identity_pk: relay_identity_pk.to_vec(),
        bundle: relay_bundle.to_vec(),
        aliases: aliases.iter().map(|owned| owned.contact.clone()).collect(),
        provisioning: Some(RelayProvision {
            aliases,
            frwd_path,
            hop_key,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_handlers(
    leases: &Arc<Mutex<LeaseStore>>,
    registry: &TokenRegistry,
    queue_tokens: &Arc<Mutex<HashMap<[u8; 32], String>>>,
    authorities: &Arc<Mutex<ProvisionAuthorities>>,
    scheduler: &RelayScheduler,
    frwd_target_policy: &FrwdTargetPolicy,
    service_id: [u8; 32],
    stream_emission: super::StreamEmission,
) -> (CellHandler, QueueCellHandler, StreamHandler) {
    let lease_for_cell = leases.clone();
    let registry_for_cell = registry.clone();
    let queue_tokens_for_cell = queue_tokens.clone();
    let scheduler_for_frwd = scheduler.clone();
    let authorities_for_cell = authorities.clone();
    let frwd_policy_for_cell = frwd_target_policy.clone();
    let on_cell: CellHandler = Arc::new(move |token: &str, cell: Cell| {
        if cell.cell_type() == Some(CellType::RelaySub) {
            let operation = cell
                .payload
                .get(1)
                .copied()
                .ok_or(QueueReject::Unauthorized)?;
            if matches!(
                operation,
                gcoms_core::bootstrap::OP_RELAY_CHALLENGE
                    | gcoms_core::bootstrap::OP_RELAY_ADMISSION
            ) {
                return Err(QueueReject::Unauthorized);
            }
            let mut store = lease_for_cell.lock().unwrap_or_else(|p| p.into_inner());
            if operation == OP_GRANT_REQUEST {
                let provision = match store.issue_dynamic_grant(&cell.payload, now_unix()) {
                    Ok(provision) => provision,
                    Err(StoreError::Replay | StoreError::GrantConsumed) => {
                        return Err(QueueReject::Conflict)
                    }
                    Err(
                        StoreError::QueueFull | StoreError::Capacity | StoreError::ReplayCapacity,
                    ) => return Err(QueueReject::Overloaded),
                    Err(_) => return Err(QueueReject::Unauthorized),
                };
                let create_path = encode_b64url(&provision.grant.grant_cap);
                registry_for_cell.insert_post(&create_path);
                return Ok(Some(Cell::new(
                    CellType::Ack,
                    0,
                    0,
                    provision.wire.to_vec(),
                )));
            }
            let result = match operation {
                OP_CREATE => store.create_lease(&cell.payload, now_unix()),
                OP_RENEW => store.renew(&cell.payload, now_unix()),
                OP_ROTATE => store.rotate(&cell.payload, now_unix()),
                OP_REVOKE => {
                    store
                        .revoke(&cell.payload, now_unix())
                        .map(|_| crate::queues::LeaseView {
                            queue_id: cell.payload[2..34].try_into().unwrap_or([0; 32]),
                            epoch: 0,
                            expiry: 0,
                            limits: LeaseLimits {
                                max_queue_cells: 0,
                                max_queue_bytes: 0,
                            },
                        })
                }
                _ => return Err(QueueReject::Unauthorized),
            };
            let view = match result {
                Ok(view) => view,
                Err(StoreError::Replay | StoreError::GrantConsumed) => {
                    return Err(QueueReject::Conflict)
                }
                Err(StoreError::QueueFull | StoreError::Capacity | StoreError::ReplayCapacity) => {
                    return Err(QueueReject::Overloaded)
                }
                Err(_) => return Err(QueueReject::Unauthorized),
            };
            if operation == OP_CREATE {
                let queue_token = encode_b64url(&view.queue_id);
                // A mint-time queue registration (or a replayed activation) is
                // not a conflict; only a token registered as another kind is.
                match registry_for_cell.kind(&queue_token) {
                    Some(gcoms_transport::TokenKind::Queue) => {}
                    None => {
                        if !registry_for_cell.insert_queue(&queue_token) {
                            return Err(QueueReject::Conflict);
                        }
                    }
                    Some(_) => return Err(QueueReject::Conflict),
                }
                queue_tokens_for_cell
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(view.queue_id, token.to_string());
            } else if operation == OP_REVOKE {
                registry_for_cell.remove_queue(&encode_b64url(&view.queue_id));
                queue_tokens_for_cell
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&view.queue_id);
                registry_for_cell.remove_post(token);
            }
            authorities_for_cell
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .note_admin_use(token, now_unix());
            return Ok(Some(Cell::new(CellType::Ack, 0, 0, Vec::new())));
        }
        if cell.cell_type() == Some(CellType::Frwd) {
            let restricted = authorities_for_cell
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .frwd
                .get(token)
                .is_some_and(|entry| entry.destinations.is_some());
            if restricted {
                return Err(QueueReject::Unauthorized);
            }
            return admit_frwd_cell(
                token,
                &cell,
                &authorities_for_cell,
                &scheduler_for_frwd,
                &service_id,
                &frwd_policy_for_cell,
            );
        }
        Err(QueueReject::Unauthorized)
    });

    let lease_for_queue = leases.clone();
    let on_queue_cell: QueueCellHandler = Arc::new(move |token, cell| {
        let path_queue = gcoms_transport::decode_b64url(token)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(QueueReject::Unauthorized)?;
        let push = UnauthenticatedRelayPush::parse(cell).map_err(|_| QueueReject::Unauthorized)?;
        if push.queue_id() != path_queue {
            return Err(QueueReject::Unauthorized);
        }
        match lease_for_queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .authenticate_push(push, now_unix())
        {
            // A cover deposit gets the same receipt as a real one.
            Ok(PushOutcome::Enqueued | PushOutcome::Duplicate | PushOutcome::Cover) => Ok(None),
            Err(StoreError::QueueFull | StoreError::Capacity | StoreError::ReplayCapacity) => {
                Err(QueueReject::Overloaded)
            }
            Err(StoreError::Replay | StoreError::GrantConsumed) => Err(QueueReject::Conflict),
            Err(_) => Err(QueueReject::Unauthorized),
        }
    });

    let lease_for_stream = leases.clone();

    let on_stream: StreamHandler = Arc::new(move |auth_body: &[u8]| {
        let cell = gcoms_core::decode(auth_body).ok()?;
        let sub = lease_for_stream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .authenticate_sub(&cell, now_unix())
            .ok()?;
        let store = lease_for_stream.clone();
        Some(Box::new(move |sink: gcoms_transport::server::StreamSink| {
            tokio::spawn(async move {
                let mut rng = rand::rngs::StdRng::from_entropy();
                let mut round = 0u16;
                loop {
                    tokio::time::sleep(stream_emission.slot_interval).await;
                    round = round.wrapping_add(1);
                    if !store
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .subscription_valid(
                            &sub.queue_id,
                            sub.epoch,
                            sub.subscription_expiry,
                            now_unix(),
                        )
                    {
                        break;
                    }
                    if !rand::Rng::gen_bool(&mut rng, stream_emission.emission_probability) {
                        continue;
                    }
                    let head = {
                        let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
                        store
                            .peek(&sub.queue_id, now_unix())
                            .map(|queued| (queued.push_nonce, queued.cell.clone()))
                    };
                    let cell = match head.as_ref().map(|(_, cell)| cell.clone()) {
                        Some(cell) => cell,
                        None if stream_emission.emit_cover => {
                            Cell::new(CellType::Cover, 0, round, Vec::new())
                        }
                        None => continue,
                    };
                    if !sink.send(cell).await {
                        break;
                    }
                    if let Some((nonce, _)) = head {
                        store.lock().unwrap_or_else(|p| p.into_inner()).acknowledge(
                            &sub.queue_id,
                            &nonce,
                            now_unix(),
                        );
                    }
                }
            });
            metrics::log_event("sub_attached", &[]);
        }) as AcceptedStream)
    });
    (on_cell, on_queue_cell, on_stream)
}

pub(crate) fn spawn_lease_sweeper(
    leases: Arc<Mutex<LeaseStore>>,
    queue_tokens: Arc<Mutex<HashMap<[u8; 32], String>>>,
    registry: TokenRegistry,
    authorities_for_cleanup: Arc<Mutex<ProvisionAuthorities>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let now = now_unix();
            let expired = {
                let mut store = leases.lock().unwrap_or_else(|p| p.into_inner());
                let tokens = queue_tokens.lock().unwrap_or_else(|p| p.into_inner());
                tokens
                    .keys()
                    .filter(|queue_id| store.lease(queue_id, now).is_none())
                    .copied()
                    .collect::<Vec<_>>()
            };
            let mut tokens = queue_tokens.lock().unwrap_or_else(|p| p.into_inner());
            for queue_id in expired {
                registry.remove_queue(&encode_b64url(&queue_id));
                if let Some(create_path) = tokens.remove(&queue_id) {
                    registry.remove_post(&create_path);
                }
            }
            drop(tokens);
            let swept = authorities_for_cleanup
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .sweep(now);
            for token in swept {
                registry.remove_post(&token);
                metrics::log_event("provision_authority_expired", &[]);
            }
        }
    })
}

#[cfg(test)]
mod provision_authority_tests {
    use super::*;
    use crate::relay::{Frwd, RelayPush};

    fn provision(
        registry: &mut ProvisionAuthorities,
        index: usize,
        expires_at: u64,
    ) -> (String, String, [u8; 32]) {
        let create_paths = vec![format!("create-{index}-a"), format!("create-{index}-b")];
        let frwd_path = format!("frwd-{index}");
        let hop_key = [(index % 256) as u8; 32];
        registry.register_provision(create_paths, &frwd_path, hop_key, expires_at);
        (frwd_path, format!("create-{index}-a"), hop_key)
    }

    fn authorized_frwd(
        hop_key: &[u8; 32],
        intermediary_service_id: &[u8; 32],
        marker: u8,
        now: u64,
    ) -> (Frwd, Cell) {
        let target = RelayTarget {
            address: "127.0.0.1:443".parse().unwrap(),
            relay_service_id: [marker; 32],
        };
        let push = RelayPush {
            queue_id: [marker; 32],
            epoch: 1,
            push_nonce: [marker; 16],
            push_expiry: now.saturating_add(60),
            msg: Some(Cell::new(CellType::Msg, 0, 0, vec![marker])),
        }
        .encode_into_cell(&[marker.wrapping_add(1); 32], &target.relay_service_id)
        .unwrap();
        let frwd = Frwd {
            target,
            frwd_expiry: now.saturating_add(60),
            relay_push: Some(UnauthenticatedRelayPush::parse(push).unwrap()),
            nonce: [marker; 16],
        };
        let cell = frwd
            .encode_into_cell(hop_key, intermediary_service_id, true)
            .unwrap();
        (frwd, cell)
    }

    #[test]
    fn pending_public_provisions_are_bounded_and_expire() {
        let mut registry = ProvisionAuthorities::default();
        for index in 0..MAX_PENDING_PROVISIONS {
            provision(&mut registry, index, 1_000_000);
        }
        assert!(registry.ensure_capacity().is_err());
        let mut swept = registry.sweep(1_000_001);
        swept.sort();
        assert_eq!(swept.len(), MAX_PENDING_PROVISIONS * 3);
        assert!(registry.ensure_capacity().is_ok());
        assert!(registry.lookup_frwd("frwd-0", 1_000_001).is_none());
    }

    #[test]
    fn activated_authority_slides_and_survives_sweep() {
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, create_path, hop_key) = provision(&mut registry, 9, 5_000);
        registry.note_admin_use(&create_path, 4_000);
        assert_eq!(registry.lookup_frwd(&frwd_path, 4_000), Some(hop_key));
        assert!(registry.sweep(5_000).is_empty());
        assert_eq!(
            registry.lookup_frwd(&frwd_path, 4_000 + PROVISION_FRWD_IDLE_SECS - 1),
            Some(hop_key)
        );
        let swept = registry.sweep(4_000 + 2 * PROVISION_FRWD_IDLE_SECS);
        assert_eq!(swept, vec!["frwd-9", "create-9-a", "create-9-b"]);
        assert_eq!(registry.lookup_frwd(&frwd_path, 4_000), None);
    }

    #[test]
    fn permanent_authority_never_expires() {
        let mut registry = ProvisionAuthorities::default();
        registry.insert_permanent("own", [7; 32]);
        assert_eq!(
            registry.lookup_frwd("own", u64::MAX - PROVISION_FRWD_IDLE_SECS),
            Some([7; 32])
        );
        assert!(registry.sweep(u64::MAX).is_empty());
    }

    #[test]
    fn lookup_does_not_slide_authority_until_work_is_admitted() {
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, _, hop_key) = provision(&mut registry, 3, 1_000);
        assert_eq!(registry.lookup_frwd(&frwd_path, 1_000), None);
        assert_eq!(registry.lookup_frwd(&frwd_path, 999), Some(hop_key));
        assert_eq!(registry.lookup_frwd(&frwd_path, 1_000), None);
        assert!(registry.note_frwd_admitted(&frwd_path, &hop_key, 999));
        assert_eq!(registry.lookup_frwd(&frwd_path, 1_000), Some(hop_key));
    }

    #[test]
    fn admission_touch_rejects_a_stale_hop_key() {
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, _, _) = provision(&mut registry, 4, 1_000);
        assert!(!registry.note_frwd_admitted(&frwd_path, &[99; 32], 900));
        assert_eq!(registry.frwd[&frwd_path].expires_at, Some(1_000));
    }

    #[test]
    fn temporary_forwarding_pins_queue_target_epoch_and_never_slides() {
        let target = RelayTarget {
            address: "127.0.0.1:24445".parse().unwrap(),
            relay_service_id: [6; 32],
        };
        let destination = AliasContact {
            target: target.clone(),
            queue_id: [7; 32],
            epoch: 8,
            push_cap: [9; 32],
            expiry: 2000,
        };
        let mut registry = ProvisionAuthorities::default();
        registry.register_temporary(
            "create".into(),
            "forward".into(),
            [5; 32],
            1500,
            vec![destination.clone()],
        );
        let make = |queue, epoch| {
            crate::relay::UnauthenticatedRelayPush::parse(
                crate::relay::RelayPush {
                    queue_id: queue,
                    epoch,
                    push_expiry: 1400,
                    push_nonce: [10; 16],
                    msg: Some(Cell::new(CellType::Msg, 0, 0, b"bootstrap".to_vec())),
                }
                .encode_into_cell(&destination.push_cap, &target.relay_service_id)
                .unwrap(),
            )
            .unwrap()
        };
        let mut frwd = crate::relay::Frwd {
            target: target.clone(),
            frwd_expiry: 1400,
            relay_push: Some(make(destination.queue_id, destination.epoch)),
            nonce: [11; 16],
        };
        assert!(registry.permits_frwd("forward", &[5; 32], &frwd, 1000));
        frwd.relay_push = Some(make([12; 32], destination.epoch));
        assert!(!registry.permits_frwd("forward", &[5; 32], &frwd, 1000));
        frwd.relay_push = Some(make(destination.queue_id, destination.epoch + 1));
        assert!(!registry.permits_frwd("forward", &[5; 32], &frwd, 1000));
        frwd.relay_push = Some(make(destination.queue_id, destination.epoch));
        frwd.target.address.set_port(24446);
        assert!(!registry.permits_frwd("forward", &[5; 32], &frwd, 1000));
        frwd.target = target;
        frwd.target.relay_service_id[0] ^= 1;
        assert!(!registry.permits_frwd("forward", &[5; 32], &frwd, 1000));
        registry.note_admin_use("create", 1499);
        assert!(registry.note_frwd_admitted("forward", &[5; 32], 1499));
        assert_eq!(registry.frwd["forward"].expires_at, Some(1500));
        assert!(registry.lookup_frwd("forward", 1500).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_frwd_does_not_slide_authority() {
        let now = now_unix();
        let expires_at = now.saturating_add(60);
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, _, hop_key) = provision(&mut registry, 5, expires_at);
        let authorities = Arc::new(Mutex::new(registry));
        let service_id = [42; 32];
        let (_, mut cell) = authorized_frwd(&hop_key, &service_id, 5, now);
        *cell.payload.last_mut().unwrap() ^= 1;
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );

        assert_eq!(
            admit_frwd_cell(
                &frwd_path,
                &cell,
                &authorities,
                &scheduler,
                &service_id,
                &FrwdTargetPolicy::new(true),
            ),
            Err(QueueReject::Unauthorized)
        );
        assert_eq!(
            authorities.lock().unwrap().frwd[&frwd_path].expires_at,
            Some(expires_at)
        );
        scheduler.shutdown();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn automatic_transit_refuses_unprobed_real_work_without_sliding_authority() {
        let now = now_unix();
        let expires_at = now.saturating_add(60);
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut registry = ProvisionAuthorities {
            transit_ready: Some(ready.clone()),
            ..Default::default()
        };
        let (path, _, key) = provision(&mut registry, 7, expires_at);
        let authorities = Arc::new(Mutex::new(registry));
        let service_id = [43; 32];
        let (_, cell) = authorized_frwd(&key, &service_id, 6, now);
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        assert_eq!(
            admit_frwd_cell(
                &path,
                &cell,
                &authorities,
                &scheduler,
                &service_id,
                &FrwdTargetPolicy::new(true)
            ),
            Err(QueueReject::Overloaded)
        );
        assert_eq!(
            authorities.lock().unwrap().frwd[&path].expires_at,
            Some(expires_at)
        );
        assert_eq!(
            authorities
                .lock()
                .unwrap()
                .admitted
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        ready.store(true, std::sync::atomic::Ordering::Release);
        assert!(admit_frwd_cell(
            &path,
            &cell,
            &authorities,
            &scheduler,
            &service_id,
            &FrwdTargetPolicy::new(true)
        )
        .is_ok());
        scheduler.shutdown();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_frwd_admission_slides_authority_before_success() {
        let now = now_unix();
        let expires_at = now.saturating_add(60);
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, _, hop_key) = provision(&mut registry, 6, expires_at);
        let authorities = Arc::new(Mutex::new(registry));
        let service_id = [43; 32];
        let (_, cell) = authorized_frwd(&hop_key, &service_id, 6, now);
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );

        assert!(matches!(
            admit_frwd_cell(
                &frwd_path,
                &cell,
                &authorities,
                &scheduler,
                &service_id,
                &FrwdTargetPolicy::new(true),
            ),
            Ok(None)
        ));
        assert!(authorities.lock().unwrap().frwd[&frwd_path]
            .expires_at
            .is_some_and(|expires| expires > expires_at));
        scheduler.shutdown();
        tokio::task::yield_now().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scheduler_shutdown_rejects_frwd_without_sliding_authority() {
        let now = now_unix();
        let expires_at = now.saturating_add(60);
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, _, hop_key) = provision(&mut registry, 7, expires_at);
        let authorities = Arc::new(Mutex::new(registry));
        let service_id = [44; 32];
        let (_, cell) = authorized_frwd(&hop_key, &service_id, 7, now);
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        scheduler.shutdown();

        assert_eq!(
            admit_frwd_cell(
                &frwd_path,
                &cell,
                &authorities,
                &scheduler,
                &service_id,
                &FrwdTargetPolicy::new(true),
            ),
            Err(QueueReject::Overloaded)
        );
        assert_eq!(
            authorities.lock().unwrap().frwd[&frwd_path].expires_at,
            Some(expires_at)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_forward_lane_rejects_frwd_without_sliding_authority() {
        let now = now_unix();
        let expires_at = now.saturating_add(60);
        let mut registry = ProvisionAuthorities::default();
        let (frwd_path, _, hop_key) = provision(&mut registry, 8, expires_at);
        let authorities = Arc::new(Mutex::new(registry));
        let service_id = [45; 32];
        let (frwd, cell) = authorized_frwd(&hop_key, &service_id, 8, now);
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        let mut receipts = Vec::new();
        let mut filled = false;
        for _ in 0..1024 {
            match scheduler.forward(frwd.clone()) {
                Ok(receipt) => receipts.push(receipt),
                Err(EnqueueError::Full) => {
                    filled = true;
                    break;
                }
                Err(EnqueueError::Shutdown | EnqueueError::Pending | EnqueueError::InvalidCell) => {
                    panic!("unexpected scheduler state while filling lane")
                }
            }
        }
        assert!(filled, "forward lane did not reach its bound");

        assert_eq!(
            admit_frwd_cell(
                &frwd_path,
                &cell,
                &authorities,
                &scheduler,
                &service_id,
                &FrwdTargetPolicy::new(true),
            ),
            Err(QueueReject::Overloaded)
        );
        assert_eq!(
            authorities.lock().unwrap().frwd[&frwd_path].expires_at,
            Some(expires_at)
        );
        scheduler.shutdown();
        drop(receipts);
    }
}
