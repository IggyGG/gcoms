// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;
use futures_util::{stream::FuturesUnordered, StreamExt};

#[cfg(all(test, feature = "client-persist"))]
#[path = "ticks_tests.rs"]
mod tests;

pub(crate) fn spawn_contact_subscription_pump(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
    poll_interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    let poll_interval = poll_interval.min(std::time::Duration::from_secs(1));
    tokio::spawn(async move {
        let mut subscriptions = FuturesUnordered::new();
        let mut active = HashSet::new();
        let mut clock = tokio::time::interval(poll_interval);
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                Some(queue_id) = subscriptions.next(), if !subscriptions.is_empty() => {
                    active.remove(&queue_id);
                    state.lock().unwrap_or_else(|p| p.into_inner())
                        .subscribed_contact_aliases.remove(&queue_id);
                    continue;
                },
                _ = clock.tick() => {},
            }
            let aliases = {
                let st = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if st.owner_transition_failed {
                    return;
                }
                if super::routing::recovering(&st) {
                    Vec::new()
                } else {
                    let now = std::time::Instant::now();
                    st.client_relay
                        .aliases
                        .iter()
                        .chain(st.staged_contact_aliases.iter().flatten())
                        .chain(
                            st.unannounced_old_contact_aliases
                                .iter()
                                .filter(|_| {
                                    st.unannounced_contact_deadlines
                                        .is_some_and(|(until, _)| until > now)
                                })
                                .flatten(),
                        )
                        .chain(
                            st.draining_contact_aliases
                                .iter()
                                .filter(|draining| {
                                    draining.receive_until > now && draining.abandon_at > now
                                })
                                .flat_map(|draining| draining.aliases.iter()),
                        )
                        .filter(|alias| owner_alias_receiving(&st, alias))
                        .cloned()
                        .collect::<Vec<_>>()
                }
            };
            for alias in aliases {
                let queue_id = alias.contact.queue_id;
                if !active.insert(queue_id) {
                    continue;
                }
                let state = state.clone();
                let scheduler = scheduler.clone();
                let events = events.clone();
                subscriptions.push(async move {
                    if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias) { return queue_id; }
                    let opened = match scheduler.subscribe(alias.clone()) {
                        Ok(receipt) => receipt.completion().await.stream(),
                        Err(error) => Err(error.to_string()),
                    };
                    match opened {
                        Ok(mut stream) => {
                            if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias) { return queue_id; }
                            state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .subscribed_contact_aliases
                                .insert(queue_id);
                            metrics::log_event("contact_sub_connected", &[]);
                            loop {
                                tokio::select! {
                                    value = stream.recv() => {
                                        let Some(Ok(cell)) = value else { break; };
                                        if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias) { break; }
                                        handle_incoming(&state, cell, &events);
                                    }
                                    _ = tokio::time::sleep(poll_interval) => {
                                        if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias) { break; }
                                    }
                                }
                            }
                        }
                        Err(error) => metrics::log_event("contact_sub_error", &[("e", error)]),
                    }
                    super::routing::owner_unavailable(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias);
                    queue_id
                });
            }
        }
    })
}

pub(crate) fn spawn_alias_lifecycle_loop(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
    timing: AliasLifecycleConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(timing.poll_interval).await;
            if super::routing::recovering(&state.lock().unwrap_or_else(|p| p.into_inner())) {
                continue;
            }
            contact_alias_lifecycle_tick(&state, &scheduler, &events, timing).await;
        }
    })
}

pub(crate) fn spawn_channel_subscription_pump(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut subscriptions = FuturesUnordered::new();
        let mut active = std::collections::HashSet::new();
        let mut clock = tokio::time::interval(std::time::Duration::from_millis(500));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                Some(key) = subscriptions.next(), if !subscriptions.is_empty() => {
                    active.remove(&key);
                    continue;
                },
                _ = clock.tick() => {},
            }
            let aliases = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                if st.owner_transition_failed {
                    return;
                }
                st.channels
                    .iter()
                    .filter(|(name, _)| {
                        st.routing.as_ref().is_none_or(|r| {
                            r.channel_ready
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .contains(*name)
                        })
                    })
                    .flat_map(|(channel, channel_state)| {
                        channel_state
                            .own_route
                            .aliases
                            .iter()
                            .enumerate()
                            .map(|(index, alias)| {
                                (
                                    (channel.clone(), index, alias.contact.queue_id),
                                    alias.clone(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            };
            for (key, alias) in aliases {
                if !active.insert(key.clone()) {
                    continue;
                }
                let state = state.clone();
                let scheduler = scheduler.clone();
                let events = events.clone();
                subscriptions.push(async move {
                    let stream = match scheduler.subscribe(alias) {
                        Ok(receipt) => receipt.completion().await.stream(),
                        Err(error) => Err(error.to_string()),
                    };
                    if let Ok(mut stream) = stream {
                        while let Some(Ok(cell)) = stream.recv().await {
                            handle_incoming(&state, cell, &events);
                        }
                    }
                    if let Some(runtime) = &state.lock().unwrap_or_else(|p| p.into_inner()).routing
                    {
                        runtime
                            .channel_ready
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&key.0);
                    }
                    key
                });
            }
        }
    })
}

pub(crate) fn spawn_channel_alias_renew_loop(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(jittered(std::time::Duration::from_secs(60))).await;
            if super::routing::recovering(&state.lock().unwrap_or_else(|p| p.into_inner())) {
                continue;
            }
            let now = now_unix();
            let aliases = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                if st.owner_transition_failed {
                    return;
                }
                st.channels
                    .iter()
                    .flat_map(|(channel, channel_state)| {
                        channel_state
                            .own_route
                            .aliases
                            .iter()
                            .enumerate()
                            .map(|(index, alias)| (channel.clone(), index, alias.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            };
            for (channel, index, alias) in aliases {
                if alias.contact.expiry.saturating_sub(now) > 10 * 60 {
                    continue;
                }
                let expiry = now.saturating_add(60 * 60);
                let renew = LeaseRenew {
                    queue_id: alias.contact.queue_id,
                    epoch: alias.contact.epoch,
                    lease_expiry: expiry,
                    nonce: random_nonzero(),
                };
                let Ok(wire) = renew.encode(
                    &alias.capabilities.admin,
                    &alias.contact.target.relay_service_id,
                ) else {
                    continue;
                };
                let cell = Cell::new(CellType::RelaySub, 0, 0, wire.to_vec());
                let renewed = match scheduler.admin_post(
                    alias.contact.target.clone(),
                    alias.create_path.clone(),
                    cell,
                ) {
                    Ok(receipt) => receipt.completion().await.accepted().is_ok(),
                    Err(_) => false,
                };
                if !renewed {
                    continue;
                }
                let update = {
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    apply_accepted_channel_renewal(&mut st, &channel, index, &alias, expiry)
                };
                if let Ok(Some(update)) = update {
                    let _ = broadcast_chan(&state, &scheduler, &channel, &update, None).await;
                }
            }
        }
    })
}

/// Called only after the relay accepts an authenticated renewal. The complete
/// route and its exact signed announcement are durable before publication.
pub(super) fn apply_accepted_channel_renewal(
    st: &mut NodeState,
    channel: &str,
    index: usize,
    prior: &OwnedAlias,
    expiry: u64,
) -> Result<Option<Vec<u8>>, String> {
    if st.owner_transition_failed {
        return Err("channel lifecycle persistence outcome is unconfirmed".into());
    }
    let Some(cs) = st.channels.get_mut(channel) else {
        return Ok(None);
    };
    if index > 1
        || cs.own_route.aliases.get(index) != Some(prior)
        || prior.contact.expiry <= now_unix()
        || expiry <= prior.contact.expiry
    {
        return Ok(None);
    }
    let name = cs
        .roster()
        .into_iter()
        .find(|member| member.is_self)
        .ok_or("channel has no own roster entry")?
        .display_name;
    let mut public = cs.own_route.public.clone();
    if index == 0 {
        public.data.expiry = expiry;
    } else {
        public.control.expiry = expiry;
    }
    let wire = match cs.role.send(&crate::channel::encode_dir(&name, &public)) {
        Ok(wire) => wire,
        Err(error) => {
            st.pause_failed_owner_transition();
            return Err(error.to_string());
        }
    };
    cs.own_route.aliases[index].contact.expiry = expiry;
    cs.own_route.public = public.clone();
    if cs.install_authenticated_route(&name, &public).is_none() {
        st.pause_failed_owner_transition();
        return Err("owned channel route replacement refused".into());
    }
    let id = crate::channel::msg_id(channel, &wire);
    cs.note(id, wire.clone());
    cs.enqueue_forward(id, wire.clone());
    if let Err(error) = persist_current_direct_state(st) {
        st.pause_failed_owner_transition();
        return Err(error);
    }
    Ok(Some(wire))
}

pub(crate) fn spawn_contact_renew_loop(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(jittered(std::time::Duration::from_secs(60))).await;
            if super::routing::recovering(&state.lock().unwrap_or_else(|p| p.into_inner())) {
                continue;
            }
            if let Err(error) = renew_contact_aliases(&state, &scheduler, &events, false).await {
                metrics::log_event("contact_update_error", &[("e", error)]);
            }
        }
    })
}

/// Direct-message maintenance (ACK outbox, retries, presence expiry) runs on
/// its own task so channel fan-out can never starve 1:1 delivery.
pub(crate) fn spawn_direct_maintenance_loop(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
    scheduler_profile: SchedulerProfile,
    seed: [u8; 32],
) -> tokio::task::JoinHandle<()> {
    let mut rng = scheduler_profile.maintenance_rng_labeled(seed, b"direct");
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(scheduler_profile.maintenance_delay(&mut rng)).await;
            direct_tick(&state, &scheduler, &events).await;
        }
    })
}

pub(crate) fn spawn_channel_maintenance_loop(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
    scheduler_profile: SchedulerProfile,
    seed: [u8; 32],
) -> tokio::task::JoinHandle<()> {
    let mut data_rng = scheduler_profile.maintenance_rng_labeled(seed, b"channel");
    let mut control_rng = scheduler_profile.maintenance_rng_labeled(seed, b"channel-control");
    tokio::spawn(async move {
        // Both loops are owned by this task, so runtime shutdown cancels both.
        // Their jobs still leave through the existing lane slots and cover policy.
        let data = async {
            loop {
                tokio::time::sleep(scheduler_profile.maintenance_delay(&mut data_rng)).await;
                channel_tick(&state, &scheduler, &events).await;
            }
        };
        let control = async {
            loop {
                tokio::time::sleep(scheduler_profile.maintenance_delay(&mut control_rng)).await;
                channel_control_tick(&state, &scheduler, &events).await;
            }
        };
        tokio::join!(data, control);
    })
}

/// Owner side: service queued invite-redeem requests. Polls frequently (the
/// friend is actively waiting) but does nothing when the inbox is empty.
pub(crate) fn spawn_invite_service_loop(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // An inbox bound alone does not bound detached work across ticks.
        // Retain at most this many active redemptions, owned by this task so
        // shutdown releases every state/profile reference before returning.
        const MAX_ACTIVE: usize = 64;
        let mut active = FuturesUnordered::new();
        let mut clock = tokio::time::interval(std::time::Duration::from_millis(100));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                Some(()) = active.next(), if !active.is_empty() => continue,
                _ = clock.tick() => {},
            }
            let requests: Vec<_> = {
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                let count = st.invite_redeem_inbox.len().min(MAX_ACTIVE - active.len());
                st.invite_redeem_inbox.drain(..count).collect()
            };
            for request in requests {
                let state = state.clone();
                let scheduler = scheduler.clone();
                let events = events.clone();
                active.push(async move {
                    service_one_invite(&state, &scheduler, &events, request).await;
                });
            }
        }
    })
}
