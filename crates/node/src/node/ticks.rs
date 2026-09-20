// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;
use futures_util::{stream::FuturesUnordered, StreamExt};

#[cfg(all(test, feature = "client-persist"))]
#[path = "ticks_tests.rs"]
mod tests;

#[derive(Default)]
struct SubscriptionRoute {
    #[cfg(feature = "experimental-gc2")]
    entry: Option<(Arc<gcoms_routing::gc2::owner::ReadyConnector>, u64)>,
}

impl SubscriptionRoute {
    /// Entry renewal does not invalidate terminal queue authority. Only observe
    /// the background owner's ready set; never dial or wake it from this pump.
    fn prepare(state: &NodeState, target: &RelayTarget) -> Option<Self> {
        #[cfg(feature = "experimental-gc2")]
        if let Some(entry) = &state.gc2_carrier {
            let revision = entry.route_revision((target.address, target.relay_service_id))?;
            return Some(Self {
                entry: Some((entry.clone(), revision)),
            });
        }
        let _ = (state, target);
        Some(Self::default())
    }

    /// A failed request on a replaced/unavailable entry is inconclusive about
    /// the inbox. Reopen through the current route before recovering authority.
    fn unchanged(&self, target: &RelayTarget) -> bool {
        #[cfg(feature = "experimental-gc2")]
        if let Some((entry, revision)) = &self.entry {
            return entry.route_revision((target.address, target.relay_service_id))
                == Some(*revision);
        }
        let _ = target;
        true
    }
}

pub(crate) fn spawn_contact_subscription_pump(
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events: broadcast::Sender<Ev>,
    poll_interval: std::time::Duration,
) -> super::api::ShutdownTask {
    let poll_interval = poll_interval.min(std::time::Duration::from_secs(1));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut subscriptions = FuturesUnordered::new();
        let mut active = HashSet::<([u8; 32], gcoms_core::TrafficClass)>::new();
        let mut clock = tokio::time::interval(poll_interval);
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                Some(key) = subscriptions.next(), if !subscriptions.is_empty() => {
                    active.remove(&key);
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    st.subscribed_contact_aliases.remove(&key.0);
                    st.subscribed_classes.remove(&key);
                    continue;
                },
                _ = clock.tick() => {},
            }
            let aliases = {
                let st = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if st.owner_transition_failed {
                    break;
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
                for &traffic in scheduler.subscription_classes() {
                    let alias = alias.clone();
                    let queue_id = alias.contact.queue_id;
                    let key = (queue_id, traffic);
                    if !active.insert(key) {
                        continue;
                    }
                    let state = state.clone();
                    let scheduler = scheduler.clone();
                    let events = events.clone();
                    subscriptions.push(async move {
                    if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias) { return key; }
                    let Some(route) = SubscriptionRoute::prepare(
                        &state.lock().unwrap_or_else(|p| p.into_inner()),
                        &alias.contact.target,
                    ) else { return key; };
                    let opened = match scheduler.subscribe_with_class(alias.clone(), traffic) {
                        Ok(receipt) => receipt.completion().await.delivery_stream(),
                        Err(error) => Err(error.to_string()),
                    };
                    // Accepted natural subscriptions end on a fixed deadline.
                    // Reopen the same authority first; a failed reopen triggers
                    // recovery. A normal stream renewal must not reprovision it.
                    let resubscribe_in_place = scheduler.is_gc2() && opened.is_ok();
                    match opened {
                        Ok(mut stream) => {
                            if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias) { return key; }
                            {
                                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                                st.subscribed_classes.insert(key);
                                if scheduler.subscription_classes().iter().all(|&class| st.subscribed_classes.contains(&(queue_id, class))) {
                                    st.subscribed_contact_aliases.insert(queue_id);
                                }
                            }
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
                    if !resubscribe_in_place && route.unchanged(&alias.contact.target) {
                        super::routing::owner_unavailable(&state.lock().unwrap_or_else(|p| p.into_inner()), &alias);
                    }
                    key
                });
                }
            }
        }
        drop(subscriptions);
    });
    super::api::ShutdownTask { stop, task }
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
) -> super::api::ShutdownTask {
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut subscriptions = FuturesUnordered::new();
        let mut active = HashSet::<(String, usize, [u8; 32], gcoms_core::TrafficClass)>::new();
        let mut clock = tokio::time::interval(std::time::Duration::from_millis(500));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                Some(key) = subscriptions.next(), if !subscriptions.is_empty() => {
                    active.remove(&key);
                    state.lock().unwrap_or_else(|p| p.into_inner()).subscribed_classes.remove(&(key.2, key.3));
                    continue;
                },
                _ = clock.tick() => {},
            }
            let aliases = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                if st.owner_transition_failed {
                    break;
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
                for &traffic in scheduler.subscription_classes() {
                    let alias = alias.clone();
                    let key = (key.0.clone(), key.1, key.2, traffic);
                    if !active.insert(key.clone()) {
                        continue;
                    }
                    let state = state.clone();
                    let scheduler = scheduler.clone();
                    let events = events.clone();
                    subscriptions.push(async move {
                        let target = alias.contact.target.clone();
                        let Some(route) = SubscriptionRoute::prepare(
                            &state.lock().unwrap_or_else(|p| p.into_inner()),
                            &target,
                        ) else {
                            return key;
                        };
                        let stream = match scheduler.subscribe_with_class(alias, traffic) {
                            Ok(receipt) => receipt.completion().await.delivery_stream(),
                            Err(error) => Err(error.to_string()),
                        };
                        let resubscribe_in_place = scheduler.is_gc2() && stream.is_ok();
                        if let Ok(mut stream) = stream {
                            state
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .subscribed_classes
                                .insert((key.2, key.3));
                            while let Some(Ok(cell)) = stream.recv().await {
                                handle_incoming(&state, cell, &events);
                            }
                        }
                        if !resubscribe_in_place && route.unchanged(&target) {
                            if let Some(runtime) =
                                &state.lock().unwrap_or_else(|p| p.into_inner()).routing
                            {
                                runtime
                                    .channel_ready
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .remove(&key.0);
                            }
                        }
                        key
                    });
                }
            }
        }
        drop(subscriptions);
    });
    super::api::ShutdownTask { stop, task }
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
        let mut maintenance = DirectMaintenance::default();
        let clock = tokio::time::sleep(scheduler_profile.maintenance_delay(&mut rng));
        tokio::pin!(clock);
        loop {
            tokio::select! {
                _ = &mut clock => {
                    maintenance.tick(&state, &scheduler, &events);
                    clock.as_mut().reset(tokio::time::Instant::now()
                        + scheduler_profile.maintenance_delay(&mut rng));
                }
                _ = maintenance.complete_next(&state), if !maintenance.is_empty() => {}
            }
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
) -> super::api::ShutdownTask {
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        // An inbox bound alone does not bound detached work across ticks.
        // Retain at most this many active redemptions, owned by this task so
        // shutdown releases every state/profile reference before returning.
        const MAX_ACTIVE: usize = 64;
        let mut active = FuturesUnordered::new();
        let mut clock = tokio::time::interval(std::time::Duration::from_millis(100));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
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
        drop(active);
    });
    super::api::ShutdownTask { stop, task }
}
