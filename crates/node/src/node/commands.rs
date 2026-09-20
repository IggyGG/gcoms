// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

#[cfg(all(test, feature = "client-persist"))]
#[path = "channel_application_tests.rs"]
mod channel_application_tests;
use futures_util::{stream::FuturesUnordered, StreamExt};

// Transport maintenance records must survive a machine backend restart. Only
// legacy application/chat work needs draining before assigning component scope.
fn machine_record_compatible(bytes: &[u8]) -> bool {
    use crate::proto::DirectRecord;
    match crate::proto::decode_direct_record(bytes) {
        Some(DirectRecord::Data {
            durable: true,
            body,
            ..
        }) => gcoms_core::component::RoutedApplication::decode(&body).is_ok(),
        Some(
            DirectRecord::Ack { .. }
            | DirectRecord::ContactUpdate { .. }
            | DirectRecord::ForwardGrant { .. }
            | DirectRecord::PresenceLease { .. },
        ) => true,
        _ => false,
    }
}

pub(crate) struct CommandLoopContext {
    pub(crate) state: Arc<Mutex<NodeState>>,
    pub(crate) frwd_admitted: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) scheduler: RelayScheduler,
    pub(crate) events_tx: broadcast::Sender<Ev>,
    #[cfg(feature = "relay-host")]
    pub(crate) relay_host: Option<Arc<super::host::RelayHost>>,
    pub(crate) cmd_rx: mpsc::Receiver<Cmd>,
}

/// Serialisation domain of a command. Commands with the same key run one at
/// a time in submission order; commands with different keys run
/// concurrently. Lock-only commands are handled inline and never wait.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum CmdKey {
    Peer(Vec<u8>),
    Channel(String),
    Global,
}

/// Bounded number of commands in flight across all keys. Beyond this the
/// loop applies back-pressure by waiting for a slot.
const MAX_INFLIGHT_COMMANDS: usize = 64;

#[derive(Default)]
struct KeyedSerializer {
    locks: Mutex<HashMap<CmdKey, KeyLocks>>,
}

/// Per-key scheduling locks. `prepare` serializes preparation; the completion
/// chain preserves wire/result order even though completion runs after the
/// preparation lock is released.
#[derive(Clone, Default)]
struct KeyLocks {
    prepare: Arc<tokio::sync::Mutex<()>>,
    completion: CompletionHandle,
}

/// FIFO completion chain: registering under the preparation lock keeps ticket
/// order equal to preparation order. A command holds its ticket (and therefore
/// keeps its successor waiting) until its completion future ends, including on
/// cancellation.
#[derive(Clone, Default)]
struct CompletionHandle {
    tail: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
}

struct CompletionTicket {
    previous: Option<tokio::sync::oneshot::Receiver<()>>,
    _mine: Option<tokio::sync::oneshot::Sender<()>>,
}

impl CompletionHandle {
    fn register(&self) -> CompletionTicket {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let previous = self
            .tail
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(receiver);
        CompletionTicket {
            previous,
            _mine: Some(sender),
        }
    }
}

impl CompletionTicket {
    /// Wait for the predecessor's completion. Dropping the ticket (normal end
    /// or cancellation) releases the successor.
    async fn wait(mut self) -> Self {
        if let Some(previous) = self.previous.take() {
            let _ = previous.await;
        }
        self
    }
}

impl KeyedSerializer {
    fn locks_for(&self, key: &CmdKey) -> KeyLocks {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        // Prune keys nobody holds any more. An entry is only pruned when no
        // command holds its preparation lock or completion chain.
        locks.retain(|_, locks| Arc::strong_count(&locks.prepare) > 1);
        locks.entry(key.clone()).or_default().clone()
    }
}

/// Everything a spawned command needs. Cloned per command.
#[derive(Clone)]
struct CmdEnv {
    state: Arc<Mutex<NodeState>>,
    scheduler: RelayScheduler,
    events_tx: broadcast::Sender<Ev>,
}

pub(crate) fn spawn_command_loop(ctx: CommandLoopContext) -> tokio::task::JoinHandle<()> {
    let CommandLoopContext {
        state,
        #[cfg_attr(not(feature = "client-persist"), allow(unused_variables))]
            frwd_admitted: frwd_admitted_counter,
        scheduler,
        events_tx,
        #[cfg(feature = "relay-host")]
        relay_host,
        mut cmd_rx,
    } = ctx;
    tokio::spawn(async move {
        let serializer = Arc::new(KeyedSerializer::default());
        type CommandFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
        let mut spawned = FuturesUnordered::<CommandFuture>::new();
        let env = CmdEnv {
            state: state.clone(),
            scheduler: scheduler.clone(),
            events_tx: events_tx.clone(),
        };
        // Own every command future in the loop. They progress concurrently;
        // cancellation releases their state references before the loop exits.
        macro_rules! dispatch {
            ($key:expr, $done:ident, |$state:ident, $scheduler:ident, $events:ident| $body:block) => {{
                let key = $key;
                let locks = serializer.locks_for(&key);
                let cmd_env = env.clone();
                let done = $done;
                spawned.push(Box::pin(async move {
                    let _prepare = locks.prepare.lock().await;
                    let _ticket = locks.completion.register().wait().await;
                    #[allow(unused_variables)]
                    let CmdEnv {
                        state: $state,
                        scheduler: $scheduler,
                        events_tx: $events,
                    } = cmd_env;
                    let result = async move $body.await;
                    let _ = done.send(result);
                }));
            }};
            ($key:expr, $done:ident, split |$state:ident, $scheduler:ident, $events:ident, $prepare:ident, $complete:ident| $body:block) => {{
                let key = $key;
                let locks = serializer.locks_for(&key);
                let cmd_env = env.clone();
                let done = $done;
                spawned.push(Box::pin(async move {
                    #[allow(unused_variables)]
                    let CmdEnv {
                        state: $state,
                        scheduler: $scheduler,
                        events_tx: $events,
                    } = cmd_env;
                    let $complete = locks.completion.clone();
                    let $prepare = locks.prepare.lock().await;
                    let result = async move $body.await;
                    let _ = done.send(result);
                }));
            }};
        }
        loop {
            let cmd = tokio::select! {
                Some(()) = spawned.next(), if !spawned.is_empty() => continue,
                cmd = cmd_rx.recv(), if spawned.len() < MAX_INFLIGHT_COMMANDS => {
                    let Some(cmd) = cmd else { break; };
                    cmd
                },
            };
            match cmd {
                Cmd::IntermediaryStats { done } => {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let _ = done.send(IntermediaryStats {
                        pool: st.forward_grants.len(),
                        active: st.active_intermediaries.len(),
                        fallbacks: st.intermediary_fallbacks,
                        frwd_admitted: frwd_admitted_counter
                            .load(std::sync::atomic::Ordering::Relaxed),
                    });
                }
                Cmd::InstallRoutingBootstrap { bundle, done } => {
                    let result = (|| {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        let runtime = st.routing.as_ref().ok_or("routing is not enabled")?;
                        if scheduler.is_gc2() {
                            return Err("GChat carrier requires GCRB2 bootstrap".into());
                        }
                        runtime
                            .discovery
                            .install(&bundle)
                            .map_err(|e| e.to_string())?;
                        persist_current_direct_state(&st)
                    })();
                    let _ = done.send(result);
                }
                Cmd::CurrentInfo { done } => {
                    let mut st = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    super::routing::refresh_public_info(&mut st);
                    let _ = done.send(st.info.clone());
                }
                Cmd::SignIdentityDigest { digest, done } => {
                    let identity_seed = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .identity_seed;
                    let signature = IdentityKeypair::from_seed(identity_seed)
                        .sign(&gcoms_core::identity_digest_signature_payload(&digest));
                    let _ = done.send(signature);
                }
                Cmd::SignPrincipalBindingHash { claims_hash, done } => {
                    let identity_seed = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .identity_seed;
                    let payload = gcoms_core::principal_binding_signature_payload(&claims_hash);
                    let signature = IdentityKeypair::from_seed(identity_seed).sign(&payload);
                    let _ = done.send(signature);
                }
                Cmd::InstallInboxRelay { relay, done } => {
                    dispatch!(CmdKey::Global, done, |state, scheduler, events_tx| {
                        install_inbox_relay(&state, &scheduler, &events_tx, &relay).await
                    });
                }
                Cmd::RenewContacts { done } => {
                    dispatch!(CmdKey::Global, done, |state, scheduler, events_tx| {
                        renew_contact_aliases(&state, &scheduler, &events_tx, true).await
                    });
                }
                Cmd::ListChannels { done } => {
                    let mut channels = {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        st.channels
                            .iter()
                            .map(|(channel, state)| ChannelView {
                                id: state.id,
                                channel: channel.clone(),
                                visibility: state.visibility,
                                status: if state.membership_outbox.is_some() {
                                    ChannelStatus::MembershipPending
                                } else {
                                    ChannelStatus::Active
                                },
                                role: match state.role {
                                    crate::channel::ChannelRole::Owner(_) => ChannelViewRole::Owner,
                                    crate::channel::ChannelRole::Member(_) => {
                                        ChannelViewRole::Member
                                    }
                                },
                                epoch: state.role.epoch(),
                            })
                            .collect::<Vec<_>>()
                    };
                    channels.sort_by(|left, right| left.channel.cmp(&right.channel));
                    let _ = done.send(channels);
                }
                Cmd::ChannelRoster { channel, done } => {
                    let result = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .channels
                        .get(&channel)
                        .map(crate::channel::ChannelState::roster)
                        .ok_or_else(|| "no channel".to_string());
                    let _ = done.send(result);
                }
                Cmd::PublicChannelDescriptor {
                    channel,
                    description,
                    activity,
                    automatic_join,
                    expires_at_unix,
                    done,
                } => {
                    let result = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .channels
                        .get(&channel)
                        .ok_or_else(|| "no channel".to_string())
                        .and_then(|channel| {
                            if channel.visibility != crate::channel::ChannelVisibility::Public {
                                return Err("private channels cannot be published".into());
                            }
                            channel
                                .role
                                .sign_public_descriptor(
                                    expires_at_unix,
                                    channel.title.clone(),
                                    description,
                                    activity,
                                    *automatic_join,
                                )
                                .map_err(str::to_string)
                        });
                    let _ = done.send(result);
                }
                Cmd::Shutdown { done } => {
                    scheduler.shutdown();
                    let drain = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                        while spawned.next().await.is_some() {}
                    });
                    if drain.await.is_err() {
                        spawned.clear();
                    }
                    let _ = done.send(());
                    break;
                }
                Cmd::SendVolatileApplication { peer, body, done } => {
                    let key = CmdKey::Peer(peer.identity_pk.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared = prepare_volatile_application(&state, &peer, &body)?;
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_direct_record(&scheduler, prepared)
                                .await
                                .map(|_| ())
                        }
                    );
                }
                Cmd::Send1to1 {
                    durable,
                    peer,
                    text,
                    via,
                    class,
                    done,
                } => {
                    let key = CmdKey::Peer(peer.identity_pk.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared = if durable {
                                prepare_durable_1to1_class(&state, &peer, &text, *via, class)?
                            } else {
                                prepare_1to1_class(&state, &peer, &text, *via, class)?
                            };
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_direct_record(&scheduler, prepared)
                                .await
                                .map(|_| ())
                        }
                    );
                }
                Cmd::Send1to1Tracked {
                    durable,
                    peer,
                    text,
                    via,
                    class,
                    done,
                } => {
                    let key = CmdKey::Peer(peer.identity_pk.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared = if durable {
                                prepare_durable_1to1_class(&state, &peer, &text, *via, class)?
                            } else {
                                prepare_tracked_1to1_class(&state, &peer, &text, *via, class)?
                            };
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_direct_record(&scheduler, prepared).await
                        }
                    );
                }
                Cmd::SendDirectPresence {
                    peer,
                    mode,
                    lease_secs,
                    via,
                    done,
                } => {
                    let key = CmdKey::Peer(peer.identity_pk.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared =
                                prepare_direct_presence(&state, &peer, mode, lease_secs, *via)?;
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_direct_record(&scheduler, prepared)
                                .await
                                .map(|_| ())
                        }
                    );
                }
                Cmd::SetDirectPresenceOptIn {
                    peer,
                    enabled,
                    via,
                    done,
                } => {
                    let peer_identity = peer.identity_pk.clone();
                    let result = if peer_identity.is_empty() || peer.primary().is_none() {
                        Err("invalid peer contact".into())
                    } else {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        let changed = if enabled {
                            st.direct_presence_opt_in.insert(peer_identity.clone())
                        } else {
                            st.direct_presence_opt_in.remove(&peer_identity)
                        };
                        if changed {
                            if !enabled {
                                withdraw_direct_presence(&mut st, &peer_identity, &events_tx);
                            }
                            if let Err(error) = persist_current_direct_state(&st) {
                                if enabled {
                                    st.direct_presence_opt_in.remove(&peer_identity);
                                }
                                Err(error)
                            } else {
                                Ok(())
                            }
                        } else {
                            Ok(())
                        }
                    };
                    if result.is_ok() && !enabled {
                        let key = CmdKey::Peer(peer_identity);
                        dispatch!(
                            key,
                            done,
                            split | state,
                            scheduler,
                            events_tx,
                            prepare,
                            complete | {
                                let prepared = prepare_direct_presence(
                                    &state,
                                    &peer,
                                    PresenceMode::Invisible,
                                    0,
                                    *via,
                                )?;
                                let ticket = complete.register();
                                drop(prepare);
                                let _ticket = ticket.wait().await;
                                complete_direct_record(&scheduler, prepared)
                                    .await
                                    .map(|_| ())
                                    .map_err(|error| {
                                        format!(
                                            "presence disabled locally; withdrawal failed: {error}"
                                        )
                                    })
                            }
                        );
                    } else {
                        let _ = done.send(result);
                    }
                }
                Cmd::ProvisionClientRelay { done } => {
                    #[cfg(feature = "relay-host")]
                    let result = relay_host
                        .as_ref()
                        .ok_or_else(|| "relay hosting is disabled".to_string())
                        .and_then(|host| host.provision(false));
                    #[cfg(not(feature = "relay-host"))]
                    let result = Err("relay hosting is not compiled in".to_string());
                    let _ = done.send(result);
                }
                Cmd::CreateChannel {
                    channel,
                    display,
                    capacity,
                    visibility,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, scheduler, events_tx| {
                        let result = create_channel(
                            &state, &scheduler, &channel, &display, capacity, visibility,
                        )
                        .await;
                        if let Ok(channel_id) = &result {
                            let _ = events_tx.send(Ev::ChannelRosterChanged {
                                channel: channel.clone(),
                                channel_id: *channel_id,
                            });
                        }
                        result
                    });
                }
                Cmd::PrepareChannelJoin { display, done } => {
                    dispatch!(CmdKey::Global, done, |state, scheduler, events_tx| {
                        prepare_channel_join(&state, &scheduler, &display).await
                    });
                }
                Cmd::ChannelKeyPackage { req_id, done } => {
                    let result = {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        st.prepared
                            .get(&req_id)
                            .map(|prepared| {
                                gcoms_mls::ChannelMember::key_package_bytes(&prepared.mls)
                                    .map(|key_package| {
                                        crate::channel::encode_join_package(
                                            &key_package,
                                            &prepared.route.public,
                                        )
                                    })
                                    .unwrap_or_default()
                            })
                            .filter(|b| !b.is_empty())
                            .ok_or_else(|| "unknown req".to_string())
                    };
                    let _ = done.send(result);
                }
                Cmd::RecoverChannelRoute {
                    channel,
                    expected_id,
                    expected_epoch,
                    welcome,
                    peer,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, scheduler, _events_tx| {
                        recover_channel_route(
                            &state,
                            &scheduler,
                            &channel,
                            expected_id,
                            expected_epoch,
                            &welcome,
                            &peer,
                        )
                        .await
                    });
                }
                Cmd::AdmitChannel {
                    channel,
                    key_package,
                    member_name,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, scheduler, events_tx| {
                        let result =
                            admit_channel(&state, &scheduler, &channel, &key_package, &member_name)
                                .await;
                        if result.is_ok() {
                            if let Some(channel_id) = state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .channels
                                .get(&channel)
                                .map(|channel| channel.id)
                            {
                                let _ = events_tx.send(Ev::ChannelRosterChanged {
                                    channel: channel.clone(),
                                    channel_id,
                                });
                            }
                        }
                        result
                    });
                }
                Cmd::CreateChannelInvite {
                    channel,
                    ttl_secs,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, _scheduler, _events_tx| {
                        create_channel_invite(&state, &channel, ttl_secs)
                    });
                }
                Cmd::RedeemChannelInvite {
                    channel,
                    invite_id,
                    invite_secret,
                    key_package,
                    member_name,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, scheduler, events_tx| {
                        let result = redeem_invite(
                            &state,
                            &scheduler,
                            &channel,
                            &invite_id,
                            &invite_secret,
                            &key_package,
                            &member_name,
                        )
                        .await;
                        if result.is_ok() {
                            if let Some(channel_id) = state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .channels
                                .get(&channel)
                                .map(|channel| channel.id)
                            {
                                let _ = events_tx.send(Ev::ChannelRosterChanged {
                                    channel: channel.clone(),
                                    channel_id,
                                });
                            }
                        }
                        result
                    });
                }
                Cmd::RedeemInviteRemote {
                    owner,
                    channel,
                    member_name,
                    key_package,
                    invite_id,
                    invite_secret,
                    timeout_secs,
                    done,
                } => {
                    let key = CmdKey::Peer(owner.identity_pk.clone());
                    dispatch!(key, done, |state, scheduler, _events_tx| {
                        redeem_invite_remote(
                            &state,
                            &scheduler,
                            &owner,
                            &channel,
                            &member_name,
                            &key_package,
                            invite_id,
                            invite_secret,
                            std::time::Duration::from_secs(timeout_secs),
                        )
                        .await
                    });
                }
                Cmd::JoinChannel {
                    req_id,
                    channel,
                    visibility,
                    welcome,
                    done,
                } => {
                    let result = {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        join_channel(&mut st, req_id, &channel, visibility, &welcome, &events_tx)
                    };
                    let _ = done.send(result);
                }
                Cmd::SendChannelText {
                    channel,
                    text,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared = prepare_channel_text(&state, &channel, &text, false)?;
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_channel_text(&scheduler, prepared)
                                .await
                                .map(|_| ())
                        }
                    );
                }
                Cmd::SendChannelTextTracked {
                    channel,
                    text,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared = prepare_channel_text(&state, &channel, &text, true)?;
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_channel_text(&scheduler, prepared).await
                        }
                    );
                }
                Cmd::SendChannelPresence {
                    channel,
                    mode,
                    lease_secs,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared =
                                prepare_channel_presence(&state, &channel, mode, lease_secs)?;
                            let ticket = complete.register();
                            drop(prepare);
                            let _ticket = ticket.wait().await;
                            complete_channel_presence(&scheduler, prepared).await
                        }
                    );
                }
                Cmd::SetChannelPresenceOptIn {
                    channel,
                    enabled,
                    done,
                } => {
                    let result = {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        if !st.channels.contains_key(&channel) {
                            Err("no channel".into())
                        } else {
                            let changed = if enabled {
                                st.channel_presence_opt_in.insert(channel.clone())
                            } else {
                                st.channel_presence_opt_in.remove(&channel)
                            };
                            if changed {
                                if !enabled {
                                    clear_channel_presence(&mut st, &channel, &events_tx);
                                }
                                if let Err(error) = persist_current_direct_state(&st) {
                                    if enabled {
                                        st.channel_presence_opt_in.remove(&channel);
                                    }
                                    Err(error)
                                } else {
                                    Ok(())
                                }
                            } else {
                                Ok(())
                            }
                        }
                    };
                    if result.is_ok() && !enabled {
                        let key = CmdKey::Channel(channel.clone());
                        dispatch!(
                            key,
                            done,
                            split | state,
                            scheduler,
                            events_tx,
                            prepare,
                            complete | {
                                let prepared = prepare_channel_presence(
                                    &state,
                                    &channel,
                                    PresenceMode::Invisible,
                                    0,
                                )?;
                                let ticket = complete.register();
                                drop(prepare);
                                let _ticket = ticket.wait().await;
                                complete_channel_presence(&scheduler, prepared)
                                    .await
                                    .map_err(|error| {
                                        format!(
                                            "presence disabled locally; withdrawal failed: {error}"
                                        )
                                    })
                            }
                        );
                    } else {
                        let _ = done.send(result);
                    }
                }
                Cmd::SendChannelDirect {
                    channel,
                    recipient,
                    text,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(
                        key,
                        done,
                        split | state,
                        scheduler,
                        events_tx,
                        prepare,
                        complete | {
                            let prepared =
                                prepare_channel_direct(&state, &channel, recipient, &text)?;
                            let application = gcoms_core::is_piece_application_payload(&text);
                            let ticket = complete.register();
                            drop(prepare);
                            let ticket = ticket.wait().await;
                            let admitted = enqueue_channel_direct(&state, &scheduler, prepared)?;
                            // Preserve admission order, but an independent
                            // piece application's receipt cannot stall the
                            // channel. Text retains its completion ordering.
                            let _ticket = if application {
                                drop(ticket);
                                None
                            } else {
                                Some(ticket)
                            };
                            complete_channel_direct(&state, admitted).await
                        }
                    );
                }
                Cmd::RemoveChannelMember {
                    channel,
                    member_id,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, scheduler, events_tx| {
                        let result = remove_channel_member(
                            &state, &scheduler, &channel, member_id, &events_tx,
                        )
                        .await;
                        if result.is_ok() {
                            if let Some(channel_id) = state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .channels
                                .get(&channel)
                                .map(|channel| channel.id)
                            {
                                let _ = events_tx.send(Ev::ChannelRosterChanged {
                                    channel: channel.clone(),
                                    channel_id,
                                });
                            }
                        }
                        result
                    });
                }
                Cmd::ReplayLastChannel {
                    channel,
                    count,
                    done,
                } => {
                    let key = CmdKey::Channel(channel.clone());
                    dispatch!(key, done, |state, scheduler, events_tx| {
                        replay_last_channel(&state, &scheduler, &channel, count).await
                    });
                }
                #[cfg(feature = "client-persist")]
                Cmd::ExportState { done } => {
                    let result = {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        persist::encode_state(&st)
                    };
                    let _ = done.send(result);
                }
                #[cfg(feature = "client-persist")]
                Cmd::ImportState { data, done } => {
                    dispatch!(CmdKey::Global, done, |state, scheduler, events_tx| {
                        persist::decode_state(&state, &scheduler, &data).await
                    });
                }
                Cmd::CentralOwnershipRequired { done } => {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let _ = done.send(st.application_inbox.central_ownership.is_some());
                }
                Cmd::ConfigureCentralComponentRoutes {
                    policy,
                    primary,
                    done,
                } => {
                    dispatch!(CmdKey::Global, done, |state, scheduler, events_tx| {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        configure_central_routes(&mut st, policy, primary)
                    });
                }
                Cmd::MachineOwnershipRequired { done } => {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let _ = done.send(st.application_inbox.machine_owned);
                }
                Cmd::ConfigureComponentRoutes {
                    policy,
                    binding,
                    done,
                } => {
                    dispatch!(CmdKey::Global, done, |state, scheduler, events_tx| {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        configure_machine_routes(&mut st, policy, binding.as_deref())
                    });
                }
                Cmd::EnableDurableApplications { done } => {
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let result =
                        if cfg!(feature = "client-persist") && st.durable_state_sink.is_some() {
                            st.durable_applications_enabled = true;
                            Ok(())
                        } else {
                            Err("durable applications require persistent client state".into())
                        };
                    let _ = done.send(result);
                }
                Cmd::SubmitLocalComponent { mut body, done } => {
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let result = submit_local_component(&mut st, &body);
                    body.fill(0);
                    let _ = done.send(result);
                }
                Cmd::ApplicationInboxPage { after, limit, done } => {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let result = if !cfg!(feature = "client-persist")
                        || st.durable_state_sink.is_none()
                        || !st.durable_applications_enabled
                    {
                        Err("durable application inbox requires persistent client state".into())
                    } else {
                        st.application_inbox.page(after, limit)
                    };
                    let _ = done.send(result);
                }
                Cmd::ApplicationInboxReceipt {
                    sequence,
                    digest,
                    done,
                } => {
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    let result = if !cfg!(feature = "client-persist")
                        || st.durable_state_sink.is_none()
                        || !st.durable_applications_enabled
                    {
                        Err("durable application inbox requires persistent client state".into())
                    } else {
                        let prior = st.application_inbox.clone();
                        match st.application_inbox.consume(sequence, digest) {
                            Ok(true) => match persist_current_direct_state(&st) {
                                Ok(()) => Ok(()),
                                Err(error) => {
                                    st.application_inbox = prior;
                                    Err(error)
                                }
                            },
                            Ok(false) => Ok(()),
                            Err(error) => Err(error),
                        }
                    };
                    let _ = done.send(result);
                }
                Cmd::PersistState { done } => {
                    let result = {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        persist_current_direct_state(&st)
                    };
                    let _ = done.send(result);
                }
            }
        }
    })
}

/// Machine ownership is distinct from the currently selected registry. Restarts
/// keep signed member-channel state, but never adopt owner/central profiles or
/// reinterpret pending legacy durable application bytes as component work.
pub(super) fn configure_machine_routes(
    st: &mut NodeState,
    policy: gcoms_core::component::RoutingPolicy,
    binding: Option<&dyn ComponentAuthority>,
) -> Result<(), String> {
    if policy.components.is_empty()
        || policy.components.len() > 64
        || policy.components.contains(&[0; 16])
    {
        return Err("invalid component routing policy".into());
    }
    if !cfg!(feature = "client-persist")
        || st.durable_state_sink.is_none()
        || st.application_inbox.central_ownership.is_some()
        || st.application_inbox.local_routing_policy.is_some()
        || st.application_inbox.routing_policy.is_some()
    {
        return Err("machine routes require persistent unconfigured non-central state".into());
    }
    let witnessed = if let Some(authority) = binding {
        authority.verify(&st.info.identity_pk, &policy, now_unix())?;
        true
    } else {
        false
    };
    let retained = st.application_inbox.machine_owned || witnessed;
    if st
        .channels
        .values()
        .any(|channel| matches!(channel.role, crate::channel::ChannelRole::Owner(_)))
        || (!retained && !st.channels.is_empty())
        || st
            .application_inbox
            .entries
            .iter()
            .any(|entry| gcoms_core::component::RoutedApplication::decode(&entry.body).is_err())
        || st.pending_1to1.values().any(|pending| {
            !pending.logical_record.as_deref().is_some_and(|record| {
                machine_record_compatible(record)
                    || (retained
                        && matches!(
                            crate::proto::decode_direct_record(record),
                            Some(crate::proto::DirectRecord::Data { durable: false, .. })
                        ))
            })
        })
    {
        return Err("machine scope requires authenticated member ownership and compatible retained inbox and outbox".into());
    }
    let previous = st.application_inbox.machine_owned;
    st.application_inbox.machine_owned = true;
    if let Err(error) = persist_current_direct_state(st) {
        st.application_inbox.machine_owned = previous;
        return Err(error);
    }
    st.application_inbox.routing_policy = Some(policy);
    Ok(())
}

/// Derive the authenticated peer from this daemon, never from request bytes.
pub(super) fn configure_central_routes(
    st: &mut NodeState,
    policy: gcoms_core::component::RoutingPolicy,
    primary: Vec<[u8; 16]>,
) -> Result<(), String> {
    if !cfg!(feature = "client-persist")
        || st.durable_state_sink.is_none()
        || st.application_inbox.machine_owned
        || st.application_inbox.routing_policy.is_some()
        || st.application_inbox.local_routing_policy.is_some()
    {
        return Err("central routes require persistent unconfigured non-machine state".into());
    }
    let ownership = application_inbox::CentralOwnership::for_policy(&policy, primary)?;
    if st
        .application_inbox
        .central_ownership
        .as_ref()
        .is_some_and(|prior| prior != &ownership)
    {
        return Err("retained central ownership or policy differs".into());
    }
    let prior = st.application_inbox.central_ownership.replace(ownership);
    if let Err(error) = persist_current_direct_state(st) {
        st.application_inbox.central_ownership = prior;
        return Err(error);
    }
    st.application_inbox.local_routing_policy = Some(policy);
    Ok(())
}

pub(super) fn submit_local_component(st: &mut NodeState, body: &[u8]) -> Result<(), String> {
    if !cfg!(feature = "client-persist")
        || st.durable_state_sink.is_none()
        || !st.durable_applications_enabled
        || gcoms_core::is_volatile_application_payload(body)
    {
        return Err("local component delivery requires durable machine state".into());
    }
    let route = gcoms_core::component::RoutedApplication::decode(body)?;
    let policy = st
        .application_inbox
        .local_routing_policy
        .as_ref()
        .or(st.application_inbox.routing_policy.as_ref())
        .ok_or("local component delivery requires explicit component routes")?;
    let peer = st.info.identity_pk.clone();
    let (kind, _) = gcoms_core::component::application_parts(&route.application)
        .ok_or("invalid local component application")?;
    if !policy.components.contains(&route.source)
        || !policy.components.contains(&route.destination)
        || !policy.permits(&peer, body)
        || !policy.routes.iter().any(|r| {
            r.local == route.source
                && r.remote == route.destination
                && r.peer_identity == peer
                && r.content_types.iter().any(|k| k == kind)
        })
    {
        return Err("unregistered local component route".into());
    }
    let prior = st.application_inbox.clone();
    st.application_inbox
        .stage(&peer, fresh_msg_id(), now_unix(), body)?;
    if let Err(error) = persist_current_direct_state(st) {
        st.application_inbox = prior;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod machine_migration_tests {
    use super::machine_record_compatible;
    #[test]
    fn migration_retains_transport_control_but_requires_routed_application_work() {
        assert!(machine_record_compatible(&crate::proto::encode_direct_ack(
            [1; 16], false
        )));
        assert!(!machine_record_compatible(
            &crate::proto::encode_direct_durable_data([1; 16], 1, b"legacy")
        ));
        assert!(!machine_record_compatible(b"corrupt"));
        let route = gcoms_core::component::RoutedApplication {
            source: [1; 16],
            destination: [2; 16],
            application: b"GCAPP1\0\x04testpayload".to_vec(),
        }
        .encode()
        .unwrap();
        assert!(machine_record_compatible(
            &crate::proto::encode_direct_durable_data([1; 16], 1, &route)
        ));
    }

    #[tokio::test]
    async fn completion_chain_orders_successors_and_releases_on_cancellation() {
        let serializer = super::KeyedSerializer::default();
        let locks = serializer.locks_for(&super::CmdKey::Peer(vec![7]));
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // Command 1 and command 2 register in preparation order; command 2 must
        // not pass while command 1's completion ticket is alive.
        let first = locks.completion.register();
        let second = locks.completion.register();
        let waiter = tokio::spawn({
            let order = order.clone();
            async move {
                let ticket = second.wait().await;
                order.lock().unwrap().push(2);
                drop(ticket);
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(order.lock().unwrap().is_empty());
        // Cancellation (or normal completion) drops the ticket and releases the
        // successor.
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*order.lock().unwrap(), vec![2]);
    }
}
