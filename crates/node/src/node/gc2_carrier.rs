//! Natural-carrier delivery and reception for a GC/2-selected node.
//!
//! The natural carrier replaces the legacy relay push for this profile: a
//! session frame travels as the payload of an authenticated GC/2 deposit to the
//! peer's terminal queue, and the peer drains its own queues through natural
//! subscriptions. The legacy carrier stays available for peers and sessions
//! that did not migrate; this module never converts between the two formats.
#![cfg(feature = "experimental-gc2")]

use super::*;
use futures_util::StreamExt;
use gcoms_protocol::alias::AliasContact;
use gcoms_protocol::relay::gc2::{Push, Subscription};
use gcoms_transport::client::gc2::{NaturalOutcome, NaturalRoute, NaturalStream};
use gcoms_transport::Tp1Client;

/// Longest deposit lifetime; the alias expiry still bounds it.
const MAX_DEPOSIT_LIFETIME_SECS: u64 = 120;
const SUBSCRIPTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60);

/// Deposit one exact session frame to the peer's natural terminal queue.
pub(crate) async fn deliver(
    client: &Tp1Client,
    contact: &AliasContact,
    class: gcoms_core::TrafficClass,
    payload: &[u8],
) -> Result<(), String> {
    let msg = gcoms_core::gc2::NaturalCell::new(gcoms_core::CellType::Msg, 0, payload.to_vec())
        .map_err(|_| "GC/2 terminal payload exceeds the cell bound".to_string())?;
    let now = now_unix();
    let push = Push {
        class,
        queue_id: contact.queue_id,
        epoch: contact.epoch,
        nonce: rand::random(),
        expiry: contact
            .expiry
            .min(now.saturating_add(MAX_DEPOSIT_LIFETIME_SECS)),
        msg: Some(msg),
    };
    let cell = push
        .encode(&contact.push_cap, &contact.target.relay_service_id)
        .map_err(|error| error.to_string())?;
    let token = crate::gc2::queue_token(&contact.queue_id);
    let route = NaturalRoute {
        addr: contact.target.address,
        service_id: contact.target.relay_service_id,
        token: &token,
        excluded: &[],
        class,
    };
    match client
        .post_natural_prepared(route, || Ok(cell))
        .await
        .map_err(|error| error.to_string())?
    {
        NaturalOutcome::Accepted(_) => Ok(()),
        other => Err(format!("GC/2 terminal deposit refused: {other:?}")),
    }
}

/// Deliver every cell of one prepared direct delivery through the natural
/// terminal. Exact bytes are preserved for retries by the caller's outbox.
pub(crate) async fn deliver_all(
    client: &Tp1Client,
    delivery: &DirectDelivery,
    class: gcoms_core::TrafficClass,
) -> Result<(), String> {
    let contact = delivery
        .peer
        .primary()
        .ok_or("peer has no public alias")?
        .clone();
    for cell in &delivery.cells {
        deliver(client, &contact, class, &cell.payload).await?;
    }
    Ok(())
}

/// Owns one natural subscription per receiving alias and class. Each MSG
/// payload is the sender's exact session frame; it is wrapped in the same inner
/// cell shape the legacy pump produces so both carriers share one decoder.
pub(crate) fn spawn_subscriptions(
    state: Arc<Mutex<NodeState>>,
    events: broadcast::Sender<Ev>,
) -> super::api::ShutdownTask {
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut subscriptions = futures_util::stream::FuturesUnordered::new();
        let mut active = std::collections::HashSet::new();
        let mut clock = tokio::time::interval(std::time::Duration::from_millis(200));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                Some(key) = subscriptions.next(), if !subscriptions.is_empty() => {
                    active.remove(&key);
                    continue;
                },
                _ = clock.tick() => {},
            }
            let (aliases, client, peers) = {
                let st = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if st.owner_transition_failed {
                    break;
                }
                if super::routing::recovering(&st) {
                    (Vec::new(), None, Vec::new())
                } else {
                    let client = natural_route_client(&st);
                    let aliases = st
                        .client_relay
                        .aliases
                        .iter()
                        .filter(|alias| owner_alias_receiving(&st, alias))
                        .cloned()
                        .collect::<Vec<_>>();
                    let peers = st
                        .peer_routes
                        .values()
                        .filter_map(|info| {
                            info.primary()
                                .map(|alias| (alias.target.address, alias.target.relay_service_id))
                        })
                        .collect::<Vec<_>>();
                    (aliases, client, peers)
                }
            };
            let Some(client) = client else { continue };
            // Keep protected circuits to established peers warm: idle periods
            // then carry the same class-channel schedule as active ones, and
            // the next delivery reuses an established circuit instead of
            // paying a fresh entry->middle->terminal setup. A hanging connect
            // must never stall subscriptions.
            for (addr, pin) in peers {
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(5), client.warm(addr, pin))
                        .await;
            }
            for alias in aliases {
                for class in [
                    gcoms_core::TrafficClass::Interactive,
                    gcoms_core::TrafficClass::Bulk,
                ] {
                    let key = (alias.contact.queue_id, class as u8);
                    if !active.insert(key) {
                        continue;
                    }
                    let alias = alias.clone();
                    let state = state.clone();
                    let client = client.clone();
                    let events = events.clone();
                    subscriptions.push(async move {
                        if !owner_alias_receiving(
                            &state.lock().unwrap_or_else(|p| p.into_inner()),
                            &alias,
                        ) {
                            return key;
                        }
                        let subscription = Subscription {
                            class,
                            queue_id: alias.contact.queue_id,
                            epoch: alias.contact.epoch,
                            expiry: alias.contact.expiry,
                            nonce: rand::random(),
                        };
                        let Ok(cell) = subscription.encode(
                            &alias.capabilities.sub,
                            &alias.contact.target.relay_service_id,
                        ) else {
                            return key;
                        };
                        let token = crate::gc2::queue_token(&alias.contact.queue_id);
                        let opened = client
                            .open_natural_prepared(
                                NaturalRoute {
                                    addr: alias.contact.target.address,
                                    service_id: alias.contact.target.relay_service_id,
                                    token: &token,
                                    excluded: &[],
                                    class,
                                },
                                tokio::time::Instant::now() + SUBSCRIPTION_LIFETIME,
                                || Ok(cell),
                            )
                            .await;
                        match opened {
                            Ok(stream) => {
                                drain(stream, &state, &alias, &events, alias.contact.queue_id)
                                    .await;
                            }
                            Err(error) => {
                                metrics::log_event("natural_sub_error", &[("e", error.to_string())])
                            }
                        }
                        key
                    });
                }
            }
        }
        subscriptions.clear();
    });
    super::api::ShutdownTask { stop, task }
}

async fn drain(
    mut stream: NaturalStream,
    state: &Arc<Mutex<NodeState>>,
    alias: &OwnedAlias,
    events: &broadcast::Sender<Ev>,
    queue_id: [u8; 32],
) {
    if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), alias) {
        return;
    }
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .subscribed_contact_aliases
        .insert(queue_id);
    metrics::log_event("natural_sub_connected", &[]);
    while let Some(value) = stream.recv().await {
        let Ok(cell) = value else { break };
        if !owner_alias_receiving(&state.lock().unwrap_or_else(|p| p.into_inner()), alias) {
            break;
        }
        let payload = cell.payload().to_vec();
        handle_incoming(state, Cell::new(CellType::Msg, 0, 0, payload), events);
    }
    super::routing::owner_unavailable(&state.lock().unwrap_or_else(|p| p.into_inner()), alias);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_expiry_never_exceeds_the_alias_lifetime() {
        // The clamp is arithmetic only; the relay re-checks liveness.
        let now = 1_000u64;
        let contact_expiry = 1_050u64;
        let clamped = contact_expiry.min(now.saturating_add(MAX_DEPOSIT_LIFETIME_SECS));
        assert_eq!(clamped, 1_050);
    }
}
