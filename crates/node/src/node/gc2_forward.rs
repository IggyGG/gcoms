//! Authenticated natural forwarding, composed under the terminal role gate.
use super::*;
use gcoms_core::gc2::{NaturalCell, MAX_CELL};
use gcoms_protocol::relay::gc2::Forward;
use gcoms_transport::{
    gc2::status_cell,
    server::{AcceptedDuplex, DuplexHandler},
    HopReply,
};

pub(crate) fn handler(
    authorities: Arc<Mutex<ProvisionAuthorities>>,
    scheduler: RelayScheduler,
    service: [u8; 32],
    policy: FrwdTargetPolicy,
    slots: Arc<super::gc2_admission::Pool>,
) -> DuplexHandler {
    type Completion = Arc<tokio::sync::watch::Sender<Option<HopReply>>>;
    let pending = Arc::new(Mutex::new(HashMap::<[u8; 32], Completion>::new()));
    Arc::new(move |path| {
        let token = path.strip_prefix("gc2/")?.to_owned();
        authorities
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .lookup_frwd(&token, now_unix())?;
        let authorities = authorities.clone();
        let scheduler = scheduler.clone();
        let policy = policy.clone();
        let slots = slots.clone();
        let pending = pending.clone();
        let accepted: AcceptedDuplex = Box::new(move |mut body, mut respond| {
            Box::pin(async move {
                let result =
                    async {
                        let bytes = gcoms_transport::server::read_body(&mut body, MAX_CELL)
                            .await
                            .ok()?;
                        let cell = NaturalCell::decode(&bytes).ok()?;
                        let now = now_unix();
                        let key = authorities
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .lookup_frwd(&token, now)?;
                        let forward = Forward::decode(&cell, &key, &service, now, &policy).ok()?;
                        {
                            let guard = authorities.lock().unwrap_or_else(|p| p.into_inner());
                            if !guard.permits_gc2_frwd(&token, &key, &forward, now) {
                                return None;
                            }
                            if guard.transit_ready.as_ref().is_some_and(|ready| {
                                !ready.load(std::sync::atomic::Ordering::Acquire)
                            }) {
                                slots.refused("readiness", "transit_not_ready");
                                return Some(HopReply::Overloaded);
                            }
                        }
                        if forward.push.is_none() {
                            return Some(HopReply::Accepted);
                        }
                        let permit = match slots.acquire(forward.class).await {
                            Ok(permit) => permit,
                            Err(reason) => {
                                slots.refused("capacity", reason);
                                return Some(HopReply::Overloaded);
                            }
                        };
                        // Retried forwarding nonces may differ, but the exact
                        // authenticated destination envelope identifies one job.
                        let mut hash = Sha256::new();
                        hash.update(forward.target.relay_service_id);
                        hash.update(forward.target.address.to_string().as_bytes());
                        hash.update(forward.push.as_ref()?.as_cell().encode());
                        let attempt: [u8; 32] = hash.finalize().into();
                        let (completion, fresh) = {
                            let mut pending = pending.lock().unwrap_or_else(|p| p.into_inner());
                            match pending.entry(attempt) {
                                std::collections::hash_map::Entry::Occupied(entry) => {
                                    (entry.get().clone(), false)
                                }
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    let (sender, _) = tokio::sync::watch::channel(None);
                                    let completion = Arc::new(sender);
                                    entry.insert(completion.clone());
                                    (completion, true)
                                }
                            }
                        };
                        let mut result = completion.subscribe();
                        if fresh {
                            tokio::spawn(async move {
                                // An incoming disconnect must not discard an
                                // admitted operation's completion or identity.
                                let _permit = permit;
                                let outcome = async {
                                    let receipt = match scheduler.forward_gc2_wait(forward).await {
                                        Ok(receipt) => receipt,
                                        Err(error) => {
                                            slots.refused(
                                                "scheduler",
                                                match error {
                                                    EnqueueError::Full => "full",
                                                    EnqueueError::Pending => "pending",
                                                    EnqueueError::Shutdown => "shutdown",
                                                    EnqueueError::InvalidCell => "invalid_cell",
                                                },
                                            );
                                            return match error {
                                                EnqueueError::Full | EnqueueError::Pending => {
                                                    HopReply::Overloaded
                                                }
                                                _ => HopReply::Internal,
                                            };
                                        }
                                    };
                                    {
                                        let mut guard =
                                            authorities.lock().unwrap_or_else(|p| p.into_inner());
                                        guard.note_frwd_admitted(&token, &key, now);
                                        guard
                                            .admitted
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    match receipt.completion().await.accepted() {
                                        Ok(_) => {
                                            crate::metrics::log_event("gc2_forward_accepted", &[]);
                                            HopReply::Accepted
                                        }
                                        Err(error) => {
                                            slots.refused("last_hop", failure_class(&error));
                                            failure_reply(&error)
                                        }
                                    }
                                }
                                .await;
                                completion.send_replace(Some(outcome));
                                pending
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .remove(&attempt);
                            });
                        } else {
                            drop(permit);
                        }
                        loop {
                            if let Some(outcome) = *result.borrow_and_update() {
                                return Some(outcome);
                            }
                            if result.changed().await.is_err() {
                                return Some(HopReply::Overloaded);
                            }
                        }
                    }
                    .await;
                if let Some(result) = result {
                    reply(&mut respond, result);
                } else if let Ok(mut send) =
                    respond.send_response(gcoms_transport::decoy::decoy_response(404), false)
                {
                    let _ = send.send_data(gcoms_transport::decoy::decoy_body(404), true);
                }
            })
        });
        Some(accepted)
    })
}

fn reply(respond: &mut h2::server::SendResponse<bytes::Bytes>, result: HopReply) {
    if let Ok(mut send) = respond.send_response(http::Response::new(()), false) {
        let _ = send.send_data(bytes::Bytes::from(status_cell(result).encode()), true);
    }
}

// Only fixed diagnostic labels leave this boundary. Transport errors can carry
// remote identifiers, so never record their raw text, tokens, or payloads.
fn failure_class(error: &str) -> &'static str {
    if error.contains("expired") {
        "expired"
    } else if error.contains("overloaded") {
        "overloaded"
    } else if error.contains("denied")
        || error.contains("unauthorized")
        || error.contains("refused")
    {
        "refused"
    } else if error.contains("no ready") {
        "no_ready_route"
    } else if error.contains("deadline") || error.contains("timed out") || error.contains("timeout")
    {
        "timeout"
    } else if error.contains("closed") {
        "closed"
    } else if error.contains("shutdown") || error.contains("shut down") {
        "shutdown"
    } else {
        "transport_failure"
    }
}

fn failure_reply(error: &str) -> HopReply {
    let error = error.to_ascii_lowercase();
    if error.contains("overloaded")
        || error.contains("no permits")
        || error.contains("refused")
        || error.contains("backing off")
    {
        HopReply::Overloaded
    } else {
        // An uncertain last-hop result must not invite immediate alias replay.
        // Internal already exists on the wire; no reply schema changes.
        HopReply::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_last_hop_is_not_reported_as_capacity() {
        assert_eq!(failure_reply("GC/2 relay overloaded"), HopReply::Overloaded);
        assert_eq!(
            failure_reply("GC/2 relay refused: 403"),
            HopReply::Overloaded
        );
        for error in [
            "hop reply timed out",
            "connection closed",
            "scheduler shut down",
            "unexpected response",
        ] {
            assert_eq!(failure_reply(error), HopReply::Internal);
        }
    }
}
