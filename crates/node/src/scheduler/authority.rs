//! Refresh only the lifetime of an already known, owner-renewed inbox. The
//! pinned relay must prove that the exact queue/epoch/push capability is still
//! active. This is not discovery, renewal, or permission to replay an expired
//! forwarded envelope.
use super::*;

#[derive(Clone)]
pub(super) struct VerifiedAuthority {
    contact: AliasContact,
    expiry: u64,
}

struct Cached {
    contact: AliasContact,
    proof: Option<VerifiedAuthority>,
    retry_after: tokio::time::Instant,
    failures: u32,
}

/// One entry per bounded scheduler lane, including negative results. Holding
/// this lock coalesces concurrent stale sends; it never locks the job queue.
#[derive(Default)]
pub(super) struct Memo(tokio::sync::Mutex<Option<Cached>>);

fn same_binding(a: &AliasContact, b: &AliasContact) -> bool {
    a.target == b.target
        && a.queue_id == b.queue_id
        && a.epoch == b.epoch
        && a.push_cap == b.push_cap
}

pub(super) fn contact(semantic: &SemanticJob) -> Option<&AliasContact> {
    match semantic {
        SemanticJob::Push { contact, .. } => Some(contact),
        SemanticJob::Frwd { destination, .. } => Some(destination),
        // Owner subscriptions use admin renewal. Intermediaries cannot refresh
        // authority on another sender's already authenticated envelope.
        _ => None,
    }
}

pub(super) fn apply(
    mut semantic: SemanticJob,
    proof: Option<VerifiedAuthority>,
) -> Result<SemanticJob, String> {
    if let Some(proof) = proof {
        let destination = match &mut semantic {
            SemanticJob::Push { contact, .. } => contact,
            SemanticJob::Frwd { destination, .. } => destination,
            _ => return Err("lease proof cannot authorize this operation".into()),
        };
        if !same_binding(destination, &proof.contact) {
            return Err("lease proof changed its destination binding".into());
        }
        ensure_live_authority(proof.expiry)?;
        // This affects only this locally prepared hop. The signed directory
        // route and the application message/expiry are not rewritten.
        destination.expiry = proof.expiry;
    }
    Ok(semantic)
}

impl Memo {
    pub(super) fn backing_off(&self, contact: &AliasContact) -> bool {
        self.0.try_lock().is_ok_and(|cached| {
            cached.as_ref().is_some_and(|entry| {
                same_binding(&entry.contact, contact)
                    && entry.failures > 0
                    && entry.retry_after > tokio::time::Instant::now()
            })
        })
    }

    #[cfg(feature = "experimental-gc2")]
    pub(super) async fn observe(&self, contact: Option<&AliasContact>, result: &JobResult) {
        let Some(contact) = contact else { return };
        let mut cached = self.0.lock().await;
        if let JobResult::Failed(error) = result {
            let error = error.to_ascii_lowercase();
            if !(error.contains("overloaded")
                || error.contains("refused")
                || error.contains("no permits"))
            {
                return;
            }
            let old = cached
                .as_ref()
                .filter(|entry| same_binding(&entry.contact, contact));
            let failures = old.map_or(1, |entry| entry.failures.saturating_add(1));
            let proof = old.and_then(|entry| entry.proof.clone());
            *cached = Some(Cached {
                contact: contact.clone(),
                proof,
                failures,
                retry_after: tokio::time::Instant::now()
                    + retry_delay(failures, &mut rand::thread_rng()),
            });
        } else if matches!(result, JobResult::HopAccepted(_)) {
            if let Some(entry) = cached
                .as_mut()
                .filter(|entry| same_binding(&entry.contact, contact))
            {
                entry.failures = 0;
                entry.retry_after = tokio::time::Instant::now();
            }
        }
    }

    pub(super) async fn resolve(
        &self,
        client: &Tp1Client,
        contact: Option<&AliasContact>,
        natural: bool,
    ) -> Result<Option<VerifiedAuthority>, String> {
        let Some(contact) = contact else {
            return Ok(None);
        };
        if natural && self.backing_off(contact) {
            return Err("relay contact is backing off".into());
        }
        if contact.expiry > now_unix() {
            return Ok(None);
        }
        let mut cached = self.0.lock().await;
        if let Some(entry) = cached
            .as_ref()
            .filter(|entry| same_binding(&entry.contact, contact))
        {
            if entry.failures > 0 && entry.retry_after > tokio::time::Instant::now() {
                return Err("relay authority refresh is backing off".into());
            }
            if let Some(proof) = entry.proof.as_ref().filter(|p| p.expiry > now_unix()) {
                return Ok(Some(proof.clone()));
            }
            if entry.retry_after > tokio::time::Instant::now() {
                return Err("relay authority refresh is backing off".into());
            }
        }
        let failures = cached
            .as_ref()
            .filter(|entry| same_binding(&entry.contact, contact))
            .map_or(0, |entry| entry.failures);
        let result = tokio::time::timeout(Duration::from_secs(60), query(client, contact, natural))
            .await
            .map_err(|_| "relay authority refresh timed out".to_string())
            .and_then(|result| result);
        let failures = if result.is_ok() {
            0
        } else {
            failures.saturating_add(1)
        };
        *cached = Some(Cached {
            contact: contact.clone(),
            proof: result.as_ref().ok().cloned(),
            retry_after: tokio::time::Instant::now()
                + retry_delay(failures, &mut rand::thread_rng()),
            failures,
        });
        result.map(Some)
    }
}

fn retry_delay(failures: u32, rng: &mut impl Rng) -> Duration {
    let base = 5_000u64
        .saturating_mul(1 << failures.saturating_sub(1).min(4))
        .min(60_000);
    Duration::from_millis(rng.gen_range(base..=base.saturating_add(base / 5).min(60_000)))
}

#[cfg(feature = "experimental-gc2")]
fn observe_probe(contact: &AliasContact, outcome: &str, status: Option<u16>) {
    let expired_by_seconds = now_unix().saturating_sub(contact.expiry);
    crate::metrics::log_event(
        "gc2_authority_probe",
        &[
            ("outcome", outcome.into()),
            ("expired_by_seconds", expired_by_seconds.to_string()),
            (
                "status",
                status.map_or_else(String::new, |code| code.to_string()),
            ),
        ],
    );
    // Routing identifiers stay out of aggregate metrics. Explicit local debug
    // opt-in permits only the public relay address, never queue/capability data.
    if std::env::var("GCOMS_PRIVATE_ROUTE_DIAGNOSTICS").as_deref() == Ok("1") {
        eprintln!(
            "{}",
            serde_json::json!({
                "event": "gc2_authority_probe_diagnostic",
                "relay_address": contact.target.address.to_string(),
                "outcome": outcome,
                "status": status,
                "expired_by_seconds": expired_by_seconds,
            })
        );
    }
}

// A cover deposit carries no application message. The existing relay accepts
// it only after checking the exact queue, epoch, current capability and that
// its expiry is no later than the owner's live lease. The pinned TLS response
// therefore proves authority through that short expiry; no relay wire change,
// lease extension, directory rewrite or application delivery is involved.
async fn query(
    client: &Tp1Client,
    contact: &AliasContact,
    natural: bool,
) -> Result<VerifiedAuthority, String> {
    let mut admitted_expiry = None;
    #[cfg(feature = "experimental-gc2")]
    if natural {
        use gcoms_protocol::relay::gc2::Push;
        use gcoms_transport::gc2::{NaturalOutcome, NaturalRoute};
        let token = crate::gc2::queue_token(&contact.queue_id);
        let outcome = client
            .post_natural_prepared(
                NaturalRoute {
                    addr: contact.target.address,
                    service_id: contact.target.relay_service_id,
                    token: &token,
                    excluded: &[],
                    class: TrafficClass::Interactive,
                },
                || {
                    let expiry = now_unix().saturating_add(60);
                    let probe = Push {
                        class: TrafficClass::Interactive,
                        queue_id: contact.queue_id,
                        epoch: contact.epoch,
                        nonce: random_nonzero_with(&mut rand::rngs::OsRng),
                        expiry,
                        msg: None,
                    }
                    .encode(&contact.push_cap, &contact.target.relay_service_id)?;
                    admitted_expiry = Some(expiry);
                    Ok(probe)
                },
            )
            .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                observe_probe(contact, "transport_error", None);
                return Err(error.to_string());
            }
        };
        let (kind, status) = match &outcome {
            NaturalOutcome::Accepted(None) => ("accepted", None),
            NaturalOutcome::Accepted(Some(_)) => ("unexpected_body", None),
            NaturalOutcome::Conflict => ("conflict", None),
            NaturalOutcome::Overloaded => ("overloaded", None),
            NaturalOutcome::Internal => ("internal", None),
            NaturalOutcome::Decoy(code) => ("decoy", Some(*code)),
        };
        observe_probe(contact, kind, status);
        if !matches!(outcome, NaturalOutcome::Accepted(None)) {
            return Err("relay refused the GC/2 authority probe".into());
        }
        return verified(contact, admitted_expiry);
    }
    let _ = natural;
    let outcome = client
        .post_cell_prepared(
            contact.target.address,
            contact.target.relay_service_id,
            &gcoms_transport::encode_b64url(&contact.queue_id),
            &[],
            TrafficClass::Interactive,
            || {
                let expiry = now_unix().saturating_add(60);
                let probe = RelayPush {
                    queue_id: contact.queue_id,
                    epoch: contact.epoch,
                    push_nonce: random_nonzero_with(&mut rand::rngs::OsRng),
                    push_expiry: expiry,
                    msg: None,
                }
                .encode_into_cell(&contact.push_cap, &contact.target.relay_service_id)?;
                admitted_expiry = Some(expiry);
                Ok(bytes::Bytes::from(probe.encode_wire()?))
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    if outcome.into_accepted()?.is_some() {
        return Err("relay returned an unexpected authority probe response".into());
    }
    verified(contact, admitted_expiry)
}

fn verified(contact: &AliasContact, expiry: Option<u64>) -> Result<VerifiedAuthority, String> {
    let expiry = expiry.ok_or("authority probe was not admitted")?;
    ensure_live_authority(expiry)?;
    Ok(VerifiedAuthority {
        contact: contact.clone(),
        expiry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_backoff_is_jittered_bounded_and_resets_after_success() {
        let mut rng = StdRng::seed_from_u64(1);
        for failure in 1..=100 {
            let delay = retry_delay(failure, &mut rng);
            assert!((Duration::from_secs(5)..=Duration::from_secs(60)).contains(&delay));
            if failure >= 5 {
                assert_eq!(delay, Duration::from_secs(60));
            }
        }
        assert!(retry_delay(0, &mut rng) <= Duration::from_secs(6));
        assert!(retry_delay(2, &mut rng) >= Duration::from_secs(10));
    }
    #[cfg(feature = "experimental-gc2")]
    #[tokio::test]
    async fn overload_blocks_live_authority_but_not_an_alternate_and_success_clears_it() {
        let memo = Memo::default();
        let contact = AliasContact {
            target: RelayTarget {
                address: "192.0.2.1:4433".parse().unwrap(),
                relay_service_id: [1; 32],
            },
            queue_id: [2; 32],
            epoch: 1,
            push_cap: [3; 32],
            expiry: now_unix() + 3600,
        };
        memo.observe(
            Some(&contact),
            &JobResult::Failed("GC/2 relay overloaded".into()),
        )
        .await;
        assert!(memo.backing_off(&contact));
        assert!(memo
            .resolve(&Tp1Client::new().unwrap(), Some(&contact), true)
            .await
            .err()
            .unwrap()
            .contains("backing off"));
        let mut alternate = contact.clone();
        alternate.target.address = "192.0.2.2:4433".parse().unwrap();
        assert!(!memo.backing_off(&alternate));
        memo.observe(Some(&contact), &JobResult::HopAccepted(bytes::Bytes::new()))
            .await;
        assert!(!memo.backing_off(&contact));
        memo.observe(
            Some(&contact),
            &JobResult::Failed("connection timed out".into()),
        )
        .await;
        assert!(
            !memo.backing_off(&contact),
            "uncertain outcomes must not trigger alternate-alias replay"
        );
    }
}
