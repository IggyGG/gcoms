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
    pub(super) async fn resolve(
        &self,
        client: &Tp1Client,
        contact: Option<&AliasContact>,
        natural: bool,
    ) -> Result<Option<VerifiedAuthority>, String> {
        let Some(contact) = contact.filter(|c| c.expiry <= now_unix()) else {
            return Ok(None);
        };
        let mut cached = self.0.lock().await;
        if let Some(entry) = cached
            .as_ref()
            .filter(|entry| same_binding(&entry.contact, contact))
        {
            if let Some(proof) = entry.proof.as_ref().filter(|p| p.expiry > now_unix()) {
                return Ok(Some(proof.clone()));
            }
            if entry.retry_after > tokio::time::Instant::now() {
                return Err("relay authority refresh is backing off".into());
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(60), query(client, contact, natural))
            .await
            .map_err(|_| "relay authority refresh timed out".to_string())
            .and_then(|result| result);
        *cached = Some(Cached {
            contact: contact.clone(),
            proof: result.as_ref().ok().cloned(),
            retry_after: tokio::time::Instant::now() + Duration::from_secs(5),
        });
        result.map(Some)
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
            .await
            .map_err(|e| e.to_string())?;
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
