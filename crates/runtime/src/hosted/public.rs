use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use gcoms_mls::hosted::*;
use gcoms_sdk::{hosted as wire, GcClient};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(super) fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
pub(super) fn decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > wire::MAX_HTTP_BYTES {
        return Err("hosted wire exceeds bound".into());
    }
    B64.decode(value).map_err(|_| "invalid hosted wire".into())
}
pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(super) fn query_hash(query: wire::ReadQuery) -> [u8; 32] {
    Sha256::digest(query.authentication_bytes()).into()
}

#[async_trait]
pub(super) trait Transport: Send + Sync {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String>;
}
pub(super) struct Routed {
    pub client: Arc<dyn GcClient>,
    pub endpoint: String,
}
#[async_trait]
impl Transport for Routed {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        self.client
            .hosted_request(
                &self.endpoint,
                wire::Request {
                    version: wire::VERSION,
                    channel,
                    operation,
                },
            )
            .await
            .map_err(|error| error.to_string())
    }
}

pub(super) enum SnapshotAuthority<'a> {
    Joining(&'a PreparedHostedJoin),
    Code(&'a HostedAccessCode),
}
impl SnapshotAuthority<'_> {
    fn proof(&self, channel: [u8; 32], query: wire::ReadQuery) -> Result<String, String> {
        let hash = query_hash(query);
        let proof = match self {
            Self::Joining(prepared) => prepared.read_proof(channel, hash, now() + 120),
            Self::Code(code) => code.read_proof(channel, hash, now() + 120),
        }
        .map_err(|e| e.to_string())?;
        Ok(encode(&proof.encode().map_err(|e| e.to_string())?))
    }
}

/// Replay public membership and policy from pinned owner genesis. Never trust a
/// service's current rules or a bare GroupInfo as authoritative channel state.
pub(super) async fn snapshot(
    transport: &dyn Transport,
    channel: [u8; 32],
    authority: SnapshotAuthority<'_>,
) -> Result<(HostedObserver, wire::Head), String> {
    let mut after = 0;
    let mut head: Option<wire::Head> = None;
    let mut observer: Option<HostedObserver> = None;
    let mut previous_time = 0;
    loop {
        let query = wire::ReadQuery {
            after,
            through: head.as_ref().map(|h| h.sequence),
            limit: wire::MAX_PAGE_RECORDS,
        };
        // A join has no admitted local channel worker yet. Retry this read-only
        // page across transient circuit failures using the same prepared leaf
        // and pinned transcript head; no membership write is retried here.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut retries = 0;
        let response = loop {
            let result = tokio::time::timeout_at(
                deadline,
                transport.exchange(
                    channel,
                    wire::Operation::Snapshot {
                        query,
                        proof: authority.proof(channel, query)?,
                    },
                ),
            )
            .await
            .map_err(|_| "hosted snapshot read deadline elapsed")?;
            match result {
                Ok(reply) => break reply,
                Err(_) if retries < 3 => {
                    retries += 1;
                    tokio::time::sleep_until(deadline.min(
                        tokio::time::Instant::now()
                            + std::time::Duration::from_millis(100 * retries),
                    ))
                    .await;
                }
                Err(error) => return Err(error),
            }
        };
        let wire::Reply::Snapshot(page) = response else {
            return Err(format!("hosted snapshot refused: {response:?}"));
        };
        if page.after != after
            || page.next < after
            || page.next > page.head.sequence
            || (page.next == after && after != page.head.sequence)
            || page.next - after > u64::from(wire::MAX_PAGE_RECORDS)
            || head
                .as_ref()
                .is_some_and(|h| h.sequence != page.head.sequence || h.hash != page.head.hash)
            || page.head.sequence > 1_000_000
        {
            return Err("inconsistent hosted snapshot pagination".into());
        }
        if observer.is_none() {
            let policy = HostedPolicy::decode(
                &decode(page.policy.as_deref().ok_or("missing genesis policy")?)?,
                channel,
            )
            .map_err(|e| e.to_string())?;
            let genesis = decode(page.genesis.as_deref().ok_or("missing genesis tree")?)?;
            if page.head.sequence == 0
                && gcoms_channel_service::genesis_hash(&policy, &genesis)
                    .map_err(|e| e.to_string())?
                    != page.head.hash
            {
                return Err("genesis anchor mismatch".into());
            }
            observer =
                Some(HostedObserver::new(policy, channel, &genesis).map_err(|e| e.to_string())?);
        } else if page.policy.is_some() || page.genesis.is_some() {
            return Err("unexpected replacement genesis".into());
        }
        let public = observer.as_mut().ok_or("snapshot state missing")?;
        let mut sequence = after;
        for record in page.public_records {
            if record.sequence <= sequence
                || record.sequence > page.next
                || record.accepted_at < previous_time
                || record.accepted_at > now().saturating_add(120)
            {
                return Err("invalid public transcript ordering".into());
            }
            sequence = record.sequence;
            previous_time = record.accepted_at;
            match record.change {
                wire::PublicChange::Membership(commit) => public
                    .accept(&decode(&commit)?, record.accepted_at)
                    .map_err(|e| e.to_string())?,
                wire::PublicChange::Control(control) => public
                    .replay_control(
                        &HostedControl::decode(&decode(&control)?).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?,
            }
        }
        after = page.next;
        if after == page.head.sequence {
            public
                .publish_group_info(&decode(
                    page.group_info
                        .as_deref()
                        .ok_or("missing final group info")?,
                )?)
                .map_err(|e| e.to_string())?;
            return Ok((observer.take().ok_or("snapshot state missing")?, page.head));
        }
        if page.group_info.is_some() {
            return Err("premature group info".into());
        }
        head = Some(page.head);
    }
}
