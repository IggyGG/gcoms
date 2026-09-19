// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;
use zeroize::Zeroize;

#[derive(Clone)]
pub(crate) struct DirectDelivery {
    pub(crate) peer: NodeInfo,
    /// The node's own relay provision: the fallback first hop when no
    /// intermediary grant is eligible for this peer.
    pub(crate) relay: RelayProvision,
    pub(crate) cells: Vec<Cell>,
}

impl Zeroize for DirectDelivery {
    fn zeroize(&mut self) {
        for cell in &mut self.cells {
            cell.payload.as_mut_slice().zeroize();
        }
        self.relay.hop_key.zeroize();
        for alias in &mut self.relay.aliases {
            alias.capabilities.push.zeroize();
            alias.capabilities.sub.zeroize();
            alias.capabilities.admin.zeroize();
            alias.lease_create.payload.as_mut_slice().zeroize();
        }
    }
}

impl Drop for DirectDelivery {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub(crate) struct PendingDirect {
    pub(crate) delivery: DirectDelivery,
    pub(crate) logical_record: Option<Vec<u8>>,
    pub(crate) sequence: u64,
    pub(crate) next_attempt: std::time::Instant,
    pub(crate) expires: std::time::Instant,
    pub(crate) application_event: bool,
}

impl Zeroize for PendingDirect {
    fn zeroize(&mut self) {
        if let Some(record) = &mut self.logical_record {
            record.as_mut_slice().zeroize();
        }
    }
}

impl Drop for PendingDirect {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectSessionState {
    InitiatedUnconfirmed { expires: std::time::Instant },
    Established,
}

#[derive(Clone)]
pub(crate) struct ProcessedDirect {
    pub(crate) frame_hash: [u8; 32],
    pub(crate) delivery: DirectDelivery,
}

#[derive(Clone, Copy)]
pub(crate) struct DirectPresenceObservation {
    pub(crate) reachability: Reachability,
    pub(crate) expires: std::time::Instant,
}

/// Await a set of independent futures concurrently and collect their
/// outputs in order. Poll in the owning task so cancellation drops all child
/// futures before releasing the node's persistent state.
pub(crate) async fn futures_join_all<F, T>(futures: impl IntoIterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    use std::task::Poll;
    let mut pending: Vec<_> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut remaining = pending.len();
    let mut slots: Vec<Option<T>> = (0..remaining).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        for (future, slot) in pending.iter_mut().zip(&mut slots) {
            if let Some(current) = future.as_mut() {
                if let Poll::Ready(value) = current.as_mut().poll(cx) {
                    *slot = Some(value);
                    *future = None;
                    remaining -= 1;
                }
            }
        }
        if remaining == 0 {
            Poll::Ready(slots.iter_mut().map(|slot| slot.take().unwrap()).collect())
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod concurrent_futures_tests {
    use super::futures_join_all;
    use std::{future::Future, sync::Arc, task::Context};

    #[tokio::test]
    async fn cancellation_drops_children_before_returning_to_the_owner() {
        let owner = Arc::new(());
        let jobs = (0..3).map(|_| {
            let owner = owner.clone();
            async move {
                let _owner = owner;
                std::future::pending::<()>().await;
            }
        });
        let mut joined = Box::pin(futures_join_all(jobs));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(joined.as_mut().poll(&mut context).is_pending());
        assert_eq!(Arc::strong_count(&owner), 4);
        drop(joined);
        assert_eq!(Arc::strong_count(&owner), 1);
    }

    #[tokio::test]
    async fn polls_every_child_and_preserves_input_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let polled = Arc::new(AtomicUsize::new(0));
        let mut senders = Vec::new();
        let mut jobs = Vec::new();
        for index in 0..3 {
            let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
            senders.push(sender);
            let polled = polled.clone();
            jobs.push(async move {
                polled.fetch_add(1, Ordering::SeqCst);
                receiver.await.unwrap();
                index
            });
        }
        let mut joined = Box::pin(futures_join_all(jobs));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(joined.as_mut().poll(&mut context).is_pending());
        assert_eq!(polled.load(Ordering::SeqCst), 3);
        for sender in senders.into_iter().rev() {
            sender.send(()).unwrap();
        }
        assert_eq!(joined.await, vec![0, 1, 2]);
        assert!(futures_join_all(Vec::<std::future::Ready<()>>::new())
            .await
            .is_empty());
    }
}

/// Size of the active intermediary set (SPEC §15 `LANE_SET`).
pub(crate) const LANE_SET: usize = 4;
/// One member of the active set is replaced this often (SPEC §15 `LANE_ROTATE`).
pub(crate) const LANE_ROTATE: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// Grants a node retains from peers.
pub(crate) const MAX_FORWARD_GRANTS: usize = 256;
/// Lifetime of a grant this node issues; re-issued with contact renewals.
pub(crate) const FORWARD_GRANT_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Add +/-25% uniform jitter so that a fleet started together does not
/// renew, retry, or poll in lockstep.
pub(crate) fn jittered(base: std::time::Duration) -> std::time::Duration {
    use rand::Rng;
    let quarter = base.as_millis() as u64 / 4;
    if quarter == 0 {
        return base;
    }
    let offset = rand::thread_rng().gen_range(0..=quarter * 2);
    base - std::time::Duration::from_millis(quarter) + std::time::Duration::from_millis(offset)
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn fresh_msg_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

pub struct NodeState {
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_sessions: bool,
    /// Retained GC/2 carrier readiness. The background owner future is owned by
    /// the node task set; this handle only opens circuits through it. Not
    /// archived: the startup profile selects the carrier.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_carrier: Option<std::sync::Arc<gcoms_routing::gc2::owner::ReadyConnector>>,
    /// Endpoint client shared by background GC/2 delivery and subscriptions.
    /// Present only while the startup profile selects the natural carrier.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_carrier_client: Option<std::sync::Arc<gcoms_transport::Tp1Client>>,
    /// Protected GC/2 client over the ready connector. Used throughout the
    /// selected protected profile, including when no entry is ready. The other
    /// client is used only by explicitly unprotected fixtures.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_carrier_route: Option<std::sync::Arc<gcoms_transport::Tp1Client>>,
    /// Parallel protected circuits for bulk records. A single carrier circuit
    /// carries at most one record per profile period, so bulk stripes over the
    /// shared entry-circuit bound instead of queueing behind one pipe.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_carrier_bulk_routes: Vec<std::sync::Arc<gcoms_transport::Tp1Client>>,
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_carrier_bulk_cursor: usize,
    /// Durable GC/2 directory owned by the carrier. Advertised introductions
    /// from the private provisioning card are installed here.
    #[cfg(feature = "experimental-gc2")]
    pub(crate) gc2_carrier_directory:
        Option<std::sync::Arc<gcoms_routing::gc2::directory::Directory>>,
    #[cfg(feature = "experimental-gc2")]
    pub(super) gc2_receipts: super::gc2_receipts::Ledger,
    #[cfg(feature = "experimental-gc2")]
    pub(crate) retained_direct: std::sync::OnceLock<crate::scheduler::RetainedAccount>,
    pub(crate) routing: Option<Arc<super::routing::RoutingRuntime>>,
    pub(crate) secrets: Arc<LocalSecrets>,
    pub(crate) identity_seed: [u8; 32],
    #[cfg(feature = "client-persist")]
    pub(crate) sealed_tls_identity: Vec<u8>,
    pub(crate) info: NodeInfo,
    pub(crate) sessions: HashMap<Vec<u8>, PeerSession>,
    pub(crate) session_states: HashMap<Vec<u8>, DirectSessionState>,
    pub(crate) peer_routes: HashMap<Vec<u8>, NodeInfo>,
    pub(crate) peer_route_generations: HashMap<Vec<u8>, u64>,
    pub(crate) local_contact_generation: u64,
    pub(crate) pending_1to1: HashMap<[u8; 16], PendingDirect>,
    pub(crate) next_direct_sequence: u64,
    pub(crate) durable_applications_enabled: bool,
    pub(crate) application_inbox: application_inbox::ApplicationInbox,
    pub(crate) direct_ack_outbox: VecDeque<DirectDelivery>,
    pub(crate) processed_direct: HashMap<(Vec<u8>, u64), ProcessedDirect>,
    pub(crate) processed_direct_order: VecDeque<(Vec<u8>, u64)>,
    pub(crate) direct_presence: HashMap<Vec<u8>, DirectPresenceObservation>,
    pub(crate) direct_presence_counters: HashMap<Vec<u8>, u64>,
    pub(crate) direct_presence_opt_in: HashSet<Vec<u8>>,
    pub(crate) channel_presence: HashMap<(String, [u8; 32]), DirectPresenceObservation>,
    pub(crate) channel_presence_counters: HashMap<(String, [u8; 32]), u64>,
    pub(crate) channel_presence_opt_in: HashSet<String>,
    pub(crate) parked: Vec<(Vec<u8>, gcoms_crypto::session::Frame)>,
    pub(crate) accepted_first_moves: VecDeque<[u8; 32]>,
    pub(crate) channels: HashMap<String, crate::channel::ChannelState>,
    pub(crate) prepared: HashMap<u64, PreparedChannelJoin>,
    pub(crate) chan_parked: Vec<(String, Vec<u8>)>,
    pub(crate) channel_fragments: crate::proto::ChannelFragmentBuffer,
    pub(crate) last_channel_send: Option<(String, Vec<u8>)>,
    pub(crate) pending_channel_direct: HashMap<[u8; 16], (String, [u8; 32])>,
    pub(crate) next_prep_id: u64,
    pub(crate) client_relay: RelayProvision,
    /// Intermediaries this node may route through (SPEC §11.1), keyed by
    /// the intermediary's relay service id. Fed by `ForwardGrant` records
    /// from established peers. Private bearers; sealed on persist.
    pub(crate) forward_grants: HashMap<[u8; 32], crate::alias::ForwardGrant>,
    /// Service ids of the intermediaries currently pinned as lanes (`LANE_SET`).
    pub(crate) active_intermediaries: Vec<[u8; 32]>,
    pub(crate) last_intermediary_rotation: std::time::Instant,
    /// Deliveries that fell back to the node's own relay because no eligible
    /// intermediary existed. Exposed for diagnostics.
    pub(crate) intermediary_fallbacks: u64,
    pub(crate) staged_contact_aliases: Option<Vec<OwnedAlias>>,
    pub(crate) unannounced_old_contact_aliases: Option<Vec<OwnedAlias>>,
    pub(crate) unannounced_contact_deadlines: Option<(std::time::Instant, std::time::Instant)>,
    pub(crate) alias_lifecycle_timing: AliasLifecycleConfig,
    pub(crate) owner_transition_failed: bool,
    #[cfg(feature = "client-persist")]
    pub(in crate::node) owner_clock: Mutex<persist::owner_aliases::RestoreClock>,
    #[cfg(feature = "client-persist")]
    pub(crate) owner_alias_origins: HashMap<[u8; 32], OwnedAlias>,
    #[cfg(feature = "client-persist")]
    pub(crate) owner_alias_renewals: HashMap<[u8; 32], Vec<u8>>,
    pub(crate) draining_contact_aliases: Vec<DrainingContactAliases>,
    pub(crate) subscribed_contact_aliases: HashSet<[u8; 32]>,
    pub(crate) subscribed_classes: HashSet<([u8; 32], gcoms_core::TrafficClass)>,
    pub(crate) contact_aliases_activated: std::time::Instant,
    pub(crate) frwd_target_policy: FrwdTargetPolicy,
    pub(crate) scheduler: RelayScheduler,
    /// Owner side: invite-redeem requests received from friends over sealed
    /// direct sessions, awaiting async processing by the invite service. Bounded.
    pub(crate) invite_redeem_inbox: VecDeque<InviteRedeemRequest>,
    /// Friend side: redemptions this node is waiting on, keyed by the request
    /// message id. The oneshot wakes the `join_with_invite` caller when the
    /// owner's `InviteWelcome` arrives (or the wait times out).
    pub(crate) pending_invite_redemptions:
        HashMap<[u8; 16], tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>>,
    #[cfg_attr(not(feature = "client-persist"), allow(dead_code))]
    pub(crate) durable_state_sink: Option<DurableStateSink>,
}

/// An invite-redeem request received from a friend, queued for async handling.
pub(crate) struct InviteRedeemRequest {
    /// The friend's identity pk, to route the `InviteWelcome` reply back.
    pub(crate) sender_pk: Vec<u8>,
    pub(crate) message_id: [u8; 16],
    pub(crate) channel: String,
    pub(crate) member_name: String,
    pub(crate) invite_id: [u8; 16],
    pub(crate) invite_secret: [u8; 32],
    pub(crate) key_package: Vec<u8>,
}

impl NodeState {
    /// A failed lifecycle checkpoint has an unknown durable outcome. Refuse new
    /// application jobs until the last confirmed archive is reopened. The relay
    /// transit scheduler is independent and holds no local application state.
    pub(crate) fn pause_failed_owner_transition(&mut self) {
        self.owner_transition_failed = true;
        self.scheduler.shutdown();
    }
}

#[derive(Clone)]
pub(crate) struct DrainingContactAliases {
    pub(crate) receive_until: std::time::Instant,
    pub(crate) aliases: Vec<OwnedAlias>,
    pub(crate) abandon_at: std::time::Instant,
    pub(crate) next_revoke: std::time::Instant,
}

pub(crate) struct PreparedChannelJoin {
    pub(crate) mls: gcoms_mls::PreparedJoin,
    pub(crate) route: crate::channel::OwnedChannelRoute,
    pub(crate) display: String,
}

pub(crate) fn random_nonzero<const N: usize>() -> [u8; N] {
    loop {
        let mut value = [0; N];
        rand::thread_rng().fill_bytes(&mut value);
        if value != [0; N] {
            return value;
        }
    }
}

/// Natural-carrier client currently selected by the startup profile, if any.
pub(crate) fn natural_client(st: &NodeState) -> Option<std::sync::Arc<gcoms_transport::Tp1Client>> {
    #[cfg(feature = "experimental-gc2")]
    {
        natural_route_client(st)
    }
    #[cfg(not(feature = "experimental-gc2"))]
    {
        let _ = st;
        None
    }
}

/// Selecting GC/2 protection is a lifetime decision, independent of readiness.
/// Keep the protected connector during startup/outages: it reports unavailable
/// routes without dialing a terminal or falling back to another carrier. Only
/// explicitly unprotected fixtures have no protected connector.
#[cfg(feature = "experimental-gc2")]
pub(crate) fn natural_route_client(
    st: &NodeState,
) -> Option<std::sync::Arc<gcoms_transport::Tp1Client>> {
    if let Some(route) = &st.gc2_carrier_route {
        return Some(route.clone());
    }
    st.gc2_carrier_client.clone()
}

/// Class-aware natural client selection. Bulk records round-robin over the
/// parallel protected circuits; interactive and control records keep the
/// single protected client, and unprotected fixtures keep the direct client.
#[cfg(feature = "experimental-gc2")]
pub(crate) fn natural_client_for(
    st: &mut NodeState,
    class: gcoms_core::TrafficClass,
) -> Option<std::sync::Arc<gcoms_transport::Tp1Client>> {
    let protected = st.gc2_carrier_route.is_some();
    if protected {
        if class == gcoms_core::TrafficClass::Bulk && !st.gc2_carrier_bulk_routes.is_empty() {
            let index = st.gc2_carrier_bulk_cursor % st.gc2_carrier_bulk_routes.len();
            st.gc2_carrier_bulk_cursor = st.gc2_carrier_bulk_cursor.wrapping_add(1);
            return Some(st.gc2_carrier_bulk_routes[index].clone());
        }
        return st.gc2_carrier_route.clone();
    }
    st.gc2_carrier_client.clone()
}

pub(crate) fn validate_application_payload(payload: &[u8]) -> Result<(), String> {
    if gcoms_core::is_volatile_application_payload(payload) {
        return Err("one-use contact requires volatile application transport".into());
    }
    validate_application_size(payload)
}

pub(crate) fn validate_application_size(payload: &[u8]) -> Result<(), String> {
    if payload.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT {
        return Err(format!(
            "application payload exceeds {} byte limit",
            gcoms_core::APPLICATION_PAYLOAD_LIMIT
        ));
    }
    Ok(())
}

#[cfg(test)]
mod cancellation_tests {
    use super::futures_join_all;
    use std::{future::Future, sync::Arc, task::Poll};

    #[tokio::test]
    async fn canceling_a_batch_drops_child_owners_before_returning() {
        let owner = Arc::new(());
        let released = Arc::downgrade(&owner);
        let mut batch = Box::pin(futures_join_all([async move {
            let _owner = owner;
            std::future::pending::<()>().await;
        }]));
        std::future::poll_fn(|cx| {
            assert!(batch.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(batch);
        // No sleep/yield: cancellation must release the resource synchronously.
        assert!(released.upgrade().is_none());
    }
}
