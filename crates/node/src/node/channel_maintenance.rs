//! Bounded channel-data admission. Receipts remain owned across maintenance
//! ticks; a slow hop must neither block other channels nor trigger a duplicate.
use super::*;
use futures_util::{future::BoxFuture, stream::FuturesUnordered, StreamExt};

const MAX_PLANS: usize = 64;
const MAX_CHANNEL_PLANS: usize = 8;
const MAX_RECEIPTS: usize = 128;
const MAX_CHANNEL_RECEIPTS: usize = 8;
const ADMISSION_ATTEMPTS_PER_TICK: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Work {
    Forward([u8; 16]),
    Pull([u8; 16], [u8; 32]),
    Message([u8; 16]),
    Pex(u8),
}

#[cfg(all(test, feature = "client-persist"))]
mod tests {
    use super::*;
    use crate::scheduler::{JobResult, Receipt};

    fn fixture(names: &[&str]) -> (Arc<Mutex<NodeState>>, RelayScheduler) {
        let scheduler = RelayScheduler::with_profile(
            Arc::new(Tp1Client::new().unwrap()),
            SchedulerProfile::fixture(),
        );
        let mut state = persist::tests::state();
        state.scheduler = scheduler.clone();
        for name in names {
            state.channels.insert(
                (*name).into(),
                persist::tests::established_owner_fixture(name),
            );
        }
        (Arc::new(Mutex::new(state)), scheduler)
    }

    fn message(state: &Arc<Mutex<NodeState>>, name: &str, byte: u8, size: usize) -> [u8; 16] {
        let mut state = state.lock().unwrap();
        let cs = state.channels.get_mut(name).unwrap();
        let mut peer = cs.own_route.public.clone();
        peer.pseudonym = [byte; 32];
        let wire = vec![byte; size];
        let id = crate::channel::msg_id(name, &wire);
        cs.message_outbox.insert(
            id,
            crate::channel::ChannelMessageOutbox {
                wire,
                expected: [(peer.pseudonym, peer)].into_iter().collect(),
                acknowledged: HashSet::new(),
            },
        );
        id
    }

    #[tokio::test]
    async fn full_lane_does_not_block_another_wire_in_the_same_channel() {
        full_lane_progress(false).await;
    }

    #[tokio::test]
    async fn full_lane_does_not_block_another_recipient_of_the_same_wire() {
        full_lane_progress(true).await;
    }

    async fn full_lane_progress(shared_wire: bool) {
        let (state, scheduler) = fixture(&["shared"]);
        let id = message(&state, "shared", 1, 16);
        if shared_wire {
            let mut st = state.lock().unwrap();
            let cs = st.channels.get_mut("shared").unwrap();
            let mut second = cs.own_route.public.clone();
            second.pseudonym = [2; 32];
            cs.message_outbox
                .get_mut(&id)
                .unwrap()
                .expected
                .insert(second.pseudonym, second);
        } else {
            message(&state, "shared", 2, 16);
        }
        let mut maintenance = ChannelMaintenance::default();
        maintenance.stage(&state, &scheduler);
        let blocked = maintenance.plans[0].targets[0].pseudonym;
        let mut accepted = Vec::new();
        let mut held = Vec::new();
        for _ in 0..2 {
            maintenance.admit_with(|peer, _| {
                if peer.pseudonym == blocked {
                    return Err(EnqueueError::Full);
                }
                accepted.push(peer.pseudonym);
                let (send, receipt) = Receipt::test_channel();
                held.push(send);
                Ok(receipt)
            });
        }
        assert_eq!(
            accepted.len(),
            1,
            "a saturated lane must not hide other usable recipients"
        );
        assert_ne!(accepted[0], blocked);
        drop(maintenance);
        drop(held);
        assert_eq!(scheduler.resource_snapshot().jobs, 0);
        scheduler.shutdown();
    }

    #[tokio::test]
    async fn saturation_release_rotates_large_small_and_later_channel_work() {
        let (state, scheduler) = fixture(&["a-large", "b-stalled", "c-small", "d-later"]);
        let large = message(&state, "a-large", 1, 256 * 1024);
        let stalled = message(&state, "b-stalled", 2, 256 * 1024);
        let small = message(&state, "c-small", 3, 12);
        let mut maintenance = ChannelMaintenance::default();
        maintenance.stage(&state, &scheduler);
        let staged_budget = scheduler.resource_snapshot();
        maintenance.admit_with(|_, _| Err(EnqueueError::Full));
        assert!(maintenance.is_empty());
        assert!(maintenance
            .plans
            .iter()
            .all(|p| p.next.iter().all(|&index| index == 0)));
        let mut observed = Vec::new();
        let mut held = Vec::new();
        for round in 0..5 {
            if round == 1 {
                message(&state, "d-later", 4, 12);
                maintenance.stage(&state, &scheduler);
            }
            // Only one slot becomes available each round; subsequent calls
            // remain Full. A stable map/plan prefix cannot take every release.
            let mut available = true;
            maintenance.admit_with(|peer, _| {
                if !available {
                    return Err(EnqueueError::Full);
                }
                available = false;
                observed.push(peer.pseudonym[0]);
                let (send, receipt) = Receipt::test_channel();
                held.push(send);
                Ok(receipt)
            });
        }
        // New work joins the bounded queue behind its current cursor; it
        // gets a turn within one traversal, without resetting older work.
        assert_eq!(observed, [1, 2, 3, 1, 4]);
        // Pending is a separately owned scheduler attempt, never a successful
        // cell or permission to advance to a new attempt identity.
        let before: Vec<_> = maintenance
            .plans
            .iter()
            .map(|p| (p.token, p.next.clone()))
            .collect();
        maintenance.admit_with(|_, _| Err(EnqueueError::Pending));
        assert_eq!(
            before,
            maintenance
                .plans
                .iter()
                .map(|p| (p.token, p.next.clone()))
                .collect::<Vec<_>>()
        );
        for send in held {
            assert!(send
                .send(JobResult::HopAccepted(bytes::Bytes::new()))
                .is_ok());
        }
        for _ in 0..5 {
            maintenance.complete_next(&state).await;
        }
        let st = state.lock().unwrap();
        for (name, id) in [
            ("a-large", large),
            ("b-stalled", stalled),
            ("c-small", small),
        ] {
            let outbox = &st.channels[name].message_outbox[&id];
            assert!(
                outbox.acknowledged.is_empty(),
                "hop receipts must not ACK an MLS message"
            );
        }
        drop(st);
        assert!(staged_budget.bytes < crate::scheduler::MAX_QUEUED_BYTES);
        drop(maintenance);
        assert_eq!(scheduler.resource_snapshot().jobs, 0);
        assert_eq!(scheduler.resource_snapshot().bytes, 0);
        scheduler.shutdown();
    }

    #[tokio::test]
    async fn partial_forward_receipts_cannot_settle_total_target_accounting() {
        let (state, scheduler) = fixture(&["forward"]);
        let mut cs = persist::tests::established_owner_fixture("forward");
        let wire = vec![9; 64 * 1024];
        let id = crate::channel::msg_id("forward", &wire);
        cs.enqueue_forward(id, wire.clone());
        let target = crate::channel::PeerRef::from_route(&cs.own_route.public);
        state.lock().unwrap().channels.insert("forward".into(), cs);
        let cells = crate::proto::encode_chan_cells("forward", &wire).unwrap();
        let total = cells.len() * 2;
        let payload_bytes = cells.iter().map(|cell| cell.payload.len()).sum();
        let mut maintenance = ChannelMaintenance::default();
        maintenance.plans.push_back(Plan {
            token: 1,
            channel: "forward".into(),
            work: Work::Forward(id),
            cells,
            targets: vec![target.clone(), target],
            next: vec![0; 2],
            target_cursor: 0,
            pending: 0,
            accepted: 0,
            payload_bytes,
            wire_digest: Some(Sha256::digest(&wire).into()),
            _payload: scheduler.retain_attempt_payload(payload_bytes).unwrap(),
        });
        let mut senders = Vec::new();
        maintenance.admit_with(|_, _| {
            if !senders.is_empty() {
                return Err(EnqueueError::Full);
            }
            let (send, receipt) = Receipt::test_channel();
            senders.push(send);
            Ok(receipt)
        });
        assert!(senders
            .pop()
            .unwrap()
            .send(JobResult::HopAccepted(bytes::Bytes::new()))
            .is_ok());
        maintenance.complete_next(&state).await;
        assert_eq!(
            state.lock().unwrap().channels["forward"].pending[0].attempts,
            0
        );
        assert_eq!(maintenance.plans[0].total(), total);
        let mut completed = 1;
        while !maintenance.plans.is_empty() {
            maintenance.admit_with(|_, _| {
                let (send, receipt) = Receipt::test_channel();
                senders.push(send);
                Ok(receipt)
            });
            for send in senders.drain(..) {
                completed += 1;
                let result = if completed == total {
                    JobResult::Failed("terminal refused one cell".into())
                } else {
                    JobResult::HopAccepted(bytes::Bytes::new())
                };
                assert!(send.send(result).is_ok());
                maintenance.complete_next(&state).await;
            }
        }
        let state = state.lock().unwrap();
        assert_eq!(state.channels["forward"].pending[0].wire, wire);
        assert_eq!(state.channels["forward"].pending[0].attempts, 1);
        assert_eq!(scheduler.resource_snapshot().jobs, 0);
        scheduler.shutdown();
    }

    #[tokio::test]
    async fn retained_payloads_leave_scheduler_admission_headroom_and_drop_cleanly() {
        let names: Vec<_> = (0..16).map(|n| format!("channel-{n:02}")).collect();
        let (state, scheduler) = fixture(&names.iter().map(String::as_str).collect::<Vec<_>>());
        for (n, name) in names.iter().enumerate() {
            message(&state, name, n as u8, 512 * 1024);
        }
        let mut maintenance = ChannelMaintenance::default();
        maintenance.stage(&state, &scheduler);
        assert!(!maintenance.plans.is_empty());
        let admitted = scheduler
            .retain_attempt_payload(gcoms_core::MAX_MESSAGE + 512)
            .unwrap();
        let mut held = Vec::new();
        maintenance.admit_with(|_, _| {
            let (send, receipt) = Receipt::test_channel();
            held.push(send);
            Ok(receipt)
        });
        assert!(held.len() <= MAX_RECEIPTS);
        for plan in &maintenance.plans {
            assert!(plan.pending <= MAX_CHANNEL_RECEIPTS);
        }
        drop(maintenance);
        assert!(held.iter().all(|sender| sender.is_closed()));
        // Cancelling receipt observation releases its local plans, not a
        // scheduler reservation that still belongs to another active attempt.
        assert_eq!(scheduler.resource_snapshot().jobs, 1);
        drop(admitted);
        assert_eq!(scheduler.resource_snapshot().jobs, 0);
        assert_eq!(scheduler.resource_snapshot().bytes, 0);
        scheduler.shutdown();
    }
}

struct Plan {
    token: u64,
    channel: String,
    work: Work,
    cells: Vec<Cell>,
    targets: Vec<crate::channel::PeerRef>,
    next: Vec<usize>,
    target_cursor: usize,
    pending: usize,
    accepted: usize,
    // Charge the one encoded copy shared by all targets, including framing and
    // target metadata. Scheduler admissions separately charge queued copies.
    payload_bytes: usize,
    wire_digest: Option<[u8; 32]>,
    _payload: crate::scheduler::PayloadReservation,
}

impl Plan {
    fn total(&self) -> usize {
        self.cells.len() * self.targets.len()
    }

    fn fully_admitted(&self) -> bool {
        self.next.iter().all(|&index| index == self.cells.len())
    }
}

#[derive(Default)]
pub(crate) struct ChannelMaintenance {
    plans: VecDeque<Plan>,
    completions: FuturesUnordered<BoxFuture<'static, (u64, bool)>>,
    last_channel: Option<String>,
    last_work: HashMap<String, Work>,
    next_token: u64,
}

impl ChannelMaintenance {
    pub(crate) fn is_empty(&self) -> bool {
        self.completions.is_empty()
    }

    pub(crate) fn tick(&mut self, state: &Arc<Mutex<NodeState>>, scheduler: &RelayScheduler) {
        self.stage(state, scheduler);
        self.admit(scheduler);
        self.settle(state);
    }

    fn stage(&mut self, state: &Arc<Mutex<NodeState>>, scheduler: &RelayScheduler) {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.owner_transition_failed {
            return;
        }
        for plan in &mut self.plans {
            if !st.channels.contains_key(&plan.channel) {
                plan.next.fill(plan.cells.len());
            }
        }
        self.last_work
            .retain(|name, _| st.channels.contains_key(name));
        let mut names: Vec<_> = st.channels.keys().cloned().collect();
        names.sort();
        let pivot = self
            .last_channel
            .as_ref()
            .map_or(0, |last| names.partition_point(|name| name <= last));
        let count = names.len();
        if count > 0 {
            names.rotate_left(pivot % count);
        }
        // Select one wire per channel per bounded round. The cursor advances after
        // selection, so a saturated round resumes behind the last admitted
        // channel instead of repeatedly favouring HashMap iteration order.
        let mut attempted = HashSet::new();
        for _ in 0..MAX_CHANNEL_PLANS {
            for name in &names {
                if self.plans.len() == MAX_PLANS {
                    break;
                }
                if self.plans.iter().filter(|p| p.channel == *name).count() >= MAX_CHANNEL_PLANS {
                    continue;
                }
                let cs = st.channels.get_mut(name).expect("listed channel");
                if cs.own_route.aliases.len() != 2 {
                    continue;
                }
                let mut work: Vec<_> = cs.pending.iter().map(|p| Work::Forward(p.id)).collect();
                work.extend(
                    cs.pull_outbox
                        .iter()
                        .map(|(p, id, _)| Work::Pull(*id, p.pseudonym)),
                );
                work.extend(cs.message_outbox.iter().filter_map(|(id, p)| {
                    p.expected
                        .keys()
                        .any(|peer| !p.acknowledged.contains(peer))
                        .then_some(Work::Message(*id))
                }));
                work.extend([Work::Pex(0), Work::Pex(1)]);
                work.sort();
                work.dedup();
                let pivot = self
                    .last_work
                    .get(name)
                    .map_or(0, |last| work.partition_point(|key| key <= last));
                let count = work.len();
                work.rotate_left(pivot % count);
                for key in work {
                    if !attempted.insert((name.clone(), key.clone())) {
                        continue;
                    }
                    if self
                        .plans
                        .iter()
                        .any(|p| p.channel == *name && p.work == key)
                    {
                        continue;
                    }
                    let plan = self.prepare(name, cs, key.clone(), scheduler);
                    // Empty/unreachable work still rotates; Full retains the
                    // original wire in ChannelState for a later opportunity.
                    self.last_work.insert(name.clone(), key);
                    if let Some(plan) = plan {
                        self.last_channel = Some(name.clone());
                        self.plans.push_back(plan);
                        break;
                    }
                }
            }
        }
    }

    fn reserve_payload(
        &self,
        scheduler: &RelayScheduler,
        bytes: usize,
    ) -> Option<crate::scheduler::PayloadReservation> {
        if bytes.checked_add(self.plans.iter().map(|p| p.payload_bytes).sum::<usize>())?
            > crate::scheduler::MAX_QUEUED_BYTES * 3 / 4
        {
            return None;
        }
        // Do not fill the shared budget with staged payloads and leave no room
        // for their first actual admission. This reservation is released only
        // after the plan reservation succeeds; other producers keep their own
        // unchanged limits and may still temporarily occupy this headroom.
        let _headroom = scheduler
            .retain_attempt_payload(4 * gcoms_core::MAX_MESSAGE)
            .ok()?;
        scheduler.retain_attempt_payload(bytes).ok()
    }

    fn prepare(
        &mut self,
        name: &str,
        cs: &mut crate::channel::ChannelState,
        work: Work,
        scheduler: &RelayScheduler,
    ) -> Option<Plan> {
        let (cells, targets, payload, payload_bytes, wire_digest) = if matches!(work, Work::Pex(_))
        {
            // At most two PEX cells per channel, as before, and reserve before
            // constructing randomized control material outside the scheduler.
            let bytes = gcoms_core::MAX_MESSAGE + 512;
            let payload = self.reserve_payload(scheduler, bytes)?;
            let mut cells = Vec::new();
            let mut targets = Vec::new();
            // A plan shares cells across targets, so each PEX has its own plan.
            if let Some((partner, _)) = cs.overlay.pex_outbound() {
                let mut refs = vec![crate::channel::PeerRef::from_route(&cs.own_route.public)];
                for pid in cs.overlay.view.random_descriptors(7).iter().map(|d| d.id) {
                    if let Some(peer) = cs.resolve(&pid) {
                        refs.push(peer);
                    }
                }
                let have = cs.have_list();
                let peer = cs.resolve(&partner)?;
                match stage_channel_pex(name, cs, peer.pseudonym, &refs, &have) {
                    Ok((target, cell)) => {
                        targets.push(target);
                        cells.push(cell);
                    }
                    Err(error) => metrics::log_event(
                        "chan_pex_prepare_failed",
                        &[("channel", name.into()), ("e", error)],
                    ),
                }
            }
            (cells, targets, payload, bytes, None)
        } else {
            let (wire, targets): (&[u8], Vec<_>) = match &work {
                Work::Forward(id) => {
                    let ids = cs.overlay.forward_targets(None);
                    let targets = ids.into_iter().filter_map(|id| cs.resolve(&id)).collect();
                    (&cs.pending.iter().find(|p| p.id == *id)?.wire, targets)
                }
                Work::Pull(id, peer) => {
                    let (target, _, wire) = cs
                        .pull_outbox
                        .iter()
                        .find(|(p, i, _)| i == id && p.pseudonym == *peer)?;
                    (wire, vec![target.clone()])
                }
                Work::Message(id) => {
                    let outbox = cs.message_outbox.get(id)?;
                    (
                        &outbox.wire,
                        outbox
                            .expected
                            .iter()
                            .filter(|(id, _)| !outbox.acknowledged.contains(*id))
                            .map(|(_, peer)| crate::channel::PeerRef::from_route(peer))
                            .collect(),
                    )
                }
                Work::Pex(_) => unreachable!(),
            };
            if targets.is_empty() {
                if let Work::Forward(id) = work {
                    cs.settle_forward(id, false);
                }
                return None;
            }
            // Conservative framing/Vec/Cell allowance without retaining a
            // second encoded copy for every target. One transient encoding is
            // additionally bounded by the protocol's existing frame limit.
            let framed = wire.len().checked_add(name.len() + 3)?;
            let bytes = framed
                .checked_add(framed.div_ceil(1024) * 128)?
                .checked_add(
                    targets.len()
                        * (std::mem::size_of::<crate::channel::PeerRef>()
                            + std::mem::size_of::<usize>())
                        + 512,
                )?;
            let payload = self.reserve_payload(scheduler, bytes)?;
            let cells = match crate::proto::encode_chan_cells(name, wire) {
                Ok(cells) => cells,
                Err(_) => {
                    if let Work::Forward(id) = work {
                        cs.settle_forward(id, false);
                    }
                    return None;
                }
            };
            (
                cells,
                targets,
                payload,
                bytes,
                Some(Sha256::digest(wire).into()),
            )
        };
        if cells.is_empty() || targets.is_empty() {
            return None;
        }
        let token = self.next_token;
        self.next_token += 1;
        Some(Plan {
            token,
            channel: name.into(),
            work,
            next: vec![0; targets.len()],
            target_cursor: 0,
            cells,
            targets,
            pending: 0,
            accepted: 0,
            payload_bytes,
            wire_digest,
            _payload: payload,
        })
    }

    fn admit(&mut self, scheduler: &RelayScheduler) {
        self.admit_with(|peer, cell| {
            scheduler.push(
                ProducerClass::ChannelData,
                peer.contact.clone(),
                cell.clone(),
            )
        });
    }

    fn admit_with(
        &mut self,
        mut push: impl FnMut(
            &crate::channel::PeerRef,
            &Cell,
        ) -> Result<crate::scheduler::Receipt, EnqueueError>,
    ) {
        let mut last_admitted = None;
        let mut remaining = ADMISSION_ATTEMPTS_PER_TICK;
        let mut deferred = HashSet::new();
        while remaining > 0 && self.completions.len() < MAX_RECEIPTS {
            let mut served = HashSet::new();
            let mut progressed = false;
            for _ in 0..self.plans.len() {
                let mut plan = self.plans.pop_front().expect("counted plan");
                let pending = plan.pending
                    + self
                        .plans
                        .iter()
                        .filter(|p| p.channel == plan.channel)
                        .map(|p| p.pending)
                        .sum::<usize>();
                if remaining > 0
                    && self.completions.len() < MAX_RECEIPTS
                    && !plan.fully_admitted()
                    && pending < MAX_CHANNEL_RECEIPTS
                    && !served.contains(&plan.channel)
                {
                    // A full/pending target keeps its exact fragment cursor,
                    // but cannot prevent another recipient using a free lane.
                    let target = (0..plan.targets.len())
                        .map(|offset| (plan.target_cursor + offset) % plan.targets.len())
                        .find(|&target| {
                            plan.next[target] < plan.cells.len()
                                && !deferred.contains(&(plan.token, target))
                        });
                    let Some(target) = target else {
                        self.plans.push_back(plan);
                        continue;
                    };
                    plan.target_cursor = (target + 1) % plan.targets.len();
                    let peer = &plan.targets[target];
                    let cell = &plan.cells[plan.next[target]];
                    remaining -= 1;
                    progressed = true;
                    match push(peer, cell) {
                        Ok(receipt) => {
                            let token = plan.token;
                            self.completions.push(Box::pin(async move {
                                let result = receipt.completion().await.accepted();
                                if let Err(error) = &result {
                                    metrics::log_event("chan_push_failed", &[("e", error.clone())]);
                                }
                                (token, result.is_ok())
                            }));
                            last_admitted = Some(plan.token);
                            plan.next[target] += 1;
                            plan.pending += 1;
                            served.insert(plan.channel.clone());
                        }
                        // Neither result owns a new attempt. Keep the cursor;
                        // never count a pending or unadmitted cell as accepted.
                        Err(EnqueueError::Full | EnqueueError::Pending) => {
                            deferred.insert((plan.token, target));
                        }
                        Err(EnqueueError::Shutdown | EnqueueError::InvalidCell) => {
                            plan.next.fill(plan.cells.len());
                        }
                    }
                }
                self.plans.push_back(plan);
            }
            if !progressed {
                break;
            }
        }
        if let Some(index) =
            last_admitted.and_then(|token| self.plans.iter().position(|p| p.token == token))
        {
            let count = self.plans.len();
            self.plans.rotate_left((index + 1) % count);
        }
    }

    pub(crate) async fn complete_next(&mut self, state: &Arc<Mutex<NodeState>>) {
        if let Some((token, accepted)) = self.completions.next().await {
            if let Some(plan) = self.plans.iter_mut().find(|p| p.token == token) {
                plan.pending -= 1;
                plan.accepted += usize::from(accepted);
            }
            self.settle(state);
        }
    }

    fn settle(&mut self, state: &Arc<Mutex<NodeState>>) {
        self.plans.retain(|plan| {
            if !plan.fully_admitted() || plan.pending != 0 {
                return true;
            }
            let accepted = plan.accepted == plan.total();
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(cs) = st.channels.get_mut(&plan.channel) {
                match plan.work {
                    Work::Forward(id) => cs.settle_forward(id, accepted),
                    Work::Pull(id, peer) if accepted => {
                        cs.pull_outbox.retain(|(target, queued, wire)| {
                            *queued != id
                                || target.pseudonym != peer
                                || target.contact != plan.targets[0].contact
                                || plan.wire_digest != Some(Sha256::digest(wire).into())
                        });
                    }
                    _ => {}
                }
            }
            metrics::log_event(
                "chan_tick",
                &[
                    ("channel", plan.channel.clone()),
                    ("pushes", plan.accepted.to_string()),
                    ("expected", plan.total().to_string()),
                ],
            );
            false
        });
    }
}
