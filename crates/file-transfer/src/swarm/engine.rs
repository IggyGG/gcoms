use super::{protocol::*, Cache, Error, Result, State, Status};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const MAX_PEERS: usize = 64;
const MAX_SOURCES: usize = 4;
const ACTIVE_DOWNLOADS: usize = 2;
const PIPELINE: usize = 4;
pub const BLOCK_WINDOW: usize = 8;
pub const PAYLOAD_BUDGET: usize = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: u64 = 30;

/// Local aggregate observations; contains no share, route, or member identifiers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub verified_pieces: u64,
    pub received_blocks: u64,
    pub received_bytes: u64,
    pub rejected_pieces: u64,
    pub retries: u64,
    pub buffered_bytes: usize,
    pub pending_pulls: usize,
    pub hop_accepted: u64,
    pub outcome_unknown: u64,
    pub not_sent: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub channel: [u8; 32],
    pub member: Member,
}
#[derive(Debug)]
pub struct Action {
    pub peer: Peer,
    pub message: Message,
    _payload: Option<PayloadReservation>,
}
#[derive(Clone, Debug)]
pub struct PayloadReservation(Arc<ReservedPayload>);
#[derive(Debug)]
struct ReservedPayload {
    counter: Arc<AtomicUsize>,
    bytes: usize,
}
impl Drop for ReservedPayload {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
#[derive(Clone, Copy, Debug)]
pub struct SendToken {
    peer: Peer,
    id: ShareId,
    piece: u32,
    offset: u32,
    request: [u8; 16],
}
#[derive(Clone, Copy, Debug)]
pub enum SendOutcome {
    HopAccepted,
    OutcomeUnknown,
    DefinitelyNotSent,
}
impl Action {
    pub fn offer(peer: Peer, manifest: Manifest) -> Self {
        Self {
            peer,
            message: Message::Offers {
                manifests: vec![manifest],
                next: None,
            },
            _payload: None,
        }
    }
    /// Hold through encoding and transport completion. Reservation includes six
    /// bounded payload copies for the worker, application envelope and transport.
    pub fn payload_guard(&self) -> Option<PayloadReservation> {
        self._payload
            .as_ref()
            .map(|p| PayloadReservation(p.0.clone()))
    }
    pub fn send_token(&self) -> Option<SendToken> {
        match self.message {
            Message::Want {
                id,
                piece,
                offset,
                request,
            } => Some(SendToken {
                peer: self.peer,
                id,
                piece,
                offset,
                request,
            }),
            _ => None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct View {
    pub state: State,
    pub sources: usize,
    /// Distinct peers whose pieces were verified during this engine lifetime.
    pub verified_sources: usize,
    pub waiting_for_peers: bool,
    pub delivered: usize,
}
struct Pull {
    peer: Peer,
    request: [u8; 16],
    bytes: Vec<u8>,
    received: Vec<bool>,
    outstanding: BTreeMap<usize, BlockAttempt>,
    proof: Option<Vec<Hash>>,
}
struct BlockAttempt {
    deadline: u64,
    attempts: u8,
}
impl Pull {
    fn fill_window(&mut self, id: ShareId, piece: u32, out: &mut Vec<Action>) {
        for block in 0..self.received.len() {
            if self.outstanding.len() >= BLOCK_WINDOW {
                break;
            }
            if self.received[block] || self.outstanding.contains_key(&block) {
                continue;
            }
            self.outstanding.insert(
                block,
                BlockAttempt {
                    deadline: u64::MAX,
                    attempts: 0,
                },
            );
            out.push(Action {
                _payload: None,
                peer: self.peer,
                message: Message::Want {
                    id,
                    piece,
                    offset: (block * BLOCK_BYTES) as u32,
                    request: self.request,
                },
            });
        }
    }
}
struct Served {
    id: ShareId,
    piece: u32,
    proof: Vec<Hash>,
    bytes: Vec<u8>,
}

/// A bounded state machine. All times are supplied by the host, enabling fault
/// simulations without sleeps. The host calls `set_members` from GComs' verified
/// roster, never from an incoming application record.
pub struct Engine {
    pub cache: Cache,
    members: BTreeMap<[u8; 32], (Member, BTreeSet<Member>)>,
    sources: BTreeMap<ShareId, BTreeSet<Peer>>,
    verified_sources: BTreeMap<ShareId, BTreeSet<Peer>>,
    inventories: BTreeMap<(ShareId, Peer), Vec<bool>>,
    pulls: BTreeMap<(ShareId, u32), Pull>,
    backoff: BTreeMap<Peer, u64>,
    discovery: BTreeMap<Peer, u64>,
    refresh_at: u64,
    served: VecDeque<Served>,
    refresh_cursor: usize,
    receipt_cursor: usize,
    diagnostics: Diagnostics,
    payload_reserved: Arc<AtomicUsize>,
}
impl Engine {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            members: BTreeMap::new(),
            sources: BTreeMap::new(),
            verified_sources: BTreeMap::new(),
            inventories: BTreeMap::new(),
            pulls: BTreeMap::new(),
            backoff: BTreeMap::new(),
            discovery: BTreeMap::new(),
            refresh_at: 0,
            served: VecDeque::new(),
            refresh_cursor: 0,
            receipt_cursor: 0,
            diagnostics: Diagnostics::default(),
            payload_reserved: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub fn set_members(
        &mut self,
        channel: [u8; 32],
        own: Member,
        members: impl IntoIterator<Item = Member>,
    ) {
        let members: BTreeSet<_> = members.into_iter().collect();
        if members.contains(&own) {
            self.members.insert(channel, (own, members));
        } else {
            self.members.remove(&channel);
        }
        let authorized = |p: &Peer| {
            self.members
                .get(&p.channel)
                .is_some_and(|(own, roster)| roster.contains(&p.member) && own != &p.member)
        };
        self.discovery.retain(|p, _| authorized(p));
        self.inventories.retain(|(_, p), _| authorized(p));
        self.pulls.retain(|_, pull| authorized(&pull.peer));
        self.backoff.retain(|p, _| authorized(p));
        for sources in self.sources.values_mut() {
            sources.retain(&authorized);
        }
    }
    pub fn clear_members(&mut self) {
        self.members.clear();
        self.discovery.clear();
        self.sources.clear();
        self.inventories.clear();
        self.pulls.clear();
        self.served.clear();
        self.backoff.clear();
    }
    pub fn permits(&self, peer: Peer, scope: &Scope) -> bool {
        scope.channel == peer.channel
            && self
                .members
                .get(&peer.channel)
                .is_some_and(|(own, members)| {
                    members.contains(&peer.member)
                        && members.contains(own)
                        && peer.member != *own
                        && scope.permits(&peer.member)
                        && scope.permits(own)
                })
    }
    pub fn own_scope(&self, scope: &Scope) -> bool {
        self.members
            .get(&scope.channel)
            .is_some_and(|(own, members)| {
                members.contains(own)
                    && scope.permits(own)
                    && scope.participants.iter().all(|p| members.contains(p))
            })
    }
    pub fn views(&self) -> Vec<View> {
        self.cache
            .entries()
            .values()
            .map(|state| {
                let sources = self
                    .sources
                    .get(&state.manifest.id)
                    .map_or(0, BTreeSet::len);
                View {
                    state: state.clone(),
                    sources,
                    verified_sources: self
                        .verified_sources
                        .get(&state.manifest.id)
                        .map_or(0, BTreeSet::len),
                    waiting_for_peers: state.status == Status::Downloading
                        && !self.pulls.keys().any(|(id, _)| id == &state.manifest.id),
                    delivered: state.completed_by.len(),
                }
            })
            .collect()
    }
    pub fn accept(&mut self, id: ShareId, now: u64) -> Result<()> {
        if !self.own_scope(&self.cache.get(id)?.manifest.scope) {
            return Err(Error::Unauthorized);
        }
        if self.cache.get(id)?.status != Status::Downloading
            && self
                .cache
                .entries()
                .values()
                .filter(|s| s.status == Status::Downloading && self.own_scope(&s.manifest.scope))
                .count()
                >= ACTIVE_DOWNLOADS
        {
            return Err(Error::Quota);
        }
        self.cache.accept(id, now)?;
        self.refresh_at = 0;
        Ok(())
    }
    pub fn pause(&mut self, id: ShareId) -> Result<()> {
        self.cache.pause(id)?;
        self.pulls.retain(|(share, _), _| *share != id);
        Ok(())
    }
    pub fn cancel(&mut self, id: ShareId) -> Result<()> {
        self.cache.cancel(id)?;
        self.pulls.retain(|(share, _), _| *share != id);
        self.served.retain(|s| s.id != id);
        Ok(())
    }
    fn source(&mut self, id: ShareId, peer: Peer) {
        let sources = self.sources.entry(id).or_default();
        if sources.len() < MAX_PEERS {
            sources.insert(peer);
        }
    }
    pub fn action_allowed(&self, action: &Action) -> bool {
        if !self.permits(
            action.peer,
            &Scope {
                channel: action.peer.channel,
                participants: vec![],
            },
        ) {
            return false;
        }
        match &action.message {
            Message::Discover { .. } => true,
            Message::Offers { manifests, .. } => manifests.iter().all(|m| {
                self.permits(action.peer, &m.scope)
                    && self.cache.get(m.id).is_ok_and(|s| {
                        !matches!(
                            s.status,
                            Status::Cancelled | Status::Importing | Status::Failed
                        )
                    })
            }),
            Message::Want {
                id,
                piece,
                offset,
                request,
            } => {
                self.cache.get(*id).is_ok_and(|s| {
                    s.status == Status::Downloading && self.permits(action.peer, &s.manifest.scope)
                }) && self.pulls.get(&(*id, *piece)).is_some_and(|p| {
                    p.peer == action.peer
                        && p.request == *request
                        && p.outstanding
                            .contains_key(&(*offset as usize / BLOCK_BYTES))
                })
            }
            Message::Inventory { id, .. } => self.cache.get(*id).is_ok_and(|s| {
                s.status == Status::Downloading && self.permits(action.peer, &s.manifest.scope)
            }),
            Message::Data { id, .. } | Message::Have { id, .. } => {
                self.cache.get(*id).is_ok_and(|s| {
                    matches!(s.status, Status::Downloading | Status::Complete)
                        && self.permits(action.peer, &s.manifest.scope)
                })
            }
            Message::Complete { id, .. } => self.cache.get(*id).is_ok_and(|s| {
                s.status == Status::Complete && self.permits(action.peer, &s.manifest.scope)
            }),
            Message::Unavailable { id, .. } => self
                .cache
                .get(*id)
                .is_ok_and(|s| self.permits(action.peer, &s.manifest.scope)),
        }
    }
    pub fn receive(&mut self, peer: Peer, message: Message, now: u64) -> Result<Vec<Action>> {
        if !self.permits(
            peer,
            &Scope {
                channel: peer.channel,
                participants: vec![],
            },
        ) {
            return Err(Error::Unauthorized);
        }
        message.validate()?;
        let mut out = Vec::new();
        match message {
            Message::Discover { after } => {
                let manifests: Vec<_> = self
                    .cache
                    .entries()
                    .iter()
                    .filter(|(id, s)| {
                        after.is_none_or(|a| **id > a)
                            && self.permits(peer, &s.manifest.scope)
                            && !matches!(
                                s.status,
                                Status::Cancelled | Status::Importing | Status::Failed
                            )
                    })
                    .take(9)
                    .map(|(_, s)| s.manifest.clone())
                    .collect();
                let next = if manifests.len() > 8 {
                    Some(manifests[7].id)
                } else {
                    None
                };
                out.push(Action {
                    _payload: None,
                    peer,
                    message: Message::Offers {
                        manifests: manifests.into_iter().take(8).collect(),
                        next,
                    },
                });
            }
            Message::Offers { manifests, next } => {
                for manifest in manifests {
                    if !self.permits(peer, &manifest.scope) {
                        return Err(Error::Unauthorized);
                    }
                    let id = manifest.id;
                    self.cache.offer(manifest, now)?;
                    self.source(id, peer);
                }
                if let Some(after) = next {
                    out.push(Action {
                        _payload: None,
                        peer,
                        message: Message::Discover { after: Some(after) },
                    });
                }
            }
            Message::Inventory { id, start } => {
                let state = self.cache.get(id)?;
                if !self.permits(peer, &state.manifest.scope) {
                    return Err(Error::Unauthorized);
                }
                if start as usize > state.have.len() {
                    return Err(Error::Invalid("inventory offset"));
                }
                let end = (start as usize + INVENTORY_PAGE).min(state.have.len());
                let pieces = if matches!(state.status, Status::Downloading | Status::Complete) {
                    state.have[start as usize..end].to_vec()
                } else {
                    vec![false; end - start as usize]
                };
                out.push(Action {
                    _payload: None,
                    peer,
                    message: Message::Have { id, start, pieces },
                });
            }
            Message::Have { id, start, pieces } => {
                let state = self.cache.get(id)?;
                if !self.permits(peer, &state.manifest.scope) {
                    return Err(Error::Unauthorized);
                }
                if start as usize + pieces.len() > state.have.len() {
                    return Err(Error::Invalid("inventory bounds"));
                }
                let total = state.have.len();
                let downloading = state.status == Status::Downloading;
                self.source(id, peer);
                if downloading && self.sources.get(&id).is_some_and(|s| s.contains(&peer)) {
                    let inventory = self
                        .inventories
                        .entry((id, peer))
                        .or_insert_with(|| vec![false; total]);
                    inventory[start as usize..start as usize + pieces.len()]
                        .copy_from_slice(&pieces);
                    let next = start as usize + pieces.len();
                    if !pieces.is_empty() && next < total {
                        out.push(Action {
                            _payload: None,
                            peer,
                            message: Message::Inventory {
                                id,
                                start: next as u32,
                            },
                        });
                    }
                }
            }
            Message::Want {
                id,
                piece,
                offset,
                request,
            } => {
                let state = self.cache.get(id)?;
                if !self.permits(peer, &state.manifest.scope) {
                    return Err(Error::Unauthorized);
                }
                let available = matches!(state.status, Status::Downloading | Status::Complete)
                    && state.have.get(piece as usize).copied().unwrap_or(false);
                if !available {
                    out.push(Action {
                        _payload: None,
                        peer,
                        message: Message::Unavailable { id, request },
                    });
                    return Ok(out);
                }
                let length = state.manifest.cipher_len(piece)?;
                if offset as usize >= length || !(offset as usize).is_multiple_of(BLOCK_BYTES) {
                    return Err(Error::Invalid("block offset"));
                }
                if !self.served.iter().any(|s| s.id == id && s.piece == piece) {
                    while !self.served.is_empty()
                        && (self.served.len() == PIPELINE
                            || self.buffered_bytes() + length > PAYLOAD_BUDGET)
                    {
                        self.served.pop_front();
                    }
                    if self.buffered_bytes() + length > PAYLOAD_BUDGET {
                        return Ok(out);
                    }
                    let (proof, bytes) = self.cache.read_piece(id, piece)?;
                    self.served.push_back(Served {
                        id,
                        piece,
                        proof,
                        bytes,
                    });
                }
                let end = (offset as usize + BLOCK_BYTES).min(length);
                let reserved = (end - offset as usize + 1024) * 6;
                if self.buffered_bytes() + reserved > PAYLOAD_BUDGET {
                    return Ok(out);
                }
                self.payload_reserved.fetch_add(reserved, Ordering::AcqRel);
                let reservation = PayloadReservation(Arc::new(ReservedPayload {
                    counter: self.payload_reserved.clone(),
                    bytes: reserved,
                }));
                let served = self
                    .served
                    .iter()
                    .find(|s| s.id == id && s.piece == piece)
                    .unwrap();
                out.push(Action {
                    _payload: Some(reservation),
                    peer,
                    message: Message::Data {
                        id,
                        piece,
                        offset,
                        request,
                        proof: served.proof.clone(),
                        bytes: served.bytes[offset as usize..end].to_vec(),
                    },
                });
            }
            Message::Data {
                id,
                piece,
                offset,
                request,
                proof,
                bytes,
            } => {
                let state = self.cache.get(id)?;
                if !self.permits(peer, &state.manifest.scope) {
                    return Err(Error::Unauthorized);
                }
                let length = state.manifest.cipher_len(piece)?;
                let Some(pull) = self.pulls.get_mut(&(id, piece)) else {
                    return Ok(out);
                };
                if pull.peer != peer
                    || pull.request != request
                    || offset as usize >= length
                    || !(offset as usize).is_multiple_of(BLOCK_BYTES)
                {
                    return Ok(out);
                }
                let block = offset as usize / BLOCK_BYTES;
                if pull.received[block] || !pull.outstanding.contains_key(&block) {
                    return Ok(out);
                }
                if bytes.len() != BLOCK_BYTES.min(length - offset as usize)
                    || proof.len() > 16
                    || pull.proof.as_ref().is_some_and(|p| p != &proof)
                {
                    self.diagnostics.rejected_pieces =
                        self.diagnostics.rejected_pieces.saturating_add(1);
                    self.pulls.remove(&(id, piece));
                    self.backoff.insert(peer, now + 120);
                    return Err(Error::Invalid("piece response"));
                }
                pull.proof = Some(proof);
                self.diagnostics.received_blocks =
                    self.diagnostics.received_blocks.saturating_add(1);
                self.diagnostics.received_bytes = self
                    .diagnostics
                    .received_bytes
                    .saturating_add(bytes.len() as u64);
                pull.bytes[offset as usize..offset as usize + bytes.len()].copy_from_slice(&bytes);
                pull.received[block] = true;
                pull.outstanding.remove(&block);
                if pull.received.iter().all(|received| *received) {
                    let pull = self.pulls.remove(&(id, piece)).unwrap();
                    let retained = match self.cache.put(
                        id,
                        piece,
                        &pull.bytes,
                        pull.proof.as_ref().unwrap(),
                        now,
                    ) {
                        Ok(retained) => retained,
                        Err(error) => {
                            self.diagnostics.rejected_pieces =
                                self.diagnostics.rejected_pieces.saturating_add(1);
                            self.backoff.insert(peer, now + 120);
                            if matches!(error, Error::Io(_) | Error::Quota) {
                                self.cache
                                    .failure(id, format!("Could not retain piece: {error}"))?;
                            }
                            return Err(error);
                        }
                    };
                    if retained {
                        let sources = self.verified_sources.entry(id).or_default();
                        if sources.len() < MAX_PEERS {
                            sources.insert(peer);
                        }
                        self.diagnostics.verified_pieces =
                            self.diagnostics.verified_pieces.saturating_add(1);
                    }
                    let state = self.cache.get(id)?;
                    if state.status == Status::Complete {
                        if let Some(sources) = self.sources.get(&id) {
                            for source in sources {
                                out.push(Action {
                                    _payload: None,
                                    peer: *source,
                                    message: Message::Complete {
                                        id,
                                        sha256: state.manifest.sha256,
                                    },
                                });
                            }
                        }
                    }
                } else {
                    pull.fill_window(id, piece, &mut out);
                }
            }
            Message::Unavailable { id, request } => {
                self.pulls.retain(|(share, _), p| {
                    !(*share == id && p.peer == peer && p.request == request)
                });
                self.inventories.remove(&(id, peer));
                self.backoff.insert(peer, now + REQUEST_TIMEOUT);
            }
            Message::Complete { id, sha256 } => {
                let state = self.cache.get(id)?;
                if !self.permits(peer, &state.manifest.scope) || sha256 != state.manifest.sha256 {
                    return Err(Error::Unauthorized);
                }
                self.cache.receipt(id, peer.member)?;
            }
        }
        Ok(out)
    }
    pub fn tick(&mut self, now: u64) -> Result<Vec<Action>> {
        self.cache.expire(now)?;
        self.verified_sources
            .retain(|id, _| self.cache.entries().contains_key(id));
        let revoked: Vec<_> = self
            .cache
            .entries()
            .iter()
            .filter(|(_, s)| s.status == Status::Downloading && !self.own_scope(&s.manifest.scope))
            .map(|(id, _)| *id)
            .collect();
        for id in revoked {
            self.cache.failure(
                id,
                "Conversation membership unavailable; transfer paused".into(),
            )?;
        }
        self.sources
            .retain(|id, _| self.cache.entries().contains_key(id));
        self.pulls.retain(|(id, _), _| {
            self.cache
                .get(*id)
                .is_ok_and(|s| s.status == Status::Downloading)
        });
        self.inventories.retain(|(id, _), _| {
            self.cache
                .get(*id)
                .is_ok_and(|s| s.status == Status::Downloading)
        });
        let mut out = Vec::new();
        for (channel, (own, members)) in &self.members {
            for member in members.iter().filter(|m| *m != own).take(MAX_PEERS) {
                let peer = Peer {
                    channel: *channel,
                    member: *member,
                };
                if self.discovery.len() >= MAX_PEERS && !self.discovery.contains_key(&peer) {
                    continue;
                }
                let at = self.discovery.entry(peer).or_default();
                if *at <= now && out.len() < 8 {
                    *at = now + 60;
                    out.push(Action {
                        _payload: None,
                        peer,
                        message: Message::Discover { after: None },
                    });
                }
            }
        }
        if self.refresh_at <= now {
            self.refresh_at = now + 30;
            let mut completed = Vec::new();
            for ((id, state), sources) in self
                .cache
                .entries()
                .iter()
                .filter_map(|entry| self.sources.get(entry.0).map(|s| (entry, s)))
            {
                if state.status == Status::Downloading {
                    // Rotate candidate discovery so unavailable early advertisers
                    // cannot prevent a later healthy cache from being selected.
                    let peers: Vec<_> = sources
                        .iter()
                        .filter(|p| self.backoff.get(p).is_none_or(|at| *at <= now))
                        .collect();
                    if !peers.is_empty() {
                        for n in 0..MAX_SOURCES.min(peers.len()) {
                            let peer = *peers[(self.refresh_cursor + n) % peers.len()];
                            out.push(Action {
                                _payload: None,
                                peer,
                                message: Message::Inventory { id: *id, start: 0 },
                            });
                        }
                    }
                } else if state.status == Status::Complete {
                    for peer in sources {
                        completed.push(Action {
                            _payload: None,
                            peer: *peer,
                            message: Message::Complete {
                                id: *id,
                                sha256: state.manifest.sha256,
                            },
                        });
                    }
                }
            }
            if !completed.is_empty() {
                for n in 0..8.min(completed.len()) {
                    let action = &completed[(self.receipt_cursor + n) % completed.len()];
                    out.push(Action {
                        _payload: None,
                        peer: action.peer,
                        message: action.message.clone(),
                    });
                }
                self.receipt_cursor = (self.receipt_cursor + 8) % completed.len();
            }
            self.refresh_cursor = self.refresh_cursor.wrapping_add(MAX_SOURCES);
        }
        let expired: Vec<_> = self
            .pulls
            .iter()
            .filter(|(_, p)| p.outstanding.values().any(|block| block.deadline <= now))
            .map(|(k, _)| *k)
            .collect();
        for (id, piece) in expired {
            self.diagnostics.retries = self.diagnostics.retries.saturating_add(1);
            let pull = self.pulls.get_mut(&(id, piece)).unwrap();
            if pull
                .outstanding
                .values()
                .any(|block| block.deadline <= now && block.attempts >= 2)
            {
                self.backoff.insert(pull.peer, now + 120);
                self.pulls.remove(&(id, piece));
            } else {
                for (&block, attempt) in &mut pull.outstanding {
                    if attempt.deadline > now {
                        continue;
                    }
                    attempt.attempts += 1;
                    attempt.deadline = u64::MAX; // host owns this queued attempt until completion
                    out.push(Action {
                        _payload: None,
                        peer: pull.peer,
                        message: Message::Want {
                            id,
                            piece,
                            offset: (block * BLOCK_BYTES) as u32,
                            request: pull.request,
                        },
                    });
                }
            }
        }
        for (id, state) in self
            .cache
            .entries()
            .iter()
            .filter(|(_, s)| s.status == Status::Downloading)
            .take(ACTIVE_DOWNLOADS)
        {
            while self.pulls.keys().filter(|(share, _)| share == id).count() < PIPELINE {
                let mut candidates = Vec::new();
                for (i, have) in state.have.iter().enumerate() {
                    if *have || self.pulls.contains_key(&(*id, i as u32)) {
                        continue;
                    }
                    let peers: Vec<_> = self
                        .inventories
                        .iter()
                        .filter(|((share, peer), map)| {
                            share == id
                                && map.get(i) == Some(&true)
                                && self.permits(*peer, &state.manifest.scope)
                                && self.backoff.get(peer).is_none_or(|at| *at <= now)
                        })
                        .map(|((_, p), _)| *p)
                        .collect();
                    if !peers.is_empty() {
                        candidates.push((peers.len(), i as u32, peers));
                    }
                }
                candidates.sort_by_key(|(rarity, index, _)| (*rarity, *index));
                let Some((_, piece, peers)) = candidates.into_iter().next() else {
                    break;
                };
                let peer = *peers
                    .iter()
                    .min_by_key(|p| self.pulls.values().filter(|pull| pull.peer == **p).count())
                    .unwrap();
                let request = rand::random();
                let length = state.manifest.cipher_len(piece)?;
                if self.buffered_bytes() + length > PAYLOAD_BUDGET {
                    break;
                }
                let mut pull = Pull {
                    peer,
                    request,
                    bytes: vec![0; length],
                    received: vec![false; length.div_ceil(BLOCK_BYTES)],
                    outstanding: BTreeMap::new(),
                    proof: None,
                };
                pull.fill_window(*id, piece, &mut out);
                self.pulls.insert((*id, piece), pull);
            }
        }
        Ok(out)
    }
    /// Payload buffers remain bounded independently of total file sizes.
    pub fn buffered_bytes(&self) -> usize {
        self.payload_reserved.load(Ordering::Acquire)
            + self
                .pulls
                .values()
                .map(|p| p.bytes.capacity())
                .sum::<usize>()
            + self
                .served
                .iter()
                .map(|s| s.bytes.capacity())
                .sum::<usize>()
    }
    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            buffered_bytes: self.buffered_bytes(),
            pending_pulls: self.pulls.len(),
            ..self.diagnostics
        }
    }

    /// Call once when a queued Want finishes its real transport attempt, or is
    /// discarded before sending. A local wrapper timeout is not completion.
    pub fn send_finished(&mut self, token: Option<SendToken>, outcome: SendOutcome, now: u64) {
        match outcome {
            SendOutcome::HopAccepted => {
                self.diagnostics.hop_accepted = self.diagnostics.hop_accepted.saturating_add(1)
            }
            SendOutcome::OutcomeUnknown => {
                self.diagnostics.outcome_unknown =
                    self.diagnostics.outcome_unknown.saturating_add(1)
            }
            SendOutcome::DefinitelyNotSent => {
                self.diagnostics.not_sent = self.diagnostics.not_sent.saturating_add(1)
            }
        }
        let Some(token) = token else { return };
        let Some(pull) = self.pulls.get_mut(&(token.id, token.piece)) else {
            return;
        };
        if pull.peer != token.peer || pull.request != token.request {
            return;
        }
        if let Some(block) = pull
            .outstanding
            .get_mut(&(token.offset as usize / BLOCK_BYTES))
        {
            block.deadline = match outcome {
                SendOutcome::DefinitelyNotSent => now,
                _ => now.saturating_add(REQUEST_TIMEOUT * (1 << block.attempts)),
            };
        }
    }
}
