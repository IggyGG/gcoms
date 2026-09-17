use super::{protocol::*, Cache, Error, Result, State, Status};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_PEERS: usize = 64;
const MAX_SOURCES: usize = 4;
const ACTIVE_DOWNLOADS: usize = 2;
const PIPELINE: usize = 4;
const REQUEST_TIMEOUT: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub channel: [u8; 32],
    pub member: Member,
}
#[derive(Clone, Debug)]
pub struct Action {
    pub peer: Peer,
    pub message: Message,
}
#[derive(Clone, Debug)]
pub struct View {
    pub state: State,
    pub sources: usize,
    pub waiting_for_peers: bool,
    pub delivered: usize,
}
struct Pull {
    peer: Peer,
    request: [u8; 16],
    bytes: Vec<u8>,
    proof: Option<Vec<Hash>>,
    deadline: u64,
    attempts: u8,
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
    inventories: BTreeMap<(ShareId, Peer), Vec<bool>>,
    pulls: BTreeMap<(ShareId, u32), Pull>,
    backoff: BTreeMap<Peer, u64>,
    discovery: BTreeMap<Peer, u64>,
    refresh_at: u64,
    served: VecDeque<Served>,
    refresh_cursor: usize,
    receipt_cursor: usize,
}
impl Engine {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            members: BTreeMap::new(),
            sources: BTreeMap::new(),
            inventories: BTreeMap::new(),
            pulls: BTreeMap::new(),
            backoff: BTreeMap::new(),
            discovery: BTreeMap::new(),
            refresh_at: 0,
            served: VecDeque::new(),
            refresh_cursor: 0,
            receipt_cursor: 0,
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
            Message::Want { id, .. } | Message::Inventory { id, .. } => {
                self.cache.get(*id).is_ok_and(|s| {
                    s.status == Status::Downloading && self.permits(action.peer, &s.manifest.scope)
                })
            }
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
                    let (proof, bytes) = self.cache.read_piece(id, piece)?;
                    if self.served.len() == PIPELINE {
                        self.served.pop_front();
                    }
                    self.served.push_back(Served {
                        id,
                        piece,
                        proof,
                        bytes,
                    });
                }
                let served = self
                    .served
                    .iter()
                    .find(|s| s.id == id && s.piece == piece)
                    .unwrap();
                let end = (offset as usize + BLOCK_BYTES).min(length);
                out.push(Action {
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
                    || pull.bytes.len() != offset as usize
                {
                    return Ok(out);
                }
                if bytes.len() != BLOCK_BYTES.min(length - pull.bytes.len())
                    || proof.len() > 16
                    || pull.proof.as_ref().is_some_and(|p| p != &proof)
                {
                    self.pulls.remove(&(id, piece));
                    self.backoff.insert(peer, now + 120);
                    return Err(Error::Invalid("piece response"));
                }
                pull.proof = Some(proof);
                pull.bytes.extend(bytes);
                pull.deadline = now + REQUEST_TIMEOUT;
                pull.attempts = 0;
                if pull.bytes.len() == length {
                    let pull = self.pulls.remove(&(id, piece)).unwrap();
                    if let Err(error) =
                        self.cache
                            .put(id, piece, &pull.bytes, pull.proof.as_ref().unwrap(), now)
                    {
                        self.backoff.insert(peer, now + 120);
                        if matches!(error, Error::Io(_) | Error::Quota) {
                            self.cache
                                .failure(id, format!("Could not retain piece: {error}"))?;
                        }
                        return Err(error);
                    }
                    let state = self.cache.get(id)?;
                    if state.status == Status::Complete {
                        if let Some(sources) = self.sources.get(&id) {
                            for source in sources {
                                out.push(Action {
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
                    out.push(Action {
                        peer,
                        message: Message::Want {
                            id,
                            piece,
                            offset: pull.bytes.len() as u32,
                            request,
                        },
                    });
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
                                peer,
                                message: Message::Inventory { id: *id, start: 0 },
                            });
                        }
                    }
                } else if state.status == Status::Complete {
                    for peer in sources {
                        completed.push(Action {
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
                    out.push(completed[(self.receipt_cursor + n) % completed.len()].clone());
                }
                self.receipt_cursor = (self.receipt_cursor + 8) % completed.len();
            }
            self.refresh_cursor = self.refresh_cursor.wrapping_add(MAX_SOURCES);
        }
        let expired: Vec<_> = self
            .pulls
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        for (id, piece) in expired {
            let pull = self.pulls.get_mut(&(id, piece)).unwrap();
            if pull.attempts >= 2 {
                self.backoff.insert(pull.peer, now + 120);
                self.pulls.remove(&(id, piece));
            } else {
                pull.attempts += 1;
                pull.deadline = now + REQUEST_TIMEOUT * (1 << pull.attempts);
                out.push(Action {
                    peer: pull.peer,
                    message: Message::Want {
                        id,
                        piece,
                        offset: pull.bytes.len() as u32,
                        request: pull.request,
                    },
                });
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
                self.pulls.insert(
                    (*id, piece),
                    Pull {
                        peer,
                        request,
                        bytes: Vec::with_capacity(state.manifest.cipher_len(piece)?),
                        proof: None,
                        deadline: now + REQUEST_TIMEOUT,
                        attempts: 0,
                    },
                );
                out.push(Action {
                    peer,
                    message: Message::Want {
                        id: *id,
                        piece,
                        offset: 0,
                        request,
                    },
                });
            }
        }
        Ok(out)
    }
    /// Payload buffers remain bounded independently of total file sizes.
    pub fn buffered_bytes(&self) -> usize {
        self.pulls
            .values()
            .map(|p| p.bytes.capacity())
            .sum::<usize>()
            + self
                .served
                .iter()
                .map(|s| s.bytes.capacity())
                .sum::<usize>()
    }
}
