use super::*;

const MAX_LIST: usize = 1000;
const MODERATED: u8 = 1;
const INVITE_ONLY: u8 = 2;
const TOPIC_OPERATORS: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedRole {
    Owner = 1,
    Operator = 2,
    Voice = 3,
    Member = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedMode {
    Moderated = 1,
    InviteOnly = 2,
    TopicOperators = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedDiscovery {
    Public = 1,
    Private = 2,
    Secret = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedAccessList {
    Ban = 1,
    Exemption = 2,
    InviteException = 3,
}

/// Typed, ordered policy changes. Boolean wire values must be exactly 0 or 1.
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedPolicyChange {
    #[tls_codec(discriminant = 1)]
    Mode(HostedMode, u8),
    Role([u8; 32], HostedRole),
    AccessList(HostedAccessList, [u8; 32], u8),
    AccessCode(Option<[u8; 32]>),
    Capacity(u32),
    Discovery(HostedDiscovery),
    Transfer([u8; 32]),
    Close,
    Operator([u8; 32], u8),
    Voice([u8; 32], u8),
    Kick([u8; 32]),
    Leave,
}

/// Effective policy derived from the signed genesis and accepted control log.
/// Identity rules use channel-scoped keys. They cannot prevent a person from
/// acquiring an entirely new identity; no global user directory is introduced.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HostedRules {
    revision: u64,
    owner: [u8; 32],
    flags: u8,
    capacity: u32,
    discovery: HostedDiscovery,
    closed: u8,
    access_key: Option<[u8; 32]>,
    operators: Vec<[u8; 32]>,
    voices: Vec<[u8; 32]>,
    bans: Vec<[u8; 32]>,
    exemptions: Vec<[u8; 32]>,
    invite_exceptions: Vec<[u8; 32]>,
    pending_removals: Vec<[u8; 32]>,
}

fn set_entry(list: &mut Vec<[u8; 32]>, key: [u8; 32], enabled: bool) -> Result<(), MlsError> {
    match list.binary_search(&key) {
        Ok(index) if !enabled => {
            list.remove(index);
        }
        Err(index) if enabled => {
            if list.len() == MAX_LIST {
                return Err(MlsError::GroupFull);
            }
            list.insert(index, key);
        }
        _ => {}
    }
    Ok(())
}

impl HostedRules {
    pub(super) fn genesis(policy: &HostedPolicy) -> Self {
        Self {
            revision: 0,
            owner: policy.owner,
            flags: TOPIC_OPERATORS
                | if policy.public_join == 0 {
                    INVITE_ONLY
                } else {
                    0
                },
            capacity: policy.capacity,
            discovery: HostedDiscovery::Private,
            closed: 0,
            access_key: policy.access_key,
            operators: Vec::new(),
            voices: Vec::new(),
            bans: Vec::new(),
            exemptions: Vec::new(),
            invite_exceptions: Vec::new(),
            pending_removals: Vec::new(),
        }
    }

    pub fn pending_removals(&self) -> &[[u8; 32]] {
        &self.pending_removals
    }
    pub fn departing(&self, key: [u8; 32]) -> bool {
        self.pending_removals.binary_search(&key).is_ok()
    }
    pub(super) fn finish_removals(&mut self, removed: &[[u8; 32]]) {
        self.pending_removals.retain(|key| !removed.contains(key));
        self.operators.retain(|key| !removed.contains(key));
        self.voices.retain(|key| !removed.contains(key));
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
    pub fn discovery(&self) -> HostedDiscovery {
        self.discovery
    }
    pub fn closed(&self) -> bool {
        self.closed != 0
    }
    pub fn access_key(&self) -> Option<[u8; 32]> {
        self.access_key
    }
    pub fn mode(&self, mode: HostedMode) -> bool {
        self.flags & Self::bit(mode) != 0
    }
    pub fn list(&self, list: HostedAccessList) -> &[[u8; 32]] {
        match list {
            HostedAccessList::Ban => &self.bans,
            HostedAccessList::Exemption => &self.exemptions,
            HostedAccessList::InviteException => &self.invite_exceptions,
        }
    }
    pub fn role(&self, key: [u8; 32]) -> HostedRole {
        if key == self.owner {
            HostedRole::Owner
        } else if self.operators.binary_search(&key).is_ok() {
            HostedRole::Operator
        } else if self.voices.binary_search(&key).is_ok() {
            HostedRole::Voice
        } else {
            HostedRole::Member
        }
    }
    pub fn operator(&self, key: [u8; 32]) -> bool {
        matches!(self.role(key), HostedRole::Owner | HostedRole::Operator)
    }
    pub fn voiced(&self, key: [u8; 32]) -> bool {
        self.voices.binary_search(&key).is_ok()
    }
    pub fn banned(&self, key: [u8; 32]) -> bool {
        self.bans.binary_search(&key).is_ok() && self.exemptions.binary_search(&key).is_err()
    }
    pub fn invite_exception(&self, key: [u8; 32]) -> bool {
        self.invite_exceptions.binary_search(&key).is_ok()
    }
    /// Caller must separately verify that the key is in the current MLS roster.
    pub fn may_post(&self, key: [u8; 32]) -> bool {
        !self.closed()
            && self.pending_removals.is_empty()
            && !self.banned(key)
            && (!self.mode(HostedMode::Moderated) || self.role(key) != HostedRole::Member)
    }
    pub fn may_change_topic(&self, key: [u8; 32]) -> bool {
        !self.closed()
            && self.pending_removals.is_empty()
            && !self.banned(key)
            && (!self.mode(HostedMode::TopicOperators) || self.operator(key))
    }
    fn bit(mode: HostedMode) -> u8 {
        match mode {
            HostedMode::Moderated => MODERATED,
            HostedMode::InviteOnly => INVITE_ONLY,
            HostedMode::TopicOperators => TOPIC_OPERATORS,
        }
    }

    pub(super) fn transition(
        &self,
        actor: [u8; 32],
        change: &HostedPolicyChange,
        members: &[Member],
    ) -> Result<Self, MlsError> {
        let contains = |key: &[u8; 32]| members.iter().any(|m| m.signature_key.as_slice() == key);
        if self.closed()
            || !self.pending_removals.is_empty()
            || !contains(&actor)
            || (!matches!(change, HostedPolicyChange::Leave)
                && (self.banned(actor) || !self.operator(actor)))
        {
            return Err(MlsError::Unauthorized);
        }
        let mut next = self.clone();
        match change {
            HostedPolicyChange::Kick(target) => {
                if *target == self.owner || !contains(target) {
                    return Err(MlsError::Unauthorized);
                }
                set_entry(&mut next.pending_removals, *target, true)?;
            }
            HostedPolicyChange::Leave => {
                if actor == self.owner {
                    return Err(MlsError::Unauthorized);
                }
                set_entry(&mut next.pending_removals, actor, true)?;
            }
            HostedPolicyChange::Operator(target, enabled)
            | HostedPolicyChange::Voice(target, enabled) => {
                if *enabled > 1 {
                    return Err(MlsError::Encoding);
                }
                if !contains(target) {
                    return Err(MlsError::MemberNotFound);
                }
                if matches!(change, HostedPolicyChange::Operator(..)) {
                    if *target == self.owner {
                        return Err(MlsError::Unauthorized);
                    }
                    set_entry(&mut next.operators, *target, *enabled == 1)?;
                } else {
                    set_entry(&mut next.voices, *target, *enabled == 1)?;
                }
            }
            HostedPolicyChange::Mode(mode, enabled) => match enabled {
                0 => next.flags &= !Self::bit(*mode),
                1 => next.flags |= Self::bit(*mode),
                _ => return Err(MlsError::Encoding),
            },
            HostedPolicyChange::Role(target, role) => {
                if !contains(target) || *target == self.owner || *role == HostedRole::Owner {
                    return Err(MlsError::Unauthorized);
                }
                set_entry(&mut next.operators, *target, *role == HostedRole::Operator)?;
                set_entry(&mut next.voices, *target, *role == HostedRole::Voice)?;
            }
            HostedPolicyChange::AccessList(list, target, enabled) => {
                if *enabled > 1 {
                    return Err(MlsError::Encoding);
                }
                if *list == HostedAccessList::Ban && *target == self.owner {
                    return Err(MlsError::Unauthorized);
                }
                let entries = match list {
                    HostedAccessList::Ban => &mut next.bans,
                    HostedAccessList::Exemption => &mut next.exemptions,
                    HostedAccessList::InviteException => &mut next.invite_exceptions,
                };
                set_entry(entries, *target, *enabled == 1)?;
            }
            HostedPolicyChange::AccessCode(key) => next.access_key = *key,
            HostedPolicyChange::Capacity(limit) => {
                if !(2..=500).contains(limit) {
                    return Err(MlsError::Encoding);
                }
                next.capacity = *limit;
            }
            HostedPolicyChange::Discovery(discovery) => next.discovery = *discovery,
            HostedPolicyChange::Transfer(target) => {
                if actor != self.owner || !contains(target) || self.banned(*target) {
                    return Err(MlsError::Unauthorized);
                }
                next.owner = *target;
                set_entry(&mut next.operators, *target, false)?;
                set_entry(&mut next.voices, *target, false)?;
            }
            HostedPolicyChange::Close => {
                if actor != self.owner {
                    return Err(MlsError::Unauthorized);
                }
                next.closed = 1;
            }
        }
        next.revision = self.revision.checked_add(1).ok_or(MlsError::Encoding)?;
        Ok(next)
    }
}
