//! Display metadata never replaces an MLS leaf or a routing-directory key.
use super::ChannelRole;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_UPDATE_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ChannelChange {
    Topic(String),
    Nickname(String),
    Transfer([u8; 32]),
    Leave,
    Close,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (ChannelRole, ChannelRole) {
        let mut owner = gcoms_mls::OwnerSession::create(
            gcoms_crypto::IdentityKeypair::from_seed([42; 32]),
            "owner",
            64,
        )
        .unwrap();
        let prepared = gcoms_mls::ChannelMember::prepare("member").unwrap();
        let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let invite =
            owner.sign_invite_key_package(&package, "member", gcoms_mls::Caps::member(), 3600);
        let admission = owner.admit(&invite, &package).unwrap();
        let member = gcoms_mls::ChannelMember::join(prepared, &admission.welcome).unwrap();
        (ChannelRole::Owner(owner), ChannelRole::Member(member))
    }

    #[test]
    fn authenticated_metadata_preserves_leaf_identity_and_survives_checkpoint() {
        let (mut owner, mut member) = pair();
        let original_roster = member.roster_members();
        let original_id = member.channel_id();
        let member_id = member.own_pseudonym();
        let owner_id = owner.own_pseudonym();
        assert!(Metadata::prepare(&mut member, ChannelChange::Topic("forged".into())).is_err());
        let topic = Metadata::prepare(&mut owner, ChannelChange::Topic("Planning".into())).unwrap();
        Metadata::receive(&mut member, owner_id, &topic).unwrap();
        let nick =
            Metadata::prepare(&mut member, ChannelChange::Nickname("New name".into())).unwrap();
        Metadata::receive(&mut owner, member_id, &nick).unwrap();
        let stale = nick;
        let latest =
            Metadata::prepare(&mut member, ChannelChange::Nickname("Latest".into())).unwrap();
        Metadata::receive(&mut owner, member_id, &latest).unwrap();
        Metadata::receive(&mut owner, member_id, &stale).unwrap();
        assert_eq!(
            Metadata::read(&owner).unwrap().nickname(member_id),
            Some("Latest")
        );
        assert_eq!(member.roster_members(), original_roster);
        assert_eq!(member.channel_id(), original_id);
        let saved = member.checkpoint(&[19; 32]).unwrap();
        let reopened = member
            .restore_checkpoint(&[19; 32], &saved, || {
                panic!("member must not request an owner key")
            })
            .unwrap();
        assert_eq!(Metadata::read(&reopened).unwrap().topic(), "Planning");
        assert_eq!(
            Metadata::read(&reopened).unwrap().nickname(member_id),
            Some("Latest")
        );
        assert_eq!(reopened.roster_members(), original_roster);
        assert!(Metadata::receive(&mut owner, [99; 32], &latest).is_err());
        assert!(ChannelChange::Nickname("\nspoof".into())
            .validate()
            .is_err());
        assert!(ChannelChange::Topic("x".repeat(513)).validate().is_err());
    }

    #[test]
    fn newcomer_gets_existing_metadata_only_from_authenticated_administrator() {
        let (mut owner, mut member) = pair();
        Metadata::prepare(&mut owner, ChannelChange::Topic("Existing topic".into())).unwrap();
        Metadata::prepare(&mut owner, ChannelChange::Nickname("Host".into())).unwrap();
        let snapshot = Metadata::snapshot(&owner).unwrap();
        let owner_id = owner.own_pseudonym();
        let member_id = member.own_pseudonym();
        assert!(Metadata::receive(&mut member, member_id, &snapshot).is_err());
        assert!(member.channel_metadata().unwrap().is_empty());
        Metadata::receive(&mut member, owner_id, &snapshot).unwrap();
        assert_eq!(Metadata::read(&member).unwrap().topic(), "Existing topic");
        assert_eq!(
            Metadata::read(&member).unwrap().nickname(owner_id),
            Some("Host")
        );
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Value {
    sequence: u64,
    text: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Metadata {
    topic: Value,
    topic_actor: String,
    nicknames: BTreeMap<String, Value>,
    #[serde(default)]
    leaving: BTreeSet<String>,
    #[serde(default)]
    closed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    version: u8,
    sequence: u64,
    change: ChannelChange,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Packet {
    Update(Update),
    Ownership(String),
    // The authenticated channel administrator supplies existing public
    // display metadata to a new member; stable MLS identities never change.
    Snapshot(Metadata),
}

fn id(member: [u8; 32]) -> String {
    member.iter().map(|v| format!("{v:02x}")).collect()
}
impl ChannelChange {
    pub fn validate(&self) -> Result<(), String> {
        let (text, maximum, empty) = match self {
            Self::Transfer(_) | Self::Leave | Self::Close => return Ok(()),
            Self::Topic(text) => (text, 512, true),
            Self::Nickname(text) => (text, 64, false),
        };
        if text.len() > maximum
            || (!empty && text.trim().is_empty())
            || text.chars().any(char::is_control)
        {
            return Err(format!(
                "Use {}–{maximum} UTF-8 bytes without control characters",
                if empty { 0 } else { 1 }
            ));
        }
        Ok(())
    }
}
impl Metadata {
    pub(crate) fn read(role: &ChannelRole) -> Result<Self, String> {
        let bytes = role.channel_metadata().map_err(|e| e.to_string())?;
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_slice(&bytes).map_err(|_| "Invalid retained channel metadata".into())
    }
    pub(crate) fn topic(&self) -> &str {
        &self.topic.text
    }
    pub(crate) fn closed(&self) -> bool {
        self.closed
    }
    pub(crate) fn leaving(&self, member: [u8; 32]) -> bool {
        self.leaving.contains(&id(member))
    }
    pub(crate) fn pending_leave(&self, role: &ChannelRole) -> Option<[u8; 32]> {
        if self.closed {
            return None;
        }
        role.roster_members()
            .into_iter()
            .map(|m| m.pseudonym)
            .find(|member| Some(*member) != role.owner() && self.leaving(*member))
    }
    pub(crate) fn nickname(&self, member: [u8; 32]) -> Option<&str> {
        self.nicknames.get(&id(member)).map(|v| v.text.as_str())
    }
    pub(crate) fn prepare(
        role: &mut ChannelRole,
        change: ChannelChange,
    ) -> Result<Vec<u8>, String> {
        change.validate()?;
        if Self::read(role)?.closed {
            return Err("This channel is closed".into());
        }
        if let ChannelChange::Transfer(next) = change {
            let chain = role.propose_owner(next).map_err(|e| e.to_string())?;
            let packet =
                serde_json::to_vec(&Packet::Ownership(gcoms_transport::encode_b64url(&chain)))
                    .map_err(|_| "Channel ownership encoding failed")?;
            Self::receive(role, role.own_pseudonym(), &packet)?;
            return Ok(packet);
        }
        let metadata = Self::read(role)?;
        let actor = role.own_pseudonym();
        let previous = match &change {
            ChannelChange::Transfer(_) => unreachable!(),
            ChannelChange::Leave | ChannelChange::Close => 0,
            ChannelChange::Topic(_) => metadata.topic.sequence,
            ChannelChange::Nickname(_) => {
                metadata.nicknames.get(&id(actor)).map_or(0, |v| v.sequence)
            }
        };
        let update = Update {
            version: 1,
            sequence: previous
                .checked_add(1)
                .ok_or("Channel metadata counter exhausted")?,
            change,
        };
        let wire = serde_json::to_vec(&Packet::Update(update))
            .map_err(|_| "Channel metadata encoding failed")?;
        Self::receive(role, actor, &wire)?;
        Ok(wire)
    }
    pub(crate) fn receive(
        role: &mut ChannelRole,
        actor: [u8; 32],
        wire: &[u8],
    ) -> Result<(), String> {
        if wire.len() > MAX_UPDATE_BYTES {
            return Err("Channel metadata exceeds limit".into());
        }
        if Self::read(role)?.closed {
            return Err("This channel is closed".into());
        }
        let packet: Packet =
            serde_json::from_slice(wire).map_err(|_| "Invalid channel metadata update")?;
        if let Packet::Ownership(encoded) = packet {
            let chain =
                gcoms_transport::decode_b64url(&encoded).ok_or("Invalid ownership encoding")?;
            if gcoms_transport::encode_b64url(&chain) != encoded {
                return Err("Noncanonical ownership encoding".into());
            }
            return role.install_owner(actor, &chain).map_err(|e| e.to_string());
        }
        if let Packet::Snapshot(incoming) = packet {
            if !role.channel_admin(actor) {
                return Err("Only channel administrators can seed display metadata".into());
            }
            incoming.validate_snapshot(role)?;
            let mut metadata = Self::read(role)?;
            if (incoming.topic.sequence, &incoming.topic_actor)
                > (metadata.topic.sequence, &metadata.topic_actor)
            {
                metadata.topic = incoming.topic;
                metadata.topic_actor = incoming.topic_actor;
            }
            for (key, value) in incoming.nicknames {
                if metadata
                    .nicknames
                    .get(&key)
                    .is_none_or(|old| old.sequence < value.sequence)
                {
                    metadata.nicknames.insert(key, value);
                }
            }
            return role
                .set_channel_metadata(
                    &serde_json::to_vec(&metadata)
                        .map_err(|_| "Channel metadata encoding failed")?,
                )
                .map_err(|e| e.to_string());
        }
        let Packet::Update(update) = packet else {
            unreachable!()
        };
        if update.version != 1 || update.sequence == 0 {
            return Err("Unsupported channel metadata version or counter".into());
        }
        update.change.validate()?;
        if !role.roster_members().iter().any(|m| m.pseudonym == actor) {
            return Err("Unknown channel member".into());
        }
        let mut metadata = Self::read(role)?;
        let members = role.roster_members();
        metadata
            .leaving
            .retain(|key| members.iter().any(|m| id(m.pseudonym) == *key));
        match update.change {
            ChannelChange::Close => {
                if role.owner() != Some(actor) {
                    return Err("Only the channel owner can close it".into());
                }
                metadata.closed = true;
            }
            ChannelChange::Leave => {
                if role.owner() == Some(actor) {
                    return Err("Transfer ownership or close the channel before leaving".into());
                }
                metadata.leaving.insert(id(actor));
            }
            ChannelChange::Transfer(_) => {
                return Err("Ownership requires a signed delegation".into())
            }
            ChannelChange::Topic(text) => {
                if !role.channel_admin(actor) {
                    return Err(
                        "Only the channel owner or an administrator can change its topic".into(),
                    );
                }
                if (update.sequence, id(actor))
                    > (metadata.topic.sequence, metadata.topic_actor.clone())
                {
                    metadata.topic = Value {
                        sequence: update.sequence,
                        text,
                    };
                    metadata.topic_actor = id(actor);
                }
            }
            ChannelChange::Nickname(text) => {
                let members = role.roster_members();
                metadata
                    .nicknames
                    .retain(|key, _| members.iter().any(|m| id(m.pseudonym) == *key));
                if metadata
                    .nicknames
                    .get(&id(actor))
                    .is_none_or(|v| update.sequence > v.sequence)
                {
                    metadata.nicknames.insert(
                        id(actor),
                        Value {
                            sequence: update.sequence,
                            text,
                        },
                    );
                }
            }
        }
        let bytes =
            serde_json::to_vec(&metadata).map_err(|_| "Channel metadata encoding failed")?;
        role.set_channel_metadata(&bytes).map_err(|e| e.to_string())
    }

    fn validate_snapshot(&self, role: &ChannelRole) -> Result<(), String> {
        ChannelChange::Topic(self.topic.text.clone()).validate()?;
        let members = role.roster_members();
        if self.topic.sequence > 0
            && (self.topic_actor.len() != 64
                || !self.topic_actor.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err("Unknown topic authority".into());
        }
        for (key, value) in &self.nicknames {
            ChannelChange::Nickname(value.text.clone()).validate()?;
            if value.sequence == 0 || !members.iter().any(|m| id(m.pseudonym) == *key) {
                return Err("Unknown nickname identity".into());
            }
        }
        Ok(())
    }

    pub(crate) fn snapshot(role: &ChannelRole) -> Result<Vec<u8>, String> {
        let mut metadata = Self::read(role)?;
        let members = role.roster_members();
        metadata
            .nicknames
            .retain(|key, _| members.iter().any(|m| id(m.pseudonym) == *key));
        let wire = serde_json::to_vec(&Packet::Snapshot(metadata))
            .map_err(|_| "Channel metadata encoding failed")?;
        if wire.len() > MAX_UPDATE_BYTES {
            return Err("Channel metadata exceeds limit".into());
        }
        Ok(wire)
    }

    /// The successor retains its own exact encrypted announcement, so an
    /// offline member does not depend on the departing owner's outbox.
    pub(crate) fn ownership_snapshot(role: &ChannelRole) -> Result<Vec<u8>, String> {
        if !role.is_owner() {
            return Err("Only the current owner can announce its authority".into());
        }
        let chain = role.ownership_certificate().map_err(|e| e.to_string())?;
        if chain.is_empty() {
            return Err("No delegated authority".into());
        }
        serde_json::to_vec(&Packet::Ownership(gcoms_transport::encode_b64url(&chain)))
            .map_err(|_| "Channel ownership encoding failed".into())
    }
}
