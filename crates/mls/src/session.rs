use crate::invite::{leaf_hash, verify_invite, Invite};
use crate::{MlsError, CHANNEL_MAX, GROUP_MAX, MAX_KEY_PACKAGE_BYTES};
use gcoms_crypto::IdentityKeypair;
use openmls::prelude::MlsGroupJoinConfig;
use openmls::prelude::ProtocolVersion;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageBundle,
    LeafNodeParameters, Member, MlsGroup, MlsGroupCreateConfig, SenderRatchetConfiguration,
    SignaturePublicKey,
};
use openmls::prelude::{MlsMessageIn, MlsMessageOut, StagedWelcome};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
use zeroize::Zeroize;

mod authority;

/// Domain separator for the channel group id (SPEC §9.2: the channel id is
/// the owner key fingerprint, never the key itself).
const GROUP_ID_DOMAIN: &[u8] = b"gc1/channel";

/// The MLS group id of a channel owned by `owner_public_key`.
pub fn channel_group_id(owner_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GROUP_ID_DOMAIN);
    hasher.update(owner_public_key);
    hasher.finalize().into()
}

macro_rules! channel_metadata_api {
    ($session:ty) => {
        impl $session {
            /// Opaque, bounded application metadata sealed with the MLS state.
            pub fn channel_metadata(&self) -> Result<Vec<u8>, MlsError> {
                self.ctx.channel_metadata()
            }
            /// The transport must authorize the authenticated sender before
            /// installing metadata, then checkpoint before publishing an event.
            pub fn set_channel_metadata(&mut self, bytes: &[u8]) -> Result<(), MlsError> {
                self.ctx.set_channel_metadata(bytes)
            }
            pub fn channel_owner(&self) -> Option<[u8; 32]> {
                self.ctx.owner_pseudonym
            }
            pub fn channel_admin(&self, member: [u8; 32]) -> bool {
                self.ctx.may_remove(Some(member))
            }
        }
    };
}
channel_metadata_api!(OwnerSession);
channel_metadata_api!(ChannelMember);

/// Upper bound on any single MLS wire we are willing to parse.
pub const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;

pub fn epoch_of_wire(wire: &[u8]) -> Option<u64> {
    use tls_codec::Deserialize as _;
    if wire.len() > MAX_WIRE_BYTES {
        return None;
    }
    let msg = MlsMessageIn::tls_deserialize_exact(wire).ok()?;
    let proto = msg.try_into_protocol_message().ok()?;
    Some(proto.epoch().as_u64())
}

pub fn pseudonym_of_key_package(wire: &[u8]) -> Option<[u8; 32]> {
    if wire.len() > MAX_KEY_PACKAGE_BYTES {
        return None;
    }
    let message = MlsMessageIn::tls_deserialize_exact(wire).ok()?;
    let openmls::framing::MlsMessageBodyIn::KeyPackage(key_package_in) = message.extract() else {
        return None;
    };
    let backend = OpenMlsRustCrypto::default();
    let key_package = key_package_in
        .validate(backend.crypto(), ProtocolVersion::default())
        .ok()?;
    if key_package.ciphersuite() != CIPHERSUITE {
        return None;
    }
    key_package
        .leaf_node()
        .signature_key()
        .as_slice()
        .try_into()
        .ok()
}

pub enum ReceiveOutcome {
    Application { sender_index: u32, payload: Vec<u8> },
    CommitMerged { sender_index: u32 },
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMember {
    pub leaf_index: u32,
    pub pseudonym: [u8; 32],
    pub display_name: String,
}

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
pub const CIPHERSUITE_ID: u16 = CIPHERSUITE as u16;

fn ensure_ciphersuite(ciphersuite: Ciphersuite) -> Result<(), MlsError> {
    if ciphersuite == CIPHERSUITE {
        Ok(())
    } else {
        Err(MlsError::UnsupportedCiphersuite(ciphersuite as u16))
    }
}

pub fn ciphersuite_of_key_package(wire: &[u8]) -> Option<u16> {
    if wire.len() > MAX_KEY_PACKAGE_BYTES {
        return None;
    }
    let message = MlsMessageIn::tls_deserialize_exact(wire).ok()?;
    let openmls::framing::MlsMessageBodyIn::KeyPackage(key_package_in) = message.extract() else {
        return None;
    };
    let backend = OpenMlsRustCrypto::default();
    let key_package = key_package_in
        .validate(backend.crypto(), ProtocolVersion::default())
        .ok()?;
    Some(key_package.ciphersuite() as u16)
}

pub fn ciphersuite_of_welcome(wire: &[u8]) -> Option<u16> {
    let (wire, _) = authority::split_welcome(wire).ok()?;
    let message = MlsMessageIn::tls_deserialize_exact(wire).ok()?;
    let openmls::framing::MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return None;
    };
    Some(welcome.ciphersuite() as u16)
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .padding_size(128)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .padding_size(128)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn fresh_leaf(
    backend: &OpenMlsRustCrypto,
    display_name: &str,
) -> Result<(CredentialWithKey, SignatureKeyPair), MlsError> {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
    signer
        .store(backend.storage())
        .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
    let credential = BasicCredential::new(display_name.as_bytes().to_vec());
    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: SignaturePublicKey::from(signer.to_public_vec()),
        },
        signer,
    ))
}

struct Ctx {
    backend: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
    /// Leaf pseudonym of the channel owner. Only this leaf may commit
    /// removals (SPEC §8.4 "removal = the revocation mechanism, issued by the
    /// owner or delegated administrators"). `None` until learned from the
    /// Welcome's roster.
    owner_pseudonym: Option<[u8; 32]>,
    /// Leaves delegated administration through the authenticated directory.
    admin_pseudonyms: Vec<[u8; 32]>,
}

fn zeroize_storage(backend: &OpenMlsRustCrypto) {
    if let Ok(mut values) = backend.storage().values.write() {
        for (mut key, mut value) in values.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        zeroize_storage(&self.backend);
    }
}

impl Ctx {
    // Application state shares the existing sealed MLS checkpoint. Keeping it
    // in a reserved storage namespace makes a send/receive rollback atomic
    // with metadata, without changing old archive layouts or leaf identities.
    fn channel_metadata(&self) -> Result<Vec<u8>, MlsError> {
        let storage = self
            .backend
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Encoding)?;
        Ok(storage
            .get(b"gcoms/channel-metadata/v1".as_slice())
            .cloned()
            .unwrap_or_default())
    }

    fn set_channel_metadata(&self, bytes: &[u8]) -> Result<(), MlsError> {
        if bytes.len() > 16 * 1024 {
            return Err(MlsError::Encoding);
        }
        let mut storage = self
            .backend
            .storage()
            .values
            .write()
            .map_err(|_| MlsError::Encoding)?;
        if let Some(mut previous) =
            storage.insert(b"gcoms/channel-metadata/v1".to_vec(), bytes.to_vec())
        {
            previous.zeroize();
        }
        Ok(())
    }
    fn ensure_ciphersuite(&self) -> Result<(), MlsError> {
        ensure_ciphersuite(self.group.ciphersuite())
    }

    fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, MlsError> {
        self.ensure_ciphersuite()?;
        let msg = self
            .group
            .create_message(&self.backend, &self.signer, payload)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        msg.tls_serialize_detached().map_err(|_| MlsError::Encoding)
    }

    fn pseudonym_of_index(&self, index: u32) -> Option<[u8; 32]> {
        self.group
            .members()
            .find(|member| member.index.u32() == index)
            .and_then(|member| member.signature_key.as_slice().try_into().ok())
    }

    fn may_remove(&self, sender_pseudonym: Option<[u8; 32]>) -> bool {
        let Some(sender) = sender_pseudonym else {
            return false;
        };
        self.owner_pseudonym == Some(sender) || self.admin_pseudonyms.contains(&sender)
    }

    fn receive(&mut self, wire: &[u8]) -> Result<ReceiveOutcome, MlsError> {
        self.ensure_ciphersuite()?;
        if wire.len() > MAX_WIRE_BYTES {
            return Err(MlsError::Encoding);
        }
        let msg = MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| MlsError::Encoding)?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        let processed = self
            .group
            .process_message(&self.backend, protocol)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        let sender_idx = match processed.sender() {
            openmls::prelude::Sender::Member(i) => i.u32(),
            _ => u32::MAX,
        };
        // Resolve the sender leaf before the commit is merged: after a merge
        // the removed leaves (possibly the sender's peers) are gone.
        let sender_pseudonym = self.pseudonym_of_index(sender_idx);
        match processed.into_content() {
            openmls::prelude::ProcessedMessageContent::ApplicationMessage(am) => {
                Ok(ReceiveOutcome::Application {
                    sender_index: sender_idx,
                    payload: am.into_bytes(),
                })
            }
            openmls::prelude::ProcessedMessageContent::StagedCommitMessage(sc) => {
                // Membership revocation is an owner/admin privilege. A commit
                // from any other leaf that removes someone is discarded
                // without merging, so a single infiltrator cannot evict the
                // rest of the channel.
                if (sc.remove_proposals().next().is_some() || sc.add_proposals().next().is_some())
                    && !self.may_remove(sender_pseudonym)
                {
                    return Err(MlsError::Unauthorized);
                }
                if sc.self_removed() {
                    return Err(MlsError::Removed);
                }
                self.group
                    .merge_staged_commit(&self.backend, *sc)
                    .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
                Ok(ReceiveOutcome::CommitMerged {
                    sender_index: sender_idx,
                })
            }
            _ => Ok(ReceiveOutcome::Other),
        }
    }

    fn roster(&self) -> Vec<(u32, String)> {
        self.group
            .members()
            .map(|m: Member| {
                (
                    m.index.u32(),
                    String::from_utf8_lossy(m.credential.serialized_content()).to_string(),
                )
            })
            .collect()
    }

    fn roster_members(&self) -> Vec<RosterMember> {
        self.group
            .members()
            .filter_map(|member: Member| {
                Some(RosterMember {
                    leaf_index: member.index.u32(),
                    pseudonym: member.signature_key.as_slice().try_into().ok()?,
                    display_name: String::from_utf8_lossy(member.credential.serialized_content())
                        .to_string(),
                })
            })
            .collect()
    }

    fn pseudonym_for_name(&self, name: &str) -> Option<[u8; 32]> {
        self.group.members().find_map(|member| {
            (member.credential.serialized_content() == name.as_bytes())
                .then(|| member.signature_key.as_slice().try_into().ok())
                .flatten()
        })
    }

    fn own_pseudonym(&self) -> [u8; 32] {
        self.signer
            .to_public_vec()
            .try_into()
            .expect("the selected MLS suite has 32-byte Ed25519 leaf keys")
    }

    fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    fn update(&mut self) -> Result<Vec<u8>, MlsError> {
        self.ensure_ciphersuite()?;
        let (commit, _welcome, _group_info) = self
            .group
            .self_update(&self.backend, &self.signer, LeafNodeParameters::default())
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?
            .into_contents();
        let encoded = commit
            .tls_serialize_detached()
            .map_err(|_| MlsError::Encoding);
        if encoded.is_err() {
            self.group
                .clear_pending_commit(self.backend.storage())
                .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
            return encoded;
        }
        self.group
            .merge_pending_commit(&self.backend)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        encoded
    }
}

pub struct OwnerSession {
    ctx: Ctx,
    identity: IdentityKeypair,
    capacity: usize,
}

pub struct Admission {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

pub struct StagedAdmission {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

pub struct StagedRemoval {
    pub commit: Vec<u8>,
}

pub struct PreparedJoin {
    backend: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    key_package: KeyPackage,
}

pub struct ChannelMember {
    ctx: Ctx,
}

impl OwnerSession {
    pub fn create(
        identity: IdentityKeypair,
        display_name: &str,
        capacity: usize,
    ) -> Result<Self, MlsError> {
        let backend = OpenMlsRustCrypto::default();
        let (credential, signer) = fresh_leaf(&backend, display_name)?;
        let gid = channel_group_id(&identity.public_bytes());
        let group = MlsGroup::new_with_group_id(
            &backend,
            &signer,
            &create_config(),
            GroupId::from_slice(&gid),
            credential,
        )
        .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        ensure_ciphersuite(group.ciphersuite())?;
        let capacity = capacity.clamp(2, CHANNEL_MAX);
        let _ = GROUP_MAX;
        let own = signer
            .to_public_vec()
            .try_into()
            .map_err(|_| MlsError::Encoding)?;
        Ok(OwnerSession {
            ctx: Ctx {
                backend,
                signer,
                group,
                owner_pseudonym: Some(own),
                admin_pseudonyms: Vec::new(),
            },
            identity,
            capacity,
        })
    }

    pub fn channel_id(&self) -> Vec<u8> {
        self.identity.public_bytes()
    }

    pub fn stable_channel_id(&self) -> [u8; 32] {
        Sha256::digest(self.ctx.group.group_id().as_slice()).into()
    }

    pub fn owner_public_key(&self) -> Vec<u8> {
        self.identity.public_bytes()
    }

    pub fn sign_owner_metadata(&self, payload: &[u8]) -> Vec<u8> {
        self.identity.sign(payload)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn sign_invite_key_package(
        &self,
        key_package_bytes: &[u8],
        name: &str,
        caps: crate::Caps,
        ttl: u64,
    ) -> Invite {
        crate::invite::sign_invite(
            &self.identity,
            &leaf_hash(key_package_bytes),
            name,
            caps,
            ttl,
        )
    }

    pub fn admit(
        &mut self,
        invite: &Invite,
        key_package_bytes: &[u8],
    ) -> Result<Admission, MlsError> {
        let staged = self.stage_admit(invite, key_package_bytes)?;
        self.merge_pending()?;
        Ok(Admission {
            commit: staged.commit,
            welcome: staged.welcome,
        })
    }

    pub fn stage_admit(
        &mut self,
        invite: &Invite,
        key_package_bytes: &[u8],
    ) -> Result<StagedAdmission, MlsError> {
        if key_package_bytes.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(MlsError::Encoding);
        }
        verify_invite(invite).map_err(|_| MlsError::BadInvite)?;
        if invite.channel != self.channel_id() {
            return Err(MlsError::WrongChannel);
        }
        if leaf_hash(key_package_bytes) != invite.leaf {
            return Err(MlsError::LeafMismatch);
        }
        self.ctx
            .stage_admit(key_package_bytes, &invite.name, self.capacity)
    }

    pub fn remove(&mut self, member_id: [u8; 32]) -> Result<Vec<u8>, MlsError> {
        let staged = self.stage_remove(member_id)?;
        self.merge_pending()?;
        Ok(staged.commit)
    }

    pub fn stage_remove(&mut self, member_id: [u8; 32]) -> Result<StagedRemoval, MlsError> {
        self.ctx.stage_remove(member_id)
    }

    pub fn merge_pending(&mut self) -> Result<(), MlsError> {
        self.ctx
            .group
            .merge_pending_commit(&self.ctx.backend)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, MlsError> {
        self.ctx.send(payload)
    }

    pub fn update(&mut self) -> Result<Vec<u8>, MlsError> {
        self.ctx.update()
    }

    pub fn ciphersuite(&self) -> u16 {
        self.ctx.group.ciphersuite() as u16
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<(u32, Vec<u8>)>, MlsError> {
        match self.ctx.receive(wire)? {
            ReceiveOutcome::Application {
                sender_index,
                payload,
            } => Ok(Some((sender_index, payload))),
            _ => Ok(None),
        }
    }

    pub fn receive_outcome(&mut self, wire: &[u8]) -> Result<ReceiveOutcome, MlsError> {
        self.ctx.receive(wire)
    }

    pub fn roster(&self) -> Vec<(u32, String)> {
        self.ctx.roster()
    }

    pub fn roster_members(&self) -> Vec<RosterMember> {
        self.ctx.roster_members()
    }

    pub fn epoch(&self) -> u64 {
        self.ctx.epoch()
    }

    pub fn pseudonym_for_name(&self, name: &str) -> Option<[u8; 32]> {
        self.ctx.pseudonym_for_name(name)
    }

    pub fn own_pseudonym(&self) -> [u8; 32] {
        self.ctx.own_pseudonym()
    }

    /// Replace the set of leaves delegated administration.
    pub fn set_admins(&mut self, admins: Vec<[u8; 32]>) {
        self.ctx.admin_pseudonyms = admins;
    }
}

impl ChannelMember {
    pub fn prepare(display_name: &str) -> Result<PreparedJoin, MlsError> {
        let backend = OpenMlsRustCrypto::default();
        let (credential, signer) = fresh_leaf(&backend, display_name)?;
        let bundle: KeyPackageBundle = KeyPackage::builder()
            .build(CIPHERSUITE, &backend, &signer, credential)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        ensure_ciphersuite(bundle.key_package().ciphersuite())?;
        Ok(PreparedJoin {
            backend,
            signer,
            key_package: bundle.key_package().clone(),
        })
    }

    pub fn key_package_bytes(prepared: &PreparedJoin) -> Result<Vec<u8>, MlsError> {
        let encoded = MlsMessageOut::from(prepared.key_package.clone())
            .tls_serialize_detached()
            .map_err(|_| MlsError::Encoding)?;
        if encoded.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(MlsError::Encoding);
        }
        Ok(encoded)
    }

    pub fn prepared_pseudonym(prepared: &PreparedJoin) -> [u8; 32] {
        prepared
            .signer
            .to_public_vec()
            .try_into()
            .expect("the selected MLS suite has 32-byte Ed25519 leaf keys")
    }

    pub fn join(prepared: PreparedJoin, welcome: &[u8]) -> Result<Self, MlsError> {
        let (welcome, authority) = authority::split_welcome(welcome)?;
        let body = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|_| MlsError::Encoding)?
            .extract();
        let welcome_msg = match body {
            openmls::framing::MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Encoding),
        };
        ensure_ciphersuite(welcome_msg.ciphersuite())?;
        let staged =
            StagedWelcome::new_from_welcome(&prepared.backend, &join_config(), welcome_msg, None)
                .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        let group = staged
            .into_group(&prepared.backend)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        ensure_ciphersuite(group.ciphersuite())?;
        // The channel creator occupies leaf 0 for the life of the group: a
        // leaf is only ever added at the lowest free index and the owner is
        // never removed (removing it would end the channel).
        let owner_pseudonym = group
            .members()
            .find(|member| member.index.u32() == 0)
            .and_then(|member| member.signature_key.as_slice().try_into().ok());
        let mut member = ChannelMember {
            ctx: Ctx {
                backend: prepared.backend,
                signer: prepared.signer,
                group,
                owner_pseudonym,
                admin_pseudonyms: Vec::new(),
            },
        };
        authority::restore_join_authority(&mut member, authority)?;
        Ok(member)
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, MlsError> {
        self.ctx.send(payload)
    }

    pub fn update(&mut self) -> Result<Vec<u8>, MlsError> {
        self.ctx.update()
    }

    pub fn ciphersuite(&self) -> u16 {
        self.ctx.group.ciphersuite() as u16
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<(u32, Vec<u8>)>, MlsError> {
        match self.ctx.receive(wire)? {
            ReceiveOutcome::Application {
                sender_index,
                payload,
            } => Ok(Some((sender_index, payload))),
            _ => Ok(None),
        }
    }

    pub fn receive_outcome(&mut self, wire: &[u8]) -> Result<ReceiveOutcome, MlsError> {
        self.ctx.receive(wire)
    }

    /// Replace the set of leaves delegated administration (SPEC §9.2, one
    /// level of delegation). Sourced from the MLS-authenticated directory.
    pub fn set_admins(&mut self, admins: Vec<[u8; 32]>) {
        self.ctx.admin_pseudonyms = admins;
    }

    pub fn owner_pseudonym(&self) -> Option<[u8; 32]> {
        self.ctx.owner_pseudonym
    }

    pub fn roster(&self) -> Vec<(u32, String)> {
        self.ctx.roster()
    }

    pub fn roster_members(&self) -> Vec<RosterMember> {
        self.ctx.roster_members()
    }

    pub fn stable_channel_id(&self) -> [u8; 32] {
        Sha256::digest(self.ctx.group.group_id().as_slice()).into()
    }

    pub fn epoch(&self) -> u64 {
        self.ctx.epoch()
    }

    pub fn pseudonym_for_name(&self, name: &str) -> Option<[u8; 32]> {
        self.ctx.pseudonym_for_name(name)
    }

    pub fn own_pseudonym(&self) -> [u8; 32] {
        self.ctx.own_pseudonym()
    }
}

// ---------------------------------------------------------------------------
// client-persist: export/import of group state for clients that keep an
// encrypted-at-rest archive (SPEC §1: clients MAY archive locally).
// The exported bytes are key material; callers MUST encrypt them at rest.
// ---------------------------------------------------------------------------
/// Test-only hooks that emulate a misbehaving client.
#[doc(hidden)]
pub mod test_hooks {
    use super::*;

    /// Produce a Remove commit from a plain member, as a patched client
    /// would. Merges it locally so the forger's own view diverges.
    pub fn member_remove_commit(member: &mut ChannelMember, target: [u8; 32]) -> Vec<u8> {
        let index = member
            .ctx
            .group
            .members()
            .find(|m: &Member| m.signature_key.as_slice() == target)
            .map(|m| m.index)
            .expect("target is a member");
        let (commit, _welcome, _group_info) = member
            .ctx
            .group
            .remove_members(&member.ctx.backend, &member.ctx.signer, &[index])
            .expect("member can build a remove commit");
        let wire = commit.tls_serialize_detached().expect("serialize");
        member
            .ctx
            .group
            .merge_pending_commit(&member.ctx.backend)
            .expect("merge");
        wire
    }
}

#[cfg(feature = "client-persist")]
pub mod persist {
    //! Sealed export/import of group state for clients that keep an
    //! encrypted-at-rest archive (SPEC §1: clients MAY archive locally).
    //!
    //! Every archive is AES-256-GCM under a caller-supplied 32-byte wrapping
    //! key, with the archive kind, ciphersuite and group id bound as
    //! associated data. A tampered blob, a blob sealed for another group or
    //! kind, or a blob sealed under another key fails closed. The identity
    //! seed is never written: the owner signer is re-derived by the caller.
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use openmls::prelude::KeyPackageIn;
    use rand::RngCore;
    use zeroize::{ZeroizeOnDrop, Zeroizing};

    const MAGIC: &[u8; 6] = b"GCMLS3";
    const KIND_OWNER: u8 = 1;
    const KIND_MEMBER: u8 = 2;
    const KIND_PREPARED: u8 = 3;
    /// Sealed archives above this size are rejected before decryption.
    pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

    fn put16(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&(b.len() as u16).to_be_bytes());
        v.extend_from_slice(b);
    }

    fn take<'a>(buf: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
        let end = p.checked_add(n)?;
        let out = buf.get(*p..end)?;
        *p = end;
        Some(out)
    }

    fn take16<'a>(buf: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
        let l = u16::from_be_bytes([*buf.get(*p)?, *buf.get(*p + 1)?]) as usize;
        *p += 2;
        take(buf, p, l)
    }

    fn take32<'a>(buf: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
        let l = u32::from_be_bytes(buf.get(*p..*p + 4)?.try_into().ok()?) as usize;
        *p += 4;
        take(buf, p, l)
    }

    fn dump_storage(v: &mut Vec<u8>, backend: &OpenMlsRustCrypto) {
        let map = backend.storage().values.read().unwrap();
        v.extend_from_slice(&(map.len() as u32).to_be_bytes());
        for (k, val) in map.iter() {
            v.extend_from_slice(&(k.len() as u32).to_be_bytes());
            v.extend_from_slice(k);
            v.extend_from_slice(&(val.len() as u32).to_be_bytes());
            v.extend_from_slice(val);
        }
    }

    fn restore_storage(buf: &[u8], p: &mut usize) -> Result<OpenMlsRustCrypto, MlsError> {
        let backend = OpenMlsRustCrypto::default();
        let count = u32::from_be_bytes(
            take(buf, p, 4)
                .ok_or(MlsError::Encoding)?
                .try_into()
                .unwrap(),
        );
        {
            let mut map = backend.storage().values.write().unwrap();
            for _ in 0..count {
                let k = take32(buf, p).ok_or(MlsError::Encoding)?.to_vec();
                let val = take32(buf, p).ok_or(MlsError::Encoding)?.to_vec();
                map.insert(k, val);
            }
        }
        Ok(backend)
    }

    /// Decrypted archive body. Its storage copy is wiped on drop.
    struct Head {
        gid: Vec<u8>,
        signer_pub: Vec<u8>,
        capacity: usize,
        kp: Vec<u8>,
        owner_pseudonym: Option<[u8; 32]>,
        admin_pseudonyms: Vec<[u8; 32]>,
        backend: OpenMlsRustCrypto,
    }

    impl Drop for Head {
        fn drop(&mut self) {
            zeroize_storage(&self.backend);
            self.signer_pub.zeroize();
            self.kp.zeroize();
        }
    }

    impl ZeroizeOnDrop for Head {}

    fn aad(kind: u8, gid: &[u8]) -> Vec<u8> {
        let mut aad = b"gc1/sealed-mls/v3".to_vec();
        aad.push(kind);
        aad.extend_from_slice(&CIPHERSUITE_ID.to_be_bytes());
        put16(&mut aad, gid);
        aad
    }

    #[allow(clippy::too_many_arguments)]
    fn seal(
        wrapping_key: &[u8; 32],
        kind: u8,
        gid: &[u8],
        signer_pub: &[u8],
        capacity: usize,
        kp: &[u8],
        owner_pseudonym: Option<[u8; 32]>,
        admin_pseudonyms: &[[u8; 32]],
        backend: &OpenMlsRustCrypto,
    ) -> Result<Vec<u8>, MlsError> {
        let mut plain = Zeroizing::new(Vec::with_capacity(4096));
        put16(&mut plain, signer_pub);
        plain.extend_from_slice(&(capacity as u32).to_be_bytes());
        plain.extend_from_slice(&(kp.len() as u32).to_be_bytes());
        plain.extend_from_slice(kp);
        match owner_pseudonym {
            Some(pseudonym) => {
                plain.push(1);
                plain.extend_from_slice(&pseudonym);
            }
            None => plain.push(0),
        }
        plain.extend_from_slice(&(admin_pseudonyms.len() as u16).to_be_bytes());
        for admin in admin_pseudonyms {
            plain.extend_from_slice(admin);
        }
        dump_storage(&mut plain, backend);
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = Aes256Gcm::new_from_slice(wrapping_key)
            .expect("AES-256 key length")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad(kind, gid),
                },
            )
            .map_err(|_| MlsError::Encoding)?;
        let mut out = Vec::with_capacity(6 + 1 + 2 + 2 + gid.len() + 12 + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(kind);
        out.extend_from_slice(&CIPHERSUITE_ID.to_be_bytes());
        put16(&mut out, gid);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open(wrapping_key: &[u8; 32], buf: &[u8], want_kind: u8) -> Result<Head, MlsError> {
        if buf.len() > MAX_ARCHIVE_BYTES || buf.len() < 6 + 1 + 2 + 2 + 12 + 16 {
            return Err(MlsError::Encoding);
        }
        if &buf[..6] != MAGIC || buf[6] != want_kind {
            return Err(MlsError::Encoding);
        }
        let suite = u16::from_be_bytes([buf[7], buf[8]]);
        if suite != CIPHERSUITE_ID {
            return Err(MlsError::UnsupportedCiphersuite(suite));
        }
        let mut p = 9usize;
        let gid = take16(buf, &mut p).ok_or(MlsError::Encoding)?.to_vec();
        let nonce = take(buf, &mut p, 12).ok_or(MlsError::Encoding)?;
        let plain = Aes256Gcm::new_from_slice(wrapping_key)
            .expect("AES-256 key length")
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &buf[p..],
                    aad: &aad(want_kind, &gid),
                },
            )
            .map_err(|_| MlsError::Unauthorized)?;
        let plain = Zeroizing::new(plain);
        let buf: &[u8] = &plain;
        let mut p = 0usize;
        let signer_pub = take16(buf, &mut p).ok_or(MlsError::Encoding)?.to_vec();
        let capacity = u32::from_be_bytes(
            take(buf, &mut p, 4)
                .ok_or(MlsError::Encoding)?
                .try_into()
                .unwrap(),
        ) as usize;
        let kp = take32(buf, &mut p).ok_or(MlsError::Encoding)?.to_vec();
        let owner_pseudonym = match *buf.get(p).ok_or(MlsError::Encoding)? {
            1 => {
                p += 1;
                Some(
                    take(buf, &mut p, 32)
                        .ok_or(MlsError::Encoding)?
                        .try_into()
                        .unwrap(),
                )
            }
            0 => {
                p += 1;
                None
            }
            _ => return Err(MlsError::Encoding),
        };
        let n_admins = u16::from_be_bytes(
            take(buf, &mut p, 2)
                .ok_or(MlsError::Encoding)?
                .try_into()
                .unwrap(),
        ) as usize;
        if n_admins > CHANNEL_MAX {
            return Err(MlsError::Encoding);
        }
        let mut admin_pseudonyms = Vec::with_capacity(n_admins);
        for _ in 0..n_admins {
            admin_pseudonyms.push(
                take(buf, &mut p, 32)
                    .ok_or(MlsError::Encoding)?
                    .try_into()
                    .unwrap(),
            );
        }
        let backend = restore_storage(buf, &mut p)?;
        if p != buf.len() {
            return Err(MlsError::Encoding);
        }
        Ok(Head {
            gid,
            signer_pub,
            capacity,
            kp,
            owner_pseudonym,
            admin_pseudonyms,
            backend,
        })
    }

    fn ctx_from(head: &Head) -> Result<Ctx, MlsError> {
        let backend = OpenMlsRustCrypto::default();
        {
            let mut dst = backend.storage().values.write().unwrap();
            let src = head.backend.storage().values.read().unwrap();
            *dst = src.clone();
        }
        let group = MlsGroup::load(backend.storage(), &GroupId::from_slice(&head.gid))
            .map_err(|e| MlsError::OpenMls(format!("load: {e:?}")))?
            .ok_or_else(|| MlsError::OpenMls("group not in storage".into()))?;
        ensure_ciphersuite(group.ciphersuite())?;
        let signer = SignatureKeyPair::read(
            backend.storage(),
            &head.signer_pub,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| MlsError::OpenMls("signer not in storage".into()))?;
        Ok(Ctx {
            backend,
            signer,
            group,
            owner_pseudonym: head.owner_pseudonym,
            admin_pseudonyms: head.admin_pseudonyms.clone(),
        })
    }

    impl OwnerSession {
        /// Seal owner + group state under `wrapping_key`. The owner identity
        /// is not stored: supply it again to [`OwnerSession::restore`].
        pub fn persist(&self, wrapping_key: &[u8; 32]) -> Result<Vec<u8>, MlsError> {
            seal(
                wrapping_key,
                KIND_OWNER,
                self.ctx.group.group_id().as_slice(),
                &self.ctx.signer.to_public_vec(),
                self.capacity,
                &[],
                self.ctx.owner_pseudonym,
                &self.ctx.admin_pseudonyms,
                &self.ctx.backend,
            )
        }

        /// Restore from [`OwnerSession::persist`] bytes. `identity` must be
        /// the same owner identity the channel was created with: the archive
        /// group id is bound to its fingerprint.
        pub fn restore(
            wrapping_key: &[u8; 32],
            buf: &[u8],
            identity: IdentityKeypair,
        ) -> Result<Self, MlsError> {
            let head = open(wrapping_key, buf, KIND_OWNER)?;
            if head.gid.as_slice() != channel_group_id(&identity.public_bytes()) {
                return Err(MlsError::WrongChannel);
            }
            let ctx = ctx_from(&head)?;
            Ok(OwnerSession {
                ctx,
                identity,
                capacity: head.capacity,
            })
        }
    }

    impl ChannelMember {
        /// Seal member + group state under `wrapping_key`.
        pub fn persist(&self, wrapping_key: &[u8; 32]) -> Result<Vec<u8>, MlsError> {
            seal(
                wrapping_key,
                KIND_MEMBER,
                self.ctx.group.group_id().as_slice(),
                &self.ctx.signer.to_public_vec(),
                0,
                &[],
                self.ctx.owner_pseudonym,
                &self.ctx.admin_pseudonyms,
                &self.ctx.backend,
            )
        }

        /// Restore from [`ChannelMember::persist`] bytes.
        pub fn restore(wrapping_key: &[u8; 32], buf: &[u8]) -> Result<Self, MlsError> {
            let head = open(wrapping_key, buf, KIND_MEMBER)?;
            let ctx = ctx_from(&head)?;
            Ok(ChannelMember { ctx })
        }
    }

    impl PreparedJoin {
        /// Seal a prepared join (key package + signer + storage).
        pub fn persist(&self, wrapping_key: &[u8; 32]) -> Result<Vec<u8>, MlsError> {
            let kp = self
                .key_package
                .tls_serialize_detached()
                .map_err(|_| MlsError::Encoding)?;
            seal(
                wrapping_key,
                KIND_PREPARED,
                &[],
                &self.signer.to_public_vec(),
                0,
                &kp,
                None,
                &[],
                &self.backend,
            )
        }

        /// Restore from [`PreparedJoin::persist`] bytes.
        pub fn restore(wrapping_key: &[u8; 32], buf: &[u8]) -> Result<Self, MlsError> {
            let head = open(wrapping_key, buf, KIND_PREPARED)?;
            let kp_in =
                KeyPackageIn::tls_deserialize_exact(&head.kp).map_err(|_| MlsError::Encoding)?;
            let key_package = kp_in
                .validate(head.backend.crypto(), ProtocolVersion::default())
                .map_err(|e| MlsError::OpenMls(format!("kp validate: {e:?}")))?;
            ensure_ciphersuite(key_package.ciphersuite())?;
            let backend = OpenMlsRustCrypto::default();
            {
                let mut dst = backend.storage().values.write().unwrap();
                let src = head.backend.storage().values.read().unwrap();
                *dst = src.clone();
            }
            let signer = SignatureKeyPair::read(
                backend.storage(),
                &head.signer_pub,
                CIPHERSUITE.signature_algorithm(),
            )
            .ok_or_else(|| MlsError::OpenMls("signer not in storage".into()))?;
            Ok(PreparedJoin {
                backend,
                signer,
                key_package,
            })
        }
    }
}

#[cfg(all(test, feature = "client-persist"))]
mod persist_tests {
    use super::*;
    use gcoms_crypto::IdentityKeypair;

    const KEY: [u8; 32] = [0x4b; 32];

    fn owner_id() -> IdentityKeypair {
        IdentityKeypair::from_seed([9u8; 32])
    }

    fn owner_and_member() -> (OwnerSession, ChannelMember) {
        let mut owner = OwnerSession::create(owner_id(), "boss", 64).unwrap();
        let prepared = ChannelMember::prepare("newbie").unwrap();
        let kp = ChannelMember::key_package_bytes(&prepared).unwrap();
        let invite = owner.sign_invite_key_package(&kp, "newbie", crate::Caps::member(), 3600);
        let admission = owner.admit(&invite, &kp).unwrap();
        let member = ChannelMember::join(prepared, &admission.welcome).unwrap();
        (owner, member)
    }

    #[test]
    fn owner_restore_continues_group() {
        let (owner, mut member) = owner_and_member();
        let blob = owner.persist(&KEY).unwrap();
        let mut owner2 = OwnerSession::restore(&KEY, &blob, owner_id()).unwrap();
        assert_eq!(owner2.ciphersuite(), CIPHERSUITE_ID);
        assert_eq!(owner2.channel_id(), owner.channel_id());
        assert_eq!(owner2.roster().len(), 2);
        let wire = owner2.send(b"after-restore").unwrap();
        let got = member.receive(&wire).unwrap().unwrap();
        assert_eq!(got.1, b"after-restore");
        let wire2 = member.send(b"back").unwrap();
        let got2 = owner2.receive(&wire2).unwrap().unwrap();
        assert_eq!(got2.1, b"back");
    }

    #[test]
    fn member_restore_continues_group_and_keeps_owner_binding() {
        let (mut owner, member) = owner_and_member();
        let blob = member.persist(&KEY).unwrap();
        let mut member2 = ChannelMember::restore(&KEY, &blob).unwrap();
        assert_eq!(member2.ciphersuite(), CIPHERSUITE_ID);
        assert_eq!(member2.owner_pseudonym(), Some(owner.own_pseudonym()));
        let wire = owner.send(b"hello-again").unwrap();
        let got = member2.receive(&wire).unwrap().unwrap();
        assert_eq!(got.1, b"hello-again");
        assert_eq!(member2.roster().len(), 2);
    }

    #[test]
    fn prepared_restore_produces_same_key_package() {
        let prepared = ChannelMember::prepare("newbie").unwrap();
        let kp1 = ChannelMember::key_package_bytes(&prepared).unwrap();
        let blob = prepared.persist(&KEY).unwrap();
        let prepared2 = PreparedJoin::restore(&KEY, &blob).unwrap();
        let kp2 = ChannelMember::key_package_bytes(&prepared2).unwrap();
        assert_eq!(kp1, kp2);
        let mut owner = OwnerSession::create(owner_id(), "boss", 64).unwrap();
        let invite = owner.sign_invite_key_package(&kp2, "newbie", crate::Caps::member(), 3600);
        let admission = owner.admit(&invite, &kp2).unwrap();
        let _member = ChannelMember::join(prepared2, &admission.welcome).unwrap();
    }

    #[test]
    fn archive_is_authenticated_and_bound() {
        let (owner, member) = owner_and_member();
        let blob = owner.persist(&KEY).unwrap();
        // garbage / truncation
        assert!(OwnerSession::restore(&KEY, &[0u8; 16], owner_id()).is_err());
        let mut short = blob.clone();
        short.truncate(40);
        assert!(OwnerSession::restore(&KEY, &short, owner_id()).is_err());
        // wrong wrapping key
        assert!(matches!(
            OwnerSession::restore(&[0x11; 32], &blob, owner_id()),
            Err(MlsError::Unauthorized)
        ));
        // ciphertext tamper anywhere in the body
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            OwnerSession::restore(&KEY, &tampered, owner_id()),
            Err(MlsError::Unauthorized)
        ));
        // kind swap: an owner archive cannot be opened as a member archive
        let mut kind_swapped = blob.clone();
        kind_swapped[6] = 2;
        assert!(ChannelMember::restore(&KEY, &kind_swapped).is_err());
        // group id in the header is bound as AAD
        let mut gid_tampered = blob.clone();
        gid_tampered[12] ^= 1;
        assert!(OwnerSession::restore(&KEY, &gid_tampered, owner_id()).is_err());
        // ciphersuite byte cannot be downgraded
        let mut suite = blob.clone();
        suite[7..9].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(matches!(
            OwnerSession::restore(&KEY, &suite, owner_id()),
            Err(MlsError::UnsupportedCiphersuite(0x0001))
        ));
        // restoring under a different owner identity is refused
        let other = IdentityKeypair::from_seed([0x77; 32]);
        assert!(matches!(
            OwnerSession::restore(&KEY, &blob, other),
            Err(MlsError::WrongChannel)
        ));
        // a member archive keeps working under the right key
        let mblob = member.persist(&KEY).unwrap();
        assert!(ChannelMember::restore(&KEY, &mblob).is_ok());
        assert!(ChannelMember::restore(&[0x22; 32], &mblob).is_err());
    }

    #[test]
    fn archives_never_contain_the_identity_seed_or_plaintext_storage() {
        let (owner, _) = owner_and_member();
        let blob = owner.persist(&KEY).unwrap();
        let seed = [9u8; 32];
        assert!(!blob.windows(32).any(|w| w == seed));
        // The signer public key is the first plaintext field; it must not be
        // visible in the sealed blob either.
        let signer = owner.own_pseudonym();
        assert!(!blob.windows(32).any(|w| w == signer));
    }
}

impl Ctx {
    fn stage_admit(
        &mut self,
        key_package_bytes: &[u8],
        member_name: &str,
        capacity: usize,
    ) -> Result<StagedAdmission, MlsError> {
        if self.owner_pseudonym != Some(self.own_pseudonym()) {
            return Err(MlsError::Unauthorized);
        }
        if key_package_bytes.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(MlsError::Encoding);
        }
        if self.group.members().count() >= capacity {
            return Err(MlsError::GroupFull);
        }
        let kp_msg = MlsMessageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|_| MlsError::Encoding)?;
        let kp = match kp_msg.extract() {
            openmls::framing::MlsMessageBodyIn::KeyPackage(kp) => {
                let kp = kp
                    .validate(self.backend.crypto(), ProtocolVersion::default())
                    .map_err(|_| MlsError::BadInvite)?;
                ensure_ciphersuite(kp.ciphersuite())?;
                kp
            }
            _ => return Err(MlsError::Encoding),
        };
        if kp.leaf_node().credential().serialized_content() != member_name.as_bytes()
            || self
                .group
                .members()
                .any(|member| member.credential.serialized_content() == member_name.as_bytes())
        {
            return Err(MlsError::BadInvite);
        }
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&self.backend, &self.signer, &[kp])
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        let encoded = commit
            .tls_serialize_detached()
            .and_then(|commit| {
                welcome
                    .tls_serialize_detached()
                    .map(|welcome| StagedAdmission { commit, welcome })
            })
            .map_err(|_| MlsError::Encoding);
        if encoded.is_err() {
            self.group
                .clear_pending_commit(self.backend.storage())
                .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        }
        encoded.and_then(|mut staged| {
            staged.welcome = self.wrap_welcome(staged.welcome)?;
            Ok(staged)
        })
    }
    fn stage_remove(&mut self, member_id: [u8; 32]) -> Result<StagedRemoval, MlsError> {
        if !self.may_remove(Some(self.own_pseudonym())) || self.owner_pseudonym == Some(member_id) {
            return Err(MlsError::Unauthorized);
        }
        let index = self
            .group
            .members()
            .find(|m: &Member| m.signature_key.as_slice() == member_id)
            .map(|m| m.index)
            .ok_or(MlsError::MemberNotFound)?;
        let (commit, _welcome, _group_info) = self
            .group
            .remove_members(&self.backend, &self.signer, &[index])
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        let encoded = commit
            .tls_serialize_detached()
            .map(|commit| StagedRemoval { commit })
            .map_err(|_| MlsError::Encoding);
        if encoded.is_err() {
            self.group
                .clear_pending_commit(self.backend.storage())
                .map_err(|e| MlsError::OpenMls(format!("{e:?}")))?;
        }
        encoded
    }
}

#[cfg(test)]
mod zeroize_tests {
    use super::*;

    #[test]
    fn memory_storage_wipe_removes_serialized_secrets() {
        let backend = OpenMlsRustCrypto::default();
        backend
            .storage()
            .values
            .write()
            .unwrap()
            .insert(b"secret-key".to_vec(), b"secret-value".to_vec());
        zeroize_storage(&backend);
        assert!(backend.storage().values.read().unwrap().is_empty());
    }
}
