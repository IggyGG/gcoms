//! Experimental hosted-channel admission primitives.
//!
//! The observer holds only OpenMLS public state. Admission is checked both by
//! that observer and by members, independent of the delivery service. This is a
//! separate profile: a legacy channel cannot opt in by receiving an external
//! commit. Transport, durable sequencing and policy updates are not supplied by
//! this module yet.

use crate::session::{CIPHERSUITE, MAX_WIRE_BYTES};
use crate::{MlsError, RosterMember};
use gcoms_crypto::{verify_signature, IdentityKeypair};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

const VERSION: u16 = 1;
const MAX_NAME: usize = 128;
const MAX_AUTHORITY: usize = 16 * 1024;
const POLICY_DOMAIN: &[u8] = b"gcoms/hosted/policy/v1";
const JOIN_DOMAIN: &[u8] = b"gcoms/hosted/join/v1";

fn mls(error: impl std::fmt::Debug) -> MlsError {
    MlsError::OpenMls(format!("{error:?}"))
}

fn channel_id(root: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"gcoms/hosted/channel/v1");
    hash.update(root);
    hash.finalize().into()
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && std::str::from_utf8(name).is_ok_and(|s| !s.chars().any(char::is_control))
}

/// Owner-signed immutable genesis policy. New revisions and moderation will
/// require authenticated ordered policy events, rather than replacing this
/// object with an unverified directory response.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HostedPolicy {
    version: u16,
    root: VLBytes,
    owner: [u8; 32],
    capacity: u32,
    public_join: u8,
    signature: VLBytes,
}

impl HostedPolicy {
    fn payload(&self) -> Vec<u8> {
        let mut bytes = POLICY_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&channel_id(self.root.as_slice()));
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.capacity.to_be_bytes());
        bytes.push(self.public_join);
        bytes
    }

    /// Stable hosted channel identifier, distinct from the legacy profile.
    pub fn channel_id(&self) -> [u8; 32] {
        channel_id(self.root.as_slice())
    }

    /// Encode the public signed policy; never contains private key material.
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.tls_serialize_detached()?)
    }

    /// Verify against a channel ID obtained from a trusted invitation or saved
    /// channel, not an ID supplied by the same untrusted directory response.
    pub fn decode(bytes: &[u8], expected_channel: [u8; 32]) -> Result<Self, MlsError> {
        if bytes.len() > MAX_AUTHORITY {
            return Err(MlsError::Encoding);
        }
        let policy = Self::tls_deserialize_exact(bytes)?;
        policy.verify(expected_channel)?;
        Ok(policy)
    }

    fn verify(&self, expected_channel: [u8; 32]) -> Result<(), MlsError> {
        if self.version != VERSION || !(2..=500).contains(&self.capacity) || self.public_join > 1 {
            return Err(MlsError::Encoding);
        }
        if self.channel_id() != expected_channel {
            return Err(MlsError::WrongChannel);
        }
        if !verify_signature(
            self.root.as_slice(),
            &self.payload(),
            self.signature.as_slice(),
        ) {
            return Err(MlsError::Unauthorized);
        }
        Ok(())
    }

    fn join_payload(&self, epoch: u64, leaf: &[u8], name: &[u8], expiry: u64) -> Vec<u8> {
        let mut bytes = JOIN_DOMAIN.to_vec();
        bytes.extend_from_slice(&Sha256::digest(self.payload()));
        bytes.extend_from_slice(&epoch.to_be_bytes());
        bytes.extend_from_slice(leaf);
        bytes.extend_from_slice(&(name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&expiry.to_be_bytes());
        bytes
    }

    /// Preauthorize this exact fresh leaf at one epoch. The service cannot
    /// change the leaf, name, policy, expiry or epoch, or issue its own permit.
    pub fn permit(
        &self,
        root: &IdentityKeypair,
        epoch: u64,
        leaf: [u8; 32],
        name: &str,
        expiry: u64,
    ) -> Result<JoinPermit, MlsError> {
        if root.public_bytes() != self.root.as_slice() || !valid_name(name.as_bytes()) {
            return Err(MlsError::Unauthorized);
        }
        Ok(JoinPermit {
            expiry,
            signature: root
                .sign(&self.join_payload(epoch, &leaf, name.as_bytes(), expiry))
                .into(),
        })
    }

    fn authorize(
        &self,
        epoch: u64,
        leaf: &[u8],
        name: &[u8],
        aad: &[u8],
        now: u64,
    ) -> Result<(), MlsError> {
        if leaf.len() != 32 || !valid_name(name) || aad.len() > MAX_AUTHORITY {
            return Err(MlsError::Encoding);
        }
        let permit = JoinPermit::tls_deserialize_exact(aad)?;
        if self.public_join == 1 && permit.expiry == 0 && permit.signature.as_slice().is_empty() {
            return Ok(());
        }
        if permit.expiry <= now {
            return Err(MlsError::Expired);
        }
        if !verify_signature(
            self.root.as_slice(),
            &self.join_payload(epoch, leaf, name, permit.expiry),
            permit.signature.as_slice(),
        ) {
            return Err(MlsError::Unauthorized);
        }
        Ok(())
    }
}

/// Public, epoch-bound proof of admission. Contains a signature, not a bearer
/// secret. OpenMLS binds it to the joiner's signature through commit AAD.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct JoinPermit {
    expiry: u64,
    signature: VLBytes,
}

impl JoinPermit {
    /// Only accepted by an explicitly public-join policy.
    pub fn public() -> Self {
        Self {
            expiry: 0,
            signature: Vec::new().into(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.tls_serialize_detached()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > MAX_AUTHORITY {
            return Err(MlsError::Encoding);
        }
        Ok(Self::tls_deserialize_exact(bytes)?)
    }
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .padding_size(128)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .padding_size(128)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn group_info(bytes: &[u8]) -> Result<VerifiableGroupInfo, MlsError> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(MlsError::Encoding);
    }
    let openmls::framing::MlsMessageBodyIn::GroupInfo(info) =
        MlsMessageIn::tls_deserialize_exact(bytes)?.extract()
    else {
        return Err(MlsError::Encoding);
    };
    if info.ciphersuite() != CIPHERSUITE {
        return Err(MlsError::UnsupportedCiphersuite(info.ciphersuite() as u16));
    }
    Ok(info)
}

fn protocol(bytes: &[u8]) -> Result<ProtocolMessage, MlsError> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(MlsError::Encoding);
    }
    MlsMessageIn::tls_deserialize_exact(bytes)?
        .try_into_protocol_message()
        .map_err(mls)
}

/// A newcomer creates and retains this private state before requesting a permit.
pub struct PreparedHostedJoin {
    backend: OpenMlsRustCrypto,
    signer: Option<SignatureKeyPair>,
    credential: CredentialWithKey,
}

impl Drop for PreparedHostedJoin {
    fn drop(&mut self) {
        crate::session::zeroize_storage(&self.backend);
    }
}

impl PreparedHostedJoin {
    pub fn new(name: &str) -> Result<Self, MlsError> {
        if !valid_name(name.as_bytes()) {
            return Err(MlsError::Encoding);
        }
        let backend = OpenMlsRustCrypto::default();
        let (credential, signer) = crate::session::fresh_leaf(&backend, name)?;
        Ok(Self {
            backend,
            signer: Some(signer),
            credential,
        })
    }

    pub fn member_id(&self) -> [u8; 32] {
        self.signer
            .as_ref()
            .expect("prepared signer")
            .to_public_vec()
            .try_into()
            .expect("Ed25519 key length")
    }

    /// Prepare a join from authenticated public state while all existing
    /// members may be offline. The returned session cannot send until the
    /// ordered service accepts the exact commit and `accept_join` is called.
    pub fn join(
        mut self,
        public: &HostedObserver,
        permit: &JoinPermit,
        now: u64,
    ) -> Result<(HostedSession, Vec<u8>), MlsError> {
        let aad = permit.encode()?;
        public.policy.authorize(
            public.epoch(),
            &self.member_id(),
            self.credential.credential.serialized_content(),
            &aad,
            now,
        )?;
        if public.group.members().count() >= public.policy.capacity as usize {
            return Err(MlsError::GroupFull);
        }
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config())
            .with_aad(aad)
            .build_group(
                &self.backend,
                group_info(&public.info)?,
                self.credential.clone(),
            )
            .map_err(mls)?
            .load_psks(self.backend.storage())
            .map_err(mls)?
            .build(
                self.backend.rand(),
                self.backend.crypto(),
                self.signer.as_ref().expect("prepared signer"),
                |_| true,
            )
            .map_err(mls)?
            .finalize(&self.backend)
            .map_err(mls)?;
        let (commit, _, info) = bundle.into_contents();
        let commit = commit.tls_serialize_detached()?;
        let info: MlsMessageOut = info.ok_or(MlsError::Encoding)?.into();
        let info = info.tls_serialize_detached()?;
        let session = HostedSession {
            ctx: crate::session::Ctx {
                backend: std::mem::take(&mut self.backend),
                signer: self.signer.take().expect("prepared signer"),
                group,
                owner_pseudonym: Some(public.policy.owner),
                admin_pseudonyms: Vec::new(),
            },
            policy: public.policy.clone(),
            pending_join: Some(PendingJoin {
                hash: Sha256::digest(&commit).into(),
                info,
            }),
        };
        Ok((session, commit))
    }
}

/// MLS member secrets stay in clients. Never instantiate this in the hosted
/// sequencer. Application messages remain encrypted despite public handshakes.
pub struct HostedSession {
    ctx: crate::session::Ctx,
    policy: HostedPolicy,
    pending_join: Option<PendingJoin>,
}

#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
struct PendingJoin {
    hash: [u8; 32],
    info: Vec<u8>,
}

#[cfg(feature = "client-persist")]
#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct HostedArchive {
    policy: HostedPolicy,
    pending: Option<PendingJoin>,
}

impl HostedSession {
    /// Seal member secrets and pending acceptance together. The wrapping key
    /// belongs to the client's encrypted profile, never the channel service.
    #[cfg(feature = "client-persist")]
    pub fn persist(&self, wrapping_key: &[u8; 32]) -> Result<Vec<u8>, MlsError> {
        let metadata = HostedArchive {
            policy: self.policy.clone(),
            pending: self.pending_join.clone(),
        }
        .tls_serialize_detached()?;
        crate::session::persist::seal_hosted(&self.ctx, wrapping_key, &metadata)
    }

    #[cfg(feature = "client-persist")]
    pub fn restore(
        wrapping_key: &[u8; 32],
        bytes: &[u8],
        expected_channel: [u8; 32],
    ) -> Result<Self, MlsError> {
        let (ctx, metadata) = crate::session::persist::restore_hosted(wrapping_key, bytes)?;
        let archive = HostedArchive::tls_deserialize_exact(metadata)?;
        archive.policy.verify(expected_channel)?;
        if ctx.group.group_id().as_slice() != expected_channel
            || ctx.owner_pseudonym != Some(archive.policy.owner)
        {
            return Err(MlsError::WrongChannel);
        }
        Ok(Self {
            ctx,
            policy: archive.policy,
            pending_join: archive.pending,
        })
    }
    pub fn create(
        root: &IdentityKeypair,
        name: &str,
        capacity: u32,
        public_join: bool,
    ) -> Result<Self, MlsError> {
        if !(2..=500).contains(&capacity) {
            return Err(MlsError::Encoding);
        }
        let mut prepared = PreparedHostedJoin::new(name)?;
        let mut policy = HostedPolicy {
            version: VERSION,
            root: root.public_bytes().into(),
            owner: prepared.member_id(),
            capacity,
            public_join: u8::from(public_join),
            signature: Vec::new().into(),
        };
        policy.signature = root.sign(&policy.payload()).into();
        let group = MlsGroup::new_with_group_id(
            &prepared.backend,
            prepared.signer.as_ref().expect("prepared signer"),
            &create_config(),
            GroupId::from_slice(&policy.channel_id()),
            prepared.credential.clone(),
        )
        .map_err(mls)?;
        Ok(Self {
            ctx: crate::session::Ctx {
                backend: std::mem::take(&mut prepared.backend),
                signer: prepared.signer.take().expect("prepared signer"),
                group,
                owner_pseudonym: Some(policy.owner),
                admin_pseudonyms: Vec::new(),
            },
            policy,
            pending_join: None,
        })
    }

    pub fn policy(&self) -> &HostedPolicy {
        &self.policy
    }
    pub fn epoch(&self) -> u64 {
        self.ctx.group.epoch().as_u64()
    }
    pub fn roster(&self) -> Vec<RosterMember> {
        self.ctx.roster_members()
    }

    /// Public snapshot submitted with the pending commit, allowing the service
    /// to atomically store a complete next epoch before acknowledging it.
    pub fn proposed_group_info(&self) -> Result<&[u8], MlsError> {
        self.pending_join
            .as_ref()
            .map(|p| p.info.as_slice())
            .ok_or(MlsError::Unauthorized)
    }

    /// Must follow authenticated durable acceptance of this exact commit.
    /// This is service acceptance, never evidence of recipient delivery.
    pub fn accept_join(&mut self, accepted_commit: &[u8]) -> Result<(), MlsError> {
        if self.pending_join.as_ref().map(|p| p.hash)
            != Some(Sha256::digest(accepted_commit).into())
        {
            return Err(MlsError::Unauthorized);
        }
        // OpenMLS finalizes the speculative local epoch in the builder. This
        // wrapper keeps sending/export disabled until durable acceptance.
        self.pending_join = None;
        Ok(())
    }

    pub fn export_group_info(&self) -> Result<Vec<u8>, MlsError> {
        if self.pending_join.is_some() {
            return Err(MlsError::Unauthorized);
        }
        Ok(self
            .ctx
            .group
            .export_group_info(self.ctx.backend.crypto(), &self.ctx.signer, true)
            .map_err(mls)?
            .tls_serialize_detached()?)
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, MlsError> {
        if self.pending_join.is_some() {
            return Err(MlsError::Unauthorized);
        }
        Ok(self
            .ctx
            .group
            .create_message(&self.ctx.backend, &self.ctx.signer, payload)
            .map_err(mls)?
            .tls_serialize_detached()?)
    }

    pub fn receive(&mut self, wire: &[u8], now: u64) -> Result<crate::ReceiveOutcome, MlsError> {
        if self.pending_join.is_some() {
            return Err(MlsError::Unauthorized);
        }
        let processed = self
            .ctx
            .group
            .process_message(&self.ctx.backend, protocol(wire)?)
            .map_err(mls)?;
        if let ProcessedMessageContent::StagedCommitMessage(_) = processed.content() {
            validate_join(&self.policy, self.ctx.group.members(), &processed, now)?;
        }
        let sender_index = match processed.sender() {
            Sender::Member(i) => i.u32(),
            _ => u32::MAX,
        };
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.ctx
                    .group
                    .merge_staged_commit(&self.ctx.backend, *commit)
                    .map_err(mls)?;
                Ok(crate::ReceiveOutcome::CommitMerged { sender_index })
            }
            ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(crate::ReceiveOutcome::Application {
                    sender_index,
                    payload: message.into_bytes(),
                })
            }
            _ => Err(MlsError::Unauthorized),
        }
    }
}

fn validate_join(
    policy: &HostedPolicy,
    members: impl Iterator<Item = Member>,
    processed: &ProcessedMessage,
    now: u64,
) -> Result<(), MlsError> {
    if !matches!(processed.sender(), Sender::NewMemberCommit) {
        return Err(MlsError::Unauthorized);
    }
    let ProcessedMessageContent::StagedCommitMessage(commit) = processed.content() else {
        return Err(MlsError::Unauthorized);
    };
    // Reject replacement/removal, PSKs and configuration changes hidden in a
    // joining commit. Admission authorizes one added member only.
    if commit
        .queued_proposals()
        .any(|p| !matches!(p.proposal(), Proposal::ExternalInit(_)))
    {
        return Err(MlsError::Unauthorized);
    }
    let leaf = commit
        .update_path_leaf_node()
        .ok_or(MlsError::Unauthorized)?;
    let mut count = 0;
    for member in members {
        count += 1;
        if member.credential.serialized_content() == leaf.credential().serialized_content() {
            return Err(MlsError::BadInvite);
        }
    }
    if count >= policy.capacity as usize {
        return Err(MlsError::GroupFull);
    }
    policy.authorize(
        processed.epoch().as_u64(),
        leaf.signature_key().as_slice(),
        leaf.credential().serialized_content(),
        processed.aad(),
        now,
    )
}

/// Delivery-service state: public ratchet tree, signed public policy and group
/// context only. No MLS member, signer, epoch secret or application decryption
/// method. Rebuild by replaying the accepted ordered commit log from genesis.
pub struct HostedObserver {
    backend: OpenMlsRustCrypto,
    group: PublicGroup,
    policy: HostedPolicy,
    info: Vec<u8>,
}

impl HostedObserver {
    /// Start from owner-signed policy and the owner's epoch-zero GroupInfo.
    /// Later snapshots must be verified by replay, not trusted as new genesis.
    pub fn new(
        policy: HostedPolicy,
        expected_channel: [u8; 32],
        info: &[u8],
    ) -> Result<Self, MlsError> {
        policy.verify(expected_channel)?;
        let observer = Self::from_info(policy, info)?;
        let members: Vec<_> = observer.group.members().collect();
        if observer.epoch() != 0
            || members.len() != 1
            || members[0].signature_key.as_slice() != observer.policy.owner
        {
            return Err(MlsError::Unauthorized);
        }
        Ok(observer)
    }

    fn from_info(policy: HostedPolicy, bytes: &[u8]) -> Result<Self, MlsError> {
        let info = group_info(bytes)?;
        if info.group_id().as_slice() != policy.channel_id() {
            return Err(MlsError::WrongChannel);
        }
        let tree = info
            .extensions()
            .ratchet_tree()
            .ok_or(MlsError::Encoding)?
            .ratchet_tree()
            .clone();
        let backend = OpenMlsRustCrypto::default();
        let (group, _) = PublicGroup::from_external(
            backend.crypto(),
            backend.storage(),
            tree,
            info,
            ProposalStore::new(),
        )
        .map_err(mls)?;
        Ok(Self {
            backend,
            group,
            policy,
            info: bytes.to_vec(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Validate a complete next epoch without mutating this observer. Persist
    /// the commit and GroupInfo atomically before installing the returned state
    /// and returning acceptance. A malformed snapshot cannot strand admission.
    pub fn stage_join(&self, wire: &[u8], next_info: &[u8], now: u64) -> Result<Self, MlsError> {
        let mut candidate = Self::from_info(self.policy.clone(), &self.info)?;
        candidate.accept(wire, now)?;
        candidate.publish_group_info(next_info)?;
        Ok(candidate)
    }

    /// Verify and advance one public membership commit. Clients must still
    /// verify it independently. Serialize calls under the service's durable
    /// compare-and-append transaction; a second commit at the old epoch fails.
    pub fn accept(&mut self, wire: &[u8], now: u64) -> Result<(), MlsError> {
        let processed = self
            .group
            .process_message(self.backend.crypto(), protocol(wire)?)
            .map_err(mls)?;
        validate_join(&self.policy, self.group.members(), &processed, now)?;
        let ProcessedMessageContent::StagedCommitMessage(commit) = processed.into_content() else {
            return Err(MlsError::Unauthorized);
        };
        self.group
            .merge_commit(self.backend.storage(), *commit)
            .map_err(mls)?;
        // Do not advertise the previous epoch's GroupInfo after advancing.
        self.info.clear();
        Ok(())
    }

    /// Publish a member's fresh GroupInfo only if its authenticated public
    /// context AND tree exactly match the state derived from accepted commits.
    pub fn publish_group_info(&mut self, bytes: &[u8]) -> Result<(), MlsError> {
        let candidate = Self::from_info(self.policy.clone(), bytes)?;
        if candidate.group.group_context() != self.group.group_context()
            || candidate.group.export_ratchet_tree() != self.group.export_ratchet_tree()
        {
            return Err(MlsError::Unauthorized);
        }
        self.info = bytes.to_vec();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_client_cannot_bypass_private_admission() {
        let root = IdentityKeypair::from_seed([24; 32]);
        let mut owner = HostedSession::create(&root, "owner", 500, false).unwrap();
        let mut observer = HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        let attacker = PreparedHostedJoin::new("attacker").unwrap();
        // Deliberately bypass PreparedHostedJoin::join's outgoing policy check.
        let (_, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config())
            .with_aad(JoinPermit::public().encode().unwrap())
            .build_group(
                &attacker.backend,
                group_info(&observer.info).unwrap(),
                attacker.credential.clone(),
            )
            .unwrap()
            .load_psks(attacker.backend.storage())
            .unwrap()
            .build(
                attacker.backend.rand(),
                attacker.backend.crypto(),
                attacker.signer.as_ref().expect("prepared signer"),
                |_| true,
            )
            .unwrap()
            .finalize(&attacker.backend)
            .unwrap();
        let wire = bundle.into_commit().tls_serialize_detached().unwrap();
        assert!(observer.accept(&wire, 100).is_err());
        assert!(owner.receive(&wire, 100).is_err());
        assert_eq!(observer.epoch(), 0);
        assert_eq!(owner.epoch(), 0);
        assert_eq!(observer.member_count(), 1);
        assert_eq!(owner.roster().len(), 1);
    }
}
