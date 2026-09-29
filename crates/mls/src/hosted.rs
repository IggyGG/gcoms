//! Experimental hosted-channel admission primitives.
//!
//! The observer holds only OpenMLS public state. Admission is checked both by
//! that observer and by members, independent of the delivery service. This is a
//! separate profile: a legacy channel cannot opt in by receiving an external
//! commit. Transport and durable sequencing are supplied by the embedding application.

use crate::session::{CIPHERSUITE, MAX_WIRE_BYTES};
use crate::{MlsError, RosterMember};
use gcoms_crypto::{verify_signature, IdentityKeypair};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

mod access;
mod application;
mod control;
mod membership;
pub use application::HostedMessageKind;
mod read;
mod rules;
pub use access::HostedAccessCode;
pub use control::{HostedControl, HostedControlEvent};
use membership::validate_membership;
pub use read::{HostedReadProof, HostedReadScope};
pub use rules::{
    HostedAccessList, HostedDiscovery, HostedMode, HostedPolicyChange, HostedRole, HostedRules,
};

const VERSION: u16 = 1;
const MAX_NAME: usize = 128;
const MAX_AUTHORITY: usize = 16 * 1024;
const POLICY_DOMAIN: &[u8] = b"gcoms/hosted/policy/v1";
const JOIN_DOMAIN: &[u8] = b"gcoms/hosted/join/v1";
const CONTENT_DOMAIN: &[u8] = b"gcoms/hosted/content/v1";
const MESSAGE_DOMAIN: &[u8] = b"gcoms/hosted/message/v1";
/// Genesis follows one owner self-update: no expiring KeyPackage leaf remains
/// in the public replay anchor of a long-lived channel.
pub const HOSTED_GENESIS_EPOCH: u64 = 1;
/// Includes framing overhead; bounds service authentication before MLS parsing.
pub const MAX_HOSTED_MESSAGE: usize = 1024 * 1024;

/// A member-authenticated ciphertext envelope. The service can authorize the
/// sender and epoch without decrypting its MLS application message.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HostedMessage {
    channel: [u8; 32],
    epoch: u64,
    member: [u8; 32],
    kind: HostedMessageKind,
    ciphertext: VLBytes,
    signature: VLBytes,
}

impl HostedMessage {
    fn payload(&self) -> Vec<u8> {
        let mut bytes = MESSAGE_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.channel);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.member);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&Sha256::digest(self.ciphertext.as_slice()));
        bytes
    }

    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.tls_serialize_detached()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > MAX_HOSTED_MESSAGE {
            return Err(MlsError::Encoding);
        }
        Ok(Self::tls_deserialize_exact(bytes)?)
    }

    pub fn kind(&self) -> HostedMessageKind {
        self.kind
    }

    pub fn member_id(&self) -> [u8; 32] {
        self.member
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn verify(
        &self,
        channel: [u8; 32],
        epoch: u64,
        mut members: impl Iterator<Item = Member>,
        backend: &OpenMlsRustCrypto,
    ) -> Result<(), MlsError> {
        if self.channel != channel {
            return Err(MlsError::WrongChannel);
        }
        if self.epoch != epoch {
            return Err(MlsError::StaleState);
        }
        if !members.any(|m| m.signature_key.as_slice() == self.member) {
            return Err(MlsError::Unauthorized);
        }
        if self.tls_serialized_len() > self.kind.wire_limit()
            || self.signature.as_slice().len() != 64
        {
            return Err(MlsError::Encoding);
        }
        let wire = protocol(self.ciphertext.as_slice())?;
        if !matches!(wire, ProtocolMessage::PrivateMessage(_))
            || wire.content_type() != ContentType::Application
            || wire.epoch().as_u64() != epoch
            || wire.group_id().as_slice() != channel
        {
            return Err(MlsError::Unauthorized);
        }
        backend
            .crypto()
            .verify_signature(
                CIPHERSUITE.signature_algorithm(),
                &self.payload(),
                &self.member,
                self.signature.as_slice(),
            )
            .map_err(|_| MlsError::Unauthorized)
    }
}

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
    access_key: Option<[u8; 32]>,
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
        match self.access_key {
            Some(key) => {
                bytes.push(1);
                bytes.extend_from_slice(&key);
            }
            None => bytes.push(0),
        }
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

    fn join_payload(
        &self,
        epoch: u64,
        leaf: &[u8],
        name: &[u8],
        expiry: u64,
        revision: u64,
        authority: u8,
    ) -> Vec<u8> {
        let mut bytes = JOIN_DOMAIN.to_vec();
        bytes.extend_from_slice(&Sha256::digest(self.payload()));
        bytes.push(authority);
        bytes.extend_from_slice(&revision.to_be_bytes());
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
            authority: 0,
            issuer: None,
            revision: 0,
            expiry,
            signature: root
                .sign(&self.join_payload(epoch, &leaf, name.as_bytes(), expiry, 0, 0))
                .into(),
        })
    }

    /// Authorize against the current verified policy revision, not a stale
    /// genesis snapshot. The root is no longer authoritative after transfer.
    pub fn permit_for(
        &self,
        root: &IdentityKeypair,
        public: &HostedObserver,
        leaf: [u8; 32],
        name: &str,
        expiry: u64,
    ) -> Result<JoinPermit, MlsError> {
        if self.payload() != public.policy.payload()
            || root.public_bytes() != self.root.as_slice()
            || !valid_name(name.as_bytes())
            || public.rules.owner() != self.owner
        {
            return Err(MlsError::Unauthorized);
        }
        let revision = public.rules.revision();
        Ok(JoinPermit {
            authority: 0,
            issuer: None,
            revision,
            expiry,
            signature: root
                .sign(&self.join_payload(
                    public.epoch(),
                    &leaf,
                    name.as_bytes(),
                    expiry,
                    revision,
                    0,
                ))
                .into(),
        })
    }

    fn authorize(
        &self,
        rules: &HostedRules,
        epoch: u64,
        leaf: &[u8],
        name: &[u8],
        aad: &[u8],
        now: u64,
    ) -> Result<(), MlsError> {
        if leaf.len() != 32 || !valid_name(name) || aad.len() > MAX_AUTHORITY {
            return Err(MlsError::Encoding);
        }
        let key = leaf.try_into().map_err(|_| MlsError::Encoding)?;
        if rules.closed() || rules.banned(key) {
            return Err(MlsError::Unauthorized);
        }
        let permit = JoinPermit::tls_deserialize_exact(aad)?;
        if matches!(permit.authority, 2 | 3) != permit.issuer.is_some() {
            return Err(MlsError::Encoding);
        }
        if permit.revision != rules.revision() {
            return Err(MlsError::StaleState);
        }
        if (!rules.mode(HostedMode::InviteOnly) || rules.invite_exception(key))
            && permit.authority == 0
            && permit.expiry == 0
            && permit.signature.as_slice().is_empty()
        {
            return Ok(());
        }
        if permit.expiry <= now {
            return Err(MlsError::Expired);
        }
        let payload = self.join_payload(
            epoch,
            leaf,
            name,
            permit.expiry,
            permit.revision,
            permit.authority,
        );
        let authorized = match permit.authority {
            0 => {
                rules.owner() == self.owner
                    && verify_signature(self.root.as_slice(), &payload, permit.signature.as_slice())
            }
            1 => rules.access_key().is_some_and(|key| {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .verify_signature(
                        CIPHERSUITE.signature_algorithm(),
                        &payload,
                        &key,
                        permit.signature.as_slice(),
                    )
                    .is_ok()
            }),
            2 => permit.issuer.is_some_and(|key| {
                rules.operator(key)
                    && !rules.departing(key)
                    && !rules.banned(key)
                    && OpenMlsRustCrypto::default()
                        .crypto()
                        .verify_signature(
                            CIPHERSUITE.signature_algorithm(),
                            &payload,
                            &key,
                            permit.signature.as_slice(),
                        )
                        .is_ok()
            }),
            3 => permit.issuer.is_some_and(|key| {
                rules
                    .invitation_expiry(key)
                    .is_some_and(|expiry| expiry > now && permit.expiry <= expiry)
                    && OpenMlsRustCrypto::default()
                        .crypto()
                        .verify_signature(
                            CIPHERSUITE.signature_algorithm(),
                            &payload,
                            &key,
                            permit.signature.as_slice(),
                        )
                        .is_ok()
            }),
            _ => false,
        };
        if !authorized {
            return Err(MlsError::Unauthorized);
        }
        Ok(())
    }
}

/// Public, epoch-bound proof of admission. Contains a signature, not a bearer
/// secret. OpenMLS binds it to the joiner's signature through commit AAD.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct JoinPermit {
    authority: u8,
    issuer: Option<[u8; 32]>,
    revision: u64,
    expiry: u64,
    signature: VLBytes,
}

impl JoinPermit {
    /// Only accepted by an explicitly public-join policy.
    pub fn public() -> Self {
        Self {
            authority: 0,
            issuer: None,
            revision: 0,
            expiry: 0,
            signature: Vec::new().into(),
        }
    }

    pub fn public_for(public: &HostedObserver) -> Self {
        Self {
            revision: public.rules.revision(),
            ..Self::public()
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
            &public.rules,
            public.epoch(),
            &self.member_id(),
            self.credential.credential.serialized_content(),
            &aad,
            now,
        )?;
        if public.member_count() >= public.rules.capacity() as usize
            || public.group.members().count() >= 1000
        {
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
        let rules = if public.rules.departing(self.member_id()) || permit.authority == 3 {
            public.stage_join(&commit, &info, now)?.rules
        } else {
            public.rules.clone()
        };
        let session = HostedSession {
            ctx: crate::session::Ctx {
                backend: std::mem::take(&mut self.backend),
                signer: self.signer.take().expect("prepared signer"),
                group,
                owner_pseudonym: Some(public.policy.owner),
                admin_pseudonyms: Vec::new(),
            },
            policy: public.policy.clone(),
            rules,
            pending_rekey: None,
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
    rules: HostedRules,
    pending_join: Option<PendingJoin>,
    pending_rekey: Option<PendingJoin>,
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
    rules: HostedRules,
    pending: Option<PendingJoin>,
    rekey: Option<PendingJoin>,
}

impl HostedSession {
    /// Current owners/operators can issue one-leaf admission without the
    /// creator's root key. Revocation and transfer are enforced on receipt.
    pub fn permit_join(
        &self,
        leaf: [u8; 32],
        name: &str,
        expiry: u64,
    ) -> Result<JoinPermit, MlsError> {
        let issuer = self
            .ctx
            .signer
            .public()
            .try_into()
            .map_err(|_| MlsError::Encoding)?;
        if self.pending_join.is_some()
            || self.rules.closed()
            || !self.rules.operator(issuer)
            || self.rules.banned(issuer)
            || self.rules.departing(issuer)
            || !self.ctx.group.is_active()
            || !valid_name(name.as_bytes())
        {
            return Err(MlsError::Unauthorized);
        }
        let revision = self.rules.revision();
        Ok(JoinPermit {
            authority: 2,
            issuer: Some(issuer),
            revision,
            expiry,
            signature: self
                .ctx
                .signer
                .sign(&self.policy.join_payload(
                    self.epoch(),
                    &leaf,
                    name.as_bytes(),
                    expiry,
                    revision,
                    2,
                ))
                .map_err(mls)?
                .into(),
        })
    }

    /// Rebuild a refused speculative join at a newer epoch while preserving
    /// its scoped signing identity. Never use this to reset an accepted member.
    pub fn prepare_join_retry(self) -> Result<PreparedHostedJoin, MlsError> {
        if self.pending_join.is_none() {
            return Err(MlsError::Unauthorized);
        }
        let encoded = zeroize::Zeroizing::new(self.ctx.signer.tls_serialize_detached()?);
        let signer = SignatureKeyPair::tls_deserialize_exact(encoded.as_slice())?;
        let leaf = self.ctx.group.own_leaf_node().ok_or(MlsError::Encoding)?;
        let prepared = PreparedHostedJoin {
            backend: OpenMlsRustCrypto::default(),
            credential: CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: SignaturePublicKey::from(signer.to_public_vec()),
            },
            signer: Some(signer),
        };
        prepared
            .signer
            .as_ref()
            .expect("prepared signer")
            .store(prepared.backend.storage())
            .map_err(mls)?;
        Ok(prepared)
    }

    /// Create a private channel with a reusable client-held admission code.
    /// Only its verification key appears in service-visible policy.
    pub fn create_keyed(
        root: &IdentityKeypair,
        name: &str,
        capacity: u32,
        code: &HostedAccessCode,
    ) -> Result<Self, MlsError> {
        let mut session = Self::create(root, name, capacity, false)?;
        session.policy.access_key = Some(code.verification_key());
        session.policy.signature = root.sign(&session.policy.payload()).into();
        session.rules = HostedRules::genesis(&session.policy);
        Ok(session)
    }
    /// Prepare an exact signed ciphertext for durable outgoing storage/retry.
    /// The caller must checkpoint the advanced sender state before publishing.
    pub fn send_hosted(&mut self, payload: &[u8]) -> Result<HostedMessage, MlsError> {
        self.send_kind(HostedMessageKind::Text, payload)
    }

    /// Kind is authenticated both outside and inside MLS. Receivers must use
    /// this classification when dispatching content, especially topics/notices.
    pub fn send_kind(
        &mut self,
        kind: HostedMessageKind,
        payload: &[u8],
    ) -> Result<HostedMessage, MlsError> {
        if payload.len() > kind.wire_limit() - 1024 {
            return Err(MlsError::Encoding);
        }
        if self.pending_join.is_some() || !kind.allowed(&self.rules, self.member_id()) {
            return Err(MlsError::Unauthorized);
        }
        let mut content = CONTENT_DOMAIN.to_vec();
        content.push(kind as u8);
        content.extend_from_slice(payload);
        let ciphertext = self
            .ctx
            .group
            .create_message(&self.ctx.backend, &self.ctx.signer, &content)
            .map_err(mls)?
            .tls_serialize_detached()?;
        let mut message = HostedMessage {
            channel: self.policy.channel_id(),
            epoch: self.epoch(),
            member: self
                .ctx
                .signer
                .to_public_vec()
                .try_into()
                .map_err(|_| MlsError::Encoding)?,
            kind,
            ciphertext: ciphertext.into(),
            signature: Vec::new().into(),
        };
        message.signature = self
            .ctx
            .signer
            .sign(&message.payload())
            .map_err(mls)?
            .into();
        Ok(message)
    }

    /// Authenticate both the service-visible envelope and the encrypted MLS
    /// sender. A false outer identity must not consume another sender's ratchet.
    /// Authenticate a service-visible envelope, including our own durable sends,
    /// without trying to decrypt a sender ratchet with its sending instance.
    pub fn verify_hosted(&self, message: &HostedMessage) -> Result<(), MlsError> {
        if !message.kind.allowed(&self.rules, message.member) {
            return Err(MlsError::Unauthorized);
        }
        message.verify(
            self.policy.channel_id(),
            self.epoch(),
            self.ctx.group.members(),
            &self.ctx.backend,
        )
    }

    pub fn verify_group_info(&self, bytes: &[u8]) -> Result<(), MlsError> {
        let public = HostedObserver::from_info(self.policy.clone(), bytes)?;
        if public.group.group_context() != self.ctx.group.public_group().group_context()
            || public.group.export_ratchet_tree() != self.ctx.group.export_ratchet_tree()
        {
            return Err(MlsError::Unauthorized);
        }
        Ok(())
    }

    pub fn receive_hosted(&mut self, message: &HostedMessage) -> Result<Vec<u8>, MlsError> {
        if self.pending_join.is_some() {
            return Err(MlsError::Unauthorized);
        }
        if !message.kind.allowed(&self.rules, message.member) {
            return Err(MlsError::Unauthorized);
        }
        message.verify(
            self.policy.channel_id(),
            self.epoch(),
            self.ctx.group.members(),
            &self.ctx.backend,
        )?;
        let mut candidate = self.fork()?;
        let processed = candidate
            .ctx
            .group
            .process_message(
                &candidate.ctx.backend,
                protocol(message.ciphertext.as_slice())?,
            )
            .map_err(mls)?;
        let Sender::Member(index) = processed.sender() else {
            return Err(MlsError::Unauthorized);
        };
        let actual = candidate
            .ctx
            .group
            .members()
            .find(|m| m.index == *index)
            .ok_or(MlsError::Unauthorized)?;
        if actual.signature_key.as_slice() != message.member {
            return Err(MlsError::Unauthorized);
        }
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(MlsError::Unauthorized);
        };
        let content = application.into_bytes();
        let payload = content
            .strip_prefix(CONTENT_DOMAIN)
            .ok_or(MlsError::Encoding)?;
        let (kind, payload) = payload.split_first().ok_or(MlsError::Encoding)?;
        if *kind != message.kind as u8 {
            return Err(MlsError::Unauthorized);
        }
        let payload = payload.to_vec();
        *self = candidate;
        Ok(payload)
    }

    /// Speculative copy for an atomic client transaction. Install at most one
    /// copy as live state; never publish independently from both instances.
    pub fn try_clone(&self) -> Result<Self, MlsError> {
        self.fork()
    }

    fn fork(&self) -> Result<Self, MlsError> {
        let backend = OpenMlsRustCrypto::default();
        *backend
            .storage()
            .values
            .write()
            .map_err(|_| MlsError::Encoding)? = self
            .ctx
            .backend
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Encoding)?
            .clone();
        let result = (|| {
            let group = MlsGroup::load(backend.storage(), self.ctx.group.group_id())
                .map_err(mls)?
                .ok_or(MlsError::Encoding)?;
            let signer = SignatureKeyPair::read(
                backend.storage(),
                &self.ctx.signer.to_public_vec(),
                CIPHERSUITE.signature_algorithm(),
            )
            .ok_or(MlsError::Encoding)?;
            Ok((group, signer))
        })();
        let (group, signer) = match result {
            Ok(parts) => parts,
            Err(error) => {
                crate::session::zeroize_storage(&backend);
                return Err(error);
            }
        };
        Ok(Self {
            ctx: crate::session::Ctx {
                backend,
                signer,
                group,
                owner_pseudonym: self.ctx.owner_pseudonym,
                admin_pseudonyms: self.ctx.admin_pseudonyms.clone(),
            },
            policy: self.policy.clone(),
            rules: self.rules.clone(),
            pending_join: self.pending_join.clone(),
            pending_rekey: self.pending_rekey.clone(),
        })
    }
    /// Seal member secrets and pending acceptance together. The wrapping key
    /// belongs to the client's encrypted profile, never the channel service.
    #[cfg(feature = "client-persist")]
    pub fn persist(&self, wrapping_key: &[u8; 32]) -> Result<Vec<u8>, MlsError> {
        let metadata = HostedArchive {
            policy: self.policy.clone(),
            rules: self.rules.clone(),
            pending: self.pending_join.clone(),
            rekey: self.pending_rekey.clone(),
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
            rules: archive.rules,
            pending_join: archive.pending,
            pending_rekey: archive.rekey,
        })
    }
    pub fn create(
        root: &IdentityKeypair,
        name: &str,
        capacity: u32,
        public_join: bool,
    ) -> Result<Self, MlsError> {
        Self::create_with_config(root, name, capacity, public_join, create_config())
    }

    fn create_with_config(
        root: &IdentityKeypair,
        name: &str,
        capacity: u32,
        public_join: bool,
        config: MlsGroupCreateConfig,
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
            access_key: None,
            signature: Vec::new().into(),
        };
        policy.signature = root.sign(&policy.payload()).into();
        let mut group = MlsGroup::new_with_group_id(
            &prepared.backend,
            prepared.signer.as_ref().expect("prepared signer"),
            &config,
            GroupId::from_slice(&policy.channel_id()),
            prepared.credential.clone(),
        )
        .map_err(mls)?;
        group
            .self_update(
                &prepared.backend,
                prepared.signer.as_ref().expect("prepared signer"),
                LeafNodeParameters::default(),
            )
            .map_err(mls)?;
        group.merge_pending_commit(&prepared.backend).map_err(mls)?;
        Ok(Self {
            ctx: crate::session::Ctx {
                backend: std::mem::take(&mut prepared.backend),
                signer: prepared.signer.take().expect("prepared signer"),
                group,
                owner_pseudonym: Some(policy.owner),
                admin_pseudonyms: Vec::new(),
            },
            rules: HostedRules::genesis(&policy),
            policy,
            pending_join: None,
            pending_rekey: None,
        })
    }

    pub fn rules(&self) -> &HostedRules {
        &self.rules
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
            .or(self.pending_rekey.as_ref())
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
        let actor = self
            .ctx
            .signer
            .public()
            .try_into()
            .map_err(|_| MlsError::Encoding)?;
        if !self.rules.may_post(actor) {
            return Err(MlsError::Unauthorized);
        }
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
        let mut candidate = self.fork()?;
        let result = candidate.receive_inner(wire, now);
        if result.is_ok() || matches!(result, Err(MlsError::Removed)) {
            *self = candidate;
        }
        result
    }

    fn receive_inner(&mut self, wire: &[u8], now: u64) -> Result<crate::ReceiveOutcome, MlsError> {
        if self.pending_join.is_some() {
            return Err(MlsError::Unauthorized);
        }
        if self.pending_rekey.is_some() {
            self.ctx
                .group
                .clear_pending_commit(self.ctx.backend.storage())
                .map_err(mls)?;
            self.pending_rekey = None;
        }
        let processed = self
            .ctx
            .group
            .process_message(&self.ctx.backend, protocol(wire)?)
            .map_err(mls)?;
        let removed = if let ProcessedMessageContent::StagedCommitMessage(_) = processed.content() {
            validate_membership(
                &self.policy,
                &self.rules,
                self.ctx.group.members(),
                &processed,
                now,
            )?
        } else {
            Vec::new()
        };
        let used_invitation = membership::used_invitation(&processed)?;
        let sender_index = match processed.sender() {
            Sender::Member(i) => i.u32(),
            _ => u32::MAX,
        };
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                let self_removed = commit.self_removed();
                self.ctx
                    .group
                    .merge_staged_commit(&self.ctx.backend, *commit)
                    .map_err(mls)?;
                self.rules.finish_removals(&removed);
                self.rules.consume_invitation(used_invitation);
                if self_removed {
                    return Err(MlsError::Removed);
                }
                Ok(crate::ReceiveOutcome::CommitMerged { sender_index })
            }
            ProcessedMessageContent::ApplicationMessage(message) => {
                let member = self
                    .ctx
                    .group
                    .members()
                    .find(|m| m.index.u32() == sender_index)
                    .ok_or(MlsError::Unauthorized)?;
                if !self.rules.may_post(
                    member
                        .signature_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| MlsError::Encoding)?,
                ) {
                    return Err(MlsError::Unauthorized);
                }
                Ok(crate::ReceiveOutcome::Application {
                    sender_index,
                    payload: message.into_bytes(),
                })
            }
            _ => Err(MlsError::Unauthorized),
        }
    }
}
/// Delivery-service state: public ratchet tree, signed public policy and group
/// context only. No MLS member, signer, epoch secret or application decryption
/// method. Rebuild by replaying the accepted ordered commit log from genesis.
pub struct HostedObserver {
    backend: OpenMlsRustCrypto,
    group: PublicGroup,
    policy: HostedPolicy,
    rules: HostedRules,
    info: Vec<u8>,
}

impl HostedObserver {
    pub fn rules(&self) -> &HostedRules {
        &self.rules
    }
    /// Verify append authority without possession of any decryption key.
    pub fn verify_message(&self, message: &HostedMessage) -> Result<(), MlsError> {
        if !message.kind.allowed(&self.rules, message.member) {
            return Err(MlsError::Unauthorized);
        }
        message.verify(
            self.policy.channel_id(),
            self.epoch(),
            self.group.members(),
            &self.backend,
        )
    }

    /// Start from owner-signed policy and the owner's genesis GroupInfo.
    /// Later snapshots must be verified by replay, not trusted as new genesis.
    pub fn new(
        policy: HostedPolicy,
        expected_channel: [u8; 32],
        info: &[u8],
    ) -> Result<Self, MlsError> {
        policy.verify(expected_channel)?;
        let observer = Self::from_info(policy, info)?;
        let members: Vec<_> = observer.group.members().collect();
        if observer.epoch() != HOSTED_GENESIS_EPOCH
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
            rules: HostedRules::genesis(&policy),
            policy,
            info: bytes.to_vec(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }
    pub fn member_count(&self) -> usize {
        self.group
            .members()
            .filter(|m| {
                !self
                    .rules
                    .departing(m.signature_key.as_slice().try_into().expect("Ed25519 key"))
            })
            .count()
    }

    /// Validate a complete next epoch without mutating this observer. Persist
    /// the commit and GroupInfo atomically before installing the returned state
    /// and returning acceptance. A malformed snapshot cannot strand admission.
    pub fn stage_join(&self, wire: &[u8], next_info: &[u8], now: u64) -> Result<Self, MlsError> {
        if protocol(wire)?.epoch().as_u64() != self.epoch() {
            return Err(MlsError::StaleState);
        }
        let mut candidate = Self::from_info(self.policy.clone(), &self.info)?;
        candidate.rules = self.rules.clone();
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
        let removed = validate_membership(
            &self.policy,
            &self.rules,
            self.group.members(),
            &processed,
            now,
        )?;
        let used_invitation = membership::used_invitation(&processed)?;
        let ProcessedMessageContent::StagedCommitMessage(commit) = processed.into_content() else {
            return Err(MlsError::Unauthorized);
        };
        self.group
            .merge_commit(self.backend.storage(), *commit)
            .map_err(mls)?;
        self.rules.finish_removals(&removed);
        self.rules.consume_invitation(used_invitation);
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
    fn public_replay_anchor_does_not_expire_with_the_creators_key_package() {
        let root = IdentityKeypair::from_seed([26; 32]);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .lifetime(Lifetime::init(0, 1))
            .build();
        let owner =
            HostedSession::create_with_config(&root, "owner", 500, true, config.clone()).unwrap();
        assert_eq!(owner.epoch(), HOSTED_GENESIS_EPOCH);
        HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        // Negative control: the un-updated initial tree still has the expired
        // KeyPackage leaf and cannot be imported as current public state.
        let prepared = PreparedHostedJoin::new("owner").unwrap();
        let raw = MlsGroup::new_with_group_id(
            &prepared.backend,
            prepared.signer.as_ref().unwrap(),
            &config,
            GroupId::from_slice(&owner.policy.channel_id()),
            prepared.credential.clone(),
        )
        .unwrap();
        let info = raw
            .export_group_info(
                prepared.backend.crypto(),
                prepared.signer.as_ref().unwrap(),
                true,
            )
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        assert!(HostedObserver::from_info(owner.policy, &info).is_err());
    }

    #[test]
    fn false_outer_sender_cannot_consume_another_members_ratchet() {
        let root = IdentityKeypair::from_seed([25; 32]);
        let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
        let mut observer = HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        let (mut alice, first) = PreparedHostedJoin::new("alice")
            .unwrap()
            .join(&observer, &JoinPermit::public(), 100)
            .unwrap();
        observer = observer
            .stage_join(&first, alice.proposed_group_info().unwrap(), 100)
            .unwrap();
        alice.accept_join(&first).unwrap();
        owner.receive(&first, 100).unwrap();
        let (mut bob, second) = PreparedHostedJoin::new("bob")
            .unwrap()
            .join(&observer, &JoinPermit::public(), 101)
            .unwrap();
        observer = observer
            .stage_join(&second, bob.proposed_group_info().unwrap(), 101)
            .unwrap();
        bob.accept_join(&second).unwrap();
        owner.receive(&second, 101).unwrap();
        alice.receive(&second, 101).unwrap();
        let original = owner.send_hosted(b"real owner message").unwrap();
        let mut forged = original.clone();
        forged.member = bob.ctx.signer.to_public_vec().try_into().unwrap();
        forged.signature = bob.ctx.signer.sign(&forged.payload()).unwrap().into();
        // The service only verifies outer authority. It cannot inspect the
        // encrypted MLS sender; every receiving client must check that too.
        observer.verify_message(&forged).unwrap();
        assert!(matches!(
            alice.receive_hosted(&forged),
            Err(MlsError::Unauthorized)
        ));
        assert_eq!(
            alice.receive_hosted(&original).unwrap(),
            b"real owner message"
        );
        assert!(
            alice.receive_hosted(&original).is_err(),
            "MLS replay must still fail"
        );
        let mut signature = forged.signature.as_slice().to_vec();
        signature[0] ^= 1;
        forged.signature = signature.into();
        assert!(observer.verify_message(&forged).is_err());
        let bytes = original.encode().unwrap();
        assert!(HostedMessage::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(HostedMessage::decode(&vec![0; MAX_HOSTED_MESSAGE + 1]).is_err());
    }

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
        assert_eq!(observer.epoch(), HOSTED_GENESIS_EPOCH);
        assert_eq!(owner.epoch(), HOSTED_GENESIS_EPOCH);
        assert_eq!(observer.member_count(), 1);
        assert_eq!(owner.roster().len(), 1);
    }
}
