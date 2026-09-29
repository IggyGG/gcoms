use super::*;

const READ_DOMAIN: &[u8] = b"gcoms/hosted/read/v1";

/// Read-only authority. Snapshot proves public policy/membership to a newcomer;
/// Records includes application ciphertext and requires membership. Proofs bind
/// the complete canonical query hash, channel, purpose and a short expiry.
#[derive(Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedReadScope {
    Snapshot = 1,
    Records = 2,
    Receipts = 3,
    BlobRead = 4,
    BlobWrite = 5,
}

#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HostedReadProof {
    channel: [u8; 32],
    scope: HostedReadScope,
    query: [u8; 32],
    expiry: u64,
    authority: u8,
    key: [u8; 32],
    signature: VLBytes,
}
impl HostedReadProof {
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.tls_serialize_detached()?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > 256 {
            return Err(MlsError::Encoding);
        }
        Ok(Self::tls_deserialize_exact(bytes)?)
    }
    pub fn member_id(&self) -> Option<[u8; 32]> {
        (self.authority == 0).then_some(self.key)
    }
    fn payload(&self) -> Vec<u8> {
        let mut bytes = READ_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.channel);
        bytes.push(self.scope as u8);
        bytes.extend_from_slice(&self.query);
        bytes.extend_from_slice(&self.expiry.to_be_bytes());
        bytes.push(self.authority);
        bytes.extend_from_slice(&self.key);
        bytes
    }
    pub(super) fn sign(
        signer: &SignatureKeyPair,
        channel: [u8; 32],
        scope: HostedReadScope,
        query: [u8; 32],
        expiry: u64,
        authority: u8,
    ) -> Result<Self, MlsError> {
        let mut proof = Self {
            channel,
            scope,
            query,
            expiry,
            authority,
            key: signer.public().try_into().map_err(|_| MlsError::Encoding)?,
            signature: Vec::new().into(),
        };
        proof.signature = signer.sign(&proof.payload()).map_err(mls)?.into();
        Ok(proof)
    }
    /// Verify cryptographic proof only. Callers must still authorize its scope
    /// against current membership or a retained historical read boundary.
    pub fn verify(
        &self,
        channel: [u8; 32],
        scope: HostedReadScope,
        query: [u8; 32],
        now: u64,
    ) -> Result<(), MlsError> {
        if self.channel != channel
            || self.scope != scope
            || self.query != query
            || self.expiry <= now
            || self.expiry.saturating_sub(now) > 120
            || self.authority > 1
        {
            return Err(MlsError::Unauthorized);
        }
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(
                CIPHERSUITE.signature_algorithm(),
                &self.payload(),
                &self.key,
                self.signature.as_slice(),
            )
            .map_err(|_| MlsError::Unauthorized)
    }
}
impl HostedSession {
    pub fn read_proof(
        &self,
        scope: HostedReadScope,
        query: [u8; 32],
        expiry: u64,
    ) -> Result<HostedReadProof, MlsError> {
        HostedReadProof::sign(
            &self.ctx.signer,
            self.policy.channel_id(),
            scope,
            query,
            expiry,
            0,
        )
    }
}
impl PreparedHostedJoin {
    pub fn read_proof(
        &self,
        channel: [u8; 32],
        query: [u8; 32],
        expiry: u64,
    ) -> Result<HostedReadProof, MlsError> {
        HostedReadProof::sign(
            self.signer.as_ref().ok_or(MlsError::Unauthorized)?,
            channel,
            HostedReadScope::Snapshot,
            query,
            expiry,
            0,
        )
    }
}
impl HostedObserver {
    pub fn policy(&self) -> &HostedPolicy {
        &self.policy
    }
    pub fn group_info(&self) -> &[u8] {
        &self.info
    }
    pub fn members(&self) -> Vec<[u8; 32]> {
        self.group
            .members()
            .filter_map(|m| m.signature_key.as_slice().try_into().ok())
            .collect()
    }
    pub fn verify_read(
        &self,
        proof: &HostedReadProof,
        scope: HostedReadScope,
        query: [u8; 32],
        now: u64,
    ) -> Result<(), MlsError> {
        proof.verify(self.policy.channel_id(), scope, query, now)?;
        if proof.authority == 0
            && self
                .group
                .members()
                .any(|m| m.signature_key.as_slice() == proof.key)
        {
            return Ok(());
        }
        if scope == HostedReadScope::Snapshot && !self.rules.closed() {
            if proof.authority == 1
                && (self.rules.access_key() == Some(proof.key)
                    || self
                        .rules
                        .invitation_expiry(proof.key)
                        .is_some_and(|expiry| expiry > now))
            {
                return Ok(());
            }
            if proof.authority == 0
                && !self.rules.banned(proof.key)
                && (!self.rules.mode(HostedMode::InviteOnly)
                    || self.rules.invite_exception(proof.key))
            {
                return Ok(());
            }
        }
        Err(MlsError::Unauthorized)
    }
}
