use super::*;

/// Authenticated durable receipt for one exact service record. This is not a
/// read receipt and has no expiry: an offline recipient may acknowledge later.
#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HostedReceipt {
    channel: [u8; 32],
    sender: [u8; 32],
    recipient: [u8; 32],
    record: [u8; 32],
    sequence: u64,
    signature: VLBytes,
}
impl HostedReceipt {
    fn payload(&self) -> Vec<u8> {
        let mut bytes = b"gcoms/hosted/recipient-receipt/v1".to_vec();
        bytes.extend_from_slice(&self.channel);
        bytes.extend_from_slice(&self.sender);
        bytes.extend_from_slice(&self.recipient);
        bytes.extend_from_slice(&self.record);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes
    }
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.tls_serialize_detached()?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > 256 {
            return Err(MlsError::Encoding);
        }
        Ok(Self::tls_deserialize_exact(bytes)?)
    }
    pub fn verify(&self, channel: [u8; 32]) -> Result<(), MlsError> {
        if self.channel != channel || self.sender == self.recipient || self.sequence == 0 {
            return Err(MlsError::Unauthorized);
        }
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(
                CIPHERSUITE.signature_algorithm(),
                &self.payload(),
                &self.recipient,
                self.signature.as_slice(),
            )
            .map_err(|_| MlsError::Unauthorized)
    }
    pub fn sender(&self) -> [u8; 32] {
        self.sender
    }
    pub fn recipient(&self) -> [u8; 32] {
        self.recipient
    }
    pub fn record_id(&self) -> [u8; 32] {
        self.record
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}
impl HostedSession {
    /// Call only after authenticated plaintext and its application event have
    /// reached durable storage. Publication can wait for the consumer's commit.
    pub fn receipt(
        &self,
        sender: [u8; 32],
        record: [u8; 32],
        sequence: u64,
    ) -> Result<HostedReceipt, MlsError> {
        let mut receipt = HostedReceipt {
            channel: self.policy.channel_id(),
            sender,
            recipient: self.member_id(),
            record,
            sequence,
            signature: Vec::new().into(),
        };
        receipt.signature = self
            .ctx
            .signer
            .sign(&receipt.payload())
            .map_err(mls)?
            .into();
        receipt.verify(self.policy.channel_id())?;
        Ok(receipt)
    }
}
