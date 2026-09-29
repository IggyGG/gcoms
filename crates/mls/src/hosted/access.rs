use super::*;
use zeroize::Zeroizing;

/// Reusable high-entropy admission secret, held by invited clients only.
/// Exported bytes belong in a private invite or encrypted profile, never in
/// service configuration, public policy, logs or a catalog descriptor.
pub struct HostedAccessCode {
    signer: SignatureKeyPair,
}

impl HostedAccessCode {
    pub fn generate() -> Result<Self, MlsError> {
        Ok(Self {
            signer: SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?,
        })
    }

    pub fn verification_key(&self) -> [u8; 32] {
        self.signer
            .public()
            .try_into()
            .expect("validated Ed25519 access key")
    }

    /// Caller must protect the returned secret throughout its lifetime.
    pub fn export_secret(&self) -> Result<Zeroizing<Vec<u8>>, MlsError> {
        Ok(Zeroizing::new(self.signer.tls_serialize_detached()?))
    }

    pub fn import_secret(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > 128 {
            return Err(MlsError::Encoding);
        }
        let signer = SignatureKeyPair::tls_deserialize_exact(bytes)?;
        if signer.signature_scheme() != CIPHERSUITE.signature_algorithm()
            || signer.public().len() != 32
        {
            return Err(MlsError::Encoding);
        }
        // A deserialized key must prove that its public and private halves match.
        let challenge = b"gcoms/hosted/access-code/check/v1";
        let signature = signer.sign(challenge).map_err(mls)?;
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(
                CIPHERSUITE.signature_algorithm(),
                challenge,
                signer.public(),
                &signature,
            )
            .map_err(|_| MlsError::Unauthorized)?;
        Ok(Self { signer })
    }

    /// Prove code possession for this leaf and current epoch. Observing an old
    /// proof gives the service no reusable secret and no proof for its own leaf.
    pub fn permit(
        &self,
        policy: &HostedPolicy,
        epoch: u64,
        leaf: [u8; 32],
        name: &str,
        expiry: u64,
    ) -> Result<JoinPermit, MlsError> {
        if policy.access_key != Some(self.verification_key()) || !valid_name(name.as_bytes()) {
            return Err(MlsError::Unauthorized);
        }
        Ok(JoinPermit {
            authority: 1,
            expiry,
            signature: self
                .signer
                .sign(&policy.join_payload(epoch, &leaf, name.as_bytes(), expiry))
                .map_err(mls)?
                .into(),
        })
    }
}
