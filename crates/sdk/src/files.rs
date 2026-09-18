//! Local API for backend-owned durable file reception. No private transport keys
//! or network connections are needed by the consuming component.
use crate::ContactCard;
use serde::{Deserialize, Serialize};

pub const CONTENT_TYPE: &str = gcoms_core::FILE_RECORD_CONTENT_TYPE;
pub const ACK_CONTENT_TYPE: &str = gcoms_core::FILE_ACK_CONTENT_TYPE;
pub const CHUNK_BYTES: u64 = gcoms_core::file_stream::RECOMMENDED_CHUNK_BYTES;

/// Choose a useful chunk without exceeding the recipient's existing contact or
/// byte-credit grant. Existing 8 KiB contacts remain usable without migration.
pub fn negotiated_chunk_bytes(
    contact: &gcoms_core::file_stream::FileContact,
) -> Result<u64, crate::SdkError> {
    let bytes = CHUNK_BYTES
        .min(contact.max_chunk_size)
        .min(contact.max_inflight_bytes);
    if bytes == 0 {
        return Err(crate::SdkError::Protocol(
            "file contact grants no chunk credit".into(),
        ));
    }
    Ok(bytes)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStorage {
    /// Independent owner-private managed admission configuration. Legacy storage
    /// alone never authorizes managed attempts. Not an IPC request field.
    #[serde(default)]
    pub attempt_trust_file: Option<std::path::PathBuf>,
    pub directory: std::path::PathBuf,
    pub state_auth_key: [u8; 32],
    pub disk_quota_bytes: u64,
    pub max_file_size: u64,
}
impl std::fmt::Debug for FileStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStorage")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileRequest {
    Release {
        transfer_id: [u8; 16],
    },
    Offer {
        peer: ContactCard,
        destination: [u8; 16],
        max_bytes: u64,
    },
    Status {
        transfer_id: [u8; 16],
    },
    Cancel {
        transfer_id: [u8; 16],
    },
    PrepareAttempt {
        peer: ContactCard,
        destination: [u8; 16],
        delivery_id: [u8; 16],
        expected_generation: u64,
        sha256: [u8; 32],
        size_bytes: u64,
        receiver_descriptor_sha256: [u8; 32],
        expires_at_unix: u64,
    },
    ActivateAttempt {
        attempt_id: [u8; 16],
        proof: FileAttemptProof,
    },
    AdmitStaging {
        attempt_id: [u8; 16],
        proof: FileAttemptProof,
    },
    AttemptStatus {
        attempt_id: [u8; 16],
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileReply {
    Offered {
        transfer_id: [u8; 16],
        contact: Vec<u8>,
    },
    Status {
        committed_bytes: u64,
        complete: bool,
        failed: bool,
        sha256: Option<String>,
        path: Option<std::path::PathBuf>,
    },
    Cancelled,
    PreparedAttempt {
        attempt_id: [u8; 16],
        contact_sha256: [u8; 32],
        expires_at_unix: u64,
        request_message_id: [u8; 16],
    },
    ActivatedAttempt,
    AttemptStatus {
        committed_bytes: u64,
        awaiting_staging: bool,
        request_message_id: Option<[u8; 16]>,
    },
}

/// Canonical public metadata and collector signatures. No caller-selected trust,
/// keys, broker state or lease. The receiver verifies these inside server dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAttemptProof {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub signatures: Vec<u8>,
}
impl FileRequest {
    pub fn is_managed(&self) -> bool {
        matches!(
            self,
            Self::PrepareAttempt { .. }
                | Self::ActivateAttempt { .. }
                | Self::AdmitStaging { .. }
                | Self::AttemptStatus { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_negotiation_preserves_old_contacts_and_byte_credit() {
        use gcoms_core::file_stream::{checkpoint_batch_chunks, Contact, FileContact};
        let mut contact = FileContact {
            profile_version: 2,
            transfer_id: [1; 16],
            recipient_contact: Contact {
                address: "192.0.2.1:443".parse().unwrap(),
                relay_service_id: [2; 32],
                queue_id: [3; 32],
                epoch: 1,
                push_cap: [4; 32],
                lease_expiry: 2000,
            },
            file_cap: [5; 32],
            contact_expiry: 1900,
            max_file_size: 1_000_000,
            max_chunk_size: 8192,
            max_inflight_bytes: 32 * 8192,
        };
        for version in [1, 2] {
            contact.profile_version = version;
            let old = FileContact::decode(&contact.encode().unwrap(), 1000).unwrap();
            assert_eq!(negotiated_chunk_bytes(&old).unwrap(), 8192);
        }
        contact.max_chunk_size = CHUNK_BYTES;
        let size = negotiated_chunk_bytes(&contact).unwrap();
        assert_eq!(size, 11264);
        assert_eq!(
            checkpoint_batch_chunks(contact.max_inflight_bytes, size).unwrap(),
            23
        );
        contact.max_inflight_bytes = 1024;
        assert_eq!(negotiated_chunk_bytes(&contact).unwrap(), 1024);
        contact.max_inflight_bytes = 0;
        assert!(negotiated_chunk_bytes(&contact).is_err());
    }

    #[test]
    fn managed_calls_append_without_reinterpreting_legacy_file_ordinals() {
        let legacy = [
            FileRequest::Release {
                transfer_id: [1; 16],
            },
            FileRequest::Offer {
                peer: ContactCard(vec![]),
                destination: [2; 16],
                max_bytes: 1,
            },
            FileRequest::Status {
                transfer_id: [1; 16],
            },
            FileRequest::Cancel {
                transfer_id: [1; 16],
            },
        ];
        for (ordinal, request) in legacy.into_iter().enumerate() {
            let bytes = postcard::to_allocvec(&request).unwrap();
            assert_eq!(bytes[0], ordinal as u8);
            assert_eq!(
                postcard::from_bytes::<FileRequest>(&bytes).unwrap(),
                request
            );
            assert_eq!(crate::ipc::Request::File(request).minimum_version(), 10);
        }
        let proof = FileAttemptProof {
            request: vec![],
            response: vec![],
            signatures: vec![],
        };
        let managed = [
            FileRequest::PrepareAttempt {
                peer: ContactCard(vec![]),
                destination: [2; 16],
                delivery_id: [3; 16],
                expected_generation: 0,
                sha256: [4; 32],
                size_bytes: 1,
                receiver_descriptor_sha256: [5; 32],
                expires_at_unix: 1,
            },
            FileRequest::ActivateAttempt {
                attempt_id: [1; 16],
                proof: proof.clone(),
            },
            FileRequest::AdmitStaging {
                attempt_id: [1; 16],
                proof,
            },
            FileRequest::AttemptStatus {
                attempt_id: [1; 16],
            },
        ];
        for (ordinal, request) in managed.into_iter().enumerate() {
            let bytes = postcard::to_allocvec(&request).unwrap();
            assert_eq!(bytes[0], ordinal as u8 + 4);
            assert_eq!(
                postcard::from_bytes::<FileRequest>(&bytes).unwrap(),
                request
            );
            assert_eq!(crate::ipc::Request::File(request).minimum_version(), 12);
        }
    }
}
