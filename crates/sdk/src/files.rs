//! Local API for backend-owned durable file reception. No private transport keys
//! or network connections are needed by the consuming component.
use crate::ContactCard;
use serde::{Deserialize, Serialize};

pub const CONTENT_TYPE: &str = "application/vnd.ghost.file-record.v1";
pub const ACK_CONTENT_TYPE: &str = "application/vnd.ghost.file-ack.v1";
pub const CHUNK_BYTES: u64 = 8192;

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
