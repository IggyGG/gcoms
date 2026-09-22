//! Bounded file-sharing operations. Local paths never cross the IPC boundary.
use serde::{Deserialize, Serialize};
pub const PIECE_BYTES: usize = 256 * 1024;
pub type ShareId = [u8; 16];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub channel: [u8; 32],
    /// Empty for the channel; two sorted member IDs for a private conversation.
    pub participants: Vec<[u8; 32]>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfig {
    pub quota_bytes: u64,
    pub retention_secs: u64,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            quota_bytes: 10 * 1024 * 1024 * 1024,
            retention_secs: 7 * 86400,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Offered,
    Importing,
    Downloading,
    WaitingForPeers,
    Paused,
    Complete,
    Failed,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: ShareId,
    pub scope: Scope,
    pub name: String,
    pub size_bytes: u64,
    pub verified_bytes: u64,
    pub status: Status,
    pub sources: u16,
    pub verified_sources: u16,
    pub completed_by: u16,
    pub error: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub files: Vec<FileInfo>,
    pub config: CacheConfig,
    pub used_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    List,
    Prepare {
        id: ShareId,
        scope: Scope,
        name: String,
        size_bytes: u64,
    },
    WritePiece {
        id: ShareId,
        piece: u32,
        bytes: Vec<u8>,
    },
    Commit {
        id: ShareId,
    },
    Accept {
        id: ShareId,
    },
    Pause {
        id: ShareId,
    },
    Resume {
        id: ShareId,
    },
    Cancel {
        id: ShareId,
    },
    ReadPiece {
        id: ShareId,
        piece: u32,
    },
    Configure(CacheConfig),
    SetEnabled(bool),
    /// IPC20: reuse verified same-scope content and return the canonical handle.
    CommitReusing {
        id: ShareId,
    },
}
impl Request {
    pub fn validate(&self) -> Result<(), crate::SdkError> {
        let invalid = match self {
            Self::Prepare {
                id,
                scope,
                name,
                size_bytes,
            } => {
                *id == [0; 16]
                    || *size_bytes > 10 * 1024 * 1024 * 1024
                    || name.is_empty()
                    || name.len() > 255
                    || name
                        .chars()
                        .any(|c| c.is_control() || c == '/' || c == '\\')
                    || name == "."
                    || name == ".."
                    || (!scope.participants.is_empty()
                        && (scope.participants.len() != 2
                            || scope.participants[0] >= scope.participants[1]))
            }
            Self::WritePiece { bytes, .. } => bytes.len() > PIECE_BYTES,
            Self::Configure(c) => {
                !(1024 * 1024..=1024 * 1024 * 1024 * 1024).contains(&c.quota_bytes)
                    || !(86400..=365 * 86400).contains(&c.retention_secs)
            }
            _ => false,
        };
        if invalid {
            Err(crate::SdkError::Protocol(
                "invalid or oversized file request".into(),
            ))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Snapshot(Snapshot),
    Piece(Vec<u8>),
    /// Only returned for CommitReusing; existing Snapshot wire layout is unchanged.
    Committed {
        original: ShareId,
        canonical: ShareId,
        snapshot: Snapshot,
    },
}
