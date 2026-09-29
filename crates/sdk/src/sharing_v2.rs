//! Explicit hosted/contact file scopes. Legacy sharing wire layouts stay intact.
use crate::{sharing, ContactCard, SdkError};
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "gcoms-files-v2";
pub const OFFER_TYPE: &str = "application/vnd.gcoms.file-offer.v2";
pub const COMPLETION_TYPE: &str = "application/vnd.gcoms.file-complete.v2";
pub const DIRECT_CONTROL_TYPE: &str = "application/vnd.gcoms.file-control.v2";
pub const DIRECT_TYPE: &str = "application/vnd.gcoms.file-direct.v2";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    Hosted {
        channel: [u8; 32],
    },
    /// SHA-256 of an explicitly registered contact's verified public identity.
    Contact {
        peer: [u8; 32],
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: sharing::ShareId,
    pub scope: Scope,
    pub name: String,
    pub size_bytes: u64,
    pub verified_bytes: u64,
    pub status: sharing::Status,
    pub sources: u16,
    pub verified_sources: u16,
    pub completed_by: u16,
    pub error: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub files: Vec<FileInfo>,
    pub config: sharing::CacheConfig,
    pub used_bytes: u64,
    pub error: Option<String>,
}
/// This statement is authenticated by its encrypted conversation transport.
/// Completion is emitted only after piece and whole-file verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    pub publisher: [u8; 32],
    pub file: sharing::ShareId,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    List,
    /// Replace this application's explicit contact authorization set. Omitted
    /// or blocked contacts lose all new transfer authority immediately.
    Contacts(Vec<ContactCard>),
    Prepare {
        id: sharing::ShareId,
        scope: Scope,
        name: String,
        size_bytes: u64,
    },
    WritePiece {
        id: sharing::ShareId,
        piece: u32,
        bytes: Vec<u8>,
    },
    Commit {
        id: sharing::ShareId,
    },
    Accept {
        id: sharing::ShareId,
    },
    Pause {
        id: sharing::ShareId,
    },
    Resume {
        id: sharing::ShareId,
    },
    Cancel {
        id: sharing::ShareId,
    },
    ReadPiece {
        id: sharing::ShareId,
        piece: u32,
    },
    Configure(sharing::CacheConfig),
    SetEnabled(bool),
}
impl Request {
    pub fn validate(&self) -> Result<(), SdkError> {
        let invalid = match self {
            Self::Contacts(cards) => {
                cards.len() > 256
                    || cards
                        .iter()
                        .any(|c| c.0.is_empty() || c.0.len() > 128 * 1024)
            }
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
                    || matches!(name.as_str(), "." | "..")
                    || name
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '/' | '\\'))
                    || match scope {
                        Scope::Hosted { channel } => *channel == [0; 32],
                        Scope::Contact { peer } => *peer == [0; 32],
                    }
            }
            Self::WritePiece { bytes, .. } => bytes.len() > sharing::PIECE_BYTES,
            Self::Configure(config) => {
                return sharing::Request::Configure(config.clone()).validate()
            }
            _ => false,
        };
        if invalid {
            Err(SdkError::Protocol("invalid modern file request".into()))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Snapshot(Snapshot),
    Piece(Vec<u8>),
}
