use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum MlsError {
    BadInvite,
    Expired,
    WrongChannel,
    LeafMismatch,
    GroupFull,
    MemberNotFound,
    OpenMls(String),
    Encoding,
    Removed,
    UnsupportedCiphersuite(u16),
    /// A commit attempted a privileged change (removal) from a leaf that
    /// is neither the owner nor a delegated administrator.
    Unauthorized,
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlsError::BadInvite => write!(f, "invite signature invalid"),
            MlsError::Expired => write!(f, "invite expired"),
            MlsError::WrongChannel => write!(f, "invite for a different channel"),
            MlsError::LeafMismatch => write!(f, "key package does not match invite leaf"),
            MlsError::GroupFull => write!(f, "group at capacity"),
            MlsError::MemberNotFound => write!(f, "member not found"),
            MlsError::OpenMls(e) => write!(f, "openmls: {e}"),
            MlsError::Encoding => write!(f, "malformed encoding"),
            MlsError::Removed => write!(f, "removed from group"),
            MlsError::Unauthorized => write!(f, "commit from a leaf without that privilege"),
            MlsError::UnsupportedCiphersuite(suite) => {
                write!(
                    f,
                    "MLS ciphersuite 0x{suite:04x} is not the required PQ-hybrid suite"
                )
            }
        }
    }
}

impl Error for MlsError {}

impl From<tls_codec::Error> for MlsError {
    fn from(_: tls_codec::Error) -> Self {
        MlsError::Encoding
    }
}

pub mod invite;
pub mod session;

pub use invite::{now_unix, verify_invite, Caps, Invite};
pub use session::{
    channel_group_id, ciphersuite_of_key_package, ciphersuite_of_welcome, epoch_of_wire,
    pseudonym_of_key_package, Admission, ChannelMember, OwnerSession, PreparedJoin, ReceiveOutcome,
    RosterMember, StagedAdmission, StagedRemoval, CIPHERSUITE_ID, MAX_WIRE_BYTES,
};

pub const GROUP_MAX: usize = 64;
pub const CHANNEL_MAX: usize = 5000;
pub const MAX_KEY_PACKAGE_BYTES: usize = 48 * 1024;
