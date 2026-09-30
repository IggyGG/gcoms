//! Reusable invitations. A link is a channel admission credential, never a
//! grant to run commands on another member's machine.
use crate::SdkError;
pub use gcoms_core::invitation::{
    EnrollmentPhase, EnrollmentStatus, InvitationPolicy, InvitationPreset, InvitationSummary,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InvitationRequest {
    Create {
        channel: String,
        policy: InvitationPolicy,
    },
    Share {
        channel: String,
        id: [u8; 16],
    },
    Inspect {
        link: String,
    },
    List {
        channel: String,
    },
    Revoke {
        channel: String,
        id: [u8; 16],
    },
    StartEnrollment {
        link: String,
        display: String,
    },
    EnrollmentStatus {
        id: [u8; 16],
    },
    ResumeEnrollment {
        id: [u8; 16],
    },
    CancelEnrollment {
        id: [u8; 16],
    },
    Retire {
        channel: String,
        id: [u8; 16],
    },
    ListEnrollments,
    RetireEnrollment {
        id: [u8; 16],
    },
}

impl std::fmt::Debug for InvitationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InvitationRequest([redacted])")
    }
}

impl InvitationRequest {
    pub fn validate(&self) -> Result<(), SdkError> {
        let valid_channel = |channel: &str| !channel.is_empty() && channel.len() <= 1024;
        let valid = match self {
            Self::StartEnrollment { link, display } => {
                !link.is_empty()
                    && link.len() <= 192 * 1024
                    && !display.is_empty()
                    && display.len() <= 1024
            }
            Self::ListEnrollments
            | Self::RetireEnrollment { .. }
            | Self::EnrollmentStatus { .. }
            | Self::ResumeEnrollment { .. }
            | Self::CancelEnrollment { .. } => true,
            Self::Create { channel, policy } => valid_channel(channel) && policy.validate().is_ok(),
            Self::Inspect { link } => !link.is_empty() && link.len() <= 192 * 1024,
            Self::List { channel }
            | Self::Retire { channel, .. }
            | Self::Share { channel, .. }
            | Self::Revoke { channel, .. } => valid_channel(channel),
        };
        if valid {
            Ok(())
        } else {
            Err(SdkError::Protocol("invalid invitation request".into()))
        }
    }
    pub fn required_capability(&self) -> crate::ipc::Capability {
        match self {
            Self::ListEnrollments
            | Self::RetireEnrollment { .. }
            | Self::Inspect { .. }
            | Self::StartEnrollment { .. }
            | Self::EnrollmentStatus { .. }
            | Self::ResumeEnrollment { .. }
            | Self::CancelEnrollment { .. } => crate::ipc::Capability::ChannelMember,
            _ => crate::ipc::Capability::ChannelAdmin,
        }
    }
}
impl zeroize::Zeroize for InvitationRequest {
    fn zeroize(&mut self) {
        if let Self::Inspect { link } | Self::StartEnrollment { link, .. } = self {
            link.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationDetails {
    pub link: String,
    pub channel: String,
    pub id: [u8; 16],
    pub policy: InvitationPolicy,
    pub local_only: bool,
}
impl std::fmt::Debug for InvitationDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationDetails")
            .field("link", &"[redacted]")
            .field("channel", &self.channel)
            .field("id", &self.id)
            .field("policy", &self.policy)
            .field("local_only", &self.local_only)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InvitationReply {
    Enrollment(EnrollmentStatus),
    Created(InvitationDetails),
    Inspected(InvitationDetails),
    Listed(Vec<InvitationSummary>),
    Revoked(InvitationSummary),
    Enrollments(Vec<EnrollmentStatus>),
    Retired,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn appended_ipc_policy_roundtrips_without_granting_machine_admin() {
        let request = crate::ipc::Request::Invitations(InvitationRequest::Create {
            channel: "friends".into(),
            policy: InvitationPreset::Friends.policy(100).unwrap(),
        });
        let bytes = postcard::to_allocvec(&request).unwrap();
        let previous = postcard::to_allocvec(&crate::ipc::Request::ChannelRecovery {
            channel: "friends".into(),
            request: None,
        })
        .unwrap();
        assert_eq!(bytes[0], previous[0] + 1);
        assert_eq!(
            postcard::from_bytes::<crate::ipc::Request>(&bytes).unwrap(),
            request
        );
        assert_eq!(request.minimum_version(), 23);
        assert_eq!(
            request.required_capability(),
            crate::ipc::Capability::ChannelAdmin
        );
        let inspect = InvitationRequest::Inspect {
            link: "opaque".into(),
        };
        assert_eq!(
            inspect.required_capability(),
            crate::ipc::Capability::ChannelMember
        );
        assert!(InvitationRequest::Create {
            channel: "x".into(),
            policy: InvitationPolicy {
                expires_at: None,
                max_admissions: Some(0)
            }
        }
        .validate()
        .is_err());
        let reply = InvitationReply::Inspected(InvitationDetails {
            link: "secret".into(),
            channel: "friends".into(),
            id: [7; 16],
            policy: InvitationPolicy {
                expires_at: None,
                max_admissions: None,
            },
            local_only: false,
        });
        assert_eq!(
            postcard::from_bytes::<InvitationReply>(&postcard::to_allocvec(&reply).unwrap())
                .unwrap(),
            reply
        );
        assert!(!format!("{reply:?}").contains("secret"));
    }
}
