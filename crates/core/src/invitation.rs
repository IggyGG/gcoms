//! Shared invitation policy values; no networking or admission authority.
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct InvitationPolicy {
    /// Absolute Unix seconds. None explicitly means no expiration.
    pub expires_at: Option<u64>,
    /// Total distinct admissions, never refunded by removing a member.
    pub max_admissions: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum InvitationPreset {
    OnePerson,
    Friends,
    Devices,
}

impl InvitationPreset {
    pub fn policy(self, now: u64) -> Result<InvitationPolicy, String> {
        let (lifetime, limit) = match self {
            Self::OnePerson => (3600, 1),
            Self::Friends => (7 * 86400, 25),
            Self::Devices => (90 * 86400, 100),
        };
        Ok(InvitationPolicy {
            expires_at: Some(
                now.checked_add(lifetime)
                    .ok_or("invitation time overflow")?,
            ),
            max_admissions: Some(limit),
        })
    }
}

impl InvitationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_admissions == Some(0) || self.expires_at == Some(0) {
            return Err("invitation bounds must be positive or explicitly unlimited".into());
        }
        Ok(())
    }

    pub fn validate_new(&self, now: u64) -> Result<(), String> {
        self.validate()?;
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err("invitation expiry must be in the future".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct InvitationSummary {
    pub id: [u8; 16],
    pub policy: InvitationPolicy,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
    pub revision: u64,
    pub admissions: u64,
    pub pending: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EnrollmentPhase {
    WaitingNetwork,
    WaitingOwner,
    VerifyingReturnRoute,
    AwaitingAdmission,
    ApplyingMembership,
    Joined,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct EnrollmentStatus {
    pub id: [u8; 16],
    pub channel: String,
    pub display: String,
    pub phase: EnrollmentPhase,
    pub attempts: u32,
    pub last_error: Option<String>,
}
