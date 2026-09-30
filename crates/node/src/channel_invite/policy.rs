//! Owner-side invitation policy and bounded, persisted redemption accounting.
//!
//! Callers stage this ledger together with the MLS change and persist both before
//! returning success. No transport receipt is treated as a completed enrollment.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const INVITATION_LIMIT: usize = 64;
pub const PENDING_ENROLLMENT_LIMIT: usize = 64;
pub const RETAINED_MEMBER_LIMIT: usize = gcoms_mls::CHANNEL_MAX;
pub const CHANNEL_BYTE_LIMIT: usize = 32 * 1024 * 1024;
pub const PROFILE_BYTE_LIMIT: usize = 128 * 1024 * 1024;
pub const WELCOME_BYTE_LIMIT: usize = 256 * 1024;

pub use gcoms_core::invitation::{InvitationPolicy, InvitationPreset, InvitationSummary};

/// One immutable admission result. The request hash binds the MLS key package;
/// the member identity prevents another installation from reclaiming its slot.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Redemption {
    pub request: [u8; 32],
    pub member: [u8; 32],
    pub principal: Option<[u8; 32]>,
    pub name: String,
    pub epoch: u64,
    pub welcome: Vec<u8>,
    pub confirmed: bool,
    /// Explicit MLS removal releases a pending slot without inventing an ACK.
    pub removed: bool,
    pub bootstrap_id: [u8; 16],
}

impl Drop for Redemption {
    fn drop(&mut self) {
        self.welcome.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvitationRecord {
    pub id: [u8; 16],
    pub secret: [u8; 32],
    /// Channel owner identity at issue time; ownership transfer invalidates it.
    pub issuer: [u8; 32],
    pub policy: InvitationPolicy,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
    pub revision: u64,
    pub admissions: u64,
    pub redemptions: Vec<Redemption>,
    pub publication: Option<crate::node::invitation_directory::Publication>,
}

impl Drop for InvitationRecord {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl InvitationRecord {
    pub fn summary(&self) -> InvitationSummary {
        InvitationSummary {
            id: self.id,
            policy: self.policy,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
            revision: self.revision,
            admissions: self.admissions,
            pending: self
                .redemptions
                .iter()
                .filter(|r| !r.confirmed && !r.removed)
                .count() as u32,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvitationLedger {
    pub records: Vec<InvitationRecord>,
}

impl InvitationLedger {
    pub fn validate(&self) -> Result<(), String> {
        if self.records.len() > INVITATION_LIMIT {
            return Err("invitation ledger limit exceeded".into());
        }
        let mut ids = std::collections::HashSet::new();
        let mut requests = std::collections::HashSet::new();
        let mut members = std::collections::HashSet::new();
        let mut pending = 0usize;
        for record in &self.records {
            record.policy.validate()?;
            if !ids.insert(record.id)
                || record.revision == 0
                || record.admissions < record.redemptions.len() as u64
                || record
                    .policy
                    .max_admissions
                    .is_some_and(|max| record.admissions > max)
            {
                return Err("invalid invitation ledger accounting".into());
            }
            for result in &record.redemptions {
                if !requests.insert(result.request)
                    || !members.insert(result.member)
                    || result.name.len() > 1024
                    || result.welcome.len() > WELCOME_BYTE_LIMIT
                    || (!result.confirmed && !result.removed && result.welcome.is_empty())
                {
                    return Err("invalid invitation redemption".into());
                }
                pending += usize::from(!result.confirmed && !result.removed);
            }
        }
        if members.len() > RETAINED_MEMBER_LIMIT || pending > PENDING_ENROLLMENT_LIMIT {
            return Err("enrollment capacity reached".into());
        }
        let encoded = zeroize::Zeroizing::new(self.encode_unchecked()?);
        if encoded.len() > CHANNEL_BYTE_LIMIT {
            return Err("invitation ledger byte limit exceeded".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        self.encode_unchecked()
    }

    fn encode_unchecked(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|_| "cannot encode invitation ledger".into())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > CHANNEL_BYTE_LIMIT {
            return Err("invitation ledger byte limit exceeded".into());
        }
        let ledger: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid invitation ledger")?;
        ledger.validate()?;
        Ok(ledger)
    }

    pub fn insert(&mut self, record: InvitationRecord) -> Result<(), String> {
        if self.records.len() >= INVITATION_LIMIT {
            return Err(
                "invitation limit reached; close and retire an old invitation first".into(),
            );
        }
        if self.records.iter().any(|r| r.id == record.id) {
            return Err("invitation id collision".into());
        }
        self.records.push(record);
        if let Err(error) = self.validate() {
            self.records.pop();
            return Err(error);
        }
        Ok(())
    }

    /// Returns an exact previous result before checking policy expiry/revocation.
    /// This only authorizes retrieving an already-committed result, never a new
    /// MLS add. A removed member is rejected separately against the MLS roster.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        id: &[u8; 16],
        secret: &[u8; 32],
        issuer: &[u8; 32],
        request: &[u8; 32],
        member: &[u8; 32],
        name: &str,
        now: u64,
    ) -> Result<Option<&Redemption>, String> {
        let record = self
            .records
            .iter()
            .find(|r| &r.id == id)
            .ok_or("invite not found")?;
        if !bool::from(record.secret.ct_eq(secret)) || &record.issuer != issuer {
            return Err("invite not found".into());
        }
        if let Some(result) = record.redemptions.iter().find(|r| &r.request == request) {
            return if result.removed {
                Err("member was removed; request a new invitation".into())
            } else if &result.member == member && result.name == name {
                Ok(Some(result))
            } else {
                Err("enrollment does not match its original request".into())
            };
        }
        if self
            .records
            .iter()
            .flat_map(|r| &r.redemptions)
            .any(|r| &r.member == member || &r.request == request)
        {
            return Err("member already has an enrollment; resume its original request".into());
        }
        if record.revoked_at.is_some() {
            return Err("invite revoked".into());
        }
        if record.policy.expires_at.is_some_and(|expiry| now >= expiry) {
            return Err("invite expired".into());
        }
        if record
            .policy
            .max_admissions
            .is_some_and(|max| record.admissions >= max)
        {
            return Err("invite admission limit reached".into());
        }
        let pending = self
            .records
            .iter()
            .flat_map(|r| &r.redemptions)
            .filter(|r| !r.confirmed && !r.removed)
            .count();
        let retained = self
            .records
            .iter()
            .map(|r| r.redemptions.len())
            .sum::<usize>();
        if pending >= PENDING_ENROLLMENT_LIMIT || retained >= RETAINED_MEMBER_LIMIT {
            return Err("enrollment capacity reached".into());
        }
        record
            .admissions
            .checked_add(1)
            .ok_or("invitation admission counter exhausted")?;
        Ok(None)
    }

    pub fn commit(&mut self, id: &[u8; 16], result: Redemption) -> Result<(), String> {
        let record = self
            .records
            .iter_mut()
            .find(|r| &r.id == id)
            .ok_or("invite not found")?;
        record.admissions = record
            .admissions
            .checked_add(1)
            .ok_or("invitation admission counter exhausted")?;
        record.redemptions.push(result);
        if let Err(error) = self.validate() {
            let record = self
                .records
                .iter_mut()
                .find(|r| &r.id == id)
                .expect("same record");
            record.redemptions.pop();
            record.admissions -= 1;
            return Err(error);
        }
        Ok(())
    }

    pub fn confirm(
        &mut self,
        bootstrap_id: &[u8; 16],
        member: &[u8; 32],
    ) -> Option<(usize, usize)> {
        for (record_index, record) in self.records.iter_mut().enumerate() {
            for (result_index, result) in record.redemptions.iter_mut().enumerate() {
                if &result.bootstrap_id == bootstrap_id
                    && &result.member == member
                    && !result.confirmed
                    && !result.removed
                {
                    result.confirmed = true;
                    return Some((record_index, result_index));
                }
            }
        }
        None
    }

    pub(crate) fn remove_member(&mut self, member: &[u8; 32]) {
        for result in self.records.iter_mut().flat_map(|r| &mut r.redemptions) {
            if &result.member == member {
                result.removed = true;
                result.welcome.zeroize();
                result.welcome.clear();
            }
        }
    }

    pub fn rollback_confirmation(&mut self, index: (usize, usize)) {
        self.records[index.0].redemptions[index.1].confirmed = false;
    }

    pub fn revoke(&mut self, id: &[u8; 16], now: u64) -> Result<InvitationSummary, String> {
        let record = self
            .records
            .iter_mut()
            .find(|r| &r.id == id)
            .ok_or("invite not found")?;
        if record.revoked_at.is_none() {
            record.revision = record
                .revision
                .checked_add(1)
                .ok_or("invitation revision exhausted")?;
            record.revoked_at = Some(now);
        }
        Ok(record.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(policy: InvitationPolicy) -> InvitationLedger {
        let mut ledger = InvitationLedger::default();
        ledger
            .insert(InvitationRecord {
                id: [1; 16],
                secret: [2; 32],
                issuer: [3; 32],
                policy,
                created_at: 1,
                revoked_at: None,
                revision: 1,
                admissions: 0,
                redemptions: Vec::new(),
                publication: None,
            })
            .unwrap();
        ledger
    }
    #[test]
    fn removal_releases_pending_capacity_without_refund_or_fake_confirmation() {
        let mut ledger = ledger(InvitationPolicy {
            expires_at: None,
            max_admissions: Some(2),
        });
        ledger.commit(&[1; 16], result(8)).unwrap();
        assert_eq!(ledger.records[0].summary().pending, 1);
        ledger.remove_member(&[8; 32]);
        let summary = ledger.records[0].summary();
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.admissions, 1);
        let removed = &ledger.records[0].redemptions[0];
        assert!(!removed.confirmed);
        assert!(removed.removed);
        assert!(removed.welcome.is_empty());
        assert!(ledger
            .authorize(&[1; 16], &[2; 32], &[3; 32], &[8; 32], &[8; 32], "member8", 1)
            .is_err());
        assert!(
            InvitationLedger::decode(&ledger.encode().unwrap())
                .unwrap()
                .records[0]
                .redemptions[0]
                .removed
        );
    }

    fn result(n: u8) -> Redemption {
        Redemption {
            request: [n; 32],
            member: [n; 32],
            principal: None,
            name: format!("member-{n}"),
            epoch: u64::from(n),
            welcome: vec![n; 20],
            confirmed: false,
            removed: false,
            bootstrap_id: [n; 16],
        }
    }
    fn authorize(
        ledger: &InvitationLedger,
        n: u8,
        now: u64,
    ) -> Result<Option<&Redemption>, String> {
        ledger.authorize(
            &[1; 16],
            &[2; 32],
            &[3; 32],
            &[n; 32],
            &[n; 32],
            &format!("member-{n}"),
            now,
        )
    }

    #[test]
    fn limit_is_durable_and_exact_retry_does_not_consume_again() {
        let mut ledger = ledger(InvitationPolicy {
            expires_at: Some(20),
            max_admissions: Some(2),
        });
        for n in [4, 5] {
            assert!(authorize(&ledger, n, 10).unwrap().is_none());
            ledger.commit(&[1; 16], result(n)).unwrap();
        }
        let mut ledger = InvitationLedger::decode(&ledger.encode().unwrap()).unwrap();
        assert_eq!(
            authorize(&ledger, 6, 10).err().unwrap(),
            "invite admission limit reached"
        );
        ledger.revoke(&[1; 16], 11).unwrap();
        assert_eq!(
            authorize(&ledger, 4, 30).unwrap().unwrap().welcome,
            vec![4; 20]
        );
        assert_eq!(ledger.records[0].admissions, 2);
        assert!(ledger
            .authorize(&[1; 16], &[9; 32], &[3; 32], &[4; 32], &[4; 32], "member-4", 10)
            .is_err());
        assert!(ledger
            .authorize(&[1; 16], &[2; 32], &[8; 32], &[4; 32], &[4; 32], "member-4", 10)
            .is_err());
        assert!(ledger
            .authorize(
                &[1; 16],
                &[2; 32],
                &[3; 32],
                &[4; 32],
                &[4; 32],
                "different",
                10
            )
            .is_err());
    }

    #[test]
    fn expiry_and_total_limit_are_independent() {
        let mut finite = ledger(InvitationPolicy {
            expires_at: None,
            max_admissions: Some(1),
        });
        assert!(authorize(&finite, 4, u64::MAX).unwrap().is_none());
        finite.commit(&[1; 16], result(4)).unwrap();
        assert!(authorize(&finite, 5, u64::MAX).is_err());
        let timed = ledger(InvitationPolicy {
            expires_at: Some(10),
            max_admissions: None,
        });
        assert!(authorize(&timed, 4, 9).unwrap().is_none());
        assert_eq!(authorize(&timed, 4, 10).err().unwrap(), "invite expired");
    }

    #[test]
    fn unlimited_policy_still_has_pending_capacity_and_rejects_corrupt_archive() {
        let mut ledger = ledger(InvitationPolicy {
            expires_at: None,
            max_admissions: None,
        });
        for n in 0..PENDING_ENROLLMENT_LIMIT as u8 {
            ledger.commit(&[1; 16], result(n)).unwrap();
        }
        assert_eq!(
            authorize(&ledger, 200, 10).err().unwrap(),
            "enrollment capacity reached"
        );
        assert!(ledger.commit(&[1; 16], result(200)).is_err());
        assert_eq!(ledger.records[0].admissions, 64);
        let mut corrupt = ledger.encode().unwrap();
        corrupt.extend_from_slice(b"{}");
        assert!(InvitationLedger::decode(&corrupt).is_err());
        ledger.records[0].admissions = 0;
        assert!(ledger.encode().is_err());
    }
}
