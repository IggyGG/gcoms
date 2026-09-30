//! Ordered, bounded membership delivery. A missing ACK holds that recipient's
//! next commit, not every other member's admission. Legacy members keep the old
//! convergence barrier until their authenticated enrollment opts into history.
use super::*;

pub(crate) const EPOCH_LIMIT: usize = 128;
pub(crate) const BYTE_LIMIT: usize = 32 * 1024 * 1024;

impl ChannelState {
    pub(crate) fn catchup_enabled(&self) -> bool {
        self.role.roster_members().iter().all(|member| {
            member.pseudonym == self.role.own_pseudonym()
                || self.catchup_members.contains(&member.pseudonym)
        })
    }
    pub(crate) fn membership_pending(&self) -> bool {
        self.membership_outbox.is_some() || !self.membership_journal.is_empty()
    }
    pub(crate) fn membership_barrier(&self) -> bool {
        self.membership_pending() && !self.catchup_enabled()
    }
    pub(crate) fn membership_records(&self) -> impl Iterator<Item = &MembershipOutbox> {
        self.membership_outbox
            .iter()
            .chain(self.membership_journal.iter())
    }
    pub(crate) fn membership_records_mut(&mut self) -> impl Iterator<Item = &mut MembershipOutbox> {
        self.membership_outbox
            .iter_mut()
            .chain(self.membership_journal.iter_mut())
    }
    pub(crate) fn retain_membership(&mut self, record: MembershipOutbox) {
        if self.membership_outbox.is_none() {
            self.membership_outbox = Some(record);
        } else {
            self.membership_journal.push_back(record);
        }
    }
    pub(crate) fn catchup_bytes(&self) -> usize {
        // Exact encoded recipient records: identity, route-length prefix,
        // fixed route wire and the independently encoded ACK identities.
        let recipients = |expected: usize, acknowledged: usize| {
            8usize
                .saturating_add(expected.saturating_mul(32 + 4 + CHANNEL_ROUTE_LEN))
                .saturating_add(acknowledged.saturating_mul(32))
        };
        let membership = self.membership_records().fold(0usize, |n, r| {
            n.saturating_add(28)
                .saturating_add(r.commit.len())
                .saturating_add(recipients(r.expected.len(), r.acknowledged.len()))
        });
        self.message_outbox.values().fold(membership, |n, r| {
            n.saturating_add(20)
                .saturating_add(r.wire.len())
                .saturating_add(recipients(r.expected.len(), r.acknowledged.len()))
        })
    }
    /// Called before staging a membership change, with headroom for the commit
    /// and its bootstrap. The sealed archive also checks the exact final size.
    pub(crate) fn reserve_epoch(&self) -> Result<(), String> {
        self.reserve_epoch_after_removing(None)
    }
    pub(crate) fn reserve_epoch_after_removing(
        &self,
        removed: Option<[u8; 32]>,
    ) -> Result<(), String> {
        let current = self
            .role
            .roster_members()
            .into_iter()
            .map(|m| m.pseudonym)
            .collect::<HashSet<_>>();
        let needed = |expected: &HashMap<[u8; 32], ChannelRoute>| {
            expected
                .keys()
                .any(|id| Some(*id) != removed && current.contains(id))
        };
        if self
            .membership_records()
            .filter(|r| needed(&r.expected))
            .count()
            >= EPOCH_LIMIT
            || self.catchup_bytes().saturating_add(1024 * 1024) > BYTE_LIMIT
        {
            return Err(
                "channel catch-up journal is full; reconnect or remove offline members".into(),
            );
        }
        let oldest = self
            .membership_records()
            .filter(|r| needed(&r.expected))
            .map(|r| r.epoch.saturating_sub(1))
            .chain(
                self.message_outbox
                    .values()
                    .filter(|r| needed(&r.expected))
                    .filter_map(|r| gcoms_mls::epoch_of_wire(&r.wire)),
            )
            .min();
        if oldest.is_some_and(|epoch| {
            self.role.epoch().saturating_add(1).saturating_sub(epoch) > EPOCH_LIMIT as u64
        }) {
            return Err(
                "channel catch-up epoch limit reached; reconnect or remove offline members".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn membership_target_ready(&self, epoch: u64, member: &[u8; 32]) -> bool {
        !self.membership_records().any(|prior| {
            prior.epoch < epoch
                && prior.expected.contains_key(member)
                && !prior.acknowledged.contains(member)
        })
    }
    pub(crate) fn remove_enrollment_member(&mut self, member: &[u8; 32]) {
        // Discard only this removed member's internal bootstrap messages.
        // Ordinary application wires and their delivery state remain intact.
        let bootstrap = self
            .invitations
            .records
            .iter()
            .flat_map(|r| &r.redemptions)
            .filter(|r| &r.member == member)
            .map(|r| r.bootstrap_id)
            .collect::<Vec<_>>();
        for id in bootstrap {
            self.message_outbox.remove(&id);
        }
        self.invitations.remove_member(member);
        self.catchup_members.remove(member);
    }
    pub(crate) fn prune_membership_member(&mut self, member: &[u8; 32]) {
        for record in self.membership_records_mut() {
            record.expected.remove(member);
            record.acknowledged.remove(member);
        }
        self.prune_complete_memberships();
    }
    fn prune_complete_memberships(&mut self) {
        self.membership_journal
            .retain(|r| r.acknowledged.len() != r.expected.len());
        if self
            .membership_outbox
            .as_ref()
            .is_some_and(|r| r.acknowledged.len() == r.expected.len())
        {
            self.membership_outbox = self.membership_journal.pop_front();
        }
    }
    pub(crate) fn acknowledge_membership(
        &mut self,
        id: [u8; 16],
        epoch: u64,
        member: [u8; 32],
    ) -> bool {
        let Some(record) = self
            .membership_records_mut()
            .find(|r| r.commit_id == id && r.epoch == epoch)
        else {
            return false;
        };
        if !record.expected.contains_key(&member) {
            return false;
        }
        record.acknowledged.insert(member);
        self.prune_complete_memberships();
        true
    }
}
