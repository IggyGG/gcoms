//! Persisted owner invitation management. No network authority is extended here.
use super::*;
use crate::channel_invite::policy::{InvitationPolicy, InvitationRecord, InvitationSummary};

#[derive(Clone)]
pub struct IssuedInvitation {
    pub summary: InvitationSummary,
    pub secret: [u8; 32],
}

impl Drop for IssuedInvitation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl NodeHandle {
    /// Explicitly retire a revoked record only after all remaining members have
    /// confirmed their durable join. This never abandons a pending Welcome.
    pub async fn retire_invitation(&self, channel: &str, id: [u8; 16]) -> Result<(), String> {
        let state = self.state.upgrade().ok_or("node closed")?;
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        require_durable(&st)?;
        let cs = owner_channel(&st, channel)?;
        let index = cs
            .invitations
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or("invite not found")?;
        let record = &cs.invitations.records[index];
        if record.revoked_at.is_none() {
            return Err("revoke the invitation before retiring it".into());
        }
        if record
            .redemptions
            .iter()
            .any(|r| !r.confirmed && !r.removed)
        {
            return Err(
                "members are still confirming; retain this invitation's enrollment results".into(),
            );
        }
        let record = st
            .channels
            .get_mut(channel)
            .unwrap()
            .invitations
            .records
            .remove(index);
        if let Err(error) = persist_current_direct_state(&st) {
            st.channels
                .get_mut(channel)
                .unwrap()
                .invitations
                .records
                .insert(index, record);
            return Err(error);
        }
        Ok(())
    }
}

pub(crate) fn require_durable(st: &NodeState) -> Result<(), String> {
    #[cfg(feature = "client-persist")]
    if st.durable_state_sink.is_some() {
        return Ok(());
    }
    let _ = st;
    Err("reusable invitations require a durable profile".into())
}

fn owner_channel<'a>(
    st: &'a NodeState,
    channel: &str,
) -> Result<&'a crate::channel::ChannelState, String> {
    let cs = st.channels.get(channel).ok_or("no channel")?;
    if !cs.role.is_owner() {
        return Err("not owner".into());
    }
    if crate::channel::metadata::Metadata::read(&cs.role)?.closed() {
        return Err("This channel is closed".into());
    }
    Ok(cs)
}

pub(crate) fn create(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    policy: InvitationPolicy,
) -> Result<IssuedInvitation, String> {
    let now = now_unix();
    policy.validate_new(now)?;
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    require_durable(&st)?;
    let cs = owner_channel(&st, channel)?;
    let issuer = cs.role.own_pseudonym();
    let prior = cs.invitations.clone();
    let mut id = [0; 16];
    let mut secret = [0; 32];
    rand::thread_rng().fill_bytes(&mut id);
    rand::thread_rng().fill_bytes(&mut secret);
    let record = InvitationRecord {
        id,
        secret,
        issuer,
        policy,
        created_at: now,
        revoked_at: None,
        revision: 1,
        admissions: 0,
        redemptions: Vec::new(),
        publication: None,
    };
    let summary = record.summary();
    st.channels
        .get_mut(channel)
        .expect("locked channel")
        .invitations
        .insert(record)?;
    if let Err(error) = persist_current_direct_state(&st) {
        st.channels
            .get_mut(channel)
            .expect("locked channel")
            .invitations = prior;
        use zeroize::Zeroize;
        secret.zeroize();
        return Err(error);
    }
    Ok(IssuedInvitation { summary, secret })
}

pub(crate) fn list(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
) -> Result<Vec<InvitationSummary>, String> {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    let cs = owner_channel(&st, channel)?;
    Ok(cs
        .invitations
        .records
        .iter()
        .map(InvitationRecord::summary)
        .collect())
}

pub(crate) fn revoke(
    state: &Arc<Mutex<NodeState>>,
    channel: &str,
    id: [u8; 16],
) -> Result<InvitationSummary, String> {
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    require_durable(&st)?;
    let prior = owner_channel(&st, channel)?.invitations.clone();
    let summary = st
        .channels
        .get_mut(channel)
        .expect("locked channel")
        .invitations
        .revoke(&id, now_unix())?;
    if let Err(error) = persist_current_direct_state(&st) {
        st.channels
            .get_mut(channel)
            .expect("locked channel")
            .invitations = prior;
        return Err(error);
    }
    Ok(summary)
}
