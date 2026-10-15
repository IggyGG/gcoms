//! Supersession is limited to deferred routing state, never application records
//! or already allocated ratchet counters. The caller owns the durable transaction.
use super::*;

pub(super) fn superseded(
    st: &NodeState,
    peer: &[u8],
    message_id: [u8; 16],
    record: &[u8],
) -> Vec<[u8; 16]> {
    let Some(new) = decode_direct_record(record) else {
        return Vec::new();
    };
    if new.message_id() != message_id {
        return Vec::new();
    }
    match &new {
        DirectRecord::ContactUpdate { update, .. }
            if update.verify(&st.info.identity_pk, now_unix()) => {}
        DirectRecord::ForwardGrant { grant, .. }
            if grant.issued_by == st.info.identity_pk && grant.expires_at > now_unix() => {}
        _ => return Vec::new(),
    }
    st.pending_1to1
        .iter()
        .filter_map(|(id, pending)| {
            if *id == message_id
                || pending.application_event
                || !pending.delivery.cells.is_empty()
                || pending.delivery.peer.identity_pk != peer
            {
                return None;
            }
            let old = decode_direct_record(pending.logical_record.as_ref()?)?;
            if old.message_id() != *id {
                return None;
            }
            let replaced = match (&new, old) {
                (
                    DirectRecord::ContactUpdate { update: new, .. },
                    DirectRecord::ContactUpdate { update: old, .. },
                ) => {
                    old.generation < new.generation
                        && old.verify(&st.info.identity_pk, old.issued_at)
                }
                (
                    DirectRecord::ForwardGrant { grant: new, .. },
                    DirectRecord::ForwardGrant { grant: old, .. },
                ) => {
                    old.issued_by == new.issued_by
                        && old.target == new.target
                        && old.frwd_path == new.frwd_path
                        && old.hop_key == new.hop_key
                        && old.expires_at <= new.expires_at
                }
                _ => false,
            };
            replaced.then_some(*id)
        })
        .collect()
}
