use crate::relay::{Frwd, FrwdTargetPolicy, HopKey};
use gcoms_core::Cell;

pub fn decode_authorized(
    cell: &Cell,
    hop_key: &HopKey,
    intermediary_service_id: &[u8; 32],
    now_unix: u64,
    allow_local_fixture: bool,
) -> Option<Frwd> {
    decode_authorized_with_policy(
        cell,
        hop_key,
        intermediary_service_id,
        now_unix,
        &FrwdTargetPolicy::new(allow_local_fixture),
    )
}

pub fn decode_authorized_with_policy(
    cell: &Cell,
    hop_key: &HopKey,
    intermediary_service_id: &[u8; 32],
    now_unix: u64,
    policy: &FrwdTargetPolicy,
) -> Option<Frwd> {
    Frwd::decode_from_cell_with_policy(cell, hop_key, intermediary_service_id, now_unix, policy)
        .ok()
}
