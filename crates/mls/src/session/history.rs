//! Epoch-bound sender identities. OpenMLS authenticates old application wires
//! against its retained tree; application code must not resolve their leaf
//! indices against the *current* roster (indices can be reused after removal).
use super::*;
use std::collections::BTreeMap;

pub(super) const EPOCHS: usize = 128;
const KEY: &[u8] = b"gcoms/epoch-rosters/v1";
const MAX_BYTES: usize = 16 * 1024 * 1024;
type History = BTreeMap<u64, Vec<RosterMember>>;

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], MlsError> {
    if bytes.len() < n {
        return Err(MlsError::Encoding);
    }
    let (item, rest) = bytes.split_at(n);
    *bytes = rest;
    Ok(item)
}
fn decode(mut bytes: &[u8]) -> Result<History, MlsError> {
    if bytes.is_empty() {
        return Ok(History::new());
    }
    if bytes.len() > MAX_BYTES {
        return Err(MlsError::Encoding);
    }
    let count = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().unwrap()) as usize;
    if count > EPOCHS {
        return Err(MlsError::Encoding);
    }
    let mut history = History::new();
    for _ in 0..count {
        let epoch = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
        let count = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().unwrap()) as usize;
        if count > CHANNEL_MAX {
            return Err(MlsError::Encoding);
        }
        let mut roster = Vec::with_capacity(count);
        for _ in 0..count {
            let leaf_index = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap());
            let pseudonym = take(&mut bytes, 32)?.try_into().unwrap();
            let len = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().unwrap()) as usize;
            if len > 1024 {
                return Err(MlsError::Encoding);
            }
            let display_name = String::from_utf8(take(&mut bytes, len)?.to_vec())
                .map_err(|_| MlsError::Encoding)?;
            roster.push(RosterMember {
                leaf_index,
                pseudonym,
                display_name,
            });
        }
        if history.insert(epoch, roster).is_some() {
            return Err(MlsError::Encoding);
        }
    }
    if !bytes.is_empty() {
        return Err(MlsError::Encoding);
    }
    Ok(history)
}
fn encode(history: &History) -> Result<Vec<u8>, MlsError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(history.len() as u16).to_be_bytes());
    for (epoch, roster) in history {
        bytes.extend_from_slice(&epoch.to_be_bytes());
        bytes.extend_from_slice(&(roster.len() as u16).to_be_bytes());
        for member in roster {
            if member.display_name.len() > 1024 {
                return Err(MlsError::Encoding);
            }
            bytes.extend_from_slice(&member.leaf_index.to_be_bytes());
            bytes.extend_from_slice(&member.pseudonym);
            bytes.extend_from_slice(&(member.display_name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(member.display_name.as_bytes());
            if bytes.len() > MAX_BYTES {
                return Err(MlsError::GroupFull);
            }
        }
    }
    Ok(bytes)
}
impl Ctx {
    pub(super) fn retain_epoch_roster(&self) -> Result<(), MlsError> {
        let mut storage = self
            .backend
            .storage()
            .values
            .write()
            .map_err(|_| MlsError::Encoding)?;
        let mut history = decode(storage.get(KEY).map(Vec::as_slice).unwrap_or_default())?;
        let epoch = self.epoch();
        history.retain(|previous, _| epoch.saturating_sub(*previous) < EPOCHS as u64);
        history.insert(epoch, self.roster_members());
        let bytes = encode(&history)?;
        storage.insert(KEY.to_vec(), bytes);
        Ok(())
    }
    pub(super) fn sender_at_epoch(&self, epoch: u64, index: u32) -> Result<RosterMember, MlsError> {
        let roster = if epoch == self.epoch() {
            self.roster_members()
        } else {
            let storage = self
                .backend
                .storage()
                .values
                .read()
                .map_err(|_| MlsError::Encoding)?;
            decode(storage.get(KEY).map(Vec::as_slice).unwrap_or_default())?
                .remove(&epoch)
                .ok_or(MlsError::Unauthorized)?
        };
        roster
            .into_iter()
            .find(|m| m.leaf_index == index)
            .ok_or(MlsError::Unauthorized)
    }
}
