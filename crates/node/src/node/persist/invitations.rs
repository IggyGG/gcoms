//! One sealed extension around the existing archive. The only allowed nesting
//! is channel-inbox -> invitations -> base. Binding the exact base hash prevents
//! transplanting a ledger onto a different MLS state or rolling back its counter
//! independently of membership. Older readers reject the new magic.
use super::*;
use crate::channel_invite::policy::{InvitationLedger, PROFILE_BYTE_LIMIT};

fn context(seed: &[u8; 32], base: &[u8]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"channel-enrollment",
        Sha256::digest(base),
        b"gcoms/channel-enrollment/v1",
    )
    .map_err(|error| error.to_string())
}

pub(super) fn wrap(st: &NodeState, base: SecretBuffer) -> Result<SecretBuffer, String> {
    let mut channels = st
        .channels
        .iter()
        .filter(|(_, cs)| {
            !cs.invitations.records.is_empty()
                || !cs.catchup_members.is_empty()
                || !cs.membership_journal.is_empty()
        })
        .collect::<Vec<_>>();
    if channels.is_empty() && st.enrollments.is_empty() {
        return Ok(base);
    }
    channels.sort_by_key(|(left, _)| *left);
    let catchup_total = st
        .channels
        .values()
        .try_fold(0usize, |n, cs| n.checked_add(cs.catchup_bytes()))
        .ok_or("catch-up byte overflow")?;
    if catchup_total > PROFILE_BYTE_LIMIT {
        return Err("profile catch-up journal is full".into());
    }
    let mut plain = SecretBuffer(Vec::new());
    put_count(&mut plain, channels.len())?;
    for (name, cs) in channels {
        put16(&mut plain, name.as_bytes())?;
        let encoded = SecretBuffer(cs.invitations.encode()?);
        if plain
            .len()
            .checked_add(encoded.len())
            .and_then(|n| n.checked_add(4))
            .is_none_or(|n| n > PROFILE_BYTE_LIMIT)
        {
            return Err("profile enrollment byte limit reached".into());
        }
        put32(&mut plain, &encoded)?;
        if cs.catchup_bytes() > crate::channel::catchup::BYTE_LIMIT
            || cs.membership_records().count() > crate::channel::catchup::EPOCH_LIMIT
        {
            return Err("channel catch-up journal is full".into());
        }
        put_count(&mut plain, cs.catchup_members.len())?;
        let mut members = cs.catchup_members.iter().collect::<Vec<_>>();
        members.sort();
        for member in members {
            plain.extend_from_slice(member);
        }
        put_count(&mut plain, cs.membership_journal.len())?;
        for record in &cs.membership_journal {
            if record.commit_id != crate::channel::msg_id(name, &record.commit) {
                return Err(malformed());
            }
            plain.extend_from_slice(&record.commit_id);
            plain.extend_from_slice(&record.epoch.to_be_bytes());
            put32(&mut plain, &record.commit)?;
            encode_expected(&mut plain, &record.expected, &record.acknowledged)?;
        }
    }
    let operations = SecretBuffer(super::super::enrollment::encode(&st.enrollments)?);
    if plain
        .len()
        .checked_add(operations.len())
        .and_then(|n| n.checked_add(4))
        .is_none_or(|n| n > PROFILE_BYTE_LIMIT)
    {
        return Err("profile enrollment byte limit reached".into());
    }
    put32(&mut plain, &operations)?;
    let mut wrapped = SecretBuffer(MAGIC_INVITATIONS.to_vec());
    put32(&mut wrapped, &base)?;
    put_sensitive(
        &mut wrapped,
        seal_bytes(
            &channel_archive_key(&st.identity_seed),
            &context(&st.identity_seed, &base)?,
            &plain,
        )?,
    )?;
    if wrapped.len() > MAX_ARCHIVE_BYTES {
        return Err("node state export too large".into());
    }
    Ok(wrapped)
}

pub(super) fn base(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.get(..6) != Some(MAGIC_INVITATIONS) {
        return Ok(bytes);
    }
    let mut position = 6;
    let base = take32(bytes, &mut position)?;
    if matches!(base.get(..6), Some(magic) if magic == MAGIC_INVITATIONS || magic == MAGIC_CHANNEL_INBOX)
    {
        return Err(malformed());
    }
    Ok(base)
}

pub(super) fn unwrap(bytes: &[u8], seed: &[u8; 32]) -> Result<Archive, String> {
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(malformed());
    }
    let base = base(bytes)?;
    let mut position = 6;
    take32(bytes, &mut position)?;
    let sealed = take32(bytes, &mut position)?;
    if position != bytes.len() || sealed.len() > PROFILE_BYTE_LIMIT + 28 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &context(seed, base)?,
        sealed,
    )?);
    let mut archive = decode_v2(base, seed)?;
    let mut position = 0;
    let count = take_count(&plain, &mut position, MAX_CHANNEL_ITEMS)?;
    let mut names = HashSet::new();
    for _ in 0..count {
        let name = take_string16(&plain, &mut position)?;
        if !names.insert(name.clone()) {
            return Err(malformed());
        }
        let ledger = InvitationLedger::decode(take32(&plain, &mut position)?)?;
        let channel = archive
            .channels
            .iter_mut()
            .find(|cs| cs.name == name)
            .ok_or_else(malformed)?;
        channel.invitations = ledger;
        let count = take_count(&plain, &mut position, gcoms_mls::CHANNEL_MAX)?;
        for _ in 0..count {
            let member = take_array(&plain, &mut position)?;
            if !channel.catchup_members.insert(member) {
                return Err(malformed());
            }
        }
        let count = take_count(&plain, &mut position, crate::channel::catchup::EPOCH_LIMIT)?;
        let mut previous = channel.membership_outbox.as_ref().map_or(0, |p| p.epoch);
        for _ in 0..count {
            let commit_id = take_array(&plain, &mut position)?;
            let epoch = take_u64(&plain, &mut position)?;
            let commit = take32(&plain, &mut position)?.to_vec();
            if epoch <= previous
                || epoch > channel.role.epoch()
                || commit_id != crate::channel::msg_id(&name, &commit)
                || gcoms_mls::epoch_of_wire(&commit) != epoch.checked_sub(1)
            {
                return Err(malformed());
            }
            previous = epoch;
            let (expected, acknowledged) = decode_expected(&plain, &mut position)?;
            channel.membership_journal.push_back(MembershipOutbox {
                commit_id,
                epoch,
                commit,
                expected,
                acknowledged,
            });
        }
    }
    archive.enrollments = super::super::enrollment::decode(take32(&plain, &mut position)?)?;
    if position != plain.len() {
        return Err(malformed());
    }
    Ok(archive)
}
