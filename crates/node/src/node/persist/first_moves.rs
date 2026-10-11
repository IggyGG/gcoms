//! Bounded retired GC/2 setup requests, sealed to the exact session archive.
//! Older readers reject this extension rather than silently losing replay guards.
use super::*;

const LIMIT: usize = 512;

fn context(seed: &[u8; 32], base: &[u8]) -> Result<SessionContext, String> {
    SessionContext::new(
        Sha256::digest(IdentityKeypair::from_seed(*seed).public_bytes()),
        b"retired-first-moves",
        Sha256::digest(base),
        b"gcoms/retired-first-moves/v1",
    )
    .map_err(|error| error.to_string())
}

pub(super) fn wrap(st: &NodeState, base: SecretBuffer) -> Result<SecretBuffer, String> {
    if base.get(..6) != Some(MAGIC_V21) || st.accepted_first_moves.is_empty() {
        return Ok(base);
    }
    // Normal first-move acceptance stages the newest hash before trimming.
    let count = st.accepted_first_moves.len().min(LIMIT);
    let mut plain = SecretBuffer(Vec::with_capacity(4 + 32 * count));
    put_count(&mut plain, count)?;
    for hash in st
        .accepted_first_moves
        .iter()
        .skip(st.accepted_first_moves.len() - count)
    {
        plain.extend_from_slice(hash);
    }
    let mut wrapped = SecretBuffer(MAGIC_FIRST_MOVES.to_vec());
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
    if bytes.get(..6) != Some(MAGIC_FIRST_MOVES) {
        return Ok(bytes);
    }
    let mut position = 6;
    let base = take32(bytes, &mut position)?;
    if base.get(..6) != Some(MAGIC_V21) {
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
    if position != bytes.len() || sealed.len() > 4 + 32 * LIMIT + 28 {
        return Err(malformed());
    }
    let plain = SecretBuffer(open_bytes(
        &channel_archive_key(seed),
        &context(seed, base)?,
        sealed,
    )?);
    let mut position = 0;
    let count = take_count(&plain, &mut position, LIMIT)?;
    let mut hashes = VecDeque::with_capacity(count);
    let mut unique = HashSet::with_capacity(count);
    for _ in 0..count {
        let hash = take_array(&plain, &mut position)?;
        if !unique.insert(hash) {
            return Err(malformed());
        }
        hashes.push_back(hash);
    }
    if position != plain.len() {
        return Err(malformed());
    }
    let mut archive = decode_v2(base, seed)?;
    archive.accepted_first_moves = hashes;
    Ok(archive)
}
