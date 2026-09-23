use super::protocol::*;
use super::{Error, Result};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use fs2::FileExt;
use gcoms_private_fs::{make_private, validate_private_dir, validate_private_file};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    pub quota_bytes: u64,
    pub retention_secs: u64,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            quota_bytes: 10 * 1024 * 1024 * 1024,
            retention_secs: 7 * 24 * 3600,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Offered,
    Importing,
    Downloading,
    Paused,
    Complete,
    Failed,
    Cancelled,
}
const LEGACY_MEMBERSHIP_PAUSE: &str = "Conversation membership unavailable; transfer paused";
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub manifest: Manifest,
    pub status: Status,
    pub have: Vec<bool>,
    pub created: u64,
    pub completed: Option<u64>,
    pub error: Option<String>,
    #[serde(default)]
    pub completed_by: Vec<Member>,
    #[serde(default)]
    pub duplicate_of: Option<ShareId>,
}
impl State {
    pub fn verified_bytes(&self) -> u64 {
        self.have
            .iter()
            .enumerate()
            .filter(|(_, have)| **have)
            .map(|(i, _)| self.manifest.piece_len(i as u32).unwrap_or(0) as u64)
            .sum()
    }
    fn reserved(&self) -> u64 {
        if self.duplicate_of.is_some() || matches!(self.status, Status::Offered | Status::Cancelled)
        {
            4096 + self.have.len() as u64 * 8
        } else {
            self.manifest.reservation()
        }
    }
}

pub struct Cache {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    pub config: CacheConfig,
    entries: BTreeMap<ShareId, State>,
    _lock: File,
}
fn private_error(_: String) -> Error {
    Error::Invalid("unsafe cache filesystem permissions or type")
}
fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
        make_private(path, true).map_err(private_error)?;
    }
    validate_private_dir(path, "file cache").map_err(private_error)
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error::Invalid("cache parent"))?;
    validate_private_dir(parent, "file cache").map_err(private_error)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".stage-")
        .tempfile_in(parent)?;
    make_private(temp.path(), false).map_err(private_error)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| Error::Io(e.error))?;
    crate::journal::sync_directory(parent)?;
    Ok(())
}
fn read_private(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    validate_private_file(path, "file cache entry").map_err(private_error)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::Invalid("cache entry length"));
    }
    Ok(bytes)
}
impl Cache {
    pub fn open(root: &Path, key: [u8; 32], config: CacheConfig) -> Result<Self> {
        if config.quota_bytes < 4096 || config.retention_secs == 0 {
            return Err(Error::Invalid("cache limits"));
        }
        private_dir(root)?;
        let lock_path = root.join("cache.lock");
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => {
                make_private(&lock_path, false).map_err(private_error)?;
                file
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_private_file(&lock_path, "cache lock").map_err(private_error)?;
                OpenOptions::new().read(true).write(true).open(&lock_path)?
            }
            Err(e) => return Err(e.into()),
        };
        lock.try_lock_exclusive()?;
        let mut cache = Self {
            root: root.into(),
            key: Zeroizing::new(key),
            config,
            entries: BTreeMap::new(),
            _lock: lock,
        };
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.len() != 32 || !name.bytes().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            validate_private_dir(&entry.path(), "share directory").map_err(private_error)?;
            let id: ShareId = hex::decode(name)
                .map_err(|_| Error::Invalid("share ID"))?
                .try_into()
                .map_err(|_| Error::Invalid("share ID"))?;
            let path = entry.path().join("state");
            if !path.exists() {
                std::fs::remove_dir_all(entry.path())?;
                continue;
            }
            let sealed = read_private(&path, 8 * MAX_PIECES + 16384)?;
            if sealed.len() < 28 {
                return Err(Error::Invalid("encrypted journal"));
            }
            let plain = Zeroizing::new(
                Aes256Gcm::new_from_slice(cache.key.as_ref())
                    .expect("key length")
                    .decrypt(
                        Nonce::from_slice(&sealed[..12]),
                        Payload {
                            msg: &sealed[12..],
                            aad: &id,
                        },
                    )
                    .map_err(|_| Error::Invalid("journal authentication"))?,
            );
            let mut state: State =
                serde_json::from_slice(&plain).map_err(|_| Error::Invalid("journal encoding"))?;
            state.manifest.validate()?;
            if state.manifest.id != id
                || state.have.len() != state.manifest.pieces()
                || cache.entries.len() >= MAX_TRANSFERS
            {
                return Err(Error::Invalid("journal bounds"));
            }

            // Finish cleanup interrupted by process or power loss while this
            // exclusive cache owner was replacing or cancelling a piece.
            if state.status == Status::Cancelled || state.duplicate_of.is_some() {
                cache.remove_pieces(id)?;
            }
            for artifact in std::fs::read_dir(entry.path())? {
                let artifact = artifact?;
                if artifact
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".stage-"))
                {
                    validate_private_file(&artifact.path(), "interrupted cache write")
                        .map_err(private_error)?;
                    std::fs::remove_file(artifact.path())?;
                }
            }
            // Older engines persisted temporary roster unavailability as a user
            // pause. Recover only that specific automatic pause; all other pauses
            // and failures retain their existing meaning.
            let membership_wait = state.status == Status::Paused
                && state.error.as_deref() == Some(LEGACY_MEMBERSHIP_PAUSE);
            if membership_wait {
                state.status = Status::Downloading;
                state.error = None;
            }
            // A single linear recovery scan. Never trust a journal bit without its bytes.
            let mut repaired = false;
            for i in 0..state.have.len() {
                if !state.have[i] {
                    continue;
                }
                let valid = if state.status == Status::Importing {
                    cache
                        .read_raw(id, i as u32)
                        .and_then(|(_, bytes)| {
                            state.manifest.open(i as u32, &bytes).map(Zeroizing::new)
                        })
                        .is_ok()
                } else {
                    cache.read_piece_with(&state.manifest, i as u32).is_ok()
                };
                if state.have[i] && !valid {
                    state.have[i] = false;
                    repaired = true;
                }
            }
            if repaired {
                if state.status != Status::Importing {
                    state.status = Status::Paused;
                }
                state.completed = None;
                state.error =
                    Some("Retained pieces failed verification; resume to repair them".into());
            }
            if repaired || membership_wait {
                cache.save(&state)?;
            }
            cache.entries.insert(id, state);
        }
        // Lowering the quota never discards active jobs; admission remains blocked.
        Ok(cache)
    }
    fn dir(&self, id: ShareId) -> PathBuf {
        self.root.join(hex::encode(id))
    }
    fn piece_path(&self, id: ShareId, index: u32) -> PathBuf {
        self.dir(id).join(format!("{index}.piece"))
    }
    fn save(&self, state: &State) -> Result<()> {
        private_dir(&self.dir(state.manifest.id))?;
        let plain = Zeroizing::new(
            serde_json::to_vec(state).map_err(|_| Error::Invalid("journal encoding"))?,
        );
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let sealed = Aes256Gcm::new_from_slice(self.key.as_ref())
            .expect("key length")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &state.manifest.id,
                },
            )
            .map_err(|_| Error::Invalid("journal encryption"))?;
        let mut bytes = nonce.to_vec();
        bytes.extend(sealed);
        atomic(&self.dir(state.manifest.id).join("state"), &bytes)
    }
    fn replace(&mut self, state: State) -> Result<()> {
        self.save(&state)?;
        self.entries.insert(state.manifest.id, state);
        Ok(())
    }
    pub fn entries(&self) -> &BTreeMap<ShareId, State> {
        &self.entries
    }
    pub fn get(&self, id: ShareId) -> Result<&State> {
        self.entries.get(&id).ok_or(Error::Unavailable)
    }
    pub fn used(&self) -> u64 {
        self.entries.values().map(State::reserved).sum()
    }
    pub fn expire(&mut self, now: u64) -> Result<()> {
        let ids: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, s)| {
                s.completed
                    .is_some_and(|at| at.saturating_add(self.config.retention_secs) <= now)
                    || (matches!(s.status, Status::Offered | Status::Cancelled)
                        && s.created.saturating_add(self.config.retention_secs) <= now)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.remove(id)?;
        }
        Ok(())
    }
    fn admit(&mut self, bytes: u64, now: u64) -> Result<()> {
        self.expire(now)?;
        while self.used().saturating_add(bytes) > self.config.quota_bytes {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, s)| s.status == Status::Complete)
                .min_by_key(|(_, s)| s.completed)
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => self.remove(id)?,
                None => return Err(Error::Quota),
            }
        }
        Ok(())
    }
    pub fn offer(&mut self, manifest: Manifest, now: u64) -> Result<()> {
        manifest.validate()?;
        if let Some(old) = self.entries.get(&manifest.id) {
            return if old.manifest == manifest {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if self.entries.len() >= MAX_TRANSFERS {
            return Err(Error::Quota);
        }
        // Unsolicited descriptors cannot evict accepted, retained content.
        if self
            .used()
            .saturating_add(4096 + manifest.pieces() as u64 * 8)
            > self.config.quota_bytes
        {
            return Err(Error::Quota);
        }
        let pieces = manifest.pieces();
        self.replace(State {
            manifest,
            status: Status::Offered,
            have: vec![false; pieces],
            created: now,
            completed: None,
            error: None,
            completed_by: Vec::new(),
            duplicate_of: None,
        })
    }
    pub fn accept(&mut self, id: ShareId, now: u64) -> Result<()> {
        let mut state = self.get(id)?.clone();
        if state.status == Status::Complete {
            return Ok(());
        }
        if matches!(
            state.status,
            Status::Cancelled | Status::Importing | Status::Failed
        ) {
            return Err(Error::Unavailable);
        }
        if state.status == Status::Offered {
            self.admit(
                state
                    .manifest
                    .reservation()
                    .saturating_sub(state.reserved()),
                now,
            )?;
        }
        state.status = Status::Downloading;
        state.error = None;
        if state.have.is_empty() {
            state.status = Status::Complete;
            state.completed = Some(now);
        }
        self.replace(state)
    }
    pub fn receipt(&mut self, id: ShareId, member: Member) -> Result<()> {
        let mut state = self.get(id)?.clone();
        if state.completed_by.contains(&member) {
            return Ok(());
        }
        if state.completed_by.len() < 64 {
            state.completed_by.push(member);
            self.replace(state)?;
        }
        Ok(())
    }
    pub fn failure(&mut self, id: ShareId, message: String) -> Result<()> {
        let mut state = self.get(id)?.clone();
        state.error = Some(message);
        if state.status == Status::Downloading {
            state.status = Status::Paused;
        }
        self.replace(state)
    }
    pub fn pause(&mut self, id: ShareId) -> Result<()> {
        let mut state = self.get(id)?.clone();
        if state.status == Status::Downloading
            || (state.status == Status::Paused
                && state.error.as_deref() == Some(LEGACY_MEMBERSHIP_PAUSE))
        {
            state.status = Status::Paused;
            state.error = None;
            self.replace(state)?;
        }
        Ok(())
    }
    pub fn cancel(&mut self, id: ShareId) -> Result<()> {
        let mut state = self.get(id)?.clone();
        state.status = Status::Cancelled;
        state.have.fill(false);
        state.completed = None;
        self.replace(state)?;
        self.remove_pieces(id)
    }
    fn remove_pieces(&self, id: ShareId) -> Result<()> {
        for entry in std::fs::read_dir(self.dir(id))? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "piece")
                || entry.file_name() == "tree"
            {
                std::fs::remove_file(entry.path())?;
            }
        }
        crate::journal::sync_directory(&self.dir(id))?;
        Ok(())
    }
    fn remove(&mut self, id: ShareId) -> Result<()> {
        // Tombstone first: a crash during cleanup cannot resurrect availability.
        self.cancel(id)?;
        std::fs::remove_dir_all(self.dir(id))?;
        crate::journal::sync_directory(&self.root)?;
        self.entries.remove(&id);
        Ok(())
    }
    pub fn begin_import(
        &mut self,
        id: ShareId,
        scope: Scope,
        name: String,
        size: u64,
        now: u64,
    ) -> Result<()> {
        if let Some(old) = self.entries.get(&id) {
            if let Some(target) = old.duplicate_of {
                if !self
                    .entries
                    .get(&target)
                    .is_some_and(|s| s.status == Status::Complete)
                {
                    return Err(Error::Unavailable);
                }
            }
            return if (old.duplicate_of.is_some()
                || matches!(old.status, Status::Importing | Status::Complete))
                && old.manifest.scope == scope
                && old.manifest.name == name
                && old.manifest.size == size
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let manifest = Manifest {
            version: 1,
            id,
            scope,
            name,
            size,
            sha256: hash(&[]),
            root: empty_root(),
            key: rand::random(),
        };
        manifest.validate()?;
        if self.entries.len() >= MAX_TRANSFERS
            || self
                .entries
                .values()
                .filter(|s| s.status == Status::Importing)
                .count()
                >= 2
        {
            return Err(Error::Quota);
        }
        self.admit(manifest.reservation(), now)?;
        let count = manifest.pieces();
        self.replace(State {
            manifest,
            status: Status::Importing,
            have: vec![false; count],
            created: now,
            completed: None,
            error: None,
            completed_by: Vec::new(),
            duplicate_of: None,
        })
    }
    pub fn import_piece(&mut self, id: ShareId, index: u32, plain: &[u8]) -> Result<()> {
        let mut state = self.get(id)?.clone();
        if state.status != Status::Importing {
            return Err(Error::Conflict);
        }
        if plain.len() != state.manifest.piece_len(index)? {
            return Err(Error::Invalid("source piece length"));
        }
        if self.piece_path(id, index).exists() {
            let (_, old) = self.read_raw(id, index)?;
            let original = Zeroizing::new(state.manifest.open(index, &old)?);
            if original.as_slice() != plain {
                return Err(Error::Conflict);
            }
            state.have[index as usize] = true;
            return self.replace(state);
        }
        let cipher = state.manifest.seal(index, plain)?;
        self.write_piece(id, index, &cipher, &[])?;
        state.have[index as usize] = true;
        self.replace(state)
    }
    pub fn finish_import(&mut self, id: ShareId, now: u64) -> Result<Manifest> {
        let mut state = self.get(id)?.clone();
        if let Some(existing) = state.duplicate_of {
            let target = self.get(existing)?;
            return if target.status == Status::Complete && target.duplicate_of.is_none() {
                Ok(target.manifest.clone())
            } else {
                Err(Error::Unavailable)
            };
        }
        if state.status == Status::Complete {
            return Ok(state.manifest.clone());
        }
        if state.status != Status::Importing || !state.have.iter().all(|v| *v) {
            return Err(Error::Unavailable);
        }
        let mut digest = Sha256::new();
        let mut leaves = Vec::with_capacity(state.manifest.pieces());
        for i in 0..state.have.len() {
            let (_, cipher) = self.read_raw(id, i as u32)?;
            let plain = Zeroizing::new(state.manifest.open(i as u32, &cipher)?);
            digest.update(&plain);
            leaves.push(leaf(i as u32, &cipher));
        }
        state.manifest.sha256 = digest.finalize().into();
        let layers = tree(&leaves);
        state.manifest.root = layers.last().unwrap()[0];
        // This index contains only hashes of ciphertext, like the proofs in
        // received piece records. Publish it once instead of rewriting the file
        // to attach a proof to every source piece.
        let index: Vec<u8> = layers.iter().flatten().flatten().copied().collect();
        atomic(&self.dir(id).join("tree"), &index)?;
        state.status = Status::Complete;
        state.completed = Some(now);
        let manifest = state.manifest.clone();
        self.replace(state)?;
        Ok(manifest)
    }
    /// Reuse only verified complete content in the exact authorization scope.
    /// The import ID remains a durable alias so a lost commit reply is retryable.
    /// No ciphertext is transplanted between distinct keys, IDs or scopes.
    pub fn reuse_import(&mut self, id: ShareId) -> Result<Manifest> {
        let mut source = self.get(id)?.clone();
        if let Some(existing) = source.duplicate_of {
            let target = self.get(existing)?;
            return if target.status == Status::Complete && target.duplicate_of.is_none() {
                Ok(target.manifest.clone())
            } else {
                Err(Error::Unavailable)
            };
        }
        if source.status != Status::Complete {
            return Err(Error::Unavailable);
        }
        let existing = self
            .entries
            .values()
            .find(|state| {
                state.manifest.id != id
                    && state.duplicate_of.is_none()
                    && state.status == Status::Complete
                    && state.manifest.scope == source.manifest.scope
                    && state.manifest.size == source.manifest.size
                    && state.manifest.sha256 == source.manifest.sha256
            })
            .cloned();
        let Some(existing) = existing else {
            return Ok(source.manifest);
        };
        // Revalidate retained bytes before announcing this cache as a source.
        let mut digest = Sha256::new();
        for index in 0..existing.manifest.pieces() {
            let plain = Zeroizing::new(self.export_piece(existing.manifest.id, index as u32)?);
            digest.update(&plain);
        }
        if <[u8; 32]>::from(digest.finalize()) != source.manifest.sha256 {
            return Err(Error::Invalid("retained content digest"));
        }
        source.duplicate_of = Some(existing.manifest.id);
        // Older readers ignore duplicate_of. Keep the superseded import in a
        // non-serving state they already understand, never Complete without
        // its bytes. The canonical file remains complete and unchanged.
        source.status = Status::Cancelled;
        source.completed = None;
        source.have.fill(false);
        self.replace(source)?;
        self.remove_pieces(id)?;
        Ok(existing.manifest)
    }

    pub fn import(
        &mut self,
        id: ShareId,
        scope: Scope,
        name: String,
        size: u64,
        input: &mut impl Read,
        now: u64,
    ) -> Result<Manifest> {
        self.begin_import(id, scope, name, size, now)?;
        if let Some(canonical) = self.get(id)?.duplicate_of {
            return Ok(self.get(canonical)?.manifest.clone());
        }
        if self.get(id)?.status == Status::Complete {
            return Ok(self.get(id)?.manifest.clone());
        }
        let manifest = self.get(id)?.manifest.clone();
        for i in 0..manifest.pieces() {
            let mut bytes = Zeroizing::new(vec![0; manifest.piece_len(i as u32)?]);
            input.read_exact(&mut bytes)?;
            self.import_piece(id, i as u32, &bytes)?;
        }
        let mut extra = [0];
        if input.read(&mut extra)? != 0 {
            return Err(Error::Invalid("source length changed"));
        }
        self.finish_import(id, now)
    }
    pub fn export_piece(&self, id: ShareId, index: u32) -> Result<Vec<u8>> {
        let state = self.get(id)?;
        if state.status != Status::Complete {
            return Err(Error::Unavailable);
        }
        let (_, cipher) = self.read_piece(id, index)?;
        state.manifest.open(index, &cipher)
    }
    fn write_piece(&self, id: ShareId, index: u32, data: &[u8], proof: &[Hash]) -> Result<()> {
        let mut bytes = Vec::with_capacity(data.len() + proof.len() * 32 + 1);
        bytes.push(proof.len() as u8);
        for hash in proof {
            bytes.extend(hash);
        }
        bytes.extend(data);
        atomic(&self.piece_path(id, index), &bytes)
    }
    fn read_raw(&self, id: ShareId, index: u32) -> Result<(Vec<Hash>, Vec<u8>)> {
        let bytes = read_private(&self.piece_path(id, index), PIECE_BYTES + 28 + 513)?;
        let n = usize::from(*bytes.first().ok_or(Error::Invalid("piece header"))?);
        if n > 16 || bytes.len() < 1 + n * 32 {
            return Err(Error::Invalid("piece proof"));
        }
        let proof = bytes[1..1 + n * 32].as_chunks::<32>().0.to_vec();
        Ok((proof, bytes[1 + n * 32..].to_vec()))
    }
    fn read_piece_with(&self, manifest: &Manifest, index: u32) -> Result<(Vec<Hash>, Vec<u8>)> {
        let (mut proof, bytes) = self.read_raw(manifest.id, index)?;
        if proof.is_empty() && manifest.pieces() > 1 {
            let path = self.dir(manifest.id).join("tree");
            validate_private_file(&path, "source Merkle index").map_err(private_error)?;
            let mut file = File::open(path)?;
            let mut width = manifest.pieces().next_power_of_two();
            if file.metadata()?.len() != (2 * width - 1) as u64 * 32 {
                return Err(Error::Invalid("Merkle index length"));
            }
            let mut base = 0;
            let mut node = index as usize;
            while width > 1 {
                file.seek(SeekFrom::Start((base + (node ^ 1)) as u64 * 32))?;
                let mut sibling = [0; 32];
                file.read_exact(&mut sibling)?;
                proof.push(sibling);
                base += width;
                width /= 2;
                node /= 2;
            }
        }
        verify(manifest, index, &bytes, &proof)?;
        Ok((proof, bytes))
    }
    pub fn read_piece(&self, id: ShareId, index: u32) -> Result<(Vec<Hash>, Vec<u8>)> {
        let state = self.get(id)?;
        if !state.have.get(index as usize).copied().unwrap_or(false)
            || matches!(state.status, Status::Cancelled | Status::Importing)
        {
            return Err(Error::Unavailable);
        }
        self.read_piece_with(&state.manifest, index)
    }
    pub fn put(
        &mut self,
        id: ShareId,
        index: u32,
        data: &[u8],
        proof: &[Hash],
        now: u64,
    ) -> Result<bool> {
        let mut state = self.get(id)?.clone();
        if !matches!(state.status, Status::Downloading | Status::Complete) {
            return Err(Error::Unavailable);
        }
        verify(&state.manifest, index, data, proof)?;
        if state.have[index as usize] {
            return Ok(false);
        }
        self.write_piece(id, index, data, proof)?;
        state.have[index as usize] = true;
        if state.have.iter().all(|v| *v) {
            let mut hash = Sha256::new();
            for i in 0..state.have.len() {
                let (_, cipher) = self.read_piece_with(&state.manifest, i as u32)?;
                let plain = Zeroizing::new(state.manifest.open(i as u32, &cipher)?);
                hash.update(&plain);
            }
            if Hash::from(hash.finalize()) != state.manifest.sha256 {
                state.status = Status::Failed;
                state.error = Some("Final file digest mismatch".into());
            } else {
                state.status = Status::Complete;
                state.completed = Some(now);
            }
        }
        self.replace(state)?;
        Ok(true)
    }
    /// Caller owns destination policy. No remote filename becomes a filesystem path.
    pub fn export(&self, id: ShareId, output: &mut impl Write) -> Result<()> {
        let state = self.get(id)?;
        if state.status != Status::Complete {
            return Err(Error::Unavailable);
        }
        for i in 0..state.have.len() {
            let (_, cipher) = self.read_piece(id, i as u32)?;
            let plain = Zeroizing::new(state.manifest.open(i as u32, &cipher)?);
            output.write_all(&plain)?;
        }
        Ok(())
    }
}
