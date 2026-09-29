//! Ciphertext-only ordered storage. Transport and reader authorization are the
//! embedding service's responsibility; these APIs must not be exposed unauthenticated.

use gcoms_mls::hosted::{HostedMessage, HostedObserver, HostedPolicy};
use gcoms_mls::{MlsError, MAX_WIRE_BYTES};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

const MAGIC: &[u8; 8] = b"GCHLOG01";
const MAX_FRAME: usize = 2 * MAX_WIRE_BYTES + 64 * 1024;
const JOIN: u8 = 1;
const MESSAGE: u8 = 2;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Mls(MlsError),
    Invalid(String),
    Full,
    Busy,
    Poisoned,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "channel log I/O: {e}"),
            Self::Mls(e) => write!(f, "channel validation: {e}"),
            Self::Invalid(e) => write!(f, "invalid channel log: {e}"),
            Self::Full => f.write_str("channel storage quota reached"),
            Self::Busy => f.write_str("channel log has another writer"),
            Self::Poisoned => f.write_str("channel log must be reopened after a write failure"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<MlsError> for Error {
    fn from(e: MlsError) -> Self {
        Self::Mls(e)
    }
}
impl From<tls_codec::Error> for Error {
    fn from(e: tls_codec::Error) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// Explicit limits include the header and all retained frames.
#[derive(Clone, Copy)]
pub struct Limits {
    pub bytes: u64,
    pub records: usize,
}
impl Limits {
    fn validate(self) -> Result<Self, Error> {
        if self.bytes == 0
            || self.bytes > 16 * 1024 * 1024 * 1024
            || self.records == 0
            || self.records > 1_000_000
        {
            return Err(Error::Invalid("limits outside supported bounds".into()));
        }
        Ok(self)
    }
}

/// Unsigned local receipt. A network protocol must authenticate its own response.
/// This means durable service acceptance only, not recipient delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acceptance {
    pub sequence: u64,
    pub id: [u8; 32],
    pub record_hash: [u8; 32],
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct Header {
    channel: [u8; 32],
    policy: VLBytes,
    genesis: VLBytes,
}

/// An ordered replay item. Membership and application content remain distinct.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Record {
    pub sequence: u64,
    pub previous: [u8; 32],
    pub accepted_at: u64,
    kind: u8,
    first: VLBytes,
    second: VLBytes,
}
impl Record {
    pub fn membership(&self) -> Option<(&[u8], &[u8])> {
        (self.kind == JOIN).then_some((self.first.as_slice(), self.second.as_slice()))
    }
    pub fn message(&self) -> Result<Option<HostedMessage>, Error> {
        if self.kind == MESSAGE {
            Ok(Some(HostedMessage::decode(self.first.as_slice())?))
        } else {
            Ok(None)
        }
    }
    fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"gcoms/hosted/record-id/v1");
        h.update([self.kind]);
        h.update((self.first.as_slice().len() as u64).to_be_bytes());
        h.update(self.first.as_slice());
        h.update((self.second.as_slice().len() as u64).to_be_bytes());
        h.update(self.second.as_slice());
        h.finalize().into()
    }
}

struct Index {
    offset: u64,
    receipt: Acceptance,
}

/// Owns an exclusive writer lock. No private MLS state is present in this type.
pub struct ChannelLog {
    file: File,
    observer: HostedObserver,
    header_hash: [u8; 32],
    index: Vec<Index>,
    ids: HashMap<[u8; 32], usize>,
    limits: Limits,
    bytes: u64,
    last_time: u64,
    poisoned: bool,
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn write_frame(file: &mut File, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::Invalid("frame exceeds bound".into()));
    }
    file.write_all(&(bytes.len() as u32).to_be_bytes())?;
    file.write_all(bytes)?;
    file.write_all(&checksum(bytes))?;
    Ok(())
}

enum Frame {
    End,
    Torn,
    Complete(Vec<u8>),
}
fn read_frame(file: &mut File) -> Result<Frame, Error> {
    let offset = file.stream_position()?;
    let remaining = file.metadata()?.len().saturating_sub(offset);
    if remaining == 0 {
        return Ok(Frame::End);
    }
    if remaining < 4 {
        return Ok(Frame::Torn);
    }
    let mut length = [0; 4];
    file.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(Error::Invalid("frame exceeds bound".into()));
    }
    if remaining < length as u64 + 36 {
        return Ok(Frame::Torn);
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    let mut stored = [0; 32];
    file.read_exact(&mut stored)?;
    if checksum(&bytes) != stored {
        return Err(Error::Invalid("frame checksum mismatch".into()));
    }
    Ok(Frame::Complete(bytes))
}

impl ChannelLog {
    /// Parent directory must already exist and be private. Fails if the file
    /// exists; an uncertain prior create must be inspected/reopened explicitly.
    pub fn create(
        path: &Path,
        policy: HostedPolicy,
        channel: [u8; 32],
        genesis: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        gcoms_private_fs::validate_private_parent(path, "channel log").map_err(Error::Invalid)?;
        let observer = HostedObserver::new(policy.clone(), channel, genesis)?;
        let header = Header {
            channel,
            policy: policy.encode()?.into(),
            genesis: genesis.to_vec().into(),
        }
        .tls_serialize_detached()?;
        let bytes = MAGIC.len() as u64 + header.len() as u64 + 36;
        if bytes > limits.bytes {
            return Err(Error::Full);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.try_lock().map_err(|_| Error::Busy)?;
        gcoms_private_fs::make_private(path, false).map_err(Error::Invalid)?;
        file.write_all(MAGIC)?;
        write_frame(&mut file, &header)?;
        file.sync_all()?;
        // Sync the directory entry on platforms that support directory fsync.
        #[cfg(unix)]
        File::open(
            path.parent()
                .ok_or_else(|| Error::Invalid("missing parent".into()))?,
        )?
        .sync_all()?;
        Ok(Self {
            file,
            observer,
            header_hash: checksum(&header),
            index: Vec::new(),
            ids: HashMap::new(),
            limits,
            bytes,
            last_time: 0,
            poisoned: false,
        })
    }

    pub fn open(path: &Path, expected_channel: [u8; 32], limits: Limits) -> Result<Self, Error> {
        let limits = limits.validate()?;
        gcoms_private_fs::validate_private_parent(path, "channel log").map_err(Error::Invalid)?;
        gcoms_private_fs::validate_private_file(path, "channel log").map_err(Error::Invalid)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock().map_err(|_| Error::Busy)?;
        if file.metadata()?.len() > limits.bytes {
            return Err(Error::Full);
        }
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(Error::Invalid("unsupported log profile".into()));
        }
        let Frame::Complete(header_bytes) = read_frame(&mut file)? else {
            return Err(Error::Invalid("incomplete header".into()));
        };
        let header = Header::tls_deserialize_exact(&header_bytes)?;
        if header.channel != expected_channel {
            return Err(Error::Mls(MlsError::WrongChannel));
        }
        let policy = HostedPolicy::decode(header.policy.as_slice(), expected_channel)?;
        let observer = HostedObserver::new(policy, expected_channel, header.genesis.as_slice())?;
        let bytes = file.stream_position()?;
        let mut store = Self {
            file,
            observer,
            header_hash: checksum(&header_bytes),
            index: Vec::new(),
            ids: HashMap::new(),
            limits,
            bytes,
            last_time: 0,
            poisoned: false,
        };
        loop {
            let offset = store.file.stream_position()?;
            let bytes = match read_frame(&mut store.file)? {
                Frame::End => break,
                Frame::Torn => {
                    store.file.set_len(offset)?;
                    store.file.sync_all()?;
                    break;
                }
                Frame::Complete(bytes) => bytes,
            };
            if store.index.len() >= limits.records {
                return Err(Error::Full);
            }
            let record = Record::tls_deserialize_exact(&bytes)?;
            store.check_order(&record)?;
            let id = record.id();
            if store.ids.contains_key(&id) {
                return Err(Error::Invalid("duplicate log record".into()));
            }
            if let Some(next) = store.validate(&record)? {
                store.observer = next;
            }
            let receipt = Acceptance {
                sequence: record.sequence,
                id,
                record_hash: checksum(&bytes),
            };
            store.ids.insert(id, store.index.len());
            store.index.push(Index { offset, receipt });
            store.last_time = record.accepted_at;
        }
        store.bytes = store.file.seek(SeekFrom::End(0))?;
        Ok(store)
    }

    pub fn observer(&self) -> &HostedObserver {
        &self.observer
    }
    pub fn len(&self) -> usize {
        self.index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn previous(&self) -> [u8; 32] {
        self.index
            .last()
            .map_or(self.header_hash, |i| i.receipt.record_hash)
    }
    fn check_order(&self, record: &Record) -> Result<(), Error> {
        if record.sequence != self.index.len() as u64 + 1
            || record.previous != self.previous()
            || record.accepted_at < self.last_time
        {
            return Err(Error::Invalid(
                "sequence, predecessor or time mismatch".into(),
            ));
        }
        Ok(())
    }
    fn validate(&self, record: &Record) -> Result<Option<HostedObserver>, Error> {
        match record.kind {
            JOIN => Ok(Some(self.observer.stage_join(
                record.first.as_slice(),
                record.second.as_slice(),
                record.accepted_at,
            )?)),
            MESSAGE if record.second.as_slice().is_empty() => {
                self.observer
                    .verify_message(&HostedMessage::decode(record.first.as_slice())?)?;
                Ok(None)
            }
            _ => Err(Error::Invalid("unsupported record kind".into())),
        }
    }

    pub fn append_join(
        &mut self,
        commit: &[u8],
        info: &[u8],
        now: u64,
    ) -> Result<Acceptance, Error> {
        if commit.len() > MAX_WIRE_BYTES || info.len() > MAX_WIRE_BYTES {
            return Err(Error::Invalid("join exceeds bound".into()));
        }
        self.append(JOIN, commit.to_vec(), info.to_vec(), now)
    }
    pub fn append_message(
        &mut self,
        message: &HostedMessage,
        now: u64,
    ) -> Result<Acceptance, Error> {
        self.append(MESSAGE, message.encode()?, Vec::new(), now)
    }
    fn append(
        &mut self,
        kind: u8,
        first: Vec<u8>,
        second: Vec<u8>,
        now: u64,
    ) -> Result<Acceptance, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let record = Record {
            sequence: self.index.len() as u64 + 1,
            previous: self.previous(),
            accepted_at: now,
            kind,
            first: first.into(),
            second: second.into(),
        };
        let id = record.id();
        if let Some(index) = self.ids.get(&id) {
            return Ok(self.index[*index].receipt);
        }
        self.check_order(&record)?;
        let bytes = record.tls_serialize_detached()?;
        let size = bytes.len() as u64 + 36;
        if self.index.len() >= self.limits.records
            || size > self.limits.bytes.saturating_sub(self.bytes)
        {
            return Err(Error::Full);
        }
        let next = self.validate(&record)?;
        // Any uncertain write stops this instance. Reopening validates the
        // durable prefix and deduplicates a fully written but unacknowledged item.
        self.poisoned = true;
        self.file.seek(SeekFrom::Start(self.bytes))?;
        write_frame(&mut self.file, &bytes)?;
        self.file.sync_all()?;
        let receipt = Acceptance {
            sequence: record.sequence,
            id,
            record_hash: checksum(&bytes),
        };
        self.ids.insert(id, self.index.len());
        self.index.push(Index {
            offset: self.bytes,
            receipt,
        });
        self.bytes += size;
        self.last_time = now;
        if let Some(next) = next {
            self.observer = next;
        }
        self.poisoned = false;
        Ok(receipt)
    }

    /// One bounded record per read; transport pagination must also bound totals.
    pub fn read(&mut self, sequence: u64) -> Result<Option<Record>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let Some(index) = sequence
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| self.index.get(n))
        else {
            return Ok(None);
        };
        self.file.seek(SeekFrom::Start(index.offset))?;
        let Frame::Complete(bytes) = read_frame(&mut self.file)? else {
            return Err(Error::Invalid("record disappeared".into()));
        };
        if checksum(&bytes) != index.receipt.record_hash {
            return Err(Error::Invalid("record changed".into()));
        }
        Ok(Some(Record::tls_deserialize_exact(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_crypto::IdentityKeypair;
    use gcoms_mls::hosted::HostedSession;

    #[test]
    fn failed_real_write_poisoned_until_reopen_without_inventing_acceptance() {
        let dir = tempfile::tempdir().unwrap();
        gcoms_private_fs::make_private(dir.path(), true).unwrap();
        let path = dir.path().join("log");
        let root = IdentityKeypair::from_seed([71; 32]);
        let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
        let channel = owner.policy().channel_id();
        let limits = Limits {
            bytes: 1024 * 1024,
            records: 10,
        };
        let mut log = ChannelLog::create(
            &path,
            owner.policy().clone(),
            channel,
            &owner.export_group_info().unwrap(),
            limits,
        )
        .unwrap();
        let first = owner.send_hosted(b"accepted").unwrap();
        log.append_message(&first, 100).unwrap();
        let before = std::fs::read(&path).unwrap();
        // Inject an actual OS write error at the store's file boundary.
        log.file = File::open(&path).unwrap();
        let second = owner.send_hosted(b"not accepted").unwrap();
        assert!(matches!(
            log.append_message(&second, 101),
            Err(Error::Io(_))
        ));
        assert_eq!(log.len(), 1);
        assert!(matches!(
            log.append_message(&second, 101),
            Err(Error::Poisoned)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(log);
        let mut reopened = ChannelLog::open(&path, channel, limits).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.append_message(&second, 101).unwrap().sequence, 2);
    }
}
