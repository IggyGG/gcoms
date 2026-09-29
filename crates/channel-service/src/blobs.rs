//! Immutable ciphertext pieces, separated from the covered channel/receipt logs.
use super::*;
use gcoms_sdk::hosted::{BlobRef, MAX_BLOB_BYTES};

const MAGIC: &[u8; 8] = b"GCHBLB01";
#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct Entry {
    previous: [u8; 32],
    owner: [u8; 32],
    file: [u8; 16],
    piece: u32,
    ciphertext: VLBytes,
}
impl Entry {
    fn reference(&self) -> BlobRef {
        BlobRef {
            owner: self.owner,
            file: self.file,
            piece: self.piece,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if !self.reference().valid()
            || self.ciphertext.as_slice().is_empty()
            || self.ciphertext.as_slice().len() > MAX_BLOB_BYTES
        {
            return Err(Error::Invalid("ciphertext piece bounds".into()));
        }
        Ok(())
    }
}
pub(crate) struct BlobLog {
    file: File,
    head: [u8; 32],
    index: HashMap<BlobRef, (u64, [u8; 32])>,
    limits: Limits,
    pub bytes: u64,
    poisoned: bool,
}
impl BlobLog {
    pub fn open(path: &Path, channel: [u8; 32], limits: Limits) -> Result<Self, Error> {
        let limits = limits.validate()?;
        gcoms_private_fs::validate_private_parent(path, "ciphertext piece log")
            .map_err(Error::Invalid)?;
        let exists = path.try_exists()?;
        if exists {
            gcoms_private_fs::validate_private_file(path, "ciphertext piece log")
                .map_err(Error::Invalid)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(!exists);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.try_lock().map_err(|_| Error::Busy)?;
        if !exists {
            gcoms_private_fs::make_private(path, false).map_err(Error::Invalid)?;
            file.write_all(MAGIC)?;
            file.write_all(&channel)?;
            file.sync_all()?;
            #[cfg(unix)]
            File::open(
                path.parent()
                    .ok_or_else(|| Error::Invalid("missing parent".into()))?,
            )?
            .sync_all()?;
        }
        if file.metadata()?.len() > limits.bytes {
            return Err(Error::Full);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0; 40];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC || header[8..] != channel {
            return Err(Error::Invalid("piece log header mismatch".into()));
        }
        let mut store = Self {
            file,
            head: checksum(&header),
            index: HashMap::new(),
            limits,
            bytes: 40,
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
            let entry = Entry::tls_deserialize_exact(&bytes)?;
            entry.validate()?;
            if entry.previous != store.head
                || store.index.len() >= store.limits.records
                || store.index.contains_key(&entry.reference())
            {
                return Err(Error::Invalid("piece log chain or index mismatch".into()));
            }
            store.index.insert(
                entry.reference(),
                (offset, checksum(entry.ciphertext.as_slice())),
            );
            store.head = checksum(&bytes);
            store.bytes = store.file.stream_position()?;
        }
        Ok(store)
    }
    pub fn contains(&self, reference: &BlobRef) -> bool {
        self.index.contains_key(reference)
    }
    pub fn append(&mut self, reference: BlobRef, ciphertext: &[u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let entry = Entry {
            previous: self.head,
            owner: reference.owner,
            file: reference.file,
            piece: reference.piece,
            ciphertext: ciphertext.to_vec().into(),
        };
        entry.validate()?;
        let digest = checksum(ciphertext);
        if let Some((_, existing)) = self.index.get(&reference) {
            if *existing != digest {
                return Err(Error::Invalid("immutable ciphertext piece changed".into()));
            }
            // Check the retained copy, including after an external storage fault.
            self.read(reference)?;
            return Ok(());
        }
        let bytes = entry.tls_serialize_detached()?;
        let end = self.bytes + bytes.len() as u64 + 36;
        if end > self.limits.bytes || self.index.len() >= self.limits.records {
            return Err(Error::Full);
        }
        let result = (|| {
            self.file.seek(SeekFrom::Start(self.bytes))?;
            write_frame(&mut self.file, &bytes)?;
            self.file.sync_all()?;
            Ok::<_, Error>(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        self.index.insert(reference, (self.bytes, digest));
        self.bytes = end;
        self.head = checksum(&bytes);
        Ok(())
    }
    pub fn read(&mut self, reference: BlobRef) -> Result<Option<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let Some((offset, digest)) = self.index.get(&reference).copied() else {
            return Ok(None);
        };
        self.file.seek(SeekFrom::Start(offset))?;
        let Frame::Complete(bytes) = read_frame(&mut self.file)? else {
            return Err(Error::Invalid("missing ciphertext piece".into()));
        };
        let entry = Entry::tls_deserialize_exact(&bytes)?;
        if entry.reference() != reference || checksum(entry.ciphertext.as_slice()) != digest {
            return Err(Error::Invalid("ciphertext piece index mismatch".into()));
        }
        Ok(Some(entry.ciphertext.as_slice().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_pieces_survive_restart_and_only_torn_tails_are_discarded() {
        let dir = tempfile::tempdir().unwrap();
        gcoms_private_fs::make_private(dir.path(), true).unwrap();
        let path = dir.path().join("test.gblob");
        let limits = Limits {
            bytes: 1024 * 1024,
            records: 16,
        };
        let reference = BlobRef {
            owner: [1; 32],
            file: [2; 16],
            piece: 0,
        };
        let mut log = BlobLog::open(&path, [3; 32], limits).unwrap();
        assert!(BlobLog::open(&path, [3; 32], limits).is_err());
        log.append(reference, b"encrypted piece").unwrap();
        let size = log.bytes;
        log.append(reference, b"encrypted piece").unwrap();
        assert_eq!(size, log.bytes);
        assert!(log.append(reference, b"changed piece").is_err());
        drop(log);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 0, 0, 16, 1])
            .unwrap();
        let mut log = BlobLog::open(&path, [3; 32], limits).unwrap();
        assert_eq!(log.bytes, size);
        assert_eq!(
            log.read(reference).unwrap(),
            Some(b"encrypted piece".to_vec())
        );
        assert!(log
            .read(BlobRef {
                owner: [4; 32],
                ..reference
            })
            .unwrap()
            .is_none());
        drop(log);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(BlobLog::open(&path, [3; 32], limits).is_err());
    }
}
