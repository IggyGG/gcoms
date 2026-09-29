//! Sender-scoped receipt storage. Receipt traffic never enters the broadcast log.
use super::*;
use gcoms_mls::hosted::HostedReceipt;

const MAGIC: &[u8; 8] = b"GCHACK01";
#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct Entry {
    previous: [u8; 32],
    receipt: VLBytes,
}

pub(crate) struct ReceiptLog {
    file: File,
    channel: [u8; 32],
    head: [u8; 32],
    by_sender: HashMap<[u8; 32], Vec<u64>>,
    ids: HashMap<([u8; 32], [u8; 32]), ()>,
    pub bytes: u64,
    limits: Limits,
    poisoned: bool,
}
impl ReceiptLog {
    pub fn open(
        path: &Path,
        channel: [u8; 32],
        limits: Limits,
        log: &mut ChannelLog,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        gcoms_private_fs::validate_private_parent(path, "receipt log").map_err(Error::Invalid)?;
        let exists = path.try_exists()?;
        if exists {
            gcoms_private_fs::validate_private_file(path, "receipt log").map_err(Error::Invalid)?;
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
            return Err(Error::Invalid("receipt log header mismatch".into()));
        }
        let mut store = Self {
            file,
            channel,
            head: checksum(&header),
            by_sender: HashMap::new(),
            ids: HashMap::new(),
            bytes: 40,
            limits,
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
            if entry.previous != store.head {
                return Err(Error::Invalid("receipt chain mismatch".into()));
            }
            let receipt = HostedReceipt::decode(entry.receipt.as_slice())?;
            log.validate_receipt(&receipt)?;
            if store.ids.len() >= limits.records
                || store
                    .ids
                    .contains_key(&(receipt.recipient(), receipt.record_id()))
            {
                return Err(Error::Invalid("duplicate or excessive receipts".into()));
            }
            store.index(&receipt, offset);
            store.head = checksum(&bytes);
            store.bytes = store.file.stream_position()?;
        }
        Ok(store)
    }
    fn index(&mut self, receipt: &HostedReceipt, offset: u64) {
        self.ids
            .insert((receipt.recipient(), receipt.record_id()), ());
        self.by_sender
            .entry(receipt.sender())
            .or_default()
            .push(offset);
    }
    pub fn contains(&self, receipt: &HostedReceipt) -> bool {
        self.ids
            .contains_key(&(receipt.recipient(), receipt.record_id()))
    }
    pub fn append(&mut self, receipt: &HostedReceipt) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        receipt.verify(self.channel)?;
        if self.contains(receipt) {
            return Ok(());
        }
        let bytes = Entry {
            previous: self.head,
            receipt: receipt.encode()?.into(),
        }
        .tls_serialize_detached()?;
        let end = self.bytes + bytes.len() as u64 + 36;
        if end > self.limits.bytes || self.ids.len() >= self.limits.records {
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
        self.index(receipt, self.bytes);
        self.bytes = end;
        self.head = checksum(&bytes);
        Ok(())
    }
    pub fn read(
        &mut self,
        sender: [u8; 32],
        after: u64,
        limit: u16,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let offsets = self
            .by_sender
            .get(&sender)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if after > offsets.len() as u64 || limit == 0 || limit > 32 {
            return Err(Error::Invalid("receipt page boundary".into()));
        }
        let mut receipts = Vec::new();
        for offset in offsets.iter().skip(after as usize).take(limit as usize) {
            self.file.seek(SeekFrom::Start(*offset))?;
            let Frame::Complete(bytes) = read_frame(&mut self.file)? else {
                return Err(Error::Invalid("missing receipt".into()));
            };
            receipts.push(
                Entry::tls_deserialize_exact(&bytes)?
                    .receipt
                    .as_slice()
                    .to_vec(),
            );
        }
        Ok(receipts)
    }
}
impl ChannelLog {
    pub(crate) fn validate_receipt(&mut self, receipt: &HostedReceipt) -> Result<(), Error> {
        receipt.verify(self.observer.policy().channel_id())?;
        let record = self
            .read(receipt.sequence())?
            .ok_or_else(|| Error::Invalid("missing receipt target".into()))?;
        let message = record
            .message()?
            .ok_or_else(|| Error::Invalid("receipt target is not a message".into()))?;
        if record.id() != receipt.record_id() || message.member_id() != receipt.sender() {
            return Err(Error::Mls(MlsError::Unauthorized));
        }
        // Recipients may acknowledge after departure. New members cannot forge
        // another identity's receipt; senders independently enforce the exact
        // recipient set saved with this message's epoch.
        if !self.observer.members().contains(&receipt.recipient())
            && !self
                .read_until
                .get(&receipt.recipient())
                .is_some_and(|end| *end >= receipt.sequence())
        {
            return Err(Error::Mls(MlsError::Unauthorized));
        }
        Ok(())
    }
}
