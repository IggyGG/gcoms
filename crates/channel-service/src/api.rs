//! Bounded hosted-profile API. Deploy behind the installed network's HTTPS
//! origin; clients reach that origin over their existing protected route.
use super::*;
use crate::blobs::BlobLog;
use crate::receipts::ReceiptLog;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use gcoms_mls::hosted::{HostedReadProof, HostedReadScope, HostedReceipt};
use gcoms_sdk::hosted::*;
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
pub fn decode(value: &str) -> Result<Vec<u8>, Error> {
    if value.len() > MAX_HTTP_BYTES {
        return Err(Error::Invalid("wire exceeds API bound".into()));
    }
    B64.decode(value)
        .map_err(|_| Error::Invalid("invalid base64 wire".into()))
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub directory: PathBuf,
    /// Required for a non-loopback upstream socket. TLS must terminate at the
    /// installed network origin; this process itself accepts only upstream HTTP.
    #[serde(default)]
    pub tls_terminated_upstream: bool,
    #[serde(default)]
    pub creation: CreationPolicy,
    pub max_channels: usize,
    pub max_total_bytes: u64,
    pub channel_bytes: u64,
    pub channel_records: usize,
    pub requests_per_second: u32,
    pub source_requests_per_second: u32,
    #[serde(default)]
    pub blocked_channels: Vec<[u8; 32]>,
    #[serde(default)]
    pub blocked_sources: Vec<IpAddr>,
    #[serde(default)]
    pub motd: String,
    #[serde(default)]
    pub rules: String,
    #[serde(default)]
    pub operator_contact: String,
}
/// Network creation authority is separate from channel moderation. Private
/// installations deny creation unless the channel is explicitly provisioned.
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", content = "channels", rename_all = "snake_case")]
pub enum CreationPolicy {
    Public,
    AllowList(Vec<[u8; 32]>),
}
impl Default for CreationPolicy {
    fn default() -> Self {
        Self::AllowList(Vec::new())
    }
}
impl CreationPolicy {
    fn allows(&self, channel: [u8; 32]) -> bool {
        match self {
            Self::Public => true,
            Self::AllowList(channels) => channels.contains(&channel),
        }
    }
}

impl Config {
    fn limits(&self) -> Limits {
        Limits {
            bytes: self.channel_bytes,
            records: self.channel_records,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        self.limits().validate()?;
        if (!self.listen.ip().is_loopback() && !self.tls_terminated_upstream)
            || !(1..=4096).contains(&self.max_channels)
            || self.max_total_bytes < self.channel_bytes
            || self.max_total_bytes > 1024 * 1024 * 1024 * 1024
            || !(1..=100_000).contains(&self.requests_per_second)
            || !(1..=self.requests_per_second).contains(&self.source_requests_per_second)
            || [&self.motd, &self.rules, &self.operator_contact]
                .iter()
                .any(|s| s.len() > 8192 || s.contains('\0'))
            || self.blocked_channels.len() > 4096
            || self.blocked_sources.len() > 4096
        {
            return Err(Error::Invalid(
                "service configuration outside bounds".into(),
            ));
        }
        gcoms_private_fs::validate_private_parent(
            &self.directory.join("channel.gch"),
            "channel service",
        )
        .map_err(Error::Invalid)
    }
}

struct Rate {
    second: u64,
    count: u32,
    sources: HashMap<IpAddr, u32>,
}
struct Inner {
    config: Config,
    channels: Mutex<HashMap<[u8; 32], ChannelLog>>,
    receipts: Mutex<HashMap<[u8; 32], ReceiptLog>>,
    blobs: Mutex<HashMap<[u8; 32], BlobLog>>,
    rate: Mutex<Rate>,
    permits: Arc<tokio::sync::Semaphore>,
}
#[derive(Clone)]
pub struct Service(Arc<Inner>);

fn file_name(channel: [u8; 32]) -> String {
    let mut name = String::with_capacity(68);
    for byte in channel {
        use std::fmt::Write;
        write!(name, "{byte:02x}").expect("string write");
    }
    name.push_str(".gch");
    name
}
fn channel_from_name(name: &str) -> Option<[u8; 32]> {
    let hex = name.strip_suffix(".gch")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut channel = [0; 32];
    for (index, byte) in channel.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(channel)
}
fn fault(code: FaultCode, message: &str) -> Reply {
    Reply::Fault(Fault {
        code,
        message: message.into(),
    })
}
fn error_reply(error: Error) -> Reply {
    match error {
        Error::Mls(MlsError::Unauthorized | MlsError::Expired) => {
            fault(FaultCode::Unauthorized, "channel authority refused")
        }
        Error::Mls(MlsError::StaleState) => {
            fault(FaultCode::Conflict, "refresh ordered channel state")
        }
        Error::Mls(MlsError::GroupFull) | Error::Full => {
            fault(FaultCode::Quota, "channel or service limit reached")
        }
        Error::Io(_) | Error::Poisoned | Error::Busy => {
            fault(FaultCode::Unavailable, "channel storage unavailable")
        }
        _ => fault(FaultCode::Invalid, "invalid channel operation"),
    }
}

impl Service {
    pub fn open(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let mut channels = HashMap::new();
        let mut total = 0u64;
        for entry in std::fs::read_dir(&config.directory)? {
            let entry = entry?;
            let Some(channel) = entry.file_name().to_str().and_then(channel_from_name) else {
                continue;
            };
            if channels.len() == config.max_channels {
                return Err(Error::Full);
            }
            let log = ChannelLog::open(&entry.path(), channel, config.limits())?;
            total = total.checked_add(log.bytes).ok_or(Error::Full)?;
            if total > config.max_total_bytes {
                return Err(Error::Full);
            }
            channels.insert(channel, log);
        }
        let mut receipts = HashMap::new();
        for entry in std::fs::read_dir(&config.directory)? {
            let entry = entry?;
            let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".gack"))
                .map(str::to_owned)
            else {
                continue;
            };
            let channel = channel_from_name(&format!("{name}.gch"))
                .ok_or_else(|| Error::Invalid("invalid receipt filename".into()))?;
            let log = channels
                .get_mut(&channel)
                .ok_or_else(|| Error::Invalid("orphaned receipt log".into()))?;
            let ledger = ReceiptLog::open(&entry.path(), channel, config.limits(), log)?;
            total = total.checked_add(ledger.bytes).ok_or(Error::Full)?;
            if total > config.max_total_bytes {
                return Err(Error::Full);
            }
            receipts.insert(channel, ledger);
        }
        let mut blobs = HashMap::new();
        for entry in std::fs::read_dir(&config.directory)? {
            let entry = entry?;
            let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".gblob"))
                .map(str::to_owned)
            else {
                continue;
            };
            let channel = channel_from_name(&format!("{name}.gch"))
                .ok_or_else(|| Error::Invalid("invalid piece filename".into()))?;
            if !channels.contains_key(&channel) {
                return Err(Error::Invalid("orphaned piece log".into()));
            }
            let ledger = BlobLog::open(&entry.path(), channel, config.limits())?;
            total = total.checked_add(ledger.bytes).ok_or(Error::Full)?;
            if total > config.max_total_bytes {
                return Err(Error::Full);
            }
            blobs.insert(channel, ledger);
        }
        Ok(Self(Arc::new(Inner {
            config,
            channels: Mutex::new(channels),
            receipts: Mutex::new(receipts),
            blobs: Mutex::new(blobs),
            rate: Mutex::new(Rate {
                second: 0,
                count: 0,
                sources: HashMap::new(),
            }),
            permits: Arc::new(tokio::sync::Semaphore::new(32)),
        })))
    }
    pub fn info(&self) -> ServiceInfo {
        ServiceInfo {
            extensions: vec![
                "ciphertext-pieces-v1".into(),
                "public-directory-v1".into(),
                "covered-poll-v1".into(),
            ],
            requests_per_second: Some(self.0.config.requests_per_second),
            source_requests_per_second: Some(self.0.config.source_requests_per_second),
            version: VERSION,
            profiles: vec![PROFILE.into()],
            public_creation: matches!(self.0.config.creation, CreationPolicy::Public),
            max_members: 500,
            max_page_records: MAX_PAGE_RECORDS,
            max_http_bytes: MAX_HTTP_BYTES,
            motd: self.0.config.motd.clone(),
            rules: self.0.config.rules.clone(),
            operator_contact: self.0.config.operator_contact.clone(),
        }
    }
    fn admit(&self, source: IpAddr, now: u64) -> bool {
        let config = &self.0.config;
        if config.blocked_sources.contains(&source) {
            return false;
        }
        let Ok(mut rate) = self.0.rate.lock() else {
            return false;
        };
        if rate.second != now {
            rate.second = now;
            rate.count = 0;
            rate.sources.clear();
        }
        if rate.count >= config.requests_per_second {
            return false;
        }
        let count = rate.sources.entry(source).or_default();
        if *count >= config.source_requests_per_second {
            return false;
        }
        *count += 1;
        rate.count += 1;
        true
    }
    /// Synchronous transaction boundary, also used by non-HTTP embeddings.
    pub fn request(&self, request: Request, now: u64) -> Reply {
        if request.version != VERSION {
            return fault(FaultCode::Unsupported, "unsupported hosted profile version");
        }
        if matches!(request.operation, Operation::Info) {
            return Reply::Info(self.info());
        }
        let Ok(mut channels) = self.0.channels.lock() else {
            return fault(FaultCode::Unavailable, "storage lock unavailable");
        };
        if let Operation::Directory { after, limit } = request.operation {
            if limit == 0 || limit > 16 {
                return fault(FaultCode::Invalid, "directory page bound");
            }
            let mut entries: Vec<_> = channels
                .iter()
                .filter_map(|(id, log)| {
                    let rules = log.observer.rules();
                    if after.is_some_and(|after| *id <= after)
                        || log.poisoned
                        || rules.closed()
                        || rules.discovery() != gcoms_mls::hosted::HostedDiscovery::Public
                        || self.0.config.blocked_channels.contains(id)
                    {
                        return None;
                    }
                    Some(gcoms_sdk::hosted::DirectoryEntry {
                        channel: *id,
                        name: log.listing()?.into(),
                        members: log.observer.member_count() as u32,
                        capacity: rules.capacity(),
                        public_join: !rules.mode(gcoms_mls::hosted::HostedMode::InviteOnly)
                            && rules.access_key().is_none(),
                    })
                })
                .collect();
            entries.sort_by_key(|entry| entry.channel);
            let next = (entries.len() > usize::from(limit))
                .then(|| entries[usize::from(limit) - 1].channel);
            entries.truncate(usize::from(limit));
            return Reply::Directory { entries, next };
        }
        let channel = request.channel;
        if self.0.config.blocked_channels.contains(&channel)
            && matches!(
                request.operation,
                Operation::Create { .. }
                    | Operation::Append(_)
                    | Operation::Acknowledge { .. }
                    | Operation::PutBlob { .. }
            )
        {
            return fault(
                FaultCode::Unauthorized,
                "channel writes suspended by network operator",
            );
        }
        let result = (|| -> Result<Reply, Error> {
            let mut ledgers = self.0.receipts.lock().map_err(|_| Error::Poisoned)?;
            let mut blobs = self.0.blobs.lock().map_err(|_| Error::Poisoned)?;
            let total: u64 = channels.values().map(|log| log.bytes).sum::<u64>()
                + ledgers.values().map(|log| log.bytes).sum::<u64>()
                + blobs.values().map(|log| log.bytes).sum::<u64>();
            if let Operation::Create { policy, genesis } = request.operation {
                let policy = HostedPolicy::decode(&decode(&policy)?, channel)?;
                let genesis = decode(&genesis)?;
                if let Some(log) = channels.get(&channel) {
                    if log.observer.policy().encode()? != policy.encode()? || log.genesis != genesis
                    {
                        return Ok(fault(
                            FaultCode::Conflict,
                            "channel already exists with different genesis",
                        ));
                    }
                    return Ok(Reply::Created {
                        anchor: log.header_hash,
                    });
                }
                if !self.0.config.creation.allows(channel) {
                    return Ok(fault(
                        FaultCode::Unauthorized,
                        "channel creation is restricted by the network operator",
                    ));
                }
                let size = 8
                    + 36
                    + Header {
                        channel,
                        policy: policy.encode()?.into(),
                        genesis: genesis.clone().into(),
                    }
                    .tls_serialize_detached()?
                    .len() as u64;
                if channels.len() == self.0.config.max_channels
                    || size > self.0.config.max_total_bytes.saturating_sub(total)
                {
                    return Err(Error::Full);
                }
                let log = ChannelLog::create(
                    &self.0.config.directory.join(file_name(channel)),
                    policy,
                    channel,
                    &genesis,
                    self.0.config.limits(),
                )?;
                let anchor = log.header_hash;
                channels.insert(channel, log);
                return Ok(Reply::Created { anchor });
            }
            let Some(log) = channels.get_mut(&channel) else {
                return Ok(fault(FaultCode::NotFound, "channel unavailable"));
            };
            match request.operation {
                Operation::GetBlob { reference, proof } => {
                    if !reference.valid() {
                        return Err(Error::Invalid("piece reference bounds".into()));
                    }
                    let proof = HostedReadProof::decode(&decode(&proof)?)?;
                    log.observer.verify_read(
                        &proof,
                        HostedReadScope::BlobRead,
                        checksum(&reference.authentication_bytes(None)),
                        now,
                    )?;
                    let reader = proof
                        .member_id()
                        .ok_or(Error::Mls(MlsError::Unauthorized))?;
                    if log.observer.rules().closed()
                        || log.observer.rules().pending_removals().contains(&reader)
                    {
                        return Err(Error::Mls(MlsError::Unauthorized));
                    }
                    match blobs
                        .get_mut(&channel)
                        .map(|ledger| ledger.read(reference))
                        .transpose()?
                        .flatten()
                    {
                        Some(body) => Ok(Reply::Blob {
                            body: encode(&body),
                        }),
                        None => Ok(fault(FaultCode::NotFound, "ciphertext piece unavailable")),
                    }
                }
                Operation::PutBlob {
                    reference,
                    body,
                    proof,
                } => {
                    if !reference.valid() || body.len() > MAX_BLOB_BYTES.div_ceil(3) * 4 {
                        return Err(Error::Invalid("piece bounds".into()));
                    }
                    let body = decode(&body)?;
                    if body.is_empty() || body.len() > MAX_BLOB_BYTES {
                        return Err(Error::Invalid("piece bounds".into()));
                    }
                    let proof = HostedReadProof::decode(&decode(&proof)?)?;
                    log.observer.verify_read(
                        &proof,
                        HostedReadScope::BlobWrite,
                        checksum(&reference.authentication_bytes(Some(checksum(&body)))),
                        now,
                    )?;
                    if proof.member_id() != Some(reference.owner)
                        || !log.observer.rules().may_post(reference.owner)
                    {
                        return Err(Error::Mls(MlsError::Unauthorized));
                    }
                    let missing = !blobs
                        .get(&channel)
                        .is_some_and(|ledger| ledger.contains(&reference));
                    if missing
                        && body.len() as u64 + 256
                            > self.0.config.max_total_bytes.saturating_sub(total)
                    {
                        return Err(Error::Full);
                    }
                    if let std::collections::hash_map::Entry::Vacant(entry) = blobs.entry(channel) {
                        entry.insert(BlobLog::open(
                            &self
                                .0
                                .config
                                .directory
                                .join(file_name(channel))
                                .with_extension("gblob"),
                            channel,
                            self.0.config.limits(),
                        )?);
                    }
                    blobs
                        .get_mut(&channel)
                        .expect("opened")
                        .append(reference, &body)?;
                    Ok(Reply::BlobStored)
                }
                Operation::Acknowledge { receipts } => {
                    self.acknowledge(channel, log, &mut ledgers, receipts, total)
                }
                Operation::Receipts { query, proof } => {
                    let page = Self::receipt_page(channel, log, &mut ledgers, query, proof, now)?;
                    Ok(Reply::Receipts {
                        after: page.after,
                        next: page.next,
                        receipts: page.receipts,
                    })
                }
                Operation::Poll {
                    query,
                    proof,
                    acknowledgments,
                    receipts,
                } => {
                    if query.limit == 0 || query.limit > 32 || acknowledgments.len() > 16 {
                        return Err(Error::Invalid("covered poll bound".into()));
                    }
                    if !acknowledgments.is_empty()
                        && self.0.config.blocked_channels.contains(&channel)
                    {
                        return Err(Error::Mls(MlsError::Unauthorized));
                    }
                    // Validate both read scopes before accepting any acknowledgment.
                    let Reply::Records(page) =
                        log.read_api(query, &proof, HostedReadScope::Records, now, false)?
                    else {
                        return Err(Error::Invalid("covered poll reply".into()));
                    };
                    let receipts = receipts
                        .map(|r| {
                            Self::receipt_page(channel, log, &mut ledgers, r.query, r.proof, now)
                        })
                        .transpose()?;
                    let acknowledged = acknowledgments.len();
                    if acknowledged != 0 {
                        self.acknowledge(channel, log, &mut ledgers, acknowledgments, total)?;
                    }
                    Ok(Reply::Polled {
                        page,
                        acknowledged,
                        receipts,
                    })
                }
                Operation::Snapshot { query, proof } => {
                    log.read_api(query, &proof, HostedReadScope::Snapshot, now, false)
                }
                Operation::Read { query, proof } => {
                    log.read_api(query, &proof, HostedReadScope::Records, now, false)
                }
                Operation::Fetch { query, proof } => {
                    log.read_api(query, &proof, HostedReadScope::Records, now, true)
                }
                Operation::Append(append) => {
                    let (kind, first, second) = match append {
                        Append::Membership { commit, info } => {
                            (JOIN, decode(&commit)?, decode(&info)?)
                        }
                        Append::Control(wire) => (CONTROL, decode(&wire)?, Vec::new()),
                        Append::Message(wire) => (MESSAGE, decode(&wire)?, Vec::new()),
                    };
                    let record = Record {
                        sequence: 0,
                        previous: [0; 32],
                        accepted_at: now,
                        kind,
                        first: first.into(),
                        second: second.into(),
                    };
                    let size = record.tls_serialize_detached()?.len() as u64 + 36;
                    if !log.ids.contains_key(&record.id())
                        && size > self.0.config.max_total_bytes.saturating_sub(total)
                    {
                        return Err(Error::Full);
                    }
                    let accepted = log.append(
                        kind,
                        record.first.as_slice().to_vec(),
                        record.second.as_slice().to_vec(),
                        now,
                    )?;
                    Ok(Reply::Accepted(gcoms_sdk::hosted::Acceptance {
                        sequence: accepted.sequence,
                        id: accepted.id,
                        record_hash: accepted.record_hash,
                    }))
                }
                _ => Err(Error::Invalid("unsupported operation".into())),
            }
        })();
        result.unwrap_or_else(error_reply)
    }
    fn acknowledge(
        &self,
        channel: [u8; 32],
        log: &mut ChannelLog,
        ledgers: &mut HashMap<[u8; 32], ReceiptLog>,
        receipts: Vec<String>,
        total: u64,
    ) -> Result<Reply, Error> {
        if receipts.is_empty() || receipts.len() > 16 {
            return Err(Error::Invalid("receipt batch bound".into()));
        }
        let receipts = receipts
            .iter()
            .map(|r| HostedReceipt::decode(&decode(r)?).map_err(Error::from))
            .collect::<Result<Vec<_>, Error>>()?;
        for receipt in &receipts {
            log.validate_receipt(receipt)?;
        }
        // Reserve worst-case encoded frame size before creating or writing.
        let missing = receipts
            .iter()
            .filter(|r| !ledgers.get(&channel).is_some_and(|l| l.contains(r)))
            .count() as u64;
        if missing > 0
            && missing * 336 + u64::from(!ledgers.contains_key(&channel)) * 40
                > self.0.config.max_total_bytes.saturating_sub(total)
        {
            return Err(Error::Full);
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = ledgers.entry(channel) {
            let path = self
                .0
                .config
                .directory
                .join(file_name(channel))
                .with_extension("gack");
            entry.insert(ReceiptLog::open(
                &path,
                channel,
                self.0.config.limits(),
                log,
            )?);
        }
        let ledger = ledgers.get_mut(&channel).expect("opened");
        for receipt in receipts {
            ledger.append(&receipt)?;
        }
        Ok(Reply::Acknowledged)
    }
    fn receipt_page(
        channel: [u8; 32],
        log: &ChannelLog,
        ledgers: &mut HashMap<[u8; 32], ReceiptLog>,
        query: ReadQuery,
        proof: String,
        now: u64,
    ) -> Result<ReceiptPage, Error> {
        if query.through.is_some() || query.limit == 0 || query.limit > 32 {
            return Err(Error::Invalid("receipt query bound".into()));
        }
        let proof = HostedReadProof::decode(&decode(&proof)?)?;
        proof.verify(
            channel,
            HostedReadScope::Receipts,
            checksum(&query.authentication_bytes()),
            now,
        )?;
        let sender = proof
            .member_id()
            .ok_or(Error::Mls(MlsError::Unauthorized))?;
        if !log.observer.members().contains(&sender) && !log.read_until.contains_key(&sender) {
            return Err(Error::Mls(MlsError::Unauthorized));
        }
        let receipts = if let Some(ledger) = ledgers.get_mut(&channel) {
            ledger.read(sender, query.after, query.limit)?
        } else {
            if query.after != 0 {
                return Err(Error::Invalid("receipt cursor beyond log".into()));
            }
            Vec::new()
        };
        Ok(ReceiptPage {
            after: query.after,
            next: query.after + receipts.len() as u64,
            receipts: receipts.iter().map(|r| encode(r)).collect(),
        })
    }
    pub fn router(&self) -> axum::Router {
        use axum::{extract::DefaultBodyLimit, routing::post};
        axum::Router::new()
            .route("/v1/hosted", post(handle))
            .route("/v1/hosted/bulk", post(handle))
            .layer(DefaultBodyLimit::max(MAX_HTTP_BYTES))
            .with_state(self.clone())
    }
}

async fn handle(
    axum::extract::State(service): axum::extract::State<Service>,
    axum::extract::ConnectInfo(source): axum::extract::ConnectInfo<SocketAddr>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, axum::Json<Reply>) {
    use axum::http::StatusCode;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let source = source.ip();
    if !service.admit(source, now) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(fault(FaultCode::Quota, "request rate limit")),
        );
    }
    let Ok(permit) = service.0.permits.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(fault(FaultCode::Unavailable, "service busy")),
        );
    };
    let request = match serde_json::from_slice::<Request>(&body) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(fault(FaultCode::Invalid, "invalid request")),
            )
        }
    };
    if request.operation.requires_bulk() != uri.path().ends_with("/bulk") {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(fault(
                FaultCode::Invalid,
                "incorrect traffic class endpoint",
            )),
        );
    }
    let reply = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        service.request(request, now)
    })
    .await
    .unwrap_or_else(|_| fault(FaultCode::Unavailable, "service unavailable"));
    // Typed faults are intentional protocol responses, including after an
    // uncertain durable write. Clients retry exact bytes or replay the log.
    (StatusCode::OK, axum::Json(reply))
}

impl ChannelLog {
    fn head_at(&self, sequence: u64) -> Result<Head, Error> {
        let hash = if sequence == 0 {
            self.header_hash
        } else {
            self.index
                .get(sequence as usize - 1)
                .ok_or_else(|| Error::Invalid("head beyond log".into()))?
                .receipt
                .record_hash
        };
        Ok(Head { sequence, hash })
    }
    fn info_at(&mut self, through: u64) -> Result<Vec<u8>, Error> {
        if through == self.len() as u64 {
            return Ok(self.observer.group_info().to_vec());
        }
        for sequence in (1..=through).rev() {
            let record = self
                .read(sequence)?
                .ok_or_else(|| Error::Invalid("missing record".into()))?;
            if let Some((_, info)) = record.membership() {
                return Ok(info.to_vec());
            }
        }
        Ok(self.genesis.clone())
    }
    fn read_api(
        &mut self,
        query: ReadQuery,
        proof: &str,
        scope: HostedReadScope,
        now: u64,
        full: bool,
    ) -> Result<Reply, Error> {
        if query.limit == 0 || query.limit > MAX_PAGE_RECORDS {
            return Err(Error::Invalid("invalid page limit".into()));
        }
        if full && (query.limit != 1 || query.through != query.after.checked_add(1)) {
            return Err(Error::Invalid(
                "bulk fetch requires one exact deferred record".into(),
            ));
        }
        let proof = HostedReadProof::decode(&decode(proof)?)?;
        let hash = Sha256::digest(query.authentication_bytes()).into();
        let ceiling = if self.observer.verify_read(&proof, scope, hash, now).is_ok() {
            self.len() as u64
        } else {
            proof.verify(self.observer.policy().channel_id(), scope, hash, now)?;
            proof
                .member_id()
                .and_then(|id| self.read_until.get(&id).copied())
                .ok_or(Error::Mls(MlsError::Unauthorized))?
        };
        let through = query.through.unwrap_or(ceiling);
        if through > ceiling || query.after > through {
            return Err(Error::Invalid("read outside authorized prefix".into()));
        }
        let head = self.head_at(through)?;
        let mut next = query.after;
        let mut records = Vec::new();
        let mut public_records = Vec::new();
        let final_info = if scope == HostedReadScope::Snapshot {
            Some(encode(&self.info_at(through)?))
        } else {
            None
        };
        let policy = (scope == HostedReadScope::Snapshot && query.after == 0)
            .then(|| self.observer.policy().encode())
            .transpose()?
            .map(|b| encode(&b));
        let genesis =
            (scope == HostedReadScope::Snapshot && query.after == 0).then(|| encode(&self.genesis));
        let mut remaining = if scope == HostedReadScope::Records && !full {
            INLINE_PAGE_BYTES - 1024
        } else {
            MAX_HTTP_BYTES - 65536
        };
        for item in [&final_info, &policy, &genesis].into_iter().flatten() {
            remaining = remaining.checked_sub(item.len()).ok_or(Error::Full)?;
        }
        for sequence in
            query.after + 1..=through.min(query.after.saturating_add(u64::from(query.limit)))
        {
            let record = self
                .read(sequence)?
                .ok_or_else(|| Error::Invalid("missing record".into()))?;
            if scope == HostedReadScope::Records {
                let wire = encode(&record.encode()?);
                if full && wire.len() <= INLINE_WIRE_BYTES {
                    return Err(Error::Invalid("record does not require bulk".into()));
                }
                let (item, size) = if !full && wire.len() > INLINE_WIRE_BYTES {
                    (
                        RecordItem::Deferred {
                            sequence,
                            hash: record.hash()?,
                            wire_bytes: wire.len(),
                        },
                        256,
                    )
                } else {
                    let size = wire.len() + 64;
                    (RecordItem::Inline(wire), size)
                };
                if size > remaining {
                    break;
                }
                remaining -= size;
                records.push(item);
            } else {
                let change = if let Some((commit, _)) = record.membership() {
                    Some(PublicChange::Membership(encode(commit)))
                } else {
                    record
                        .control()?
                        .map(|control| control.encode().map(|b| PublicChange::Control(encode(&b))))
                        .transpose()?
                };
                if let Some(change) = change {
                    let size = match &change {
                        PublicChange::Membership(w) | PublicChange::Control(w) => w.len() + 128,
                    };
                    if size > remaining {
                        break;
                    }
                    remaining -= size;
                    public_records.push(PublicRecord {
                        sequence,
                        accepted_at: record.accepted_at,
                        change,
                    });
                }
            }
            next = sequence;
        }
        if next == query.after && next < through {
            return Err(Error::Full);
        }
        if scope == HostedReadScope::Snapshot {
            Ok(Reply::Snapshot(SnapshotPage {
                head,
                after: query.after,
                next,
                policy,
                genesis,
                public_records,
                group_info: (next == through).then_some(final_info).flatten(),
            }))
        } else {
            Ok(Reply::Records(RecordPage {
                head,
                after: query.after,
                next,
                records,
            }))
        }
    }
}
