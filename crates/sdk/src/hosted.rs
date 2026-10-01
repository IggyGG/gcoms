//! Versioned hosted-channel service contract. Public proof and MLS wires are
//! base64url without padding; chat plaintext and member secrets never appear.
use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const PROFILE: &str = "hosted-mls-pq-v1";
pub const MAX_HTTP_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PAGE_RECORDS: u16 = 128;
/// Ordinary polling and small messages stay on the covered interactive class.
/// Larger state/files use explicit bulk requests, as existing file transport does.
pub const INLINE_WIRE_BYTES: usize = 4096;
pub const INLINE_PAGE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub channel: [u8; 32],
    pub operation: Operation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Operation {
    Info,
    Create {
        policy: String,
        genesis: String,
    },
    Snapshot {
        query: ReadQuery,
        proof: String,
    },
    Read {
        query: ReadQuery,
        proof: String,
    },
    /// One covered exchange for transcript polling, committed acknowledgments
    /// and sender receipt recovery. Advertised by covered-poll-v1.
    Poll {
        query: ReadQuery,
        proof: String,
        acknowledgments: Vec<String>,
        receipts: Option<ReceiptQuery>,
    },
    Fetch {
        query: ReadQuery,
        proof: String,
    },
    Append(Append),
    /// Always covered, bounded batches. Never selected by requires_bulk.
    Receipts {
        query: ReadQuery,
        proof: String,
    },
    Acknowledge {
        receipts: Vec<String>,
    },
    /// Authenticated ciphertext pieces use the explicit bulk class.
    PutBlob {
        reference: BlobRef,
        body: String,
        proof: String,
    },
    GetBlob {
        reference: BlobRef,
        proof: String,
    },
    /// Only explicitly published public channels; never member/user discovery.
    Directory {
        after: Option<[u8; 32]>,
        limit: u16,
    },
}

impl Operation {
    pub fn requires_bulk(&self) -> bool {
        match self {
            Self::PutBlob { .. }
            | Self::GetBlob { .. }
            | Self::Create { .. }
            | Self::Snapshot { .. }
            | Self::Fetch { .. }
            | Self::Append(Append::Membership { .. }) => true,
            Self::Append(Append::Message(wire) | Append::Control(wire)) => {
                wire.len() > INLINE_WIRE_BYTES
            }
            _ => false,
        }
    }
}
/// Piece namespace is owned by the authenticated channel-scoped publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub owner: [u8; 32],
    pub file: [u8; 16],
    pub piece: u32,
}
pub const MAX_BLOB_BYTES: usize = 256 * 1024 + 2048;
impl BlobRef {
    pub fn authentication_bytes(&self, digest: Option<[u8; 32]>) -> Vec<u8> {
        let mut bytes = b"gcoms/hosted/blob/v1".to_vec();
        bytes.extend(self.owner);
        bytes.extend(self.file);
        bytes.extend(self.piece.to_be_bytes());
        bytes.push(u8::from(digest.is_some()));
        if let Some(digest) = digest {
            bytes.extend(digest);
        }
        bytes
    }
    pub fn valid(&self) -> bool {
        self.owner != [0; 32] && self.file != [0; 16] && self.piece < 40_960
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Append {
    Membership { commit: String, info: String },
    Control(String),
    Message(String),
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadQuery {
    pub after: u64,
    /// Pin all pages to the first response's head. None selects the current
    /// authorized head; departed members stop at their removal record.
    pub through: Option<u64>,
    pub limit: u16,
}
impl ReadQuery {
    /// Fixed encoding hashed by the read proof; distinct from JSON presentation.
    pub fn authentication_bytes(&self) -> [u8; 19] {
        let mut bytes = [0; 19];
        bytes[..8].copy_from_slice(&self.after.to_be_bytes());
        bytes[8] = u8::from(self.through.is_some());
        bytes[9..17].copy_from_slice(&self.through.unwrap_or(0).to_be_bytes());
        bytes[17..].copy_from_slice(&self.limit.to_be_bytes());
        bytes
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Reply {
    Info(ServiceInfo),
    Created {
        anchor: [u8; 32],
    },
    Snapshot(SnapshotPage),
    Records(RecordPage),
    Polled {
        page: RecordPage,
        acknowledged: usize,
        receipts: Option<ReceiptPage>,
    },
    Accepted(Acceptance),
    Receipts {
        after: u64,
        next: u64,
        receipts: Vec<String>,
    },
    Acknowledged,
    Blob {
        body: String,
    },
    BlobStored,
    Fault(Fault),
    Directory {
        entries: Vec<DirectoryEntry>,
        next: Option<[u8; 32]>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    pub channel: [u8; 32],
    pub name: String,
    pub members: u32,
    pub capacity: u32,
    pub public_join: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceInfo {
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub requests_per_second: Option<u32>,
    #[serde(default)]
    pub source_requests_per_second: Option<u32>,
    pub version: u16,
    pub profiles: Vec<String>,
    pub public_creation: bool,
    pub max_members: u32,
    pub max_page_records: u16,
    pub max_http_bytes: usize,
    pub motd: String,
    pub rules: String,
    pub operator_contact: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Head {
    pub sequence: u64,
    pub hash: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotPage {
    pub head: Head,
    pub after: u64,
    pub next: u64,
    pub policy: Option<String>,
    pub genesis: Option<String>,
    pub public_records: Vec<PublicRecord>,
    /// Present only on the last page; pinned against replayed context and tree.
    pub group_info: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicRecord {
    pub sequence: u64,
    pub accepted_at: u64,
    pub change: PublicChange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PublicChange {
    Membership(String),
    Control(String),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptQuery {
    pub query: ReadQuery,
    pub proof: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptPage {
    pub after: u64,
    pub next: u64,
    pub receipts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordPage {
    pub head: Head,
    pub after: u64,
    pub next: u64,
    /// Canonical encoded records, retaining their signed encrypted content and
    /// predecessor hashes. Clients validate and durably apply them in order.
    pub records: Vec<RecordItem>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RecordItem {
    Inline(String),
    Deferred {
        sequence: u64,
        hash: [u8; 32],
        wire_bytes: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acceptance {
    pub sequence: u64,
    pub id: [u8; 32],
    pub record_hash: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fault {
    pub code: FaultCode,
    pub message: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultCode {
    Unsupported,
    Invalid,
    Unauthorized,
    NotFound,
    Conflict,
    Quota,
    Unavailable,
}

/// The host owns DNS, TLS and route selection. There is no direct-HTTP fallback.
pub async fn exchange<C: crate::GcClient + ?Sized>(
    client: &C,
    endpoint: &str,
    request: Request,
) -> Result<Reply, crate::SdkError> {
    if !endpoint.ends_with("/v1/hosted") || request.version != VERSION {
        return Err(crate::SdkError::Protocol(
            "unsupported hosted endpoint or profile".into(),
        ));
    }
    let body =
        serde_json::to_vec(&request).map_err(|e| crate::SdkError::Protocol(e.to_string()))?;
    let request = crate::CatalogHttpRequest {
        method: "POST".into(),
        url: if request.operation.requires_bulk() {
            format!("{endpoint}/bulk")
        } else {
            endpoint.into()
        },
        body,
    };
    request.validate_size()?;
    let response = client.catalog_request(request).await?;
    if response.body.len() > MAX_HTTP_BYTES {
        return Err(crate::SdkError::Protocol(
            "hosted response exceeds bound".into(),
        ));
    }
    if response.status != 200 {
        return Err(crate::SdkError::Protocol(format!(
            "hosted service status {}",
            response.status
        )));
    }
    decode_reply_json(&response.body)
}

// JSON-only adapters keep Serde's buffered tagged-enum Content tree out of the
// HTTP client. The public derives remain compatible with every existing codec.
#[derive(Deserialize)]
struct JsonEnvelope<'a> {
    #[serde(borrow)]
    kind: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    value: Option<&'a serde_json::value::RawValue>,
}

fn invalid_reply() -> crate::SdkError {
    crate::SdkError::Protocol("invalid hosted response".into())
}

fn json_body<'a, T: Deserialize<'a>>(
    value: Option<&'a serde_json::value::RawValue>,
) -> Result<T, crate::SdkError> {
    // Keep one byte-slice parser/visitor specialization throughout.
    serde_json::from_slice(value.ok_or_else(invalid_reply)?.get().as_bytes())
        .map_err(|_| invalid_reply())
}

fn json_object<'a, T: Deserialize<'a>>(
    value: Option<&'a serde_json::value::RawValue>,
) -> Result<T, crate::SdkError> {
    // An adjacent-tag enum's struct variants accept object bodies only. A
    // standalone derived struct also accepts sequences; do not broaden the wire.
    let value = value.ok_or_else(invalid_reply)?;
    if !value.get().trim_ascii_start().starts_with('{') {
        return Err(invalid_reply());
    }
    json_body(Some(value))
}

struct JsonRecordItem(RecordItem);
impl<'de> Deserialize<'de> for JsonRecordItem {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Deferred {
            sequence: u64,
            hash: [u8; 32],
            wire_bytes: usize,
        }
        let envelope = JsonEnvelope::deserialize(deserializer)?;
        let item = match envelope.kind.as_ref() {
            "inline" => {
                RecordItem::Inline(json_body(envelope.value).map_err(serde::de::Error::custom)?)
            }
            "deferred" => {
                let Deferred {
                    sequence,
                    hash,
                    wire_bytes,
                } = json_object(envelope.value).map_err(serde::de::Error::custom)?;
                RecordItem::Deferred {
                    sequence,
                    hash,
                    wire_bytes,
                }
            }
            _ => return Err(serde::de::Error::custom("invalid hosted record")),
        };
        Ok(Self(item))
    }
}

#[derive(Deserialize)]
struct JsonRecordPage {
    head: Head,
    after: u64,
    next: u64,
    records: Vec<JsonRecordItem>,
}
impl From<JsonRecordPage> for RecordPage {
    fn from(page: JsonRecordPage) -> Self {
        Self {
            head: page.head,
            after: page.after,
            next: page.next,
            records: page.records.into_iter().map(|record| record.0).collect(),
        }
    }
}

struct JsonPublicChange(PublicChange);
impl<'de> Deserialize<'de> for JsonPublicChange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = JsonEnvelope::deserialize(deserializer)?;
        let body = json_body(envelope.value).map_err(serde::de::Error::custom)?;
        Ok(Self(match envelope.kind.as_ref() {
            "membership" => PublicChange::Membership(body),
            "control" => PublicChange::Control(body),
            _ => return Err(serde::de::Error::custom("invalid hosted public change")),
        }))
    }
}

#[derive(Deserialize)]
struct JsonPublicRecord {
    sequence: u64,
    accepted_at: u64,
    change: JsonPublicChange,
}
#[derive(Deserialize)]
struct JsonSnapshotPage {
    head: Head,
    after: u64,
    next: u64,
    policy: Option<String>,
    genesis: Option<String>,
    public_records: Vec<JsonPublicRecord>,
    group_info: Option<String>,
}
impl From<JsonSnapshotPage> for SnapshotPage {
    fn from(page: JsonSnapshotPage) -> Self {
        Self {
            head: page.head,
            after: page.after,
            next: page.next,
            policy: page.policy,
            genesis: page.genesis,
            public_records: page
                .public_records
                .into_iter()
                .map(|record| PublicRecord {
                    sequence: record.sequence,
                    accepted_at: record.accepted_at,
                    change: record.change.0,
                })
                .collect(),
            group_info: page.group_info,
        }
    }
}

// Decode each selected body from the original bounded JSON bytes, retaining
// field-order independence and duplicate-field/type validation.
fn decode_reply_json(bytes: &[u8]) -> Result<Reply, crate::SdkError> {
    #[derive(Deserialize)]
    struct Created {
        anchor: [u8; 32],
    }
    #[derive(Deserialize)]
    struct Polled {
        page: JsonRecordPage,
        acknowledged: usize,
        receipts: Option<ReceiptPage>,
    }
    #[derive(Deserialize)]
    struct Receipts {
        after: u64,
        next: u64,
        receipts: Vec<String>,
    }
    #[derive(Deserialize)]
    struct Blob {
        body: String,
    }
    #[derive(Deserialize)]
    struct Directory {
        entries: Vec<DirectoryEntry>,
        next: Option<[u8; 32]>,
    }
    let envelope: JsonEnvelope<'_> = serde_json::from_slice(bytes).map_err(|_| invalid_reply())?;
    Ok(match envelope.kind.as_ref() {
        "info" => Reply::Info(json_body(envelope.value)?),
        "created" => {
            let Created { anchor } = json_object(envelope.value)?;
            Reply::Created { anchor }
        }
        "snapshot" => Reply::Snapshot(json_body::<JsonSnapshotPage>(envelope.value)?.into()),
        "records" => Reply::Records(json_body::<JsonRecordPage>(envelope.value)?.into()),
        "polled" => {
            let Polled {
                page,
                acknowledged,
                receipts,
            } = json_object(envelope.value)?;
            Reply::Polled {
                page: page.into(),
                acknowledged,
                receipts,
            }
        }
        "accepted" => Reply::Accepted(json_body(envelope.value)?),
        "receipts" => {
            let Receipts {
                after,
                next,
                receipts,
            } = json_object(envelope.value)?;
            Reply::Receipts {
                after,
                next,
                receipts,
            }
        }
        "acknowledged" | "blob_stored" => {
            if let Some(value) = envelope.value {
                serde_json::from_slice::<()>(value.get().as_bytes())
                    .map_err(|_| invalid_reply())?;
            }
            if envelope.kind == "acknowledged" {
                Reply::Acknowledged
            } else {
                Reply::BlobStored
            }
        }
        "blob" => {
            let Blob { body } = json_object(envelope.value)?;
            Reply::Blob { body }
        }
        "fault" => Reply::Fault(json_body(envelope.value)?),
        "directory" => {
            let Directory { entries, next } = json_object(envelope.value)?;
            Reply::Directory { entries, next }
        }
        _ => return Err(invalid_reply()),
    })
}

#[cfg(test)]
mod reply_json_tests {
    use super::*;

    fn equivalent(case: &str) {
        let original = serde_json::from_str::<Reply>(case);
        let actual = decode_reply_json(case.as_bytes());
        assert_eq!(actual.is_ok(), original.is_ok(), "{case}");
        if let (Ok(original), Ok(actual)) = (original, actual) {
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(original).unwrap()
            );
        }
    }

    #[test]
    fn borrowed_envelope_matches_the_original_json_decoder() {
        let cases = [
            r#"{"kind":"info","value":{"version":1,"profiles":[],"public_creation":false,"max_members":64,"max_page_records":16,"max_http_bytes":1048576,"motd":"","rules":"","operator_contact":""}}"#,
            r#"{"kind":"created","value":{"anchor":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#,
            r#"{"kind":"snapshot","value":{"head":{"sequence":0,"hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},"after":0,"next":0,"policy":null,"genesis":null,"public_records":[],"group_info":null}}"#,
            r#"{"kind":"records","value":{"head":{"sequence":0,"hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},"after":0,"next":0,"records":[{"kind":"inline","value":"encrypted"}]}}"#,
            r#"{"kind":"polled","value":{"page":{"head":{"sequence":0,"hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},"after":0,"next":0,"records":[]},"acknowledged":0}}"#,
            r#"{"kind":"accepted","value":{"sequence":1,"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"record_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#,
            r#"{"kind":"receipts","value":{"after":0,"next":0,"receipts":[]}}"#,
            r#"{"kind":"acknowledged"}"#,
            r#"{"kind":"blob_stored","value":null}"#,
            r#"{"value":{"body":"ciphertext"},"kind":"b\u006cob","other":true}"#,
            r#"{"kind":"fault","value":{"code":"unauthorized","message":"denied"}}"#,
            r#"{"kind":"directory","value":{"entries":[],"next":null}}"#,
            r#"{"kind":"blob","value":{"body":"first","body":"duplicate"}}"#,
            r#"{"kind":"blob","kind":"blob","value":{"body":"duplicate"}}"#,
            r#"{"kind":"blob","value":null,"value":{"body":"duplicate"}}"#,
            r#"{"kind":"blob","value":{}}"#,
            r#"{"kind":"blob","value":{"body":false}}"#,
            r#"{"kind":"blob_stored","value":42}"#,
            r#"{"kind":"unknown","value":{}}"#,
            r#"{"kind":"acknowledged"} false"#,
            r#"["blob",{"body":"sequence"}]"#,
            r#"["blob",["sequence body"]]"#,
            r#"{"kind":"receipts","value":[0,0,[]]}"#,
            r#"{"kind":"directory","value":[[],null]}"#,
        ];
        for case in cases {
            equivalent(case);
        }
    }

    #[test]
    fn nested_json_records_retain_the_public_decoder_semantics() {
        let head = serde_json::to_string(&Head {
            sequence: 1,
            hash: [7; 32],
        })
        .unwrap();
        let hash = serde_json::to_string(&[9_u8; 32]).unwrap();
        let mut items = vec![
            r#"{"kind":"inline","value":"encrypted"}"#.to_string(),
            r#"{"value":"escaped\nwire","kind":"in\u006cine","unknown":true}"#.into(),
            r#"["inline","sequence"]"#.into(),
            format!(
                r#"{{"kind":"deferred","value":{{"sequence":2,"hash":{hash},"wire_bytes":4097}}}}"#
            ),
            format!(r#"["deferred",[2,{hash},4097]]"#),
        ];
        for kind in ["inline", "deferred", "unknown", "0", "null"] {
            let tag = if kind == "0" || kind == "null" {
                kind.to_string()
            } else {
                format!("\"{kind}\"")
            };
            for value in ["null", "false", "42", "{}", "[]", "\"wire\""] {
                items.push(format!(r#"{{"kind":{tag},"value":{value}}}"#));
            }
        }
        items.extend([
            r#"{"kind":"inline"}"#.into(),
            r#"{"kind":"inline","kind":"inline","value":"duplicate"}"#.into(),
            r#"{"kind":"inline","value":null,"value":"duplicate"}"#.into(),
            format!(r#"{{"kind":"deferred","value":{{"sequence":1,"sequence":2,"hash":{hash},"wire_bytes":4097}}}}"#),
        ]);
        for item in items {
            let page = format!(r#"{{"head":{head},"after":0,"next":1,"records":[{item}]}}"#);
            equivalent(&format!(r#"{{"kind":"records","value":{page}}}"#));
            equivalent(&format!(
                r#"{{"kind":"polled","value":{{"page":{page},"acknowledged":1,"receipts":{{"after":0,"next":1,"receipts":["receipt"]}}}}}}"#
            ));
        }
        for change in [
            r#"{"kind":"membership","value":"commit"}"#,
            r#"{"value":"control","kind":"control","other":{}}"#,
            r#"["membership","commit"]"#,
            r#"{"kind":"control","value":null}"#,
            r#"{"kind":"control","value":42}"#,
            r#"{"kind":"unknown","value":"wire"}"#,
            r#"{"kind":0,"value":"wire"}"#,
            r#"{"kind":"control","kind":"control","value":"duplicate"}"#,
            r#"{"kind":"control","value":null,"value":"duplicate"}"#,
        ] {
            let record = format!(r#"{{"sequence":1,"accepted_at":2,"change":{change}}}"#);
            equivalent(&format!(
                r#"{{"kind":"snapshot","value":{{"head":{head},"after":0,"next":1,"public_records":[{record}],"policy":"policy","genesis":"genesis","group_info":"info"}}}}"#
            ));
        }
    }
}
