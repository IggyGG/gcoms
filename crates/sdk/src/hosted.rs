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

// Decode the JSON envelope once, then its selected body. Serde's generic tagged
// enum visitor also instantiates every reply through a buffered Content tree.
// The HTTP exchange needs only JSON and can borrow the original bounded bytes,
// retaining field-order independence and duplicate-field/type validation.
fn decode_reply_json(bytes: &[u8]) -> Result<Reply, crate::SdkError> {
    use serde_json::value::RawValue;
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow)]
        kind: std::borrow::Cow<'a, str>,
        #[serde(borrow)]
        value: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Created {
        anchor: [u8; 32],
    }
    #[derive(Deserialize)]
    struct Polled {
        page: RecordPage,
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
    fn invalid() -> crate::SdkError {
        crate::SdkError::Protocol("invalid hosted response".into())
    }
    fn body<'a, T: Deserialize<'a>>(value: Option<&'a RawValue>) -> Result<T, crate::SdkError> {
        serde_json::from_str(value.ok_or_else(invalid)?.get()).map_err(|_| invalid())
    }
    let envelope: Envelope<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    Ok(match envelope.kind.as_ref() {
        "info" => Reply::Info(body(envelope.value)?),
        "created" => {
            let Created { anchor } = body(envelope.value)?;
            Reply::Created { anchor }
        }
        "snapshot" => Reply::Snapshot(body(envelope.value)?),
        "records" => Reply::Records(body(envelope.value)?),
        "polled" => {
            let Polled {
                page,
                acknowledged,
                receipts,
            } = body(envelope.value)?;
            Reply::Polled {
                page,
                acknowledged,
                receipts,
            }
        }
        "accepted" => Reply::Accepted(body(envelope.value)?),
        "receipts" => {
            let Receipts {
                after,
                next,
                receipts,
            } = body(envelope.value)?;
            Reply::Receipts {
                after,
                next,
                receipts,
            }
        }
        "acknowledged" | "blob_stored" => {
            if let Some(value) = envelope.value {
                serde_json::from_str::<()>(value.get()).map_err(|_| invalid())?;
            }
            if envelope.kind == "acknowledged" {
                Reply::Acknowledged
            } else {
                Reply::BlobStored
            }
        }
        "blob" => {
            let Blob { body } = body(envelope.value)?;
            Reply::Blob { body }
        }
        "fault" => Reply::Fault(body(envelope.value)?),
        "directory" => {
            let Directory { entries, next } = body(envelope.value)?;
            Reply::Directory { entries, next }
        }
        _ => return Err(invalid()),
    })
}

#[cfg(test)]
mod reply_json_tests {
    use super::*;

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
        ];
        for case in cases {
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
    }
}
