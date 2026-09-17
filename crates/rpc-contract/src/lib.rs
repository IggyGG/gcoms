//! Runtime-free, JSON wire contracts. Unrestricted integers use decimal strings.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

pub const WIRE_VERSION: u16 = 1;
pub const LOCAL_FRAME_LIMIT: usize = 16 * 1024 * 1024;
pub const DEFAULT_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
pub const DEFAULT_RECORD_LIMIT: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema, TS)]
#[serde(transparent)]
pub struct OperationId(
    #[schemars(length(min = 16, max = 128), regex(pattern = "^[A-Za-z0-9_-]+$"))] String,
);
impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, RpcError> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err(RpcError::new(
                ErrorCode::InvalidRequest,
                "invalid operation ID",
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, TS)]
#[ts(type = "string")]
pub struct DecimalU64(pub u64);
impl JsonSchema for DecimalU64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DecimalU64".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let maximum = u64::MAX.to_string();
        let mut alternatives = vec![
            "0".to_owned(),
            "[1-9][0-9]{0,18}".to_owned(),
            maximum.clone(),
        ];
        for (index, digit) in maximum.bytes().enumerate().skip(1) {
            if digit > b'0' {
                alternatives.push(format!(
                    "{}[0-{}][0-9]{{{}}}",
                    &maximum[..index],
                    char::from(digit - 1),
                    maximum.len() - index - 1
                ));
            }
        }
        schemars::json_schema!({"type": "string", "pattern": format!("^({})$", alternatives.join("|"))})
    }
}
impl Serialize for DecimalU64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        let n: u64 = value.parse().map_err(serde::de::Error::custom)?;
        if value != n.to_string() {
            return Err(serde::de::Error::custom("noncanonical u64"));
        }
        Ok(Self(n))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    Query,
    Operation,
    Session,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Version,
    Instance,
    Service,
    Method,
    Unauthorized,
    Conflict,
    Expired,
    Unavailable,
    Busy,
    PayloadTooLarge,
    Storage,
    Transport,
    Timeout,
    Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: ErrorCode,
    pub message: String,
}
impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Protocol, message)
    }
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for RpcError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
pub struct OperationToken {
    pub id: OperationId,
    pub deadline: DecimalU64,
}

/// Safe to retain in browser storage: no arguments, result, credentials or passphrase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
pub struct OperationHandle {
    pub destination: String,
    pub instance: String,
    pub service: String,
    pub version: u16,
    pub method: String,
    pub operation: OperationToken,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Invocation {
    Call {
        #[ts(type = "unknown")]
        args: Value,
        operation: Option<OperationToken>,
    },
    Status {
        operation_id: OperationId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub rpc: u16,
    pub id: OperationId,
    pub instance: String,
    pub service: String,
    pub version: u16,
    pub method: String,
    pub invocation: Invocation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Outcome {
    Ok(#[ts(type = "unknown")] Value),
    Error(#[ts(type = "unknown")] Value),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplyBody {
    Done { outcome: Outcome },
    Running,
    OutcomeUnknown,
    Unavailable,
    Failed { error: RpcError },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub rpc: u16,
    pub id: OperationId,
    pub instance: String,
    pub service: String,
    pub version: u16,
    pub method: String,
    pub body: ReplyBody,
}
impl Request {
    pub fn reply(&self, body: ReplyBody) -> Reply {
        Reply {
            rpc: WIRE_VERSION,
            id: self.id.clone(),
            instance: self.instance.clone(),
            service: self.service.clone(),
            version: self.version,
            method: self.method.clone(),
            body,
        }
    }
    pub fn check_reply(&self, reply: &Reply) -> Result<(), RpcError> {
        if reply.rpc != WIRE_VERSION
            || reply.id != self.id
            || reply.instance != self.instance
            || reply.service != self.service
            || reply.version != self.version
            || reply.method != self.method
        {
            return Err(RpcError::protocol("reply binding does not match request"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Method {
    pub id: String,
    pub kind: MethodKind,
    pub args_schema: Value,
    pub output_schema: Value,
    pub error_schema: Value,
    pub args_typescript: String,
    pub output_typescript: String,
    pub error_typescript: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub version: u16,
    pub methods: Vec<Method>,
}
impl Service {
    pub fn content_type(&self) -> String {
        content_type(&self.name, self.version)
    }
}
pub fn content_type(service: &str, version: u16) -> String {
    format!("application/vnd.ghost.rpc.{service}.v{version}+json")
}
pub fn typescript() -> String {
    [
        OperationId::decl(),
        DecimalU64::decl(),
        MethodKind::decl(),
        ErrorCode::decl(),
        RpcError::decl(),
        OperationToken::decl(),
        OperationHandle::decl(),
        Invocation::decl(),
        Request::decl(),
        Outcome::decl(),
        ReplyBody::decl(),
        Reply::decl(),
    ]
    .into_iter()
    .map(|s| format!("export {s}\n"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_in_fixtures_roundtrip_without_wire_changes() {
        let wire: Value = serde_json::from_str(include_str!("../schemas/wire.json")).unwrap();
        let request: Request = serde_json::from_value(wire["fixtures"]["request"].clone()).unwrap();
        let reply: Reply = serde_json::from_value(wire["fixtures"]["reply"].clone()).unwrap();
        request.check_reply(&reply).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            wire["fixtures"]["request"]
        );
        let handle: OperationHandle =
            serde_json::from_value(wire["fixtures"]["handle"].clone()).unwrap();
        assert_eq!(handle.operation.deadline.0, u64::MAX);
    }
    #[test]
    fn lossless_ids_and_numbers() {
        let encoded = serde_json::to_string(&DecimalU64(u64::MAX)).unwrap();
        assert_eq!(encoded, "\"18446744073709551615\"");
        assert_eq!(
            serde_json::from_str::<DecimalU64>(&encoded).unwrap().0,
            u64::MAX
        );
        for invalid in ["1", "\"01\"", "\"-1\"", "\"18446744073709551616\""] {
            assert!(serde_json::from_str::<DecimalU64>(invalid).is_err());
        }
        assert!(OperationId::new("short").is_err());
        assert!(OperationId::new("invalid/id/12345678").is_err());
    }
}
