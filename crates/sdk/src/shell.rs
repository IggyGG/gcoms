//! Capability-scoped host execution. Only the machine daemon implements this API.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
pub const MAX_TIMEOUT_SECONDS: u64 = 3600;
pub const OUTPUT_LIMIT: usize = 1024 * 1024;
pub const CHUNK_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Execute {
    pub command_id: String,
    pub script: String,
    pub working_directory: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}
fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellRequest {
    Execute(Execute),
    Read { command_id: String, after: u64 },
    Cancel { command_id: String },
    Health,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Interrupted,
}
impl State {
    pub fn terminal(&self) -> bool {
        *self != Self::Running
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Chunk {
    pub sequence: u64,
    pub stderr: bool,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Snapshot {
    pub command_id: String,
    pub state: State,
    pub exit_code: Option<i32>,
    pub chunks: Vec<Chunk>,
    pub next_sequence: u64,
    pub truncated: bool,
    pub error: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellReply {
    Job(Snapshot),
    Health {
        ready: bool,
        shell: String,
        running: usize,
        error: Option<String>,
    },
}
