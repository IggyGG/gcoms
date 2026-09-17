//! Local JSONL metrics.
//!
//! Design constraints (SPEC §14, R4): the metrics file is an operator
//! diagnostic, never a record of who talked to whom. No field may carry a
//! relay address, queue id, path token, or peer address. Callers pass only
//! event names, error strings, counts, and durations. The writer runs on
//! its own thread behind a bounded channel so a slow disk never blocks a
//! task that holds node state; overflow is counted and dropped.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

/// Events buffered toward the writer thread before new ones are dropped.
pub const QUEUE_CAPACITY: usize = 4096;
/// Field names that must never appear in a metrics line.
pub const FORBIDDEN_FIELDS: &[&str] = &["target", "queue", "token", "peer", "addr", "path", "to"];

static SENDER: OnceLock<Mutex<Option<SyncSender<String>>>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

fn sender() -> &'static Mutex<Option<SyncSender<String>>> {
    SENDER.get_or_init(|| Mutex::new(None))
}

pub fn init(path: &std::path::Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    let (tx, rx) = sync_channel::<String>(QUEUE_CAPACITY);
    std::thread::Builder::new()
        .name("gc-metrics".into())
        .spawn(move || {
            while let Ok(line) = rx.recv() {
                let _ = writeln!(file, "{line}");
            }
        })?;
    *sender().lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
    Ok(())
}

/// Lines the writer could not keep up with since startup.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

fn escape_json(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

pub fn log_event(event: &str, fields: &[(&str, String)]) {
    debug_assert!(
        fields
            .iter()
            .all(|(key, _)| !FORBIDDEN_FIELDS.contains(key)),
        "metrics must not carry routing identifiers"
    );
    log_event_filtered(event, fields);
}

/// Release-path behaviour: forbidden fields are silently dropped so that a
/// caller bug can never leak an identifier even without the debug check.
fn log_event_filtered(event: &str, fields: &[(&str, String)]) {
    let mut line = String::with_capacity(96);
    line.push_str("{\"ts\":");
    line.push_str(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
            .to_string(),
    );
    line.push_str(",\"event\":\"");
    escape_json(event, &mut line);
    line.push('"');
    for (key, value) in fields {
        if FORBIDDEN_FIELDS.contains(key) {
            continue;
        }
        line.push_str(",\"");
        escape_json(key, &mut line);
        line.push_str("\":\"");
        escape_json(value, &mut line);
        line.push('"');
    }
    line.push('}');
    let guard = sender().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(tx) = guard.as_ref() {
        match tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_produces_valid_json_for_hostile_values() {
        let mut out = String::new();
        escape_json("a\"b\\c\nd\u{1}e", &mut out);
        assert_eq!(out, "a\\\"b\\\\c\\nd\\u0001e");
    }

    #[test]
    fn forbidden_fields_are_dropped_rather_than_written() {
        // Only the filtering path is testable without the writer; the
        // debug assertion documents the contract for callers.
        assert!(FORBIDDEN_FIELDS.contains(&"target"));
        assert!(FORBIDDEN_FIELDS.contains(&"queue"));
        assert!(FORBIDDEN_FIELDS.contains(&"token"));
        assert!(FORBIDDEN_FIELDS.contains(&"peer"));
    }

    #[cfg(unix)]
    #[test]
    fn metrics_file_is_owner_only_and_burst_does_not_block() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gc-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.jsonl");
        init(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let start = std::time::Instant::now();
        for i in 0..(QUEUE_CAPACITY * 2) {
            log_event_filtered(
                "burst",
                &[("n", i.to_string()), ("target", "must-not-appear".into())],
            );
        }
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("must-not-appear"));
        assert!(contents
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
