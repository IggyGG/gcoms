//! Versioned, caller-owned-buffer ABI. No Rust allocation crosses the boundary.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(any(
    all(feature = "client", feature = "relay"),
    not(any(feature = "client", feature = "relay"))
))]
compile_error!("select exactly one of client or relay; relay requires --no-default-features");
#[cfg(target_os = "android")]
mod android;
mod command;

use futures_util::FutureExt;
use std::{
    collections::HashMap,
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use zeroize::Zeroizing;

pub const MAX_REQUEST: usize = 1100 * 1024;
pub const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_JOBS: usize = 16;
const MAX_SESSIONS: usize = 8;
type Bytes = Zeroizing<Vec<u8>>;
enum Outcome {
    Pending,
    Ready(Bytes),
    Cancelled,
}
struct Job {
    input: Bytes,
    result: Arc<Mutex<Outcome>>,
}
struct Session {
    sender: Mutex<Option<tokio::sync::mpsc::Sender<Job>>>,
    jobs: Mutex<HashMap<u64, Arc<Mutex<Outcome>>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}
static SESSIONS: OnceLock<Mutex<HashMap<u64, Arc<Session>>>> = OnceLock::new();
static IDS: AtomicU64 = AtomicU64::new(1);
fn sessions() -> &'static Mutex<HashMap<u64, Arc<Session>>> {
    SESSIONS.get_or_init(Default::default)
}
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
fn session(id: u64) -> Option<Arc<Session>> {
    lock(sessions()).get(&id).cloned()
}
fn boundary<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}
fn id() -> u64 {
    IDS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn gcoms_mobile_abi_version() -> u32 {
    1
}
/// 1 = outbound client, 2 = embedded relay. Both libraries export the same ABI.
#[no_mangle]
pub extern "C" fn gcoms_mobile_role() -> u32 {
    if cfg!(feature = "relay") {
        2
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn gcoms_mobile_create() -> u64 {
    boundary(0, || {
        let mut registry = lock(sessions());
        if registry.len() >= MAX_SESSIONS {
            return 0;
        }
        let handle = id();
        if handle == 0 {
            return 0;
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(MAX_JOBS);
        let thread = match std::thread::Builder::new()
            .name("gcoms-mobile".into())
            .spawn(move || worker(receiver))
        {
            Ok(thread) => thread,
            Err(_) => return 0,
        };
        registry.insert(
            handle,
            Arc::new(Session {
                sender: Mutex::new(Some(sender)),
                jobs: Mutex::new(HashMap::new()),
                thread: Mutex::new(Some(thread)),
            }),
        );
        handle
    })
}
/// Copies UTF-8 JSON before returning. Zero indicates invalid input or backpressure.
///
/// # Safety
/// input must address length readable bytes for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn gcoms_mobile_submit(handle: u64, input: *const u8, length: usize) -> u64 {
    boundary(0, || {
        if input.is_null() || length == 0 || length > MAX_REQUEST {
            return 0;
        }
        let Some(session) = session(handle) else {
            return 0;
        };
        let mut jobs = lock(&session.jobs);
        if jobs.len() >= MAX_JOBS {
            return 0;
        }
        let ticket = id();
        if ticket == 0 {
            return 0;
        }
        let result = Arc::new(Mutex::new(Outcome::Pending));
        // SAFETY: caller guarantees readable input; bounded length checked above.
        let input = Zeroizing::new(unsafe { std::slice::from_raw_parts(input, length) }.to_vec());
        let job = Job {
            input,
            result: result.clone(),
        };
        let sender = lock(&session.sender);
        if sender.as_ref().is_none_or(|s| s.try_send(job).is_err()) {
            return 0;
        }
        jobs.insert(ticket, result);
        ticket
    })
}
/// 0 = pending; -1 = invalid handle/ticket; -2 = contained panic.
/// Positive = required byte count. Copies and consumes only if capacity suffices.
/// Query with output=NULL/capacity=0. Result bytes have no trailing NUL.
///
/// # Safety
/// A non-null output must address capacity writable bytes and must not alias input.
#[no_mangle]
pub unsafe extern "C" fn gcoms_mobile_take(
    handle: u64,
    ticket: u64,
    output: *mut u8,
    capacity: usize,
) -> isize {
    boundary(-2, || {
        let Some(session) = session(handle) else {
            return -1;
        };
        let mut jobs = lock(&session.jobs);
        let Some(job) = jobs.get(&ticket).cloned() else {
            return -1;
        };
        let result = lock(&job);
        match &*result {
            Outcome::Pending => 0,
            Outcome::Cancelled => -1,
            Outcome::Ready(bytes) => {
                let length = bytes.len();
                if !output.is_null() && capacity >= length {
                    // SAFETY: caller owns sufficient writable memory.
                    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, length) };
                    jobs.remove(&ticket);
                }
                length as isize
            }
        }
    })
}
/// Releases a ticket. Queued work is skipped; already running durable work finishes.
/// Cancellation never promises rollback. Reconcile state before retrying mutations.
#[no_mangle]
pub extern "C" fn gcoms_mobile_cancel(handle: u64, ticket: u64) -> i32 {
    boundary(-2, || {
        let Some(session) = session(handle) else {
            return -1;
        };
        let Some(job) = lock(&session.jobs).remove(&ticket) else {
            return -1;
        };
        *lock(&job) = Outcome::Cancelled;
        0
    })
}
/// Closes the profile and joins its worker. Call off the platform UI thread.
#[no_mangle]
pub extern "C" fn gcoms_mobile_destroy(handle: u64) -> i32 {
    boundary(-2, || {
        let Some(session) = lock(sessions()).remove(&handle) else {
            return -1;
        };
        for job in lock(&session.jobs).values() {
            *lock(job) = Outcome::Cancelled;
        }
        lock(&session.sender).take();
        let thread = lock(&session.thread).take();
        if thread.is_some_and(|t| t.join().is_err()) {
            return -2;
        }
        0
    })
}
fn worker(mut receiver: tokio::sync::mpsc::Receiver<Job>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        while let Some(job) = receiver.blocking_recv() {
            finish(&job, Err("runtime creation failed".into()));
        }
        return;
    };
    runtime.block_on(async move {
        let mut state = command::State::new();
        let mut poisoned = false;
        while let Some(job) = receiver.recv().await {
            if matches!(*lock(&job.result), Outcome::Cancelled) {
                continue;
            }
            let result = if poisoned {
                Err("session failed; destroy and recreate it".into())
            } else {
                match serde_json::from_slice::<command::Command>(&job.input) {
                    Err(_) => Err("invalid ABI v1 request".into()),
                    Ok(command) => match AssertUnwindSafe(state.execute(command))
                        .catch_unwind()
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            poisoned = true;
                            Err("contained native panic; recreate session".into())
                        }
                    },
                }
            };
            finish(&job, result);
        }
        let _ = AssertUnwindSafe(state.close()).catch_unwind().await;
    });
}
fn finish(job: &Job, result: Result<serde_json::Value, String>) {
    let response = match result {
        Ok(value) => serde_json::json!({"ok": value}),
        Err(error) => serde_json::json!({"error": error}),
    };
    struct Bounded(Bytes);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_RESPONSE {
                return Err(std::io::Error::other("response too large"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Zeroizing::new(Vec::new()));
    if serde_json::to_writer(&mut output, &response).is_err() {
        output.0 = Zeroizing::new(
            br#"{"error":"response exceeds ABI bound; use smaller pages"}"#.to_vec(),
        );
    }
    let mut slot = lock(&job.result);
    if !matches!(*slot, Outcome::Cancelled) {
        *slot = Outcome::Ready(output.0);
    }
}
