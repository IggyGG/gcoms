//! Native Network.framework cost signals. One process-wide path monitor owns
//! a capture-free global Block for the lifetime of the desktop process.
//! ABI: https://clang.llvm.org/docs/Block-ABI-Apple.html
use std::{
    ffi::{c_char, c_void},
    sync::{
        atomic::{AtomicU8, Ordering},
        OnceLock,
    },
    time::Duration,
};
static PATH: AtomicU8 = AtomicU8::new(0);
static STARTED: OnceLock<bool> = OnceLock::new();
#[repr(C)]
struct Descriptor {
    reserved: usize,
    size: usize,
}
#[repr(C)]
struct GlobalBlock {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    invoke: unsafe extern "C" fn(*const GlobalBlock, *mut c_void),
    descriptor: *const Descriptor,
}
#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_path_monitor_create() -> *mut c_void;
    fn nw_path_monitor_set_update_handler(monitor: *mut c_void, handler: *const GlobalBlock);
    fn nw_path_monitor_set_queue(monitor: *mut c_void, queue: *mut c_void);
    fn nw_path_monitor_start(monitor: *mut c_void);
    fn nw_path_get_status(path: *mut c_void) -> i32;
    fn nw_path_is_expensive(path: *mut c_void) -> bool;
    fn nw_path_is_constrained(path: *mut c_void) -> bool;
}
unsafe extern "C" {
    static _NSConcreteGlobalBlock: c_void;
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> *mut c_void;
    fn getloadavg(load: *mut f64, count: i32) -> i32;
}
unsafe extern "C" fn update(_block: *const GlobalBlock, path: *mut c_void) {
    // SAFETY: Network.framework supplies a live nw_path_t for this callback.
    let eligible = unsafe {
        nw_path_get_status(path) == 1
            && !nw_path_is_expensive(path)
            && !nw_path_is_constrained(path)
    };
    PATH.store(if eligible { 1 } else { 2 }, Ordering::Release);
}
fn start() -> bool {
    // SAFETY: the capture-free global Block has the documented ABI layout and
    // remains allocated for the lifetime of this single process-wide monitor.
    unsafe {
        let monitor = nw_path_monitor_create();
        let queue = dispatch_queue_create(c"gcoms.relay-sharing".as_ptr(), std::ptr::null());
        if monitor.is_null() || queue.is_null() {
            return false;
        }
        let descriptor = Box::leak(Box::new(Descriptor {
            reserved: 0,
            size: std::mem::size_of::<GlobalBlock>(),
        }));
        let block = Box::leak(Box::new(GlobalBlock {
            isa: std::ptr::addr_of!(_NSConcreteGlobalBlock),
            flags: 1 << 28,
            reserved: 0,
            invoke: update,
            descriptor,
        }));
        nw_path_monitor_set_update_handler(monitor, block);
        nw_path_monitor_set_queue(monitor, queue);
        nw_path_monitor_start(monitor);
    }
    true
}
pub(super) async fn eligibility() -> Result<(), &'static str> {
    if !*STARTED.get_or_init(start) || PATH.load(Ordering::Acquire) != 1 {
        return Err("Waiting for an unmetered network");
    }
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("/usr/bin/pmset")
            .args(["-g", "batt"])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    if !output.is_ok_and(|out| {
        out.is_ok_and(|out| {
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains("AC Power")
        })
    }) {
        return Err("Paused on battery power");
    }
    let mut load = 0.0;
    // SAFETY: one initialized f64 is writable for the synchronous C call.
    if unsafe { getloadavg(&mut load, 1) } != 1
        || load > std::thread::available_parallelism().map_or(1, usize::from) as f64
    {
        return Err("Paused while this device is busy");
    }
    let memory = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("/usr/bin/memory_pressure")
            .arg("-Q")
            .kill_on_drop(true)
            .output(),
    )
    .await;
    if !memory.is_ok_and(|output| {
        output.is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("System-wide memory free percentage: ")?
                            .trim()
                            .strip_suffix('%')?
                            .parse::<u8>()
                            .ok()
                    })
                    .is_some_and(|free| free > 10)
        })
    }) {
        return Err("Paused under memory pressure");
    }
    Ok(())
}
