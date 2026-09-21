# GComs mobile native interface

Android emulator/iOS simulator qualified preview. Link exactly one build:
`--no-default-features --features client` or `--no-default-features --features relay`.
Both expose ABI 1 in `include/gcoms_mobile.h`. The client excludes relay hosting,
NAT mapping and relay queue storage. The relay embeds these facilities.

Use `scripts/build-mobile.py` for distributions. It selects only `cdylib` on
Android or `staticlib` on Apple with `cargo rustc --lib --crate-type`, enabling
release LTO. The manifest's default rlib is for Rust tests and fixture hosts.
Apple archives retain the external symbols needed by the application linker.

One current-thread Tokio runtime runs on one owned background thread per session.
Up to 8 sessions and 16 outstanding tickets per session are allowed. Request JSON
is capped at 1100 KiB and response JSON at 2 MiB. Results are copied into caller-owned
buffers; no Rust allocation is freed by foreign code. File requests reuse the
validated 256 KiB piece API. The host application owns its source and destination
streams and must never load a complete file just to cross this interface.

Requests carry an `op` field; see `src/command.rs` for the versioned command set.
Replies contain either `ok` or `error`. Byte arrays use JSON integer arrays.
Polling inbox results does not acknowledge them: commit the exact sequence/digest
only after application effects are durable. Peers must be explicitly authenticated
and trusted. Events are transient and bounded; use snapshots/inbox to reconcile.

`suspend` closes all protocol workers and releases profile/cache locks. Resume with
a new `open` request and a secret from the application's platform unlock provider.
Use an OS-private absolute profile path. Production selects GC/2 explicitly; fixture
mode is rejected unless the separate non-release `fixtures` feature is compiled.

Cancellation skips queued work and releases results. Already-running mutations
finish before the next command, preserving runtime durability. It does not roll
back a send: reconcile state before retrying. Destroy joins graceful shutdown and
must run off the UI thread. Panics are contained at the ABI/operation boundaries;
memory allocation failure or a caller supplying invalid pointers remains a process
failure. A native panic poisons the session until destruction.

JNI 0.21.1 is an Android-only dependency for the thin Kotlin bridge. The native
worker uses the existing Tokio, serde, zeroize and futures-util ecosystem.
