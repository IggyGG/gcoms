# Rust integration qualification

- Compile independent `ipc,files` and `embedded,files,gc2-carrier` consumers.
  Reject host/crypto/MLS/RPC dependencies in the IPC graph and forced Tokio
  multithread runtimes in either integration.
- Run SDK version/capability tests and facade backend tests, including encrypted
  cache reopen, bounded upload/export, forbidden scope and destination overwrite.
- Verify a disconnected local probe cannot stop the listener; macOS peer PID
  lookup can fail after disconnect, and only that connection must be rejected.
- Retain runtime durability/shutdown/GC2 bootstrap tests extracted from GChat.
  Verify file receive progress while outbound receipts are stalled.
- Run existing swarm corruption, quota, resumability and membership tests.
- Test GChat against this exact source pair, preserve archive/cache fixtures, run
  formatting, lint, package-consumer and generated-contract gates.
- Measure stripped consumer executables for opt-level 3/s/z with LTO, one codegen
  unit and unwind. Record the host separately from IPC consumer bytes.
- Execute integration tests and size checks natively on Linux x86_64 and macOS
  arm64/x86_64. Cross compilation alone is not native qualification.

Linux results are recorded in [the integration report](docs/RUST_INTEGRATIONS.md).
The full workspace passed 900 cases before the cache-only follow-up; the affected
suites passed 105 after it. GChat passed 137 Rust tests, 22 frontend tests,
generated contracts and the packaged desktop check. Native macOS jobs remain
pending. Retain per-platform source and binary hashes before marking them passed.
