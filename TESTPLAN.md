# Rust integration qualification

Windows/mobile follow-up (in progress): run the native backend and size matrix
on Windows x64 MSVC as well as Linux/macOS. The private temporary-root helper
must preserve current-user ownership and remove inherited Windows grants.
Qualify outbound-only runtime behavior, mobile ABI cancellation/lifecycle,
Android emulator/iOS simulator consumers and simulated APNs/FCM providers.
Measure the base SDK and optional push adapter independently. These additions
do not establish physical-device or live-provider qualification.

- Run `cargo test -p gcoms-node --all-features --lib notification` for binding
  authorization, revisions, unbind/expiry/rotation/revocation, admission filtering,
  coalescing and bounded hint backpressure.
- Run `cargo test -p gcoms --all-features --test network_client` to exercise the
  remote administrative binding API alongside trusted messaging/channel/files.
- Run the Mobile SDK preview CI matrix for JNI/Swift execution, 16 KiB alignment,
  separate client/relay native graphs, 3/s/z measurements and sample app deltas.
  Verify both LOAD and GNU_RELRO alignment, compatible simulator selection, and
  the client through its separately hosted fixture relay. Development fixture
  sizes cannot establish production baselines.
  Generate SDK and optional FCM POM/module metadata with `gcomsPublishRole` set
  to the tested role and verify that the FCM dependency names that role's SDK.
  Check APK ZIP offsets as well as ELF alignment: each native entry must be
  uncompressed and aligned to 16 KiB so installed APK bytes include native code.
- Keep the public startup future below 16 KiB and run GChat's complete channel
  journey on the default thread stack, including restored post-quantum identity.
  Native desktop CI compares 3/s/z results with the committed platform baselines
  and rejects growth above 5% on the same Rust toolchain.

- Compile independent `ipc,files` and `embedded,files,gc2-carrier` consumers.
  Reject host/crypto/MLS/RPC dependencies in the IPC graph and forced Tokio
  multithread runtimes in either integration. Also check `network-client,files`
  without `relay-host`, SDK `embedded` or `quick-xml`. Exercise two outbound
  clients through remote inboxes, trusted delivery, channel joining, encrypted
  profile/cache reopen and refusal of local relay provisioning.
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
generated contracts and the packaged desktop check. The final native follow-up
passed 106 focused tests per target on Linux x86_64 and macOS arm64/x86_64,
including the disconnected-peer regression. Size checks passed for all three
optimization levels; downloaded binary and source hashes were independently verified.

After the concurrent crypto merge, the combined application/runtime/SDK/swarm/crypto
suites passed 157 Linux tests (two explicit ignores) and strict Clippy. Native results remain bound
to their recorded source revision.
