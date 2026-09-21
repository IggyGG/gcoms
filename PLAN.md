# Windows and mobile integrations

In progress (2026-09-21, Codex): native Windows x64 qualification; an outbound
network-client backend with relay hosting compiled out; minimal Kotlin/Swift
client and relay packages; optional app-operated APNs/FCM gateway. Mobile
acceptance uses Android emulator/iOS simulator and simulated push providers.
Physical-device, battery and live push qualification remain deferred.

Checkpoint: outbound messaging/channel/file/reopen integration passed on Linux,
along with 504 application/runtime/SDK/node/file tests (three explicit ignores).
The native mobile ABI and Kotlin sources compile; the relay ABI fixture verifies
channel/file operations and suspend/reopen. Android relay instrumentation passes
on the API 35 16 KiB emulator. Windows x64, Linux x64 and macOS ARM64 native CI
passed at e75c72c, including macOS Intel. Mobile CI now builds separate
client/relay AARs and XCFrameworks and records linked/installed sample deltas.
Swift execution remains in progress. The optional gateway's nine simulations and
four owner-binding/admission tests pass. The remote owner-binding integration
passes, along with strict Rust Clippy and Kotlin FCM adapter compilation/tests.
Swift adapters and final mobile size evidence remain in qualification.
Native Apple archives build for device and both simulator architectures. The
first mobile CI runs exposed simulator selection and Android RELRO alignment
issues; fixes retain the production three-profile measurements and use smaller
development fixtures for functional tests. Android client fixtures pass relay
configuration through test assets to avoid adb's command-length limit.
Both client instrumentation tests now pass on the 16 KiB emulator, including
channel/invitation creation, file import/export and profile reopen. GChat's
unoptimized journey exposed startup stack pressure during identity restoration;
boxing the application's startup future fixes the journey on the default stack.
The full workspace and current-source GChat gates are being repeated.

Implementation order: Windows native gate, Rust role separation, mobile ABI and
packages, push registration/relay notifications, integrated qualification and
per-platform size evidence. Preserve the existing IPC and embedded consumers.

# Minimal Rust application integrations

Implemented the two explicit Rust variants on the current GComs trunk:
`ipc,files` for an existing host, and `embedded,files,gc2-carrier` for an in-process
protocol and relay. GChat consumes the shared runtime and file APIs while keeping
its network configuration, archives and cache key.

Completed on 2026-09-20:

- Consolidated retained application/runtime work with current GC/2 and persistence.
- Made RPC and daemon launch optional, removed forced multithread scheduling, and
  selected the measured size profile while preserving unwind.
- Added streaming file operations, IPC18 capability/version checks, host-owned
  cache lifecycle, and regressions for reconnect, corruption and membership.
- Passed Linux workspace, focused follow-up, GChat, lint, documentation, generated
  contract and packaged consumer gates. Linux IPC is 851 KiB; embedded is 8.93 MiB.

[Evidence and exact inputs](docs/RUST_INTEGRATIONS.md). Native macOS arm64/x86_64
qualification is complete: 106 focused tests passed on each target, and the
CI matrix measured both consumers at opt-level 3/s/z. The macOS disconnected-peer
listener regression is fixed and covered on every target.

The subsequent concurrent crypto merge was preserved and validated with 157
combined Linux tests and strict Clippy; the native size record retains its exact
measured revision.
