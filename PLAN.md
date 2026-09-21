# Windows and mobile integrations

Completed the emulator/simulator preview on 2026-09-21. The outbound-only Rust
backend, minimal C ABI, Kotlin/Swift client and relay packages, and optional
app-operated APNs/FCM hint adapters are implemented and qualified. Physical-device,
battery and live-provider qualification remains outside this accepted scope.

- Linux, macOS ARM64/Intel and Windows x64 native tests and 3/s/z size gates pass
  at b39199e. All executable/source hashes are verified; maximum growth is 2.24%.
- All four Android base/push roles pass 16 KiB emulator instrumentation.
  Release AARs, POM/module dependencies, APK alignment and installed deltas pass.
- All four Swift base/push roles pass simulator tests, including secure profile
  reopen and push-state Keychain persistence in ad-hoc signed test hosts.
- Production libraries cover both Android ABIs and all three Apple architectures.
  Full LTO is active; z minimizes Android libraries and linked Apple samples
  across 3/s/z. App additions are measured for
  installed emulators/simulators and built ARM64 samples. Mobile CI enforces a
  separate 5% same-toolchain size baseline for each platform, role and push option.
- Full Rust workspace: 910 passed, seven explicit ignores; strict Clippy,
  documentation, minimal features and packaged Rust/npm consumers pass.
  GChat f7a83ce against GComs b39199e passes 137 tests and strict Clippy.
- Client fixtures compile before provisioning their five-minute relay card.
  Production grant expiry is unchanged. Android explicitly selects the qualified
  NDK 27.3.13750724 and DataStore 1.2.1. Every packaged native library passes LOAD,
  RELRO and ZIP alignment checks; both push roles exercise the native counter.

[Desktop evidence](docs/evidence/rust-integrations-mobile-20260921/),
[mobile qualification and final baselines](docs/evidence/mobile-preview-lto-20260921/),
and [combined workspace/GChat checks](docs/evidence/mobile-preview-20260921/combined-checks.json)
retain exact source revisions and artifact/report hashes. Pre-LTO mobile records
are historical evidence; they are excluded from final size comparisons.

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
