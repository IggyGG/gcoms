# Windows and mobile integrations

In progress (2026-09-21, Codex). The outbound-only Rust backend, minimal mobile
C ABI, Kotlin/Swift client and relay packages, and optional app-operated APNs/FCM
hint gateway are implemented. Acceptance remains an emulator/simulator preview
with simulated providers; physical-device, battery and live push work is deferred.

Current qualification:

- Linux, macOS ARM64/Intel and Windows x64 native tests and 3/s/z size gates pass
  at b39199e. All executable/source hashes are verified; maximum growth is 2.24%.
  Current records are in `docs/evidence/rust-integrations-mobile-20260921/`.
- All four Android base/push roles pass 16 KiB emulator instrumentation. SDK AAR,
  POM/module dependencies, APK alignment and installed deltas are verified.
- Both base Swift roles passed simulator tests. Both push roles now also pass,
  including profile-secret and push-state Keychain reopen in an ad-hoc signed host.
- Full Rust workspace: 910 passed, seven explicit ignores; strict Clippy,
  documentation, minimal features and packaged Rust/npm consumers pass.
  GChat f7a83ce against GComs b39199e passes 137 tests and strict Clippy.
- Size inspection found that producing an rlib alongside foreign libraries
  disabled LTO. Production now selects only the OS library type. The Android
  client probe falls from 10.17 to 7.36 MB on ARM64 and 11.97 to 8.80 MB on x86_64.
  Apple release measurements now strip symbols and select the active simulator
  architecture. Final mobile measurements are being repeated for these changes.

Retained pre-LTO records are explicitly marked as superseded under
`docs/evidence/mobile-preview-20260921/`. Final baselines and the mobile CI size
gate will be committed after all corrected distributions are verified.

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
