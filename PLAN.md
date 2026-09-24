# Android first checkpoint failure, 2026-09-24

Physical Android 1015 reached the sticky `owner lifecycle persistence outcome is
unconfirmed` state during the recovery follow-up. Later periodic-save messages
hide the originating error. Capture the bounded first encoding/storage/lifecycle
error and static caller location in local native logs. This diagnostic change
preserves the exact failure classification, rollback, durable barriers and
scheduler shutdown; it does not repair or waive the underlying failure. The
last confirmed profile is reopened by restarting the app without clearing data.
Cluster workload reproduction and focused checkpoint-failure checks are ongoing.
Cluster validation passed on frozen `b6188f7`: 333 node library tests, two existing
exclusions, strict all-target/all-feature node Clippy and all 692 source bindings
unchanged. [Receipt](docs/evidence/checkpoint-diagnostics-20260924/summary.json).
Android 1016 is building separately; no underlying repair or device pass claimed.
`codematch=unreachable` in this environment.

# Inbox installation recovery, 2026-09-23

Fleet-files owns the Android recovery follow-up. A targeted authenticated fixture
reproduced installation waiting on peer notification after both queues and the
replacement checkpoint committed. The candidate leaves exact peer updates to the
existing bounded durable retry owner. Exact candidate `15be948` passed 333 node tests (two existing exclusions) and
strict all-target/all-feature node Clippy in the cluster. The same final test
fails against the original implementation after its peer request reaches the
held TLS response. All 691 source bindings stayed unchanged. Physical Android
verification remains open; Android 1015 is building on `15be948` / `48ccdfb`.
No phone-delivery or full-rollout pass is claimed.
[Receipt](docs/evidence/inbox-install-20260923/summary.json).

# Windows concurrent membership fixture

Windows17 again passed GChat native CI, then failed the GComs command-loop load
fixture when a later admission found a prior membership change still awaiting
ACKs. Its exact cause is not established by that log. The test now orders each
manual admission through the caller's Welcome application while retaining all
eight tasks, channel/direct load, fast current-info queries and successful drain.
Every admission must return to Active. A separate gated delayed-Welcome case
proves that genuinely pending membership can recover while other commands remain
responsive. No production behavior, error handling or convergence deadline changed.
The final bounded Windows source is `7eec615`; local tests/Clippy passed, native
retry remains pending. [Evidence](docs/evidence/windows-concurrency-fixture-20260921/summary.json).

# Windows routing fixture correction

Windows16 passed the full GChat native entrypoint but stopped in two GComs
profile tests: the fixtures made their pre-existing temporary routing directories
private only on Unix. The strict Windows ownership check correctly refused them.
`77e756e` makes both fixtures private using the cross-platform helper and verifies
that an existing nonprivate directory is still rejected without repair. No
production ACL or routing-store behavior changes. The bounded Windows retry uses
`115f31b`, only this test change atop its original `9f8b483` input; the unified
SDK branch retains the same fix separately. Both local snapshots passed affected
tests and strict node Clippy. Native Windows retry/installer results remain pending.
[Exact failure and local checks](docs/evidence/windows-routing-profile-20260921/summary.json).

# Concurrent bootstrap integration

The subsequent `a5c3b6b` main-line change adds trusted client-side GC/2 bundle
installation without publishing those seeds through the relay service. The merge
preserves the completed SDK/release fixes. Exact merged source `1decc33` passed
four local helper/Node API cases, no-host compilation and strict node Clippy,
with unchanged sources. The deployed-relay provisioning probe is retained as
explicitly ignored opt-in work; its default exclusion was verified without running
it. [Focused evidence](docs/evidence/client-bootstrap-release-integration-20260921/summary.json).

# GChat release integration follow-up

The 2026-09-21 fleet integration combines SDK handoff `4fd466b` with the
release branch's Windows owner-only file permissions, transport timing and Python
portability fixes, authenticated channel management and research-import provenance.
The only source conflict uses the SDK's directly boxed application-start future;
existing awaiting callers and bounded startup remain intact. Combined source
`e3874a0` passed the application/runtime/SDK and node suites, mobile ABI and feature
graphs, strict affected Clippy and GChat `2081526` consumer tests/Clippy. Both frozen
sources remained unchanged. The [bounded receipt](docs/evidence/sdk-release-integration-20260921/summary.json)
retains exact counts and exclusions. This does not replace earlier native artifact
receipts or enable live push in GChat.

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
