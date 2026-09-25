## Responsive application result, 2026-09-25

[Candidate19 application/build receipts](docs/evidence/responsive-carrier-20260925/application.json):
all ten actual GChat clients joined over six protected relays. Two rounds of ten
simultaneous sends produced 180 verified remote deliveries with exact IDs and
authenticated sender ACKs. Conservative action-to-observation times were
0.531–0.840 seconds: R02 passes in this scope. One join took 33.461 seconds, so
R04 still fails; other joins were 0.202–26.770 seconds. No production, installed,
mobile, hourly-turnover or ten-forwarding-participant claim follows. All child
processes/namespaces stopped; host links, binaries and tooling unchanged.

The initial namespace launch failed before clients started because this new pod
lacked ethtool. Its failure and cleanup remain retained. The retry used identical
binaries after installing that utility; 309 retained file hashes and 54 exported
evidence files were verified. The paired optimized build has 16 verified evidence
files. Further work: diagnose the remaining join/recovery waits and qualify the
staged compatible relay/client rollout; do not weaken deadline verdicts.

Validated responsive-carrier implementation: [source-bound receipt](docs/evidence/responsive-carrier-20260925/summary.json)
records 90 routing tests, 350 Node tests (two exclusions) on a fresh-credential
rerun, one protected channel/file/renewal integration, 31 runtime tests (one
exclusion), strict affected-package Clippy, formatting and 58 Python checks.
The original node run crossing the UTC hour failed five static-introduction
cases; it remains failed. Fresh replay passed unchanged source and does not
qualify hourly recovery. The separately bound application run is summarized below.

## Immediate sending and randomized cover, 2026-09-25

Owner-approved policy: real traffic sends when transport capacity is available;
interactive cover gaps are independently uniform 10–10,000 ms. GChat selects
new authenticated profile 46, preserving old profile meanings. This removes
intentional cover-slot waiting, not congestion or route setup. Timing/activity
privacy is reduced and unqualified. Extra bursts remain deferred. See
[traffic policy](docs/GC2_TRAFFIC_PROFILES.md) for costs, migration and limitations.
Current validation must prove immediate data/EOF, bounded cover and no catch-up
burst, continued cover under data, old-profile compatibility, durable profile
selection, class isolation and real application delivery/recovery. R02/R03/R04
remain open until source-bound application measurements pass; prior slow/failed
runs remain failures. No deployed or installed behavior is claimed by source edits.

# Larger-channel invitation reply repair, 2026-09-25

The ten-client actual GChat run stopped at the sixth join: its MLS Welcome
exceeded the unchanged 12,217-byte direct-record limit. Five clients had joined;
concurrent message rounds did not run. The [red receipt](docs/evidence/ten-client-application-red-20260925/summary.json)
retains exact binaries, timing, logs and clean teardown.

A separate red regression proves invitation ACK IDs did not match their retry
outbox keys. The candidate uses the encoded logical receipt ID, rejects pending
ID collisions, and carries larger Welcomes in bounded authenticated control
chunks. Small replies stay compatible; no packet, authority or cover limit is
relaxed. Owner-bound reassembly requires the complete digest and successful receive
persistence. Sender reopen retains exact retry bytes and wire. The protocol and
node checks/strict Clippy pass with [separate source-bound scopes](docs/evidence/invitation-reply-20260925/summary.json).
The final extra checks fixed missing imports/std-only RNG in existing minimal-feature
fixtures only; their original compilation failure remains retained.

[Transport contract](docs/CHANNEL_INVITE_TRANSPORT.md). Actual ten-client
qualification on the repaired source is next. Production rollout and latency
requirements remain open; the traffic-policy decision remains pending.

# Actual application connection-loss result, 2026-09-25

Candidate16 replaced both established entry connections within 0–1 ms after a
controlled reset in the disconnected cluster. Actual GChat core/service chat
recovered, the 64 MiB in-flight file exported with its expected SHA-256, and
reopening retained the same identity and complete file. All child processes and
namespaces were removed. The retained 652-file inventory and 38 exported evidence
files were verified. [Application receipt](docs/evidence/reliability-entry-loss-20260925/summary.json)
and [exact binary/source build receipt](docs/evidence/reliability-entry-loss-20260925/build.json).

The complete recovery still took 38.638 seconds, joining took 53.872 seconds, and
some authenticated ACKs exceeded five seconds. R02/R03/R04 remain failed. This
closes the proven owner retry-tick delay, not all protected-route setup latency.
Current fixed cover policy is unchanged; its performance/privacy tradeoff awaits
the user's decision before changing that policy. Physical-device checks remain
deferred; simulator/emulator network journeys and final release checks remain.
No installed release, credential expiry, carrier-cap or privacy claim is made by
this transport-reset run. Earlier receipts keep their original source bindings.

# Established carrier replacement, 2026-09-24

A real carrier-cap application log showed 29.982 seconds between driver completion
and replacement. A paused-clock real-TLS/mux regression reproduces that owner delay
(red: one failure, one pacing control pass). The candidate permits only the same
retained guard to replace a carrier after at least 30 seconds of published readiness.
It preserves authority validation, entry limits, unrelated failed dials and the
normal timer. Both focused tests, all 86 routing package tests, 49 selected Node GC/2 tests
(one explicit exclusion), strict routing/Node Clippy and workspace formatting pass
on unchanged source. [Receipt](docs/evidence/owner-completion-20260924/summary.json).
Actual application transport-loss validation passed correctness; R03 remains failed.
The test-only `entry-loss` controller keeps relays/authority alive while resetting
only the isolated client's fixture relay sockets; it requires old driver endings,
new publications, both-class recovery, authenticated chat, resumed file hash and
reopen. Controller regressions pass 20/20. `codematch=unreachable`.

# Official GComs native gate, 2026-09-24

Frozen `580ce8a` passed the official Linux `scripts/ci.py`: 990 Rust passes,
zero failures, nine explicit exclusions; 190 Python tests; docs, strict workspace
Clippy, frontend, generated contracts/vectors, minimal checks, 21 package archives
and consumers, and dependency policy. All 722 source bindings were unchanged.
The original missing-NumPy environment failure is retained; the successful retry
uses a private versioned virtual environment, without changing candidate source.
[Receipt](docs/evidence/reliability-native-20260924/summary.json).
This does not qualify later owner-completion work, paired GChat native, installed
release, mobile networking, or the still-failed latency targets.

# One GiB interrupted application transfer, 2026-09-24

Candidate14 completed the actual GChat core/service five-hop file recovery case.
The receiver was killed with 107,741,184 verified bytes; reopening retained the
exact piece count and identity. Chat remained usable during resumed bulk transfer.
The full 1,073,741,824-byte export matched its expected SHA-256, including after
another reopen. All processes/namespaces were removed; 8,333 retained evidence
files were verified. The predeclared 2400-second completion budget is correctness
coverage, not a speed claim; the earlier 1200-second timeout remains failed.
[Receipt](docs/evidence/reliability-file-recovery-20260924/summary.json).
Native/mobile release, ten participants and latency requirements remain open.

# Real carrier lifetime application gate, 2026-09-24

The disconnected actual GChat core/service run reached the unchanged 1800-second
carrier cap with introductions still fresh. Both clients regained both classes,
a 256 MiB in-flight file exported with its exact hash, and reopening retained
identity and verified bytes. All child processes and namespaces were removed.
Recovery took 56.449 seconds, so R03 remains failed; this is no latency, installed,
privacy or consecutive credential-expiry qualification. Frozen candidate12
receipts remain separate from the later bounded-control runtime.
[Receipt](docs/evidence/reliability-carrier-cap-20260924/summary.json).

# Current completion plan, 2026-09-24

Implement the [reliability release requirements](docs/RELIABILITY_RELEASE.md):
batch independent failures in the cluster, repair the shared runtime, qualify
actual GChat/device journeys, then release. Neighbour-graph design follows that
release. Older entries below retain their historical input/result scope.

# Android resume: identify the failing protected-route stage, 2026-09-24

The original file completed with an exact export hash, but after the native Save
picker resumes the app, replacement inbox recovery repeatedly reports a bare TLS
EOF and message ACKs stall. Add stage context to existing error paths: middle
number, middle TLS/admission/target acknowledgment, and terminal TLS. Never log
addresses, pins, tokens or payloads. No routing selection, retry, deadline, admission
or authentication changes. Validate routing/transport in the cluster, then pair
Android 1019 with those exact sources for the existing-profile observation.
Cluster routing/transport passed 148 tests (four existing exclusions), strict
all-target/all-feature Clippy and changed-file formatting on 712 unchanged source
bindings. Whole-workspace formatting found unrelated existing node formatting
differences, retained in the receipt. Formatting-only a7dc754 resolves those two
files and passes full workspace formatting separately; Android 1019 remains
frozen on 3c7b628 and is still building.
[Receipt](docs/evidence/route-stage-20260924/summary.json). codematch=unreachable.

# Retained Android delivery: bounded relay admission diagnostics, 2026-09-24

Android 1018 no longer reproduces the duplicate owner-role checkpoint pause,
and the original file has now completed with a matching hash. Earlier sender attempts received
GC/2 overload replies. Distinguish queue fullness, aggregate storage and replay
capacity in the existing optional local metrics sink. Preserve every wire reply,
authentication check, limit and replay deadline; record no routing identifiers.
Cluster validation passed: 335 node library tests, real queue/service tests, strict Clippy and the production relay build on unchanged source. The diagnostics candidate remains **not deployed**; the original Android file completed without a relay update. [Receipt](docs/evidence/queue-admission-20260924/summary.json). Subsequent device ACK recovery remains unqualified. codematch=unreachable.

# Reopen after an owner-role deadline, 2026-09-24

The original laptop reports "active owner alias expired before publication".
A real outbound constructor regression reproduces that error with an authenticated
saved owner budget already consumed while its public lease timestamp remains fresh.
Filter public owner addresses by the effective sealed deadline, keeping the exact
private record and membership available for normal background recovery. Do not
extend leases, discard identity, bypass durable writes or weaken legacy startup.
The fresh-budget control still publishes its addresses; expired routed startup
must retain its archive without publishing those addresses. Exact candidate
296d3b6 passed 334 node tests (two existing exclusions), strict all-target/all-feature
Clippy and 696 unchanged source bindings. The original constructor failed with
the reported error. [Receipt](docs/evidence/owner-reopen-20260924/summary.json).
Actual laptop recovery and Android 1017 remain pending. codematch=unreachable.

# Incomplete referral recovery, 2026-09-24

The actual file/reopen continuation observed a temporary loss of usable five-hop
routes across an hourly boundary while two entries remained ready. A targeted
pinned-TLS discovery test independently reproduced a scheduling defect: an own-only
successful refresh deferred available middle referrals for five minutes. Its
75-second red result is retained. Candidate background discovery uses the existing
60/120/240/300-second failure backoff until five independent fresh relay addresses
are available. Application traffic cannot trigger it; guard selection, entry retry
pacing, authority deadlines, route length and circuit limits are unchanged.
Exact candidate 7cb83b4 passed all 82 routing package tests (zero failures or
ignores), strict all-target/all-feature routing Clippy and 694 unchanged source
bindings. The original implementation failed the new assertion after 75.05s.
[Receipt](docs/evidence/referral-recovery-20260924/summary.json). Actual application
validation is next. This does not claim that the missing historical reply contents or Android's separate
uncertain-checkpoint cause have been established. `codematch=unreachable`.

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
# Retained owner roles during live recovery, 2026-09-24

Android 1017 captured the first checkpoint error: invalid owner alias binding or
duplicate queue. Live recovery reapplied a complete saved record by appending
draining roles already present in memory. The new regression reproduces that exact
failure. Replace the nonactive role collections from the complete retained record;
keep the original authority, deadlines, duplicate rejection and failure rollback.
Exact b9a8702 passed 335 node tests (two existing exclusions), strict all-target/
all-feature Clippy and formatting; all 697 committed source files match the
tested snapshot. The original exact-error regression is retained, as is an initial
stale-build-cache comparison that is excluded from qualification.
[Receipt](docs/evidence/owner-role-recovery-20260924/summary.json).
Android 1018 and paired application validation are running; device recovery remains open.
`codematch=unreachable`.

### Ten-client application follow-up, 2026-09-25

Candidate `28b24ca` / `8b7b9c5` built and passed fixture-host strict Clippy.
Eight actual GChat clients joined; clients six through eight assembled the new
bounded Welcome records, clearing the old packet-size failure. The ninth join
failed its unchanged 120-second application deadline while the owner still awaited
existing-member membership ACKs; concurrent sends were not reached. All seven
completed joins exceeded R04 (45.84–100.98 seconds). No ACK requirement, traffic
policy, or deadline was relaxed. Offline inspection of a copied encrypted fixture
confirmed `runtime: invite join deadline elapsed`; original state stayed unchanged
and both namespaces were torn down. See
`docs/evidence/ten-client-application-20260925/summary.json`. Remaining: membership
convergence latency, ten-client delivery, final mobile network and release gates.
Physical devices remain deferred; the traffic-pacing product choice is pending.

Offline follow-up decoded copies of all ten candidate17 fixture profiles. The
owner retained epoch8 and six of seven required ACKs; participant3 remained at
epoch7 and logged no arrival of the exact missing commit. Applying that retained
wire to a decoded copy advanced it to epoch8; its resulting ACK authenticated as
the expected member at the owner. No network retry or crypto-state reset was
performed. Original encrypted files stayed unchanged and temporary decrypted
copies were removed. The first diagnostic compile failure is retained separately.
See `docs/evidence/ten-client-application-20260925/membership-inspection.json`.
