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
interactive cover opportunities are independently uniform 10–10,000 ms. A cover
record is skipped if that writer sent real data since the previous opportunity;
the next random interval still starts on schedule. GChat selects
new authenticated profile 46, preserving old profile meanings. This removes
intentional cover-slot waiting, not congestion or route setup. Timing/activity
privacy is reduced and unqualified. Extra bursts remain deferred. See
[traffic policy](docs/GC2_TRAFFIC_PROFILES.md) for costs, migration and limitations.
Current validation must prove immediate data/EOF, bounded cover and no catch-up
burst, cover suppression after sent data and idle resumption, old-profile compatibility, durable profile
selection, class isolation and real application delivery/recovery. R02/R03/R04
remain open until source-bound application measurements pass; prior slow/failed
runs remain failures. No deployed or installed behavior is claimed by source edits.

# Ten simultaneous application senders

Run `gchat-turnover.py --mode multi-party` with the source-bound production
application host and six protected relay fixtures in disconnected namespaces.
Ten real GChat clients join one channel, then each submits one unique message
simultaneously in each of two rounds. Require all nine other clients to retain
exactly one matching message ID and the sender to report authenticated delivery.
Missing recipients, duplicate IDs, changed authorship and local-only acceptance
must fail the checker. Record individual action-to-observation latency; the
180-second round correctness budget does not waive the five-second requirement.
Setup has one 1200-second deadline and the worker has an 1800-second outer bound.

[Controller checks](docs/evidence/ten-client-controller-20260925/summary.json)
passed 21 tests. The actual application result is separate. This covers ten app
senders; it does not replace the separate ten-forwarding-participant requirement.
No current production profile, cover policy or device state changes.

# Published carrier completion without retry-tick delay

Run `gc2::owner::completion_tests` plus the full routing package and Node GC/2
regressions. The real TLS/mux fixture holds Tokio time at completion: a long-lived
publication must immediately replace only itself; short-lived and unpublished
failures remain paced, unrelated failed guards stay on their original clock, and
readiness revision changes only with actual publication/removal.
[Source-bound affected-package pass](docs/evidence/owner-completion-20260924/summary.json)
retains the original failing implementation and unchanged candidate hashes.

Then run `scripts/gchat-turnover.py --mode entry-loss --file-bytes 67108864` in the
isolated cluster with the exact built app/host. Require both old drivers to end
from the recorded reset, two new ready drivers, unchanged identity, ACKs, continuing
verified file bytes, export hash and reopen. Record the complete recovery duration
against R03's 10-second target; a correctness pass does not waive that ceiling.
Candidate16 passed correctness with 0–1 ms replacement starts but 38.638 seconds
for application recovery: R03 still fails. The [terminal receipt](docs/evidence/reliability-entry-loss-20260925/summary.json)
also records 53.872-second joining and all four authenticated ACK timings.

# Official frozen native baseline

Use the unchanged `scripts/ci.py` entrypoint, with its pinned toolchain and isolated
Python dependencies. The `580ce8a` pass and original environment failure are bound
in [the native receipt](docs/evidence/reliability-native-20260924/summary.json).
Later runtime changes need their own source-bound validation.

# Interrupted full-size file correctness

`gchat-turnover.py --mode file-recovery --file-bytes 1073741824
--file-completion-seconds 2400` verifies retained partial bytes after SIGKILL,
concurrent authenticated chat, complete export hash and same-identity reopening.
The deadline is declared before the run and late completion fails. Keep historical
1200-second failures separate; this mode does not qualify throughput or latency.
[Candidate14 pass](docs/evidence/reliability-file-recovery-20260924/summary.json).

# Real carrier-cap application evidence

Use `scripts/gchat-turnover.py --mode carrier-cap` with source-bound application
and qualification-host binaries in disconnected cluster namespaces. Require two
actual elapsed 1800-second driver completions per client, authenticated authority
fresh beyond each cap, both-class recovery, admitted chat ACKs, a file spanning
the cap, exact export and same-identity reopen. Retain recovery timing separately:
the candidate12 correctness pass took 56.449 s and does not meet the 10 s target.
[Receipt](docs/evidence/reliability-carrier-cap-20260924/summary.json).

# Protected-route failure context

Run the routing and transport packages and strict all-target/all-feature Clippy
on the frozen diagnostic candidate. Preserve pin rejection, circuit cancellation,
capacity, lifecycle and five-hop integration checks. Error strings gain static
stage context only; no peer identifiers or capabilities. The real Android resume
failure must be observed separately, with the original profile and pending ID.

# GC/2 admission refusal diagnostics

Run node library tests and strict all-feature/all-target node Clippy on the
frozen candidate. Existing GC/2 queue/service tests must retain admission,
replay, shared-capacity and class behavior. Confirm local diagnostic labels are
static and contain no queue, token, address or payload. Actual device evidence
must distinguish relay admission from recipient acknowledgment.

# Consumed owner budget on routed reopen

Run routed_reopen_preserves_expired_owner_without_publishing_consumed_budget in
the node library. Exercise the real outbound constructor on fresh and consumed
sealed budgets while public lease timestamps remain future. Require retained
owner authority and channel membership, no expired public aliases, a committed
snapshot with no deadline increase, and no uncertain-persistence pause. The
non-routed validation control must still reject expired authority. Preserve the
original exact-error red result. Run the node library and strict Clippy before
actual laptop/profile recovery and Android installation.

# Authenticated incomplete-referral retry

`renewed_guard_retries_incomplete_referrals_before_normal_discovery_period` serves
an authenticated own-only GCD2 reply, makes four independent fresh referrals
available afterward and never manually wakes the owner. Require discovery within
75 seconds, no retry before the existing 60-second backoff, exactly two requests,
unchanged guards and a complete five-hop candidate. Preserve the failing original
implementation. Run routing package tests and strict all-target/all-feature Clippy;
existing failed-dial, request-independent scheduling and cancellation tests remain.

# First checkpoint failure diagnostics

Keep the accepted-owner-renewal and failed-promotion rollback fixtures, including
failure after a sink sees the candidate bytes. New local logs distinguish encoding
from sink failures and identify the first branch that pauses the owner. No new
network request, retry, authority change or persistence success follows from
logging. Check the affected node failure cases and strict node Clippy on frozen
cluster inputs. Physical Android reproduction must retain the original generic
failure and the first underlying error separately.

# Inbox installation with a stalled peer

`installed_inbox_does_not_wait_for_peer_update_delivery` accepts both queue
creations over pinned TLS, checks the replacement and encrypted peer updates in
the committed snapshot, then holds a peer-update response open. Installation must
complete independently. The ordinary maintenance owner must retry the retained
wire when due; cancellation must retain it and never emit application delivery.
Run the node library and strict node all-target/all-feature Clippy in the cluster.
Keep the original failing implementation as the negative control. Physical
Android recovery, bidirectional ACKs, file resume and notifications remain separate.

# Concurrent manual admissions and delayed Welcome

Keep the eight-task fixture's channel/direct load, <500ms current-info bound and
successful task drain. Order manual admit plus member join as one fixture cycle;
require Active membership after every cycle so the final90s timeout cannot pass
silently. Bound preparation failure. Separately hold a Welcome until the next
admission reports MembershipPending, verify responsive commands, then join and
require bounded Active recovery with no retry or swallowed error.

Initial main `0c22dee` passed both cases and strict node Clippy. Final release
`7eec615` additionally includes the30s preparation guard; both cases, all seven
routing-profile cases, strict node Clippy/source/import/fmt/diff passed unchanged.
Its test bytes equal main `ff3025c`. Windows17 remains failed; its complete GChat
native pass is not relabeled for the successor. [Receipts](docs/evidence/windows-concurrency-fixture-20260921/summary.json).

# Windows persisted routing profile fixtures

Use the shared owner-only filesystem helper for pre-created temporary roots on
Windows and Unix. Keep startup/reopen/wrong-seed assertions, plus an existing
nonprivate-directory case that must fail without rewriting permissions or creating
routing material. Production permission checks must remain strict.

Both `77e756e` (unified branch) and `115f31b` (bounded Windows release input)
passed seven profile cases, four routing-cache cases, two private-fs cases and
strict all-target/all-feature node Clippy locally, with unchanged source snapshots.
Source/import checks, formatting and diff checks passed. Windows16's complete
GChat pass and original GComs failure remain separate; the next exact Windows
pair must produce fresh native and installer receipts.
[Evidence](docs/evidence/windows-routing-profile-20260921/summary.json).

# Client bootstrap API follow-up

Test the trusted client bundle API through the Node command loop: fresh carrier
seeds install, malformed/mixed-expired bundles leave the directory unchanged,
relay advertisement seeds are untouched, and non-GC/2 nodes refuse installation.
The deployed-relay probe requires explicit `--ignored` plus independently authorized
live provisioning; it is excluded from ordinary local/native CI.

Completed on `1decc33`: four local tests passed; the live probe was reported ignored
without execution. No-host client compilation, all-target/all-feature node Clippy,
formatting, source/provenance and diff checks passed on unchanged frozen sources.
[Exact receipt](docs/evidence/client-bootstrap-release-integration-20260921/summary.json).

# Combined SDK and release-branch boundary

Validate the exact combined source with application feature variants, the outbound
client/relay separation and mobile client/relay graphs, minimal core/SDK checks,
strict affected-package Clippy, Python/source/import checks and the current GChat
consumer. Preserve channel-management, IPC19 and Windows owner-only DACL repairs.
Existing native SDK size baselines and published GChat binaries retain their own
source bindings; a combined build is not covered by those older receipts. Live
push, physical-device testing and app-store distribution remain separate scopes.

Completed on `e3874a0` / GChat `2081526`: application/runtime/SDK 103 passed
(one namespace exclusion), node library 315 passed (one low-port exclusion), six
mobile ABI cases across four role/push variants, GChat 143 passed (two namespace
exclusions), 169 Python and nine gateway simulations. Minimal and independent
consumer checks, eight Android/iOS dependency graphs, both strict Clippy gates,
formatting, source and amended research-import checks passed.
[Exact sources, logs and scope](docs/evidence/sdk-release-integration-20260921/summary.json).

# Rust integration qualification

The native backend and size matrix passes on Windows x64 MSVC and Linux/macOS
at b39199e. All Android/iOS base/push preview distributions and final size gates
pass; [exact mobile evidence](docs/evidence/mobile-preview-lto-20260921/) records
the qualified revisions and toolchains. The private temporary-root helper
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
  Build only `cdylib` (Android) or `staticlib` (Apple) per compiler invocation;
  emitting an rlib alongside them disables LTO. Record the selected crate type.
  Strip Apple archive debug/local symbols while preserving linker externals,
  and measure postprocessed release apps for only the active simulator CPU.
  Ad-hoc sign the disposable Swift simulator host with its own Keychain access
  group; require profile-secret and push-state reopen through fresh providers.
  Mint client fixture credentials after consumer compilation. Keep production
  grant expiry unchanged; slow Xcode/Gradle builds must not age the test grant.
  Generate SDK and optional FCM POM/module metadata with `gcomsPublishRole` set
  to the tested role and verify that the FCM dependency names that role's SDK.
  Check APK ZIP offsets as well as ELF alignment: each native entry must be
  uncompressed and aligned to 16 KiB so installed APK bytes include native code.
  Validate LOAD and RELRO boundaries for every packaged native dependency.
  Require the optional push adapter to exercise DataStore native counter writes
  and reads on the 16 KiB emulator; its runtime dependency is DataStore 1.2.1.
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
# Reapplying retained owner roles

`owner_recovery_replaces_retained_roles_without_duplicate_queues` restores a
complete owner record twice into populated state through the durable lifecycle
transaction. Require one copy of every retained queue, unchanged authority and
origins, no deadline extension, successful archive decoding and no owner pause.
Preserve the original duplicate-queue failure, run the full node library and
strict node Clippy, then verify the retained Android profile and partial download.
