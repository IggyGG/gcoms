## Hosted removal and application permissions — IRC-3/IRC-5/IRC-6

`channel-service/tests/removal.rs` checks pending-rekey restart, kick confidentiality,
owner-offline and all-members-offline progress, same-identity rejoin, role reset,
retained bans and competing commits. MLS adversarial tests forge removals and stale
policy commits, unauthorized topics and false message classes. Verify the original
chat still decrypts after a rejected forged classification. Run full MLS/service
tests and strict Clippy; scale/network/GChat qualification remains separate.

## Ordered hosted policy — IRC-3

Run all-feature MLS and channel-service tests and strict all-target Clippy.
`tests/policy.rs` covers durable role/mode updates, independent +o/+v, bans and
exemptions, key rotation, invite exceptions, stale admission revision, ownership
transfer and admission by the new owner. Internal adversarial controls attempt
self-promotion, impersonation and consumption of another sender's ratchet.
Human-readable reasons must remain absent from the service log.

## Hosted admission and legacy isolation — IRC-1

Run `cargo test --locked -p gcoms-mls --all-features`, strict all-target/all-feature
MLS Clippy, formatting and the source check. Require actual PQ-hybrid external
joins while previous members process no traffic, followed by ordered commit
replay and encrypted bidirectional member traffic. Both an observer and a member
must reject a modified client's private join, expired proof, duplicate name and
replayed/stale epoch. Reject mismatched snapshots without advancing the observer.
Sealed restart must preserve pending acceptance, reject the wrong key/channel and
reject decoding as a legacy member archive. The public observer cannot process
application ciphertext. Test the old legacy receiver as a negative control:
the unauthorized external commit advances its epoch and roster; the fixed
receiver must reject it before merging. Keep the existing channel/persistence
regressions and the explicitly separate slow capacity gate.

These are source/component tests. They do not qualify service persistence,
GChat integration, 500 members, timing, native artifacts or installed releases.

## Ordered hosted storage — IRC-2

Run `cargo test --locked -p gcoms-channel-service -p gcoms-mls --all-features`
and strict all-target/all-feature Clippy for both packages. Require an offline
owner to replay joins/messages across service restart, exact retry receipts,
exclusive writer locking, full-record corruption refusal, partial-tail recovery,
quota refusal without mutation and a real failed write followed by poisoned
refusal and correct reopen. Verify application plaintext and test identity seeds
are absent from the service log. A forged outer sender must not consume the
correct MLS sender's ratchet. Genesis replay must remain valid with an expired
original KeyPackage lifetime; the un-updated negative control must fail.

Explicit MLS scale gate:
`cargo test --locked --release -p gcoms-mls --all-features --test hosted five_hundred_real_members_and_ten_concurrent_senders -- --ignored --nocapture`.
Require 500 distinct actual leaves, 499 membership changes, ten concurrent
senders, 4,990 authenticated receives, overflow rejection and retained duration /
wire-size measurements. Keep network/UI/ACK timing and file/churn qualification
separate; this component gate cannot close IRC-8 by itself.

## Reusable hosted admission codes — IRC-3

The MLS suite must import a protected reusable secret, admit private members
with the owner absent, refuse reuse of its public verifier as a secret, reject
wrong-code proofs and retry a concurrent refused join with the same leaf
identity. Accepted members cannot invoke the pending-join reset API. A code's
private serialization must not appear in public policy. Ordered key rotation
and revocation require separate policy-change regressions before being enabled.

## Bounded file recovery latency

Run `cargo test --locked -p gcoms-file-transfer` and
`cargo test --locked -p gcoms-runtime --all-features --lib`, followed by strict
all-target/all-feature Clippy for both packages and outbound-only facade compilation.
The reopened-cache regression must preserve verified pieces, immediately query a
new permitted source, reject unauthorized sources, avoid duplicate-query bursts,
respect four-source admission and preserve paused/unaccepted/cancelled intent.

The runtime's controlled transport model uses real encrypted pieces, a retained
first piece, 450 ms hop receipts, 16 MiB, the actual send-window bound and a declared
60-second recovery allowance within 180 seconds. Four sends fail that model; eight
complete in 147.75 simulated seconds with exact export bytes and unchanged payload /
pending-action bounds. This is a deterministic concurrency model, not a measurement
of installed Windows or real GC/2 paths. Keep delayed-receipt and locking/retry runtime
regressions, and require the real signed app's interrupted-transfer/reopen/hash gate
before publishing a Windows replacement. Preserve both original failed Windows runs.

## File transport profile writes

`cargo test -p gcoms-runtime --all-features --lib piece_transport_does_not_rewrite_profiles_or_require_wrapper_saves -- --nocapture`
uses two encrypted profiles and authenticated channel recipients. Sixteen exact
4 KiB piece records must request no outgoing wrapper or incoming event profile
saves. Block profile replacement: piece transport must still work, ordinary
private text must retain its save error, and shutdown must report failure while
the retained encrypted bytes remain unchanged. No text ACK may masquerade as file
completion. Keep the original-runtime red result and ordinary-barrier negative
control. Run the runtime suite, file cache crash/journal/resume/corruption tests,
strict Clippy and outbound-only compilation. This component test does not replace
the signed application's bounded interrupted-transfer/reopen/hash release gate.

[Source-bound checks and controls](docs/evidence/piece-profile-writes-20260928/summary.json): 32 runtime passes, 20 file-package passes, strict Clippy and outbound-only compilation.

## Windows named-pipe authentication ordering

Run the isolated native `local_pipe_diagnostic` workflow before broad release
builds. Cover a silent connection, canceled accept, disconnected probe, bounded
silent-peer expiry, a 256 KiB frame with every byte preserved, and reply writes.
Retain pinned server SID and owner-only ACL tests. The exact old local.rs must
fail the silent-peer regression; restore and hash every tracked source afterward.
Then require the actual Windows installed 16 MiB chat/file/reopen journey. Linux
success or an offline Windows profile lifecycle cannot substitute for that gate.

## Native external-probe exclusion inventory

Native CI records three additional explicit exclusions: the live deployed-relay
probe (requires a separately authorized fresh bundle), the external native
five-hop bootstrap probe, and the nested native TLS/HTTP2 probe. These require
separate provisioned artifacts and do not constitute desktop application coverage.
Accept only their exact GComs test names in receipt validation; reject unknown
names and using these exclusions in GChat reports. Keep failed native counts,
incomplete harnesses, source bindings and installer acceptance mandatory.
The Windows candidate's original verifier rejection remains retained. Its native
result is 1004 GComs passes / 9 explicit exclusions and 186 GChat passes / 1
namespace exclusion, not successful execution of the excluded tests.

## Ownership announcement before voluntary departure

Withhold the old owner's authenticated ACK after transferring ownership and
requesting leave. Require the epoch, original recipient route and exact pending
announcement to remain unchanged. Deliver the real MLS ACK; require reclamation,
removal and the successor's retained ownership. Removing the guard must fail the
epoch assertion. Also run the existing real GChat transfer/leave/new-admission
case, the complete node library, durable-removal regressions and strict Clippy.
Sequential and concurrent integration fixtures must retain the same prepared
package while retrying only known pre-admission busy refusals. Keep their existing
flood, exact delivery, responsiveness and delayed-Welcome assertions. The delayed
Welcome now explicitly checks prompt refusal and unchanged epoch before joining.
Require a removed-recipient/name-reuse regression: pending exact wire and original
recipient remain retained with no invented ACK, but do not block admission of a
new pseudonym. Live unacknowledged recipients must continue to hold the barrier.

[Completed source checks and negative controls](docs/evidence/ownership-departure-20260927/summary.json): 357 node-library passes, 12 integrations, strict Clippy and the unchanged GChat ownership case.

## macOS executable fixture permissions

Run gcoms-private-fs tests and strict Clippy natively with TMPDIR below /private/tmp. Verify requested unsafe modes actually exist, including setuid/setgid, before requiring rejection. Keep writable/public/symlink/hardlink and accepted 0500 checks. Retain original failure; production validation must remain byte-identical. [Evidence](docs/evidence/private-executable-fixture-20260927/summary.json).

## Bounded invitation retry (2026-09-27)

Require known busy refusals followed by success with the same prepared request, no retry for rejection/expiry/ambiguous failures, and the original deadline capping backoff and the waiting future. Removing retry must fail the success regression. Run all SDK tests, strict Clippy, outbound-only compilation and the real GChat consumer. Preserve the five-client message pass separately from the failed file deadline; dropping a helper future is not scheduler cancellation proof. [Evidence](docs/evidence/invitation-busy-retry-20260927/summary.json).

## Admission and bootstrap ordering (2026-09-27)

Require three negative controls: retained wire versus new epoch; empty metadata bootstrap receipt; concurrent finalization before directory publication. Verify exact ciphertext/ID through checkpoint, unchanged invitation on refusal, authenticated ACK release, replay and transient guard release. Cold-route fixtures must settle the initial bootstrap ACK before beginning the original blocked-route scenario. Full source-bound checks and prior failures are retained.
[Evidence](docs/evidence/channel-admission-20260927/summary.json).

## Protected subscription recovery on profile 46

Run `cargo test --locked -p gcoms-node --all-features --lib protected_routes -- --test-threads=1`.
Require both classes for every retained inbox/channel alias, identical authority
when readiness changes, genuine terminal-failure recovery and no revision change
from unpublished dial failures. Keep the 20-second deadline. Use production
responsive profile 46; this is not a 20-second setup claim for fixed-rate profile 22.
The optional `subscription_diagnostic` Rust integration workflow runs the same
assertions on all four desktop targets and strict node Clippy on Linux. Retain
any original failures separately; no skip or timeout increase is permitted.

## Manual reconnect and background delivery

Deliver an unchanged authenticated directory first, then export/import a manual
reconnect code. Require separate ciphertext and no automatic enqueue of the
manual code; an exact manual retry remains idempotent. A failed durable export
returns an error without exposing a cached code or changing pending control.
Retain tamper/epoch/authority rejection tests and run the real GChat reconnect
consumer, node library and strict Clippy. Cluster validation passed: 12 focused,
352 node (two exclusions), 83 core (three exclusions), both strict Clippy checks.
The original replay negative control failed as expected; see
[receipt](docs/evidence/manual-reconnect-20260927/summary.json).

## Skip redundant responsive cover, 2026-09-25

At a random cover opportunity, sent data on that outgoing interactive channel
replaces the cover record. The flag resets at that opportunity; idle cover resumes
without delaying real data or accumulating missed work. No new tasks or queues.
[Source-bound cluster validation](docs/evidence/responsive-cover-suppression-20260925/summary.json):
92 routing tests, strict all-feature/all-target routing Clippy and formatting pass;
739 source files unchanged. The old implementation fails the new suppression
regression. The earlier legacy catalog timeout and formatting failure are retained;
the final fresh-credential run passes, without proving hourly-boundary recovery.
This later change does not inherit candidate19 application timings or qualify new
SDK binaries, installed clients, relays or privacy. Platform rebuilds remain open.

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
15 seconds, no retry before five seconds, exactly two requests,
unchanged guards and a complete five-hop candidate. Authenticated incomplete
replies back off through 5/10/20/40/80/160/300 seconds; failed discovery requests
retain 60/120/240/300 seconds and complete directories retain five minutes.
Preserve the failing original
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

2026-09-22 bootstrap bulk routing: volatile D13 file records use the GC/2 bulk class; contact, command and acknowledgement records remain interactive. The seven direct-maintenance tests pass, including class derivation and retry/ownership gates. Minimal receivers must subscribe to both classes. Live end-to-end transfer and installation remain pending. codematch=unreachable.


## Five-relay carrier update — 2026-09-23

Offline five-relay gates: 54 routing unit, 6 discovery, 10 carrier, 11 persistent-node integration, 1 fresh-inbox, and 124 consumer tests passed (2 consumer tests remain explicitly ignored). Evidence and exact executed commands: test-evidence/gc2-five-relay-20260923/verification.json. These results do not establish live fleet or cross-OS deployment acceptance.


## Minimal native carrier interop — 2026-09-23

The optional native transport gate now checks five independently pinned TLS/HTTP2 layers and a 128 KiB response. Run `DS_MINIMAL_TLS_PROBE=<native Dropship qualification binary> cargo test -p gcoms-transport --test minimal_tls -- --include-ignored --test-threads=1` under the workstation runner. Six tests passed on Linux x64 against Dropship 9b486cd carrier sources; size/fixture evidence is in that repository at test-evidence/native-carrier-20260923. This verifies transport primitives, not five-relay route selection or fleet deployment.


## Transfer recovery — 2026-09-23

Accepted downloads retain verified pieces and resume automatically after restart or temporary conversation membership loss. No requests or incoming pieces are accepted without current authorization. Explicit pauses/cancellations remain stopped. Reopening repairs the older automatic membership-pause marker; other errors keep their existing recovery behavior. Transport completions continue to arm retries while files are disabled or roster refresh fails.

Validation: 51 component tests passed, two existing qualification tests ignored, including an overnight restart at 80% and a send completion delivered while locked. Evidence: `test-evidence/file-resume-20260923/verification.json`. Android live recovery remains pending; these gates do not establish fleet end-to-end acceptance. No new dependencies.


## Retained inbox authority (2026-09-23)

Run `cargo test -p gcoms-node --all-features --lib lease_authority_tests -- --test-threads=1`. Cover real TLS/H2 admission for owner-renewed leases, concurrent-send coalescing, stale capability/epoch rejection, expired leases, unexpected responses, queue-path binding, GC/2 without legacy fallback, and entry plus three middles plus inbox. Also check the client-only feature graph and scheduler Clippy gates. Live acceptance requires the Android partial download to continue from its retained verified pieces through final integrity verification; offline tests alone do not establish it.

## Bounded release files (2026-09-25)

Use `gchat-turnover.py --mode file-recovery --release-check` with the frozen paired build and qualification host: 16 MiB, 180-second completion and 600-second total ceiling. Require abrupt restart, retained pieces/identity, authenticated chat ACK, final hash and reopen/export. The separate 1 GiB campaign is nonblocking; retain its failed deadlines. Authentication, persistence, signatures and rollback remain mandatory.

## SDK persistence setup receipt correction (2026-09-27)

The Intel Mac native SDK run exposed a stale fixture assumption: authenticated
admission metadata now has its own tracked delivery receipt, which can follow
the warmup text ACK. Subscribe before admission and observe both setup IDs before
disconnecting the receiver. Only these known IDs may recur; the subsequently
admitted offline message still requires its own authenticated ACK after reopen.
Production code is unchanged. Linux runtime: 31 pass / 0 fail / 1 existing
namespace exclusion; strict all-feature/all-target runtime Clippy passes. A
late known setup receipt passes and a new premature delivery event fails the
intended assertion. Original Intel failure and initial correction compile error
are retained. See docs/evidence/runtime-admission-ack-fixture-20260927/summary.json.

## Native overlay test resources (2026-09-27)

The macOS native CI entrypoint raises its soft file-descriptor limit to 8192,
without changing the hard limit or installed application limits. Hosting 24 nodes
in one process exhausted the shell default of 256. The unchanged overlay test
passed after provisioning sufficient descriptors. The final harness and fixture
pass the real 24-node delivery test, five resource-helper checks, formatting and
strict all-target/all-feature Node Clippy. [Scoped evidence](docs/evidence/native-overlay-resources-20260927/summary.json).

Only the 24-node fixture allows 180 seconds for each authenticated admission;
other fixtures retain 30 seconds. It retains one prepared package, the normal ACK
barrier, all original first-hop and recipient-delivery assertions, and their
existing deadlines. This is a correctness setup budget, not a passing join-latency
claim. Original Windows/Mac failures remain failed; Windows and complete platform
CI must qualify the new source separately. No production runtime change.
## Circuit fixture credential window

The retained twelve-client/source-limit fixture must start with at least sixty
seconds left in its real authenticated credential epoch. Near the hourly boundary,
wait for the next epoch and install freshly issued introductions before opening
clients. Keep production expiry, source limits, the twelve retained connections
and the twenty-four circuit assertion unchanged. Run the complete routing
`circuits` integration target and strict all-target/all-feature routing Clippy.
The original 2026-09-27 21:00 UTC expiry-boundary failure remains retained.

## Completed discovery retry (2026-09-29)

Run the complete `gcoms-file-transfer` package and strict all-target/all-feature
Clippy, then the `gcoms-runtime` `files::tests` with `files,gc2-carrier` enabled.
`discovery_completion` covers failed real-send completion, the existing 30-second
retry bound, no duplicate while queued/in flight, stale completions, healthy
60-second cadence, and membership removal/restoration. Preserve the original red
test against 8cdfd3f. Runtime checks retain incoming progress with stalled outbound
receipts and retry completion across locking. These are component checks, not
proof of Mac installed 16 MiB completion within 180 seconds; the separately bound
native artifact must still pass that gate and rollback qualification.

`completion_source` separately reproduces an authenticated completion arriving
before discovery after cache reopen. It must request inventory from that source
without waiting for the discovery clock, preserve retained pieces, and request
only missing pieces after inventory. Negative cases preserve private scope,
digest checks, pause/cancel/unaccepted intent, duplicate suppression, the first
four immediate source queries, revocation and source backoff. A completion claim
alone must neither verify pieces nor complete the local download.

## Hosted service API and durable runtime — IRC-1/IRC-2/IRC-3

- `cargo test --locked -p gcoms-channel-service --all-features --test api`:
  query/scope-bound reads, private snapshots, deferred bulk records, departed
  readers bounded through removal across restart, HTTP size/version/rate gates.
- `cargo test --locked -p gcoms-runtime --all-features hosted::tests`:
  lost post-fsync acceptance plus client restart, offline receive and durable
  event commit, competing admission identity continuity, stale text/control
  recovery, revoked sender failure, exclusive/authenticated encrypted profiles
  and poisoning after an uncertain save.
- `cargo test --locked -p gcoms-routing --all-features catalog`:
  protected legacy/GC2 routing, bulk bounds and TLS/origin/no-fallback checks.
- Existing SDK IPC compatibility fixtures retain old request indices. IPC22
  requires HostedChannels for both service exchange and client-owned operations.
- Receipt aggregation, GChat user flows and 500-member network/latency tests remain
  required. A service acceptance response is not a recipient acknowledgement.

## IRC hosted/contact file profile

Run `cargo test --locked -p gcoms-runtime --all-features modern_` for a real
channel-independent contact file: verified progress, pause, authorization removal,
restart, explicit registration, resumption, exact export and authenticated
completion. Run `hosted::tests::file_` for separate durable file consumption,
immutable identified-send retries and covered completion in moderated channels.
`gcoms-sdk` `modern_files_require_separate_authority_and_zeroize_uploads` checks
IPC23 capability/version requirements and upload zeroization. Node's
`file_records_are_bulk_while_chat_control_and_acknowledgements_stay_interactive`
checks both root-contact and component-wrapped scheduling, including retry records.
Strict affected-package Clippy and actual GChat/500-member flows remain required.

### IRC file recovery follow-up

Run `modern_` across runtime/SDK/application with hosted and file features, the
full `gcoms-file-transfer` suite, and the node
`contact_route_renewal_preserves_established_pq_refresh_keys` regression. Require
verified partial-cache retention, renewed-contact recovery, exact full export and
authenticated completion. Retain failing network/error diagnostics. The hosted
case must reject changed ciphertext and finish with the publisher offline. Run
GChat's full workspace suite, including the contact-only permission file journey.
Archive migration exercises each prior hosted layout before writing/reopening v4.

### Opt-in hosted directory

Run the `hosted_directory` tests across service/runtime/SDK. Require default
nonpublication, rejected nonoperator publication, public paging bounds, retained
listing reconstruction, private/secret/closed omission and invitation-only labels.
Clients apply the same signed control and require IPC24 for typed publication and
browsing. GChat verifies scoped `/list`, global `/hosted list`, bounded cursors and
ordinary contact-only unlock/file behavior. Topics remain encrypted.

The GC2 contact-renewal regression must consume durable inbox entries and drive
logical-ACK maintenance, authenticate at least two actual periodic PQ frames,
and retain the same session tag. Unconsumed inbox quota is not a crypto failure.

### Durable hosted client capacity

`durable_hosted_capacity_smoke` exercises twelve actual encrypted client states
against the ciphertext service. The explicit ignored
`five_hundred_durable_hosted_clients_ten_senders_offline_and_churn` runs the same
500-identity campaign in release mode: ten concurrent senders, withheld offline
ACKs, reopen and exact recipient completion, encrypted piece storage, kick/rekey
and replacement admission. Keep covered and bulk JSON byte counters and timing.
This uses in-process transport and cannot qualify protected-network latency or the
separate whole-file engine. Run the smoke before the large campaign.

### Hosted owner responsiveness under uncertain acceptance

Run `hosted_local_send_preempts_a_lost_network_reply_without_losing_or_duplicating_delivery`.
Withhold an actual service reply after fsync, require a second local send to queue
within 200ms, then retry without duplicates or false delivery. Close must interrupt
a stalled read; reopen must retain both messages and require real recipient
receipts before Delivered. Run strict runtime/application all-feature checks.

## Hosted HTTPS deployment

Validate the source-bound service binary and supplied configuration, preserve and
validate the existing TLS boundary before reload, and probe hosted Info plus the
pre-existing health/defaults paths. Keep direct HTTPS readiness separate from
actual installed-network GChat admission, message receipts, recovery and files.
Require state-preserving restart and rollback without discarding accepted logs.

## Installed hosted origin authority

Run `signed_hosted_origins_preserve_catalog_configuration_and_reject_unsigned_hosts`.
A hosted Directory operation must authorize the signed provider before attempting
the protected route. Explicit catalog replacement/clearing must preserve current
provider authority, malformed updates must retain prior configuration, and an
unsigned host must fail the origin gate. No test installs a direct fallback.
Repeat the source-bound real GChat network journey after this fix.

The native relay rollout must preserve existing catalog hosts and configure only
approved signed-provider HTTPS destinations. Retain each host's pre/post PID,
active state and restart count, and stop the rollout on any failure. Process and
listener readiness alone never substitute for protected GChat delivery checks.

## Hosted admission snapshot recovery

Run runtime `snapshot_recovery` tests: lose two responses after authenticated
service reads and require one eventual membership change; return Unauthorized
and require one attempt; fail every transport read and require exactly four
attempts. Keep prepared identity and pinned pagination authority unchanged.
Repeat the offline-owner real-network GChat journey without bypassing TLS.

## Combined covered polling

Run runtime `covered_poll`: require one covered steady-state exchange for data,
committed ACKs and sender receipts; no ACK before consumer commit; legacy service
Info must retain the prior Read/Acknowledge/Receipts path. A bad receipt read
scope with an otherwise valid ACK must be rejected before storing that ACK, and
seventeen ACKs must exceed the batch bound. Retain the existing lost-ACK-response,
service-restart, three-recipient completion and interrupted-owner checks.
Run service API cases and strict affected-package Clippy, then measure actual
GChat timings; fewer requests alone do not qualify the five-second target.

## Bounded durable replay and nonblocking views

Run `cargo test --release -p gcoms-runtime --all-features --lib hosted` and strict
runtime all-target/all-feature Clippy. Lose the second deferred fetch before
applying a 24-admission page: cursor, archive bytes and checkpoint count must stay
unchanged. Reopen, recover all members/events with fewer than 12 full-state saves,
and reopen again exactly. Force a real save failure and require poisoned reads
and sends until restoring/reopening the prior prefix. While a real service poll
is held, List and bounded FileEvents must finish within 200ms without cancelling
the poll; shutdown, reopen and authenticated delivery must still work. Check
available/away/invisible expiry at the exact signed deadline. Repeat the original
500-client campaign with its 7200-second deadline and retain phase/resource logs.

## Bounded hosted piece concurrency

Run all runtime library tests with all features and strict runtime Clippy. Hold
two actual service blob responses, queue a third, and require chat/send/sync to
finish while the third cannot enter. Release the original responses and verify
exact success. Hold an authorized read, learn a signed channel closure, then
release it: the caller must receive an error. Shutdown must cancel detached bulk
I/O within 200ms. Retain the existing tamper, interrupted publisher, partial
restart, exact hash and contact revocation tests. Repeat the live 16MiB journey
against the fixed 180s resume-verification and 600s workflow targets.

Replay cost comparisons retain the 7200-second campaign limit and identical
500-member work. Record aggregate checkpoint counts at each catch-up marker
alongside process I/O/RSS. The 75ms scheduling budget is checked between records;
actual large-room feedback and recovery still require measured qualification.

Current archive qualification uses GComs65b54c7/GChatd4ff03d; the paired-pass
receipt includes every archive hash and the untouched source manifests. Live07
qualifies only its runtime907e54f two-client protected-network journey. Retain
earlier failed latency results and require separate 500-member and native
installed results before claiming the full IRC parity release.
