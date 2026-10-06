GC/2 receive-credit isolation, 2026-10-07: run `cargo test --offline --locked -p gcoms-node --all-features --test gc2_queue_service stalled_subscription_credit_resumes_without_blocking_finite_push -- --exact --nocapture`. The raw pinned connection must exhaust a 16-byte subscription window, retain the queue head across a second deposit notification, accept that finite PUSH within three seconds without subscription credit, then deliver both exact messages after credit returns. Require zero queued bytes and owned-driver shutdown. Result: one passed, zero failed, seven filtered out; 0.32 seconds execution after 1m56s compilation. This is a focused server regression, not full native-client delivery, mobile launch or release qualification. [Evidence](docs/evidence/gc2-flow-control-20261007/receive-credit-regression.json).

Discovery role fixtures, 2026-10-06: candidate 154 passed native GChat qualification but exposed two discovery tests that assumed `Tp1Client` retained a physical connection after a 404. Both failures reproduce on the frozen source. These tests now retain pinned raw TLS/HTTP2 across cross-role requests and the final valid renewal, preserving GC/1 rejection, exact one/two-connection counts, terminal/control separation, bounded requests and owned cleanup. All eight discovery tests pass. Only the test fixture changes; production code, dependencies and API/wire contracts remain unchanged. The original Windows failure remains retained and a new candidate still requires native qualification. See [causal fixture evidence](docs/evidence/relay-capacity-20261005/discovery-role-test-connection.json).

Physical connection role isolation, 2026-10-05: `cargo test --offline --locked -p gcoms-node --all-features --test gc2_queue_service -- --test-threads=1` must keep one raw TLS/HTTP2 connection throughout terminal-to-entry/transit/reentry rejection checks. The connection then retains its terminal subscription behavior and delivers the queued bytes. Do not use a reconnecting pooled client to prove per-connection role immutability. Keep the original candidate 153 failure and focused reproduction; all seven integration tests pass after the fixture repair. [Source-bound evidence](docs/evidence/relay-capacity-20261005/role-isolation-test-connection.json).

Transport admission regression, 2026-10-05: run `cargo test --offline --locked -p gcoms-transport --all-features --lib server::lifetime_tests -- --test-threads=1` and the raw dispatch integration test, then the existing transport controls. Eight active unknown-path connections must stop blocking fresh admission after the existing 120-second budget; authenticated connections survive, rejected paths never authenticate and no request is replayed. Client 404 retirement must preserve subscribers and remove only the exact pooled connection. All 64 distinct checks and strict all-target/all-feature Clippy pass; [evidence](docs/evidence/relay-capacity-20261005/transport-unauthenticated-lifetime.json) binds source and logs.

Terminal restart preflight, 2026-10-05: `relay-preflight` restarts relay 3, which owns client 1's inbox, and requires recovered authenticated chat and the complete DS-sized file within its existing deadlines. `python3 -m unittest discover -s scripts/tests -p gchat_turnover_test.py` passes 37 controls, including bounded payload-free failure evidence distinguishing missing recipients from missing sender acknowledgments. Candidate 152's full campaign remains failed; rerun the unchanged 64-client 30-minute gate on the new frozen source. [Original failure and smaller diagnostic](docs/evidence/relay-capacity-20261005/terminal-restart-load.json).

Simulator grant timing, 2026-10-05: the original Apple SDK client run reached its relay test more than five minutes after fixture startup and failed with TP-1 unauthenticated 404. The test now requests one fresh card from its authenticated loopback fixture after launch; grant lifetimes, protocol authentication, Android assets and production packages are unchanged. Six fixture controls and the actual Rust helper smoke pass; fresh cards retain the listener and cleanup closes it. Native Apple qualification remains required. See [fixture evidence](docs/evidence/relay-capacity-20261005/apple-fixture-grant-timing.json).

IPC cancellation regressions, 2026-10-05: `cargo test --offline --locked -p gcoms-sdk --features ipc --lib interrupted_write_tests -- --test-threads=1` must preserve exact request order after cancellation within both a frame prefix and payload, and reject new frames after a partial write error. Also run `interrupted_read_tests`, `disconnect_tests` and `payload_cleanup` with the same command flags; all nine focused checks pass. Retain the original baseline corruption failure and require the unchanged native Windows shared-daemon archive/flush test in the next source-bound qualification. [Evidence](docs/evidence/relay-capacity-20261005/ipc-cancellation.json).

Explicit recovery regression: run `cargo test --offline --locked -p gcoms-node --all-features --lib node::membership_recovery::tests -- --test-threads=1` and the same command with `node::channels::maintenance::tests`. Retain the original full-64-control failure, then require real reusable enrollment after explicit recovery, unchanged ordinary wires/expected recipients/ACKs, survivor controls, exact failed-save rollback and reopen. Staged controls whose exact journal key is retired must stop new fragments while admitted receipts settle; a queued removal notice for the same revoked leaf remains eligible. All 18 focused tests pass; [evidence](docs/evidence/relay-capacity-20261005/explicit-recovery-control-retirement.json) retains original failures and exact source hashes. No live membership operation follows from these tests.

Invitation responsiveness and pressure fixtures, 2026-10-05: creating a reusable invitation keeps channel preparation serialization and owner, policy, durable-store and 64-record checks, but no longer waits for an earlier text/presence delivery receipt. The regression holds a real first-hop reply unresolved and requires both durable creation and a full-ledger rejection to return within two seconds; admission and other command ordering are unchanged. Two restore/materialization pressure fixtures now saturate the configured scheduler data allowance instead of assuming the former 7 MiB allowance; all rejection, defer, counter and reclamation assertions remain. All six focused invitation, pressure, ordering and paired GChat controls passed; [retained receipts](docs/evidence/relay-capacity-20261005/explicit-recovery-control-retirement.json) preserve their exact source transitions. These source changes are not yet live.

Early lock validation, 2026-10-05: native CI now resolves every independent consumer lock before running the native suite. The separate mobile lock needed the same already-pinned signal dependency as the example consumer; all four tracked locks and all 16 Android/iOS client/relay, push and fixture graph combinations pass offline with `--locked`. No lock changes occur during these checks. This is dependency validation; native device, size and release qualification remain required. See [mobile lock evidence](docs/evidence/relay-capacity-20261005/mobile-lock-preflight.json).

Release portability repair, 2026-10-05: the existing outbound-only scheduler fix `9e57d2f` is reused at `09b6a0a`, and the isolated Rust consumer lock now includes the already-pinned Tokio signal dependency. The unchanged released 0.1.49 application compiles with `--locked` in IPC, embedded and network-client modes; current consumer graph checks pass and network-client still excludes relay hosting. Original Android/iOS/SDK failures are retained. Native platform qualification and SDK size measurements remain required. See [portability evidence](docs/evidence/relay-capacity-20261005/release-portability.json).

Capacity port integrated, 2026-10-05: deployed patch `5d61b75` is merged at `10a6f89`, with reviewed bounds and regression coverage at `fb8a8b5`. Default queue leases now allow 1024 cells / 16 MiB, subscription replay bookkeeping allows 4096 nonces per queue, legacy scheduler lanes allow 512 lanes / 1024 cells with 64 additional control slots, and the combined endpoint/transit scheduler budget is 64 MiB. Global byte/job bounds and shared GC/2 lease limits still apply; existing negotiated leases change only through normal provisioning or renewal. All 95 focused scheduler, queue, relay-service and GC/2 queue tests plus strict node Clippy pass. Existing wire/API contracts and the 64-member limit are unchanged. See [capacity integration evidence](docs/evidence/relay-capacity-20261005/deployed-capacity-port.json).

Live capacity, 2026-10-05: the operator reports all eight relays on the manual capacity hotfix, binary SHA-256 `a54a317de4068715512bcae2ff7512a49070c9f4421e00bb79d57019adbea21a`, with 2048 circuits and 4096 connections; the hub also has the patch. This live manual rollout remains separate from the pending managed release. Source-paired qualification, the 64-client 30-minute campaign, desktop publication and managed fleet delivery acceptance remain required. Earlier failed attempts below are retained evidence.

Automated relay qualification, 2026-10-05: the isolated fixture renews authenticated bootstrap introductions throughout setup and traffic while preserving relay identities and production lifetimes. `relay-preflight` checks two clients, a DS-sized file and relay restart before `relay-load` runs the unchanged 64-client gate. The source-bound builder accepts `--fetch` to populate dependencies only inside its retained source copy before its offline build. GChat release CI invokes the same builder and fixture automatically. Full load and live fleet acceptance remain required.

Load setup, 2026-10-05: load-12 stopped at 53 confirmed members with a TP-1 unauthenticated 404 before traffic. Restore the original serial setup that admitted all 64 members in load-11. Retain the independent observer correction and unchanged release gates. The authentication failure root cause remains unproven; see docs/evidence/relay-capacity-20261005/load12-admission.json.

Delivery observer regressions require one held channel admission to leave other channels progressing, with the next member of the held channel still blocked. A held unrelated history read must not move the timestamp of an already completed receiver observation. All original exact-identity, authorship, recipient and authenticated acknowledgment checks remain. Independent send and observation pools are bounded to eight and sixteen workers, with at most 64 pending commands. Retain the interrupted load-11 observer evidence; rerun the full 30-minute campaign against the same native artifacts.

Retained channel admission: race maintenance against invitation broadcast/bootstrap for the same destination, authority, class and ciphertext. Require one scheduler job and a still-queued receipt after finalization admission succeeds; different ciphertext must take a second job, and shutdown must still fail. Run node::channels::membership_wait_tests with all features before the unchanged 64-client campaign.

The relay-load default uses four channels of 17/17/17/16 members sharing one operator, with all other 63 clients partitioned exactly once. Four simultaneous commands produce the same 63 recipient deliveries per ten-second round. Require exact identities, authorship, every recipient and authenticated sender delivery on every channel, including all ten operator subscriptions. Use `--load-single-channel` separately to retain the 64-member admission diagnostic. Keep docs/evidence/relay-capacity-20261005/load09-admission.json as failed evidence.

Direct recovery regression: `cargo test --offline --locked -p gcoms-node --all-features --lib node::direct::maintenance_tests -- --test-threads=1` must release the completed attempt, retry confirmed local route failure within the existing 3.75–6.25-second jitter bounds, preserve exact bytes and original expiry, and leave timeout, Internal, accepted and rekeyed work on their original schedule. No deadline or load gate changes.

Bandwidth regression: `cargo test --offline --locked -p gcoms-routing --all-features --lib service::bandwidth::tests -- --test-threads=1` requires opposite-direction admission to preserve a blocked read or write wake-up, shared aggregate credit and byte accounting, and clean pause errors. Keep the before-fix failure and interrupted load-07 evidence.

Fleet load configuration: `relay-load` defaults to 2048 circuits and 4096 connections per operator relay, matching live service flags. Preflight requires each reported forwarding limit to equal the configured capacity, with one interactive reservation. Use `--load-relay-circuits` and `--load-relay-connections` for other predeclared capacity profiles; the same 64-client gates apply. The failed 128-circuit load-06 remains retained and does not qualify defaults.

Transport recovery regression: `missing_reply_headers_retire_only_the_stalled_connection_without_replay` requires a fresh pinned connection after a reply-header timeout, exactly one submission of the uncertain request, and continued delivery on an existing subscriber. `finite_request_deadline_includes_response_body` requires body timeouts to retain the pool entry. Deadlines and public errors remain unchanged.

Contribution invitation regression: retain local contribution routes while carrying only signed network founders in invitations; scan all eligible routes before applying the eight-introduction bound. The disconnected fixture setup runs under its ordinary profile owner, preserving Unix peer authentication. Both failed setup attempts remain retained.

Legacy file-resume comparison, 2026-10-05: the unchanged prior trunk `a2d4fc1b` also fails `modern_contact_file_verifies_resumes_and_revokes_without_a_channel` at its original 240-second resume deadline. That earlier full runtime suite recorded 66 passes, one failure and three ignored cases; its separate serial retry failed too. These are retained pre-existing legacy fixture results, not current-source or GC/2 qualification. The native-executor correction is retained at `b28d4d4`; its validation is separate from the capacity-port tests above. No deadline or assertion was weakened. See [comparison receipt](docs/evidence/relay-capacity-20261005/legacy-resume-baseline.json).

Disconnected load setup uses the existing single-use SDK invitation API through an owner-only fixture endpoint. It does not qualify reusable HTTPS-provider invitations. Unexpected invitation response shapes fail immediately instead of consuming the setup deadline. The first 64-client attempt was stopped before traffic because the driver used the obsolete bare `/invite` behavior; its evidence is retained.

Relay capacity qualification, 2026-10-05: run GComs transport possession-proof and catalog relay-registration integration tests, forwarding/admission/backoff tests, routing bandwidth tests and runtime sharing persistence tests. Validate paired GChat sources with strict Clippy, core tests and the real turnover host. Run `gcoms/scripts/gchat-turnover.py --build BUILD --out NEW_EVIDENCE --mode relay-load --fixture-host BUILD/bin/turnover_daemon` for the blocking 64-client 30-minute test. Require <1% refusals, recipient p95 <5s, a verified 5,235,248-byte file, successful restart and no wedges. Keep failed attempts and separately prove actual desktop publication, provider withdrawal and delivery through the live fleet. The fixture enables payload-free transport timeout stages; `gcoms-transport`'s `finite_request_deadline_includes_response_body` regression still requires the unchanged timeout and public error.

Current release, 2026-10-03: SDK 0.1.98 is published with all 12 original desktop/mobile qualification archives. Its exact build inputs match qualified source 32072fe; original archive names and source labels are retained. The newer SDK 0.1.102 pointer remains available. All 17 infrastructure targets and four GChat desktop platforms are deployed or published. GChat mobile installed acceptance and SDK 1.0 remain incomplete; the 64-member limit, covered receipts and version-bound 20%/5% size policy are unchanged.

See the [immutable SDK index](https://gchat.boo/updates/sdk/f8ae216bf9016d59f17a4dad836806b5a31fbe3c4b57d35dba12d4f3f2f64852/index.json) and [current launch evidence](https://github.com/IggyGG/gchat/blob/main/docs/evidence/stabilization-20261001/launch-simplification.json). Routine releases follow an authoritative Forgejo main push automatically.

## Retained earlier checkpoints

The current release status above supersedes earlier pending matrix observations. Original outcomes and evidence remain below.

The shared native evidence policy now records the three existing explicit
64-member MLS/durable-client capacity tests under the mandatory stress.mls64
gate. Native package qualification continues to reject unknown or cross-project
exclusions; a missing capacity receipt still blocks release. All 22 policy
controls pass in both repositories. No application API or runtime changed.

The exact release SDK source 8f8fdb3 passes all four original base mobile jobs.
Three Apple combinations (client/base, relay/base and relay/push) independently
verify their provider digests, 562 source hashes and nine production libraries
each. Their native and linked size comparisons pass the approved 20% feature
allowance. Apple client/push and both Mac desktop SDK jobs remain pending.
SDK 1.0 remains unqualified and the post-1.0 5% limit is unchanged. See
`docs/evidence/stabilization-20261001/sdk-apple-8f8fdb3.json`.

The original protected Linux job for release 0.1.98 passes both full native
GChat/GComs CI commands on exact sources `52d28d7`/`8f8fdb3`. Its original provider
ZIP, both source bindings, derived Rust/npm inputs and all linked logs verify
through the unchanged qualification handler. GComs records 211 passing Python
checks, zero failed Rust checks and a successful dependency audit. The original
failed/split Linux attempts remain retained; this is a new full native pass.
Signed packaging and installed-network/fleet acceptance remain required.

The release's exact GComs revision `8f8fdb3` passes Linux/Windows SDK jobs and
all four Android role/push combinations. Independent verification retains all
six original provider ZIPs, 426 desktop source hashes per platform, 562 source
and 31 packaging hashes per Android result, 24 native libraries and the actual
16 KiB emulator/alignment evidence. All 20 desktop, 24 Android native and eight
linked APK size comparisons pass the approved 20% feature allowance. The Mac
desktop jobs remain pending. The Apple client/base job passes; its original
114,926,219-byte provider ZIP, 562 source hashes and nine production libraries
verify independently. Nine native and two linked application size comparisons
pass (maximum 11.215% growth), with matching toolchains. The remaining two
Apple push combinations are pending, so SDK 1.0 remains unqualified. See the native
policy receipt and retained `operations/desktop-8f8fdb3-verified-263.json`,
`operations/android-sdk-archives-verified-264.json` and
`operations/apple-sdk-archives-verified-277.json`.

Earlier SDK source `32072fe` also passes all four desktop jobs on Linux,
Windows, Intel Mac and Apple Silicon. Every original provider ZIP size/digest
and 426 source hashes per platform are independently verified. All 40 native
same-toolchain size comparisons remain below the approved 20% feature cap
(maximum 14.533%). Its Apple mobile jobs remain queued; no complete current-source
mobile matrix or SDK 1.0 qualification is claimed. Original failures and the
post-1.0 5% regression cap remain unchanged. See the native policy receipt and
retained `operations/desktop-32072fe-verified-225.json`.

Corrected SDK source `32072fe` now passes all four Android client/relay and
base/push emulator jobs. Full provider ZIPs, 562 source hashes and 31 packaging
hashes per result, 24 native libraries and eight linked APK size comparisons
are independently verified. The real emulator uses 16 KiB pages; alignment and
same-toolchain size checks pass the approved 20% allowance (native growth
10.07–13.59%). Apple jobs on this source remain queued, so these results do not
qualify its complete mobile matrices or SDK 1.0. Original failures are retained.
Evidence: `docs/evidence/stabilization-20261001/sdk-size-policy.json` and retained
`operations/android-sdk-archives-verified-190.json`.

Clean SDK source `1654677` now has four fully retained Apple role/push results.
Every provider ZIP size and digest, 562 reported source hashes per result and all
36 distributable native-library hashes match. The 36 same-toolchain native size
checks and eight linked application size checks pass the approved 20% feature
allowance (observed growth 8.07–11.50%). Original Android preflight failures and
overall failed mobile matrices remain unchanged; fixture static libraries were
not separately archived. All four Android role/push combinations on corrected source
`32072fe` now pass; their independent verification is recorded above. This does not qualify SDK 1.0, installed apps or the fleet.
See `docs/evidence/stabilization-20261001/sdk-size-policy.json` and retained
`operations/apple-sdk-archives-verified-175.json`.

Android SDK runs `37020911991` and `37021726565` fail before tool setup because
isolated `mobile_elf_test` cannot import `sdk_size_policy`. The test now sets its
own scripts import path; production size/security checks are unchanged. Its four
ELF controls and six size-policy controls pass independently, and full Python
passes 211 tests. L0 checks 979 paths and seven research hashes. Mobile CI now
triggers on this test's changes. The four Apple jobs in those runs succeed, but
their provider archives are independently retained and verified. Original
failed runs remain retained; corrected Android emulator qualification passes above.
No product runtime, API, limits or dependencies change in this repair. See the
[native policy receipt](docs/evidence/stabilization-20261001/sdk-size-policy.json).

## Stable SDK release preparation (2026-10-01)

Source `1654677b3bac40977b7048ce0fe06c03fe6076e9` passes native run
`37020912213` on Linux, Windows, Intel Mac and Apple Silicon. All four backend
stages and 40 same-toolchain size comparisons pass under the approved 20% feature
allowance. Each source is clean; every one of the 426 reported file hashes on each
platform matches its committed Git blob. Full provider archives are verified and
retained. The 5% SDK 1.0 rule, original failed runs and baselines are unchanged;
see the [native policy receipt](docs/evidence/stabilization-20261001/sdk-size-policy.json).
The complete Linux workspace, Rustdoc and strict Clippy also pass on this source.
The original full CI run then fails at npm because the isolated lab has no upstream
DNS. Verified locked dependencies unblock JavaScript checks (eight tests), build,
vectors, generated files and minimal SDK/core graphs. A pinned Python 3.12 runner
with verified official registry caches now passes all 20 Rust/two npm archives,
three unchanged released-consumer feature graphs and dependency auditing in
126.30 seconds, with the original checkout unchanged. All stages are retained
separately; the original full CI failure is not relabelled as a single passing run.
These checks do not qualify full release activation or declare SDK 1.0. Mobile SDK combinations, installed acceptance, fleet activation
and a subsequent unattended release remain required.

Run the FIFO request regression in separate original/corrected build targets.
The seven-second transport drain must reproduce duplicate block retries with four
requests and verify the file and authenticated completion with two requests and
zero retries. The earlier six-second model did not reproduce the native backlog;
retain that original result. Then run all file tests, strict Clippy and the unchanged
real encrypted contact reopen/byte comparison/completion assertions. Preserve
30-second request timers, 240-second phase bounds, the four-ciphertext ratchet window,
keys, wire bytes and receipt rules. Fresh four-platform native qualification and
full committed workspace validation remain mandatory.

Full Windows worker `36863200902` retains a GC2 catalog test failure: its private
TLS origin dropped TCP without sending `close_notify`. The test origin now shuts
down its TLS stream normally after writing the complete response. Production TLS,
certificate/hostname refusals, remote DNS and bulk-body assertions are unchanged.
Both real legacy and GC2 HTTPS tests pass on Linux; fresh full Windows qualification
remains required. The original provider archive is verified and retained in the
[Windows checkpoint](docs/evidence/stabilization-20261001/windows-locked-storage-tests.json).

Verified native run `36881757477` passes Linux, Windows and Apple Silicon backend
checks and all ten size comparisons on each platform under the approved 20% policy.
Intel Mac fails contact reopen and its size phase is cancelled; the complete release
remains unqualified. The historical measurement reports also mark their source dirty
because backend evidence was written outside the ignored evidence directory. The
workflow now retains all output under `test-evidence/` and requires a clean checkout
before backend execution and after measurement, with the exact revision and a clean
measurement report. Earlier reports remain unchanged; fresh native qualification is
required. See the [native checkpoint](docs/evidence/stabilization-20261001/sdk-native-90d7eac.json).

Linux channel-service validation passes 18 tests. Its first strict Clippy
run finds an unused mutable fixture binding; that failure is retained and the
binding is corrected without changing assertions. Corrected Clippy and native
Windows full-workspace validation remain required.

Run all-feature channel-service tests and strict all-target Clippy. Read unit
log snapshots through the owning handle and restore the original cursor. Close
integration logs before raw filesystem snapshots, then reopen through normal
validation before continuing. Preserve exact byte comparisons, exclusive locking,
quota/deduplication, torn-tail/corruption and actual OS write-error poisoning.
The original Windows error-33 failures remain failures; require a fresh native
Windows full-workspace packaging check. Do not skip these tests on Windows.

Run `python3 -m unittest discover -s scripts/tests -p rust_integration_size_test.py`.
Require the owner-approved feature allowance to pass at exactly 20% and fail one
byte above it. SDK 1.0 prereleases and later majors must pass at exactly 5% and
fail one byte above it, without an override. Reject changed toolchains, absent
consumer baselines, changed policies and invalid measured bytes. Every native
workflow runs these controls before compiling. Fresh native results must record
the effective policy; earlier 5% failures retain their original conclusions.

Run reopening_retries_durable_work_without_renewing_or_completing_it against a
real retained direct session. Restore a 55-second durable retry, deferred record,
ordinary direct retry and an expired record. Durable work must be due immediately;
ordinary pacing stays intact, expired authority is absent, exact wire/logical IDs
and counters remain, and no receipt or inbound delivery is fabricated. Retain the
original timer's failing assertion separately from invalid fixture attempts.
Then run the unchanged contact-file recovery, full serial workspace gate and
strict Clippy. A component pass does not replace fresh native recovery.

The corrected source passes the complete 1,151-test Linux workspace, 13 retained
ignores, the unchanged real contact resume, Rustdoc, strict workspace Clippy and
minimal SDK/core checks. Preserve the original timer's failing control and every
invalid fixture separately. Verified native run `36845346885` passes Linux/Windows
backend and contact recovery. Mac runs and fresh approved size qualification still require
their own source-bound results; see the
[reopen receipt](docs/evidence/stabilization-20261001/durable-reopen.json).

Run all SDK tests and fixed-byte IPC fixtures. The client direction must match
the original Hello/Request/ProfileHello ordinals, reject server frames on write
and client frames on read, and enforce the unchanged 16 MiB bound before a single
zeroizing allocation. Borrowed HTTP reply decoding must match the original JSON
decoder for all variants, sequence/field order, escaped tags, unknown fields,
duplicates, missing content, unit/null values and invalid/trailing data.
Nested inline/deferred records and public membership/control changes must match
the public decoder through records, polls and snapshots, including escaped tags,
field order, invalid scalar values and duplicates. Enum struct variants require
object bodies; standalone newtype structs preserve their sequence semantics.
Retain the original sequence-overacceptance failure and corrected result.
Run all workspace tests, strict Clippy, Rustdoc, minimal graphs, unchanged released
facade checks, locked current consumers and eight mobile dependency graphs.
The size regression requires every measured delta even when two consumers exceed
the effective version-bound ceiling, preserves its exact boundary and rejects a different toolchain. Native jobs
retain source and failure logs; isolated size checks still run after backend
failure. A retained archive or component pass cannot qualify failed native recovery.
The source/attempt-bound backend archive must be available before size compilation;
the final archive must still retain all results and the job's original conclusion.
Enable `GCOMS_FILE_RECOVERY_DIAGNOSTICS=1` only in test executions to retain bounded
block offsets/counts, together with error counter timing, against the unchanged
contact resume assertions and deadlines. Never infer lost ratchet state solely
from a stale simultaneous-setup error.

Run `python3 scripts/check-released-facade.py` to compile the unchanged published
0.1.49 Rust source in IPC, outbound and embedded graphs. The native integration
matrix also runs it and retains each compiler log. Fixture hash changes fail
before Cargo; dependency selection uses the current isolated locked consumer.
Run runtime all-feature tests including
`slow_contact_sends_remain_bounded_and_survive_control_interrupts` and the unchanged
`modern_contact_file_verifies_resumes_and_revokes_without_a_channel`. Require the
same native Mac and Windows tests; no deadline, byte count, lock requirement or
assertion may be relaxed to turn the original failures into passes.
Run all-feature node tests, including the legacy and credited session lane
regressions, real protected bulk files, direct delivery/reopening and the unchanged
contact resume test. Legacy session classification must depend on the actual
retained session, including when GC/2 is enabled for new conversations. GC/2 must
keep its bulk class. Require corrected native evidence on all four platforms;
the first failed native run remains failed.
The legacy window regression prepares six real durable records, verifies that
four are encrypted and two remain persisted without ratchet advancement, then
releases one receipt slot and requires exactly one materialization with the
original deadline. Actual GC/2 sessions must bypass this legacy bound. Run the
node suite with native CI's `--test-threads=1`; retain the original parallel ACK
timeout. Keep the failed one-slot file recovery and require fresh native Windows
and both Mac recovery runs against the four-slot source. Do not increase key
retention, skip limits, deadlines or retry authority.

Run the all-feature RPC runtime tests and strict Clippy. The optional-method
regression compiles an unchanged handler without the new method, returns its
default unsupported result through the actual typed client/router and preserves
authorization. Existing invalid declarations remain rejected.
Require `cargo tree --locked --manifest-path mobile/native/Cargo.toml
--no-default-features --features <client|relay|client,push|relay,push-gateway>`
for Android and Apple targets before their native packaging/size/lifecycle checks.

## IRC/main invitation integration (2026-09-30)

Integrate main's reusable invitations and enrollment without dropping hosted
channels, contacts or the 64-member limit. IPC26 keeps the released IPC22 recovery
and IPC23 invitation discriminants; hosted/file operations follow them with
separate capabilities. Negotiate released IPC23, reject unpublished IPC24/25, and
retain legacy privilege checks. Fixed-byte invitation/recovery fixtures and an
actual IPC23 handshake check the merged layout. Full paired checks are pending.

## IRC parity: retain the 64-member limit (2026-09-30)

The user confirmed the existing limit of **64 members**, including the owner.
Hosted creation, signed policy changes and service capacity advertising enforce
that limit. Qualification targets 64 independent members; no larger campaign is
required. The active 500-member run was cancelled at the user's scope reduction,
its grant revoked and all owned processes stopped. Its original evidence remains
historical, not a capacity pass. Covered receipts, Topic pending and the separate
ordinary-message/replay recovery requirements remain unchanged.

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
`cargo test --locked --release -p gcoms-mls --all-features --test hosted sixty_four_real_members_and_ten_concurrent_senders -- --ignored --nocapture`.
Require 64 distinct actual leaves, 63 membership changes, ten concurrent
senders, 630 authenticated receives, overflow rejection and retained duration /
wire-size measurements. Keep network/UI/ACK timing and file/churn qualification
separate; this component gate cannot close IRC-8 by itself.

## Reusable hosted admission codes — IRC-3

The MLS suite must import a protected reusable secret, admit private members
with the owner absent, refuse reuse of its public verifier as a secret, reject
wrong-code proofs and retry a concurrent refused join with the same leaf
identity. Accepted members cannot invoke the pending-join reset API. A code's
private serialization must not appear in public policy. Ordered key rotation
and revocation require separate policy-change regressions before being enabled.
## Owner-controlled membership recovery

Run node `membership_recovery::tests`, channel maintenance revocation accounting, MLS and SDK library suites with all features. Require stale/partial/owner refusal, durable-save rollback, original wire/ACK retention through reopen, old-leaf exclusion, fresh same-name admission, removal-history bounds and IPC21/22 capability enforcement. Paired GChat `membership_recovery_invitation_delivery_kick_and_reopen` must exercise real mint/join/redeem, delivery ACK, normal kick and restart.

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
  and enforces the version-bound 20% feature / 5% stable ceiling on the same Rust toolchain.

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
`sixty_four_durable_hosted_clients_ten_senders_offline_and_churn` runs the same
64-identity campaign in release mode: ten concurrent senders, withheld offline
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
Hold transport availability off for four seconds and require recovery on the
fourth read, followed by exactly one admitted membership change. The 1/2/4-second
backoff must stay inside the existing 30-second page deadline; it cannot dial or
wake routing maintenance. Preserve the original 600-ms retry-exhaustion failure.
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
available/away/invisible expiry at the exact signed deadline. Run the current
64-client campaign with the retained 7200-second deadline and retain phase/resource logs.

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

Current archive qualification uses GComs `65b54c7`/GChat `d4ff03d`; the paired-pass
receipt includes every archive hash and the untouched source manifests. Live07
qualifies only its runtime `907e54f` two-client protected-network journey. Retain
earlier failed latency results and require separate 500-member and native
installed results before claiming the full IRC parity release.

## Retained inbox recovery when replacement is full

With a pinned TLS fixture, populate the six retained cleanup roles and allow
replacement as after repeated failed recovery rounds. Require actual retained
admission responses and queue probes, durable restoration, identical queue IDs,
capabilities and original deadlines, and no application delivery event. The old
replacement-only branch must fail this case. Retain the capacity-refusal test,
failed-checkpoint refusal and existing owner-alias restoration/expiry tests.
The personal-profile invitation/send/kick check is a separate live receipt.

## Owner announcement backpressure

The pinned-transport retained-inbox fixture now includes a peer and fills the
shared retained-control allowance. The old runtime must fail with the exact
live `direct retained payload admission` error. The corrected runtime must
finish authenticated restoration, keep every role/capability and never extend
its deadline, while announcement stays pending. Releasing capacity then permits
normal durable announcement; failed storage must leave retry pending without
an event or new pending record, and a completed retry must not duplicate it.
Retain ordinary replacement progress, owner checkpoint refusal, contact-update
encryption/archive checks and the original invalid millisecond equality result
(deadline conversion may floor a remainder, never increase authority).

For the IPC25 integration, run SDK all-feature tests and strict SDK/runtime
Clippy. `recovery_is_owner_capability_bounded_and_versioned` decodes and re-encodes
fixed released IPC22 request/response bytes.
`hosted_task_dialects_and_new_capabilities_fail_before_welcome` rejects task IPC23/24
and hosted/file capabilities on IPC22. The retained route-recovery connection test
also requires hosted dispatch denial under an ordinary legacy admin session.
Repeat merged GChat Rust/UI/generated checks and paired package consumers.

Retain the serial 500-client campaign and its original 7200-second bound. The
separate ignored `sixty_four_concurrent_durable_hosted_clients_ten_senders_offline_and_churn`
runs at most four independent catch-up owners, with identical commit validation
and private archives. Run its 12-client concurrent smoke first; do not compare
its wall time as a production-code-only speedup or protected-network result.
Require a configured channel quota above the measured 339,264,618-byte admission
log; the 500-member deployment template uses 1 GiB with a 4 GiB aggregate ceiling.

Use the merged-paired-pass archive receipt for `0e7db6a`/`5533b1e`. The 1,096-test
workspace receipt belongs to `65b54c7` and must not be substituted for the active
merged workspace rerun. Current GChat full browser integration passes 80 cases;
physical native installers and 500-member protected-network checks remain separate.

### Current merged protected-network result — 2026-09-30

GComs `0e7db6a` with GChat `5533b1e` passes the live08 two-client correctness and
fixed latency checks: 118ms feedback, 1.905s delivery plus covered receipt, 4.044s
offline-owner join, 100.142s resumed 16MiB verification and 179.396s full workflow.
GChat retains the exact source/binary report in
`docs/evidence/irc-hosted-live-20260930/merged-08.json`. Topic pending/handoff,
moderation, offline recovery, exact exported hash and unvoiced completion pass.
The temporary grant was revoked after owned daemons stopped; see
`docs/evidence/irc-hosted-service-20260930/merged-grant-revocation.json`.
A separate 12-profile application smoke is running before the full 500-profile
protected-network gate. The merged full workspace and durable-runtime campaigns
remain running; native installed qualification and trunk publication remain open.

## Deferred replay concurrency and retained session memory

Run the hosted runtime release suite and the full runtime library suite with
strict all-target/all-feature Clippy. The held-fetch regression must observe two
requests before releasing either, return the second first, keep a third blocked,
and preserve original disk bytes until the ordered batch completes. Cancellation
must reopen the original prefix and recover all membership events. The old
sequential implementation fails this test at the unchanged three-second bound.
Keep lost-fetch, forged hash/length, failed-checkpoint and urgency regressions.

After create, successful checkpoint, restored archive and failed save, live owners
must retain no separate sealed-session allocation. Saved bytes must still contain
the MLS state and reopen to the exact prior view. A failed replacement remains
poisoned and must reopen the last intact archive. Preserve all version1–3 archive
migration cases. Repeat the application smoke with the selected recovery policy
below and the covered-receipt/file deadlines. Retain the original 14.537s and
16.590s membership-recovery timing failures with their original requirements.

For the 500-client durable runtime campaign, use the deployed 100000-record
profile. `channel_records` bounds the separate authenticated receipt ledger too;
ten senders already require 4990 entries. Retain the failed 2000-record run.
Do not skip recipient signatures or count only transcript records. Resource and
7200-second deadlines remain independent and unchanged for the corrected run.

### IRC-8 operator relay capacity

Cluster checks must include routing `service::capacity_tests`, node
`relay_capacity::tests`, existing GC/2 mux/entry tests and strict Clippy. The real
256-stream regression verifies exact saturation, the reserved interactive slot,
released sockets and failed-target permit recovery above the old128 ceiling.
Default128 and hard4096/8192 ceilings and unchanged eight-per-IP unauthenticated
admission are checked independently. Actual protected-network capacity, resource
use, cleanup and native qualification remain separate required gates.

For the user-selected long-backlog policy, keep 10 seconds for ordinary offline
message recovery. GChat must display confirmed applied-record progress during
large membership replay and clear it only after catch-up, failure or cancellation.
Measure long membership replay separately; do not relabel earlier failed runs.
Apply that distinction in every room: even a twelve-member room can accumulate
slow membership replay. Replay exceeding ten seconds must show positive confirmed
progress; ordinary offline-message recovery still fails beyond ten seconds.
Keep the 300-second smoke and 1,800-second capacity observation bounds, complete
unique rosters and indicator completion. New reports identify the selected policy.

### IRC-8 removed-member replay

Replay an authorized kick and its rekey in one page on the removed client.
Require durable inactive state, a removal event and successful reopen. Reject
a mismatched next GroupInfo without advancing MLS state. Preserve forged-removal
and stale-policy controls; never grant removed clients new epoch secrets.
Repeat live removal/exclusion/replacement before capacity qualification.
