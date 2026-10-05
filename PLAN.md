Invitation responsiveness and pressure fixtures, 2026-10-05: creating a reusable invitation keeps channel preparation serialization and owner, policy, durable-store and 64-record checks, but no longer waits for an earlier text/presence delivery receipt. The regression holds a real first-hop reply unresolved and requires both durable creation and a full-ledger rejection to return within two seconds; admission and other command ordering are unchanged. Two restore/materialization pressure fixtures now saturate the configured scheduler data allowance instead of assuming the former 7 MiB allowance; all rejection, defer, counter and reclamation assertions remain. Focused Rust validation is pending; these source changes are not yet live.

Early lock validation, 2026-10-05: native CI now resolves every independent consumer lock before running the native suite. The separate mobile lock needed the same already-pinned signal dependency as the example consumer; all four tracked locks and all 16 Android/iOS client/relay, push and fixture graph combinations pass offline with `--locked`. No lock changes occur during these checks. This is dependency validation; native device, size and release qualification remain required. See [mobile lock evidence](docs/evidence/relay-capacity-20261005/mobile-lock-preflight.json).

Release portability repair, 2026-10-05: the existing outbound-only scheduler fix `9e57d2f` is reused at `09b6a0a`, and the isolated Rust consumer lock now includes the already-pinned Tokio signal dependency. The unchanged released 0.1.49 application compiles with `--locked` in IPC, embedded and network-client modes; current consumer graph checks pass and network-client still excludes relay hosting. Original Android/iOS/SDK failures are retained. Native platform qualification and SDK size measurements remain required. See [portability evidence](docs/evidence/relay-capacity-20261005/release-portability.json).

Capacity port integrated, 2026-10-05: deployed patch `5d61b75` is merged at `10a6f89`, with reviewed bounds and regression coverage at `fb8a8b5`. Default queue leases now allow 1024 cells / 16 MiB, subscription replay bookkeeping allows 4096 nonces per queue, legacy scheduler lanes allow 512 lanes / 1024 cells with 64 additional control slots, and the combined endpoint/transit scheduler budget is 64 MiB. Global byte/job bounds and shared GC/2 lease limits still apply; existing negotiated leases change only through normal provisioning or renewal. All 95 focused scheduler, queue, relay-service and GC/2 queue tests plus strict node Clippy pass. Existing wire/API contracts and the 64-member limit are unchanged. See [capacity integration evidence](docs/evidence/relay-capacity-20261005/deployed-capacity-port.json).

Live capacity, 2026-10-05: the operator reports all eight relays on the manual capacity hotfix, binary SHA-256 `a54a317de4068715512bcae2ff7512a49070c9f4421e00bb79d57019adbea21a`, with 2048 circuits and 4096 connections; the hub also has the patch. This live manual rollout remains separate from the pending managed release. Source-paired qualification, the 64-client 30-minute campaign, desktop publication and managed fleet delivery acceptance remain required. Earlier failed attempts below are retained evidence.

Automated relay qualification, 2026-10-05: the isolated fixture renews authenticated bootstrap introductions throughout setup and traffic while preserving relay identities and production lifetimes. `relay-preflight` checks two clients, a DS-sized file and relay restart before `relay-load` runs the unchanged 64-client gate. The source-bound builder accepts `--fetch` to populate dependencies only inside its retained source copy before its offline build. GChat release CI invokes the same builder and fixture automatically. Full load and live fleet acceptance remain required.

Load setup, 2026-10-05: load-12 stopped at 53 confirmed members with a TP-1 unauthenticated 404 before traffic. Restore the original serial setup that admitted all 64 members in load-11. Retain the independent observer correction and unchanged release gates. The authentication failure root cause remains unproven; see docs/evidence/relay-capacity-20261005/load12-admission.json.

Delivery observer correction, 2026-10-05: load-11 admitted all 64 clients and carried commands across a relay restart, but was stopped when independent reads proved that waiting for unrelated send RPCs inflated recipient latency. Record first successful history visibility in each observation worker while retaining exact message identity, authorship, all authenticated delivery acknowledgments and every original release threshold. Prepare independent channels concurrently while preserving serial admission within each channel. Reuse the unchanged build-08 binaries. See docs/evidence/relay-capacity-20261005/load11-observer.json. This is not a release pass.

Invitation finalization, 2026-10-05: the four-channel 64-client setup confirmed 34 channel members before an exact ciphertext already admitted by maintenance was reported as a join error. Retained channel broadcast/bootstrap admission now accepts that existing local attempt without dispatching another job or treating it as delivered. Other scheduler errors remain errors; the outbox and authenticated receipts remain required. Regression and campaign validation are in progress. See docs/evidence/relay-capacity-20261005/load10-admission.json.

Fleet load setup, 2026-10-05: load-09 confirmed 43 members in one channel before the next owner admission exceeded its unchanged deadline. It had no transport timeouts; the workload never started. This failed diagnostic remains retained. The blocking fleet fixture now matches four operator channels with all 64 concurrent clients, 32 contributing nodes and the original aggregate 63 recipient deliveries every ten seconds. Latency, refusal, file, restart and 30-minute gates remain unchanged. The separate `--load-single-channel` diagnostic remains available; no 64-member admission pass is claimed. All 29 fixture and build-binding checks pass.

Local route recovery, 2026-10-05: load-08 joined 28 participants before the owner Welcome timed out; there were no header timeouts or relay refusals. The campaign did not start. Direct maintenance now shortens only a confirmed local route-selection failure to a jittered five-second retry, including completion after a ready-set change. It retains exact ciphertext, expiry and all uncertain-outcome schedules. Validation and a fresh 64-client campaign remain required. See docs/evidence/relay-capacity-20261005/load08-setup.json.

Desktop bandwidth wake-up fix, 2026-10-05: a regression reproduces a lost wake-up in the original shared read/write timer, then passes for both directions after independent timers. All three bandwidth tests and strict routing Clippy pass. The 2048-circuit load-07 was stopped with 16 joined participants after this defect was proven; all fixture children stopped cleanly. A new build and 64-client campaign must pass before release.

64-client fixture configuration, 2026-10-05: load-06 joined 12 participants before timing out. It used 128-circuit operator defaults, while the actual fleet is configured for 2048 circuits and 4096 connections. The load driver now models and verifies those explicit fleet limits; default-128 qualification remains unproven. All original latency, refusal, file, restart and duration gates remain unchanged. See docs/evidence/relay-capacity-20261005/load06-setup.json.

Transport recovery, 2026-10-05: retained load attempt 05 isolates owner timeouts to submitted requests awaiting reply headers. The client now retires only that exact cached connection without replay, preserving existing subscribers, uncertainty, deadlines and public errors. All 31 transport integration tests and strict Clippy pass; the synchronized body-timeout regression retains its pool entry. A fresh 64-client campaign is still required. See docs/evidence/relay-capacity-20261005/transport-recovery.json; this diagnosis alone does not qualify release.

Relay capacity and desktop contribution, 2026-10-05: implementation is under validation. Forwarding uses configured capacity with bounded admission; GC/2 endpoint lane limits, cross-class probe backoff, authenticated alternate-alias failover and bounded refusal diagnostics are implemented. Desktop sharing uses modest budgets, native eligibility guards, encrypted opt-out and signed membership-bound provider registration after independent listener proof. Existing messaging APIs, covered schedules and the 64-member limit remain. The 64-client 30-minute campaign, native publication and fleet delivery acceptance must pass before this item is complete. codematch=unreachable.

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

## Stable SDK release preparation (2026-10-01, in progress)

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

Native Intel run `36881757477` still misses the original contact reopen deadline
with a four-block window: it receives 15 resumed blocks and makes 11 retries.
Contact files now request two blocks, leaving transport capacity for control and
receipts. General exchange remains at eight. The 30-second timer, four-ciphertext
ratchet window, 240-second phase bounds, public methods, keys and wire are unchanged.
A seven-second FIFO reproduces the four-request backlog and passes with two requests;
the earlier six-second simulation did not reproduce it and is retained separately.
The correction passes 31 file tests, strict file-transfer Clippy and the unchanged
real encrypted reopen, byte comparison and authenticated completion in 191.85
seconds total. Earlier eight/four-window evidence is preserved. Full committed
workspace and fresh four-platform native qualification remain open; see the
[request-window checkpoint](docs/evidence/stabilization-20261001/contact-request-window.json).

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

Native full Windows packaging run `36852045944` passes GChat qualification but
fails two channel-service tests on OS error 33: the tests read an exclusively
locked log through another handle. Unit snapshots now use the owning handle and
restore its cursor; integration snapshots release and reopen the normal log.
Every original integrity, quota, poison, deduplication and lock assertion remains.
Production code and public API are unchanged. Original native failures are
retained; Linux and fresh Windows checks remain required. See the
[locked-storage checkpoint](docs/evidence/stabilization-20261001/windows-locked-storage-tests.json).

The owner approved up to **20% same-toolchain size growth for this initial feature
release**, followed by **5% after SDK 1.0**. All four desktop/native and both mobile
native/application size checks use one recorded, source-bound policy. The actual
SDK package version selects the limit; 1.0 prereleases and every stable major
automatically require 5%. There is no command-line limit override. Missing native
baselines fail, and exact integer boundaries are checked. Original 5% failures
remain retained failures; fresh native CI against this policy is required.
Recovery, compatibility, signing and installed/deployed qualification are unchanged.
Six focused controls and the full Python/source gates pass; see the
[policy checkpoint](docs/evidence/stabilization-20261001/sdk-size-policy.json).

Native Windows run 36835572270 receives the second resumed full piece at 236
seconds, leaving the 41-byte tail beyond the unchanged 240-second deadline.
Its two unknown-key errors precede reopening by 55 seconds. The durable outbox
restored old retry clocks while occupying the four-ciphertext window; reopening
now retries the original durable application records immediately. Exact cells,
ratchet counters, sequence, expiry and authenticated delivery rules remain.
The real-session regression fails on the original 55-second timer and passes on
the correction, including deferred work and expired-authority refusal. Initial
invalid fixtures remain retained. Corrected Linux source passes 1,151 workspace
tests with 13 retained ignores, the real contact interrupted-file recovery inside
its original 240-second bound, Rustdoc, strict workspace Clippy and both minimal
feature checks. Source-bound native run `36845346885` also passes Linux's 190
backend tests and Windows's 192 tests, including the real contact interrupted-file
recovery; verified provider archives retain those original results. Intel Mac is now running; ARM Mac remains queued. Linux's ten comparisons
grew 10.0–12.8% and fit the approved 20% allowance. Their original workflow
failed under 5%; fresh policy-bound native qualification remains required and
SDK 1.0 remains undeclared. See
[durable reopen checkpoint](docs/evidence/stabilization-20261001/durable-reopen.json).

The JSON HTTP decoder now uses one byte-slice parser and borrowed envelopes for
nested record/public-change variants. Public Serde derives, SDK methods, IPC26
and dependency versions remain unchanged. Expanded public-decoder comparisons
found an overaccepted struct-variant sequence body; that original failure is
retained, and object-only parsing corrects it. SDK tests pass 80 cases, strict
workspace Clippy passes, and all three unchanged released plus three current
consumer graphs compile. Linux IPC opt-3 falls further to 1,282,912 bytes, still
11.6% above the original baseline; the unchanged 5% ceiling remains failed.
Native parent run `36835572270` passes Linux's backend/contact recovery but fails
all ten size comparisons (10–16% growth). Windows's backend fails while independent
measurement continues; both Mac workers are queued. This is not native approval
of the new JSON source or an SDK 1.0 declaration. See
[JSON checkpoint](docs/evidence/stabilization-20261001/sdk-http-json-size.json).
Backend logs now upload immediately after their real native gate, before the
long independent size builds. Each attempt has a separate source-bound archive;
the final complete artifact and original failed job conclusion remain required.
This makes an early recovery failure available for diagnosis while measurements
continue; it cannot authorize a release. Workflow execution remains pending.

SDK codec preparation passes 1,149 workspace tests with 13 retained exclusions,
strict Clippy, Rustdoc, minimal IPC/core checks, three unchanged released consumer
graphs, three current locked consumers and eight Android/Apple dependency graphs.
IPC26 bytes and bounds remain unchanged. Count/write share one bounded zeroizing
postcard flavor; clients link only their message directions, and HTTP replies use
a borrowed JSON envelope with the original reply shapes. No dependency version or
public facade changes. Linux IPC opt-3 falls from 1,561,216 to 1,317,432 bytes,
still 14.6% above the original 1,149,728-byte baseline: the 5% gate remains failed.
Native logs and all measured deltas now survive failures, and independent consumer
measurement runs even after backend tests fail. Original compile/Clippy failures
remain retained. See [codec checkpoint](docs/evidence/stabilization-20261001/sdk-codec-size.json).

Native four-window run `36827922107` still fails contact recovery on all four
platforms. The cluster recovery passes; its unknown-mix-key event
occurs during initial simultaneous setup before reopening. That event alone does
not establish the cause of native missing blocks. Bounded error counters and
test-only block receive diagnostics will distinguish stale setup from stale file
responses without logging identities, keys or routes. Native recovery, all size
profiles, installed acceptance, fleet activation and SDK 1.0 remain open.

The follow-up native run `36820878112` still failed contact recovery on Windows
and Intel Mac; Linux recovered the file but failed the unchanged size ceiling
(IPC opt-3 grew 36%). Those verdicts and logs are retained. Legacy sessions now
keep at most four durable application ciphertexts outstanding per peer, leaving
later original logical records in the durable outbox until an authenticated
receipt releases a slot. GC/2's credited window and independent ACK generation
remain unchanged. A rejected one-slot experiment missed the original 240-second
file deadline; the four-slot contact recovery passes in 171.64 seconds. The full
node suite passes with native CI's serial test execution; the first parallel run's
GC/2 ACK timeout remains a failure. Native qualification and size work remain open.
See [window checkpoint](docs/evidence/stabilization-20261001/legacy-window-recovery.json).

Native run `36814943114` reproduced the unchanged contact file reopen failure on
Linux, Windows and both Macs. The failure logs remain retained. Bulk/control
priority can reorder legacy direct-session DH epochs, leaving encrypted blocks
undecryptable; legacy initial sends and retained retries now share one FIFO lane.
GC/2 credited sessions retain bulk isolation. No keys, receipt rules, wire layout
or deadlines change. The actual contact resume test passes in the cluster in
92.53 seconds against the original 240-second bound. All 492 node tests pass with
two retained ignores, including protected bulk files and direct recovery; strict
workspace Clippy passes. Corrected native qualification is still required. See
[transport checkpoint](docs/evidence/stabilization-20261001/legacy-lane-recovery.json).

The native failures exposed a stale independent consumer lock and two Windows
fixture assumptions about held file locks. Preserve the locks and inspect the
encrypted hosted journal after its clients close. The contact-file worker now
retains eight real durable send completions within the shared 128-action limit;
neither a three-second wrapper nor a control interrupt can admit a duplicate.
The unchanged real contact resume test and a delayed-completion/control regression
pass in the cluster. Updated workspace tests pass 1,144 cases with 13 retained
ignores. The first documentation stage failed after a concurrent consumer check
changed the shared dependency cache; the sequential unchanged-source documentation
and strict workspace Clippy pass. Python runs 205 cases with one skip. All three
locked consumer graphs and the unchanged released consumer compile checks pass.
Native qualification remains open. See
[source checkpoint](docs/evidence/stabilization-20261001/sdk-contract-and-send-window.json).
Retained SDK 0.1.49 source is now compiled unchanged in all three independent
consumer graphs. The supported facade and eventual 1.0 gates are documented in
`docs/STABLE_CONTRACTS.md`; no stable release is declared by these component checks.

Reconcile the independent mobile lockfile's missing SDK serde_json dependency;
keep locked Android/Apple client, relay and optional push graphs reproducible.
Allow default implementations for optional typed RPC methods so existing service
handlers retain source compatibility. The real router regression must return the
default unsupported result and still reject unauthorized callers. No wire,
IPC26, component credential or 64-member policy changes are introduced.
Full native/mobile consumers and the SDK 1.0 declaration remain gated.
The affected source passes 1,143 all-feature workspace tests with 13 retained
exclusions, strict Clippy and Rustdoc. All eight locked Android/Apple role/push
dependency graphs resolve. The first run's stale two-method descriptor assertion
is retained as a failure; the corrected assertion requires the original IDs and
the optional method. Live platform packaging remains separately gated.

## IRC parity 64-member source qualification (2026-09-30)

Merged source `a460d74` passes 1,142 tests, 13 retained exclusions, strict workspace
Clippy, Rustdoc and both minimal-feature checks. Creation/control boundaries and
released IPC23 invitation bytes/handshake pass with the new IPC26 hosted layout.
The separate GChat 64-member network campaign passes; no larger campaign is
required. Paired GChat passes 194 tests, strict Clippy, generated contracts,
all 22 archive consumers, 63 UI tests and Linux desktop compilation. Source
implementation and 64-member qualification are complete. Native installer
publication remains separate. See
[workspace receipt](docs/evidence/irc-workspace-20260930/limit-64-merged-qualified.json).

## IRC/main invitation integration (2026-09-30)

Integrate main's reusable invitations and enrollment without dropping hosted
channels, contacts or the 64-member limit. IPC26 keeps the released IPC22 recovery
and IPC23 invitation discriminants; hosted/file operations follow them with
separate capabilities. Negotiate released IPC23, reject unpublished IPC24/25, and
retain legacy privilege checks. Fixed-byte invitation/recovery fixtures and an
actual IPC23 handshake check the merged layout. Paired GChat passes 194 tests
with three retained exclusions, strict Clippy and generated contracts. Package
checks, frontend and Linux desktop compilation pass.

## IRC parity: retain the 64-member limit (2026-09-30)

The user confirmed the existing limit of **64 members**, including the owner.
Hosted creation, signed policy changes and service capacity advertising enforce
that limit. Qualification targets 64 independent members; no larger campaign is
required. The active 500-member run was cancelled at the user's scope reduction,
its grant revoked and all owned processes stopped. Its original evidence remains
historical, not a capacity pass. Covered receipts, Topic pending and the separate
ordinary-message/replay recovery requirements remain unchanged.

## Owner-controlled membership recovery (2026-09-29)

Implemented explicit, durable batch MLS revocation for stuck membership; original message/ACK journals remain. SDK and IPC22 expose a bound preview. Paired GChat recovery and focused protocol validation are recorded in the membership-recovery receipt; installed profile repair is a separate result. See [contract](docs/MEMBERSHIP_RECOVERY.md).

## Bounded file recovery latency (2026-09-28)

A reopened, already accepted download queries a newly authenticated source without
waiting for the next 30-second inventory poll. Immediate queries retain the first
four-source bound; repeated offers, unaccepted/paused/cancelled transfers and later
sources do not accelerate requests. Periodic source rotation remains in place.

The host admits up to eight file sends while retaining each action until its actual
transport completion. The existing 4 MiB payload budget, 128 pending actions,
request identities, piece verification, recipient accounting and shutdown behavior
remain unchanged. This changes active transfer concurrency, not idle polling or
cover timing. [Recovery checks](TESTPLAN.md#bounded-file-recovery-latency) include
negative results at the previous limits. Exact installed-app qualification remains
required; this source change does not relabel the failed Windows 29 transfers.

## File transport profile writes (2026-09-28)

Remove whole-profile saves only for the authenticated piece application type.
These records use independent nonces and do not advance retained text state;
their separate cache validates and journals file pieces. Preserve ordinary text,
stateful event, explicit-save and shutdown barriers. The two-profile regression
measured 32 profile saves and 1,938,231 profile bytes for 65,536 payload bytes on
the original runtime, versus zero file-related profile saves/bytes after the
change. This measures write amplification, not Android latency or CPU savings.
Source checks and the actual application's bounded transfer gate remain separate.

[Source-bound checks and controls](docs/evidence/piece-profile-writes-20260928/summary.json): 32 runtime passes, 20 file-package passes, strict Clippy and outbound-only compilation.

## Windows named-pipe preface (2026-09-28)

The retained Windows installer reached two connected profiles then its service
exited with ERROR_CANNOT_IMPERSONATE (1368). The listener checked the client SID
before reading data. Read one byte with a two-second bound, retain it for the
unchanged frame parser, then apply the existing current-user impersonation check.
Drop empty/disconnected probes without exposing them to application handlers.
Keep SID pins, owner-only ACLs, remote-client rejection and fatal auth failures.
Unix, wire formats, relay routing and personal profiles remain unchanged.
Native regression/source/mutation checks must pass before runtime publication.

## Voluntary departure and ownership ACKs (2026-09-27)

The native Mac ownership-transfer case exposed a pending successor announcement
that could be invalidated by the old owner's removal. It also reproduces on
Linux with a bounded 20-second diagnostic wait. Keep voluntary departures in the
current epoch until admitted messages receive their authenticated ACKs. Check
under the removal lock; preserve explicit administrative removal and durable
rollback behavior. The unchanged application regression passes with this guard.
Admission and ownership-transfer barriers consider unacknowledged recipients
still in the authenticated roster. Explicit revocation does not turn retained
messages into delivered messages or transfer their ACK identity to a reused
nickname; it also cannot block every later admission on a departed member.
Full affected-package checks and a guard-removal negative control are retained
with the source-bound handoff; no older release receipt qualifies this change.

[Completed source checks and negative controls](docs/evidence/ownership-departure-20260927/summary.json): 357 node-library passes, 12 integrations, strict Clippy and the unchanged GChat ownership case.

## Private executable fixture on macOS (2026-09-27)

R07: preserve the production owner/mode/link security checks. Set the test file to the current primary group before applying unsafe privilege bits, and assert that chmod actually retained each requested mode. This fixes macOS silently stripping setgid from wheel-owned temporary files. Original fixture failure reproduced on native Mac; all three package cases and strict Clippy pass with /private/tmp. [Evidence](docs/evidence/private-executable-fixture-20260927/summary.json). Full platform release checks remain separate.

## Known invitation refusals (2026-09-27)

R04: the shared in-process SDK retries only the two authenticated pre-admission busy refusals, retaining the prepared identity, invitation and original absolute deadline. Other errors and ambiguous outcomes are not repeated. SDK 67 cases, paired GChat core 45 cases, strict SDK Clippy and outbound-only compilation pass. Five actual clients joined and all 20 cross-client messages received authenticated ACKs. The separate 16 MiB recovery test failed its unchanged 180-second completion bound; this is not release or Android qualification. [Evidence](docs/evidence/invitation-busy-retry-20260927/summary.json).

## Admission and bootstrap ordering (2026-09-27)

R04: prevent a new MLS admission from overtaking retained channel wires or an unfinished newcomer bootstrap. Keep exact Welcome replay and existing bounded invitation retries. A per-channel transient finalizer guard spans directory publication and bootstrap persistence; an always-present durable bootstrap snapshot remains gated by the newcomer's authenticated ACK. Source checks pass: 355 node, nine invitation integrations and strict Clippy. Final actual Android delivery remains a separate gate.
[Evidence](docs/evidence/channel-admission-20260927/summary.json).

## Production subscription fixture (2026-09-27)

R07: all three protected subscription/revision recovery tests now use the current
responsive production profile 46 instead of historical fixed-rate profile 22.
Assertions and the 20-second deadline are unchanged. Each passes on Linux,
Apple Silicon Mac, Intel Mac and Windows; strict node Clippy passes. Optional
local diagnostic events contain only fixture indices, dispatch decisions and
class counts. Production runtime bytes/constants are unchanged.
[Evidence](docs/evidence/production-subscription-20260927/summary.json) preserves
the old native failures and diagnostic setup failures. This does not qualify
a new full native pair or an installed artifact.

## Manual reconnect replay isolation (2026-09-27)

A release regression reproduced a manual reconnect code reusing an already
authenticated background directory ciphertext. Keep an independent, bounded
per-channel export cache; commit the MLS send ratchet before returning a code
and never submit that ciphertext to the background control queue. Preserve
wire format, recipient authentication, expiry, epoch and exact-import replay
checks. No checkpoint format change; a restart can mint a fresh code. Cluster
red/green, 352 node tests (two existing exclusions), 83 GChat core tests
(three existing exclusions) and both strict affected-package Clippy checks pass.
[Source-bound evidence](docs/evidence/manual-reconnect-20260927/summary.json)
retains the original replay failure and harness failures. Source and formatting
audits pass; codematch was unavailable. Installed/native-platform rollout is separate.

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

## IRC parity — 2026-09-29, Codex

Implementing the user-approved classic IRC parity plan in the contained
`irc-parity` component worktrees. The first gate is ciphertext-only hosted MLS
admission, with legacy channel permissions preserved. Contacts-only identity,
500-member qualification and no service decryption are fixed requirements.
[Feature and acceptance ledger](docs/IRC_PARITY.md). No parity feature or new
release is qualified by this planning checkpoint.

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


## Five-relay carrier update — 2026-09-23

The shared Rust GC/2 application carrier now selects exactly three independent middles between the retained entry and terminal inbox. Whole-path validation rejects reused IPs/service identities, excluded endpoints and expired authority before opening streams. Minimal payload route integration, uniform framing, passive attachments, replicated durability and fleet rollout remain pending.


## Transfer recovery — 2026-09-23

Accepted downloads retain verified pieces and resume automatically after restart or temporary conversation membership loss. No requests or incoming pieces are accepted without current authorization. Explicit pauses/cancellations remain stopped. Reopening repairs the older automatic membership-pause marker; other errors keep their existing recovery behavior. Transport completions continue to arm retries while files are disabled or roster refresh fails.

Validation: 51 component tests passed, two existing qualification tests ignored, including an overnight restart at 80% and a send completion delivered while locked. Evidence: `test-evidence/file-resume-20260923/verification.json`. Android live recovery remains pending; these gates do not establish fleet end-to-end acceptance. No new dependencies.


## Interrupted-download route recovery (2026-09-23)

The client can verify a stale inbox descriptor with a message-free, authenticated cover deposit using the existing relay protocol. It reuses only the short expiry explicitly accepted by the pinned relay for that exact queue, epoch and capability. This does not renew a lease or repair a missing inbox. The live Android download and full fleet acceptance remain open until verified on the deployed clients.

## Bounded release qualification (2026-09-25)

Owner-approved: replace the release-blocking 1 GiB campaign with a 16 MiB interrupted-transfer/hash/reopen check, 180-second completion and 600-second overall ceiling. Preserve both failed large-file attempts; capacity qualification runs separately. Authentication, persistence, signatures and rollback remain required. Implementation and cluster validation are tracked in GChat `target/release-automation-20260925/`; no new installed or fleet qualification is inferred.

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

# Authenticated referral retry after the 04:00 boundary, 2026-09-28

The signed Linux 0.1.30 bounded transfer reached 15,990,784 of 16,777,216 bytes
before its unchanged 180-second completion deadline failed. Both clients lost
usable routes at the hourly authority boundary and regained them about a minute
later. Offline authenticated inspection of the stopped disposable profiles showed
fresh retained directory entries at 04:01:01–02 UTC; later authenticated relay
observations showed all eight fresh referrals. The original failure is retained;
this is not a successful file gate or permission to relax its deadline.

A successful own-only guard reply now starts a separate bounded referral retry at
five seconds, backing off through 10/20/40/80/160/300 seconds. Failed requests keep
60/120/240/300 seconds; complete directories keep five minutes. This does not
extend authority, replace guards, increase entry counts, dial from an application
request, or alter data/cover scheduling. The same authenticated TLS regression
fails against the old scheduler at 15 seconds and passes the new scheduler in
5.36 seconds. Failed-request pacing and the maintenance ceiling have explicit
checks. The new application artifact still requires its own bounded file/reopen
and rollback validation. `codematch=unreachable`.

Validation: 93 routing package passes, zero failures, one existing native probe
exclusion; strict routing Clippy, legacy feature check, formatting and source
audit passed. [Receipt](docs/evidence/authenticated-referral-retry-20260928/summary.json).
The first green harness invocation reused a stale red binary from equal archive
mtimes; that invalid result is retained separately from the rebuilt passing run.

IRC-2/IRC-3 checkpoint: ordered policy enforcement passes component tests and
strict Clippy. IRC-8 has one source-bound 500-member MLS capacity pass, with
4,990 authenticated receives from ten concurrent senders; full client/network
qualification remains open. See the parity ledger and its evidence receipt.

IRC-3 lifecycle checkpoint: departure, kick, member-assisted rekey and sealed
pending recovery pass, along with dual service/client message-class authorization.
IRC-4 through IRC-8 application and transport integration remains in progress;
no UI/release completion is claimed.

IRC-1/IRC-2/IRC-3 integration checkpoint: bounded service API, scoped readers,
single-use invitations and protected routing are implemented. IPC22 and the
opt-in durable runtime client are connected; four real-service recovery/storage
tests and strict runtime/SDK/application checks pass on the initial client
source. GChat, recipient receipt aggregation and the remaining parity/release
ledger remain open. See docs/IRC_PARITY.md for evidence and current limits.

## IRC-4 file integration checkpoint — 2026-09-29

The typed hosted/contact file profile, IPC23 capability, encrypted cache worker,
independent hosted file-event cursor and GChat routing are implemented on the task
branch and remain under qualification. The hosted inbox tests pass, including
uncertain publication, restart, chat-consumer independence and moderated completion.
`test-evidence/irc-parity/files-inbox-02.log` records 18 selected passes. The first
contact-file fixture runs failed because the bare runtime did not enable durable
applications; the corrected fixture now follows the application's explicit opt-in.
Do not claim verified end-to-end files or release readiness until that gate and
the GChat journeys pass. Current 500-member network and native gates remain open.

### IRC-4 recovery qualification checkpoint — 2026-09-29

Hosted whole-file verification rejects modified ciphertext and resumes from an
encrypted cache with the publisher offline (`files-modern-08/09/10.log`). The
public GChat contact file journey, shared quota/activity/error handling and strict
workspace checks pass in `files-routing-05/06.log`. These are bounded library/local
fixture results, not the 500-member protected-network or installed-app gate.

The larger direct-contact restart case retains verified pieces but fails to finish.
`files-modern-10.log` captures accepted contact renewal followed by authenticated
frame decryption failures; transport admission is not counted as download success.
The focused PQ renewal regression and archive-v1/v2/v3 migration tests are pending.
Contact permission separation and a full GChat regression are running.

The focused node regression reproduces a pre-existing renewed-bundle/retained-session
KEM mismatch (`files-pq-red-01.log`). Established sessions now retain their
handshake-bound keys when routing/first-move bundles change; PQ refresh and DH
ratcheting continue. Its forced-refresh case and old hosted archive migration pass
in `files-modern-12.log`. That run was evicted for exceeding the pod's 5 GiB
emptyDir limit during the larger file test, so completion is unqualified. The
fresh `files-modern-13.log` run uses one package feature graph and library tests.

### IRC-3 opt-in directory checkpoint — 2026-09-29

Explicit operator-signed publication now connects persistent service discovery,
validated runtime results, IPC24 and GChat browsing. Private/secret/closed and
unpublished rooms are omitted; topics remain encrypted. Three directory tests
and strict seven-package Clippy pass in `directory-02.log`. That combined run's
separate GC2 fixture failure is retained; the corrected inbox-consuming regression
passes 65 authenticated messages and two measured PQ refreshes in
`files-gc2-renewal-04.log`. Broader current regression, protected-network capacity
and release qualification remain open. See `docs/IRC_PARITY.md`.

### IRC-8 durable capacity campaign — 2026-09-29

Added a source-bound durable client/service campaign beyond the earlier MLS-only
gate. The twelve-client release smoke passes (`runtime-capacity-03.log`): ten
concurrent senders, every recipient receipt, withheld offline completion, reopen,
AEAD piece storage, kick/rekey and replacement admission. It records covered/bulk
JSON volume and local timings. The explicit 500-client campaign is running;
transport is in-process, so neither result qualifies protected-network latency.
The detailed classic feature mapping is `docs/IRC_FEATURE_MATRIX.md`.

### IRC-2/IRC-8 responsive hosted ownership — 2026-09-29

The runtime previously held its hosted mutex across remote synchronization, which
could delay a new local send by the whole request deadline. The owner now gives
local mutations priority, interrupts network waits and retries across existing
durable boundaries. Ordinary polling does not repeatedly interrupt joins.
`hosted-responsive-01.log` passes a real MLS/service case with a withheld reply
after fsync: local queue feedback within 200ms, exact deduplication, no false ACK,
reopen/completion and prompt close during a stalled read. Strict seven-package
Clippy passes, including the capacity-fixture iterator correction. Broader retained
integration/regression evidence is `directory-regression-04.log` (tests passed;
its original strict stage caught that test-only iterator lint).

### IRC-2 hosted service deployment preparation — 2026-09-30

Added bounded systemd/loopback configuration and exact HTTPS route templates for
the installed signed origin, with retained-state rollback instructions. The
source255f9cd release binary builds successfully on the bounded HEL worker; its
hash is retained in docs/evidence/irc-hosted-service-20260930/build.json. Deployment
and actual protected-network/GChat qualification remain in progress.

### IRC-2 installed-network origin regression — 2026-09-30

The first connected live GChat run exposed missing hosted-provider authorization:
endpoints came from signed defaults but the protected route had an empty allowlist.
The runtime now merges current verified providers with the explicit catalog hosts
before hosted network operations, preserving the eight-host bound and refusing
unsigned destinations. Local queue/history operations remain independent of trust
refresh. `hosted-origins-02.log` passes the real runtime authority regression and
strict seven-package all-target Clippy; the initial test-fixture compile failure
is retained. The corrected release pair and live journey are being rebuilt.

### IRC-2 relay HTTPS egress configuration — 2026-09-30

Read-only preflight found all eight installed relay allowlists empty. The hosted
service requires the two exact signed provider hosts at the egress boundary as
well as the client. Added a bounded single-host rolling configuration helper:
reviewable dry run, preserve prior origins, refuse an existing task drop-in,
validate the unit and restore the prior configuration on failed restart. The
first dry run is correct; serial rollout and protected application checks follow.

Relay egress rollout completed serially on r1–r8: only the two signed provider
hosts were added, every unit/listener returned and restart counters remain zero.
No relay executable, key or retained state changed. Receipts are retained in
docs/evidence/irc-hosted-service-20260930/relay-origins.json; application routing
qualification is still pending the corrected live GChat journey.

### IRC-2 hosted snapshot transport recovery — 2026-09-30

The protected-network GChat run created a channel and accepted its encrypted
topic, then lost a TLS circuit while an offline-owner newcomer read admission
state. Read-only snapshot pages now allow four transport attempts within a
30-second page deadline, retaining the prepared identity and pinned transcript.
Authenticated service refusals are not retried. Membership writes keep their
existing durable retry semantics. `snapshot-recovery-03.log` passes recovery
after two lost authenticated reads, one membership change, immediate authority
refusal and bounded exhaustion; strict seven-package Clippy passes. The earlier
network failure remains retained; the updated live journey remains to be run.

### IRC-8 vendored package qualification — 2026-09-30

The isolated archive gate stopped before packaging because Cargo requires an
explicit registry when dependencies come from a directory replacement. Name
crates-io as the package destination while retaining the runner's vendor source
for dependency resolution. The first failure remains in packages-b6f0b60-01.log;
archive/consumer validation of the corrected invocation is pending.

The vendored destination correction reaches all twenty Rust package archives.
The archive-content gate then caught missing license texts in the new channel
service crate. Include the repository's existing MIT and Apache texts, matching
the other crates. This adds no new licensing terms or dependency. The failed
archive gate is retained as packages-4df1c06-11.log; corrected consumers are next.

### IRC-2 covered polling round trips — 2026-09-30

The fourth actual GChat journey passed offline-owner admission/Topic pending,
authenticated topic handoff, moderation/voice/notices, offline recovery and a
verified 16 MiB partial-file restart with an unvoiced completion receipt. It
missed latency targets: 9.165s small-room message/ACK and about 299s resumed
verification. Keep those failures. Combine transcript reads, at most sixteen
consumer-committed ACKs and at most thirty-two sender receipts into one covered
poll. Both read scopes validate before ACK storage, with unchanged signatures,
quotas and durability. Service-info negotiation retains the older request flow.
The preceding full seven-package suite passed 690 tests (seven explicit ignores).
Current hosted regressions, three poll-specific cases, five service API cases
and strict checks pass; evidence is docs/evidence/irc-covered-poll-20260930.
A new paired build/deployment and live timing check remain required.

### IRC-8 durable capacity baseline and hosted rollout — 2026-09-30

The durable 500-client baseline on 64632fd timed out at its unchanged two-hour
bound (exit 124). The last admission marker was 476; the run did not produce a
completed send/recovery/churn result. Retained process samples show 5.60GiB peak
RSS and 261.65GB cumulative writes. This failed baseline motivates bounded replay
checkpointing; see `docs/evidence/irc-durable-capacity-20260930/baseline-01.json`.
The source changes and replacement campaign are not yet qualified at 500.

The installed HEL ciphertext service now runs 8687749 and advertises combined
covered polling. All four pre-existing state files were unchanged across its
restart; the old 255f9cd binary remains available for rollback. The WebPKI probe
and deployment receipt are `docs/evidence/irc-hosted-service-20260930/poll-rollout.json`.
GChat live05 passes correctness through the installed network, while small-room
ACK 6.146s and 16MiB resume285.756s still fail the latency targets.

### IRC-2/IRC-8 bounded replay and durable views — 2026-09-30

Replaced per-record sealed-state writes with 16MiB-bounded prefetch and short
synchronous replay batches, each checkpointed before yielding. Lost prefetch
replies leave the previous durable prefix intact; validation or save failures
still fail closed. Published channel/file views avoid waiting behind network I/O,
retain presence deadlines, and clear on errors or closure. Consumer commits now
receive local priority. All 25 hosted runtime cases and strict runtime Clippy pass
in `docs/evidence/irc-checkpoint-batch-20260930/summary.json`. The replacement 500
campaign and paired protected-network latency remain outstanding.

The retained 8853149 package staging results now include the separate successful
npm archive install/export checks after filling the offline metadata cache.
All 20 Rust archives passed normalized-manifest/license checks and the external
renamed consumer compiled. The original full runner remains recorded as failed
at its npm-cache step; these component results do not qualify the latest paired
release. `docs/evidence/irc-package-staging-20260930/summary.json` records archive
hashes, runner adaptations and logs. Nothing was published to package registries.

### IRC-4 bounded hosted file window — 2026-09-30

The live two-client run now meets small-room delivery and full-workflow targets,
but resumed verification remains 234.873s against 180s. Hosted file transfers now
keep two immutable pieces in flight while the channel owner continues covered
sync. Local authority is checked both before the request and before its result is
exposed; cache verification and saved piece progress remain unchanged. Real held
service responses prove the two-request bound, concurrent chat, shutdown and
revocation refusal. All 60 runtime library tests pass (two explicit ignores),
and strict all-target runtime Clippy passes. Evidence:
`docs/evidence/irc-blob-window-20260930/summary.json`. Live latency remains open.
The batching count test now freezes only its scheduling clock to avoid making
its write-count assertion depend on debug-build CPU speed. Real-time capacity
and responsiveness tests keep their original clocks and bounds.

### IRC-8 paired archive consumer gate — 2026-09-30

The full release-mode package runner passed on clean GComs 441efb5 and GChat
12a8a93: 20 normalized Rust archives, isolated renamed Rust and npm consumers,
paired GChat Rust, generated bindings, frontend checks/tests/build, dependency
notices and Linux desktop compilation. Original checkouts remained unchanged and
nothing was published. The disposable Debian runner used verified locked Rust
archives and an isolated sysroot of signed-APT-selected desktop dependencies.
Earlier missing-cache, source-hygiene and library setup failures remain retained.
`docs/evidence/irc-package-staging-20260930/paired-pass.json` binds the sources,
archives and logs. The subsequent 907e54f file-window change still needs the
current-source package gate and installed/native runtime qualification.

The live06 temporary bootstrap grant was revoked after both daemons stopped;
operator file ownership and0600 permissions were preserved. Receipt:
`docs/evidence/irc-hosted-service-20260930/grant-revocation.json`.

### IRC-8 replay cost follow-up — 2026-09-30

The second 500-client campaign admits all 500 but still accumulates large write
volume during replay. The replay checkpoint window is now 75ms between records,
with the same 16MiB prefetch bound and checkpoint-before-yield rule. Roster change
detection uses a set instead of scanning the old roster for every current member.
The 26 hosted cases and strict runtime Clippy pass; the 12-client durable smoke
also passes and reports aggregate replay checkpoint counts. Current 500-client
performance remains unqualified. See `docs/evidence/irc-replay-budget-20260930`.
The full workspace run on older 441efb5 hit the debug-speed-dependent count test;
its failed log is retained. That test's controlled scheduling clock was corrected
in `907e54f` and passed the full runtime library run before this follow-up.

### IRC-8 current paired archives and live timing — 2026-09-30

The full archive/consumer gate now also passes on GComs `65b54c7` and GChat `d4ff03d`,
including the two-piece file window and 75ms replay batch. The same 20 Rust
archives, external Rust/npm consumers, paired GChat tests/frontend and Linux
desktop compilation pass without publishing packages or changing source inputs.
Evidence: `docs/evidence/irc-package-staging-20260930/current-paired-pass.json`.

The actual two-client protected-network journey on runtime `907e54f` passes both
correctness and its fixed latency targets: 110ms local feedback, 2.409s delivery
plus covered receipt, 3.328s offline-owner join after network readiness, 170.050s
resumed 16MiB verification and 297.114s full file workflow. Exact hash verification,
Topic pending/handoff, moderation and unvoiced file completion all pass. GChat
retains the source-bound `window-07.json` receipt. The temporary bootstrap-only
grant was revoked after both daemons stopped; accepted channel logs remain.
This is a two-client pass, not 500-member or native installed qualification.
The full workspace and unchanged-bound 500-client campaigns remain running.

## Inbox recovery at the retained-cleanup bound (2026-09-29)

The live channel repair uncovered an independent recovery loop: after retained
attempts failed, every later round requested a replacement even when six retained
cleanup groups made installation impossible. At that bound, a still-live retained
inbox now gets the existing authenticated restoration path again, inside the same
outer deadline/backoff. Normal replacement remains available below the bound.
No queue or message is discarded; sealed authority, expiry, cleanup bounds and
failed-checkpoint refusal remain unchanged. `codematch=unreachable`.

## Keep receiving while owner announcements are backpressured (2026-09-29)

After explicit provider configuration, live recovery still failed with local
`direct retained payload admission: relay lane queue is full`. Authenticated
queue restoration and its durable owner checkpoint had already succeeded; peer
announcement admission then incorrectly kept all inbox subscriptions paused.

Routed owner recovery/replacement now marks announcement pending and resumes
receiving after its existing durable authority checks. The normal owner loop
retries announcement admission without blocking inbox or channel recovery;
admitted control records still belong to durable direct maintenance. Every
restoration, including after restart, recreates the announcement intent. Full
outboxes do not silently mark announcements complete. No retained payload,
capability, authority deadline, queue bound or delivery ACK is discarded.

### IRC-8 trunk integration and IPC compatibility — 2026-09-30

Integrating current trunk eef71ea preserves owner-controlled legacy membership
recovery and inbox restoration fixes. IPC25 keeps the published IPC22 recovery
discriminants, appends hosted/file variants, and rejects the conflicting
unpublished task IPC23/24 dialects before dispatch. Hosted and modern-file
capabilities require IPC25. Fixed original recovery bytes, older capability denial
and handshake refusal regressions are included. Paired merged qualification is
running; earlier live/archive results retain their original source bindings.

The 500-member admission log measured 339,264,618 bytes, exceeding the deployment
profile's 256 MiB channel quota. The supplied and installed HEL profile now allows
1 GiB/channel within the unchanged 4 GiB aggregate ceiling, exact seven-channel
allowlist and existing rate bounds. Restart preserved all retained state and
HTTPS Info; see `docs/evidence/irc-hosted-service-20260930/capacity-quota-rollout.json`.
This corrects storage headroom, not replay latency. The original serial capacity
campaigns remain unchanged; an additional four-owner concurrent replay campaign
retains independent validation/archives and all original send/recovery/churn
assertions, reporting its scheduling separately. No security check is skipped.

Merged-source archives pass on GComs `0e7db6a`/GChat `5533b1e`: all 20 Rust archives,
isolated Rust/npm consumers, GChat Rust/generated/frontend checks and Linux
desktop compilation. `docs/evidence/irc-package-staging-20260930/merged-paired-pass.json`
records the real clean commits and archive hashes. The full pre-merge workspace
gate on `65b54c7` also completed: 1,096 tests passed, 12 explicit ignores, 129 suites;
strict Clippy, documentation and minimal core/IPC builds pass. Its separate
receipt is `docs/evidence/irc-workspace-20260930/pre-merge.json`; the merged
workspace rerun is active. No package registry publication or installed release
claim follows from either result.

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

The unchanged serial batch02 campaign (`3be4455`, 25ms batches) reached its
7200-second limit with exit124. All 500 members were admitted in 709.945s; the
last catch-up marker was 176 clients at 6950.801s. The last resource sample
recorded 225,198,874,624 bytes written. It did not reach the full message/offline/
file/churn phases and is not a capacity pass. The source-bound failure receipt is
`docs/evidence/irc-durable-capacity-20260930/serial-batch-02.json`. The later 75ms
serial and separately scheduled four-owner campaigns remain unchanged and active.

The full merged GComs `0e7db6a` gate completed: 1,110 tests passed, 13 explicit
ignores, 129 suites, strict workspace Clippy, Rust documentation and minimal
core/IPC builds. `docs/evidence/irc-workspace-20260930/merged.json` retains its
exact log hash. This qualifies the merged implementation before the new deferred
replay concurrency follow-up. The actual 12-profile application smoke verified
12 independent identities and 110 recipient signatures for ten simultaneous
senders, but the returning owner took 14.537s to replay eleven admissions after
network readiness (10s target). A bounded two-read replay window is now under
validation; originals and fixed deadlines remain unchanged.

### IRC-8 deferred reads and live session memory — in validation

Hosted replay prefetches two immutable deferred reads concurrently within the
unchanged 16 MiB batch, then applies their authenticated records in order. The
old sequential code fails the new held-response control after three seconds;
the changed code passes 28 release hosted cases and two explicit capacity ignores.
The strengthened test observes the second response returning before the first,
checks the two-read bound and verifies cancellation/reopen of the original prefix.
No receipt, transport class, protocol/IPC, MLS or persistence validation is skipped.

The live archive also drops its temporary sealed session buffer after checkpoint
or restore. Each save still serializes the actual MLS state, the disk format is
unchanged and uncertain saves poison the owner as before. A separate regression
covers retained on-disk state, exact reopen, actual replacement failure and buffer
release. The full current runtime/strict gate and updated release hosted run are
active. An earlier follow-up build was evicted after exhausting its 5 GiB emptyDir;
its interrupted gate is not a pass. Validation now uses an explicitly permitted
12 GiB persistent scratch volume. The completed earlier 1,110-test merged gate
and all source-bound failed capacity/timing receipts remain retained.

The combined `40b440d` follow-up now passes 29 release hosted cases, the complete
63-test runtime library suite (three unchanged exclusions) and strict runtime
all-target/all-feature Clippy. Source hashes, negative control and the interrupted
volume-bound run are recorded in `docs/evidence/irc-replay-window-20260930/summary.json`.
The current full workspace rerun, new release application binary and source-bound
500-client concurrent campaign are active. The previous 12-profile recovery miss
remains a failure until the new actual network run measures it again.

The original four-owner concurrent campaign on `0e7db6a` was OOM-killed at its
unchanged 8 GiB memory limit at 02:31:25 UTC. The last observed marker was 476
clients caught up; it is not a completed capacity pass. Kubernetes exit137 and
the limitations of the retained partial logs are recorded in
`docs/evidence/irc-durable-capacity-20260930/concurrent-04-oom.json`. The current
`40b440d` campaign includes the sealed-buffer release and retains the same CPU,
memory, replay concurrency and 7200-second deadline.

The unchanged 75ms serial baseline (`65b54c7`) also timed out at 7200 seconds,
with all 500 identities admitted and the last reported catch-up marker at 176
clients / 7152.111 seconds. Its complete log, resource samples and exit124 are
retained in `docs/evidence/irc-durable-capacity-20260930/serial-window-03.json`.
This does not qualify capacity; the current four-owner `40b440d` run remains
separate and active under its original limits.

The new actual 12-profile protected-network campaign now passes correctness and
all measured targets on GComs `40b440d` / GChat `c5bbfe8`: owner recovery 6.130s,
maximum burst feedback 121ms, 220 covered recipient signatures and 106.008s resumed
16MiB verification. Independent replacement, no historical ciphertext, resource
coverage and cleanup pass; the grant is revoked. The GChat source-bound receipt
is `docs/evidence/irc-hosted-capacity-20260930/smoke-12-02.json`. This is not a
500-member pass. Current small-room, full workspace/package, scale and installed
release gates remain open; the IRC ledger records the current proof boundaries.

The current `40b440d` full workspace gate is complete: 1,112 tests passed, 13
unchanged explicit exclusions, 129 suites, strict all-target/all-feature Clippy,
Rust documentation and minimal core/IPC builds. See
`docs/evidence/irc-workspace-20260930/replay-qualified.json`. The same source with
GChat `c5bbfe8` also passes live09 small-room correctness and fixed timing:
113ms feedback, 3.933s covered display/ACK, 7.857s offline-owner join, 164.709s
resumed 16MiB verification and 329.148s whole file workflow. Topic pending/handoff,
moderation, notices and actual offline/file receipts pass. Its temporary grant
is revoked. Full GChat/package consumers and separate 500-member campaigns remain
active; native installed qualification and normal main publication remain open.

The current four-owner runtime campaign completed all 500 catch-ups and reached
sending at 3928.692s under the original 8GiB limit, then failed at 4009.46s on the
fixture's 2000-record receipt quota. Ten senders require 4990 recipient signatures.
Production already uses 100000 records; only the test fixture is being aligned
with that deployed setting. The original failure is retained in
`docs/evidence/irc-durable-capacity-20260930/concurrent-05-quota.json`. Every receipt
assertion and the original CPU/memory/7200s limits stay in the new campaign.
This is not a completed capacity pass or a production-code change.

The paired archive gate on `40b440d` / `c5bbfe8` passes all 20 normalized Rust
archives, external renamed Rust and npm consumers, paired GChat Rust/frontend,
generated contracts, notices and Linux desktop compilation, with original source
unchanged. All 22 archives (20 crates/two npm tarballs) are retained separately
from the source repository. See
`docs/evidence/irc-package-staging-20260930/replay-paired-pass.json`. This precedes
the test-only capacity receipt-quota correction; its production code is identical.
The corrected fixture is being rebuilt/checked before its fresh capacity run.
No registry publication or native installation follows from this build result.

The test-only `1d11de1` quota fixture passes release compilation, 28 hosted tests
(two unchanged ignored capacity cases), and strict runtime all-feature/all-target
Clippy. A fresh binary-only worker runs the corrected capacity test under the
original 4CPU/8GiB/7200s limits; see
`docs/evidence/irc-durable-capacity-20260930/quota-fixture-checks.json`.
The independent protected-network500 campaign failed member-83's 180-second
cold bootstrap before joining, after 81 total channel admissions. All daemons
stopped and its grant was revoked; original private profiles are retained for
diagnosis. Paired GChat retains its decisive failure receipt. Neither500 gate
is complete; the current paired188 Rust/strict and package gates are complete.

### IRC-8 relay aggregate capacity — in validation

A private clone of failed member-83 connects in33.271s without the fleet load,
leaving its original profile unchanged; the diagnostic grant is revoked. A
separate retained-profile load diagnostic is collecting transport counters.
The deployed relay source caps each service at128 forwarding circuits; aggregate
socket measurements approach that bound as clients accumulate. This is a
capacity hypothesis, not yet a definitive explanation of the original timeout.

Explicit operator circuit/connection budgets are implemented with default
128/1024, hard ceilings4096/8192, validation before listen, and unchanged source
and per-entry bounds. Real stream saturation/release tests are being qualified.
All eight native relays now run the qualified full-feature binary at the original
128/1024 capacity settings, with identity files, existing drop-ins and resource
limits preserved. See `relay-control-rollout.json` in the durable-capacity
evidence directory. The matched load comparison remains in progress; no new
network-capacity pass is claimed.

The retained-profile load diagnostic reproduced a failure at68 started profiles
(65 ready), timing out member-64 after180s. Its transport counters retained two
ready entries, an eligible terminal route and zero restored inbox subscriptions;
other stalled profiles reported explicit logical-circuit refusals. All cloned
daemons stopped, originals stayed byte-identical and its grant was revoked.
See `docs/evidence/irc-durable-capacity-20260930/bootstrap-load-01.json`. A paired
old/new operator-budget control is still required to isolate capacity from other
relay-source changes.

The isolated original owner's 80 missed admissions converge to81 members in
96.815s after network readiness, missing the unchanged10s target without fleet
congestion. Its original profile stayed untouched and its diagnostic grant was
revoked. See `docs/evidence/irc-durable-capacity-20260930/owner-backlog-81.json`.
The user selected a 10-second target for ordinary offline-message recovery and
visible progress for large membership backlogs. GChat is implementing that display;
the earlier 96.815-second result remains a failure under its original target.


### IRC-8 durable 500-client qualification — 2026-09-30

The concurrent durable-client campaign passes on fixture `1d11de1` and production
`40b440d`: 500 independent members, ten concurrent senders, 5,000 message deliveries,
4,990 authenticated recipient signatures, offline reopen, encrypted piece transfer,
kick and replacement. It finishes in 4,166.48 seconds within the unchanged
7,200-second, 4-CPU, 8-GiB budget; sampled high-water RSS is 7,483,960 KiB.
See `docs/evidence/irc-durable-capacity-20260930/concurrent-06-pass.json`.
This is in-process transport, not a protected-network GChat or installed release pass.
All earlier quota, deadline and memory failures remain retained.

The complete workspace on operator-capacity source `250ece7` also passes:
1,115 tests, 13 unchanged exclusions, strict Clippy, rustdoc and minimal feature
checks. See `docs/evidence/irc-workspace-20260930/relay-capacity-qualified.json`.
The full relay executable preserves push-gateway support; fleet comparison is next.

The paired package gate also passes on `250ece7` / `c5bbfe8`, including all
20 Rust and two npm archives, external consumers, generated contracts, UI and
Linux desktop compilation. All archives are downloaded and hash verified.
See `docs/evidence/irc-package-staging-20260930/relay-paired-pass.json`. This
precedes GChat’s new catch-up display, which needs its own paired validation.

The same-binary relay control at 128/1024 again stalls: 76 profiles start and
75 become ready; member-73 exceeds the unchanged 180-second bootstrap bound.
Cleanup, grant revocation and original-profile preservation pass. See
`docs/evidence/irc-durable-capacity-20260930/bootstrap-load-02-control.json`.
The same binary is now being rolled to the explicit hosted budget before the
matched repeat; the control failure is retained.

The matched hosted-budget rollout is complete on all eight relays: 2,048
circuits and 4,096 connections, with the same binary, identity files, original
configuration and resource ceilings as the control. See
`docs/evidence/irc-durable-capacity-20260930/relay-hosted-rollout.json`.
The retained-profile comparison is running; 500-member application qualification
still remains separate.

### IRC-8 matched relay capacity result — 2026-09-30

The same relay binary and 85 retained independent client profiles pass bootstrap
at the hosted 2048-circuit/4096-connection limits: all ready in 180.305 seconds
and held online for 30 seconds. The matched 128/1024 control stopped at 75 ready.
Original profiles are unchanged, clients stopped and the temporary grant revoked.
See `docs/evidence/irc-durable-capacity-20260930/bootstrap-load-03-hosted.json`.
This qualifies the bounded bootstrap diagnosis; the 500-member application
workflow remains a separate live gate.

### IRC-8 bounded admission recovery follow-up — 2026-09-30

The current 12-member network smoke failed on member-11 after a transient
independent-route outage exhausted four read attempts in about 600 ms. Ten peers
had joined; the failure remains a failure, all daemons stopped and the grant was
revoked. Snapshot read retries now back off 1/2/4 seconds within the existing
30-second page deadline and four-attempt limit. They retain the prepared leaf and
pinned transcript, never repeat a membership write and cannot wake route
maintenance. A held-route regression requires one eventual membership admission.
Qualification of this change is in progress; prior 250ece7 results keep their scope.

The final snapshot-read maintenance source `a715a70` passes the full GComs gate:
1,116 tests, 13 unchanged ignored tests, strict workspace/all-target Clippy,
rustdoc and both minimal feature checks. Evidence:
`docs/evidence/irc-workspace-20260930/snapshot-maintenance-qualified.json`.
Paired GChat and protected-network application qualification remain in progress.

Smoke05 exposed removed-member replay failure: an accepted rekey was followed
by a private-state GroupInfo comparison that a removed MLS member cannot pass.
Both MLS and durable-runtime regressions reproduce it
(`removal-replay-regression-01.json` in durable-capacity evidence). The fix
independently verifies the public transition from the prior authenticated tree
and signed policy, then persists the removed member inactive. Invalid snapshots
must leave state untouched. Focused and full qualification are in progress.

Removal fix `2c4535d` passes MLS and hosted-runtime tests and strict Clippy
(`docs/evidence/irc-durable-capacity-20260930/removal-fixed-01.json`).
Forged removal, stale policy and mismatched snapshot controls remain enforced.
Full workspace and fresh protected-network qualification are running.

Removal source `2c4535d` passes the full GComs gate: 1,117 tests, 13 unchanged
ignored tests, strict workspace/all-target Clippy, documentation and minimal
core/SDK feature checks. Evidence: `removal-replay-qualified.json` in the
workspace evidence directory. New GChat worker scheduling qualification remains
separate from the retained passing twelve-member removal journey.

IRC-8 current pair `2c4535d` / GChat `556c8f8` passes full GComs regression
(1,117 tests, 13 unchanged ignores), strict/doc/minimal checks, paired GChat
(191 tests, three unchanged ignores), all 22 archive consumers, generated
contracts, UI63 and Linux desktop compilation. Fresh protected two-client run11
also passes unchanged timing, correctness, cleanup and grant revocation. See
`docs/IRC_PARITY.md` for source-bound receipts. Exact-source smoke07 precedes
the still-open protected-network 500-member and installed release gates.

IRC-8 documentation correction: the initial 4 KiB/s receipt illustration applies
to older fixed-cover profile 22. The existing trunk and qualified task artifacts
select responsive profile 46: immediate real data with padded interactive
records and randomized idle cover. The task preserves that profile and keeps
receipts on the interactive endpoint; large-room acknowledgment timing remains
separate as selected by the user. See `docs/IRC_PARITY.md`. No code or active
campaign settings changed.
