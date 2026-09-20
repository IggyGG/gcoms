# Fleet file-transfer findings — 2026-09-20

> **Candidate update (2026-09-20).** The current implementation adds explicit
> GCRB2 provisioning, channel bulk transport, both subscription classes,
> shared profile 22, pipelined piece requests and retained send ownership. Local node
> library validation passed 285 tests (one ignored), and the profile-22 cold
> channel/renewal test passed in 125.94 seconds; these results do not
> qualify the fleet. Runs 11–12 reached the opted-in carrier but failed before
> a verified file export; all eight hosts were cleaned up. The historical
> post-merge note below describes the earlier state. See the
> [implementation and remaining gates](GCHAT_FILE_TRANSFER_FOLLOWUP.md).

**Full fleet qualification has not passed.** Canary 15 passes the standard
64 KiB transfer and receiver reopen. Capacity 01 verifies files through 256 MiB
but exposes excessive chat latency during routing credential renewal. Capacity
02 retains authority through the first rollover and again verifies 256 MiB,
then fails during a 1 GiB transfer near the second rollover. Both capacity runs
ended and cleaned up all eight hosts. The 16-client ramp, 56 transfer pairs, 30-minute baseline,
four-hour mixed workload and fault matrix remain unqualified. Historical failures
below are retained; see [the runbook](FLEET_FILES.md) for the exact campaign.

> **Post-merge state (2026-09-19).** The campaign branch is reconciled with trunk
> `a71db53` and now builds relays and clients with the fleet carrier profile.
> Runs 01–10 below were measured on the retired legacy schedule with unpaced
> bulk; they are historical, and no carrier-profile fleet run has been executed
> yet. Local carrier evidence: the three-hop natural-scheduler regression
> (`crates/node/tests/gc2_queue_service.rs`) delivers 64 × 11 KiB bulk records
> plus interleaved chat over the shared padded lattice and passes 7/7 after the
> merge. The fleet canary and scale gates on the carrier profile remain open.

## Real fleet observations

Runs 01–10 used eight isolated test relay listeners on the recorded Hetzner hosts,
two application clients, fresh test identities, and the retired legacy scheduler
(the carrier profile had not been integrated at that point).
Production relay services were not restarted or reconfigured. All ten runs
reported successful cleanup on every host, including unchanged production
service state. The final topology passed all 64 test-relay TCP reachability checks;
this is transport reachability evidence, not 56 verified file-transfer pairs.

| Retained run | Fixture | Result |
| --- | --- | --- |
| `files-canary-01`–`03` | Setup/admission | Failed; retained firewall, uncertain-create and join-deadline evidence |
| `files-canary-04`–`06` | 64 KiB | Transfer deadline failed with the original file worker |
| `files-canary-07` | 64 KiB | Worker remained responsive; transfer deadline still failed |
| `files-canary-08` | 1 KiB diagnostic | Independent SHA-256 export passed, 134.073 seconds after acceptance |
| `files-canary-09` | 64 KiB, added counters | Transfer deadline failed; no verified piece or export |
| `files-canary-10` | 64 KiB, worker/serializer/PEX fixes | Transfer deadline failed; no received block, verified piece or export |

Run 08 used an explicitly reduced fixture in its retained coordinator copy. Its
`phase_passed` is true, while its qualification verdict remains `incomplete`.
It does not replace the standard canary. Its measured end-to-end application
goodput was approximately 7.64 bytes/second, including initial transfer discovery.
This single observation is not a sustained throughput measurement.

Run 09 retained two received ciphertext blocks (22,528 bytes) in the receiver's
last diagnostic sample, zero verified pieces and zero rejected pieces. Both
workers emitted observations at five-second intervals. The sender recorded
14 send-receipt timeouts before cleanup. Some receiver send failures occurred
during cleanup, so final counters must not all be attributed to the transfer
window. The block samples show slow progress; they do not establish whole-file
integrity or the precise cause of the latency.

## Fixes and remaining findings

GChat previously waited for a complete batch of outgoing receipts before reading
another incoming event, and discarded received events during transient session
lock contention. Its worker now keeps at most four send futures alive across
receive/timer iterations and waits for the session lock. Shutdown cancels the
send pool. A deterministic real-channel regression fails with the old worker and
passes with the fix, including byte equality and shutdown with held receipts.

The deployment harness also needed exact TCP DNAT matching, the correct chat IPC
endpoint, private loopback client advertisements, and namespace hairpin routing
to a colocated relay's public address. These fixes preserve the isolated-listener
scope. Collection failure no longer prevents cleanup. Reports reject missing
exports, missing acceptance, incomplete host coverage and incomplete cleanup.

Run 09 left two findings for follow-up:

* The retired legacy lane rate is incompatible with the planned single-source
  1 GiB/four-hour target. The runbook keeps the capacity discussion separate
  from measured evidence, and the carrier lattice has a different capacity
  envelope that the next campaign must measure. Receipt timeouts and repeated
  requests also need a focused queue/admission/retry investigation; raising the
  acceptance deadline would conceal this failure.
* Periodic peer-exchange cells are submitted to a relay path that accepts only
  authenticated MSG payloads, producing `RELAY_PUSH does not contain exactly one
  MSG`. This rejection was traced to `node/channels.rs`; it has not been proven
  to cause the file timeout. Preserve the MSG-only relay boundary when repairing
  peer discovery.

The next qualification step is to rerun the standard canary and the unchanged
scale gates on the carrier profile, now that this branch carries the carrier
relay and client builds. These historical results do not qualify the carrier
profile, Windows, desktop attachments, production listeners, or large-file
transfers.

## Validation and retained evidence

The implementation baseline passed 619 GComs Rust tests (six ignored), 147 GChat
Rust tests, strict Clippy for both workspaces, and GComs JavaScript checks, tests
and build. The subsequent aggregate-counter change passed 14 file-transfer tests
(one ignored), the held-receipt regression, strict GChat and file-transfer Clippy,
and file-transfer rustdoc. The final harness has 80 passing Python tests. Source
inventory, protocol vectors and formatting checks passed. This is Linux evidence.

Evidence is retained locally under this GComs task checkout and excluded from
commits:

* `test-evidence/files-canary-01` through `files-canary-10`: manifests, exact
  coordinator/worker copies, events, private host archives and original reports.
* Runs 07–09 also have `report-current-analyzer.json`; original reports remain
  intact. Run 09 has `diagnostics-summary.json` bound to its host archive hashes.
* `target/fleet-build-05` and `target/fleet-build-06`: successful frozen-source
  builds, resolved locks, source inventories and deployed executable hashes.
* `target/file-worker-red.log` and `target/file-worker-green-02.log`: expected
  failure and passing regression; `fleet-worker-final-regression.log` retests the
  final instrumented worker. An earlier green-run attempt reused a stale Cargo
  artifact and remains retained as an invalid comparison.
* `target/fleet-workspace-tests.log`, `fleet-gchat-worker-tests.log`,
  `fleet-python-final-03.log`, and source-check reports retain validation details.

Do not publish raw archives or retained test volumes: they can contain private
test identities, routing metadata and encrypted caches. No such material is
included in the source commits.

## Follow-up before the next fleet candidate — 2026-09-18

The carrier component work has been merged into this task and the tree is
reconciled with trunk `a71db53`. The relay and client builds in this branch run
the carrier profile; the large-file capacity gate still needs a fleet
measurement on that profile.

The channel command serializer now releases its lock after file authorization,
encryption and enqueue, before awaiting hop acceptance. A real TLS/H2 regression
holds one peer's receipt open and verifies delivery to another peer in the same
channel, then cancellation during shutdown. Its old-code failure is retained in
`target/channel-application-red-02.log`; the fix passes in
`target/channel-application-green.log`.

The PEX framing refusal is repaired with an authenticated pairwise MSG envelope,
using disposition 4 so disposition 3 remains file application traffic. The
three-node regression first verifies ordinary plaintext and all-member delivery
ACKs, then requires actual PEX reception. It fails before and passes after the
repair (`target/pex-relay-red.log`, `target/pex-relay-green-02.log`). The relay's
MSG-only deposit boundary is unchanged. This fixes the rejection; it does not
prove that PEX caused the fleet transfer timeout.

The harness now waits for a download slot, records admission separately, creates
fresh partial transfers for faults, stops an unavailable seed before acceptance,
and verifies complementary source contributions in two exclusive phases. It
requires actual partial-progress and source observations instead of accepting
scenario labels alone. The broader Python suite passes 88 tests. One analyzer
shortcut discovered during review is retained in `target/fleet-fault-evidence-red.log`;
the new regression rejects it.

GC/2's directory now serializes exact introductions and retained guard order in
bounded version-2 private state. A durable sink commits before publication. A
failed or ambiguous save disables routing through that directory until actual
authenticated storage is reloaded. A public-API reproduction demonstrates the
previous ambiguous-save failure and its correction in
`target/guard-ambiguity-red.log` and `target/guard-ambiguity-green.log`. Node/GChat
storage and profile integration remain pending.

Validation: the combined workspace with the Node fixes passed 732 Rust cases
(six ignored), including the 24-node overlay; GChat passed all 147 cases against
an unchanged source snapshot (`test-gc-chat-3ic3l10s.json`). The subsequent routing
persistence work passed all 67 routing cases separately. Strict workspace Clippy,
formatting, eight independent cell vectors, source inventory and research import
checks also passed during this follow-up. Logs remain under `target/` and the
source-check report directory. No further fleet campaign has run at this point;
the latest standard canary remains the failed run 09 above.


## Canary 10 and natural-scheduler integration

Canary 10 used the unchanged-source release receipt in `target/fleet-build-07`.
Both clients were ready, and the receiver accepted the 64 KiB offer. It missed
the unchanged 300-second completion gate. Final diagnostics recorded zero
received blocks and zero verified pieces, with eight sender send timeouts.
Receiver errors during cleanup are not evidence of failures during the transfer.
All eight cleanup observations passed, including unchanged production services.
The new report analyzer records two observed clients, 65,536 offered bytes and
zero verified file bytes. The original report remains intact; the corrected scope
is in `report-current-analyzer.json`.

Both clients now received authenticated channel PEX (11 and 12 observations),
with no former MSG-framing refusal in their metrics. This confirms the PEX repair
on the fleet and also shows that it did not resolve the file-transfer failure.
The file worker's 20-second send timeout cannot distinguish scheduler queue delay
from a stalled transport response. Subsequent diagnostic builds include the
existing bounded Node scheduler aggregates alongside file-engine observations.

The carrier component work is now reconciled with trunk (`a71db53`), including
the natural scheduler and the GChat carrier selection. Its three-hop local
regression checks 64 bulk records of 11 KiB alongside chat and owned
subscriptions; the fleet relays and clients build with the carrier profile
(`--schedule gc2`; GChat `gc2-carrier` with `GC_GC2_CARRIER`). The standard
canary and every remaining scale/capacity/fault gate still require a passing
carrier-profile fleet run. See [the integration boundary](GC2_SCHEDULER.md).

## Carrier-profile canaries — 2026-09-19 (runs 11–12)

The first two fleet runs on the merged carrier profile. Relays start with
`--schedule gc2`; clients run the `gc2-carrier` build with `GC_GC2_CARRIER=true`.

* `files-canary-11`: eight relays ready in 47.7 s. The run aborted at 169 s in
  client startup: the daemon rejected `GC_GC2_CARRIER=1`, because the flag's
  boolean environment value must be `true` or `false`. Fixed in
  `fleet_files_remote.py` and in the release notes. Cleanup completed.
* `files-canary-12`: eight relays ready in 145.6 s; **two carrier clients were
  observed for the first time**. The run aborted at 271 s when a client command
  returned `outcome_unknown: runtime: inbox routing is recovering`. Client
  diagnostics show the carrier scheduler active (`accepted` 3, `dispatched` 3,
  `failed` 3) with zero file blocks. The isolated relay log records
  `gcnode: network configuration unavailable; maintenance deferred`, and its
  metrics record `gc2_advertisement_deferred: no complete circuit to an
  available inbox service`: without a network document and inter-relay
  circuits, the test relay cannot advertise a GC/2 introduction, so the client
  carrier routing never settles.

The next carrier campaign step is to make isolated client routing settle: the
test relays need GC/2 introductions with complete circuits between them (the
harness currently supplies only private routing bootstrap material), or a
carrier bootstrap the harness can generate without production identities. Until
that gate passes, the standard canary cannot measure file transfer on the
carrier profile. Both runs cleaned up every host and left production relay state
unchanged.

## GChat file-profile canary 13 — 2026-09-20

Run `ff-20260920-014950` used the frozen `fleet-build-09` candidate, GComs
`ea9157f` and GChat `a3c125c`. All eight relays were ready after 78.4 seconds.
Clients 0 and 8 proved GCRB2/profile-22 readiness at 136.3 and 182.3 seconds:
each had two ready entries, one usable terminal route, and both Interactive and
Bulk subscriptions, with no inbox recovery in progress.

Channel creation succeeded, but `/invite` repeatedly failed with
`routing bootstrap bundle exceeds bounds`. The invitation exporter still read
the legacy directory even when the selected carrier populated the GChat
directory. The run failed at 378.9 seconds before any file offer. This is a
failed canary, not a transfer capacity observation. Evidence remains in
`test-evidence/files-canary-13`; all eight cleanup receipts passed, including
unchanged production service identity and restart counts.

The fix uses a version-3 invitation envelope carrying GCRB2 and delegates export
and installation to the selected Node runtime. Existing v1/v2 links remain
readable. The local channel test now redeems a shareable invitation remotely
before its first file message, instead of bypassing that path with direct owner
admission. A rebuilt candidate must pass the normal canary and receiver reopen
before the capacity phase can start.

## Canary 14 interrupted by production replacement — 2026-09-20

Run `ff-20260920-022818` used frozen `fleet-build-10`, GComs `628ec44` and
GChat `36a96ae`, after all 151 paired GChat tests, strict Clippy, the remote
invitation/renewal regression, dependency policy and archive/frontend/desktop
consumer checks passed. Eight isolated relays were ready after 47.8 seconds;
client 0 proved profile-22/GCRB2 readiness after 94.5 seconds.

At 135.1 seconds the monitor detected a changed production service identity on
host 4 (`157.90.35.101`) and aborted before any file offer. Read-only journal
inspection showed a deliberate stop/start at 02:30:25 CEST with a newly installed
binary (`gc2-dfaf5e620e3920b4`); systemd reported a successful stop and zero
automatic restarts. The isolated worker never targets `ghost-relay.service`.
The other worker was notified and the rollout schedule was requested. Repeated
read-only observations found all eight production services unchanged over the
next sampled three-minute interval, about eight minutes after the replacement.
A subsequent canary uses a fresh baseline and retains the automatic stop on any
production change; this run is not a transfer timeout observation.

All eight hosts confirmed removal of the test namespace, veth, firewall rules
and volume mount, with no cleanup operation errors. Seven overall cleanup
receipts passed; host 4 correctly failed the unchanged-production requirement.
The original report remains failed in `test-evidence/files-canary-14`.
The controller now distinguishes campaign cancellation from a readiness or
transfer deadline and reports isolated resource removal separately from the
unchanged-production gate. Neither change relaxes the campaign pass criteria.

## Canary 15 passes transfer and receiver reopen — 2026-09-20

Run `ff-20260920-023919` reused frozen `fleet-build-10` (Rust GComs `628ec44`,
GChat `36a96ae`) with controller `5d8846e`. All eight isolated relays were ready
after 47.5 seconds. Both clients proved profile-22/GCRB2 readiness, invitation
export succeeded and the receiver joined through remote redemption.

The 65,536-byte file was accepted at 265.812 seconds and independently exported
and SHA-256 verified at 271.322 seconds: **5.510 seconds after acceptance**.
Offer import preceded acceptance by 62.5 seconds; this is a single small-file
measurement, not a sustained throughput estimate. After receiver restart,
the same instance identity and a second export hash were verified at 323.833
seconds. Every host passed cleanup, including unchanged production state.

`test-evidence/files-canary-15/report.json` records `phase_passed: true`,
`canary_reopen_verified: true`, and both cleanup observations true. Its overall
verdict remains `incomplete` because a canary does not qualify the full fleet
campaign. Larger files, concurrent chat, all 56 directed host pairs, the
four-hour mixed run, faults and privacy qualification remain separate gates.

## Capacity 01 exposes renewal interruption — 2026-09-20

Run `ff-20260920-024634` used the same immutable `fleet-build-10`. Its repeated
64 KiB canary and receiver reopen passed, followed by a 300.9-second chat
baseline. Independent export hashes verified 4 MiB in 31.183 seconds and 32 MiB
in 326.997 seconds after acceptance. The 256 MiB export subsequently verified in
1,408.153 seconds (23 minutes 28 seconds), with SHA-256
`629fbd96de7a30ce0b3c7b34f9bd183c73104863453d766ca2647b2f9895957e`.
These observations do not establish the 1 GiB capacity gate.

The initial introduction expires at elapsed 805.835 seconds. Both clients then
report `no ready independent GC/2 route`, lose subscriptions and enter inbox
recovery. The sender becomes route-ready near 857 seconds and the receiver near
932 seconds. The 32 MiB transfer has a 129-second interval without new observed
verified progress. Chat acknowledgement latency reaches 129.700 seconds, above
the fixed 120-second maximum; the measured baseline p95 was 16.486 seconds.
The terminal mixed p95 is 45.3865 seconds, above its 32.9727-second limit;
the terminal ledger retains 132 acknowledgments for 136 sends. Intermediate
percentiles are not substituted for this final result.
This run cannot pass the mixed-traffic gate, regardless of subsequent file
completion. The controller was deliberately interrupted after the 256 MiB
export to retest the repaired candidate. Four final chat acknowledgements were
still pending; the original failed report retains both the interruption and
missing acknowledgements. No 1 GiB file was offered. All eight cleanup receipts
passed, including unchanged production state. Observed file-engine buffers stayed
below 4 MiB; the receiver verified 1,169 pieces with no rejected pieces and eight
retries. These are aggregate process counters, including the receiver reopen.

The separate `test-evidence/files-capacity-01/coexistence-annotation.json`
maps the original events to the owner's reported activity boundaries. Its
hashes bind the unchanged manifest, event log, failed report and retained
controller/worker, plus the later owner acknowledgment. Wall times below are
approximate: they add monotonic event deltas to the manifest's wall-clock start;
the startup offset and cross-host clock uncertainty were not measured.

| Observed interval | Approximate CEST interval | Before first listener/bridge stop at 03:24:03 | After that stop |
| --- | --- | --- | --- |
| Chat baseline | 02:51:58–02:56:59 | Entire 300.891 seconds | None |
| 4 MiB acceptance to verified export | 02:56:59–02:57:31 | Entire 31.183 seconds | None |
| 32 MiB acceptance to verified export | 02:57:33–03:03:00 | Entire 326.997 seconds | None |
| 256 MiB acceptance to verified export | 03:03:11–03:26:40 | About 1,251.5 seconds | About 156.6 seconds |

The observed mixed workload runs from the first mixed chat send near 02:56:59
to the retained interruption near 03:26:40; it has no completed mixed-window
event. All 20 baseline messages were acknowledged before 03:24:03. Of 116 mixed
sends, 102 were sent and acknowledged before that boundary, two acknowledgments
crossed it, eight sends and acknowledgments were entirely after it, and four
sends remained unacknowledged (two on each side). The annotation retains every
message's send/ACK pair, including missing ACKs, rather than classifying a late
ACK as a new post-stop send.

The 256 MiB interval also spans the approximate 03:16:02 last fresh mint and
03:16:30 payload stop. The later surviving-client inventory places all of these
intervals before the final 07:11:39 stop; the post-03:24 samples therefore cannot
be called quiet. These are coexistence boundaries, not measurements of constant
background load. An unchanged production PID does not establish matched load.
Baseline-versus-mixed performance acceptance remains unqualified: repeat the
full affected comparison under a freshly coordinated and observed quiet window,
record background conditions across both intervals, and retain abort-on-change.
No subset of this run is promoted to a controlled comparison. Delivery/reopen
receipts, the latency failure and all four missing ACKs remain intact; this
annotation neither cancels nor restarts the already completed run.

The subscription pumps treated a temporarily unavailable protected route as lost
terminal authority. A local regression reproduces this inbox invalidation. The
repair waits for usable entries before opening subscriptions and retains inbox
and channel authority when the ready-route generation changes during a failed
attempt. An error on a still-ready, unchanged route retains ordinary recovery.
The regression fails before the repair and passes after it, alongside the
independent channel-control retry regression. The repair still needs a rebuilt
fleet run across credential expiry. Live observations are retained privately in
`target/protocol-plan-capacity01-live/renewal-observations.json`; the complete
campaign evidence remains under `test-evidence/files-capacity-01`.

The shared protocol worker obtained the rollout owner's acknowledgment of both
production replacements on host 4 and a hold on further deployments and
relay-impacting tests. Its initial acknowledgment claimed residual traffic ended
at 03:24:03 CEST. A later owner process inventory explicitly corrected that
claim: additional clients continued contacting four production relays, with
relay-facing work stopped at 07:10:44 and the last detached bridge at 07:11:39
CEST. The earlier acknowledgment is retained as historical evidence, not proof
of a quiet window. Both capacity runs overlap this disclosed coexistence period;
their performance observations do not establish isolated performance. The
inventory does not establish whether that traffic caused either failure.

Capacity 02 (`ff-20260920-033236`) started after the earlier, incomplete
acknowledgment with immutable
`fleet-build-11`, GComs `d6f5d97` and GChat `200cd7a`. The build snapshots and
all executable hashes pass. Local validation covers 287 node-library cases
(one ignored), eight cold-channel/protected-route/session cases, the legacy
control retry, both strict Clippy checks, all 151 GChat cases and packaged Rust,
npm, frontend and desktop consumers. Both source snapshots remained unchanged
during the paired checks.

## Capacity 02 crosses expiry with retained authority — 2026-09-20

The repeated 64 KiB canary verified in 5.435 seconds after acceptance. A separate
receiver reopen retained the same identity and verified another export. Subsequent independent exports
verified 4 MiB in 20.915 seconds, 32 MiB in 119.022 seconds and 256 MiB in
1,019.896 seconds (17 minutes). The 256 MiB SHA-256 matches the deterministic
fixture recorded above. Route choices differ from capacity 01, and both runs
overlap the later-disclosed production client activity. These timings do not
isolate the repair's effect on throughput.

The initial credential expired at 04:00 CEST, elapsed 1,643.268 seconds. Both
clients briefly reported zero Interactive subscriptions, then reported ready
routes and four subscriptions of each class by approximately eight and nine
seconds after expiry. Neither client reported inbox recovery in the five-second
samples from 30 seconds before expiry through five minutes afterward. The
largest interval between new verified-byte observations near this rollover was
30.997 seconds, versus the 129-second interruption in capacity 01. Live evidence
remains in `target/protocol-plan-capacity02-live/renewal-observations.json`.

The actual 1 GiB transfer was accepted at elapsed 1,824.069 seconds. At the
retained 1,927-second checkpoint, mixed chat had 86 acknowledged
messages, p95 9.904 seconds and maximum 40.241 seconds; baseline p95 was 18.555
seconds. No failure or production-change stop had occurred. This is an interim
observation, not a capacity-phase pass or a cleanup result.

The workstation continuation was configured to wait for a passing capacity
report before running coverage and the full campaign serially on the same
frozen binaries. Each transition requires a passing phase, no reported failures,
all eight cleanup checks and unchanged bound controller/worker/build inputs.
The full campaign retains the
30-minute baseline, four-hour mixed window and original capacity/chat gates.
The final failed capacity result stopped this continuation; neither coverage nor
the full campaign started. Its retained state remains in the ignored task-local
`target/protocol-plan-fleet-sequence-01.*` files.

## Capacity 02 final failure and cleanup — 2026-09-20

At elapsed 3,450.699 seconds, client 0 reported an `outcome_unknown` channel send:
the operation was interrupted after admission and failed for one target. The
receiver's last observed verified progress was 297,795,584 bytes (284 MiB),
at elapsed 3,441.921 seconds. The 1 GiB file has no export receipt and must not
be counted as a completed transfer. The largest independently verified export
remains 256 MiB.

The interruption coincided with the second entry/bootstrap rollover, at
04:30 CEST. Both clients lost entry/subscription readiness without reporting
inbox recovery. This is a correlation requiring a targeted reproduction, not
proof of the remaining root cause. The first-rollover authority repair does not
establish repeated-rollover reliability or justify weakening lease expiry.

The final report records 204 chat sends and 202 acknowledgments. Its acknowledged
mixed samples have p95 8.158 seconds, but two missing acknowledgments and the
admitted-send failure make the run fail regardless of that percentile.
`test-evidence/files-capacity-02/report.json` records `verdict: fail`,
`phase_passed: false`, `cleanup_complete: true` and
`isolated_resources_removed: true`. All eight host cleanup events passed,
including unchanged production state. Complete logs and the original manifest,
events and failed report remain retained; the immutable build is unchanged.

Before another capacity attempt, reproduce consecutive rollovers with both
Interactive and Bulk subscriptions and an admitted channel send in flight,
then validate the combined source pair and coordinate an isolated test window.
Owner profile/migration selection gates production rollout; this experimental
isolated test profile is not a production selection. No later campaign or
production rollout is implied by the passing small-file canary.

### Local admission correction after capacity 02

The retained client samples lose all ready entries at 04:30:03 and 04:30:05
CEST, approximately thirty minutes after the first renewal. The entry carrier
has a thirty-minute maximum lifetime; its completion/reconnect scheduling is
therefore a reproduction lead, not a confirmed diagnosis of this fleet failure.
No routing lifetime or retry schedule was changed by this follow-up.

An independent local regression reproduced the terminal channel-send error:
`prepare_channel_text` had committed the exact MLS wire and recipient outbox,
but `complete_channel_text` discarded local acceptance when the first hop
failed. It now retains acceptance only when a persistent commit covers the
complete, nonempty recipient roster. Ordinary maintenance retries the same
wire; authenticated recipient ACKs still exclusively determine delivery.
Sends without that durable outbox retain their previous failure behavior.
Failed persistence and missing tracked recipient routes remain failures.

The native regression checks the saved ID, exact ciphertext, authenticated
plaintext and ACK processing. The cold-route integration test retains its
no-delivery-before-authorized-repair, unchanged wire ID, roster/epoch and
all-member ACK assertions while checking the locally accepted ID. GChat adds
an actual offline-recipient send followed by both encrypted-profile reopens,
plaintext reception and a matching delivery ACK. These local checks do not
qualify consecutive protected-carrier turnover or complete the failed 1 GiB
fleet transfer. Capacity 02 remains failed, and its evidence is unchanged.

### Local subscription failure coverage after capacity 02

Two additional regressions exercise the real contact and channel subscription
pumps through loopback entry/middle relays and an authenticated terminal. Each
covers Interactive and Bulk for every inbox and channel alias. The first holds
all initial responses, makes a second real entry ready, then fails the in-flight
subscriptions while a usable route remains. The pumps preserve exact authority
and successfully resubscribe using fresh request nonces. The second fails those
requests with an unchanged usable route and asserts ordinary inbox and channel
recovery. It therefore checks that retaining authority during entry changes
does not suppress genuine recovery on a stable route.

All four tick tests pass, including the prior unavailable-entry and stalled
channel-control cases. In separate disposable copies, ignoring readiness
revision makes the first new test fail; suppressing ordinary recovery makes the
second fail. Those deliberate failures and the passing candidate are retained
separately under `target/subscription-recovery-01/`. No runtime scheduling,
padding, renewal timing or lease policy changed. These local branches do not
qualify consecutive expiry/maximum-carrier-lifetime turnover, the 1 GiB fleet
transfer, aggregate latency, or privacy. Expiry-stratified measurements remain
diagnostic; the overall acceptance gates remain unchanged.

### Real wall-clock entry expiry regression

`routing::gc2::owner::expiry_tests` adds a bounded loopback regression using the
actual EntryOwner discovery loop, pinned TLS, entry/transit handlers, profile 22
and authenticated natural subscriptions. Only the fixture shortens the shared
credential epoch to 24 seconds. Neither Tokio time nor the workstation clock is
changed. The production hourly credential derivation and original authenticated
carrier deadlines are unchanged; the fixture never updates a live carrier's
introduction to extend its authority.

Interactive and Bulk each receive an exact payload before the boundary. Both
streams must terminate when the original carrier authority expires. Background
discovery then obtains a fresh introduction and authenticates a new entry. The
second relay's refresh response is held: one fresh entry alone must not restore
a route without an independent fresh middle. Releasing that response permits
both classes to resubscribe and receive exact payloads with the same queue,
epoch, subscription capability and lease deadline, using fresh request nonces.
The fixture counts entry sockets, including connecting sockets, to enforce the
one-entry bound across replacement and verifies shutdown releases them.

The retained trace distinguishes refresh requests/responses, entry and transit
authentication, original-stream closure, independent-middle availability and
verified subscription delivery. A disposable mutation that disables the
expiry-triggered discovery wakeup fails at reacquisition; it is retained
separately from the candidate under `target/entry-expiry-01/`.

This is carrier lifecycle coverage, alongside the real node-pump branch tests
above. Its terminal authenticates subscription envelopes and serves known
payloads; it is not the node queue/lease implementation, an MLS/file-transfer
journey, or a fleet measurement. It does not reproduce production's full hourly
epoch or 30-minute maximum lifetime, qualify repeated turnover or the unfinished
1 GiB transfer, or explain the entire Capacity 01 recovery delay. Discovery
errors/backoff, fresh middle availability and route readiness must be correlated
in actual campaign evidence. Overall latency and privacy gates remain binding.

### Corrected coordination timeline and fresh production observation

OpenCode session `ses_f657247f6ffe3oDxEHezkGyr1X` explicitly attributes both
r4 replacements to itself: `dfaf5e620e3920b4` at 02:30:25 CEST and
`acd8ced269996ab7` at 02:46:05. These deployments affected r4 only; its later
client activity reached four production relays. Its last known fresh mint is
approximately 03:16:02, payload stop 03:16:30, and the first listener/bridge stop
03:24:03. That first pair had continued 120-second lease-create replays and
subscription reconnects. Fresh mint time, last replay/control request and last
successful relay-state mutation are distinct; the latter remains unknown.

The owner's later acknowledgment `msg_0bd3a843f001tOXmiJ7fRf05tx` reports the
additional surviving clients and the final 07:11:39 stop. This is owner-reported
quiet, not independent verification of every possible writer. The all-eight
hold covers relay-facing traffic, provisioning and service changes. Exact
acknowledgments and their ordering are retained under
`target/canary14-cleanup-reconciliation/`; delayed 03:24 notices do not supersede
the later process inventory.

A fresh read-only SSH inventory at 07:16 CEST found all eight production
services active/running with stable identities during observation and no change
to the service identity fields recorded before capacity 02. r4 still runs
SHA-256 `acd8ced269996ab71312c789a6bfbd502e794eddec257585f587c0841b6c777c`;
the other seven run
`6e4a6cb12713cba6f7bf871100f45ca26078a398d0ceccde97506fe57e6c1c31`.
No listener was present on either reserved test port, 24433 or 29443, on any
host. The receipt, per-host observations and exact read-only probe are retained
in `target/canary14-cleanup-reconciliation/production-baseline-20260920T051645878448Z/`.
The inventory sent no relay protocol/control requests and changed no services.

This observation does not qualify r4's reported `e2e858a` plus dirty activity
promotion/diagnostics binary. Its as-built patch manifest is unavailable and
the related promotion previously failed expiry/replay checks. No rollback was
requested or performed. Canary 14's production-change gate remains failed.
The campaign remains idle; the next run must refresh its own observed baseline
and retain automatic abort-on-production-change behavior.
