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
seconds after expiry. Neither client reported inbox recovery in the nominal
five-second samples from 30 seconds before expiry through five minutes afterward
(observed gaps were 5–6 seconds on the sender and 5 seconds on the receiver). The
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

The retrospective review in `target/capacity02-rollover-review-01/analysis-v2.json`
binds the original manifest, events, report and all eight archived host logs by
SHA-256, retaining a complete chat ledger and verified-progress observation
intervals. Around 04:00, each client has 66 diagnostic samples. At +4 seconds
on the sender and +3 on the receiver, `routing_ready` is false and Interactive
subscriptions are zero, while `ready_entries=2`, `usable_terminal_routes=1`
and Bulk subscriptions remain four. The next samples at +9/+8 report both
classes at four. This distinguishes subscription readiness from usable-route
availability; neither entry counts alone nor sampled absence of inbox recovery
establishes continuous readiness.

At 04:30, sender +5 and receiver +3 samples show zero usable routes, zero
entries and zero subscriptions in both classes. The sender's final sample is
+5; the receiver continues through +23. Its +8 and later timestamps map after
the approximately +7.431-second controller failure when aligned by recorded
clocks. They are retained as post-failure observations under that approximate
alignment, not evidence of a continued successful workload.
Neither client has a subsequent ready sample in the retained logs. The two
missing chat ACKs correspond to sends at elapsed 3,450.503 seconds. Acknowledged
mixed messages retain p95 8.158 seconds and maximum 40.241 seconds; excluding
the missing ACKs cannot convert the failed run into a pass.

The longest completed progress-observation interval around the first boundary
is 30.997 seconds. The unfinished 1 GiB transfer's final observation precedes
controller failure by 8.778 seconds, with no later progress/export receipt;
that interval is cut short by the failed run and is not a recovery duration.
Progress polling waits five seconds plus RPC time, diagnostics use integer
client wall timestamps, and cross-host clock offsets were not measured. No
entry-owner refresh/error trace or fresh-middle authentication timeline was
retained, so these aggregates cannot assign the interruption to a specific
renewal stage or isolate the repair's throughput effect. The original failed
report and all input hashes remain unchanged.

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

### Unpublished entry failures and recovery liveness

The independent review identified a further local counterexample: dropping a
failed entry attempt advanced the global readiness revision even if that
attempt had never published a ready carrier. With a healthy retained entry,
this unrelated churn could make terminal subscription failures appear to have
crossed a route change and repeatedly suppress ordinary inbox/channel recovery.
This is a source-derived liveness issue, not an observed cause of Capacity 02.

The new owner regression reproduces three failed unpublished dials across two
30-second retry ticks without publishing a ready entry. The old code advances
the revision three times. A separate real-loopback pump regression holds all
eight inbox/channel class subscriptions in flight through a healthy route,
rejects the second entry's pending handshake, then fails the held subscriptions.
The old code fails to request ordinary recovery; the corrected code does so
while preserving exact queue authority. This test uses explicit terminal
refusal, not a claimed reproduction of the full 60-second setup timeout.
Both failures and their passing reruns are retained under
`target/failed-entry-revision-01/`.

Ready-set revisions now advance only when a carrier is actually published or
removed. Publication/removal and revision updates share the same write lock;
the pumps obtain usable-route eligibility and revision through one read-locked
`route_revision` observation. This closes the publication/read inconsistency
without adding request-triggered dials or changing retry periods, authenticated
deadlines, capabilities or cover scheduling. It remains a point-in-time local
observation: it neither identifies the exact circuit used by a later request
nor proves terminal health or covers every possible concurrent route failure.
The prior unavailable-entry, in-flight revision-change and stable-route recovery
regressions remain required. The packet-derived client capture proposal,
including FIN/connection lifetime features, is separate work; no privacy gate
or fleet acceptance is inferred from this repair.

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
epoch or 30-minute maximum lifetime, qualify application-level repeated turnover
or the unfinished 1 GiB transfer, or explain the entire Capacity 01 recovery delay. Discovery
errors/backoff, fresh middle availability and route readiness must be correlated
in actual campaign evidence. Overall latency and privacy gates remain binding.

### Three consecutive credential expiries (local component)

`three_real_expiries_keep_authority_and_reacquire_both_classes` extends the
fixture to four authenticated credential generations and three real wall-clock
boundaries. The first deadline is 24 seconds after setup; the next two are
40 seconds apart. Issuers expose only the current generation. The owner,
profile 22, TLS, entry/transit handlers and subscription framing remain unchanged.

Both Interactive and Bulk deliver an exact independently checked payload in
every generation. At each boundary, the original streams terminate and both
classes are refused on the expired carrier objects. The background owner must
obtain two fresh entries and an independent route before resubscription. All
eight subscriptions retain the same terminal queue, capability, epoch and
deadline, while using distinct authenticated nonces. Retained guards stay
unchanged, live entry sockets including pending connections never exceed two,
and shutdown releases both sockets and ready slots.

The candidate delivered both classes after the third replacement at 110.888
seconds. All 49 routing library tests and strict routing Clippy with all features
and targets passed on the unchanged source snapshot; workspace formatting and
the checkout source audit passed. A disposable negative control keeps the first
expiry wakeup but stops scheduling it after the first successful renewal. It
delivers both classes in generations zero and one, then fails the new test at
the second boundary's reacquisition deadline. This demonstrates that a single
successful renewal cannot satisfy this regression.

Receipts, complete traces and the failing disposable source are retained under
`target/repeated-entry-expiry-01/`. The first wrapper's source audit was run in
an exported snapshot without a Git inventory and failed with `empty source
inventory`; that failure is retained separately from the passing audit against
the unchanged checkout. The first negative-control build admission was refused;
a smaller managed allowance succeeded without cache deletion or global quota
changes.

This is a test-only change. The fixture terminal authenticates subscription
envelopes and serves known payloads; it does not exercise the node's durable
queue implementation, admitted MLS chat, the GChat file engine or installed
artifacts. Actual-GChat repeated-expiry delivery/reopen, original hourly epochs
and the 1,800-second carrier lifetime remain outstanding. The failed Capacity 02
and the production/traffic hold are unchanged.

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

### Local lease correction, separate from the deployed relay

A delayed owner receipt describes an uncommitted `e2e858a` patch that promotes
leases during activation replay and reports 27 queue tests. Read-only inspection
instead finds the original-Coms fleet checkout clean at `4e8c5a4`, following
`48a4cfc` and `5bd1a95`. Promotion has been removed entirely: an exact
authenticated activation retry returns the existing lease without extending its
signed or temporary deadline, and preserves earlier replay cleanup. Push/sub
traffic cannot renew the lease. Administrative eviction remains available through
the existing control access and removes queue data and authority without making
the consumed grant reusable. These source corrections do not identify or qualify
the earlier dirty patch used to build r4's deployed `acd8ced269996ab7` binary.

The protocol peer's retained combined receipt names this exact `4e8c5a4` source:
279 node library tests pass with one existing exclusion; 23 selected GC/2
integration tests, 26 queue tests without default features, 42 routing library
tests and 55 protocol tests pass. Strict workspace/all-target/all-feature Clippy,
both no-std protocol configurations, reviewed-source rustfmt and diff checks
pass. This is not a full CI or whole-workspace formatting receipt. This audit
independently verified all 944 source hashes and 12 receipt/log hashes without
rerunning the peer's checks or modifying its checkout. The peer summary SHA-256
is `23888116d4a92ae55a80fa3b2aa7ea089b7adedbd9598f5669f5dda9ebbdc5af`;
the local review is retained at
`target/lease-promotion-security-review-02/review.json`.

The receipt's repeated 03:24:03 quiet claim remains superseded by the later
owner inventory and 07:11:39 stop acknowledgment above. No new fleet observation,
deployment, rollback, traffic, or release of the coordinated hold occurred during
this review. The local correction does not clear Canary 14 or qualify production.

### Isolated actual-daemon capture validity calibration

The local capture driver and observer parser are committed in `04c1ac7`, with
phase-bounded IPC, private-input bindings and retained-script reanalysis in
`a12af3c`. These changes are kept local. The actual application artifacts are
still immutable **build 11**, GComs `d6f5d97` / GChat `200cd7a`; this is not an
application validation receipt for later runtime or installed-bootstrap changes.

`target/client-capture-calibration-02/quartet.json` passes one matched
idle/chat/bulk/mixed **validity** quartet with an actual owner-UID sending GChat
daemon, Unix owner IPC, four local production-profile relays and an unobserved
peer. Both veth ends and public-policy-valid relay addresses exist only in
disconnected ephemeral namespaces. All four runs use fresh identities/state,
GCRB2/profile 22, a fixed 180-second startup allowance and 60-second measurement.
No private-address forwarding exception, host network mutation or production
relay is involved.

| Workload | Captured = filter-received = decoded frames | Non-IP frames | Chat ACKs | Independent file export |
| --- | ---: | ---: | ---: | --- |
| idle | 5,088 | 10 | 0/0 | none |
| chat | 5,222 | 10 | 2/2 | none |
| bulk | 5,210 | 10 | 0/0 | exact 64 KiB |
| mixed | 5,229 | 10 | 2/2 | exact matching 64 KiB |

All 20,749 frames are attributed, with zero capture drops, malformed or truncated
frames. IPv4/IPv6 pre/post sentinels are present; fixture-only sentinels remain
absent. Both file workloads have the same file identity and SHA-256
`92fa9d0e333bfc22bb8970f580d97440059222c08359040bd87e6ca6991de51d`.
Observed process lifetimes range from 240.064 to 240.096 seconds. Every daemon
exits normally; all children stop without forced kills and all host interface
identity comparisons pass. Packet-derived features include FIN/RST, TCP tuple
reuse/retransmissions and explicitly censored lifetime lower bounds; internal
relay counters remain correctness diagnostics only.

Independent retained-evidence CLI reanalysis reproduces the quartet report
exactly, SHA-256
`ef9f346d5fd295948ea60885254a2720fd7101ab01885d124bf50926b54c9395`.
Twenty-one corrupted or wrongly scoped copies are rejected; two valid controls
pass, including a changed internal counter that leaves all classifier inputs
unchanged. Those checks are retained under `target/client-capture-checks-02/`.
The earlier socket smoke's 25 frames also decode completely, including the
previously omitted non-IP and multicast observations.

The first partial attempt, `client-capture-calibration-01`, remains failed and
unchanged: mixed/chat passed individual validity, then idle setup hit the
controller's unrelated 35-second `/join` response timeout, before measurement;
bulk was not attempted. All children stopped and host links were unchanged.
The regression fails on that controller and passes after IPC waits use the
declared phase budget. The retry uses a longer equal startup allowance for
**all** workloads, without reusing the earlier passing captures or weakening a
privacy/performance gate. Its joins exceeding 35 seconds completed within the
new declared setup budget.

This quartet has no training/held-out separability estimate. It remains
`diagnostic_only:true`, `component_gate_passed:false`, `release_qualified:false`;
the <=0.55 upper-95% gates remain binding for both idle/chat and matched
bulk/mixed, including window and connection observations. Installed-default
bootstrap/catalog/desktop paths, statistical qualification, actual unrelated
ready-entry churn coverage and the failed fleet capacity gates remain separate
work. No fleet campaign, deployment, rollback or coordinated-window release
occurred. See [capture scope and commands](GCHAT_CLIENT_CAPTURE.md).

Final validation passes all **137 Python cases**, including CLI rejection of a
pooled quartet, and the 472-path source audit. The receipt is
`target/client-capture-checks-02/final.json`. An earlier suite run exposed a
separate preview-registry cache collision: reusing a loopback port for different
archives of the same package version caused Cargo to reject the new checksum
without contacting the server. `e632541` binds the registry URL to the supplied
archive hashes. Its real Cargo regression fails before the fix and then passes
both dependency executions at the same port, preserving original source locks
and checksum enforcement. The failed suite, deterministic reproduction,
red/green logs and one managed-run admission failure are retained. No global
cache deletion or quota change was used; the capture binaries and raw evidence
remain unchanged by this tooling correction.

### Recovery clock includes resume and quota restoration

The peer's local review reproduced a controller accounting gap in
`scripts/fleet_files.py` SHA-256
`daf75b807e9f96f231205b528fc977130f36f734331a1b634bd53393d732abef`:
pause/resume and quota started the recovery clock after admission, excluding a
possible 900-second admission/RPC wait. This was a source/controller finding,
not a newly observed fleet failure.

The corrected scenarios start the monotonic clock before resume admission and
before restoring quota respectively. One absolute 300-second deadline passes
through admission locks, slot polling, configuration/resume RPCs, verified-byte
queries and restart readiness. Each SSH request receives only the remaining
allowance; polling rejects late successful responses and cannot restart the
clock. `finish_recovery` now requires the original start timestamp. The separate
3,600-second full-export budget remains anchored to that same timestamp.

Scenario regressions use the real controller and RPC wrappers with a simulated
clock and SSH boundary. They reject 301-second lock/slot/resume/progress delays,
quota restoration that exhausts the budget, and multiple individually shorter
actions that cumulatively exceed it. A full admission queue stops at 300 seconds;
progress observed at exactly 300 seconds still passes. Receiver restart tests
consume 240 seconds before transport readiness and verify that its RPC gets only
60 seconds. The initial four regressions fail on the retained old controller
(11 failing subcases); all seven new scenario tests pass after correction.

All **144 Python tests**, the 472-path source audit and diff checks pass. Source,
red/green logs and validation hashes are retained in
`target/recovery-resume-deadline-01/receipt.json`. These checks establish local
controller accounting and timeout propagation. A timed-out RPC remains a failed
observation, not proof that its remote mutation was cancelled. Frozen builds,
raw fleet reports, Capacity 02's controller and failed verdict remain unchanged.
No fleet traffic, production action, publication or quiet-window release occurred.
