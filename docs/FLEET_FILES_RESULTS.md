# Fleet file-transfer findings — 2026-09-18

> **Candidate update (2026-09-20).** The current implementation adds explicit
> GCRB2 provisioning, channel bulk transport, both subscription classes,
> shared profile 22, pipelined piece requests and retained send ownership. Local node
> library validation passed 285 tests (one ignored), and the profile-22 cold
> channel/renewal test passed in 125.94 seconds; these results do not
> qualify the fleet. Runs 11–12 reached the opted-in carrier but failed before
> a verified file export; all eight hosts were cleaned up. The historical
> post-merge note below describes the earlier state. See the
> [implementation and remaining gates](GCHAT_FILE_TRANSFER_FOLLOWUP.md).

**Full fleet qualification has not passed.** The harness is implemented and the
file worker liveness defect is fixed, but the standard 64 KiB cross-host canary
still misses its five-minute deadline. The 16-client ramp, 56 transfer pairs,
30-minute baseline, four-hour mixed workload, large files and fault matrix remain
unexecuted behind that gate. See [the runbook](FLEET_FILES.md) for the exact campaign.

> **Post-merge state (2026-09-19).** The campaign branch is reconciled with trunk
> `a71db53` and now builds relays and clients with the fleet carrier profile.
> Runs 01–10 below were measured on the retired legacy schedule with unpaced
> bulk; they are historical, and no carrier-profile fleet run has been executed
> yet. Local carrier evidence: the three-hop natural-scheduler regression
> (`crates/node/tests/gc2_queue_service.rs`) delivers 64 × 11 KiB bulk records
> plus interleaved chat over the shared padded lattice and passes 7/7 after the
> merge. The fleet canary and scale gates on the carrier profile remain open.

## Real fleet observations

All runs used eight isolated test relay listeners on the recorded Hetzner hosts,
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
