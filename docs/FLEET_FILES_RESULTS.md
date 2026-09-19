# Fleet file-transfer findings — 2026-09-18

**Full fleet qualification has not passed.** The harness is implemented and the
file worker liveness defect is fixed, but the standard 64 KiB cross-host canary
still misses its five-minute deadline. The 16-client ramp, 56 transfer pairs,
30-minute baseline, four-hour mixed workload, large files and fault matrix remain
unexecuted behind that gate. See [the runbook](FLEET_FILES.md) for the exact campaign.

## Real fleet observations

All runs used eight isolated GC/1 relay listeners on the recorded Hetzner hosts,
two application clients, fresh test identities, and the production scheduler.
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

* GC/1's production lane rate is incompatible with the planned single-source
  1 GiB/four-hour target. The runbook records the calculation separately from
  measured evidence. Receipt timeouts and repeated requests also need a focused
  queue/admission/retry investigation; raising the acceptance deadline would
  conceal this failure.
* Periodic peer-exchange cells are submitted to a relay path that accepts only
  authenticated MSG payloads, producing `RELAY_PUSH does not contain exactly one
  MSG`. This rejection was traced to `node/channels.rs`; it has not been proven
  to cause the file timeout. Preserve the MSG-only relay boundary when repairing
  peer discovery.

The next qualification step is to resolve the small-file latency/receipt issue,
then rerun the standard canary and the unchanged scale gates. Compare GC/2 only
after its application integration is available. These results do not qualify
GC/2, Windows, desktop attachments, production listeners, or large-file transfers.

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

The committed GC/2 component branch (`74c783e`) has been merged into this task.
GC/1 remains the selected Node/GChat fleet profile. GC/2 application adoption is
still required for the large-file capacity gate; these changes do not constitute
a new fleet result.

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

The latest committed GC/2 component work (`b4a6c26`, including ratchet credit) has
been merged into this task. An explicit natural scheduler now connects that
transport to the existing bounded scheduling API. Its three-hop local regression
checks 64 bulk records of 11 KiB alongside chat and owned subscriptions; it does
not yet send GChat files or enable GC/2 in Node's default startup. The standard
canary and every remaining scale/capacity/fault gate still require a passing
application deployment. See [the integration boundary](GC2_SCHEDULER.md).
