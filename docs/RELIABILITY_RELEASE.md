## Immediate sending and randomized cover, 2026-09-25

Owner-approved policy: real traffic sends when transport capacity is available;
interactive cover opportunities are independently uniform 10–10,000 ms; an
opportunity is skipped if that writer sent real data since the previous one. GChat selects
new authenticated profile 46, preserving old profile meanings. This removes
intentional cover-slot waiting, not congestion or route setup. Timing/activity
privacy is reduced and unqualified. Extra bursts remain deferred. See
[traffic policy](GC2_TRAFFIC_PROFILES.md) for costs, migration and limitations.
Current validation must prove immediate data/EOF, bounded cover and no catch-up
burst, suppression after sent data and idle resumption, old-profile compatibility, durable profile
selection, class isolation and real application delivery/recovery. R02/R03/R04
remain open until source-bound application measurements pass; prior slow/failed
runs remain failures. No deployed or installed behavior is claimed by source edits.

# GChat/GComs reliability release

Owner-approved sequence, 2026-09-24: repair and qualify the current network,
release it, then develop neighbour-graph routing separately. This is the current
requirements contract; older chronological plans and receipts retain their
historical scope. Statistical privacy thresholds and mandatory 24-hour campaigns
are not release gates. Authentication, persistence, correct delivery, pinned
signatures and state-compatible rollback remain required.

The user has deferred physical Android and iPhone testing for now. Continue with
cluster Android emulators, the Mac iOS simulator and automated application journeys.
Physical-device behavior, battery results and live APNs/FCM delivery remain
unverified; they are not prerequisites for this deferred scope.

## Requirements

Timing starts at the user action (excluding human invitation/passphrase input),
or at restoration of usable connectivity for reconnect. Healthy-network tests
must have enough independently usable relays and available capacity. Do not
restart a deadline after retries, discard slow successes, or replace ceilings
with averages. Each case reports its actual prerequisites and all observations.

| ID | Required behavior | Proof |
| --- | --- | --- |
| R01 | Visible feedback within 200 ms for unlock, join, send, download, retry | Native/browser interaction timestamps; correct unlock immediately shows progress |
| R02 | Online message display and authenticated ACK within 5 s | Ten simultaneous senders; correlate exact message IDs and recipient ACKs |
| R03 | Retained unlocked session recovers within 10 s after usable connectivity returns | Suspend, restart, Wi-Fi change and relay loss; same identity and membership |
| R04 | Valid invitation joins within 30 s, with meaningful progress/errors | Fresh and retained clients; invalid/expired/replayed invitation controls |
| R05 | Local admission is not delivery; retries preserve ID/wire | No early delivery, failed first hop, failed wrapper/archive writes, reopen |
| R06 | Durable state and verified pieces survive interruption | Abrupt termination and injected storage failures; exact retained IDs and hashes |
| R07 | Files show progress and export verified complete bytes | Small file on each device path; release-blocking 16 MiB abrupt-resume/hash/reopen check; ~123 MB and 1 GiB campaigns separate |
| R08 | Stalled work cannot starve healthy channels/chat | Saturation/release, large/small backlogs, ten native participants all forwarding |
| R09 | Established network survives initial bootstrap loss | Discover an eligible new relay, remove initial bootstrap services, continue work |
| R10 | Mobile lifecycle and optional notifications work | Permission denial/opt-in/out, token rotation, live FCM/APNs, tap and reconnect |
| R11 | Security and bounded resource use survive failures | No direct/legacy fallback, forged ACK rejection, authority expiry, teardown |
| R12 | Installed release matches tested candidate and can roll back safely | Exact paired sources, binaries, signatures, upgrade/reopen and rollback checks |

An outage is an explicit bounded failure/reconnecting state, never false delivery.
Case failure, dependency-blocked, timeout and infrastructure failure are separate
results; none counts as a pass. A late continuation cannot change the original
deadline verdict.

The owner removed the 1 GiB release gate on 2026-09-25. The file-recovery
controller's `--release-check` preset uses 16 MiB, a 180-second completion budget
and a 600-second ceiling for the entire run, including setup, abrupt restart,
retained-piece/identity checks, concurrent authenticated chat, final hash and
orderly reopen/export. Authentication, persistence, signatures and rollback
remain mandatory. Failure blocks the bounded gate; it is never excused by the
separate campaign. Both retained 1 GiB runs timed out at their original
1200-second completion budget, including the node-local-storage retry.

Outside that explicit preset, the controller keeps its 1200-second default completion budget.
A separate full-size correctness run may predeclare `--file-completion-seconds`
(60–3600 seconds); the value and original failures stay in its receipt. This does
not qualify latency or revise a previous timeout. A completion observed after
that one fixed deadline is rejected before export verification.

## Work order

1. Preserve current profiles/jobs/evidence; collect terminal jobs. Maintain one
   requirement-to-test/result ledger and use fixture profiles for fault tests.
2. Add an independent-case runner and bounded stage diagnostics. Export optional
   aggregate telemetry through OTLP outside hot paths. No contents, credentials,
   invitations, filenames, production relationship IDs, IPs or route maps.
3. Reproduce and batch-fix shared GComs recovery/admission/fairness defects before
   another mobile build. Cover owner expiry, retained inboxes, incomplete referrals,
   middle-only renewal, unrelated published churn and archive publication errors.
4. Expose typed operation/recovery stages and sanitized failures through existing
   SDK/UI contracts. Preserve IDs, authentication and generated-client consistency.
   Keep optimistic pending messages distinct from authenticated delivery.
5. Run host/component checks and real GChat journeys in the cluster. Ten native
   participants must send and forward; four Android emulators and the native iOS
   simulator add installed-app coverage without pretending mobiles host relays.
6. Freeze one source pair, run official native/consumer checks, then build each
   platform candidate once and distribute the exact artifacts to device tests.
7. Verify signed upgrade/rollback; canary chat/file/reconnect checks; roll remaining
   authorized relays sequentially; publish and finish store submissions. Report
   uploaded/review/published separately. Platform blockers do not stop unrelated
   platforms, but do prevent claims that the affected platform is complete.

Compile/test independent cases in a batch and retain all failures. Reuse unchanged
source-bound evidence and dependency caches. Do not duplicate active builds or
require the personal phone to discover ordinary shared-runtime bugs. Heavy work
runs in cluster/platform workers, not on the user's interactive laptop.

Consecutive credential expiry and the unchanged 1800-second carrier cap are
separate cases. Fast tests may advance a controlled clock after establishment;
real elapsed-time evidence must be labelled separately. No authority extension,
shorter route, relaxed trust or synthetic delivery may make a test pass.

BrowserStack foreground iOS checks do not establish APNs qualification: its
documented push flow requires Enterprise signing. Qualify live APNs on a signing-
compatible device/provider before claiming the iOS notification gate. No purchase
or change to signing trust is implied.

## Initial implementation evidence

The independent-case runner, source-pair patch coverage, strict observation
deadline and actual-daemon fixture changes passed 180 Python regressions on the
cluster. Red controls exposed omission of the `gcoms` facade, late-success
acceptance, insufficient distinct relay candidates, and a reply being mistaken
for a sender delivery ACK. The fixture now uses six relays for five-hop routes;
the historical capture's default topology is unchanged. The `smoke` mode checks
chat, a small verified file and retained reopening without claiming expiry or
latency qualification. No production Rust code changed in this initial boundary.

Retained receipt: paired GChat checkout
`target/channel-reconnect-20260923/reliability-20260924-01/harness-evidence/summary.json`.
Its eight source hashes and original red/green logs bind that limited scope.
The first full script run's interruption and the original Android 1019 smoke
failure remain retained. Shared-runtime, actual-app and installed release gates
must still be completed before promotion.

The actual-application turnover controller also supports cluster kernels which
create an inert `tunl0` in every network namespace. It retains the raw inventory
and admits only a down, unaddressed IPIP fallback with no route through it.
Unexpected interfaces, configured/up tunnels and external/default routes still
fail qualification. The historical privacy capture controller is unchanged.

## Next protocol milestone (not this release)

First deliver an offline specification/simulator for 10,000 participants:

- Names plus underlying network identity; at most seven active neighbour
  admissions per device profile, not a guarantee of forgetting historical IPs.
- Restricted peers connect outward to verified reachable peers. Reachable peers
  prefer restricted peers while preserving connectivity/resilience. Account for
  public slot shortages; a one-link participant remains a client.
- Authenticated established links carry streams in either direction. Share signed,
  sequenced, expiring ID adjacency; keep addresses and local load out of the map.
- Bound admission using network-maintained state; self-reported hashes alone do
  not prove completeness. Preserve authorization independently of public IDs.
- Compare complete route alternatives and shared bottlenecks, preferring independent
  onward choices, then local capacity/latency. One valid route remains usable.
- Use compact graph storage, delta reconciliation and bounded destination caches.
  Benchmark acyclic route summaries against small exact reference graphs.
- Evaluate NAT ratios, unavailable nodes, churn, partitions, invalid/stale records,
  exhausted slots, computation/update cost and unreachable pairs.

The current five-relay policy remains until a separately accepted replacement and
versioned migration are qualified. Do not silently substitute a graph prototype.
