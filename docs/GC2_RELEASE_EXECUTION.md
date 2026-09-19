# GC/2 correction and release execution

Owner direction (2026-09-19): implement the end-to-end release plan. Privacy and
performance thresholds are informative comparisons, not automatic release vetoes.
Present measured alternatives and obtain the owner's profile/migration selection
before deployment. Encryption, authentication, protected routing, durable delivery,
and state continuity remain required. Physical mobile testing is deferred.

Scope: separated GComs, GChat, and original coms host integration only. Release to
eight native Hetzner relays and three Kubernetes anchors; publish signed Linux
x86_64, Windows MSVC x86_64, macOS x86_64, and macOS aarch64 installers. Publisher:
Gh0st, using owner-requested self-signed preview certificates (2026-09-20).
Public CA trust and Apple notarization are outside this release policy. Pinned
signature verification and all correctness/evidence requirements remain required.

## Ordered work

1. Remove protected-route bypasses; test unavailable routes, direct-dial tripwires,
   natural subscriptions, compatible legacy clients, and durable recovery.
2. Correct packet parsing, direction, time normalization, AUC ties, and independent
   run uncertainty. Invalid evidence must fail; a valid privacy measurement over
   the reference threshold must remain an informative result.
3. Bind captures and results to exact source, scripts, executable, configuration,
   and workload. Preserve prior failures and reports. Measure real persistence,
   exact IDs/bytes/receipts, tail latency, admission delay, and interface costs.
4. Compare full cover, interactive cover with immediately eligible bulk, and
   lower-data profiles. Screen 1/2/4 KiB at 250/500/1000/1500 ms. Compare bounded
   randomness against the same mean deterministic traffic budget. No profile
   change may be triggered by chat arrivals or remaining monthly allowance.
5. Run isolated production-cadence comparisons: idle/sparse/burst/bulk/mixed;
   unconstrained and 100 ms RTT, 10/2 Mbit/s, 0.5% loss links; 1/4/16 clients.
   Finalist privacy cohorts: 10 training and 20 held-out runs per workload/link,
   60 seconds warm-up and 300 measured seconds. Bootstrap independent runs,
   not adjacent windows. Performance: five balanced repeats, >=100 chat messages
   and >=1 MiB applicable transfers, with all incomplete operations retained.
6. Present the owner with privacy/latency/bandwidth alternatives. Report costs at
   8 and 24 connected hours/day, including all directions, entries, control,
   padding, and retransmissions. Mobile energy and availability stay unqualified.
7. Freeze the selected source/profile/artifacts and complete native CI, package
   consumers, installer journeys, fault recovery, 24-hour parser fuzzing, and a
   24-hour application soak with >=16 clients and four channels. The existing
   release inventory remains required; historical builds do not qualify new code.
8. Prepare and rehearse state-compatible rollback including every service drop-in.
   Canary r1 for >=1 hour, then gc-anchor-2 for >=1 hour. Update remaining natives
   individually, then anchors individually, with >=15 minutes and successful
   application checks per instance. Never restore stale crypto state as rollback.
9. Publish immutable verified artifacts, verify public downloads/installations,
   and observe the fully updated fleet for 24 hours. Retain the exact running
   executable hashes and the owner-selected privacy tradeoff in the final report.

## Initial audit baseline

- Native r1-r8 executable: 6e4a6cb12713cba6f7bf871100f45ca26078a398d0ceccde97506fe57e6c1c31.
- Anchors 0-2 executable: 12172ea6d594ec04eea6ced7d1e4c05a460eaeb525a09df84a2121d126f1ffdf.
- Existing capture reports fail their privacy threshold and contain analyzer
  errors. They remain diagnostic evidence, never a qualified current release.
- Existing release tooling only accepts GC/1 manifests; explicit GC/2 evidence
  support is required. Signing fingerprints, rights/operator review evidence,
  and the final profile selection remain outstanding.
- Pre-existing changes to GComs relay_service/queues and fleet flow/direct retry
  handling are shared work. Preserve them and validate the combined source.

Implementation status is tracked by commits and retained test reports. No fleet
update, signed release, privacy qualification, or completed soak is implied here.

## Correction checkpoint, 2026-09-20

- Protected routes now remain protected when every entry is unavailable. Entry
  readiness wakes durable retries. The cold-start regression delivers before the
  previous minute retry timer; ciphertext copies still reserve bounded memory.
- Full, interactive-only, and bounded-jitter cover profiles are explicit
  experiments. Production defaults have not changed.
- The performance fixture persists atomic archives, verifies message IDs and body
  hashes, counts partial final chunks, and includes admission wait in latency.
  It is a protocol fixture, not an installed GChat journey.
- Packet analysis uses structured fields, includes empty windows, and bootstraps
  independent runs. Historical pooled/entry-only captures remain diagnostic.
  The namespace capture helper captures all loopback traffic and retains failed
  workloads and drop counts, but it does not isolate an individual client.
- Whole-capture inspection found legacy subscription and cover traffic alongside
  the new carrier. Client/channel/file traffic-path inventory and isolated client
  capture are outstanding; record-layer estimates omit this additional cost.
- Public Gh0st signer pins are committed in both repositories. Private signing
  material is outside Git. Native signing and installer verification are pending.
- Local checks: 274 node library tests passed (one privileged test separately
  required), 42 routing tests and three protected-route integration tests passed.
  Strict node/routing Clippy passed. Python suites passed 83 GComs and 41 GChat
  checks. Full repository/native release qualification is still outstanding.
- The original coms fleet port has two unresolved combined-suite failures:
  owner queue role collision and a production client bypass check. It is not
  qualified for deployment.
- Reports and failed attempts remain under `target/gc2-requalification/`. No
  current evidence supports a final anonymity claim or a production profile
  selection. The owner has not yet been presented qualified alternatives.
