# GC/2 implementation ledger

Status: repository consolidation and research-tool migration complete. Bounded
scheduling, session readiness and larger file-chunk work is in progress; see
[the runtime increment](GC2_SCHEDULER.md). GC/1 remains the production wire and
cover profile. No GC/2 compatibility, performance, privacy or mobile qualification
is claimed by this ledger.

## Accepted contract

- GComs owns the protocol; GChat owns its application integration. Coordinate
  endpoint and relay upgrades; no silent wire-version fallback.
- Preserve encryption, authentication, indirect routing, message identities,
  ratchet/MLS invariants and durable recipient/application receipts.
- Target chat-activity protection against a local network observer while connected.
  Online periods and approximate bulk volume may remain observable. Relay or
  both-end observer resistance is not a qualified claim.
- Mobile respects OS suspension. Resume authenticated service without replacing
  the user's identity or pretending an availability gap was protected.
- Monthly privacy-extra targets are 250,000,000 mobile and 1,000,000,000 desktop
  bytes across both directions and all connections. They are advisory: no
  target-driven delivery block, padding removal or profile change.

## Ordered implementation

1. **Source consolidation and baselines.** Keep the imported runtime, restore the
   missing analyzers/tests with provenance, and validate GChat against current
   GComs without changing registry manifests. Establish application-level receipt,
   durable delivery and independent-client baselines before runtime comparison.
2. **Bounded scheduler and recovery.** Separate dispatch from completion; add
   interactive/bulk producer fairness, duplicate-attempt suppression and readiness
   barriers. Start with four finite requests per pooled terminal connection,
   at most three bulk requests, 4,096 queued jobs and 8 MiB accounted queued plus
   in-flight payload per node. Existing stricter resource limits still apply.
   Serialize ratchet preparation/persistence, not network waits. Keep counter
   distance below the skipped-key bound across all traffic classes. Reuse committed
   ciphertext and IDs after ambiguous failures. Renew credentials through existing
   authenticated re-entry without extending expired authority.
3. **GC/2 and GCT2 carrier.** Add explicit versioned natural-cell transport and a
   shared authenticated entry carrier with at most 16 logical circuit streams.
   Preserve independent service pinning, capability isolation and route exclusions.
   Bound stream IDs, credits, descriptors, reassembly and all control operations.
   Pack only already available encrypted fragments with no batching timer. Retain
   per-message receipts; no aggregate ACK becomes recipient delivery.
4. **Traffic separation and profiles.** Interactive opportunities carry data or
   padding independently of chat activity throughout connected periods. Bulk uses
   spare congestion-controlled capacity without repeated round delays, with
   reserved interactive flow-control credit. Authenticate traffic class and use
   class-filtered relay subscriptions. Queue notifications replace relay polling.
   Remove redundant inner padding only where the selected outer carrier supplies
   its intended protection; preserve 15 KiB MSG and 16 KiB record ceilings.
5. **SDK and GChat integration.** Add explicit protected desktop/mobile profiles,
   interactive/bulk send options and local aggregate diagnostics. Preserve durable
   acceptance, hop acceptance, recipient acknowledgment and application completion
   as distinct states. Test an 11 KiB useful file chunk within exact maximum
   component/application/ratchet/relay framing and recipient credit; preserve old
   contacts and the current version-2 checkpoint maximum of 32 chunks. Version
   IPC/state schemas only for actual changes, with tested archive migration.
6. **Qualification and coordinated cutover.** Complete the gates below. Preserve
   the previous traffic behavior as an explicit rollback profile inside the new
   implementation. A rollback must preserve current durable state and cannot
   silently downgrade to GC/1. Do not alter admission reservation/replay retention
   to manufacture capacity; report admission delay separately.

## Profile selection and acceptance

Initial candidates: 4 KiB each second for desktop and each 1.5 seconds for mobile.
Evaluate 1/2/4 KiB records at 250/500/1,000/1,500 ms. Select the lowest measured
overhead candidate passing the same privacy/latency gates; break ties by lower
chat latency and freeze the result in a versioned profile. Do not adapt it to chat
arrivals or monthly target balance. If no candidate passes, retain experimental
status rather than weakening the gate.

Use actual application persistence and receipts, five balanced-order repeats,
idle/sparse/burst/bulk/mixed workloads and independently authenticated producers.
Require at least 20% median bulk-goodput improvement in both bulk and mixed cases;
chat p95 must not regress by more than max(5%, 20 ms), including the worst client.
Require complete delivery/accounting, bounded resources and matched connections.
An isolated 128-byte established-session chat message must incur at most three
seconds of intentional one-way shaping delay with its actual encrypted envelopes.

Test malformed/fragmented framing, partial writes, lost replies, duplicate and
out-of-order messages, concurrent initiation, counter-window bounds, PQ/MLS epochs,
slow readers, shutdown, crash/restart, expired credentials, disconnected paths,
class/profile tampering and strict version mismatch handling.

Observe real endpoint packet timing/size/control/connection behavior with independent
training/evaluation runs and matched bulk traffic. Require a predeclared activity
classifier's held-out ROC-AUC upper 95% confidence bound to be at most 0.55, plus
traffic-independent protected scheduling and no chat-triggered extra connections
or bulk emissions. This is a limited empirical gate, not an anonymity proof.

Measure actual interface costs and physical-device power separately. Include
Wi-Fi/cellular, foreground/background, suspension and reconnect. Linux results do
not qualify mobile energy or availability. Missing mobile evidence remains pending.
Retain failures, source/executable/configuration/workload hashes and exact scope.

## Progress

- Imported runtime baseline: original coms `5588d8a`; existing GComs fixes retained.
- Research scripts, tests and aggregate result: migrated with per-file hashes.
- Two-repository source validation: `scripts/check-gchat.py`; package-archive
  validation remains a separate gate.
- Bounded scheduler/terminal pooling, opt-in fixture pipelining, durable session
  readiness and PQ-safe 11 KiB file framing: implemented in the task branch.
- Independent channel data/control maintenance and local aggregate node
  diagnostics: implemented in the task branch; congestion regression validated
  with a real TLS/H2 data response held open through a rejected control attempt
  and its successful retry.
- Node-wide endpoint/transit admission, protected cover allowance and deferred
  relay authorization: implemented; request preparation follows transport
  admission and retries preserve exact bytes.
- Owned cancellation for maintenance, subscription and command work, bounded
  active invitation processing and a shutdown deadline covering command enqueue:
  implemented. GChat tests immediate profile reopen without an arbitrary sleep.
- Explicit natural GC/2 cells and class-authenticated deposit, subscription and
  forwarding codecs: implemented behind `experimental-gc2`; see
  [the codec contract](GC2_WIRE.md). No runtime cutover or carrier qualification.
- Experimental shared GCT2 entry carrier: implemented with two permanent class
  channels, a shared 16-circuit bound, interactive reservations, fixed interactive
  records and immediately eligible bulk. Real TLS fixtures exercise shared
  connections, independent entry/middle/terminal pins, route exclusions,
  class/profile binding and cancellation. Middle transit adds no second padding
  schedule, and the entry owner owns nested drivers. See
  [its exact scope](GCT2_CARRIER.md). Runtime adoption remains pending.
- Class-bound terminal pooling and a prepared GC/2 connector: implemented.
  Bulk/interactive connections share an entry while keeping their class, pin and
  route exclusions; default GC/1 pooling is unchanged. Class-aware subscription
  and warmup APIs are available, with runtime/application propagation pending.
- Replay cleanup skips histories whose earliest expiry is still in the future.
  Retention deadlines, admission limits and queued messages are unchanged. The
  reproducible `relay_queue_cost` example measures only local queue-maintenance
  CPU work; it is not an application throughput or privacy benchmark.
- Experimental authenticated class queues share the existing storage and replay
  limits. Opaque subscriptions revalidate class, epoch, expiry and queue
  incarnation; queue changes wake waiters without polling. Exact GC/2 retries
  bind all envelope bytes. See [queue lifecycle and costs](GC2_QUEUES.md).
  An owned terminal service and explicit natural-cell client now exercise
  authenticated deposits/subscriptions through the shared carrier. Production
  node routing and SDK/application adoption remain pending.
- Explicit private GC/2 introductions, authenticated renewal and bounded
  background entry ownership are implemented experimentally. Ready connectors
  cannot dial a new entry or signal maintenance from a message request. Renewal
  and reconnect run independently of chat, preserving role isolation and route
  exclusions. See [bounds, costs and remaining integration](GC2_DISCOVERY.md).
- Complete counter-window flow control, command preparation/completion split,
  authenticated class propagation, complete GC/2 routing, protected profiles,
  SDK/GChat profile integration and application/privacy/mobile gates: pending.

## Consolidation validation — Linux, 2026-09-17

- GComs Rust workspace at `9c0eb27`: 598 passed, 5 ignored. Its Rust sources and
  dependency lock are unchanged by the subsequent consolidation-tool fixes.
  Strict Clippy, documentation, formatting, minimal-feature builds, wire vectors
  and generated-contract checks passed.
- GChat workspace at `e5148b6`, using the GComs source snapshot: 142 passed.
  The subsequently merged `48812a7` transcript-permission and preview-lock changes
  passed current-source strict Clippy and both affected transcript tests.
- Python tooling: 46 passed, including a real offline Clippy regression against
  an unpublished fixture package and checks that originals remain unchanged.
- Relay harness: 7 passed, 1 ignored. JavaScript: 8 passed, typecheck/build passed.
- Seventeen Rust package archives passed the isolated aliased-consumer check;
  both npm archives passed their isolated consumer check. GChat used source
  snapshots here; this does not claim GChat archive/registry qualification.

Full logs, failure attempts and source-check reports remain in the retained task
worktree's ignored `target/` directory. These checks establish a development
baseline. They do not qualify new privacy profiles, production throughput, mobile
power use or native platforms other than Linux.
