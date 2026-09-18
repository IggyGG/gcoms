# Bounded scheduling increment

This increment prepares GC/2's runtime while keeping GC/1 as the production wire
and cover profile. It does not implement the shared GCT2 carrier or qualify a new
anonymity profile. Four-way lane pipelining is available to explicit fixtures
through `SchedulerProfile::with_pipelining()`; production lanes retain their
existing single-attempt limit, slot interval, emission probability and cover.
Slot clocks now advance independently of completion, skipping missed slots.

Relay envelope preparation waits until the pinned connection and HTTP/2 request
capacity are ready. This gives a new hop nonce and expiry their useful lifetime
after admission, subject to the original credential expiry. Expired credentials
fail without renewal or extended authority. Prepared bytes are cached across both
transport reconnects and scheduler connection retries; end-to-end ciphertext and
message identities remain unchanged. Subscription authorization follows the same
rule. Existing request deadlines still include the admission wait.

## Requests and connection ownership

A pooled terminal HTTP/2 connection admits at most four finite requests, including
response bodies. Bulk can occupy at most three. Waiting for a bulk permit does
not consume the reserved interactive capacity. All admission permits release on
completion, error, cancellation and timeout. A slow request does not evict a
healthy shared connection or its subscription.

Concurrent requests for the same pinned route coalesce connection establishment.
Waiting for that route does not consume an independent connection-attempt slot.
At most four connections are established concurrently. The existing eight-entry
idle pool has a separate hard bound of 64 live terminal connections, including
busy connections and their drivers. Eviction aborts the owned driver when its last
borrower disappears. Pins and canonical route exclusions remain in the pool key;
lane warmup uses its authenticated cover route's exclusions.

These terminal bounds are separate from the future GCT2 limit of 16 logical
streams per shared entry connection. They do not change the relay's allocation
pool, admission reservations, replay records or credential expiry.

## Scheduler and readiness

A node retains at most 4,096 jobs and 8 MiB of accounted queued plus in-flight
work. Accounting includes ciphertext, a maximum wire buffer and retained copied
authority; existing lane bounds remain stricter where applicable. Admission uses
reject-new semantics. Dequeue does not release credit. Shutdown and lane closure
cancel warmup and active requests and drain queued receipts. Cover-enabled
endpoint and transit schedulers share this node-wide allowance. Together they
reserve 2 MiB and 128 jobs for one maximum-size cover request per lane. Payloads
share the remaining 6 MiB and 3,968 jobs; a standalone cover scheduler reserves
1 MiB and 64 jobs. No-cover fixtures retain the full allowance. Each lane has at most one cover request in flight, so a slow
cover response cannot fill its entire pipeline. Payload admission never borrows
unused cover credit.

Producer classes rotate, with byte-charged deficit round robin between destination
queues within a class. This is destination fairness; distinct SDK components
sharing one destination do not yet have separate authenticated producer IDs.

Pipelined fixtures suppress an identical semantic attempt while it is queued or
running, including across intermediary rerouting. A completed or canceled attempt
can be retried with the committed ciphertext. Deduplication includes semantic
headers and destination authority, not only payload bytes. This is in-flight
suppression, not a durable-delivery acknowledgment.

Local deposit and forwarding submissions check the inner MSG type, version,
flags and 15 KiB payload ceiling before creating a lane or reserving resources.
Malformed work returns `EnqueueError::InvalidCell` and increments the opt-in
`rejected_invalid` counter; it cannot warm a connection or consume a scheduled
opportunity. This allocation-free check does not authenticate or prepare a relay
envelope. Nonces, MACs and expiries still wait for transport admission, and the
wire encoder retains the same checks.

The 24-node fixture exposed legacy channel maintenance submitting raw PEX cells
to an MSG-only deposit API. Those submissions now fail before scheduling. The
producer and its authenticated anti-entropy replacement remain follow-up work;
this change does not enable plaintext PEX or establish application goodput or
privacy qualification.

When a pipelined fixture initiates a direct session, later durable applications
retain their logical records, IDs, ordering and original deadlines until the
session is confirmed. They consume no ratchet counters while waiting. Ordinary
non-durable callers receive explicit backpressure during that wait. Control
recovery remains necessary for a peer whose receive address changes during setup.

Archive `GCNSTJ` (v19) extends the durable-deferred-record invariant to known
sessions without requiring a routing-recovery directory. v15–v18 migration is
covered, including both historical v16 grammars, retained channel grants, machine
scope and owner aliases. Older binaries must reject v19; rollback must use a build
that understands the current archive. No identity or journal reset is required.

Still required before enabling pipelining in production: counter-window flow
control covering ACK/control traffic, removal of command-level network waits,
component fairness and the application-level comparison in the implementation
ledger. The local scheduling `TrafficClass` is not yet an authenticated wire field.

Channel data and control recovery now have independent maintenance loops. A data
batch can wait for up to 120 seconds; it no longer postpones the next retry of a
membership commit or ACK, whose convergence window is 90 seconds. Both loops still
submit through the existing scheduled lanes. A hop acceptance clears a retained
control record only if its full route and ciphertext still match the attempt.

Direct maintenance also advances independently of outstanding receipts. Its owner
retains at most 16 ACK attempts and 48 retry attempts, all submitted through the
existing scheduler. GC/2 session fixtures additionally charge retained direct
payloads and owned retry copies to the same allowance, with control and dispatch
headroom; see [retention admission](GC2_FLOW.md#shared-retention-admission). GC/1
retention behavior remains unchanged. Due retries
are selected oldest first; only selected attempts
move their retry timer. Identical committed ciphertext cannot accumulate attempts
across ticks or intermediary changes. Rewritten ciphertext after session recovery
is a distinct attempt even when the logical message ID stays the same.

ACKs remain in the bounded, archived outbox while in flight. Hop acceptance clears
matching ciphertext only if the receiver's authenticated queue still matches the
attempt. A changed receive queue or failed attempt leaves the cached ACK for a
later tick, behind other waiters. No new ratchet counter is consumed to retry, and
hop acceptance still does not complete a pending application delivery. A real
TLS/H2 regression holds one retry's response open while a newly queued ACK retries
on an independent lane and presence expires. This removes a maintenance stall;
it is not evidence of an end-to-end throughput gain or wider ratchet safety.

`NodeHandle::enable_diagnostics()` and `diagnostics()` expose bounded local
aggregates for client and relay schedulers, their local resource use and the
shared node budget. Local peaks occur independently; use the combined snapshot
instead of summing peaks to evaluate the node bound. They contain
no contacts, message IDs or payloads and do not change scheduling. Startup work can
precede counter activation; these snapshots are diagnostics, not a complete
application-delivery or interface-bandwidth accounting record.

Maintenance batches, subscriptions and commands now own their concurrent futures
directly. Canceling their parent releases all child references before shutdown
returns, allowing GChat to reopen the encrypted profile immediately. Invitation
processing owns at most 64 active redemptions in addition to its bounded inbox;
successive maintenance ticks cannot accumulate detached workers. The command
shutdown deadline includes waiting to enqueue the request into a full queue.
Per-peer/channel command serialization still includes network waits; this is
resource ownership and shutdown recovery, not the remaining preparation split.

## Larger useful file chunks

The SDK recommends 11,264 useful bytes, negotiating down to the recipient's chunk
and byte-credit limits. Old v1/v2 8 KiB contacts remain usable. The checkpoint
maximum stays 32; an existing 262,144-byte credit grant allows 23 full 11 KiB chunks
(259,072 bytes), never 32 merely because the chunk count cap permits it.

The framing test constructs and decrypts an actual ML-KEM-768 rekey frame with the
full ML-DSA sender identity, scoped application envelope and both relay wrappers:

| Layer | Bytes |
| --- | ---: |
| Useful file data | 11,264 |
| File record | 11,331 |
| Component application | 11,455 |
| Reliable direct plaintext | 11,481 |
| PQ ratchet frame | 12,669 |
| Natural MSG including header | 14,630 |
| Natural RELAY_PUSH | 14,735 |
| Natural FRWD | 14,851 |
| Existing padded wire cell | 16,384 |

This is 37.5% more useful file data per full cell, or 27.3% fewer full cells for a
large file, before receipts and final-chunk effects. It is not a measured 37.5%
end-to-end throughput improvement. A complete 32-chunk window requires 360,448
bytes of recipient credit instead of 262,144; the sender cannot enlarge that grant.

The test also pins the maximum ratchet overhead at 1,188 bytes. Direct admission
now checks the complete logical record plus sender identity against that worst
case before consuming a counter or claiming durable acceptance. The general
12 KiB application ceiling alone was insufficient for a full PQ direct frame.
Existing receive/archive limits and the 15 KiB MSG / 16 KiB wire bounds are retained.

## Privacy and costs

This increment does not reduce cover traffic. Carrier sharing and qualified
protected profiles are still necessary to address that cost. One continuously
connected duplex carrier, before TLS/TCP overhead or retransmissions, costs:

| Schedule | Bytes per 30 days | Decimal GB |
| --- | ---: | ---: |
| Existing 4 KiB / 100 ms | 212,336,640,000 | 212.34 |
| Desktop candidate 4 KiB / 1 s | 21,233,664,000 | 21.23 |
| Mobile candidate 4 KiB / 1.5 s | 14,155,776,000 | 14.16 |

Useful data replaces some padding. Additional connections and bulk traffic add
cost. These are arithmetic budgets, not measured bills or mobile energy results.
The candidates still exceed the advisory 1 GB desktop / 250 MB mobile targets;
neither exceeding a target nor OS suspension silently changes the privacy policy.
