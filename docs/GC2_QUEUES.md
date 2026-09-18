# Experimental GC/2 relay queues

The node's `experimental-gc2` feature exposes natural-cell deposit and
subscription admission on `LeaseStore` and an explicitly installed
`gc2::QueueService`. Production GC/1 handlers and profiles have not switched to
them.

Every deposit authenticates its queue, epoch, expiry, class and exact encrypted
message under the GC/2 domain. Interactive and bulk each have their own FIFO.
GC/1 has a separate FIFO and cannot consume or implicitly convert GC/2 records.
All three share the same per-lease cell/byte limits, relay byte limit and push
replay budget. A failed capacity reservation does not consume a nonce.

An exact GC/2 retry returns duplicate acceptance without enqueueing or notifying
again. Reusing its nonce with changed class, expiry, message, cover/data status or
wire version returns a conflict. Authentication precedes this lookup, including
for retries. The experimental build stores a 32-byte envelope digest plus the
optional-value tag and structure alignment in each replay record; this is
additional bounded RAM, not traffic overhead. Replay records remain until their
original expiry. Dequeue does not free replay capacity.

Subscription admission returns an opaque handle fixed to the authenticated class,
epoch, expiry and queue incarnation. Each peek and acknowledgment revalidates it.
Rotation wakes both classes and invalidates the previous handles; queued data
remains available to newly authorized subscribers. Revocation and lease expiry
remove the queue and close its notifications. Recreating the same queue ID and
epoch cannot revive a previous handle.

Per-class watch notifications remember a change that occurs between an empty peek
and waiting. Multiple updates can coalesce: a stream owner must check the queue
again after every wake. Deposits and successful dequeues notify only their class;
cover, duplicate retries and rejected deposits do not notify. No background task
is created by the store. The stream owner selects on notification,
absolute subscription expiry, connection cancellation and shutdown. The
notification itself does not extend a subscription or prove delivery.

Class splitting adds two bounded notification channels and FIFO metadata per
lease. It does not allocate another admission pool or another payload allowance.
The API has no cover timer and no traffic-profile selection.

## Owned terminal service

`QueueService::handler` attaches to TP1's owned duplex request handler. Its
separate `gc2/<canonical-base64url-queue-id>` path is bound to the authenticated
envelope's queue ID. Unknown paths, invalid MACs and malformed/version-mismatched
envelopes use the existing decoy response. Post-authentication acceptance,
conflict and overload use HTTP 200 and one eight-byte GC/2 ACK status cell.
The ACK payload is the existing two-byte version-1 hop-status encoding inside
the version-2 natural cell; it is never a recipient/application receipt.

A subscription starts with explicit hop acceptance, then natural MSG cells of its
authenticated class. The handler waits on queue changes when empty and HTTP/2
credit when full. Rotation/revocation also interrupts a blocked writer. An
absolute subscription deadline bounds idle periods and writes, and transport
shutdown owns cancellation of the whole handler. Bytes already accepted by the
transport cannot be withdrawn by revocation.

The client prepares authorization after connection/request admission, requires
the envelope's authenticated class to match its route and preserves exact retry
bytes. Natural framing handles split/coalesced cells with at most one
cell and one HTTP/2 frame buffered. Partial reads survive cancellation; malformed
or truncated framing terminates the stream. Opening requires explicit acceptance
within the ordinary setup deadline. Once open, the caller's absolute subscription
deadline replaces the legacy cell-arrival idle timeout. The API creates no inner
cover and never decodes GC/1 as a fallback.

The real TLS fixture deposits an 11 KiB bulk message and a 128-byte interactive
message through independently pinned entry, middle and terminal services using
one shared physical entry connection. Separate fixtures cover private-path/MAC
failures, partial reads, slow-reader revocation, expiry and shutdown ownership.
These are transport/queue tests with synthetic MSG payloads, not real application
encryption, persistence, receipts, throughput or privacy qualification.

Private discovery/re-entry, production node routing and profile selection,
SDK/GChat integration, application receipt trials, packet-observation privacy
tests and mobile power measurements remain separate unfinished gates.
