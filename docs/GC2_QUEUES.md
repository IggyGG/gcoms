# Experimental GC/2 relay queues

The node's `experimental-gc2` feature exposes natural-cell deposit and
subscription admission on `LeaseStore`. These APIs are plumbing for the new
carrier; production GC/1 handlers and profiles have not switched to them.

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
is created by the store. A future stream owner must select on notification,
absolute subscription expiry, connection cancellation and shutdown. The
notification itself does not extend a subscription or prove delivery.

Class splitting adds two bounded notification channels and FIFO metadata per
lease. It does not allocate another admission pool or another payload allowance.
The API has no cover timer and no traffic-profile selection. Carrier integration,
application receipt trials, packet-observation privacy tests and mobile power
measurements are separate unfinished gates.
