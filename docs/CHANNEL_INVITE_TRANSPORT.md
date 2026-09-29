# Bounded channel invitation replies

An MLS Welcome grows with the channel's ratchet tree. The six-member actual
GChat fixture exposed an owner reply above the unchanged 12,217-byte worst-case
post-quantum direct-record ceiling. Increasing a packet limit is not the repair.

Small replies retain the existing `InviteWelcome` wire format. A larger successful
reply uses direct record kind 12, `InviteWelcomeChunk`: a unique receipt ID,
original invitation request ID, SHA-256 of the complete Welcome, total length,
canonical 8192-byte offset and one bounded piece. The maximum Welcome remains
256 KiB (32 pieces). Each record fits existing session/flow/packet limits and
uses the authenticated control path. Up to four first-hop completions run
concurrently, with normal credit, persistence, deadlines and retry ownership.
Large replies require a receiver with this record kind; older receivers cannot
join those larger groups. Previously working small replies remain compatible.

The sender's retry key is the logical ID actually encoded in its record. This
also fixes existing invitation request/reply ACKs referring to a different ID
than the pending outbox. A duplicate pending ID is rejected before sequence or
session mutation; it cannot overwrite another pending record.

The receiver only allocates assembly state for a live pending request whose
expected owner matches the authenticated session peer. At most 64 pending
requests and 256 KiB per assembly are retained. Canonical lengths, offsets,
digest consistency and duplicate content are checked. No partial Welcome wakes
the caller. Receive persistence must succeed before updating the assembly or
returning the completed Welcome; the caller still verifies/applies MLS membership.
Control receipts never emit user-message delivery events.

Assembly buffers are transient request state, not a crash-durable completed join.
Cancellation or restart does not claim successful membership. Explicit retry uses
the existing persisted pending MLS join and the owner's idempotent admission
cache, with a fresh response correlation. Sender chunks retain exact logical
bytes, receipt IDs and encrypted wire in the existing retry archive. New chunk
records waiting behind flow credit require a compatible reader; a rollback must
use a separately qualified compatible artifact/state path, not assume every old
binary accepts newer pending records.

The production cover schedule, authority lifetimes, routing path and packet limits
are unchanged. The original six-member failure is retained in
[evidence](evidence/ten-client-application-red-20260925/summary.json). Application
qualification on the repaired source is separate from controller/component tests.
