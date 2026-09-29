# Owner-controlled channel recovery

A pending membership change normally retries until every required member sends
an authenticated commit acknowledgement. A disconnected member may recover through
the existing retained-Welcome route-recovery flow; an epoch-bound reconnect code
is not a substitute for that flow.

When a member should no longer belong to a channel, the owner can explicitly revoke
it with `GcClient::channel_recovery(channel, None)` followed by
`channel_recovery(channel, Some(&request))`. The preview supplies the channel ID,
MLS epoch, pending commit ID, revision, roster, missing commit acknowledgements,
and unconfirmed-message counts. Copy those bindings into the request and select
canonical member IDs, never nicknames. Local IPC 22 requires `ChannelAdmin`;
the node independently checks MLS ownership. Older IPC request tags stay unchanged.

Recovery stages one real MLS removal commit for the selected leaves. All members
missing the previous commit ACK must be selected. Any remaining member with an
unconfirmed message blocks the change. Surviving members still owe an authenticated
ACK for the new commit. No elapsed-time rule removes members automatically.

The new group state, retained membership outbox, directory, and revocation records
commit durably before success; a failed checkpoint restores the original state.
A stale preview or concurrent admission is rejected. Repeating a completed removal
is inert, including after reopen. The archive removal-history bound is enforced
before writing a state that could not reopen.

Old message IDs, ciphertext, expected recipients and ACK sets remain intact.
Revocation never counts as delivery. Unadmitted message retries to revoked leaves
stop; already admitted work can finish with its original accounting. Ordinary kick
control notices still transmit. Existing queue/byte bounds remain; recovery does
not clear a full message journal or promise delivery of earlier messages.

A revoked leaf cannot replay a cached admission Welcome, including through a
consumed invitation. A new invitation and fresh MLS leaf can reuse its nickname.
No profile-wide outbox clearing or environment-variable bypass is provided.

Validation covers atomic rollback, stale/partial/owner refusal, exact message
retention, future-message exclusion, idempotent reopen, full removal history,
maintenance accounting, old IPC compatibility and a real GChat invitation/delivery/
kick/reopen journey. See the paired membership-recovery receipt for exact inputs.
