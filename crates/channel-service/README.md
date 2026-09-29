# gcoms-channel-service

Experimental, single-writer ordered channel storage. This library stores public
membership commits and authenticated application ciphertext; it never instantiates
an MLS member or receives a client's private state. It is not yet a network daemon
or enabled in GChat. The caller must supply authenticated transport and reader
authorization before exposing records.

Each append is validated, written with its predecessor hash and flushed to disk
before returning service acceptance. Retries of the exact accepted content return
the original sequence. This is not a recipient delivery acknowledgment. Reopening
replays membership and verifies every complete frame. Only a partial final frame
is truncated; corruption of a complete record fails closed. A failed write poisons
the open store until reopening. Exclusive file locking prevents concurrent writers.
The containing directory and log must pass shared private-filesystem checks.

Storage has explicit byte and record quotas; reaching them refuses new appends.
No accepted record is silently evicted. Memory retains indexes rather than all
ciphertext bodies. This does not yet supply replication, log compaction, policy
updates, network negotiation or latency/capacity qualification.

Dependencies reuse the workspace's `sha2`, `tls_codec`, `gcoms-mls` and
`gcoms-private-fs`; tests use existing `gcoms-crypto` and `tempfile`. No new
third-party package is introduced. Run `cargo test -p gcoms-channel-service` and
strict all-target Clippy, plus the MLS suite, when changing the storage contract.
