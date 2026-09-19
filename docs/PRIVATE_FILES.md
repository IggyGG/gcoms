# Private piece exchange v1

The `gcoms-file-transfer::swarm` module supplies durable, independently
verifiable pieces above GComs. It has no sockets, tracker, public DHT, public
content discovery, or alternative transport. The host supplies a private cache
key, authenticated current membership, a clock, and transport for emitted
actions. The existing streaming transfer API and its journals remain separate.

A source imports a file under a random 128-bit share handle. Its descriptor
contains the conversation scope, safe display name, length, SHA-256 plaintext
digest, SHA-256 Merkle root, and a fresh AES-256-GCM content key. A scope is one
channel, optionally restricted to exactly two sorted channel member identities.
Descriptors and availability are exchanged only with authorized current members.
New channel members can discover retained channel shares; PM scopes never expand.

Pieces contain up to 256 KiB plaintext. Each encrypted piece stores a fresh
96-bit nonce, ciphertext and authentication tag. Associated data binds version,
share handle, channel, size, piece index and any PM participants. Once committed,
the ciphertext is immutable and every source serves those same bytes. Fresh
nonces also make pre-commit crash retries safe. An existing imported piece must
match on retry; a changed source needs a new share. Merkle leaves bind the piece
index and the complete encrypted bytes. Domain-separated branches pad to the
next power of two; empty files have a distinguished root and empty-file digest.
Each piece must pass its proof and AEAD check before becoming durable progress.
Completion additionally requires a linear plaintext digest pass. Source imports
write a compact index of ciphertext hashes once; serving a proof reads its tree
path without rewriting or rehashing a growing file prefix. Received sparse pieces
retain their individual proofs.

The bounded postcard records use content type
`application/vnd.gcoms.pieces.v1`. Discovery and descriptor pages, paged piece
inventories, requested blocks, unavailable replies and durable-completion receipts
are separate from chat messages. Blocks carry at most 11 KiB; the complete
encoded record is checked against the GComs application payload budget. Unknown,
duplicate and stale request IDs do not advance progress. Missing blocks retry
after 30, 60 and 120 seconds, then back off and choose another source. Sparse
verified progress survives restart. A source can serve verified pieces of an
accepted incomplete download.

The receiver chooses rare pieces first, with four simultaneous piece requests
and at most two active downloads. It remembers up to 64 candidate peers and
rotates inventory probes in groups of four, so early unavailable advertisements
cannot permanently crowd out later caches. There are at most four active sources
per download. File payload buffers in the engine are bounded independently of
file length; metadata and inventory bounds are separate. A file is limited to
10 GiB and a cache to 256 retained share records.

The cache has an exclusive owner lock, owner-private directories, encrypted
metadata, and atomic durable piece/journal replacement. Reopening verifies
retained pieces once and preserves good pieces when another fails. Progress is
written after durable piece storage. Imports can recover a piece written before
its journal bit. Completion receipts are stored with the encrypted metadata.
Default admission reserves 10 GiB, including overhead, and completed content is
retained for seven days. Accepted active jobs are never evicted to admit another
job. Explicit imports/downloads can evict the oldest completed copies; unsolicited
descriptors cannot. Old offers and cancellation tombstones also expire. A file
near the maximum size therefore needs more than the default quota.

The SDK `send_channel_application` uses the authenticated channel-direct
envelope with disposition 3. These frames bypass text receipt bookkeeping and
are submitted to the data producer, not the channel-control producer. GChat
filters the content type before transcript persistence and applies the piece
state machine in a dedicated worker. Older receivers ignore the new disposition;
there is no fallback that sends file records as text.

The transfer service uses the GComs data scheduling seam and bounded host
admission. On the carrier profile the scheduler maps channel application data to
the authenticated data class, and both classes then ride the shared padded
lattice. Qualifying chat latency and file goodput under the deployed lattice, and
the remaining natural-carrier integration items, are transport gates that fixture
tests do not establish. No cover cadence, routing rule or privacy policy is
changed here.

Tests in `crates/file-transfer/tests/swarm.rs` cover sparse recovery, corruption,
wrong proofs/context, bounded codec input, quota, cancellation, PM scopes, and a
late joiner reconstructing a file from complementary restarted caches after the
original source is gone. The SDK fixture tests the real channel envelope and
more than 64 consecutive file frames followed by chat. These are local fixtures,
not native release or production privacy qualification. The explicit streaming
large-file gate is:

```sh
cargo test --release -p gcoms-file-transfer --test swarm gib_import_resume_export_is_streaming -- --ignored --exact
```

Membership withdrawal stops future service through current roster checks. Copies
and keys already delivered to an authorized member remain in that member's
possession. A download waits for peers when retained sources are offline; this
protocol cannot reconstruct pieces that no surviving peer holds.
