# GC/2 ratchet credit

This experimental protocol component bounds concurrently outstanding encrypted
counters. It does not enable GC/2 in production node routing or qualify a traffic
profile. Every first move, application record, logical application ACK, presence
record and other ratcheted control record participates in the same bound.

## Counter accounting and repair

The sender may advance at most 63 counters beyond the receiver's authenticated
contiguous floor: one less than the ratchet's skipped-key limit. Bulk stops at
distance 47 and interactive application traffic stops at 55. The remaining
eight counters are available to ratcheted control traffic. These are reservations
within one window, not separate counter spaces.

A receiver keeps its contiguous floor plus a 63-bit selective receipt bitmap.
Receiving a later frame does not claim receipt of a missing earlier frame. The
sender retains the exact committed ciphertext for every counter above the floor,
including selectively received frames. Selectively received frames need no retry;
only advancement of the contiguous floor retires their retained state. A retry
uses the original counter and ciphertext, never another encryption of the body.

Application expiry suppresses application effects. It cannot silently discard a
counter still needed to repair the ratchet. The session wrapper stops new sends
when its oldest uncredited frame is 24 hours old, conservatively accounting for
the skipped-key TTL. The owning runtime must then perform explicit authenticated
session recovery, preserving live logical IDs and original application deadlines.
It must not turn expired application work into a fresh message.

## Credit without another ratchet counter

Using a ratcheted ACK to release a full ratchet window can deadlock both peers.
GC/2 credit receipts therefore consume no ratchet counter and request no receipt.
An independent application ACK still expresses application acceptance. Transport
credit never produces recipient-delivery or application-completion events.

Each ratchet plaintext contains a fresh 32-byte random receipt secret. A receipt
can only be constructed after authenticated decryption of that plaintext. HKDF
SHA-256 binds its authority to the GC/2 session tag and SHA-256 of the exact packet:

| Field | Derivation |
| --- | --- |
| HKDF input key | Random receipt secret inside the ratchet plaintext |
| HKDF salt | SHA-256 of the exact committed ciphertext packet |
| Reference, 16 bytes | HKDF info `GC2/credit-reference\0` followed by the session tag |
| AES-256-GCM key, 32 bytes | HKDF info `GC2/credit-encryption\0` followed by the session tag |

An encoded record contains `GCF2`, one purpose byte, an eight-byte application
deadline, the secret, a two-byte body length and the body. Integers are big endian.
An encoded credit receipt is exactly 80 bytes:

| Bytes | Meaning |
| --- | --- |
| 0–3 | `GCA2` |
| 4–19 | GC/2 session tag |
| 20–35 | Packet-specific derived reference |
| 36–47 | Four zero bytes followed by an eight-byte receive count |
| 48–79 | Encrypted floor and bitmap, plus the 16-byte GCM authentication tag |

The first 36 bytes are authenticated associated data. The nonce's receive count
is the contiguous floor plus the bitmap population count. It increases exactly
once per newly authenticated ratchet packet. An unchanged snapshot returns its
cached receipt bytes; a changed snapshot uses a new nonce. A receipt with a wrong
session, unknown reference, invalid tag, noncanonical bitmap, inconsistent nonce,
or coverage beyond the sender's committed counter is rejected without mutation.

The non-acknowledging credit pattern is analogous to the treatment of ACK-only
traffic in [RFC 9002, sections 2 and 7](https://www.rfc-editor.org/rfc/rfc9002.html).
The unique-per-key nonce requirement and parseable associated data follow
[RFC 5116, sections 2.1 and 3.2](https://www.rfc-editor.org/rfc/rfc5116.html).
Neither RFC qualifies this application protocol or proves its anonymity.

## Transaction and storage boundary

`CreditedSession` owns the crypto session and flow window. It permits preparation
without mutation, then commit after the caller's durable transaction. Each
prepared transaction carries an instance-specific revision: credit, send or
receive commits invalidate older candidates, and candidates cannot be committed
to a different session instance or to a restored instance. Exact duplicate
receives have no application record and cannot repeat application effects.

The GC/2 handshake factory authenticates the session tag inside the existing
hybrid first-move signature and binds it to canonical public contact information.
It checks both identity bundles, freshness and local key correspondence before
returning a candidate. Owner provisioning is excluded. The caller binds sealed
state to the tag and peer and resolves simultaneous initiation before publication.
The crypto snapshot, private flow snapshot, outgoing packet and application state
must be persisted atomically before anything is emitted. Only then commit and
send the bytes. A failed persist discards candidates. Restoring an older emitted
state is prohibited: it can repeat cryptographic state, including credit nonces.
Binary rollback must retain the latest durable state.

Private flow encoding contains receipt secrets and retained ciphertext. It must
be nested in the authenticated encrypted node archive; it is not itself an
encrypted file format. Decoding bounds all lengths/counts and checks contiguous
transmit state, receive coverage, required cached authorities and cached receipt
authentication. Reload also checks crypto counters against flow counters.
Retained packet buffers and secrets are shared between staged candidates and
zeroized when their last owner drops them.

Each peer retains at most 63 packets and 63 receipt authorities. This is roughly
one MiB per maximally occupied peer. The node accounts these retained ciphertexts
alongside pending logical records, queued cells and ACK/credit outboxes in the
scheduler's shared endpoint/transit budget. Incoming flow state retains hashes and receipt
secrets, not application plaintext or incoming ciphertext.

Outgoing volatile media retains exact retry ciphertext only in RAM. Its private
flow snapshot uses explicit version 3 and stores the counter, receipt authority,
packet hash and retention marker, excluding the media body and ciphertext. No new
wire traffic class reveals this retention choice. Durable and control frames keep
their existing persistence policy. Live staged receive/ACK transactions share the
RAM retry buffers rather than reopening their intentionally incomplete archive.

After restart, an uncredited missing volatile packet stops new sends and triggers
authenticated session recovery through maintenance. An authenticated selective
receipt can instead establish that the missing packet arrived. Durable logical
work keeps its IDs and deadlines during recovery; expired media is never rebuilt
from disk. Volatile receives use the same bounded logical receipt metadata as
Data, preventing duplicate events after re-encryption without saving the media.

## Compact peer packets and node adoption

`GCH2` (first move) and `GCM2` (established frame) prepend a 16-byte session tag
to the existing encrypted structures. Both have a 20-byte total header. The
established envelope replaces GC/1's kind, length and 1,952-byte identity key,
saving 1,935 bytes per frame before adding the 47-byte credit record inside the
ciphertext. This is a framing calculation, not measured interface goodput.
Credit packets retain their complete 80-byte `GCA2` format. All three are bounded
by the existing 15 KiB MSG limit, including the maximum PQ epoch header. Unknown
versions, noncanonical option flags, oversized KEM fields and zero tags fail.

The node's direct-session transactions now carry either an explicit legacy
session or GC/2 session. `NodeProfile::gc2_session_fixture()` selects GC/2 **peer
sessions only** in the local fixture. It does not select the natural-cell carrier
or a protected production profile. The normal production selection stays GC/1.
GC/2 incoming packets cannot silently establish a legacy session or be restored
under an unselected profile.

The GC/2 archive value (`GCPS`, version 2) encrypts the sealed ratchet and private
flow state together with a random GCM nonce and a separate HKDF key domain. Its
authenticated header binds the session tag; the enclosed ratchet also binds the
machine and peer. Node archive v21 carries this value and the logical receipt ledger and retains explicit GC/2
selection even before any session is created. GC/1 exports keep v19, and existing
session archives retain their GC/1 interpretation. Switching a live GC/1 session
archive to the GC/2 fixture is rejected pending authenticated migration. Decoding all
session candidates and checking duplicate GC/2 tags precede their publication.

Live receive transactions persist credit alongside the application inbox and
logical ACK. Expiry is evaluated once per authenticated prepared receive, so
crossing the flow deadline cannot erase its receipt while the same application
effect is being committed. The independent credit dispatcher never reports recipient delivery.
Exact duplicate setup/data packets can reproduce credit after restart without
repeating application effects. The maintenance owner retries retained ciphertext,
including logical ACKs, within its existing bounded set of active attempts.
Durable sends defer behind confirmation/counter credit; simultaneous initiation
keeps logical IDs, order and deadlines. Contact-key updates are staged with the
post-receive candidate rather than changing live state before persistence.

When a receive commits but no ratchet counter is free for the logical application
ACK, the node persists the ACK obligation (peer-keyed message ID, share-presence
flag and, for application records, the logical receipt) in the same encrypted
ledger instead of failing the receive or consuming an unratcheted copy. Receive
credit and the application effect commit without the ACK, so two peers with full
transmit windows cannot deadlock each other. Maintenance prepares at most 16
obligations per tick, at most four per peer, rotating peers; preparation persists
the exact ciphertext and receipt reference atomically before committing the
counter. Admission failure leaves the obligation pending; an uncertain durable
write pauses publication. The obligation table is bounded to 1,024 entries,
128 per peer, and expires with the application horizon (ten minutes for
non-application obligations). Receipt encoding version `GC2R2` adds the table;
`GC2R1` remains readable from older v21 archives. Transport credit retires a
receipt only after a `GC2R2` ACK was prepared; a migrated legacy archive still
requires its outstanding ACK credit before authenticated recovery.

## Shared retention admission

GC/2 retained direct payloads use at most 4 MiB and 2,048 payload records across
all peers. Ordinary sends stop growing that account at 3 MiB / 1,536 records;
control records, receive transactions and counter credit can use the remainder.
These are sublimits of the existing shared 8 MiB / 4,096 scheduler allowance,
not additional allowances. Production cover reserves remain separate. At the
retained ceiling, at least 2 MiB / 1,920 job slots remain available to endpoint
and transit dispatch, including exact-ciphertext repair. Queued requests may
still cause earlier backpressure.

Positive account changes reserve capacity atomically before a state write.
A failed write or canceled update releases that reservation; shrinking an account
releases capacity only after the write succeeds. RAM-only sessions use the same
admission. Cold restore derives counts from authenticated session windows and
outboxes before publishing them. Parsed encrypted snapshots supply no trusted
resource counts. Metadata, checkpoint scratch and the separately bounded inbox
are outside this payload accounting; these limits are not an exact RAM ceiling.

Owned retry copies reserve dispatch capacity before their futures can be polled.
Cancellation releases that capacity immediately. Deferred materialization waits
for available budget without consuming counters, changing IDs/deadlines or
marking the node's durable state uncertain. A failed durable write still pauses
publication for restart recovery. GC/2 logical ACKs use the ratchet window for
repair, eliminating the legacy replay cache's additional ciphertext copy.
Reliable control records whose ratchet counter is unavailable (forward grants,
contact updates, presence leases) are journalled with empty cells and keep their
ids, order and deadlines; the same maintenance owner encrypts them once a counter
or session becomes available.

## Authenticated session recovery

The signed, encrypted setup has a separate recovery domain and a monotonically
increasing per-peer generation. Initial setup is generation one. A retained peer
accepts only a greater recovery generation; equal-generation collisions are
resolved by identity order only while local initiation remains unconfirmed.
Established sessions reject another tag at the same generation. Exact setup
retries reproduce credit. Recovery can also authenticate first contact when the
original setup never arrived: the same identity, recipient-bundle and signature
checks apply. A known generation is never forgotten merely because setup timed
out, including across restart. Checked overflow refuses further recovery.

Maintenance recovers a session at the 24-hour retained-counter horizon, or when
an unconfirmed setup timed out and live logical work remains. It prepares at most
one peer per tick and backs off each peer for roughly a minute. It uses existing
maintenance dispatch, without an application-triggered entry dial. Replacement
requeues logical records with their IDs, order and deadlines, retires the old wire
outbox, and saves the new generation before emission. Admission pressure preserves
the previous candidate; an uncertain recovery save pauses the node until restart.
The Data or volatile timestamp supplies a fixed ten-minute ceiling, so re-encryption cannot
extend its original lifetime. GC/1 timing remains unchanged.

A consumed inbox entry is insufficient to deduplicate a lost application ACK
across recovery. The receiver therefore saves a logical receipt alongside each
GC/2 Data or volatile acceptance: peer hash, message ID, record hash, lifetime ceiling, and the
session tag/counter of its application ACK. Re-encrypting an unacknowledged record
repeats its ACK without another inbox/event effect; conflicting bytes fail before
commit. Receipt removal requires authenticated credit covering that application
ACK, or expiration of the immutable lifetime. A saved local clock floor prevents
pruned effects becoming live again after a clock correction. This is bounded
retry deduplication, not a permanent application-level ID registry.

The ledger holds at most 2,048 records globally and 128 per peer, with no premature
eviction under pressure. Each encoded entry is 112 bytes: at most 224 KiB plus
49 bytes of sealed-field overhead per checkpoint, independent of body size. Tree
metadata is additional RAM outside retained-payload admission. No extra receipt
packet or duplicated message body is added. The ledger is encrypted with a
separate identity-bound archive context. The private flow format retains its old
generation-one encoding and uses an explicit version for greater generations.

Historical GC/2 v20 archives lack consumed-ID history. Their restored sessions
must credit any potentially outstanding application ACK before recovery. A small
per-peer barrier persists in v21 until that happens; its maximum encoded size is
448 KiB for 8,192 historical peers. This conservative experimental migration never
invents history or resets the ratchet. GC/1 archive decoding and v19 exports remain
compatible; relabeling either an old or new archive is not a migration.

## Evidence and remaining adoption

The protocol tests exercise authenticated hybrid first moves, a missing counter
under a full reverse-ordered window across DH/PQ rotations, exact repair after
restart, simultaneous saturation in both directions, class reservations, lost and
reordered receipts, every-byte receipt tampering, private-state corruption,
stale/cross-session transactions, application expiry and skipped-key aging.

Node integration tests exercise durable inbox acceptance, restart after lost
setup credit, exact duplicate handling, failed receive persistence, strict archive
selection, archive tampering, simultaneous initiation, shared retention admission,
failed-write accounting rollback, budget pressure during restore/materialization,
and lost logical ACK repair after restart. Recovery tests cover consumed inbox
entries, conflicting re-encryption, ambiguous/simultaneous setup, initial packet
loss, expired setup across restart, uncertain saves, bounded receipt admission,
old archive barriers, deadline/clock behavior and generation exhaustion. These use real protocol
cryptography and the node's transaction paths; they do not qualify a deployed
carrier or production performance.

The TLS integration fixture sends eight 11 KiB durable application bodies,
waits for application acknowledgment, restarts the receiver from archive v21,
checks the retained inbox IDs, and resumes bidirectional delivery using the
sender's old contact card. It also delivers volatile events in both directions,
including after restart, while checking that they never enter the durable inbox.
The fixture uses the existing relay carrier and
compressed local cadence; it is not a GC/2 carrier or performance qualification.

Real-crypto volatile tests cover live exact repair, selective credit after
restart, missing-counter recovery, failed receive/send writes, archive relabeling,
and duplicate suppression across restart and re-encryption. The checkpoint at
`target/gc2-volatile-validation-20260918/` retains source manifests and Linux/
Windows GNU test evidence; this is not native MSVC release qualification.

Complete control deferral and class/profile propagation remain required.
The full natural-cell routing path, SDK/GChat selection, real-network goodput and
packet-observation privacy gates remain separate integration/qualification work.
