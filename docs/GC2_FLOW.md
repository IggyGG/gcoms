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

The caller must authenticate the explicit GC/2 handshake, including the session
tag, record the first move, and bind sealed-state context to that tag and peer.
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
one MiB per maximally occupied peer, not a node-wide memory bound. Runtime adoption
must account retained ciphertext alongside queued/in-flight copies and preserve
room for repair/control dispatch. Incoming flow state retains hashes and receipt
secrets, not application plaintext or incoming ciphertext. Outgoing volatile
traffic needs a separate persistence policy before this path can carry it.

## Evidence and remaining adoption

The protocol tests exercise authenticated hybrid first moves, a missing counter
under a full reverse-ordered window across DH/PQ rotations, exact repair after
restart, simultaneous saturation in both directions, class reservations, lost and
reordered receipts, every-byte receipt tampering, private-state corruption,
stale/cross-session transactions, application expiry and skipped-key aging.

Node-wide resource accounting, archive integration, authenticated GC/2 handshake
selection, logical ACK deferral and explicit new-session recovery still need
runtime integration. Higher-level application delivery, real-network goodput
and the packet-observation privacy gate remain separate qualification work.
