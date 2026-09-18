# Experimental GC/2 relay codecs

The `experimental-gc2` feature adds runtime-free codecs in `gcoms-core::gc2` and
`gcoms-protocol::relay::gc2`. It does not select a new node transport or cover
profile. The production runtime still uses GC/1. These codecs are a development
boundary for the shared-carrier work, not a qualified wire release.

A natural cell contains the existing six-byte header followed by exactly its
declared payload. The version nibble is 2. The former round-counter bytes are
reserved and must be zero: GC/2 does not add a scheduling round at each downstream
hop. Only MSG may carry the two existing fragment flags. Unknown types, reserved
bits, padding, truncation and trailing bytes fail closed. MSG payloads remain at
most 15 KiB; every complete natural cell remains at most 16 KiB.

The selected outer carrier must supply the protection that permits removing
inner padding. A natural-cell codec alone supplies neither cover nor anonymity.
No GC/1 decoder is used as a fallback, and relabeling a GC/1 envelope cannot reuse
its authentication tag.

Every relay payload starts with an explicit traffic class: 0 for interactive,
1 for bulk. A subscription names exactly one class. A forwarding envelope must
name the same class as its nested deposit. Experimental
[relay queues and the terminal service](GC2_QUEUES.md) enforce these filters;
production node/profile adoption remains pending.

| Envelope | Fields before the authentication tag |
| --- | --- |
| Deposit | class (1), queue (32), epoch (8), nonce (16), expiry (8), natural MSG length (2), MSG |
| Subscription | class (1), queue (32), epoch (8), expiry (8), nonce (16) |
| Forward | class (1), canonical target (51), expiry (8), nonce (16), natural deposit length (2), deposit |

Integers use network byte order. Empty nested content denotes cover, as in GC/1.
Expiry, destination policy and capability ownership remain enforced separately
from shape validation. An `UnverifiedPush` proves only canonical structure;
the destination must authenticate it with its own push capability.

The tag is HMAC-SHA-256 over the envelope-specific NUL-terminated domain
(`GC2/RELAY-PUSH`, `GC2/RELAY-SUB` or `GC2/FRWD`), version byte, cell-type byte,
pinned recipient service identity, two-byte unsigned payload length and the
complete unsigned payload. Thus class, route, queue, epoch, nonce, expiry, length
and exact encrypted content share the authentication boundary. Verification uses
the MAC implementation's constant-time tag comparison.

The tests cover maximum-message forwarding, exact natural lengths, malformed
headers, class/ciphertext/context tampering, class mismatch, nested expiry,
destination policy and attempted tag reuse across versions. An experimental
[shared entry carrier](GCT2_CARRIER.md) now supplies bounded multiplexing; complete
GC/2 discovery and runtime routing, ratchet flow control, archive migration, SDK/GChat profile
selection and performance/privacy qualification remain separate work in
[the implementation ledger](GC2_IMPLEMENTATION.md).
