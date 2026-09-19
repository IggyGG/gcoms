# Channel peer-exchange framing repair

Fleet diagnostics exposed `RELAY_PUSH does not contain exactly one MSG`. The
channel tick was submitting raw PEX cells to the strict MSG-only deposit codec;
that is a local encoding refusal, before HTTP, rather than remote TLS rejection.

This adapts the existing coms pairwise PEX correction (`a7cca19`) to GComs. Here
plaintext disposition **3** already carries volatile file-piece application
traffic, so PEX uses **4**. The sender encrypts bounded peer exchange with retained
channel-direct keys and emits a normal MSG. The receiver verifies the current MLS
roster, authenticated directory and AEAD binding before processing it. The first
peer reference must equal the sender's current route; other references cannot
introduce unauthenticated routes. Legacy raw PEX is ignored.

Peer exchange does not advance the shared MLS ratchet, modify archives, emit chat
messages or generate text ACKs. A separate 1,024-entry RAM replay cache leaves the
user-message cache intact. At most eight references and sixteen have IDs are
accepted, with at most two original cached ciphertexts queued for the next normal
channel tick. Existing encrypted-envelope limits and relay authentication remain
unchanged. Older GComs receivers ignore the new disposition. This does not claim
wire compatibility with the unpublished coms experiment using disposition 3.

The imported three-node regression reproduced the original framing refusal after
verifying ordinary channel plaintext and the owner's all-member delivery ACK.
`target/pex-relay-red.log` retains that failure. The correction passes that same
regression in 2.68 seconds; nine PEX unit tests pass in
`target/pex-relay-green-02.log`. They cover tampering, reflection, substituted
routes, scope mismatch, unknown descriptors, replay and lack of chat events.
Preparing 2,001 PEX messages and then decrypting a group message at a member that
saw none verifies that PEX does not consume its shared ratchet window. These
fixtures do not establish fleet-scale performance.
