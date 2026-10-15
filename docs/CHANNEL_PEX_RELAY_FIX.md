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

## Simultaneous route replacement

When two members lose their queues together, each can announce its replacement
to healthy peers while its direct announcement to the other member still targets
an obsolete queue. Healthy peers now retain and gossip the **original authenticated
MLS self-directory ciphertext**, using the same bounded cache, forwarding queue
and two-response PEX path as other eligible channel messages. This supplements
the existing durable direct announcement to every current member; it does not
replace that journal with probabilistic forwarding.

The receive must first pass the existing MLS sender/current-roster/pseudonym
checks, commit the directory and receive ratchet, and still equal the installed
route. Only a sender's own directory is eligible; owner-for-another-member batches,
rejected/obsolete routes and failed checkpoints are not forwarded. Every downstream
receiver verifies that same original MLS message. PEX route descriptors alone
cannot install authority, and forwarding cannot acknowledge an application message.
The transient cache is not a new persisted directory or a global rendezvous system.

The causal three-member test loses both mutual queue addresses, delivers both
announcements to a healthy bridge, and exercises actual pairwise-authenticated PEX.
It preserves pending message IDs/ciphertexts and requires each original recipient's
authenticated ACK. Original229 native delivery failed710/720 after restart; the
repaired source still requires the complete64-client/1800-second qualification.
