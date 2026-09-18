# GComs developer-preview protocol profile

This document describes the implemented **GC/1** profile imported for GComs 0.1.0.
It is a versioned implementation profile, not a claim of complete independent
interoperability or cryptographic standardization. Where a subformat is not expanded
below, its cited codec and fixtures define the preview implementation. Completing
language-independent descriptions of every subformat remains release follow-up.

## Version and compatibility

The protocol nibble is `1`. Public crate/product renaming does not rename on-wire
magic, media types, signature domains, service IDs, IPC enum tags or archive magic.
Unsupported versions and malformed framing fail closed. There is **no implemented
HELLO-based protocol/cipher negotiation**: cell type `Hello` is reserved by the
codec, while peers use the fixed supported profile. Local SDK Hello/Welcome is a
separate IPC handshake and must not be confused with network negotiation.

| Layer | Current version / boundary |
| --- | --- |
| Cell framing | GC/1, version nibble 1 |
| SDK local IPC | Version 16, length-delimited postcard frames, 16 MiB ceiling |
| Typed RPC | JSON wire version 1, instance/service/method binding |
| GChat API | Version 2, defined in GChat's contract crate |
| Application message body | 12 KiB before application-specific framing |
| GChat input | 12,000 UTF-8 bytes |

## Cells

A cell is a fixed bucket-sized byte array. Multi-byte fields are big endian.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | Version in high nibble; type in low nibble |
| 1 | 1 | Flags (`0x01` continuation, `0x02` final fragment) |
| 2 | 2 | Round counter |
| 4 | 2 | Payload length |
| 6 | Declared length | Payload |
| Remaining | Variable | Zero padding |

Types are `0` cover, `1` HELLO (reserved runtime role), `2` message,
`3` alias control, `4` presence, `5` legacy peer exchange, `6` relay subscription,
`7` relay push, `8` forward and `9` acknowledgement. Other type nibbles are rejected.
The low-level decoder retains flag bits; dispatchers apply their own message rules.

Codec buckets are 256, 1,024, 4,096 and 16,384 bytes. Network encoding folds the
three smaller buckets into 4,096 bytes. A decoder rejects other sizes, unsupported
versions/types, a declared length exceeding the bucket, and nonzero padding.
A single message limit is 15 KiB; send APIs reserve 3 KiB for current encapsulation.
Fragmentation has independent count, per-message and total-memory bounds in
`crates/core/src/fragment.rs`; control/MLS messages can use bounded fragmentation.
Application input is not enlarged by that control-message path.

The raw positive/negative fixture set is in `crates/conformance/vectors/cells.json`.
Both the Rust test and independent Python decoder consume it. Existing cryptographic
pins in that directory remain regression evidence, not a complete interop suite.

## Encryption and groups

Identity and direct-session implementations are in `crates/crypto`. Identities use
ML-DSA-65; introductions and session key establishment bind signed key material.
The direct-session implementation includes hybrid key establishment and ratchet
state with bounded skipped-key retention. Contact and direct-record codecs are in
`crates/protocol`. Do not substitute an algorithm or accept a key based only on an
unauthenticated display name.

Group messaging uses the MLS implementation in `crates/mls`, including the draft
post-quantum suite profile `0x004F`. Group authentication remains classical Ed25519.
The preview must not be described as standardized, universally post-quantum MLS.
Owner/delegated administration, signed member identities, epoch changes and durable
state transitions are enforced by the channel/runtime layers.

Channel peer exchange uses the existing authenticated channel-direct MSG envelope
with plaintext disposition **4**. Disposition **3** remains volatile file-piece
application traffic. PEX is bounded to 1–8 descriptors and 0–16 have IDs. The first
descriptor must match the authenticated sender's current directory route; PEX
cannot create new route authority. It uses pairwise keys without advancing the
shared MLS ratchet. Raw outer PEX is ignored and relay deposit remains MSG-only.
Pull replies contain at most two retained ciphertexts on the next channel tick.
PEX creates no chat event, text ACK or durable archive mutation. Older receivers
ignore the new disposition. See [the framing repair](docs/CHANNEL_PEX_RELAY_FIX.md).

## Transport, routing and delivery

`crates/transport` implements the authenticated TLS transport and cell framing;
`routing` implements relay introductions and circuits. Production and disposable
fixture profiles are explicit configuration choices. A loopback address does not
implicitly select a fixture or authorize a weaker production policy.

Relay receipts, local archive acceptance and remote application completion are
different events. An application must report the event it actually knows. A network
ACK is not a successful business operation. Presence is opt-in and is not proof of
human attention or an online guarantee.

Traffic padding, scheduling and cover have implementation tests and measurements.
They are **not qualified anonymity or traffic-analysis guarantees**. Simulation
results are models; private deployment measurements do not qualify this release.

## Discovery and host integration

A GComs host supplies an `InstalledNetwork` trust document. Signed defaults are
verified against installed roots, freshness and retained sequence. Invitations
cannot choose arbitrary trusted destinations. GChat ships its own application
network defaults and requires an invitation for operated-network access.

Generic component routing, capability checks and sealed ownership remain public.
`ComponentAuthority` is a trusted local host integration point. Reserved Ghost
bootstrap operations are denied in this distribution; managed installers and
certificate verification are private host implementations. They do not become
available merely because the SDK retains their wire tags for compatibility.

## Persistence and RPC

Client persistence is opt-in at the GComs layer. GChat uses encrypted profiles and
archives. Readable legacy formats remain supported only where explicit decoders and
migration tests exist. Do not edit sealed ownership or import a managed profile as
an ordinary chat identity. Renaming a crate does not justify creating a new identity.

RPC validation, authorization, replay/conflict handling and durable status are in
`rpc-contract` and `rpc`. See [typed services](docs/TYPED_SERVICES.md). Browser
transport security depends on the application's authenticated, destination-bound
same-origin gateway. There is no universal public RPC endpoint in this protocol.
