# gcoms-file-transfer

Part of **GComs**, a developer-preview encrypted communication platform.
This crate is licensed under MIT OR Apache-2.0. GC/1 wire identifiers retain their
historical names. See the repository README, SPEC.md and SECURITY.md for the
supported profile, integration guides and limitations.

The crate documentation is generated from this package's source. Applications
normally begin with `gcoms-rpc` for typed services or `gcoms-sdk` for messaging.
Lower layers are implementation components and have no independent stability
promise during the developer preview.

The additive [private piece exchange](../../docs/PRIVATE_FILES.md) supports
encrypted sparse caches, independent piece verification, restart, and multiple
authorized sources. Its state machine is under `gcoms_file_transfer::swarm`;
the host supplies membership and GComs transport.

For accepted retained downloads, a newly authenticated source among the first four
is queried immediately when the periodic inventory poll is not yet due. Duplicate
offers do not accelerate polling; later sources retain periodic rotation. This does
not accept new offers automatically or resume an explicit pause/cancellation.

Hosts must retain each action's opaque `send_token()` and call `send_finished`
when its actual transport attempt completes or when unsent work is discarded.
This applies to initial discovery as well as piece requests. A wrapper timeout
is not completion. Failed initial discovery retries after the existing 30-second
request bound; successful discovery keeps its normal 60-second cadence. Pending
attempts are not duplicated, and old completions cannot release a newer attempt
or a request created after membership removal and restoration.

Authenticated completion receipts also identify candidate sources after a restart.
For an already accepted download, a newly identified source gets the same bounded
inventory query as an offer. The receipt does not verify local pieces or mark the
download complete; normal inventory, per-piece and final integrity checks remain.

Contact exchange keeps one piece and two block requests in flight, leaving space
in the durable transport's four-ciphertext window for control and receipts. Local
durable acceptance can precede network admission; the smaller window prevents
slow FIFO delivery from amplifying duplicate retries.
cryptographic checks and authenticated file completion remain unchanged.
