# GComs runtime

Protocol runtime, encrypted GCPRT1 profiles, provisioned network enrollment,
connectivity recovery and naming maintenance. Extracted from GChat so protocol
ownership no longer depends on a chat application.

Applications should normally use the `gcoms` facade. The explicit `ProfileStorage`
adapter preserves existing encrypted combined stores during migration. Its `save`
method must commit atomically before returning. Profile writer locks and worker
shutdown remain the runtime's responsibility.

Authenticated piece-protocol records use independent nonces and the file cache's
verified piece journal. Sending or publishing these records does not rewrite the
encrypted protocol profile. File completion still requires the file protocol's
verification and durable cache; a transport receipt is not completion. Ordinary
private text and stateful events retain their profile-save barriers and errors,
as do explicit save and shutdown.

Hosted requests authorize only providers from the current verified signed network
defaults, merged with the host's explicit catalog allowlist. Configuring ordinary
catalogs does not drop hosted origins. Unsigned invitation destinations remain
refused; local history and durable queue admission do not refresh network trust.
The origin regression uses the existing workspace network crate as a test dependency.

Admission snapshot reads tolerate transient protected-circuit disconnects with
at most four attempts and a 30-second deadline per page. The same prepared
identity and pinned transcript remain authoritative. Service policy refusals
are final; this read retry does not repeat membership mutations.

Services advertising `covered-poll-v1` combine message polling with bounded
covered acknowledgment publication/recovery. Consumer archival still precedes
ACK publication; each signature is verified. Older services retain the separate
requests. Capability negotiation is transient and does not alter archive format.
