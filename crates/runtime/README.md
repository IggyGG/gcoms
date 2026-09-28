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
