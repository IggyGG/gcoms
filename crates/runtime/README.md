# GComs runtime

Protocol runtime, encrypted GCPRT1 profiles, provisioned network enrollment,
connectivity recovery and naming maintenance. Extracted from GChat so protocol
ownership no longer depends on a chat application.

Applications should normally use the `gcoms` facade. The explicit `ProfileStorage`
adapter preserves existing encrypted combined stores during migration. Its `save`
method must commit atomically before returning. Profile writer locks and worker
shutdown remain the runtime's responsibility.
