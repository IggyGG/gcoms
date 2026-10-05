## Established sessions and renewed contacts

Contact announcements replace routes and advertise bundles for new handshakes.
Existing direct sessions retain their negotiated ML-KEM key pairs across renewals
and restart; regular PQ encapsulation and DH ratchet refresh continue. A new
contact bundle cannot replace the key used by already queued session frames.
The IRC file-recovery regression exercises this boundary with forced PQ refresh,
then requires verified resumed content and a recipient completion acknowledgment.

# gcoms-node

Part of **GComs**, a developer-preview encrypted communication platform.
This crate is licensed under MIT OR Apache-2.0. GC/1 wire identifiers retain their
historical names. See the repository README, SPEC.md and SECURITY.md for the
supported profile, integration guides and limitations.

The crate documentation is generated from this package's source. Applications
normally begin with `gcoms-rpc` for typed services or `gcoms-sdk` for messaging.
Lower layers are implementation components and have no independent stability
promise during the developer preview.

The `experimental-gc2` feature provides an explicit local peer-session fixture.
It shares retained direct-message and retry admission with the endpoint/transit
scheduler, including restart and persistence-failure handling. It remains
experimental; see [the integration ledger](../../docs/GC2_IMPLEMENTATION.md) and
[flow-control contract](../../docs/GC2_FLOW.md) before selecting it.

Optional `push-notifications` adds owner-authenticated inbox bindings.
`push-gateway` additionally enables relay hosting and reqwest's rustls HTTPS
transport to one operator-configured endpoint. Neither is enabled by default.
Client push bindings do not pull in the relay HTTP gateway. See the
[app-operated push contract](../../mobile/push/README.md).


Trusted GC/2 bootstrap bytes can be installed asynchronously with
`NodeHandle::install_gc2_bootstrap`. The caller must obtain them through its
already authenticated bootstrap channel. This method validates the complete
fresh bundle and seeds only the client carrier directory; it does not fetch a
provider, publish the seeds through the relay service or select a different
protocol. Non-GC/2 nodes refuse it. The deployed-relay diagnostic is an explicitly
ignored live provisioning test and requires separate authorization to run.


### Stale peer inbox descriptors

A locally originated send to an expired cached descriptor first sends an authenticated cover probe through the configured connector. The current relay implementation accepts the probe only for the existing queue, epoch and push capability, and only when the requested short expiry fits its live lease. The client uses that pinned acknowledgement for the same destination until the accepted expiry. GC/2 uses natural cover cells and never falls back to legacy framing. One memo per bounded scheduler lane coalesces probes and backs off failed attempts. The probe consumes one short-lived replay entry but no queued message or file storage; it cannot renew or resurrect an inbox. Already authenticated forwarded envelopes and application command deadlines are unchanged. No dependencies were added.

## Operator relay capacity

`gcnode serve --relay-circuits 2048 --relay-connections 4096` explicitly budgets
a larger production relay. Defaults remain 128 forwarding circuits and 1024
accepted connections. The maximum is 4096 circuits and 8192 connections; the
connection budget must be at least twice the circuit budget. Invalid values fail
before listener startup. Embedders use `RoutingConfig::relay_capacity` with
`RelayCapacity::new`. Ordinary application traffic profiles do not select these
operator settings. Size the service's memory, descriptor and process limits
and qualify the intended workload before enabling a larger budget.

Unauthenticated source admission stays at eight connections per IP. The entry's
16-circuit/15-bulk bounds, class separation, covered schedule, authenticated path
selection and service expiry remain enforced. Bulk cannot consume the relay's
last circuit. Failed connections and dropped streams return their slots.

GC/2 forwarding and transit scheduling use this same circuit budget. Control
and reachability probes use at most 64 slots. Admission has a one-second bound
and a bounded waiter pool. Endpoint schedulers allow 512 GC/2 destination/class
lanes; legacy endpoints retain 64. Aggregate queued work remains 4096 jobs /
8 MiB, and each durable relay queue retains 256 cells / 4 MiB. Files stream in
blocks instead of requiring an entire release to fit a queue.

Authenticated control status exposes `relay_diagnostics` with scheduler and
forwarding admission counters. `GC_RELAY_DEBUG=1` enables a default metrics file
beside the keystore unless `--metrics` supplies a path. Metrics rotate at 16 MiB
with three backups; refusal journal entries are rate limited.

A direct outbox attempt that cannot select a ready GC/2 route retries its exact
ciphertext after about five seconds, with jitter. This also covers a ready-set
change arriving before the failed attempt completes. Recipient acknowledgement
waits, uncertain network outcomes, expiry and rekeyed work keep their existing
retry schedule. No retry opens an entry or uses a direct fallback.
