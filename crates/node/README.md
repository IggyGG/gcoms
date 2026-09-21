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
