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
