# gcoms-protocol

Part of **GComs**, a developer-preview encrypted communication platform.
This crate is licensed under MIT OR Apache-2.0. GC/1 wire identifiers retain their
historical names. See the repository README, SPEC.md and SECURITY.md for the
supported profile, integration guides and limitations.

The crate documentation is generated from this package's source. Applications
normally begin with `gcoms-rpc` for typed services or `gcoms-sdk` for messaging.
Lower layers are implementation components and have no independent stability
promise during the developer preview.

GC/2 cumulative receive credit validates the exact incoming packet and uses the
highest authenticated received counter’s receipt authority. Delayed duplicates
preserve usable coverage and replay cached bytes without consuming another
ratchet counter. See [the credit contract](../../docs/GC2_FLOW.md).
