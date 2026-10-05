# gcoms-transport

Part of **GComs**, a developer-preview encrypted communication platform.
This crate is licensed under MIT OR Apache-2.0. GC/1 wire identifiers retain their
historical names. See the repository README, SPEC.md and SECURITY.md for the
supported profile, integration guides and limitations.

The crate documentation is generated from this package's source. Applications
normally begin with `gcoms-rpc` for typed services or `gcoms-sdk` for messaging.
Lower layers are implementation components and have no independent stability
promise during the developer preview.

Set `GCOMS_TRANSPORT_DIAGNOSTICS=1` for local timeout attribution: connection,
request admission, HTTP/2 credit, or reply headers/body. These records contain no
addresses, capabilities or payloads. Request deadlines and public errors remain
unchanged.
