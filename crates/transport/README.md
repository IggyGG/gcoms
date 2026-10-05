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

If a submitted request reaches that deadline without receiving reply headers,
the client retires its exact cached connection so later work can reconnect.
The timed-out request is not replayed, and its outcome remains uncertain.
Existing subscribers keep their connection driver. Waiting for admission or a
partially received response body does not evict an otherwise healthy connection.

An unknown-path HTTP 404 also retires only its exact cached connection, allowing
later queue recovery to reconnect. It returns the original refusal without
replaying the request or stopping existing subscribers. On the server, a
connection that has not authenticated a private path expires 120 seconds after
its handshake, even if repeated decoy requests keep it active. Authenticated
connections retain their ordinary idle/request limits and global admission slot;
the unauthenticated per-source cap and dispatch authentication checks still apply.
