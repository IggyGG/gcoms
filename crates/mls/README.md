# gcoms-mls

Part of **GComs**, a developer-preview encrypted communication platform.
This crate is licensed under MIT OR Apache-2.0. GC/1 wire identifiers retain their
historical names. See the repository README, SPEC.md and SECURITY.md for the
supported profile, integration guides and limitations.

The crate documentation is generated from this package's source. Applications
normally begin with `gcoms-rpc` for typed services or `gcoms-sdk` for messaging.
Lower layers are implementation components and have no independent stability
promise during the developer preview.

The opt-in `hosted-channels` feature supplies experimental native hosted-channel
admission primitives with the same PQ-hybrid MLS suite. `HostedObserver` tracks
only public membership state. Owner-signed genesis policy, epoch-bound private
permits, public admission, capacity/name checks and member-side verification
prevent a delivery service from granting itself private membership. Public
handshakes do not make application messages public. `stage_join` validates the
commit and next GroupInfo together without changing the current observer; a
caller must durably store them before installing the new state and acknowledging
acceptance. Acceptance is not recipient delivery.

With `client-persist`, hosted clients seal their membership state and pending
acceptance together using a distinct archive kind. Legacy groups explicitly
reject external commits and cannot be silently converted to this profile.

This feature is not wired into GChat or a deployed hosted service yet. It does
not yet implement policy revisions, moderation, durable service sequencing or
network negotiation. The 500-member bound is not a capacity qualification.
See the [implementation ledger](../../docs/IRC_PARITY.md). No new third-party
dependency is introduced.
