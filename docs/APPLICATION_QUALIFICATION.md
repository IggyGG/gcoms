# Application runtime qualification — 2026-09-18

This run exercises the GComs application facade and its GChat consumer on the
existing private Windows VM, with separate public-network probes from Linux.
It is development evidence. Public publication and installer acceptance remain
deferred.

The machine-readable [record](../release/application-validation-2026-09-18.json)
binds the results to source and executable hashes, preserves the failed first
attempts, and distinguishes reruns, ignored cases and unexecuted harnesses. Raw
logs, source snapshots and test drivers remain in the ignored
`target/application-qualification-20260918T113411Z` directory.

## Windows execution

The `gcoms-gchat-validation` VM runs Windows 10 x86_64 build 19045 with 12 GiB RAM
and six virtual CPUs. Rust 1.98 GNU test executables were cross-built on Linux,
copied with source fixtures and runtime DLLs, verified by SHA-256 in the guest,
and executed as Windows processes. Harnesses run sequentially with one test
thread and a 15-minute per-harness limit. SSH uses the existing pinned host key.
The VM retains its restricted network configuration.

The latest result for each GComs harness totals **615 passing Windows cases**, with
five existing ignored cases. This combines the full run with the explicitly
recorded reruns of affected harnesses. GChat's complete Windows run passes **121
cases**; its Linux run passes **129 cases**. Both repositories pass strict Clippy
for Linux and the Windows GNU target.

The application tests cover embedded and shared profiles, typed RPC, durable
operations, mixed messages, channel invitations, recovery after profile restart,
capability and credential denial, exclusive inbox leases, and starting and
reattaching to the bundled daemon through Windows named pipes.

The initial run exposed an IPC detach bug: shutting down a named-pipe writer did
not close the retained OS handle. `IpcClient::close` now drops the writer, aborts
and joins its reader, and wakes blocked requests. The lease test keeps its client
alive while requiring the next attachment to acquire the inbox.

Two test portability issues were also corrected. The daemon executable path is
canonicalized in the cross-built test before checking that it is absolute. NAT
fixture cleanup accepts an already-completed socket task as well as cancellation,
while continuing to fail on task panics and retaining all mapping-ownership checks.

The first network-client run hit a DNS update deadline; all 13 cases passed on an
unchanged rerun. The first rebuilt application run passed the corrected lease and
daemon cases but hit deadlines in embedded delivery and shared profile startup,
which had passed in the initial run. The host was heavily loaded and an SSH
connection attempt also timed out. The record retains these timing failures and
the subsequent application rerun separately; test deadlines were not increased.
The final unchanged application rerun passes all five cases. The full node rerun
passes 204 cases with one existing ignored case.

The Linux workspace run stopped when node 22 missed a broadcast in the 24-node
overlay test. The unchanged harness passed in isolation in 224.95 seconds; it had
also passed in Windows. The remaining Linux harnesses were then executed with
their original settings. The record retains this intermittent delivery failure
and the initial workspace command's failed exit status.

Linux totals 627 passing cases across these runs, with five existing ignored
cases. The earlier 87-case IPC-fix regression run also passed its compiler/UI
case. Repeating that compiler/UI harness with the workspace artifacts reached
the 900-second limit while waiting on the workstation build scheduler. That
additional attempt remains incomplete. A standalone proc-macro harness initially
lacked Rust's shared-library search path; the same binary passes with that path
set. Final strict Clippy and workspace documentation tests pass.

Native MSVC builds, Windows compiler UI tests, Windows rustdoc, desktop GUI and
installer/signing acceptance are outside this execution run. Unix-only harnesses
with zero Windows cases contribute no Windows coverage. macOS is unavailable.

## Public-network probes

Both `bootstrap-hel.gchat.boo` and `bootstrap-fsn.gchat.boo` returned HTTP 200 for
HTTPS health, readiness and signed defaults. The downloaded defaults were
byte-identical and each passed the current Rust operator verifier against the
independently installed ML-DSA root, expected network `gchat.boo`, and minimum
sequence 1. Valid-shaped provisioning requests without credentials returned 401
from both providers.

All eight configured founders completed TLS 1.3 handshakes on port 4433. Each
certificate was within its validity period and its SHA-256 SPKI pin matched the
independently authenticated defaults. These pin probes send no application data
or credentials. They establish endpoint reachability and pin consistency, not
successful GC/1 routing or peer messaging.

IPv6 provider names resolve, but this workstation returns `Network is unreachable`
when connecting over IPv6. IPv6 service reachability remains unqualified.

Authenticated onboarding and end-to-end application traffic require a currently
provisioned test invitation. No invitation was available in the permitted source
folders during this run. The requested invitation file path remains the blocker
for live typed RPC, peer messaging, invitation redemption, durable reconnect and
provider failover. The successful local fixtures and public TLS probes do not
substitute for those checks. No production relay, provider or DNS configuration
was changed.
