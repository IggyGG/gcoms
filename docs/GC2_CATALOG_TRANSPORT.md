# GC/2 catalog transport

The catalog path now follows the node's selected scheduler. A GC/2 node calls
`catalog::request_gc2` with its current `ReadyConnector`; an explicitly legacy
node retains `catalog::request` with its legacy connector. A current node with
no initialized routing runtime or no ready independent entry fails closed.
Retained legacy directory contents cannot select a different transport.

`ReadyConnector::connect_https` selects an existing fresh entry and an
independent current middle, using the same guard, own-address and persistence
checks as relay-target selection. It opens an Interactive circuit with the
existing `Target::Https` wire operation. It has no physical entry dial handle
and cannot wake the background owner. There is no new relay wire operation,
profile change or request-time legacy/direct fallback.

The middle enforces its configured catalog origin allowlist and address policy,
resolves DNS, and connects to the HTTPS origin. The client independently checks
the origin certificate and hostname with ordinary WebPKI. Both client and
egress relay must allow the origin. The shared HTTP implementation preserves
the operation restrictions, HTTPS port 443, redirect refusal, 128 KiB request
and 4 MiB response limits, and 180-second total deadline (including the
45-second circuit-open bound).

GChat's normal catalog client already calls the SDK backend, which reaches
`NodeHandle::catalog_request`. Its direct HTTP helper is compiled only for
tests; it is not a production recovery path. No GChat runtime edit is needed
for this dispatch correction.

## Validation and remaining qualification

The retained-directory regression restores two fresh legacy relay entries and
runs a current-profile node with no current entries. It requires an immediate
current-route error and verifies that neither legacy listener receives a
connection. The same directory remains usable by an explicitly legacy profile.
Removing the new dispatch reproduced the old connection wait; the correction
passes.

A shared HTTPS scenario runs over both legacy circuits and a real profile-22
GC/2 entry/middle. It verifies remote resolution, rejection of an untrusted
certificate and a trusted wrong-hostname certificate, authenticated success,
client and egress origin refusal before DNS, and circuit cleanup while the
physical entry remains alive. The GC/2 case also verifies
that stopping the owner leaves no fallback. The existing background-retry test
now includes repeated catalog requests before, during and after owner activity,
with no request-triggered dials or retry acceleration.

These are local source and transport checks. They do not establish an operated
catalog deployment, installed-artifact behavior or client-observer privacy.
GChat's test-only direct HTTP catalog fixtures cannot substitute for those
checks. Keep the required all-egress installed-client capture and connection
lifetime analysis, including the accepted upper-95% separability threshold of
0.55. See [capture requirements](GC2_CLIENT_CAPTURE_REVIEW.md) and the
[traffic inventory](GCHAT_TRAFFIC_PATHS.md), whose fleet observations remain
bound to the earlier runtime.

