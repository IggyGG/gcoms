# Current-protocol network bootstrap

HTTP provisioning and relay-control versions are different namespaces:

| HTTP request/response | Contents | Relay control request |
| --- | --- | --- |
| `supported_versions: [1]`, response `version: 1` | Legacy private queue card | `provision_client_relay` |
| `supported_versions: [2]`, response `version: 2` | Legacy GCRB1 introductions | `routing_bootstrap`, legacy/default version |
| `supported_versions: [3]`, response `version: 3, routing_protocol: "gc2"` | Native GCRB2 introductions | `routing_bootstrap, version: 2` |

A GC/2 client requests **only [3]**. It rejects legacy envelopes, ambiguous extra
fields, another protocol marker, noncanonical base64url, GCRB1 bytes, invalid or
overlapping authorities, expired introductions and nonpublic relay addresses.
It does not convert old authorities or retry using an earlier protocol.

The catalog/provider requires its `experimental-gc2` feature to offer envelope
v3. A provider built without it continues to support earlier clients, but cannot
satisfy a current-only request. A provider with this feature can serve all three
explicit versions; a request supporting several receives the newest supported
version. This does not change the client's selected runtime protocol.

## Authentication and retained state

`NetworkClient::fetch_gc2_routing` keeps the existing signed-default verification,
monotonic network state, invitation validation and grant authorization. Only
providers authorized by the independently verified installed trust document
receive the grant. HTTPS certificate/hostname verification and the no-redirect
policy remain enabled. Provider failover shares the caller's total deadline and
reuses the same request ID without changing protocol.

The catalog authenticates before replay lookup and before/after control work.
Replays are separated by grant, HTTP version and request ID. Current introductions
come through authenticated relay control; the catalog never substitutes a queue
card or a legacy bundle. Current replay entries expire at the earlier of the
normal replay TTL and the shortest introduction lifetime, so a cached response
cannot extend relay authority through a rollover.

`NodeHandle::uses_gc2_routing` reports the selected scheduler, independent of
whether it is currently ready. `gc2_routing_bootstrap` reads only its retained
current-protocol directory; `has_routing_bootstrap` checks the selected protocol
instead of mistaking an empty legacy directory for a disconnected GC/2 client.
A retained introduction can need credential renewal; these accessors do not
assert routing readiness. The typed `install_gc2_routing_bootstrap` API keeps
the existing persistence, address and authority validation.

GChat's `gc2-carrier` build propagates the network-client feature. Both the
installed signed-network path and explicit trusted HTTPS provider path select
the typed current request/import from the actual node scheduler. Retained
routing gets a bounded first opportunity to reconnect. A missing invitation
still prevents fresh installed-network provisioning. Failed recovery preserves
the user's identity and archive.

## Validation and rollout boundary

The network-client TLS fixtures cover signed-default/grant handling, provider
failover, retained invitations, TLS rejection and current-only negotiation.
Provider fixtures cover current control selection, legacy refusal, grant-scoped
replay/revocation and authority-expiry replay refusal. These fixtures use local
servers; test introductions are never dialed on the public network.

GChat also has a production-profile fresh/reopen/recovery journey. Run its
compiled all-feature `gchat_core` test binary with
`scripts/test-bootstrap-namespace.py --binary <path> --output <new evidence dir>`.
The harness creates a disconnected network namespace containing only loopback
and four fixture addresses. The Rust application runs as the invoking user,
uses normal GC/2 scheduling and authenticated TLS with an explicit fixture CA,
and cannot reach the fleet. This checks the actual production constructor,
typed import, both subscription classes, encrypted directory reopening, retained
identity and recovery after downgrade refusal. Ordinary tests leave this
namespace-specific case ignored; a normal suite pass alone does not cover it.

This is source-level bootstrap qualification. It does not establish that the
operated HTTPS providers have been upgraded, that a packaged installer can
onboard against them, or that client-observer privacy thresholds pass. Deployment,
installed-artifact acceptance and privacy capture remain separate gates. No
provider/relay upgrade or test campaign is implied by this change.
