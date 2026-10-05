# Relay contribution

Embedded desktop hosts may opt into `RelaySharingConfig` through the application
builder. Existing constructors remain unchanged. Mobile NetworkClient hosts
remain outbound-only. Defaults are 32 circuits, 64 accepted connections and
512 KiB/s aggregate contribution bandwidth. The host retains its listener port,
requests an optional router mapping, and keeps personal messaging separate from
the service TLS principal.

Sharing pauses on battery, metered or unknown connectivity, excessive system
load or memory pressure. A failed public reachability check keeps the listener
unpublished. Signed provider registration binds the independently verified
listener introduction to the network, current membership grant and a fresh
service-key possession proof. Registration does not require a DNS label.
Provider leases last at most 300 seconds; hosts renew every 60 seconds, withdraw
on shutdown or network change, and retry with jittered exponential backoff.
Unavailable publication never enables forwarding. Saved opt-out settings are
authenticated, encrypted and owner-private.

Channel invitations embed only fresh signed-network founder introductions, even when the local directory also contains contributions. Recipients discover contributions through their authenticated provider directory; invitation bearers cannot add untrusted network relays.

Provider state is bounded to 1024 services, 64 per grant and 16 per public
IPv4 /24 or IPv6 /48. Bootstrap bundles keep up to five operator seeds and add
contributions up to the existing eight-introduction limit. Service pins and
addresses are deduplicated. These prefix bounds are not an ASN lookup.

## Qualification

Build exact paired sources once with `scripts/build-fleet-files.py --gchat PATH
--output PATH --target-dir PATH`. Run the retained source-bound artifacts with
`scripts/gchat-turnover.py --build PATH --out PATH --mode relay-load
--fixture-host PATH/bin/turnover_daemon`. The blocking campaign uses 64 actual
GChat application clients, six operator services, 32 contribution services,
five-hop protected routes, a 5,235,248-byte file, authenticated channel delivery
and a relay restart over 30 minutes. It measures recipient p95 under five
seconds, refusal errors below one percent, exact file hashes and process health.
Shorter `--load-seconds` runs are diagnostic and cannot qualify the release.
Channel setup retains the original serial admissions. Recipient latency is
measured at the first
successful history observation in its own worker, without waiting for unrelated
submission RPCs. Commands still require exact identity, authorship, every
recipient and the sender’s authenticated delivery state.

Contribution services in that disconnected fixture exercise the public relay
core and bandwidth policy. Installed desktop device guards and production
provider registration require separate native/live evidence. The harness records
these limits explicitly and does not turn a local pass into fleet qualification.
Roll out through the existing release coordinator, retaining rollback artifacts
and requiring authenticated delivery per host. A healthy process or matching
binary hash alone is insufficient.
