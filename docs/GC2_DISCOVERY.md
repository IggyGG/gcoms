# Experimental GC/2 discovery and entry ownership

Private GC/2 renewal and a background entry owner are available behind
`gcoms-routing/experimental-gc2`. Production Node and GChat still use GC/1.
The new APIs do not migrate invites, archives or settings and do not qualify
any candidate privacy profile.

## Versioned private introductions

A canonical introduction is 155 bytes: numeric address (19), independent service
pin (32), stable re-entry capability (32), entry capability (32), middle transit
capability (32), and unsigned big-endian expiry (8). Pins, capabilities and
expiry must be nonzero; the three roles must have distinct capabilities. Debug
output omits capabilities, and their owning values clear them on drop.

A bundle begins with five bytes `GCRB` + version 2, followed by a count byte and
exactly that many introductions. It contains 1–8 distinct pins and at most
1,246 bytes. GC/1 bundles, truncation, trailing bytes and noncanonical numeric
addresses fail. No GC/1-to-GC/2 conversion or discovery fallback exists.

The private directory retains at most 64 introductions and three independent
guards. It validates an entire incoming bundle before changing state. Production
address policy rejects special/private networks; a separate loopback fixture
constructor deliberately permits local tests. Descriptors more than 24 hours in
the future are rejected. Expired records retain only re-entry authority; they
cannot open entry or middle circuits. An older expiry cannot replace a newer
record. A referral cannot replace the stable re-entry authority of a known pin;
such a change requires explicit bootstrap migration. At capacity, the oldest
non-guard record is evicted. Own services and
every supplied terminal exclusion remove matching IPs or pins from selection.
Address updates prune guards that now overlap one another or an own service.

The private directory snapshot uses a separate `GCDR` + version 2 format. It
retains every introduction, guard order, and up to eight own-service exclusions,
at most 10,432 bytes. Strict restoration rejects duplicate pins, overlapping or
unknown guards, invalid authorities, oversized counts, truncation and trailing
bytes. Restoration keeps expired seeds and their original expiry; a backward
clock jump that puts an expiry more than 24 hours ahead fails closed. The raw
snapshot contains capabilities and must be authenticated and encrypted.

`Directory::with_checkpoint` saves the initial view before returning the
directory. Later mutations stage a candidate under the directory write lock,
save it, then publish it to routing. Failed writes leave the live view unchanged;
unchanged state needs no write. The callback must not reenter the directory.
The background owner distinguishes an unsuitable guard from a failed checkpoint:
the latter ends the owner before either entry acquisition or private renewal
can dial that unsaved guard.

`gcoms-node::routing_cache::Cache::open_gc2(...).gc2_directory(now)` supplies
the encrypted file implementation and retains the exclusive writer lock for the
directory's lifetime. It uses a distinct HKDF domain, authenticated `GCRN` version
2 header and `routing-gc2.cache` filename. AES-256-GCM with a fresh random nonce
adds 35 bytes. Private permissions, bounded reads, atomic replacement and synced
writes use the existing platform storage code. The same writer lock excludes
concurrent GC/1 or GC/2 cache owners. The original `routing.cache` is preserved;
there is no implicit conversion of GC/1 authorities or profiles.

The relay derives stable re-entry authority using HMAC-SHA256 under its retained
relay secret with domain `ghost.gct2.reentry.v2\0` and its service pin. Entry and
middle authorities retain their separate hourly domains. The client authenticates
the relay's TLS pin, sends a natural GC/2 PEX containing exactly `GCD2`, and accepts
only a natural PEX containing a canonical bundle. A reply must include the pinned
relay, fresh circuit authority and the same stable re-entry capability. Renewal
does not silently rotate the bootstrap secret.

The listener fixes each GC/2 connection to entry, middle transit or control.
Entry opens its two class channels, middle extends one target, and control can
serve repeated finite renewals through its pooled connection. Possession of
other valid capabilities does not permit switching roles. Private renewal has
four active slots and shares the existing 64/minute operation budget with private
provisioning and advertisement. It does not reserve a data-circuit slot. Bodies
have a 10-byte bound and the transport's body-read deadline. Authenticated overload
uses the existing eight-byte natural hop status; invalid bodies fail closed.

Install `gc2_handler_factory` through `Tp1Server::with_dispatch_factory`, which
runs before registered endpoints and legacy duplex handlers. Its typed rejection
is final and does not promote an unauthenticated source. Known registered paths
select a terminal role; unknown paths cannot commit a role. To cohost natural
queues, pass their handler to `gc2_handler_factory_with_terminal`. Terminal
requests still authenticate their complete envelopes, and neither terminal nor
entry/transit/control connections may switch to the other role. Simple duplex
fallback composition does not provide this enforcement.

## Background connected periods

`EntryOwner::new` returns an owned background future and a `ReadyConnector`.
The caller starts the future for an explicitly chosen connected period. It
retains up to three guards and attempts the configured one to three entries
without receiving application events. Entry retries have a 30-second background
interval; successful private renewal recurs after five minutes plus 0–10% random
jitter, serially across retained guards, with a 20-second deadline per attempt.
Failures retry after 60, 120, 240 and then at most 300 seconds plus the same
jitter, independently for each guard. This avoids waiting a full refresh period
on first failure and spreads synchronized fleet retries without using chat as
an input. Successful renewal also schedules a refresh at credential expiry plus
0–1 second of independent jitter if that comes sooner; an hourly epoch change
cannot sleep through the usual five-minute interval. Rejected renewal retains
its bounded failure backoff. Successful background renewal
can immediately wake entry selection, avoiding an extra retry interval for a
previously expired bootstrap. Requests cannot signal that wakeup. Missed timer
ticks use delay behavior rather than catch-up bursts.

Discovery uses explicit direct connections only to retained guards, separately
from protected entry connections. Both reveal connected periods. Discovery
timing, guard selection and entry count do not depend on queued messages. A
failed connection does not rotate the retained guard set. Failed entries try
another retained guard at a later maintenance opportunity. The owner never
copies a fresh expiry onto stale credentials.

`ReadyConnector` carries no dialer or maintenance notification handle. If no
fresh, independent path exists through a ready entry, it returns an error. It
does not establish another entry or fall back to GC/1/direct delivery. Middle
and terminal circuits open through existing entries, with class-separated TP1
pooling. The relay still validates capacity, target policy and each independent
TLS pin. Application traffic cannot increase the entry count or change profile.

The owner contains all entry futures, including connecting sockets, both class
channels and nested circuit drivers. Cancellation removes published readiness
and drops the driver tree and its private TP1 pool. Credential lifetimes retain
subsecond precision when converted to monotonic deadlines. Expired or invalid
timestamps cannot start a handshake. Canceled entries continue to
count against the configured bound until their futures have completed. Directory
updates cannot transiently double the physical entry set.

## Explicit costs and pending integration

Record cost multiplies by the configured entry count. For 30 continuous days,
before TLS/TCP overhead, retransmissions, control connections and bulk:

| Candidate | One entry | Three entries |
| --- | ---: | ---: |
| 4 KiB every second, both directions | 21.23 GB | 63.70 GB |
| 4 KiB every 1.5 seconds, both directions | 14.16 GB | 42.47 GB |

These candidates exceed the accepted advisory desktop/mobile targets. No lower
cost profile is qualified here. Direct private control visits up to three retained
guards. Requests can reuse a live pooled connection, but the normal five-minute
refresh interval exceeds the server's two-minute idle timeout, so regular rounds
generally require another handshake. These handshakes, requests and replies are
extra costs. The existing bounded TP1 pool still applies if guard addresses change. Natural
control responses contain at most 1,252 cell bytes, but that is not total measured
interface usage. The directory's raw introduction payload is at most 9,920 bytes,
excluding vector storage, locks and allocator overhead. Entry buffer bounds remain
documented in [the carrier contract](GCT2_CARRIER.md).

Tests cover expired-seed renewal, bounded referrals, malformed requests/replies,
role isolation, request limits, wrong TLS pins, rejected authority replacement,
fixed retry behavior, pending-dial cancellation, bounded entry attempts and real
TLS entry/middle/terminal reuse. These are component tests, including a fixture
with legacy cells inside an explicit GC/2 circuit. They are not application
goodput, packet-classifier, mobile-power or operated-network qualification.

The combined-listener gate is now installed for an explicit fixture profile
(`NodeProfile::gc2_gate_fixture`): the listener attaches a late-bound dispatch
factory that passes every path through until this node provisions a relay
service, then fixes entry/transit/control roles and rejects unknown paths
without any GC/1 fallback within the connection. The owned terminal queue
service is composed under the same gate; its handler accepts only authenticated
queue tokens that resolve to a current lease in this node's store.
`NodeProfile::gc2_carrier_fixture` additionally opens the encrypted GC/2
directory (or an in-memory one), starts a one-to-three-entry background owner
whose future is owned by the node task set, and retains the ready connector on
the node state. Restoring a directory with a different identity fails closed. Retained GC/1
re-entry authorities are migrated explicitly through the authenticated private
PEX exchange (`refresh_reentry`): the reply must present the same stable
authority and a valid GC/2 entry, retries are background-paced at a bounded
count, and a failure never falls back to GC/1. The explicit carrier profile
delivers session frames as authenticated natural terminal deposits and drains
its own class queues through natural subscriptions. Delivery and subscriptions
prefer the protected client over the ready connector whenever the directory has
live entries; the direct client only serves bootstrap migration and fixtures
without a route. Runtime adoption still needs private
provisioning/advertisement integration, production profile selection,
Node/SDK/GChat class and profile propagation, and the application/privacy/device
gates in [the implementation ledger](GC2_IMPLEMENTATION.md).
