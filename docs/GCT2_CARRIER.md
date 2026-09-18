# Experimental GCT2 entry carrier

`gcoms-routing/experimental-gc2` now supplies a working shared entry transport.
One pinned TLS/HTTP2 connection carries two permanent class channels, each with
an inner HTTP2 multiplexor. Both start before readiness is published. Interactive
records occupy fixed opportunities whether or not chat is queued. Bulk records
move when data and transport credit are available, without a round timer or idle
cover. Data never waits for a record to fill.

This is an experimental transport building block, not a node or GChat profile.
GC/1 remains the default runtime. Independently pinned middle-hop extension now
works through this entry. Private GC/2 discovery, automatic entry selection,
authenticated relay queue class enforcement,
counter-window flow control, SDK/application integration and qualification are
still pending. Complete entry/middle/terminal circuits pass local fixtures; this
is not evidence of operated-network or production protocol qualification.

## Wire and sending behavior

Every class channel opens with a canonical `Open`, acknowledged with the same
class and profile. The profile is immutable across both channels on a physical
connection. Each class can open once; duplicate class opens, profile mismatches
and GC/1 framing fail closed. An established channel cannot open again.

| Field | Bytes |
| --- | ---: |
| Magic `GCT2` | 4 |
| Class: interactive 0, bulk 1 | 1 |
| Candidate profile ID | 1 |
| Kind: cover 0, data 1, close 2, open 3 | 1 |
| Payload length, unsigned network order | 2 |
| Opaque inner multiplexor bytes | declared length |
| Interactive zero padding | remainder of fixed record |

Interactive records always occupy the selected 1/2/4 KiB size. The sender polls
already available bytes once at each fixed 250/500/1,000/1,500 ms opportunity.
No data produces cover; no opportunity is advanced or added for chat arrivals.
A blocked write skips elapsed opportunities and resumes on the next future
point of the original schedule, without a catch-up burst. Bulk data records are
exactly nine header bytes plus nonempty payload, at most 16 KiB. Bulk has no cover
record. Open/close have empty payloads. Close half-closes the channel; truncation,
trailing bytes, invalid lengths, padding and control kinds are rejected.

This schedule describes records, not a claim that real network packets reveal
no chat activity. TLS records, HTTP2 control traffic, congestion and connection
lifecycle remain part of the packet-level qualification gate.

`EntryCarrier::connect_via` adds an independently pinned TLS/HTTP2 middle hop
inside a typed entry circuit. Its initial `GCX2` body contains magic (4 bytes),
class (1), target length (2, network order) and the canonical target (at most
256 bytes). The reply is `GCX2`, the same class and zero status. Subsequent bytes
are unpadded, unscheduled terminal traffic inside that middle TLS connection.
The outer entry alone supplies interactive shaping. The caller independently
authenticates the terminal; it never inherits the middle's TLS identity.

Before opening a circuit, the API rejects entry/middle/terminal IP or pin overlap
and checks every supplied route exclusion against both intermediaries. It cannot
dial a replacement entry in response to a failed route. The existing target
allowlist and reachability policy apply at each relay. Private descriptor refresh
and selecting a compatible preconnected entry are still runtime integration work.

## Ownership and resource bounds

The caller owns and continuously polls `entry::run` for a connected period chosen
independently of chat. That future owns TLS, outer HTTP2, both channel pumps and
both inner multiplexor drivers. A bounded owned queue also holds nested middle
connection drivers. Dropping a terminal stream cancels its nested driver;
canceling the entry owner drops the complete tree. The API
does not dial, reconnect or silently select another version. The relay listener
creates connection state after a successful TLS/HTTP2 handshake; a private path
must still authenticate before entering the service.

| Resource | Bound |
| --- | --- |
| Established class channels | 2 per physical connection |
| Logical circuits | 16 shared across both classes; at most 15 bulk |
| Nested middle drivers | At most 16, each retaining a logical circuit permit |
| Middle targets per nested TLS connection | 1 |
| Relay circuits | Existing service limit, at most 128; GC/2 bulk leaves one slot |
| Circuit open operations | 64/second across both class channels |
| Outer client receive credit | 32 KiB per class, 64 KiB connection |
| Outer server receive credit | Existing TP1 256 KiB per stream, 1 MiB connection |
| Local channel buffer | 32 KiB per direction per class |
| Inner receive credit | 32 KiB per stream, 256 KiB per class connection |
| Inner queued send bytes | 32 KiB per stream |
| Inner header list / dynamic table | 1 KiB / zero |
| Inner pending/retained reset streams | 16 per multiplexor |
| Target descriptor | 256 decoded bytes maximum |
| Record / target forwarding scratch | 16 KiB maximum / 8 KiB per direction |
| Handshake / circuit open | 30 seconds |
| Entry lifetime | Earlier of capability expiry and 30 minutes |

Bulk cannot consume the full connection receive window or the final circuit
permit. HTTP2 returns receive credit only as the consumer reads bytes. Admission
does not queue while retaining another class's permit. The server repeats the
shared circuit check, so separately budgeted or malicious clients cannot bypass
it. HTTP2 provides monotonic 31-bit stream IDs and rejects invalid stream state;
no application map grows with historical circuit IDs. The fixed operation bound
and HTTP2 reset bounds limit control churn. Flood failure ends a channel; it does
not silently reduce padding or select another profile.

The service uses a separate HMAC-derived `ghost.gct2.entry.v2` capability bound to
its service identity and hourly epoch. GC/1 circuit and re-entry capabilities are
not accepted. Middle transit uses the independent `ghost.gct2.transit.v2` domain.
A physical connection binds to either entry or transit: possessing both tokens
cannot add an unshaped path to a protected entry. Service target policy,
reachability admission and capacity still
apply. The returned logical stream carries opaque bytes: the next hop requires
its own TLS pin and capability. Complete route selection must preserve every
endpoint, terminal and adjacent-hop exclusion before using a shared entry.

## Costs and remaining evidence

Candidate profile ID is `size_index * 4 + period_index`, ordered by the record
sizes and periods above. For one continuously connected carrier, two directions
for 30 days cost `record_size * 2 * 2,592,000 / period_seconds` record bytes.
The 4 KiB/1-second candidate costs 21,233,664,000 bytes; 4 KiB/1.5 seconds costs
14,155,776,000. These exclude outer protocol/link overhead, retransmission, other
connections and bulk. Duty cycle can reduce the total, but connection lifetime
and profile selection must not follow chat arrivals or monthly quota balance.

Tests exercise identical idle/burst opportunity traces, fragmented records and
half-close replies, malformed data without payload leakage, blocked writes
without catch-up, class budgets, canceled target dials, actual TLS pin rejection,
one physical connection for both classes, mismatched profiles and shutdown.
They do not qualify anonymity, production goodput, mobile power or background
availability. Profile selection and the application/privacy/device gates remain
in [the implementation ledger](GC2_IMPLEMENTATION.md).
