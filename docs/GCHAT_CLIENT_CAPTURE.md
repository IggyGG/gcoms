# Isolated GChat daemon capture calibration

`scripts/privacy-client-capture.py` drives an actual GChat daemon through its
owner-authenticated Unix IPC, using `fleet_probe` and source-bound fleet build
artifacts. It runs one randomized idle/chat/bulk/mixed quartet. This establishes
an observation boundary and application/capture validity; it does not estimate
a statistical privacy bound or qualify a release.

The public-policy-valid IPv4 addresses used here exist only inside disconnected
local network namespaces. The driver creates both veth ends inside a fresh
fixture namespace, moves one end into the observed client's namespace, and
installs no default route, gateway, host link, NAT or firewall rule. Four local
relay processes and the receiving GChat daemon share the fixture namespace.
The observed namespace contains only its holder, actual sending daemon and two
capture processes. The controller and probes use Unix IPC; application binaries
run as the invoking user. No fleet server, SSH deployment or production relay is
involved.

The privileged worker also has disposable mount and PID namespaces. Its private
resolver uses `files dns`, an unreachable fixture-only DNS address, and hides
nscd's host pathname if present. Application environment is constructed explicitly;
bootstrap/provider/proxy/desktop-service settings are not inherited. A bounded
watchdog and PID-namespace teardown contain descendants. Normal completion
requires all child processes stopped, graceful daemon exits and unchanged host
interface identities. Failed runs retain logs, packet data and cleanup outcomes.

## Run one quartet

Linux tooling: Python 3, `ip`, `unshare`, `nsenter`, `mount`, `setpriv`, `timeout`,
`ethtool`, `tcpdump` and `tshark`, with noninteractive privilege for the namespace
worker. Use a new output directory; existing evidence is never overwritten.
On the managed workstation, declare a contained output and reservation:

```sh
WORKSTATION_BUILD_BUDGET=1073741824 workstation-batch -- \
  workstation-builds run --budget 1073741824 --wait 30 --timeout 2100 \
  --output "$PWD/target/client-capture-calibration-NEW" -- \
  python3 scripts/privacy-client-capture.py \
  --build target/fleet-build-11 \
  --out target/client-capture-calibration-NEW \
  --seed 20260920
```

The build directory must contain a passing `build.json` and its exact `bin/gcnode`,
`bin/gchat`, `bin/fleet_probe`. Binary hashes, source revisions and source snapshot
hashes are bound into every run. A historical artifact validates only that
historical source pair, regardless of the current checkout. The controller binds
its own source hashes and the decoder versions separately.

Default timing is 120 seconds from observed daemon launch to measurement, then
60 seconds of measurement. Setup must finish within the fixed allowance. Every
workload uses fresh cryptographic identities and state. The numeric seed controls
workload order and the matched file bytes, never cryptographic identity or
transport randomness. Chat/mixed send two messages with distinct IDs and require
receiver delivery plus a returned application acknowledgment for each. Bulk/mixed
use the same 64 KiB file identity, bytes, receiver role, explicit acceptance,
retention and quota policy; independent export size/hash verification and an
authenticated terminal Bulk acceptance diagnostic are required. All workload
receipts must fall inside the measurement window. A failed capture stops the
sequence before allocating further runs.

Clients explicitly select the production-cadence profile 22 carrier, GCRB2 and
`--no-network-bootstrap`; no `--local-fixture` or private-forwarding exception is
used. This scope is **isolated daemon with explicit bootstrap**, not the
installed-default desktop, installed HTTPS bootstrap, catalog, names or router
mapping journey. Those paths remain separate required qualification.

## Complete packet accounting and connection observations

Capture starts before the daemon and remains through shutdown and drain. The
external `client0` capture has no relay, port or IP filter. Loopback is retained
separately as diagnostic evidence. The manifest binds the two namespace identities,
interfaces/MACs/addresses/routes, process membership, resolver configuration,
offload settings, snap length, binary/configuration identity and lifecycle times.

`privacy_client_packets.py` independently walks every classic Ethernet pcap
record, then compares frame and byte counts with an unfiltered structured decoder.
MAC direction accounts for incoming multicast and non-IP frames. Missing,
unattributed, malformed or truncated observations fail validity. The pcap count
must equal both tcpdump's recorded and filter-received counts, with zero kernel
drops. Unique IPv4 and IPv6 sentinels must reach the pcap before startup and after
shutdown; a fixture-only sentinel must remain absent. Thus zero drops alone or
an empty buffered capture cannot pass.

Features use observer packets only: fixed one-second directional packet/byte and
SYN/FIN/RST/non-IP counts, plus bidirectional TCP streams, opening/retransmitted
SYNs, handshake observations, reset refusals, FIN closes and observed lifetime
lower bounds with explicit left/right censoring. Tuple reuse and inconsistent
stream endpoints are checked. A half-close remains right-censored. Decoder stream
IDs describe packet observations; they are not protocol connection counters.
Internal relay counters support application correctness diagnostics only and
never enter the feature vectors. Historical pooled tools retain their distinct
scope and cannot be substituted for this client manifest.

`privacy_client_manifest.py` validates each capture and matches the quartet's
file identity and process lifetimes. It also retains each run's phase relative
to hourly capability expiry. A quartet that crosses a credential epoch fails
this initial calibration check; phase matching across independent statistical
runs remains future work.

## Qualification limits

`measurement_valid`, `component_gate_passed` and `release_qualified` remain
separate. Even a valid quartet reports `component_gate_passed=false` and
`release_qualified=false`: no training/held-out analysis was performed. The
accepted file contract still requires upper 95% separability <=0.55 for both
idle/chat and matched bulk/mixed, for windows and observer connection features.
Invalid data or exceeded bounds fail; unfavorable evidence must be retained.
There is no statistical matrix in this calibration driver and no waiver of the
installed-client or fleet gates.
