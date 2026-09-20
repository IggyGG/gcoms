# GChat protocol file-transfer follow-up

This candidate integrates the current protocol with the existing private piece
exchange. It does not introduce a tracker, DHT or alternate application transport.
The existing file format, cryptographic domains and wire magic remain unchanged.

The accepted capacity target is an actual 1 GiB transfer within four hours. The
previous two-entry 4 KiB/second bulk lattice could carry at most about 8 KiB/s
before framing and routing overhead. Pipelining alone could not meet that target.
Wire profile 22 therefore explicitly permits observable bulk activity and volume,
while retaining the interactive schedule and existing resource reservations.

## Implemented candidate

- Channel application commands preserve ordered admission, then release the
  channel completion chain while awaiting their independent hop receipts.
- A directory checkpoint error is sticky, including a successful replacement
  followed by a failed sync. No new routing authority or stale snapshot export
  is available until authenticated reload.
- GCRB2 import/export, protected control provisioning and the natural channel
  scheduler are connected. Both class subscriptions are required. Duplicate
  suppression binds the authenticated class as well as the semantic request.
- Queue creation accepts an exact authenticated retry after a lost receipt;
  changed nonce, limits, expiry or capabilities cannot reuse a consumed grant.
  Channel recovery probes use the selected natural envelope.
- Profile 22 has fixed 4 KiB/one-second interactive records and natural bulk
  records bounded at 16 KiB. Old IDs retain their schedules. Policy changes
  preserve the latest private state instead of restoring an older archive.
- Piece requests use an eight-block window, bounded reassembly and missing-offset
  retries. Outstanding local sends retain ownership until transport completion.
  Outgoing payload copies reserve the engine's 4 MiB allowance before allocation.
- Fleet readiness requires observed protocol/profile, usable routes and both
  subscription classes. Correctness still requires independent export hashes.
- Healthy natural subscriptions reopen their current authority at their fixed
  deadline. A failed reopen initiates recovery; scheduled expiry alone does not
  reprovision a working inbox.
- The canary reopens the receiver and verifies another export. A separate
  `--phase capacity` measures 4 MiB, 32 MiB, 256 MiB and 1 GiB with concurrent
  chat after a five-minute chat baseline. The final campaign still requires
  its independent 30-minute baseline and four-hour mixed workload.
- Simultaneous multisource recovery is separate from sequential complementary
  recovery. Its receiver must verify pieces from at least two peers. The
  `verified_sources` observation counts contributors since process startup;
  it is not persisted or inferred from advertised availability.

## Shared protocol integration

The file candidate incorporates protocol commits `4d897cc`, `b8b9d45` and
`ebd8728`: shared traffic-profile allocation, protected-route retention during
outages, readiness-triggered retry and exact authenticated queue activation.
It selects ID 22 (`Interactive`, 4096 bytes/1000 ms) explicitly. The generic
full-cover constructor and IDs 0–11 keep their existing behavior. GChat's
protected file profile and the isolated relay harness select the file policy;
`gcnode --schedule gchat-files` is its explicit relay entry point.

## Evidence and remaining qualification

Focused tests cover the receipt stall, ambiguous checkpoint errors, framing
compatibility, idle/unpaced bulk behavior, out-of-order piece delivery, duplicates,
missing offsets and retained outgoing reservations. The cold GCRB2 test uses
four real loopback relays and two nodes; channel file delivery passed first with
the retained compressed profile and then with profile 12 (74.73 seconds for the
complete cold-start, channel admission and application-delivery scenario).
The extended scenario also crosses a complete subscription renewal period and
delivers again without inbox recovery (143.88 seconds total).
Those runs used the superseded local profile-12 candidate. The current candidate
adopts shared profile ID 22 and its padded Bulk Open. The extended scenario
passed again on this shared profile in 125.94 seconds, including authenticated
Bulk admission at the terminal for both file sends.
These are local integration results, not a GChat file export or fleet result.

The pre-integration implementation (`24bcd44`, paired with GChat `c947b08`)
passed 824 GComs workspace cases (six ignored). After shared-protocol integration,
the Rust source at `341b25b` passes strict workspace Clippy, 72 routing cases,
285 node-library cases (one ignored), ten channel/protected-route/profile cases,
documentation, minimal core and SDK IPC checks. The paired GChat source at
`a3c125c` passes strict Clippy and all 151 tests, with both source snapshots
unchanged during validation. Python validation passes 95 GComs and 36 GChat
cases; the generated contracts and frontend checks also pass. A node-library
run interrupted by a workstation missing-quota error is retained and superseded
by the complete successful retry. The paired archive consumers, GChat frontend
and standalone desktop checks subsequently passed on `ea9157f` / `a3c125c`,
with unchanged source snapshots (`target/protocol-plan-packages/summary.json`).
The source-bound release build in `target/fleet-build-09` also passed.

Fleet canary 13 reached eight ready relays and two clients with observed profile
22, GCRB2 routes and both subscription classes. It then exposed a separate invite
migration defect: GChat's `/invite` still requested a legacy bootstrap from the
empty legacy directory. No file was offered. Every host passed cleanup and its
production relay state remained unchanged. The invitation path now chooses its
bootstrap through the Node runtime: v3 carries GCRB2, while existing v1 and v2
links retain their formats. The cold channel regression now joins through remote
invitation redemption before sending file application traffic.
That expanded scenario passed in 146.74 seconds, including file delivery after
subscription renewal. Its first attempt retained a route-readiness failure after
invitation import; the shared GChat inbox wait now also requires a usable route.
The final shared-wait scenario passes in 142.94 seconds. On the committed pair
`628ec44` / `36a96ae`, all 151 GChat cases, both strict Clippy checks, dependency
policy, current/legacy invite codecs and package/frontend/desktop consumers pass.
The source-bound `fleet-build-10` passes as well. Canary 14 was interrupted by an
external production relay replacement before file admission; see the retained
[fleet results](FLEET_FILES_RESULTS.md). It does not qualify the invitation fix
or file capacity on the fleet.
Canary 15 subsequently passed on the same frozen binaries: the 64 KiB transfer
verified in 5.510 seconds after acceptance, receiver restart preserved identity
and a second export hash, and all eight cleanup checks passed. This clears the
small-file/reopen gate; it does not establish larger-file capacity or full fleet
qualification.

Preserve earlier fleet failures, including the current-protocol bootstrap failure
in `files-canary-12`. Rebuild both repositories together and require the ordinary
64 KiB cross-host canary within five minutes before larger canaries. Follow with
receiver reopen, sustained larger transfers with chat, the 2→8→16-client ramp,
all 56 directed host pairs and boundary fixtures. Final qualification requires
the 30-minute baseline, four-hour mixed corpus (four 1 GiB and four 256 MiB files)
and the full fault matrix on the final candidate. Partial-progress fault
preconditions, complementary sources and simultaneous source contribution need
actual observations. No reduced diagnostic fixture substitutes for these gates.

Privacy work proceeds alongside file correctness. Keep entry ownership and
class-channel lifetime independent of chat activity. Measure idle versus chat,
then identical bulk workloads with and without chat, using independent held-out
runs. The upper confidence bound on separability must remain at most 0.55.
The old chat-versus-bulk gate is incompatible with the newly accepted observable
bulk contract; retain its failed reports as historical evidence. Do not mark
privacy qualified until the revised capture and analysis have actually passed.

The new `privacy-capture.py --profile gchat-files --protected --cadence production`
instrument uses a fixed `--seconds` connected measurement interval for each of
`idle`, `chat`, `bulk` and `mixed`. A workload that overruns it fails. Bulk/mixed
use identical bulk bytes and chunking; idle/chat share the same chat parameters
as the matched pair. Choose an interval long enough to finish every workload.
Use at least eight fresh run seeds for training and eight disjoint held-out
seeds, recording all four workloads for each seed with one binary. Then run
`privacy-files-classifier.py --out <captures> --train-seeds <csv> --eval-seeds <csv>`.
The classifier verifies capture hashes/accounting, observes both relay links,
retains silent windows, handles AUC ties and bootstraps paired whole runs. Both
window traffic and connection-count gates must meet the upper bound. It creates
a separate diagnostic report and refuses to overwrite one. Its
`component_gate_passed` result cannot set `release_qualified`, which remains false. This application harness is
component evidence; final GChat/fleet release qualification remains outstanding.
