# Isolated fleet file qualification

This private operator campaign uses the eight recorded Hetzner relay hosts. It
creates separate test listeners; it never restarts `ghost-relay.service`, modifies
its identity, or uses production bootstrap grants. Source and tooling changes stay
in the paired GComs/GChat task checkouts. The relays and clients run the fleet
GChat file carrier profile (wire profile 22), with a fixed interactive schedule,
bounded unpaced bulk records, authenticated class queues and private routing.
The isolated relays select this explicitly with `--schedule gchat-files`.
File activity and approximate volume are observable under this policy. Compressed
or fixture scheduling is not fleet evidence. Chat privacy remains a separate,
unqualified gate; successful file exports cannot qualify it.

## Build and run

From the GComs task checkout, with its GChat companion beside it:

```sh
python3 scripts/build-fleet-files.py --gchat ../gchat --output target/fleet-build-01
python3 -m unittest discover -s scripts/tests -p fleet_files_test.py
python3 scripts/fleet_files.py run --build target/fleet-build-01 \
  --output test-evidence/files-canary-01 --phase canary
python3 scripts/fleet_files.py run --build target/fleet-build-01 \
  --output test-evidence/files-capacity-01 --phase capacity
python3 scripts/fleet_files.py run --build target/fleet-build-01 \
  --output test-evidence/files-coverage-01 --phase coverage
python3 scripts/fleet_files.py run --build target/fleet-build-01 \
  --output test-evidence/files-campaign-01 --phase campaign
```

Use fresh output directories. The build snapshots both repositories, records the
resolved dependency locks and executable hashes, and refuses a passing receipt if
either source changes during compilation. Remote executables are hashed again.
The native `fleet_probe` example uses GChat's ordinary owner IPC and bounded file
I/O. Source data is generated only on senders; independent exported-file hashes
are mandatory. Native paths never travel over the file protocol.

Each phase starts with the 64 KiB cross-host canary, then reopens its receiver and
checks another export hash and retained instance identity. Capacity adds a
five-minute chat baseline and sequential 4 MiB, 32 MiB, 256 MiB and 1 GiB files
with chat. A 1 GiB export must finish within four hours of acceptance. Coverage
and the full campaign retain their separate ramp and directed-pair requirements.
Only the complete campaign can produce a fleet qualification verdict.

SSH uses the existing verified host keys and batch authentication to the recorded
numeric addresses. Each host needs root operator access, systemd, Python 3,
iproute2, iptables and ext4 tools, IPv4 forwarding, 40 GiB free on `/var/tmp` or
`/home`, and at least 5 GiB available RAM. Production service identity/PID/restart
state is sampled before and throughout the campaign. An external rollout changing
that state invalidates the comparison and stops this campaign.

## Isolation and ownership

Each run gets a private directory, retained 32 GiB sparse ext4 test volume,
network namespace, veth, named systemd slice and service units. CPU is limited to
two cores and memory to 4 GiB per host. Client caches reserve 8 GiB each. The
namespace egress is limited to 50 Mbit/s and the campaign stops at 200 GiB of
aggregate transmitted interface bytes, less than 5 GiB host free space, or less
than 1 GiB free test volume space. Resource pressure is evidence, not permission
to change protocol cover or admission rules.

Only TCP 24433 on the test hosts is reachable through the namespace forwarding
rules. Relay controls stay on namespace loopback TCP 29443; client attachments
use private Unix sockets. Fresh relay introductions and inbox grants are scoped
to these processes. Public bootstrap recovery and DNS opt-in remain disabled.
Clients advertise only namespace loopback listeners and receive through their
assigned remote inboxes. Before channel setup, all 56 directed test-relay TCP
paths and eight colocated public-address paths must be reachable. Hairpin rules
admit only the same namespace's traffic to its own test relay. These 64 TCP
checks do not prove protocol delivery.
The host worker creates narrow, named firewall chains and exact jump/SNAT rules;
cleanup applies their inverses without flushing shared chains or changing host
policies. Netem acts only on the test namespace interface.

The coordinator renews a host heartbeat every 15 seconds. A five-minute loss of
heartbeat or the seven-hour host watchdog stops owned test units and removes
network resources. Test volumes and evidence are retained. Explicit recovery is:

```sh
python3 scripts/fleet_files.py cleanup --output test-evidence/files-campaign-01
python3 scripts/fleet_files.py analyze --output test-evidence/files-campaign-01
```

Do not delete retained images while diagnosing a failed run. They contain private
test identities and encrypted caches and do not belong in commits. Human-readable
reports contain synthetic operation labels and aggregates; diagnostic archives
are private and need review before sharing.

## Workload and evidence

The campaign ramps through two, eight and sixteen clients, with two clients per
host and remote inbox assignments. It checks all 56 directed client-host pairs,
empty files and block/piece boundaries, then takes a 30-minute chat baseline.
The four-hour mixed phase sends four 1 GiB and four 256 MiB files plus a rotating
small-file workload. Four workload channels each have four members; a separate
16-member channel provides coverage. Chat is an application echo after the
recipient reads its persisted history; timings include the same observation
overhead in baseline and mixed runs.

Faults cover receiver and relay restart, bounded path loss/delay, import restart,
changed source rejection, explicit acceptance, pause/resume, complementary seeds
and late join, unavailable sources, corrupt retained pieces, a separate bounded
cache filesystem reaching ENOSPC, quota, membership withdrawal and PM isolation.
Faults target disposable state only. Cache mutation requires a stopped client.
Recovery retains identities and valid ciphertext; a missing piece without a
surviving source must wait rather than report completion.

## Fault preconditions and admission

Each receiver admits at most two active downloads. The coordinator waits up to
15 minutes for a slot and records admission delay separately; transfer timing
still begins at acceptance and the five-minute small-file gate is unchanged.
Pause, restart, quota, path and membership faults use fresh 256 MiB transfers and
require observed nonzero, incomplete verified progress before injection. They do
not reuse the original large corpus after its possible completion.

The missing-source case first observes an unaccepted offer, stops its only seed,
then accepts. It requires a waiting state and zero verified bytes while the seed
is absent, followed by a verified export after restoration. The complementary
seed case joins the late receiver while both pruned seeds remain paused and the
original sender is stopped. It resumes the even-piece seed alone, verifies that
half at the receiver, pauses it, then resumes the odd-piece seed to finish. This
proves contribution by both sources through exclusive availability, including
source switching; it is not a simultaneous multi-source throughput measurement.
Both original seed copies and the final receiver require independent export hashes.

Reports require partial-progress and complementary-contribution observations in
addition to passing scenario labels. A 30-minute measured baseline is mandatory,
as is the full four-hour mixed window. An already complete fixture or two
advertised sources cannot supply the missing fault evidence.

Partial-progress recovery cases record a separate `recovery_progress` observation
within 300 seconds of restoration (including receiver/relay startup and readiness).
Pause and quota recovery start this timer after download admission resumes.
Already completed data must still pass an independent export hash. Completing a
fresh 256 MiB recovery fixture uses the capacity phase's 3,600-second budget;
the earlier 900-second whole-file timeout was shorter than the measured healthy
256 MiB transfer. The four-hour mixed window still stops unfinished work. Reports
require both the timed recovery observation and its matching verified export.

## Carrier policy and readiness

GCRB2 introductions must be exported explicitly and installed before the owner
can establish routes. GCRB1 authority is not converted or tried as a fallback.
Profile 22 retains 4 KiB/one-second interactive records and permits bulk records
up to 16 KiB as congestion-controlled transport credit becomes available. Bulk
has no idle cover. IDs 0–11 retain their original fixed schedules. The selected
policy is authenticated in `carrier-policy.cache`; switching policy must keep
the latest routing directory, session archive and file cache in place.

The harness waits for fresh local observations of profile 22, bootstrap version
2, ready entries, a usable independent inbox route, and both authenticated
subscription classes. IPC or TCP reachability alone cannot pass readiness.
Relay coverage uses natural subscription observations. Admission, hop receipts,
verified durable pieces, whole-file verification and independent export hashes
are distinct evidence; only the final exported bytes establish transfer success.

The piece engine requests up to eight blocks per piece, four pieces per download
and two downloads. It accepts bounded out-of-order blocks and retries missing
offsets. Its 4 MiB payload allowance includes reservations for queued outgoing
payload copies. A twenty-second local receipt observation retains the active
transport future; it cannot trigger overlapping retries.

The five-minute small-file and four-hour 1 GiB gates are unchanged. Measure actual
goodput with chat and repeat the full workload after integration changes. Smaller
fixtures and extrapolated capacity do not qualify the 1 GiB gate.

Reports group verified exports by file size and include measured completion p50/p95,
median goodput, and local file-engine counters. Completion timings start at recorded
acceptance. Diagnostic counters are summed across daemon processes without counting
repeated samples twice. Cleanup recovery uses the latest observation for every
distinct host; the manual cleanup command fails if any host remains unclean.

`events.jsonl` retains observations, `manifest.json` binds inputs, private host
archives retain logs, and `report.json` derives the result. Canary success is
reported separately from full qualification. Completion flags, expected runtime,
or planned cases alone cannot pass. Missing exports/ACKs fail; missing scenarios,
relay coverage, diagnostics or runtime remain incomplete. `GCHAT_FILE_DIAGNOSTICS=1`
adds local five-second aggregates without contacts, file IDs, keys or payloads.
Embedded clients include scheduler admission, dispatch, latency and resource
aggregates in the private diagnostic log. Reports count observed ready clients
and distinguish the largest offered fixture from the largest verified export;
planned 16-client/1-GiB coverage does not appear as observed scope.

A complete pass requires all planned cases, all expected byte-identical exports,
four measured hours, every client/relay, bounded resources, verified cleanup,
and accounted chat. Small transfers have a five-minute deadline; recovery has a
five-minute progress deadline. Outside declared fault windows, chat echo p95 is
bounded by `max(2 * baseline p95, baseline p95 + 2s)`, with a 120s maximum.
Every failed run is retained. Fix the smallest reproduction, add a regression,
then repeat the scenario and the whole campaign on the final candidate.

This is Linux runtime qualification at 16 clients and at most 1 GiB. It does not
qualify deployed production listeners, installers, mobile privacy, 24-hour
endurance, larger populations or multi-gigabyte network completion.
