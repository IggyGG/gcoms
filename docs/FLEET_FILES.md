# Isolated fleet file qualification

This private operator campaign uses the eight recorded Hetzner relay hosts. It
creates separate test listeners; it never restarts `ghost-relay.service`, modifies
its identity, or uses production bootstrap grants. Source and tooling changes stay
in the paired GComs/GChat task checkouts. The current protocol is GC/1 with its
production scheduler, authentication and routing. Fixtures/compressed scheduling
are not fleet evidence. GC/2 must have application integration before comparison.

## Build and run

From the GComs task checkout, with its GChat companion beside it:

```sh
python3 scripts/build-fleet-files.py --gchat ../gchat --output target/fleet-build-01
python3 -m unittest discover -s scripts/tests -p fleet_files_test.py
python3 scripts/fleet_files.py run --build target/fleet-build-01 \
  --output test-evidence/files-canary-01 --phase canary
python3 scripts/fleet_files.py run --build target/fleet-build-01 \
  --output test-evidence/files-campaign-01 --phase campaign
```

Use fresh output directories. The build snapshots both repositories, records the
resolved dependency locks and executable hashes, and refuses a passing receipt if
either source changes during compilation. Remote executables are hashed again.
The native `fleet_probe` example uses GChat's ordinary owner IPC and bounded file
I/O. Source data is generated only on senders; independent exported-file hashes
are mandatory. Native paths never travel over the file protocol.

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

## GC/1 capacity constraint

The production scheduler uses three-second slots and a 0.5 emission probability
per destination lane. File data shares those lanes with protocol work, and each
block carries at most 11 KiB. A continuously available single-source lane therefore
has a nominal payload rate of about 1.8 KiB/s before requests, discovery, retries
and other overhead. At that rate 1 MiB takes about nine minutes and 1 GiB about
159 hours. These are calculations from the current implementation, not measured
fleet throughput or guarantees. Multiple sources can contribute separate lanes;
they do not eliminate the initial distribution cost.

Keep the five-minute small-file and four-hour large-file acceptance gates visible.
A failure can expose a capacity limit as well as a correctness defect. Do not
speed up the privacy scheduler, bypass relay authentication, or label a smaller
diagnostic fixture as large-file qualification. Repeat the same workload after
the planned protocol improvements have application integration.

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
