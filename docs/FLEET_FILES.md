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
host and remote inbox assignments. It checks all 56 directed inbox-host pairs,
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
