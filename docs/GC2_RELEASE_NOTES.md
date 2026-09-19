# GC/2 release notes — 2026-09-19

This is the client-facing summary of the GC/2 rollout: what was built, what is
now running in the fleet, exactly what changed on the wire, and what changes for
applications that consume the GC (GChat and any SDK consumer).

## 1. What GC/2 is

GC/2 is the next generation of the Ghost Communication carrier: sessions no
longer ride the legacy relay push alone. A GC/2-capable node talks to its peers
through **protected entry/middle/terminal circuits** (the GCT2 carrier) and
carries application records as authenticated cells over a fixed, padded
schedule. GC/1 remains available for peers that have not migrated, and there is
no automatic conversion between the two carriers in either direction.

## 2. What is deployed now

All eleven relay instances run the GC/2 carrier:

- eight native relays (`triform-1…8`), `ghost-relay.service` with
  `--schedule gc2`;
- three Kubernetes anchors (`gc-anchor-0…2`) with the same profile in their
  pod args;
- every instance has the signed `gchat-network.json` installed and an explicit
  `--network-config` path, a durable GC/2 directory beside its keystore
  (`keystore.gc2-directory` / `ks.gc2-directory`), its DNS record
  (`r1…r8.relays.gchat.boo`) intact, and unchanged keystore/TLS/passphrase
  material (identity continuity verified host by host).

Relay rollback material is retained: `/var/lib/ghost-relay/backups/20260919-*`
on each host (previous unit plus identity hashes), the previous release under
`/opt/ghost-relay/releases/`, and the deployment script
`deploy/deploy-relay-gc2.sh` in the fleet branch.

## 3. What changed on the wire

**Opt-in, never implicit.** GC/2 is selected by the deployment profile
(`--schedule gc2` on relays; the `gc2-carrier` feature plus `--gc2-carrier` in
GChat). The service advertisement that seeds a client's GC/2 directory is an
opted-in private provisioning request (`KIND_PROVISIONING_GC2`, option byte
`PROVISION_OPTION_GC2`). Version-1 provisioning cards stay byte-identical, so
un-upgraded clients are unaffected, and **nothing falls back silently** from
GC/2 to GC/1.

**Sessions.** GC/2 sessions use compact authenticated envelopes with a bounded
ratchet counter window: independent credit per direction, a reserved
interactive/control share, and repair of exact ciphertext after loss. Durable
application acknowledgements are not tied to the control window: they persist as
encrypted obligations (the GC2R2 receipt ledger) and materialise through a
bounded maintenance owner, so full control-window pressure cannot deadlock
application delivery.

**Traffic classes.** Durable file records are classified as **bulk** from their
authenticated component kind; chat, acknowledgements, presence and contact
updates keep the interactive and control reservations. A send may carry an
explicit class hint (`send_durable_1to1_class` on the node, SDK
`submit_durable_opaque_class`); the hint only affects the immediate reservation —
deferred copies re-derive the class from the record, and the hint never reaches
the wire.

**The carrier.** Each entry connection carries two permanent class channels
(interactive, bulk) on one shared circuit budget (16 circuits per entry, at most
15 bulk). Both classes now ride **one fixed lattice**: one record per profile
slot (250/500/1000/1500 ms), padded to the profile record bound, with cover when
nothing is queued. A blocked write skips elapsed slots without a catch-up burst.
Nodes keep protected circuits to established peers warm so idle periods carry
the same channel schedule as active ones, and the protected entry/middle client
is preferred whenever the directory has live entries.

**Provisioning and directory.** Relays advertise their GC/2 introduction in the
provisioning response; clients install it as a durable directory seed and the
background owner renews it (one to three entries). The GC/2 directory has its
own encrypted cache, key domain and writer lock, separate from GC/1.

**Archive and rollback.** A node that has run GC/2 seals its node archive as
version 21. **A v21 (GC/2) archive cannot be restored under a GC/1 profile** —
restoring refuses with a clear error instead of silently downgrading. This is
the explicit rollback profile: run with the GC/2 profile to restore, or restore
from a pre-carrier backup.

## 4. What changes for clients

### GChat

- **Default builds are unchanged.** The carrier lives behind the `gc2-carrier`
  feature (`gchat-core`), which forwards `gcoms-node/experimental-gc2`.
- **Enabling it is explicit:** build with `--features gc2-carrier`, then run
  with `--gc2-carrier` or `GC_GC2_CARRIER=1` on the daemon or the TUI
  (`--local-fixture` cannot be combined with it). Without the feature, selecting
  the flag fails with a clear error instead of falling back.
- **What a carrier-enabled client gets:** its sessions can use the protected
  circuits, its node state gains the GC/2 directory below the private network
  state, and its archive becomes v21. Contacts that are not carrier-enabled keep
  using the legacy relay paths; there is no downgrade and no conversion.
- **Rollback:** a v21 archive will not open under a build/profile without the
  carrier. Keep a pre-carrier archive backup, or restore with the carrier
  profile.

### SDK consumers

- New sends: `send_durable_1to1_tracked(_class)`, which return the exact logical
  message id that the application receipt (`Ev::DirectDelivery`) carries, and
  `submit_durable_opaque_class` on the SDK trait (a defaulted method, so
  existing implementors keep compiling).
- The 11 KiB file chunk path is unchanged and compatible:
  `negotiated_chunk_bytes` (11,264 modern / 8,192 old / 1,024 clamped) and full
  padding to at most 16 KiB per natural cell. Bulk classification of file
  records is automatic.
- No existing API changed behaviour; GC/1 consumers see no protocol difference.

## 5. Measured results

**Performance (production cadence, five balanced repeats, real persistence and
receipts):**

| | GC/1 | GC/2 |
| --- | --- | --- |
| bulk goodput | 0.514 KiB/s | **1.107 KiB/s (2.15×)** |
| mixed goodput | 0.433 KiB/s | **0.896 KiB/s (2.07×)** |
| chat p95 (chat-only) | 45.5 s | **16.7 s** |
| chat p95 (mixed) | 48.5 s | **20.7 s** |
| 128-byte one-way shaping | 6.2–12 s | **1.61 s (≤ 3 s)** |

**Robustness / native:** full in-cluster battery green (protocol 55, node lib
272 +1 ignored, routing 66, transport, core, SDK 51, network 27, minimal-feature
and doc/vector/source checks), Windows GNU VM protocol 55 + node 34, GChat 147.

**Privacy: not qualified.** On the shaped client→entry link the padded lattice
makes record rate and size activity-independent (~19–20 large records per
second in both chat and idle), but a predeclared timing/size classifier still
separates activity: **chat-vs-bulk 0.946** and **idle-vs-chat 0.904**
separability (bootstrap upper 0.997/0.966) against the ≤ 0.55 bound. The
residual signal comes from the per-message control exchange and from client-entry
channels not being kept warm across idle periods. This gate is reported open and
must not be claimed as passed. The fix is scoped in
`target/gc2-privacy-gate-plan.md` (traffic-independent keepalive plus, if
needed, lattice-scheduled control exchange), and needs its own validation cycle
and fleet redeploy.

**Mobile:** physical-device testing remains deferred by the owner and is outside
this rollout's scope.

## 6. Evidence

- Fleet report: `target/fleet-rollout/SUMMARY.md` (build digests, per-host
  results, identity hashes, anchor migration, health sweep).
- Performance: `target/perf-final-local.json`; merge/battery run:
  `target/cluster-battery/evidence-20260919-141901/`.
- Platform: `target/gc2-final-validation-20260919/` (Windows + GChat).
- Privacy: `target/privacy-captures9/` and the corrected plan/verdict in
  `target/gc2-privacy-gate-plan.md`.
- Implementation detail and history: `docs/GC2_IMPLEMENTATION.md`,
  `docs/GC2_WIRE.md`, `docs/GCT2_CARRIER.md`, `docs/GC2_FLOW.md`.
