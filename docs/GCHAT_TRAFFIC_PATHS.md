# GChat traffic-path inventory

This analysis is bound to the running file candidate: GComs runtime
`d6f5d97`, GChat `200cd7a`, immutable `fleet-build-11`. It also compares
the retained `app_performance` fixture and the original-coms fleet-port
checkout at `e2e858a`. These startup modes are materially different.
The inventory does not qualify an installed desktop release or whole-client
privacy. No subscription pump was removed for this analysis.

## The selected scheduler determines the wire

Current GChat production startup creates a `RoutingRuntime`, installs the
explicit GCRB2 directory and selects `RelayScheduler::with_gc2_transit`.
The endpoint transport uses `ReadyConnector`; the scheduler has
`natural=true` and `emit_cover=false`. Applications can use established
entries, but unavailable protected routes cannot turn into direct endpoint
connections. See [startup](../crates/node/src/node/mod.rs),
[bootstrap](../crates/node/src/node/gc2_bootstrap.rs),
[scheduler](../crates/node/src/scheduler.rs) and
[entry ownership](../crates/routing/src/gc2/owner.rs).

The contact and channel pumps in [ticks.rs](../crates/node/src/node/ticks.rs)
are now shared semantic workers. On the natural scheduler they subscribe to
both Interactive and Bulk queues through `subscribe_with_class`, which encodes
a natural authenticated Subscription in
[scheduler/gc2.rs](../crates/node/src/scheduler/gc2.rs).
The label `contact_sub_connected` therefore does not identify a legacy wire.
Two aliases with two classes can produce four such events; periodic stream
renewal produces more without introducing four new physical entry connections.

The additional compatibility `gc2_carrier::spawn_subscriptions` is guarded by
`!scheduler.is_gc2()`. It does not run alongside the natural scheduler on
this production startup path. Removing the shared pumps would remove current
contact/channel reception, staged/draining alias handling and readiness tracking.

| Startup mode | Endpoint scheduler | Subscription workers and consequence |
| --- | --- | --- |
| Current production GCRB2 / fleet build 11 | Natural, protected existing-entry connector; scheduler cover disabled | Shared contact/channel pumps subscribe by class; separate compatibility carrier pump is disabled. |
| Current `app_performance --protected` fixture without a RoutingRuntime | Legacy scheduler, plus a protected natural direct-message carrier | Both compatibility paths remain possible; the benchmark does not exercise current channel/file startup. |
| Original-coms fleet-port `e2e858a` | Earlier carrier integration | Contact pump is suppressed when its carrier is active, while channel and invite workers remain. Its results cannot be substituted for the current unified scheduler. |

The benchmark's [endpoint constructor](../crates/node/examples/app_performance.rs)
uses `NodeProfile::Fixture` and `start_persistent_restored` without a routing
configuration. Its profile ID describes the entry carrier, not every path in
the process. It sends durable direct application chunks rather than invoking
GChat's file engine. This explains why natural delivery and legacy FRWD cover
can coexist in that fixture. It does not independently establish the provenance
of a historical count unless the exact executable, arguments and logs are bound.

## Current traffic paths

| Trigger / obligation | Application and transport path | Capture implication |
| --- | --- | --- |
| File offers, availability, piece requests and piece data | GChat `chat_service/files.rs` calls SDK `send_channel_application`; the SDK adds the versioned piece envelope and calls channel-direct. The node authenticates channel membership, encrypts for that member and calls `push_with_class(..., Bulk)`. Natural Push reaches the member's channel control alias through the protected endpoint connector. | These are actual channel file messages. All piece application envelopes select Bulk; `channel-direct` does not mean a direct network dial. Include both directions and retries. |
| Channel chat, membership, directory announcements, PEX and acknowledgments | Channel workers enqueue Push jobs. The default wire class is Interactive, even where the producer accounting label is `ChannelData`. The selected scheduler encodes natural Push. | Background channel maintenance remains real traffic. Producer labels alone do not identify wire classes or byte counts. |
| Contact and channel reception | Shared pumps enqueue natural Subscription separately for each alias/class; verified deliveries enter the common semantic decoder. Normal subscription deadlines reopen existing authority. | Count subscription opens, closes and retries; do not infer physical connection counts from pump event names. |
| Direct sessions and invitation redemption / Welcome | `send_direct_record` and durable maintenance use the selected protected natural client. Invite service drains a bounded local request queue and returns replies over that authenticated session. Some repair/announcement jobs go through the natural scheduler. | The invite loop is not an independent idle network poll. Its work, replies and repair obligations still belong in the capture. |
| Inbox/channel provisioning, recovery and lease create/renew/revoke | GCRB2 provisioning uses the current control connector. Scheduler `AdminPost` explicitly retains a legacy RelaySub management envelope over the protected connector; non-management legacy data is rejected. ReadyConnector's ordinary connect binds Interactive. | A current deployment still has legacy-shaped management bytes inside protected transport. Natural data delivery does not imply that all inner wire formats have migrated. |
| Entry maintenance, directory refresh and credential rollover | The background EntryOwner owns physical entry dials, refresh and class carriers. Natural data requests select only its existing ready entries. The legacy discovery refresh/publication loop is skipped when the natural scheduler is selected. | Capture startup, idle, renewal, reconnect and shutdown, not only application intervals. Profile 22 retains Interactive cover while Bulk volume/activity is intentionally observable. |
| Authorized relay/transit work | Node startup creates a separate transit transport pool for admitted relay jobs. This pool is deliberately direct to the next relay, so forwarding does not recursively use the endpoint's onion connector. | Account for the client's advertised/authorized relay role. Relay traffic on a shared host or namespace cannot be treated as endpoint-only traffic. |
| Installed network bootstrap and signed defaults | GChat recovery can fetch HTTPS network defaults and private provisions through `NetworkClient`; explicit provider recovery also uses HTTPS. These are separate from the protected application scheduler. | Include configured-provider connections, DNS and failed attempts. Fleet's explicit private bundle and `--no-network-bootstrap` do not qualify this path. |
| Opt-in names and listener updates | GChat starts name maintenance separately from bootstrap. Pending name operations use NetworkClient HTTPS; listener updates are conditional on opt-in. | Disabling network bootstrap alone does not suppress every background network facility. Exercise enabled, disabled and pending-operation states. |
| Automatic listener / router mapping | With an automatic listener, connectivity code can perform PCP/NAT-PMP or SSDP/UPnP HTTP mapping and renewal. Fixed-port fleet clients do not start that automatic mapping path. UDP connect used only to select a local route is not itself a transmitted probe. | Include LAN control traffic and DNS where enabled. Do not classify socket construction as a packet or claim fleet coverage of default desktop mapping. |
| Catalog requests | Node `catalog_request` currently calls the legacy `runtime.discovery.connector` and `OnionConnector::connect_https`, rather than the GChat ReadyConnector. | A separate migration/audit item. It may fail with an empty legacy directory; behavior with retained legacy state must also be tested. Do not claim current-carrier coverage from an unused catalog path. |
| UI, daemon IPC and local file export | The fleet probe drives the actual GChat daemon's Unix socket; export/hash checks operate on the receiver's file data. The desktop host forwards carrier selection, but an installed desktop is not used in this run. | IPC and verified export establish application correctness, not network indistinguishability or installed-package coverage. |

Relevant implementation: [channel applications](../crates/node/src/node/channel_direct.rs),
[SDK envelope](../crates/sdk/src/types.rs),
[channels/invitations](../crates/node/src/node/channels.rs),
[direct sessions](../crates/node/src/node/direct.rs),
[routing recovery](../crates/node/src/node/routing.rs),
[catalog API](../crates/node/src/node/api.rs),
[network client](../crates/network-client/src/lib.rs),
[name maintenance](../crates/network-client/src/names.rs) and
[connectivity](../crates/node/src/connectivity/runtime.rs).
GChat counterparts are `crates/core/src/chat_service/files.rs`,
`runtime.rs`, `bootstrap.rs` and `chat_service/host.rs`.

## What the observations establish

The cold [channel-file integration](../crates/node/tests/gc2_channel_files.rs)
uses a real RoutingRuntime, GCRB2 bootstrap, remote invitation redemption and
authenticated Bulk acceptance at the terminal before and after subscription
renewal. This is materially stronger than observing subscribed Bulk queues alone.

The current fleet additionally runs the actual GChat file worker and verifies
export hashes through 256 MiB. Its 1 GiB case is still in progress. Sampled client
logs through approximately run elapsed 1,975 seconds contain 128 and 122
`contact_sub_connected` events, zero `natural_sub_connected` events from the
separate compatibility pump, and zero `frwd_cover` events. They also contain
retry/error diagnostics; zero cover events is not a claim of error-free operation.

Read-only samples of the two assigned terminal relays around elapsed 2,530 seconds
record 40,946 and 40,945 authenticated Bulk Push acceptances, alongside Interactive
Pushes and both subscription classes. Those relay samples also have zero
`frwd_cover`. These are aggregate counters, not per-file receipt IDs or an
all-egress packet trace. Private log hashes and counts are retained in
`target/protocol-plan-capacity02-live/authenticated-class-observations.json`.
Immutable copies of these four metric samples and their source/run bindings are
under `target/protocol-plan-capacity02-live/traffic-inventory/`.

Historical entry-only captures omit other client paths. The later pooled-loopback
fixture captures have a different limitation: they mix endpoint and relay traffic
and still use the fixture startup described above. Valid packet accounting or
correct application receipts cannot turn either scope into installed GChat privacy
qualification. A profile-22 ID alone is insufficient evidence.

## Remaining migration and qualification work

A concrete installed-bootstrap gap remains in the audited pair. Both GChat
`recover_network` and explicit-provider `recover_routing` use the legacy
`routing_bootstrap` / `install_routing_bootstrap` APIs. NetworkClient's
`fetch_routing` decodes the legacy BootstrapBundle. The selected GChat scheduler
rejects that installation. HTTP `supported_versions: [2]` is the provisioning
response version; it is not proof of a GCRB2 bundle. Private file bootstrap and
the already migrated channel invitation path bypass this missing transition.

The coordinating release worker has been sent the exact call chain and proposed
ownership of this migration; no overlapping bootstrap files were changed here.
The needed behavior is explicit authenticated current-protocol provisioning and
typed import, with fresh install, retained state and recovery tests. Converting
legacy authority or silently falling back would invalidate the intended routing
boundary. Catalog transport selection needs an equally explicit resolution.

For whole-client qualification:

1. Run the selected GChat daemon/installed desktop with current production startup
   in its own network namespace or equivalent isolated egress boundary. Keep
   relays in separate namespaces/processes and capture every client interface,
   address family and traffic type. Start capture before process startup and
   retain through shutdown. A relay-port-only filter is insufficient.
2. Record executable hashes, actual transport diagnostics, fresh versus retained
   state, bootstrap/naming/mapping/catalog settings, interface membership and
   packet/drop counters. Include resolver traffic attributable to the client;
   host resolver traffic must not silently escape the capture boundary.
3. Exercise real GChat channel creation/invitation, chat and file send/share,
   acceptance, export, reopen, expiry and outage recovery. Retain exact delivery
   and export hashes, authenticated terminal-class evidence, resource bounds and
   connection/circuit observations. Test release artifacts after installation as
   well as source-built daemons.
4. Compare matched idle/chat and bulk/mixed workloads using the same client
   lifecycle and background settings. Keep independent training/held-out runs,
   measurement validity separate from the accepted component criterion, and the
   existing upper-confidence-bound threshold of 0.55. Observable bulk does not
   waive the conditional chat-privacy criterion.
5. Keep fleet correctness/capacity, component measurements, full-client privacy,
   installed-package validation and owner profile selection as separate gates.
   The running capacity/coverage/fault sequence supplies fleet evidence only.

No extra relay workload or packet-capture campaign was started for this inventory;
the coordinated fleet window and frozen build remain unchanged.
