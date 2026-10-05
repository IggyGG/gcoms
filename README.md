Discovery role fixtures, 2026-10-06: candidate 154 passed native GChat qualification but exposed two discovery tests that assumed `Tp1Client` retained a physical connection after a 404. Both failures reproduce on the frozen source. These tests now retain pinned raw TLS/HTTP2 across cross-role requests and the final valid renewal, preserving GC/1 rejection, exact one/two-connection counts, terminal/control separation, bounded requests and owned cleanup. All eight discovery tests pass. Only the test fixture changes; production code, dependencies and API/wire contracts remain unchanged. The original Windows failure remains retained and a new candidate still requires native qualification. See [causal fixture evidence](docs/evidence/relay-capacity-20261005/discovery-role-test-connection.json).

Role-isolation fixture, 2026-10-05: candidate 153 exposed a test that reused `Tp1Client` after a rejected 404 while assuming the same physical connection. The client now correctly retires that pool entry. A focused baseline reproduced the failure; the fixture now retains raw TLS/HTTP2 explicitly for all three cross-role attempts, preserving rejection, unchanged queue, successful authenticated subscription, cleanup and zero-circuit assertions. All seven queue-service integration tests pass. This changes only test code; production transport behavior and API/wire contracts remain unchanged. See [causal test evidence](docs/evidence/relay-capacity-20261005/role-isolation-test-connection.json). Candidate 153 retains its failed native result and still does not qualify the release.

Relay restart recovery, 2026-10-05: unknown private paths could retain all eight unauthenticated connections for a source IP, preventing a fresh recovery connection before forwarding admission. The client now retires only the exact pooled connection on 404 without replay; existing subscribers retain their leases. The server bounds unauthenticated connections to the existing 120-second idle budget even while unknown requests continue. Authentication, connection caps, response semantics and wire/API contracts remain unchanged. Causal baseline failures and 64 passing transport/security checks plus strict Clippy are retained in [transport evidence](docs/evidence/relay-capacity-20261005/transport-unauthenticated-lifetime.json). This is a focused source fix; the new source still requires native and full fleet qualification.

Release campaign, 2026-10-05: candidate 152 admitted all 64 clients but failed after a terminal relay restart, about 20 minutes into traffic. The restarted relay accepted no further deposits; the other relays continued. The smaller terminal-restart diagnostic recovered authenticated delivery and verified the 5,235,248-byte file, but does not qualify the 64-client campaign. Preflight now restarts the receiver inbox relay, and backlog failures retain bounded recipient-versus-acknowledgment evidence without message contents. The 64-client, 30-minute, refusal, latency, file and restart gates remain unchanged. See [retained load evidence](docs/evidence/relay-capacity-20261005/terminal-restart-load.json).

Simulator grant timing, 2026-10-05: the original Apple SDK client run reached its relay test more than five minutes after fixture startup and failed with TP-1 unauthenticated 404. The test now requests one fresh card from its authenticated loopback fixture after launch; grant lifetimes, protocol authentication, Android assets and production packages are unchanged. Six fixture controls and the actual Rust helper smoke pass; fresh cards retain the listener and cleanup closes it. Native Apple qualification remains required. See [fixture evidence](docs/evidence/relay-capacity-20261005/apple-fixture-grant-timing.json).

IPC cancellation, 2026-10-05: a deterministic capacity-one transport reproduces a canceled request leaving a partial frame before the next request. The IPC writer now retains one bounded zeroizing frame and its cursor under the existing mutex, finishes its exact remaining bytes before admitting another frame, and closes the connection on a partial write error. All nine focused prefix/body cancellation, error, disconnect, read and payload-cleanup checks and strict SDK Clippy pass. Original Windows152 failed at the final `host.flush()` after archive reopen assertions; native Windows requalification remains required, and the original flush assertion is unchanged. See [retained failure and source checks](docs/evidence/relay-capacity-20261005/ipc-cancellation.json).

Explicit membership recovery, 2026-10-05: batch owner revocation now retires existing control records only for the selected leaves, in the same durable transaction. Survivor controls, ordinary message bytes and delivery acknowledgments remain intact; failed persistence restores the original controls. Already staged work stops unadmitted fragments only when its exact journal record was retired, preserving ordinary kick notices and admitted receipts. A causal regression reproduced the old 64-control backlog rejecting a fresh reusable enrollment after recovery. All 18 focused recovery and maintenance tests pass; [evidence](docs/evidence/relay-capacity-20261005/explicit-recovery-control-retirement.json) retains the causal failure. No live membership recovery is claimed.

Invitation responsiveness and pressure fixtures, 2026-10-05: creating a reusable invitation keeps channel preparation serialization and owner, policy, durable-store and 64-record checks, but no longer waits for an earlier text/presence delivery receipt. The regression holds a real first-hop reply unresolved and requires both durable creation and a full-ledger rejection to return within two seconds; admission and other command ordering are unchanged. Two restore/materialization pressure fixtures now saturate the configured scheduler data allowance instead of assuming the former 7 MiB allowance; all rejection, defer, counter and reclamation assertions remain. All six focused invitation, pressure, ordering and paired GChat controls passed; [retained receipts](docs/evidence/relay-capacity-20261005/explicit-recovery-control-retirement.json) preserve their exact source transitions. These source changes are not yet live.

Early lock validation, 2026-10-05: native CI now resolves every independent consumer lock before running the native suite. The separate mobile lock needed the same already-pinned signal dependency as the example consumer; all four tracked locks and all 16 Android/iOS client/relay, push and fixture graph combinations pass offline with `--locked`. No lock changes occur during these checks. This is dependency validation; native device, size and release qualification remain required. See [mobile lock evidence](docs/evidence/relay-capacity-20261005/mobile-lock-preflight.json).

Release portability repair, 2026-10-05: the existing outbound-only scheduler fix `9e57d2f` is reused at `09b6a0a`, and the isolated Rust consumer lock now includes the already-pinned Tokio signal dependency. The unchanged released 0.1.49 application compiles with `--locked` in IPC, embedded and network-client modes; current consumer graph checks pass and network-client still excludes relay hosting. Original Android/iOS/SDK failures are retained. Native platform qualification and SDK size measurements remain required. See [portability evidence](docs/evidence/relay-capacity-20261005/release-portability.json).

Capacity port integrated, 2026-10-05: deployed patch `5d61b75` is merged at `10a6f89`, with reviewed bounds and regression coverage at `fb8a8b5`. Default queue leases now allow 1024 cells / 16 MiB, subscription replay bookkeeping allows 4096 nonces per queue, legacy scheduler lanes allow 512 lanes / 1024 cells with 64 additional control slots, and the combined endpoint/transit scheduler budget is 64 MiB. Global byte/job bounds and shared GC/2 lease limits still apply; existing negotiated leases change only through normal provisioning or renewal. All 95 focused scheduler, queue, relay-service and GC/2 queue tests plus strict node Clippy pass. Existing wire/API contracts and the 64-member limit are unchanged. See [capacity integration evidence](docs/evidence/relay-capacity-20261005/deployed-capacity-port.json).

Live capacity, 2026-10-05: the operator reports all eight relays on the manual capacity hotfix, binary SHA-256 `a54a317de4068715512bcae2ff7512a49070c9f4421e00bb79d57019adbea21a`, with 2048 circuits and 4096 connections; the hub also has the patch. This live manual rollout remains separate from the pending managed release. Source-paired qualification, the 64-client 30-minute campaign, desktop publication and managed fleet delivery acceptance remain required. Earlier failed attempts below are retained evidence.

Automated relay qualification, 2026-10-05: the isolated fixture renews authenticated bootstrap introductions throughout setup and traffic while preserving relay identities and production lifetimes. `relay-preflight` checks two clients, a DS-sized file and relay restart before `relay-load` runs the unchanged 64-client gate. The source-bound builder accepts `--fetch` to populate dependencies only inside its retained source copy before its offline build. GChat release CI invokes the same builder and fixture automatically. Full load and live fleet acceptance remain required.

Retained channel setup coalesces an already-admitted exact ciphertext with maintenance. Invitation completion does not acknowledge delivery; the original outbox and authenticated receipt requirements still apply.

Relay load tooling: the 64-client `relay-load` campaign models the live operator fleet at 2048 circuits and 4096 connections per relay and verifies the forwarding pools before traffic. Capacity overrides are bounded by the node's existing limits. Desktop contribution budgets and the mandatory delivery, refusal, file, restart and duration thresholds stay unchanged.

Current release, 2026-10-03: SDK 0.1.98 is published with all 12 original desktop/mobile qualification archives. Its exact build inputs match qualified source 32072fe; original archive names and source labels are retained. The newer SDK 0.1.102 pointer remains available. All 17 infrastructure targets and four GChat desktop platforms are deployed or published. GChat mobile installed acceptance and SDK 1.0 remain incomplete; the 64-member limit, covered receipts and version-bound 20%/5% size policy are unchanged.

See the [immutable SDK index](https://gchat.boo/updates/sdk/f8ae216bf9016d59f17a4dad836806b5a31fbe3c4b57d35dba12d4f3f2f64852/index.json) and [current launch evidence](https://github.com/IggyGG/gchat/blob/main/docs/evidence/stabilization-20261001/launch-simplification.json). Routine releases follow an authoritative Forgejo main push automatically.

## Retained earlier checkpoints

The current release status above supersedes earlier pending matrix observations. Original outcomes and evidence remain below.

The shared native evidence policy now records the three existing explicit
64-member MLS/durable-client capacity tests under the mandatory stress.mls64
gate. Native package qualification continues to reject unknown or cross-project
exclusions; a missing capacity receipt still blocks release. All 22 policy
controls pass in both repositories. No application API or runtime changed.

The exact release SDK source 8f8fdb3 passes all four original base mobile jobs.
Three Apple combinations (client/base, relay/base and relay/push) independently
verify their provider digests, 562 source hashes and nine production libraries
each. Their native and linked size comparisons pass the approved 20% feature
allowance. Apple client/push and both Mac desktop SDK jobs remain pending.
SDK 1.0 remains unqualified and the post-1.0 5% limit is unchanged. See
`docs/evidence/stabilization-20261001/sdk-apple-8f8fdb3.json`.

The original protected Linux job for release 0.1.98 passes both full native
GChat/GComs CI commands on exact sources `52d28d7`/`8f8fdb3`. Its original provider
ZIP, both source bindings, derived Rust/npm inputs and all linked logs verify
through the unchanged qualification handler. GComs records 211 passing Python
checks, zero failed Rust checks and a successful dependency audit. The original
failed/split Linux attempts remain retained; this is a new full native pass.
Signed packaging and installed-network/fleet acceptance remain required.

The release's exact GComs revision `8f8fdb3` passes Linux/Windows SDK jobs and
all four Android role/push combinations. Independent verification retains all
six original provider ZIPs, 426 desktop source hashes per platform, 562 source
and 31 packaging hashes per Android result, 24 native libraries and the actual
16 KiB emulator/alignment evidence. All 20 desktop, 24 Android native and eight
linked APK size comparisons pass the approved 20% feature allowance. The Mac
desktop jobs remain pending. The Apple client/base job passes; its original
114,926,219-byte provider ZIP, 562 source hashes and nine production libraries
verify independently. Nine native and two linked application size comparisons
pass (maximum 11.215% growth), with matching toolchains. The remaining two
Apple push combinations are pending, so SDK 1.0 remains unqualified. See the native
policy receipt and retained `operations/desktop-8f8fdb3-verified-263.json`,
`operations/android-sdk-archives-verified-264.json` and
`operations/apple-sdk-archives-verified-277.json`.

Earlier SDK source `32072fe` also passes all four desktop jobs on Linux,
Windows, Intel Mac and Apple Silicon. Every original provider ZIP size/digest
and 426 source hashes per platform are independently verified. All 40 native
same-toolchain size comparisons remain below the approved 20% feature cap
(maximum 14.533%). Its Apple mobile jobs remain queued; no complete current-source
mobile matrix or SDK 1.0 qualification is claimed. Original failures and the
post-1.0 5% regression cap remain unchanged. See the native policy receipt and
retained `operations/desktop-32072fe-verified-225.json`.

Corrected SDK source `32072fe` now passes all four Android client/relay and
base/push emulator jobs. Full provider ZIPs, 562 source hashes and 31 packaging
hashes per result, 24 native libraries and eight linked APK size comparisons
are independently verified. The real emulator uses 16 KiB pages; alignment and
same-toolchain size checks pass the approved 20% allowance (native growth
10.07–13.59%). Apple jobs on this source remain queued, so these results do not
qualify its complete mobile matrices or SDK 1.0. Original failures are retained.
Evidence: `docs/evidence/stabilization-20261001/sdk-size-policy.json` and retained
`operations/android-sdk-archives-verified-190.json`.

Clean SDK source `1654677` now has four fully retained Apple role/push results.
Every provider ZIP size and digest, 562 reported source hashes per result and all
36 distributable native-library hashes match. The 36 same-toolchain native size
checks and eight linked application size checks pass the approved 20% feature
allowance (observed growth 8.07–11.50%). Original Android preflight failures and
overall failed mobile matrices remain unchanged; fixture static libraries were
not separately archived. All four Android role/push combinations on corrected source
`32072fe` now pass; their independent verification is recorded above. This does not qualify SDK 1.0, installed apps or the fleet.
See `docs/evidence/stabilization-20261001/sdk-size-policy.json` and retained
`operations/apple-sdk-archives-verified-175.json`.

Android SDK runs `37020911991` and `37021726565` fail before tool setup because
isolated `mobile_elf_test` cannot import `sdk_size_policy`. The test now sets its
own scripts import path; production size/security checks are unchanged. Its four
ELF controls and six size-policy controls pass independently, and full Python
passes 211 tests. L0 checks 979 paths and seven research hashes. Mobile CI now
triggers on this test's changes. The four Apple jobs in those runs succeed, but
their provider archives are independently retained and verified. Original
failed runs remain retained; corrected Android emulator qualification passes above.
No product runtime, API, limits or dependencies change in this repair. See the
[native policy receipt](docs/evidence/stabilization-20261001/sdk-size-policy.json).

The experimental `hosted-channels` profile now connects the ciphertext-only
service, durable MLS runtime, SDK/IPC and GChat. Clients enforce signed policy;
the service has no member decryption secrets. Recipient receipts stay on the
covered channel, and large channels can take longer to show delivery. An offline
newcomer sees “Topic pending” until an authorized topic writer returns.
Admission snapshot reads retain the prepared identity and pinned transcript
across up to four transport attempts, with 1/2/4-second backoff inside the same
30-second page deadline. Background routing owns recovery; admission writes and
authenticated policy refusals are not retried by this read path.

Source `1654677b3bac40977b7048ce0fe06c03fe6076e9` passes native run
`37020912213` on Linux, Windows, Intel Mac and Apple Silicon. All four backend
stages and 40 same-toolchain size comparisons pass under the approved 20% feature
allowance. Each source is clean; every one of the 426 reported file hashes on each
platform matches its committed Git blob. Full provider archives are verified and
retained. The 5% SDK 1.0 rule, original failed runs and baselines are unchanged;
see the [native policy receipt](docs/evidence/stabilization-20261001/sdk-size-policy.json).
The complete Linux workspace, Rustdoc and strict Clippy also pass on this source.
The original full CI run then fails at npm because the isolated lab has no upstream
DNS. Verified locked dependencies unblock JavaScript checks (eight tests), build,
vectors, generated files and minimal SDK/core graphs. A pinned Python 3.12 runner
with verified official registry caches now passes all 20 Rust/two npm archives,
three unchanged released-consumer feature graphs and dependency auditing in
126.30 seconds, with the original checkout unchanged. All stages are retained
separately; the original full CI failure is not relabelled as a single passing run.
These checks do not qualify full release activation or declare SDK 1.0. Mobile SDK combinations, installed acceptance, fleet activation
and a subsequent unattended release remain required.

Native Intel run `36881757477` still misses the original contact reopen deadline
with a four-block window: it receives 15 resumed blocks and makes 11 retries.
Contact files now request two blocks, leaving transport capacity for control and
receipts. General exchange remains at eight. The 30-second timer, four-ciphertext
ratchet window, 240-second phase bounds, public methods, keys and wire are unchanged.
A seven-second FIFO reproduces the four-request backlog and passes with two requests;
the earlier six-second simulation did not reproduce it and is retained separately.
The correction passes 31 file tests, strict file-transfer Clippy and the unchanged
real encrypted reopen, byte comparison and authenticated completion in 191.85
seconds total. Earlier eight/four-window evidence is preserved. Full committed
workspace and fresh four-platform native qualification remain open; see the
[request-window checkpoint](docs/evidence/stabilization-20261001/contact-request-window.json).

Full Windows worker `36863200902` retains a GC2 catalog test failure: its private
TLS origin dropped TCP without sending `close_notify`. The test origin now shuts
down its TLS stream normally after writing the complete response. Production TLS,
certificate/hostname refusals, remote DNS and bulk-body assertions are unchanged.
Both real legacy and GC2 HTTPS tests pass on Linux; fresh full Windows qualification
remains required. The original provider archive is verified and retained in the
[Windows checkpoint](docs/evidence/stabilization-20261001/windows-locked-storage-tests.json).

Verified native run `36881757477` passes Linux, Windows and Apple Silicon backend
checks and all ten size comparisons on each platform under the approved 20% policy.
Intel Mac fails contact reopen and its size phase is cancelled; the complete release
remains unqualified. The historical measurement reports also mark their source dirty
because backend evidence was written outside the ignored evidence directory. The
workflow now retains all output under `test-evidence/` and requires a clean checkout
before backend execution and after measurement, with the exact revision and a clean
measurement report. Earlier reports remain unchanged; fresh native qualification is
required. See the [native checkpoint](docs/evidence/stabilization-20261001/sdk-native-90d7eac.json).

Linux channel-service validation passes 18 tests. Its first strict Clippy
run finds an unused mutable fixture binding; that failure is retained and the
binding is corrected without changing assertions. Corrected Clippy and native
Windows full-workspace validation remain required.

Removed members independently authenticate the removal commit and its advertised
public snapshot from their prior tree and signed policy. They remain excluded
from new epoch secrets and persist an inactive channel across reopening.

IPC26 adds `sharing_v2` and `ModernFileSharing` for explicit hosted/contact file
scopes. A separate encrypted `.v2` cache preserves legacy files. Hosted offers
have their own durable consumer cursor; stable application IDs recover uncertain
publication responses. Piece transport is bulk, while completion acknowledgments
remain covered. Contacts must be explicitly registered again after reopening;
replacing that set revokes new transfer authority. File completion depends on
piece authentication, Merkle proofs and the whole-file SHA-256.

Reopening gives already durable direct application records an immediate transport
retry, using their original ciphertext, ID and expiry. This frees retained outbox
slots promptly after reconnecting; ordinary direct retry pacing remains. Neither
local restoration nor hop acceptance counts as an authenticated recipient receipt.
The complete Linux workspace and unchanged contact-file recovery pass; native
Linux and Windows backend checks pass on native workers. Mac qualification and
fresh version-bound SDK size qualification remain open in the
[reopen checkpoint](docs/evidence/stabilization-20261001/durable-reopen.json).

Hosted local mutations interrupt network waits instead of waiting behind replay
or file-piece I/O. The interrupted operation retries its retained immutable work;
this does not turn uncertain acceptance into recipient delivery. Shutdown also
cancels those waits. Read polling does not interrupt admission preparation.

File integration is undergoing end-to-end qualification. See the
[coverage ledger](docs/IRC_PARITY.md) for application, qualified 64-member and
release gates. An installed HTTPS service origin and explicit creation policy
are required; see the ledger for the deployed HEL service and exact live checks.

Owner-controlled [channel recovery](docs/MEMBERSHIP_RECOVERY.md) can revoke explicitly selected unavailable members without clearing message journals or claiming delivery. SDK/local IPC previews bind the exact membership state; ordinary authenticated ACK rules remain.

Retained file downloads query newly authenticated sources immediately and use a
bounded eight-send window; see [recovery validation](TESTPLAN.md#bounded-file-recovery-latency).
Installed platform checks remain separate from the controlled latency model.

## Immediate sending and randomized cover, 2026-09-25

Owner-approved policy: real traffic sends when transport capacity is available;
interactive cover opportunities are independently uniform 10–10,000 ms. A cover
record is skipped if that writer sent real data since the previous opportunity;
the next random interval still starts on schedule. GChat selects
new authenticated profile 46, preserving old profile meanings. This removes
intentional cover-slot waiting, not congestion or route setup. Timing/activity
privacy is reduced and unqualified. Extra bursts remain deferred. See
[traffic policy](docs/GC2_TRAFFIC_PROFILES.md) for costs, migration and limitations.
Current validation must prove immediate data/EOF, bounded cover and no catch-up
burst, cover suppression after sent data and idle resumption, old-profile compatibility, durable profile
selection, class isolation and real application delivery/recovery. R02/R03/R04
remain open until source-bound application measurements pass; prior slow/failed
runs remain failures. No deployed or installed behavior is claimed by source edits.

> Established GC/2 carriers now replace themselves on completion after at least
> 30 seconds of published readiness, without waiting for another maintenance tick.
> Failed/short-lived attempts retain retry pacing. This removes a reproduced
> owner delay; it does not yet qualify the application recovery latency target.
> See [background ownership](docs/GC2_DISCOVERY.md).

The current [reliability release requirements](docs/RELIABILITY_RELEASE.md)
define delivery/recovery deadlines, cluster validation and the subsequent graph
routing milestone. Historical qualification counts below retain their own scope.

## Protected-route error context

Recovery errors identify the failing middle number and handshake/admission stage,
or the terminal TLS handshake. These local diagnostics contain no relay addresses
or private capabilities and do not alter authentication or recovery policy.

## Local GC/2 admission diagnostics

With the existing optional metrics sink enabled, `gchat_queue_refused` records
only `operation` (`push` or `subscribe`) and a static refusal reason. It separates
queue fullness, aggregate storage and replay capacity while retaining the same
network replies and security limits. This is local troubleshooting data, not a
delivery receipt.

# GComs

Storage tests inspect locked log bytes through their owning handle, or after
closing and reopening the normal log. This respects Windows mandatory byte-range
locks while retaining integrity, quota and real failed-write checks. Production
locking is unchanged; fresh native Windows qualification is required.

The initial feature release permits up to 20% growth against the retained
same-toolchain size baselines, as approved on 2026-10-01. Native consumers, mobile
libraries and linked mobile applications share `scripts/sdk_size_policy.py`.
SDK version 1.0 (including prereleases) automatically restores the 5% regression
ceiling. Size reports retain the policy version, ceiling and source hash. This
does not waive recovery, compatibility, signing or installed release gates.

The [stable contract preparation](docs/STABLE_CONTRACTS.md) defines the supported
application facade and the remaining SDK 1.0 gates. Native CI compiles the exact
released 0.1.49 consumer in all three feature graphs. Contact file sends now retain
up to eight actual transport attempts within a shared 128-action queue; slow sends
and control interrupts cannot start a second attempt before completion. No new
dependency, IPC layout or hosted-member limit is introduced.
Legacy direct sessions keep encrypted data and control frames in one FIFO lane
so priority changes cannot skip a DH epoch during reopening. GC/2 credited
sessions preserve separate bulk and interactive traffic, including retained
retries. Keys and authenticated receipt requirements are unchanged.
Legacy sessions retain later durable application records as plaintext in the
encrypted outbox while four ciphertexts await recipient receipts. Each receipt
releases capacity without moving the original deadline or advancing a deferred
record's ratchet counter. GC/2 keeps its existing credited send window.

IPC count/write now share bounded zeroizing storage, and clients link the codecs
for their message directions. Hosted HTTP replies borrow their JSON envelopes,
including nested records, through one byte-slice decoder. Struct variants retain
object-only bodies while newtype structs retain their original sequence support;
wire bytes, public reply shapes, bounds and dependency versions remain unchanged.
Native CI retains failed backend/size logs and measures isolated consumers even
when backend tests fail. A separate source/attempt-bound backend log archive
uploads before the long size builds so failed recovery can be diagnosed promptly.
The current Linux IPC reduction still exceeds the
original 5% size ceiling; those historical failures remain unchanged under the
new approved policy. See the [codec checkpoint](docs/evidence/stabilization-20261001/sdk-codec-size.json).
The [JSON follow-up](docs/evidence/stabilization-20261001/sdk-http-json-size.json)
retains the original conformance failure, its corrected SDK/consumer checks and
the still-failed size ceiling. SDK 1.0 remains gated on native acceptance.

Rust applications start with the [`gcoms` application API](crates/application/README.md):
one dependency for messaging, channels and files. Select `network-client,files`
for a standalone client, `embedded,files,gc2-carrier` for a built-in relay, or
`ipc,files` for the smallest consumer of an existing local host.
RPC and automatic daemon launch are optional. GChat consumes the same API.

The [combined release-branch receipt](docs/evidence/sdk-release-integration-20260921/summary.json)
records the SDK merge with GChat-specific channel, persistence and platform fixes;
existing native artifact receipts retain their original source bindings.

The Linux workspace passes 910 tests (seven explicit ignores), and GChat passes
137 tests against the shared API. Native tests and size checks pass on Linux,
macOS ARM64/Intel and Windows x64 MSVC. [Measured consumer sizes](docs/RUST_INTEGRATIONS.md).
Android/iOS client and relay SDKs are qualified as an emulator/simulator preview.
See [mobile packages and measured app additions](mobile/README.md).

Mobile packages include separate optional app-operated push-hint adapters.
Physical-device, battery and live-provider qualification remains deferred;
[PLAN.md](PLAN.md) records the completed preview scope.
The `network-client,files` feature set adds a self-contained outbound protocol
client. Select `Backend::NetworkClient` when combining it with `embedded` in one
build. It hosts its inbox on remote relays and excludes local queue hosting,
forwarding and NAT mapping from a client-only build. Existing embedded and IPC
feature combinations retain their behavior. The SDK's `in-process` feature is
the shared adapter; `embedded` additionally enables relay hosting.

Background guard renewal uses bounded retry backoff when authenticated replies
have not yet supplied enough fresh independent relays for a five-hop route. A
fresh entry alone is not reported as a usable route; application requests do not
trigger additional entry dials.

Routed profile reopening retains expired inbox authority privately for background
recovery. Public addresses respect the sealed owner lifetime even when a renewed
lease carries a later timestamp; this never extends the original saved budget.
Recovery replaces the complete saved owner-role collections rather than appending
them to live state, so retained draining queues remain unique across reconnects.

When a protocol checkpoint fails, bounded local diagnostics distinguish encoding,
store failure and the first owner-lifecycle pause site. Uncertain persistence still
pauses the owner; these diagnostics do not authorize retry or confirm delivery.

An in-process application can opt into `durable_channel_inbox(true)` before
receiving starts. Channel and channel-private plaintext is sealed with the
receive checkpoint before acknowledgment; the archive owner explicitly consumes
each saved record. The inbox is bounded to 256 messages and 4 MiB and rejects new
receives at capacity without advancing their ratchets. File pieces retain their
separate journal. Shared/attached IPC clients cannot silently opt into ownership.
Enabled profiles use the `GCNSTM` checkpoint wrapper, which requires a compatible
reader and rollback binary; older binaries cannot read it.

**GComs** is a Rust communication protocol for secure connections, with typed
service APIs for addon and client integration. **GChat** is its separate reference
application, with a desktop UI, terminal UI and local service.

Development and release authority remains in the existing local Forgejo repository.
Public delivery uses [IggyGG/gcoms](https://github.com/IggyGG/gcoms) and
[IggyGG/gchat](https://github.com/IggyGG/gchat) as GitHub mirrors.
The first signed release is being prepared for Linux x86_64, Windows x86_64,
and macOS Apple Silicon/Intel. See [release preparation](docs/RELEASE.md).

## Start here

- [Typed services and addon integration](docs/TYPED_SERVICES.md): shared Rust traits,
  generated clients, TypeScript and Rust/WASM browsers, durable operation handles.
- [Private piece exchange](docs/PRIVATE_FILES.md): resumable, encrypted multi-source file transfer.
- [Isolated GChat capture calibration](docs/GCHAT_CLIENT_CAPTURE.md): actual-daemon
  observation and validity checks, separate from privacy and fleet qualification.
- [SDK](crates/sdk/README.md): embedded runtime or capability-scoped local IPC.
- [Runnable addon](examples/typed-addon/README.md): one contract and multiple clients.
- [Implemented protocol profile](SPEC.md), [architecture](docs/ARCHITECTURE.md),
  [compatibility](docs/COMPATIBILITY.md), [security](SECURITY.md).
- [Build and test](TESTING.md), [contribute](CONTRIBUTING.md), [license](LICENSE-MIT).
- [Repository ownership and source integration](docs/REPOSITORY_STRUCTURE.md),
  [relay research](docs/RELAY_RESEARCH.md), and the
  [GC/2 implementation ledger](docs/GC2_IMPLEMENTATION.md).

After package publication, a native client can depend on:

```toml
[dependencies]
gcoms-rpc = "0.1.0"
# For low-level messaging without embedding a node:
gcoms-sdk = { version = "0.1.0", default-features = false, features = ["ipc"] }
```

The same service trait generates Rust clients and dispatchers. Calls cross an
explicit transport: in-process dispatch, a local socket/named pipe, authenticated
GComs peers, or a browser HTTP gateway. A call can fail after its remote effect;
operations expose durable status and resume rather than silently repeating work.

## Repository layout

| Location | Responsibility |
| --- | --- |
| `crates/core`, `protocol` | Wire framing and portable codecs |
| `crypto`, `mls`, `transport`, `routing`, `gossip` | Encryption, groups and network transport |
| `node`, `network`, `network-client`, `catalog` | Runtime and operator-configured discovery |
| `sdk`, `file-transfer`, `private-fs` | Application integration and local storage boundaries |
| `rpc-contract`, `rpc-macros`, `rpc` | Typed service contracts, generation and runtime |
| `packages/gc-rpc`, `packages/rpc-codegen` | `@gcoms/rpc` runtime and build-time code generator |
| `conformance`, `sim`, `fuzz`, `examples` | Fixtures, models and development tools |

GComs does not embed a production network or a Ghost deployment. Hosts supply
network trust and local authority policy. Ghost fleet, recorder, machine-agent,
managed command and installer implementations remain in their private repositories.
Historical reserved wire identifiers do not imply those implementations are present.

## Build

Rust 1.98, Node 22 and npm 11 are the tested toolchain baseline. From this checkout:

```sh
cargo test --workspace --all-features -- --test-threads=1
npm ci --ignore-scripts
npm run generate
npm run check
npm test
npm run build
```

Native libraries and target prerequisites are described in TESTING.md. Development
adds `proc-macro-crate` for dependency-alias-aware macros, and `libfuzzer-sys` in the
isolated fuzz workspace. Ajv belongs only to `@gcoms/rpc-codegen`; the packaged
JavaScript runtime has no runtime npm dependencies.

Dual licensed under **MIT OR Apache-2.0**. Attribution and dependency terms are in
[NOTICE.md](NOTICE.md). Naming changes do not change GC/1 wire bytes.

The preview pins rustls >=0.23.45 and quick-xml >=0.41 for current advisory fixes,
uses rustls-pki-types' PEM parser, and disables unused postcard heapless defaults.
`deny.toml` records exact transitive-version exceptions and one reviewed build-time
unmaintained hax/libcrux macro dependency; it does not waive runtime vulnerabilities.

The application/runtime consolidation reuses existing dependencies; `sha2` derives
a purpose-specific host cache key. TLS fixture dependencies (`rcgen`, `rustls`,
`tokio-rustls`) are test-only in the runtime. No new third-party package is added.

All three Rust variants are tested natively on Linux x86_64, macOS arm64/x86_64
and Windows x64 MSVC.
Measured sizes and exact validation inputs are in [the Rust integration report](docs/RUST_INTEGRATIONS.md).

Inbox replacement completes after both new queues and peer updates are committed.
Peer notifications remain in the encrypted outbox and use the bounded direct
maintenance retry schedule; an unavailable peer cannot hold inbox installation
open. Relay acceptance still does not imply peer delivery.

## Five-relay carrier update — 2026-09-23

The shared experimental GC/2 application carrier requires an entry, three independent middles and a terminal inbox. It defers delivery when a complete route is unavailable. This is a client routing change; live fleet rollout and minimal payload integration are not yet qualified. Offline validation is recorded in test-evidence/gc2-five-relay-20260923/verification.json.


## Transfer recovery — 2026-09-23

Accepted downloads retain verified pieces and resume automatically after restart or temporary conversation membership loss. No requests or incoming pieces are accepted without current authorization. Explicit pauses/cancellations remain stopped. Reopening repairs the older automatic membership-pause marker; other errors keep their existing recovery behavior. Transport completions continue to arm retries while files are disabled or roster refresh fails.

Validation: 51 component tests passed, two existing qualification tests ignored, including an overnight restart at 80% and a send completion delivered while locked. Evidence: `test-evidence/file-resume-20260923/verification.json`. Android live recovery remains pending; these gates do not establish fleet end-to-end acceptance. No new dependencies.

Release file checks use a bounded 16 MiB interrupted transfer; the 1 GiB campaign runs separately. See [reliability requirements](docs/RELIABILITY_RELEASE.md).

Manual channel reconnect codes use separate MLS ciphertext from background
directory announcements. They are shared out of band, after the send state is
durably saved; automatic delivery cannot consume a code before it is pasted.

Protected subscription recovery fixtures use the current responsive profile 46
on Linux, both Mac architectures and Windows. The optional Rust integration
workflow diagnostic retains redacted local dispatch/count evidence; it does
not qualify installed artifacts or change production timing constants.

Hosted recovery prefetches at most 16MiB of encoded record data and checkpoints
short replay batches before every yield. Listings and bounded file-inbox reads
use the last healthy durable view during network I/O; signed presence still
expires locally at its original deadline. Consumer commits can interrupt network
waits after the application has saved its archive. This keeps recipient ACKs
behind durable consumption while reducing repeated full-state writes.

Hosted files use a two-piece upload/download window. Immutable authenticated bulk
requests release the mutable channel owner while in flight, so covered recovery
and chat can progress. The runtime bounds bulk concurrency at two and rechecks
current local membership and upload authority before exposing results. Shutdown
cancels pending bulk requests; retry uses the same piece identity and ciphertext.

Replay batches check a 75ms scheduling budget between records before saving and
yielding; a cryptographic operation or storage write may add to that interval.
The durable capacity driver reports checkpoint counts so write reduction can be
measured alongside responsiveness, without changing any receipt or policy check.

IPC26 preserves released IPC22 owner-recovery and IPC23 invitation tags, and appends
hosted channels and modern files. Their distinct capabilities require IPC26.
The conflicting, unpublished task IPC24/25 dialects are refused at negotiation;
existing supported legacy clients retain their versioned operations. Hosted
profile archives and service HTTP wires are unchanged by this IPC integration.

Hosted recovery now prefetches at most two immutable deferred records at once,
within the existing 16 MiB batch limit. It preserves sequence, scoped proofs,
hash/MLS validation and checkpoint-before-yield behavior. Live owners release
the temporary sealed session buffer after saving or restoring; the encrypted disk
archive and its compatibility rules are unchanged. Updated runtime and actual
application recovery qualification are in progress; previous timings retain their
source bindings.

Production relay operators can explicitly budget aggregate forwarding capacity
with `gcnode serve --relay-circuits N --relay-connections N`; ordinary defaults
and per-client/source security bounds remain unchanged. See the
[node operator capacity contract](crates/node/README.md#operator-relay-capacity).
This option requires workload qualification and is not itself a 500-user claim.

GC/2 forwarding now honors that circuit budget, reserves the last slot for
interactive traffic, and waits at most one second for admission. Desktop hosts
can contribute reachable relay capacity using the optional
`ApplicationBuilder::relay_sharing(RelaySharingConfig)` configuration. The
provider verifies membership, a service-key signature and the public listener
before advertising a short lease; DNS naming is independent. See
[relay contribution and qualification](docs/RELAY_SHARING.md).
