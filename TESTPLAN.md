# Authenticated incomplete-referral retry

`renewed_guard_retries_incomplete_referrals_before_normal_discovery_period` serves
an authenticated own-only GCD2 reply, makes four independent fresh referrals
available afterward and never manually wakes the owner. Require discovery within
75 seconds, no retry before the existing 60-second backoff, exactly two requests,
unchanged guards and a complete five-hop candidate. Preserve the failing original
implementation. Run routing package tests and strict all-target/all-feature Clippy;
existing failed-dial, request-independent scheduling and cancellation tests remain.

# First checkpoint failure diagnostics

Keep the accepted-owner-renewal and failed-promotion rollback fixtures, including
failure after a sink sees the candidate bytes. New local logs distinguish encoding
from sink failures and identify the first branch that pauses the owner. No new
network request, retry, authority change or persistence success follows from
logging. Check the affected node failure cases and strict node Clippy on frozen
cluster inputs. Physical Android reproduction must retain the original generic
failure and the first underlying error separately.

# Inbox installation with a stalled peer

`installed_inbox_does_not_wait_for_peer_update_delivery` accepts both queue
creations over pinned TLS, checks the replacement and encrypted peer updates in
the committed snapshot, then holds a peer-update response open. Installation must
complete independently. The ordinary maintenance owner must retry the retained
wire when due; cancellation must retain it and never emit application delivery.
Run the node library and strict node all-target/all-feature Clippy in the cluster.
Keep the original failing implementation as the negative control. Physical
Android recovery, bidirectional ACKs, file resume and notifications remain separate.

# Concurrent manual admissions and delayed Welcome

Keep the eight-task fixture's channel/direct load, <500ms current-info bound and
successful task drain. Order manual admit plus member join as one fixture cycle;
require Active membership after every cycle so the final90s timeout cannot pass
silently. Bound preparation failure. Separately hold a Welcome until the next
admission reports MembershipPending, verify responsive commands, then join and
require bounded Active recovery with no retry or swallowed error.

Initial main `0c22dee` passed both cases and strict node Clippy. Final release
`7eec615` additionally includes the30s preparation guard; both cases, all seven
routing-profile cases, strict node Clippy/source/import/fmt/diff passed unchanged.
Its test bytes equal main `ff3025c`. Windows17 remains failed; its complete GChat
native pass is not relabeled for the successor. [Receipts](docs/evidence/windows-concurrency-fixture-20260921/summary.json).

# Windows persisted routing profile fixtures

Use the shared owner-only filesystem helper for pre-created temporary roots on
Windows and Unix. Keep startup/reopen/wrong-seed assertions, plus an existing
nonprivate-directory case that must fail without rewriting permissions or creating
routing material. Production permission checks must remain strict.

Both `77e756e` (unified branch) and `115f31b` (bounded Windows release input)
passed seven profile cases, four routing-cache cases, two private-fs cases and
strict all-target/all-feature node Clippy locally, with unchanged source snapshots.
Source/import checks, formatting and diff checks passed. Windows16's complete
GChat pass and original GComs failure remain separate; the next exact Windows
pair must produce fresh native and installer receipts.
[Evidence](docs/evidence/windows-routing-profile-20260921/summary.json).

# Client bootstrap API follow-up

Test the trusted client bundle API through the Node command loop: fresh carrier
seeds install, malformed/mixed-expired bundles leave the directory unchanged,
relay advertisement seeds are untouched, and non-GC/2 nodes refuse installation.
The deployed-relay probe requires explicit `--ignored` plus independently authorized
live provisioning; it is excluded from ordinary local/native CI.

Completed on `1decc33`: four local tests passed; the live probe was reported ignored
without execution. No-host client compilation, all-target/all-feature node Clippy,
formatting, source/provenance and diff checks passed on unchanged frozen sources.
[Exact receipt](docs/evidence/client-bootstrap-release-integration-20260921/summary.json).

# Combined SDK and release-branch boundary

Validate the exact combined source with application feature variants, the outbound
client/relay separation and mobile client/relay graphs, minimal core/SDK checks,
strict affected-package Clippy, Python/source/import checks and the current GChat
consumer. Preserve channel-management, IPC19 and Windows owner-only DACL repairs.
Existing native SDK size baselines and published GChat binaries retain their own
source bindings; a combined build is not covered by those older receipts. Live
push, physical-device testing and app-store distribution remain separate scopes.

Completed on `e3874a0` / GChat `2081526`: application/runtime/SDK 103 passed
(one namespace exclusion), node library 315 passed (one low-port exclusion), six
mobile ABI cases across four role/push variants, GChat 143 passed (two namespace
exclusions), 169 Python and nine gateway simulations. Minimal and independent
consumer checks, eight Android/iOS dependency graphs, both strict Clippy gates,
formatting, source and amended research-import checks passed.
[Exact sources, logs and scope](docs/evidence/sdk-release-integration-20260921/summary.json).

# Rust integration qualification

The native backend and size matrix passes on Windows x64 MSVC and Linux/macOS
at b39199e. All Android/iOS base/push preview distributions and final size gates
pass; [exact mobile evidence](docs/evidence/mobile-preview-lto-20260921/) records
the qualified revisions and toolchains. The private temporary-root helper
must preserve current-user ownership and remove inherited Windows grants.
Qualify outbound-only runtime behavior, mobile ABI cancellation/lifecycle,
Android emulator/iOS simulator consumers and simulated APNs/FCM providers.
Measure the base SDK and optional push adapter independently. These additions
do not establish physical-device or live-provider qualification.

- Run `cargo test -p gcoms-node --all-features --lib notification` for binding
  authorization, revisions, unbind/expiry/rotation/revocation, admission filtering,
  coalescing and bounded hint backpressure.
- Run `cargo test -p gcoms --all-features --test network_client` to exercise the
  remote administrative binding API alongside trusted messaging/channel/files.
- Run the Mobile SDK preview CI matrix for JNI/Swift execution, 16 KiB alignment,
  separate client/relay native graphs, 3/s/z measurements and sample app deltas.
  Verify both LOAD and GNU_RELRO alignment, compatible simulator selection, and
  the client through its separately hosted fixture relay. Development fixture
  sizes cannot establish production baselines.
  Build only `cdylib` (Android) or `staticlib` (Apple) per compiler invocation;
  emitting an rlib alongside them disables LTO. Record the selected crate type.
  Strip Apple archive debug/local symbols while preserving linker externals,
  and measure postprocessed release apps for only the active simulator CPU.
  Ad-hoc sign the disposable Swift simulator host with its own Keychain access
  group; require profile-secret and push-state reopen through fresh providers.
  Mint client fixture credentials after consumer compilation. Keep production
  grant expiry unchanged; slow Xcode/Gradle builds must not age the test grant.
  Generate SDK and optional FCM POM/module metadata with `gcomsPublishRole` set
  to the tested role and verify that the FCM dependency names that role's SDK.
  Check APK ZIP offsets as well as ELF alignment: each native entry must be
  uncompressed and aligned to 16 KiB so installed APK bytes include native code.
  Validate LOAD and RELRO boundaries for every packaged native dependency.
  Require the optional push adapter to exercise DataStore native counter writes
  and reads on the 16 KiB emulator; its runtime dependency is DataStore 1.2.1.
- Keep the public startup future below 16 KiB and run GChat's complete channel
  journey on the default thread stack, including restored post-quantum identity.
  Native desktop CI compares 3/s/z results with the committed platform baselines
  and rejects growth above 5% on the same Rust toolchain.

- Compile independent `ipc,files` and `embedded,files,gc2-carrier` consumers.
  Reject host/crypto/MLS/RPC dependencies in the IPC graph and forced Tokio
  multithread runtimes in either integration. Also check `network-client,files`
  without `relay-host`, SDK `embedded` or `quick-xml`. Exercise two outbound
  clients through remote inboxes, trusted delivery, channel joining, encrypted
  profile/cache reopen and refusal of local relay provisioning.
- Run SDK version/capability tests and facade backend tests, including encrypted
  cache reopen, bounded upload/export, forbidden scope and destination overwrite.
- Verify a disconnected local probe cannot stop the listener; macOS peer PID
  lookup can fail after disconnect, and only that connection must be rejected.
- Retain runtime durability/shutdown/GC2 bootstrap tests extracted from GChat.
  Verify file receive progress while outbound receipts are stalled.
- Run existing swarm corruption, quota, resumability and membership tests.
- Test GChat against this exact source pair, preserve archive/cache fixtures, run
  formatting, lint, package-consumer and generated-contract gates.
- Measure stripped consumer executables for opt-level 3/s/z with LTO, one codegen
  unit and unwind. Record the host separately from IPC consumer bytes.
- Execute integration tests and size checks natively on Linux x86_64 and macOS
  arm64/x86_64. Cross compilation alone is not native qualification.

Linux results are recorded in [the integration report](docs/RUST_INTEGRATIONS.md).
The full workspace passed 900 cases before the cache-only follow-up; the affected
suites passed 105 after it. GChat passed 137 Rust tests, 22 frontend tests,
generated contracts and the packaged desktop check. The final native follow-up
passed 106 focused tests per target on Linux x86_64 and macOS arm64/x86_64,
including the disconnected-peer regression. Size checks passed for all three
optimization levels; downloaded binary and source hashes were independently verified.

After the concurrent crypto merge, the combined application/runtime/SDK/swarm/crypto
suites passed 157 Linux tests (two explicit ignores) and strict Clippy. Native results remain bound
to their recorded source revision.
