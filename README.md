The experimental `hosted-channels` profile now connects the ciphertext-only
service, durable MLS runtime, SDK/IPC and GChat. Clients enforce signed policy;
the service has no member decryption secrets. Recipient receipts stay on the
covered channel, and large channels can take longer to show delivery. An offline
newcomer sees “Topic pending” until an authorized topic writer returns.
Admission snapshot reads retain the prepared identity and pinned transcript
across up to four transport attempts, with 1/2/4-second backoff inside the same
30-second page deadline. Background routing owns recovery; admission writes and
authenticated policy refusals are not retried by this read path.

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
