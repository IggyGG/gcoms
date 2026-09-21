# Minimal Rust integrations

The application facade has no default features. All variants expose messaging,
channels, invitations and bounded streaming file operations through one API.
GChat consumes the facade and retains its own network trust, archives and cache key.

| Integration | Features | Runtime |
| --- | --- | --- |
| Client of an existing local host | `ipc,files` | Caller-provided Tokio runtime |
| Outbound network client | `network-client,files` | Caller-provided Tokio runtime |
| Embedded protocol and relay | `embedded,files,gc2-carrier` | Caller-provided Tokio runtime |

No variant forces Tokio's multithread scheduler. Typed RPC and daemon launch
are separate opt-ins. IPC excludes the node, TLS, MLS, file engine and RPC from
its dependency graph. It requires a compatible IPC18/control2 host.

See the [application guide](../crates/application/README.md) and
[standalone consumer](../examples/rust-integration/README.md) for integration code.
The consumer explicitly selects GC/2 in both modes. Applications supply signed
network configuration and their own provisioned invitation.

## Native size measurements

These are runnable consumers with channel and file operations, built with Rust
1.98.0, full LTO, one codegen unit, stripped symbols and unwind support. The
independent consumer's recommended release profile uses `opt-level = "z"`.
Each architecture is built and executed separately.

| Target | Consumer | Level 3 | Level s | Level z |
| --- | --- | ---: | ---: | ---: |
| Linux x86_64 | IPC | 1,149,728 B | 920,776 B | 871,448 B |
| Linux x86_64 | Outbound client | 14,435,896 B | 9,239,112 B | 8,703,416 B |
| Linux x86_64 | Embedded relay | 15,556,032 B | 9,998,896 B | 9,364,704 B |
| macOS 15 arm64 | IPC | 1,066,496 B | 868,432 B | 737,872 B |
| macOS 15 arm64 | Outbound client | 11,875,376 B | 7,979,312 B | 6,252,272 B |
| macOS 15 arm64 | Embedded relay | 12,869,856 B | 8,709,488 B | 6,769,616 B |
| macOS 15 x86_64 | IPC | 1,095,112 B | 865,736 B | 800,440 B |
| macOS 15 x86_64 | Outbound client | 13,999,888 B | 8,847,400 B | 7,804,616 B |
| macOS 15 x86_64 | Embedded relay | 15,125,968 B | 9,629,224 B | 8,455,592 B |
| Windows x64 MSVC | IPC | 1,318,400 B | 1,032,192 B | 950,272 B |
| Windows x64 MSVC | Outbound client | 15,430,656 B | 10,521,088 B | 9,495,040 B |
| Windows x64 MSVC | Embedded relay | 17,001,984 B | 11,625,984 B | 10,443,776 B |

The IPC consumer requires a compatible local host. The separate `gcomsd` host
is measured at level s below; its bytes are excluded from the IPC consumer.

The [2026-09-21 CI run](https://github.com/IggyGG/gcoms/actions/runs/35548594688)
passed native tests, graph checks and all three optimization levels on all four
targets at commit `e75c72c`. Retained reports include loader dependencies,
source and executable hashes: [Linux](evidence/rust-integrations-20260921/linux-x86_64.json),
[macOS ARM64](evidence/rust-integrations-20260921/darwin-arm64.json),
[macOS Intel](evidence/rust-integrations-20260921/darwin-x86_64.json),
[Windows MSVC](evidence/rust-integrations-20260921/windows-amd64.json).
Every downloaded binary and source hash was independently verified. Compared
with the prior same-toolchain native record, the maximum existing-consumer
increase is 0.246%; all pass the 5% gate. Windows and outbound clients establish
new baselines. Later optional push additions are not included in these base sizes.

These are concrete consumer executables, not an additive size promise for every
host app. Mobile shared libraries, static archives, linked sample bundles and
installed sample deltas are recorded separately. Reproduce desktop measurements:

```sh
python3 scripts/check-rust-integrations.py --measure --baseline previous-summary.json
```

The [previous native record](../release/rust-integration-native-2026-09-20.json)
and [earlier local Linux record](../release/rust-integration-linux-2026-09-20.json)
retain historical measurements and qualification inputs.

## Validation

The earlier focused application, runtime, SDK and swarm suites passed 106 tests
on each of Linux x86_64, macOS 15 arm64 and macOS 15 x86_64. Linux has two explicit
ignores; each Mac target has one. Native macOS testing found that a peer closing
before its credentials were checked could stop the local listener. The listener
now rejects that connection and keeps accepting authenticated clients. The new
regression and bundled-host startup tests pass on every target.

The earlier full Linux workspace passed 900 tests, with seven explicitly ignored
cases, before the cache reconnect follow-up. After that cache fix, the affected
suites passed 105 tests, with two explicit ignores. The reconnect test covers
both backends: shutdown releases the cache lock, corruption is rejected, requests
stay closed after failure, and restoring the journal allows the same cache to reopen.

Before the listener follow-up, GChat passed 137 Rust tests and strict Clippy
against the paired sources; GComs also passed strict Clippy. Minimal feature
checks, browser RPC compilation, Rust documentation and generated-contract checks
passed. The package gate checked 19 Rust archives, the renamed Rust consumer,
both npm archives, GChat's generated contracts, 22 frontend tests and the Linux
native desktop consumer. Sources were unchanged during that qualification; no
registry publication was performed.

[Check results](../release/rust-integration-checks-2026-09-20.json) and
[archive/source hashes](../release/rust-integration-packages-2026-09-20.json)
retain those tested revisions. The isolated production bootstrap fixture also
passed on Linux before the cache follow-up; its host evidence remains under
`target/bootstrap-integration-evidence`.

Concurrent crypto work was merged after the native measurement run. The combined
source at `846b6ab` passed 157 Linux tests across the application, runtime,
SDK, swarm and crypto suites (two explicit ignores) and strict Clippy. The native measurements
and per-platform test records above remain pinned to `da12b45`.

These fixtures qualify native integration behavior. Operated-network
reachability and GChat desktop release packaging have separate qualification.
