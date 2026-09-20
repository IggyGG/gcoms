# Minimal Rust integrations

The application facade has no default features. Both variants expose messaging,
channels, invitations and bounded streaming file operations through one API.
GChat consumes the facade and retains its own network trust, archives and cache key.

| Integration | Features | Runtime |
| --- | --- | --- |
| Client of an existing local host | `ipc,files` | Caller-provided Tokio runtime |
| Embedded protocol and relay | `embedded,files,gc2-carrier` | Caller-provided Tokio runtime |

Neither variant forces Tokio's multithread scheduler. Typed RPC and daemon launch
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
| Linux x86_64 | IPC | 1,147,680 B | 919,944 B | 871,096 B |
| Linux x86_64 | Embedded relay | 15,547,456 B | 9,989,424 B | 9,360,448 B |
| macOS 15 arm64 | IPC | 1,066,496 B | 868,432 B | 737,872 B |
| macOS 15 arm64 | Embedded relay | 12,869,840 B | 8,709,472 B | 6,753,008 B |
| macOS 15 x86_64 | IPC | 1,095,112 B | 865,736 B | 800,432 B |
| macOS 15 x86_64 | Embedded relay | 15,117,760 B | 9,625,112 B | 8,443,272 B |

The IPC consumer requires a compatible local host. The separate `gcomsd` host
is measured at level s below; its bytes are excluded from the IPC consumer.

| Target | Separate host, level s |
| --- | ---: |
| Linux x86_64 | 10,255,672 B |
| macOS 15 arm64 | 8,958,048 B |
| macOS 15 x86_64 | 9,879,624 B |

These counts describe these executables; other applications retain different
code. The IPC graphs contain 54 package names on each target. Embedded has 251
on Linux and Intel macOS, and 250 on Apple Silicon macOS. RPC and forced
multithread scheduling are absent from both consumer graphs.

The [native record](../release/rust-integration-native-2026-09-20.json) retains test counts,
toolchains, binary hashes and the [CI run](https://github.com/IggyGG/gcoms/actions/runs/35537851752).
Every downloaded binary was checked against its recorded hash, and every Rust
source hash was checked against commit `da12b45`. Full per-platform
reports and executables are retained in that run's artifacts and the local
`target/native-integration-evidence` directory. Reproduce with:

```sh
python3 scripts/check-rust-integrations.py --measure
```

The earlier [local Linux record](../release/rust-integration-linux-2026-09-20.json)
retains the measurements before the macOS listener follow-up. Native source
inputs differ only in the listener correction and its added regression test.

## Validation

The final focused application, runtime, SDK and swarm suites passed 106 tests
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

These fixtures qualify native integration behavior. Operated-network
reachability and GChat desktop release packaging have separate qualification.
