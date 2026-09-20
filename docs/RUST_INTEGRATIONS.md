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

## Linux x86_64 measurements

These are runnable consumers with channel and file operations, built with Rust
1.98.0, full LTO, one codegen unit, stripped symbols and unwind support. The
independent consumer's recommended release profile uses `opt-level = "z"`.

| Consumer | Level 3 | Level s | Level z |
| --- | ---: | ---: | ---: |
| IPC | 1,147,992 B | 920,016 B | **871,424 B (851 KiB)** |
| Embedded relay | 15,600,504 B | 9,995,752 B | **9,366,168 B (8.93 MiB)** |

The separate `gcomsd` host is 10,255,792 bytes (9.78 MiB) at level s. Its size is
not included in the IPC consumer. These byte counts describe these executables;
other applications and architectures have different retained code and sizes.

The [measurement record](../release/rust-integration-linux-2026-09-20.json)
binds every executable to its hash, source hashes, toolchain and active graph.
The graphs contain 54 package names for IPC and 251 for embedded. Reproduce with:

```sh
python3 scripts/check-rust-integrations.py --measure
```

## Validation

The full Linux workspace passed 900 tests, with seven explicitly ignored cases,
before the cache reconnect follow-up. After that fix, the affected application,
runtime, SDK and swarm suites passed 105 tests, with two explicit ignores. The
new reconnect test covers both backends: shutdown releases the cache lock,
corruption is rejected, requests stay closed after failure, and restoring the
journal allows the same cache to reopen.

GChat passed 137 Rust tests and strict Clippy against the paired sources. Both
workspaces pass strict Clippy. Minimal feature checks, the browser RPC compile,
Rust documentation and generated-contract checks pass. The package gate checked
19 Rust archives, the renamed Rust consumer, both npm archives, GChat's generated
contracts, 22 frontend tests and the native desktop consumer. Original sources
were unchanged during that qualification; no registry publication was performed.

[Check results](../release/rust-integration-checks-2026-09-20.json) and
[archive/source hashes](../release/rust-integration-packages-2026-09-20.json)
retain the tested revisions. Later documentation changes do not change those
Rust inputs. The isolated production bootstrap fixture also passed on Linux
before the cache-only follow-up; its host evidence remains under
`target/bootstrap-integration-evidence`.

## Native macOS qualification

Native Apple Silicon and Intel results are pending the
[CI matrix](../.github/workflows/rust-integrations.yml). It runs the same focused
backend/SDK/swarm tests and size comparisons on Linux, macOS arm64 and macOS
x86_64. Linux execution does not qualify macOS. These fixtures validate native
integration behavior; they do not establish operated-network reachability.
