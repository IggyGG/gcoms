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
its dependency graph. The current client requires a matching IPC20/control2 host. IPC20 retains the IPC19 layouts and appends opt-in verified file reuse with an explicit canonical-handle response. Ordinary file commits retain their existing behavior. Superseded import records use the existing non-serving cancelled state, so older cache readers cannot advertise discarded bytes as complete. Ambiguous plain IPC17 handshakes are refused before requests; update those clients and hosts together.

See the [application guide](../crates/application/README.md) and
[standalone consumer](../examples/rust-integration/README.md) for integration code.
The consumer explicitly selects GC/2 in every mode. Applications supply signed
network configuration and their own provisioned invitation.

## Responsive carrier source and artifact scope

The shared runtime's GC/2 production preset selects profile 46. Both outbound
and embedded Rust clients inherit immediate data plus random interactive cover
opportunities, skipping cover after data sent on that outgoing channel. The
Kotlin/Swift client and relay packages use the same runtime through the native
ABI. IPC consumers use their host's carrier; changing an IPC wrapper alone does
not update the host. Low-level users that explicitly select older profiles keep
those profiles. Previously built libraries, AARs, XCFrameworks, installed apps
and hosts must be rebuilt and qualified; the measurements below do not qualify
this later policy. See [traffic policy](GC2_TRAFFIC_PROFILES.md).

## Native size measurements

These are runnable consumers with channel and file operations, built with Rust
1.98.0, full LTO, one codegen unit, stripped symbols and unwind support.
Level z is smallest on every measured target. The integrating application's
root Cargo manifest controls release settings; use the standalone consumer's
profile as the size-oriented example.

| Target | Consumer | Level 3 | Level s | Level z |
| --- | --- | ---: | ---: | ---: |
| Linux x86_64 | IPC | 1,162,032 B | 926,664 B | 877,496 B |
| Linux x86_64 | Outbound client | 14,502,328 B | 9,247,944 B | 8,710,968 B |
| Linux x86_64 | Embedded relay | 15,618,496 B | 10,009,584 B | 9,374,048 B |
| macOS 15 arm64 | IPC | 1,066,528 B | 884,960 B | 754,400 B |
| macOS 15 arm64 | Outbound client | 11,941,616 B | 7,979,328 B | 6,252,336 B |
| macOS 15 arm64 | Embedded relay | 12,936,096 B | 8,726,016 B | 6,769,712 B |
| macOS 15 x86_64 | IPC | 1,111,528 B | 869,848 B | 804,544 B |
| macOS 15 x86_64 | Outbound client | 14,061,528 B | 8,855,616 B | 7,812,840 B |
| macOS 15 x86_64 | Embedded relay | 15,191,696 B | 9,641,536 B | 8,463,808 B |
| Windows x64 MSVC | IPC | 1,334,784 B | 1,038,848 B | 948,736 B |
| Windows x64 MSVC | Outbound client | 15,499,264 B | 10,536,960 B | 9,507,328 B |
| Windows x64 MSVC | Embedded relay | 17,074,688 B | 11,641,856 B | 10,458,112 B |

IPC requires a compatible local host. The separately built `gcomsd` host is
measured at level s below; these bytes are excluded from the IPC consumer.

| Target | Separate host |
| --- | ---: |
| Linux x86_64 | 10,258,968 B |
| macOS 15 arm64 | 8,958,048 B |
| macOS 15 x86_64 | 9,887,816 B |
| Windows x64 MSVC | 11,944,448 B |

The [2026-09-21 CI run](https://github.com/IggyGG/gcoms/actions/runs/35598613312)
passed native tests, graph checks and all three optimization levels on all four
targets at `b39199e`. Every downloaded executable and recorded source hash was
independently verified. Reports retain executable hashes, loader dependencies,
original-report hashes and growth comparisons:
[Linux](evidence/rust-integrations-mobile-20260921/linux-x86_64.json),
[macOS ARM64](evidence/rust-integrations-mobile-20260921/darwin-arm64.json),
[macOS Intel](evidence/rust-integrations-mobile-20260921/darwin-x86_64.json),
[Windows MSVC](evidence/rust-integrations-mobile-20260921/windows-amd64.json).

The largest increase against the committed same-toolchain `e75c72c` baselines
is 2.24%; all results pass the 5% gate. The CI gate continues to use those original
baselines. Optional mobile push distributions have separate measurements.

These executable sizes exclude loader dependencies. Windows binaries import
`VCRUNTIME140.dll`; the host application's runtime packaging is separate.
These are concrete consumers, not an additive size promise for an existing app.
Mobile libraries, linked bundles and installed app deltas are recorded in the
[mobile integration guide](../mobile/README.md).

Reproduce desktop measurements with:

```sh
python3 scripts/check-rust-integrations.py --measure --baseline previous-summary.json
```

## Validation

The current desktop matrix passes 109 native tests on Linux x86_64 and each Mac
architecture, and 104 on Windows x64 MSVC. Linux has two explicit ignores;
each other target has one. Tests cover outbound clients, embedded/IPC backends,
channel and file operations, private profile/cache reopen, bundled-host startup,
and rejection of disconnected or unauthenticated local clients.

The full Linux workspace at `b39199e` passes 910 tests with seven explicit ignores,
strict Clippy, formatting, documentation and minimal-feature checks. GChat
`f7a83ce` passes all 137 Rust tests and strict Clippy against that source pair,
including restored post-quantum identity on the default thread stack.

The package gate checks 19 Rust archives, a renamed external Rust consumer and
both npm archives. Generated RPC contracts, eight RPC tests, eight independent
wire fixtures, TypeScript builds, source inventory and dependency checks pass.
Sources stayed unchanged during the recorded package and GChat checks; no
registry publication was performed. [Combined check evidence](evidence/mobile-preview-20260921/combined-checks.json)
records the source pair and retained log/report hashes.

The [earlier native baselines](evidence/rust-integrations-20260921/) and
[previous integration qualification](../release/rust-integration-checks-2026-09-20.json)
retain historical results, including GChat frontend and desktop packaging checks.
Operated-network reachability and desktop release packaging are separate gates.
