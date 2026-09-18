# Validation

Current work stays in the existing private local Forgejo repositories. Public
publication is deferred by the owner. Run the build/test and local package-consumer
checks below. The private candidate gate is documented in [release evidence](docs/RELEASE_EVIDENCE.md).
Current release qualification targets Linux x86_64 and Windows x86_64 in a VM.
macOS is unavailable and excluded from this release effort; it is not qualified.

Run from the repository root with Rust 1.98, Node 22, npm 11 and Python 3.11+.
Native builds require the standard C/C++ toolchain used by aws-lc-rs. The public
library workspace does not require a Ghost checkout or service.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --locked -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo doc --workspace --all-features --no-deps --locked
cargo check -p gcoms-core --no-default-features
cargo check -p gcoms-sdk --no-default-features --features ipc
python3 scripts/check-vectors.py
python3 scripts/check-source.py
npm ci --ignore-scripts
npm run generate
npm run check
npm test
npm run build
python3 scripts/check-consumers.py
```

`check-consumers.py` packages publishable Rust crates together, builds an aliased
external consumer against extracted archives, and installs actual npm tarballs in
a temporary project. It keeps package metadata free of private sibling paths. Use
`--gchat /path/to/gchat` to qualify GChat against those same extracted Rust packages
and npm archives. The disposable GChat snapshot installs the local npm archives,
checks/tests/builds its frontend and generates dependency notices before the
standalone desktop Rust check. Original manifests and locks are preserved.
This staging check does not publish anything or require registry credentials.
Use `--consumer-target-dir` to reuse a Cargo build cache while retaining a fresh
archive/evidence directory for each `--release` check.

## Current-source GChat integration and relay research

Use `python3 scripts/check-gchat.py --gchat /path/to/gchat --offline` to test the
standalone application against this exact GComs worktree. `--action check` and
`--action clippy` provide build/lint variants. The runner snapshots both sources and uses
temporary Cargo source overrides, preserving the application's registry manifests
and lockfiles. Each result and its source hashes remain under
`target/gchat-source-check/reports`; the top-level summary records the latest run.

Run `python3 scripts/check-research-import.py` and
`python3 -m unittest discover -s scripts/tests -p '*_test.py'` for imported research
and its analyzers. The Rust harness gate is
`cargo test --offline --locked -p gcoms-node --example relay_performance`.
The [research guide](docs/RELAY_RESEARCH.md) distinguishes historical performance
results, quick harness checks and pending GC/2 application/privacy qualification.

## Browser and transport

`crates/rpc/tests/gc_peers.rs` uses two real disposable persistent peers, with
caller/instance binding and lost-reply recovery. Runtime tests cover conflicts,
revocation, retention and uncertain outcomes. IPC tests include capability denial.

For the runnable addon, install `wasm32-unknown-unknown`, matching wasm-bindgen-cli,
and a Playwright Chromium installation. Follow `examples/typed-addon/README.md` to
build the native server, WASM client and TypeScript client, then run the browser
harness. It uses local fixtures and an authenticated bound gateway.

`fuzz/` is the coverage-guided parser workspace; `crates/fuzz` is the earlier mutation
and measurement tooling. Run the documented short smoke gate, retain minimized
regressions, and record toolchain/time/coverage for longer campaigns. The simulator's
output is model evidence only. Ignored MLS stress tests need an explicit release-mode
run and are not included in a normal `cargo test` pass.

## Supply chain and native platforms

Run `cargo deny check` with a current advisory database and `npm audit --omit=dev`.
Review every advisory and license exception with its reason and affected version.
Network failures are incomplete checks. Archive contents and checked-in files must
pass the source inventory gate; automated scanning does not replace rights review.

Run the same native test/lint/build gates on each supported platform. Linux results
do not establish macOS/Windows behavior. Record results against the exact source
commit, including GChat when qualifying its application artifacts.

## Forgejo runners

`.forgejo/workflows/check.yml` uses a pinned checkout action and the two named
native runner labels. Provision disposable runners with Rust 1.98, Node 22, npm 11,
Python 3.11+, the native build dependencies and cargo-deny. Untrusted pull requests
receive no signing/registry secrets and must not execute on a developer workstation.
Public GChat CI starts after its GComs registry dependencies are available; local
pre-publication checks use the documented extracted-package staging.

If macOS support is revisited, bind-based multi-relay fixtures need distinct
loopback aliases and both Intel and ARM64 native qualification. No Mac access is
required for the current Linux/Windows release effort.

## Private Windows VM checks

The current manual test host is the isolated `gcoms-gchat-validation` x86_64 VM
(Windows 10 build 19045). Its restricted network exposes SSH only on the Linux
host's loopback interface. Windows GNU test executables are cross-built with Rust
1.98 on Linux, then executed inside Windows with their source fixtures and runtime
DLLs. Each harness retains its exit code and logs; timeouts and harnesses with no
Windows cases must be reported separately.

This checks Windows runtime behavior, including named pipes and file permissions.
It does not establish MSVC compilation, native compiler UI tests, desktop installer
behavior, signing or a configured Forgejo runner. Those require the corresponding
Windows build dependencies and separate acceptance evidence when release work
resumes. Public publication remains deferred.

The [2026-09-17 runtime record](release/native-validation-2026-09-17.json) contains
584 passing GComs Windows cases (five ignored) and 121 passing GChat Windows cases.
GComs' offline-member backlog harness exceeded the 15-minute VM budget; a separate
90-second diagnostic reached offline sending after successful admission and member
shutdown. That historical failure is superseded by the bounded-dial fix below. Unix-only harnesses with
zero Windows cases and the native compiler/installer gaps above are excluded from
these counts. Linux has 598 GComs and 142 GChat passing cases, with the final
transcript fix additionally retested across all core-library cases on both OSes.

## Current qualification follow-up

The offline-member backlog test now passes unchanged on Linux and in the Windows
GNU VM (16.24 seconds). GComs bounds repeated pre-TLS refused/unreachable dials with
a five-second, 64-route cooldown and cancels scheduler waits during shutdown.
TLS, HTTP and ambiguous application outcomes are not automatically retried by this
cache. GC/1, IPC v16 and retained-state formats stay unchanged.

The follow-up Linux GComs workspace run has 604 passing cases and five explicit
ignored cases; strict Clippy passes. The full Windows run is still under review,
including a concurrent-admission responsiveness failure. A passing diagnostic
harness does not substitute for native MSVC and installer qualification.

GChat's portable service, archive-reopen and standalone-daemon suites now run on
Windows too. Their readiness probes use IPC connections, since named pipes have
no socket-file entry. Unix PTY tests remain platform-specific.
