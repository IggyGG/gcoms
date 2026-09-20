# Minimal Rust application integrations

Implemented the two explicit Rust variants on the current GComs trunk:
`ipc,files` for an existing host, and `embedded,files,gc2-carrier` for an in-process
protocol and relay. GChat consumes the shared runtime and file APIs while keeping
its network configuration, archives and cache key.

Completed on 2026-09-20:

- Consolidated retained application/runtime work with current GC/2 and persistence.
- Made RPC and daemon launch optional, removed forced multithread scheduling, and
  selected the measured size profile while preserving unwind.
- Added streaming file operations, IPC18 capability/version checks, host-owned
  cache lifecycle, and regressions for reconnect, corruption and membership.
- Passed Linux workspace, focused follow-up, GChat, lint, documentation, generated
  contract and packaged consumer gates. Linux IPC is 851 KiB; embedded is 8.93 MiB.

[Evidence and exact inputs](docs/RUST_INTEGRATIONS.md). Native macOS arm64/x86_64
qualification is complete: 106 focused tests passed on each target, and the
CI matrix measured both consumers at opt-level 3/s/z. The macOS disconnected-peer
listener regression is fixed and covered on every target.

The subsequent concurrent crypto merge was preserved and validated with 157
combined Linux tests and strict Clippy; the native size record retains its exact
measured revision.
