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
  contract and packaged consumer gates. IPC is 851 KiB; embedded is 8.93 MiB.

[Evidence and exact inputs](docs/RUST_INTEGRATIONS.md). Native macOS arm64/x86_64
qualification is the remaining step; the CI matrix is included in this change.
