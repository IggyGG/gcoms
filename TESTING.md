# Validation

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
`--gchat /path/to/gchat` to qualify GChat against those same extracted Rust packages.
This staging check does not publish anything or require registry credentials.

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
