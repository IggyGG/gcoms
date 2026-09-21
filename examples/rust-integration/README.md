# Minimal Rust integrations

This is an independent consumer, including messaging, channel invitations and
streaming file import/export. It uses the caller's single-thread Tokio runtime.

```sh
cargo build --release --no-default-features --features ipc
cargo build --release --no-default-features --features network-client
cargo build --release --no-default-features --features embedded
```

For IPC, run an existing `gcomsd` host and set `GCOMS_ENDPOINT` to its private
control socket or Windows named pipe. For either standalone production build,
set `GCOMS_NETWORK` to a file containing signed network settings and supply your
provisioned `GCOMS_INVITATION`. `GCOMS_RELAY` can name a pinned relay-card file.
The outbound client keeps its inbox on remote relays and compiles out relay
hosting. `GCOMS_SECRET` supplies the private profile's unlock secret.
Run an executable without arguments for its supported operations. All modes
explicitly select GC/2; `GCOMS_FIXTURE=1` selects disposable loopback fixtures.
Use `run SECONDS` to keep a standalone profile online for background transfers.
The IPC host keeps the profile online after a client command exits.

The application dependency has no default features. IPC enables `ipc,files`;
the outbound client enables `network-client,files`, and
embedded enables `embedded,files,gc2-carrier`. None enables RPC, daemon launch
or Tokio's multithread runtime. The optional daemon is built separately with
`cargo build -p gcoms --release --features daemon,files,gc2-carrier --bin gcomsd`.

Use `python3 scripts/check-rust-integrations.py --measure` from the repository
root for native byte counts and dependency checks. Release options live in this
consumer manifest: size optimization, full LTO, one codegen unit, stripped symbols
and unwind support. The script compares levels 3, s and z and reports the host
separately. Sizes include this runnable program and depend on architecture.
