# Two small Rust integrations

This is an independent consumer, including messaging, channel invitations and
streaming file import/export. It uses the caller's single-thread Tokio runtime.

```sh
cargo build --release --no-default-features --features ipc
cargo build --release --no-default-features --features embedded
```

For IPC, run an existing `gcomsd` host and set `GCOMS_ENDPOINT` to its private
control socket. For embedded production use, supply signed network settings in
`GCOMS_NETWORK`. `GCOMS_SECRET` supplies the private profile's unlock secret.
Run either executable without arguments for its supported operations.
`GCOMS_FIXTURE=1` explicitly selects disposable loopback fixtures in embedded mode.

The application dependency has no default features. IPC enables `ipc,files`;
embedded enables `embedded,files,gc2-carrier`. Neither enables RPC, daemon launch
or Tokio's multithread runtime. The optional daemon is built separately with
`cargo build -p gcoms --release --features daemon,files,gc2-carrier --bin gcomsd`.

Use `python3 scripts/check-rust-integrations.py --measure` from the repository
root for native byte counts and dependency checks. Release options live in this
consumer manifest: size optimization, full LTO, one codegen unit, stripped symbols
and unwind support. The script compares levels 3, s and z and reports the host
separately. Sizes include this runnable program and depend on architecture.
