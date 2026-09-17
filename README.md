# GComs

**GComs** is a Rust communication protocol and developer platform for encrypted
messaging and typed application services. **GChat** is its separate reference
application, with a desktop UI, terminal UI and local service.

This is preparation for the **0.1.0 developer preview**. Source and package
publication are gated by [release readiness](docs/RELEASE.md). The public upstream
and GChat link will be recorded in [publication configuration](release/publication.json).
No production anonymity, availability or independent security review is claimed.

## Start here

- [Typed services and addon integration](docs/TYPED_SERVICES.md): shared Rust traits,
  generated clients, TypeScript and Rust/WASM browsers, durable operation handles.
- [SDK](crates/sdk/README.md): embedded runtime or capability-scoped local IPC.
- [Runnable addon](examples/typed-addon/README.md): one contract and multiple clients.
- [Implemented protocol profile](SPEC.md), [architecture](docs/ARCHITECTURE.md),
  [compatibility](docs/COMPATIBILITY.md), [security](SECURITY.md).
- [Build and test](TESTING.md), [contribute](CONTRIBUTING.md), [license](LICENSE-MIT).

After package publication, a native client can depend on:

```toml
[dependencies]
gcoms-rpc = "0.1.0"
# For low-level messaging without embedding a node:
gcoms-sdk = { version = "0.1.0", default-features = false, features = ["ipc"] }
```

The same service trait generates Rust clients and dispatchers. Calls cross an
explicit transport: in-process dispatch, a local socket/named pipe, authenticated
GComs peers, or a browser HTTP gateway. A call can fail after its remote effect;
operations expose durable status and resume rather than silently repeating work.

## Repository layout

| Location | Responsibility |
| --- | --- |
| `crates/core`, `protocol` | Wire framing and portable codecs |
| `crypto`, `mls`, `transport`, `routing`, `gossip` | Encryption, groups and network transport |
| `node`, `network`, `network-client`, `catalog` | Runtime and operator-configured discovery |
| `sdk`, `file-transfer`, `private-fs` | Application integration and local storage boundaries |
| `rpc-contract`, `rpc-macros`, `rpc` | Typed service contracts, generation and runtime |
| `packages/gc-rpc`, `packages/rpc-codegen` | `@gcoms/rpc` runtime and build-time code generator |
| `conformance`, `sim`, `fuzz`, `examples` | Fixtures, models and development tools |

GComs does not embed a production network or a Ghost deployment. Hosts supply
network trust and local authority policy. Ghost fleet, recorder, machine-agent,
managed command and installer implementations remain in their private repositories.
Historical reserved wire identifiers do not imply those implementations are present.

## Build

Rust 1.98, Node 22 and npm 11 are the tested toolchain baseline. From this checkout:

```sh
cargo test --workspace --all-features -- --test-threads=1
npm ci --ignore-scripts
npm run generate
npm run check
npm test
npm run build
```

Native libraries and target prerequisites are described in TESTING.md. Development
adds `proc-macro-crate` for dependency-alias-aware macros, and `libfuzzer-sys` in the
isolated fuzz workspace. Ajv belongs only to `@gcoms/rpc-codegen`; the packaged
JavaScript runtime has no runtime npm dependencies.

Dual licensed under **MIT OR Apache-2.0**. Attribution and dependency terms are in
[NOTICE.md](NOTICE.md). Naming changes do not change GC/1 wire bytes.

The preview pins rustls >=0.23.45 and quick-xml >=0.41 for current advisory fixes,
uses rustls-pki-types' PEM parser, and disables unused postcard heapless defaults.
`deny.toml` records exact transitive-version exceptions and one reviewed build-time
unmaintained hax/libcrux macro dependency; it does not waive runtime vulnerabilities.
