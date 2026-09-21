# GComs for Rust applications

Use `gcoms` as your application's communication dependency. It hosts a separate
identity and encrypted profile for each application, with the same API whether
the protocol runs in process or in a shared `gcomsd` service. GChat is a consumer;
it is not required by this library or daemon.

```toml
[dependencies]
gcoms = { version = "0.1.0", default-features = false, features = ["embedded", "files", "gc2-carrier"] }
tokio = { version = "1", features = ["macros", "rt"] }
```

```rust,no_run
# async fn example() -> Result<(), String> {
let app = gcoms::Application::builder("org.example.notes")
    .profile("/private/notes/protocol")
    .unlock_secret("obtain this from the user's unlock flow")
    .carrier_profile(gcoms::sdk::CarrierProfile::Gc2)
    .open().await?;
let status = app.status().await.map_err(|e| e.to_string())?;
app.close().await?;
# Ok(()) }
```

The parent directory must be private to the current user (0700 on Unix, a private
ACL on Windows). Missing directories are created privately. Existing broad
permissions are rejected. Supply an absolute path. Opening creates a profile only
when the file does not exist; `.create(true)` and `.create(false)` make that choice
explicit. Wrong secrets, corrupt profiles, and writer conflicts never create a
replacement identity. Keep each profile in its own directory; the retained
network-state format uses the profile's basename.

There are no default features. Choose one integration:

| Features | Ships in the application |
| --- | --- |
| `ipc,files` | Local client with messaging, channels and streaming files |
| `embedded,files,gc2-carrier` | In-process protocol node, relay and encrypted file cache |

Both reuse the caller's Tokio runtime; neither requires the multithread scheduler.
Add `rpc` for typed services and encrypted operation journals, `launch` for bundled
daemon startup, or `wasm` for browser RPC. Build the host with `daemon,files,gc2-carrier`.
The IPC dependency graph excludes the node, TLS, MLS, transfer engine and RPC.

The [standalone consumer](../../examples/rust-integration) exercises the public
API from an independent Cargo workspace. `scripts/check-rust-integrations.py`
checks dependency separation; `--measure` compares stripped opt-level 3/s/z
executables with LTO and one codegen unit. Keep `panic = "unwind"`: protocol
channel recovery uses unwind boundaries. The integrating application's root
Cargo manifest controls these profiles.

## Shared service

For the smallest client, enable `ipc,files` and select
`Backend::Attach { endpoint: "/private/runtime/gcoms.sock".into() }`.
The host must already be running.

With optional `launch`, a bundled host can be started automatically:

```rust,no_run
# async fn example() -> Result<(), String> {
let app = gcoms::Application::builder("org.example.notes")
    .profile("/private/notes/protocol")
    .unlock_secret("obtain this from the user's unlock flow")
    .backend(gcoms::Backend::Shared {
        executable: "/application/bundle/gcomsd".into(),
        endpoint: "/private/runtime/gcoms.sock".into(),
    })
    .open().await?;
app.close().await?;
# Ok(()) }
```

Build `gcomsd` from this package and ship that binary with the application.
The SDK coordinates concurrent startup, checks readiness, and attaches to an
existing compatible service. Nothing is downloaded or globally installed.
`Backend::Attach { endpoint }` requires an already running host. Windows uses the
SDK's private named-pipe mapping of the endpoint path. Unix socket paths must fit
the platform socket limit; use a short private runtime directory.

The control service is restricted to the current OS user. Each profile has an
immutable application registration and random local credential. Its encrypted
identity, routes, invitation, and inbox are independent of other profiles in the
same process. Application IDs organize profiles; they are not a sandbox against
other software running as the same OS user with access to those files.

`close()` joins application workers and detaches. Embedded close also stops the
owned protocol runtime. Shared close leaves that profile running so another UI
can attach. `stop_profile()` stops and saves the profile in either mode without
stopping other applications. Always await one of these on shutdown; dropping a
handle only schedules best-effort cleanup on a live Tokio runtime.

## Network setup

Applications supply signed network trust using `.network_config(json_bytes)`.
GChat supplies its own application-owned network configuration. First use needs a
provisioned invitation: pass `.invitation(code)` once, or later call
`app.messaging().import_network_invitation(code).await`. The invitation and
re-entry state are retained privately; do not put them in source, logs or command
arguments. There is no anonymous enrollment. A different signed network config
can be supplied with `.network_config(json_bytes)`.

Startup does not wait for Internet reachability. `status()` reports whether an
invitation is needed, inbox routing is recovering, or messaging is online. Relay
participation is attempted automatically; `Published` means a pinned relay has
verified the candidate listener. `Attempting` is not proof of reachability. Public
DNS remains a separate explicit opt-in through `configure_network_dns`.

`local_fixture()` is an explicit disposable loopback mode for tests. Production
never chooses it from the bind address. It skips network enrollment and relay
participation and must not be used to claim production privacy qualification.

## Typed services and messages

Enable the optional `rpc` feature for typed services.

```rust
#[gcoms::service(name = "notes.search", version = 1)]
pub trait Search {
    #[rpc(id = "find", kind = "query")]
    async fn find(&self, text: String) -> Result<Vec<String>, String>;
    #[rpc(id = "save", kind = "operation")]
    async fn save(&self, text: String) -> Result<String, String>;
}
```

The macro generates `SearchContract`, `SearchDispatcher`, and `SearchClient`.
Register a handler with `.service(Arc::new(SearchDispatcher(handler)), authorize)`
and register each authenticated peer with `.peer(peer)`. A caller adds
`.rpc_contract(SearchContract::descriptor())`, then constructs its typed client:

```rust,ignore
let client = SearchClient::new(app.rpc(&server_peer, "org.example.notes",
    &SearchContract::descriptor())?);
let results = client.find("meeting".into()).await?;
let prepared = client.prepare_save("new note".into())?;
let result = client.inner.start_and_wait(&prepared).await?;
```

The destination instance is the server's application ID. Exchange and authenticate
peer contact cards outside the protocol payload; `app.peer().await` exports the
current public binding. `app.trust_peer(peer).await` can add a verified binding after
startup or refresh that same identity's contact card after reconnection; existing
RPC clients keep their operation destinations and handles. Registration verifies the contact identity and binds
replies to that peer and service. Handlers require an explicit authorization
callback. The SDK owns encrypted operation journals and persistent client handles;
keep their sidecars with the profile when backing it up. Journals derive separate
keys from the unlock secret and a purpose-specific retained salt.

Operations retain the RPC contract's durable admission, replay and uncertain
outcome rules. A disconnect is not proof that an operation failed. Persist the
prepared handle and resume it instead of submitting a new operation ID.
Route recovery after a restart can outlast an individual RPC timeout; resume the
same handle to obtain the retained result. An interrupted effect is uncertain
unless the handler's application state can prove its outcome; the framework does
not promise exactly-once external side effects.

Ordinary messages use `app.messaging().submit_durable_opaque(...)`; their
`ApplicationMessage` arrives through `app.receive().await`. Call
`delivery.acknowledge().await` only after committing the application's effects.
Dropping a delivery without acknowledging permits redelivery. One bounded worker
multiplexes RPC and messages so they cannot steal each other's receipts. Only
registered peers are delivered, and one authenticated attachment can consume a
profile inbox. `.receive_messages(false)` creates an observer/sender attachment;
that attachment cannot register typed contracts. `worker_error()` exposes pump
failure for the host's reconnect/error UI.

## Compatibility and qualification

GC/1 and encrypted GCPRT1 profiles are unchanged. Existing lower-level crates stay
available for infrastructure consumers. New application, invitation and profile
management operations use the authenticated application-host IPC17 layout; files and network status require IPC18. The current client and host use IPC19, which preserves the IPC18 layout and appends channel topic/membership changes. Plain IPC17 connections are refused before requests because two released branches reused those tags with different meanings; update that client and service together. Authenticated profile IPC17, safe IPC10–16 operations and the IPC18 layout remain supported by the host.
GChat keeps its archives and can adapt a legacy combined store through the runtime
storage interface. Existing machine/central-owned profiles are refused by this
unscoped application API.

Run `cargo test -p gcoms --all-features --test backends -- --test-threads=1` for both backends,
mixed RPC/messages, invite redemption, restart/replay, credentials, consumer
leases and bundled daemon startup on Unix and Windows. The archived external consumer gate uses
only a renamed `gcoms` dependency, which also checks macro path resolution.
These are local fixtures; they do not establish live relay reachability. Windows
execution and the separate public-network probes are recorded in
[the qualification report](../../docs/APPLICATION_QUALIFICATION.md). Current Linux and macOS qualification is
tracked in the [native integration report](../../docs/RUST_INTEGRATIONS.md). Release versioning and registry publication
remain maintainer actions; pre-publication GChat checks use `scripts/check-gchat.py`.

## Channels and files

`app.messaging()` exposes channel creation, invitations, rosters and messaging.
`app.files()` uses the same encrypted piece engine in both backends. Call `list()`
to initialize/resume the host file worker and inspect progress. `send_path(scope,
path)` streams a local file; `accept`, `pause`, `resume`, `cancel`, and
`save_path(id, destination)` manage incoming files. Source and export paths stay
on the caller.
Lower-level `prepare`, `write_piece`, `commit`, and `read_piece` support custom
streams and resumable local upload. Each IPC piece is bounded at 256 KiB.

A scope contains a channel ID and either no participant IDs (whole channel) or
two sorted authenticated member IDs (private conversation). The host refreshes
the protocol roster before accepting work and sending queued pieces. Cache data
is encrypted and preserved across profile shutdown/reopen; explicit acceptance
precedes downloads. Export only publishes a complete verified file and never
replaces an existing destination. File requests require the distinct IPC18
`FileSharing` capability; they do not grant managed component file operations.

For migration, call `configure_file_cache(host_cache_path, key, config)` before
the first file request to retain an existing encrypted cache. This separate,
owner-authenticated startup operation configures a host-local cache in either
backend. GChat uses it to preserve its existing cache path and key. Reconnecting
a disabled cache reopens and validates its encrypted journals; a failed reopen
does not silently select another cache.

Control protocol version 2 carries explicit carrier configuration. Older hosts
are rejected with an incompatibility error. GC/2 requires explicit
`.carrier_profile(gcoms::sdk::CarrierProfile::Gc2)` on either backend and host
support for `gc2-carrier`; compiling the feature does not change a profile silently.
