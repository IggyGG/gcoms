# gcoms-sdk

GComs messaging through an embedded runtime or a capability-scoped local service.
Use `gcoms-rpc` when your addon needs generated application-specific methods.

```toml
gcoms-sdk = { version = "0.1.0", default-features = false, features = ["ipc"] }
```

This IPC-only feature set does not link the node, transport or MLS runtime.
Enable `embedded` to host a runtime, `client-persist` for encrypted client state,
or `descriptor-verification` to verify public channel descriptors without a node.
The default features include embedded, IPC and descriptor verification.

`EmbeddedClient` and `IpcClient` implement `GcClient`. Connect an IPC client with
an application label and the capabilities it needs. A server grants only its
configured subset; events additionally require their data-domain capability.
Unix sockets and Windows named pipes authenticate the local OS peer. A shared
user account is not a sandbox between mutually untrusted addons.

Generic component credentials and exact routes are available through the `machine`
module (historical API name). The host configures these grants locally; a client
cannot choose its identity or grant itself capabilities through request fields.
Reserved shell/file/bootstrap wire types do not supply a managed implementation.

IPC v17 adds credential-bound application profiles, runtime management and channel
invitations. Existing request tags and older server-side clients remain compatible.
The high-level `gcoms` facade owns profile startup and inbox consumption.

IPC uses bounded length-delimited frames with a 16 MiB ceiling. Application
bodies retain the smaller GC/1 limit. `ComponentLink` in `gcoms-rpc` preserves the
component grants when transporting typed service calls. Delivery receipts remain
distinct from an application operation's durable outcome.

MIT OR Apache-2.0. This is a developer preview; see the repository security policy.
