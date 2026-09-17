# Typed services for addons and clients

This integration style is **typed RPC**, sometimes presented as server functions
or a shared client/server API. Rust checks shared types and generated method calls;
it cannot make remote latency, authorization or uncertain outcomes disappear.

Define a small shared crate containing an owned, serializable service contract:

```rust
#[gcoms_rpc::service(name = "example.greeting", version = 1)]
pub trait Greeting {
    #[rpc(id = "greet", kind = "query")]
    async fn greet(&self, name: String) -> Result<String, String>;

    #[rpc(id = "uppercase", kind = "operation")]
    async fn uppercase(&self, text: String) -> Result<String, String>;
}
```

The macro generates `GreetingClient`, `GreetingDispatcher`, argument types and
service metadata. Implement the trait on the backend and register the dispatcher
with an explicit authorization policy. Dependency aliases are supported, including
`comms = { package = "gcoms-rpc", version = "0.1.0" }`.

## Select a transport

| Client / host | API |
| --- | --- |
| Rust in one process | `EmbeddedTransport` with an authenticated `Caller` |
| Native addon to local service | `local::LocalTransport`; private Unix socket or Windows named pipe |
| Remote GComs application | `gc::GcTransport` / SDK application messages |
| Scoped component | `gc::ComponentLink` and independently granted routes |
| Rust/WASM frontend | `browser` module; disable defaults, enable `wasm` |
| TypeScript browser | `@gcoms/rpc`, with bindings from `@gcoms/rpc-codegen` |

See the [working addon](../examples/typed-addon/README.md) and
`crates/rpc/tests/gc_peers.rs` for complete host/client setups.

## Queries and operations

A query is a read. An operation may change durable state. Prepare an operation once,
persist its opaque handle before transmission, and retain it until the outcome is
resolved. Reconnect using the same handle and destination. Do not create a new ID
because an HTTP response, socket or peer connection was lost.

The server journal scopes IDs to caller, instance, service, version and method.
An ID reused with different arguments conflicts. Status and resume are authorized
again; a stored result is not permission to bypass revocation. The encrypted file
journal is enabled by `file-store`; its key must come from host secret management.
Requests are validated before hashing. Request arguments are not stored in handles.

`outcome_unknown` means the effect may have happened but the result cannot be
established. It requires service-specific reconciliation or a user decision. This
API does not promise exactly-once execution across arbitrary external side effects.
Cancellation and deadlines likewise do not prove a remote operation was undone.

## Contract rules

Use owned, serializable types with JSON Schema and TypeScript representations.
Methods have explicit stable IDs, a query/operation kind and an explicit service
version. Unsupported borrowing, ambiguous method names, duplicate IDs and unrestricted
integer shapes fail macro validation. Use canonical decimal-string types for wide
integers that JavaScript cannot represent exactly.

The local RPC frame ceiling is 16 MiB. GComs message payloads have a smaller limit;
framing consumes part of it. Query the transport limit and use the file-transfer
protocol for large data. Raising an HTTP limit cannot raise the peer message limit.

## GChat as the example

GChat's `gchat-api` crate defines `ChatService` and the UI schema. Its local host
owns the protocol identity, encrypted chat archive and RPC operation journal.
GUI and terminal clients attach to a selected instance. The instance ID and boot
identity prevent a stale UI attachment from silently switching to another profile.

The browser frontend passes through a bound gateway; the Tauri frontend uses its
native bridge. App-specific commands remain in GChat. New addons should define
their own namespaced service contract rather than extending chat's command parser.
