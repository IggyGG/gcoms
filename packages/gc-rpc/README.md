# @gcoms/rpc

Typed GComs service clients for browsers and JavaScript hosts. The package exports
ES modules and TypeScript declarations from `@gcoms/rpc` and `@gcoms/rpc/wire`.
It has no runtime npm dependencies. Validators are generated ahead of time.

```ts
import { RpcClient, BrowserHandles, httpTransport } from '@gcoms/rpc';
// Use service constants and client bindings generated from your Rust contract.
const rpc = new RpcClient(httpTransport('/rpc'), instance, service, version,
  new BrowserHandles(localStorage));
```

The gateway must authenticate the user and bind one configured destination.
Persist operation handles before sending, then resume after lost replies. Do not
repeat an operation with a new ID when its outcome is unknown. Browser storage
inherits the application's origin/XSS threat model; handles do not contain arguments.

Schema/client generation is a separate build-time package: `@gcoms/rpc-codegen`.
This is a developer preview licensed under MIT OR Apache-2.0.
