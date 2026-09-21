# Optional app-operated push

Work in progress. The base Rust, Kotlin and Swift SDKs have no Firebase/APNs
dependency. Each application operator runs this gateway behind their own HTTPS
proxy and supplies their own APNs key / Firebase service account. Provider
credentials and registration signing keys never ship in an app.

The app's authenticated server issues a one-use, five-minute registration ticket
with `gateway.issue_ticket`. `POST /v1/register` exchanges it plus a device token
for an opaque reference and a management token. References survive token rotation;
management tokens rotate. `POST /v1/unregister` requires the management token.
Registrations expire after seven days and must be refreshed. Store the management
token in OS-protected storage and remove the relay binding when opting out.

Relays use distinct per-relay HMAC keys and an operator-configured gateway URL.
Events contain exactly `reference` and `activity:"message"`, authenticated with
`GCOMS-PUSH-EVENT-v1`, timestamp and a replay nonce. They carry no queue identity,
sender, channel, message, file name or cryptographic capability. Unknown/expired
references receive the same response. A relay is scoped to configured app IDs.

Native clients opt into `push`; relay hosts opt into `push-gateway`. The mobile
`bind_push` operation takes a 32-byte opaque reference, a monotonically increasing
`revision` persisted by the host application, and Unix-second `expires` at most
one day ahead. It binds current owned direct-message and channel inbox aliases through their existing pinned
administrative routes using the admin capability. Zero reference unbinds.
Retries may reuse the same revision and values; changed values require a new
revision. Multiple aliases are not one transaction: reconcile/retry on failure.
Rebind after reconnect/alias rotation and before suspension. Lease expiry and
capability rotation invalidate bindings; relay restart requires re-registration.
Older relays reject this optional operation.

Wire management operation 9 is version 1 followed by queue ID, epoch, revision,
expiry, 16-byte nonce, 32-byte reference and HMAC-SHA256. Integers are big endian;
the MAC covers `GC/PUSH-BIND/v1\0`, relay service ID and the preceding wire bytes.
Only newly authenticated GC/2 interactive enqueue admits a hint. Duplicate, cover,
bulk, unauthorized and rejected-full-queue operations do not. A bounded 256-entry
relay worker queue coalesces each inbox for 30 seconds and retries HTTPS three
times with ten-second request timeouts. Best-effort hints never block message
admission. The gateway URL is fixed by the relay operator, never by queue owners.

SQLite retains registrations, replay state and coalesced pending activity.
Delivery is coalesced to at most one attempt per reference every 30 seconds.
Retries back off up to one hour; invalid provider tokens are removed. Registration
rotation cannot be deleted by an old management token or an old in-flight failure.
The app reads actual data through GComs after waking. Push is best effort and
cannot guarantee background execution or delivery.

Run unit simulations with `python3 -m unittest discover -s mobile/push/gateway`.
Network providers require optional HTTPX with HTTP/2 and cryptography packages,
installed only on the gateway. Run `server.py --config /private/config.json
--state /private/push-state`; its listener binds loopback only. Terminate HTTPS
and impose request/rate limits at the app operator's reverse proxy.

Configuration has `apps` keyed by app ID, each with a 32-byte hex
`registration_key` and `providers`: `apns` uses `key_id`, `team_id`,
`topic`, `private_key_file`, optional `sandbox`; `fcm` uses `project_id`
and `service_account_file`. `relays` is keyed by relay ID, with a distinct
32-byte hex `key` and an allowlist `apps`. Configuration and state must be private.

Provider wire formats follow [Apple APNs requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)
and [FCM HTTP v1](https://firebase.google.com/docs/cloud-messaging/send/v1-api).
This preview will use simulated provider qualification; live credentials, device
delivery and battery qualification remain deferred.

Android: build native packages with `--push`, then pass `-PgcomsPush=true` and
`-PgcomsNativeRoot=/absolute/path/to/mobile-push/android` to Gradle. Link exactly
one `gcoms-client-fcm` or `gcoms-relay-fcm` artifact. Firebase auto-init defaults
off. The app supplies its own Firebase configuration, opts in, subclasses
`GComsFirebaseService`, and declares that concrete service for
`com.google.firebase.MESSAGING_EVENT`. Token callbacks enqueue a fresh
app-authenticated ticket exchange; hint callbacks enqueue bounded inbox
reconciliation using the OS's available execution window. Never hold a service
callback open for an unbounded network operation. `PushGateway` provides
registration/rotation, durable revision binding, and opt-out; use one instance
per profile with `KeystorePushStorage` or an equivalent app-owned secure store.

Apple: `--push` builds a separate GComsClientPush/GComsRelayPush Swift package
with product `GComsPush`. Supply `KeychainPushStorage` and the app's gateway
origin to `PushGateway`. Pass APNs device-token data and a fresh app ticket to
`register`; use `hintReference` to validate background notification hints.
The host app owns notification authorization, registration, signing entitlements,
`remote-notification` background mode, and completion callbacks. Reopen/reconcile
only while permitted and unlocked, and complete promptly when protected storage
is unavailable. The adapter does not claim always-on background networking.

After token registration call `bind` on the live GComs session. Bind again after
reopen or alias changes and before suspension. Opt-out first unregisters at the
gateway, then binds a zero reference. Keep the stored revision when unregistering;
deleting it can make delayed older operations relevant again. Concurrent gateway
instances for one profile are unsupported. A failed registration response may
have consumed its ticket; obtain a fresh ticket to reconcile it.
