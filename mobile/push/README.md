# Optional app-operated push

Qualified preview using emulator/simulator tests and mock providers.
The base Rust, Kotlin and Swift SDKs have no Firebase/APNs
dependency. Each application operator runs this gateway behind their own HTTPS
proxy and supplies their own APNs key / Firebase service account. Provider
credentials and registration signing keys never ship in an app.

Current GComs owners obtain a one-use registration ticket from a live owned
inbox using `NodeHandle::request_push_registration`. No invitation, provider
provisioning, listener or new relay authority is required. The request has
`app_id`, a protected-storage random `installation_nonce`, `PushPlatform`, device
`token`, a durably incremented `revision`, and opt-in `visible`. The token is
hashed before relay control. Identity proof and the lease-admin HMAC bind the
request to its queue, epoch, service, app, installation nonce, token hash,
revision, purpose, visibility and original short expiry. The installation identifier is
a hex SHA-256 digest of the app, verified identity key and installation nonce.
The app identity key is never exported.

The relay issues version 2 tickets only for configured apps. The ticket binds
its configured HTTPS gateway origin, platform/token hash, installation, revision
and visibility; expiry is at most five minutes and cannot exceed the original
lease or temporary bound. A distinct `GCOMS-PUSH-RELAY-TICKET-v2` HMAC domain uses
the configured per-relay gateway key. The client receives `ticket`,
`gateway_origin`, `installation` and `expires`, then POSTs
`{ticket, platform, token, visible}` to that origin's `/v1/register`. Registration
is one-use; after an ambiguous result use a fresh durable revision. The gateway
rejects stale revisions across rotation, restart, unregister and invalid-token
removal. Exact transport retries at the relay return the original ticket without
extending its expiry. Admission is bounded to 16 attempts per owned lease per
minute and 80 retained ticket receipts, including identity-proof work.

The previous `gateway.issue_ticket` v1 interface remains available to an app's
authenticated server when a `registration_key` is configured; it remains silent
and cannot replace a v2 registration. There is no public ticket-mint endpoint.
`POST /v1/register` returns an opaque reference and management token. References
survive token rotation; management tokens rotate. `POST /v1/unregister` requires
the management token. Registrations expire after seven days. Store management
tokens in OS-protected storage, serialize registration/opt-out per installation,
and remove all relay bindings when opting out. If a registration response was
lost, use `request_push_revocation` with a new durable revision, the same
installation scope, `visible=false`, and a fixed 64-zero hex token sentinel.
POST that purpose-bound ticket and matching fields to `/v1/unregister`; this
removes the installation without needing the lost management token. It records
a revision tombstone before removal, rejecting delayed older registrations.
Register and unregister tickets are not interchangeable.

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

Wire management operation 10 has a bounded identity-signed registration request
inside the existing protected administrative envelope; it does not alter lease
or authority state. Wire management operation 9 is version 1 followed by queue ID, epoch, revision,
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

Configuration has an exact `public_origin` (for example `https://push.gchat.boo`),
`apps` keyed by app ID (including dotted IDs such as `boo.gchat.app`), optional
32-byte hex `registration_key` for legacy tickets, and `providers`: `apns` uses `key_id`, `team_id`,
`topic`, `private_key_file`, optional `sandbox`; `fcm` uses `project_id`
and `service_account_file`. `relays` is keyed by relay ID, with a distinct
32-byte hex `key` and an allowlist `apps`. Configuration and state must be private.

The `gcnode run --push-gateway-config /private/relay-push.json` hook requires a
`push-gateway` build and an owner-private regular file. Relay config contains
`url` ending `/v1/events`, `relay_id`, the per-relay `key` as 32 byte values, and
`apps` (allowed app IDs). An empty apps list preserves event-only compatibility
but disables ticket issuance. Server HMAC/provider credentials never enter apps.

`visible=false` preserves background-only APNs and normal-priority data-only FCM.
Opt-in visible APNs uses a fixed generic GChat activity alert with no sender,
channel, text or filename; FCM remains data-only but requests high priority. The
native Android app checks current permission/opt-in before showing its fixed
local alert, including token messages queued before opt-out. A provider alert
already submitted before revocation may still arrive; actual content always
requires authenticated GComs recovery. Live provider/device delivery is a
separate qualification from the deterministic local provider mocks.

Provider wire formats follow [Apple APNs requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)
and [FCM HTTP v1](https://firebase.google.com/docs/cloud-messaging/send/v1-api).
This preview passes simulated provider qualification; live credentials, device
delivery and battery qualification remain deferred. See the
[qualification evidence](../../docs/evidence/mobile-preview-lto-20260921/validation.json)
and [gateway checks](../../docs/evidence/mobile-preview-20260921/combined-checks.json).

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
