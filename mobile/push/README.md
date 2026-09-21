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
