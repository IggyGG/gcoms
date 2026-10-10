# GComs mobile agent (Android)

The M2 agent: the real mobile client, built on the **GComs SDK client role**
(`boo.gcoms:gcoms-client`). It is separate from the M1 install-chain probe
(`../probe/`), which has no SDK dependency.

## What it does

When provisioned with `filesDir/dropship-config.json`, the agent first runs
DS-MIN in its own process. DS-MIN downloads and verifies the authorized worker
before loading it as an Android shared library. Success requires the downloaded
worker's runtime-ready signal and the signed-payload/admission receipt. The APK
does not contain a prelinked worker substitute. `filesDir/d` retains the private
identity and download state between starts.

A private `deployment-request.json` may pin `release_id`, `apk_sha256` and
`worker_sha256`. Only a verified download and the current process's loaded worker
ready signal produce `deployment-ready.json`. The deployment runner independently
checks the installed APK digest and live PID; an old observation cannot pass.

Repeated foreground-service starts reuse the active installer. Mobile installer
starts reserve a private, durable recovery generation before network publication;
restarting keeps the identity seed and download files. A corrupt, unsafe or
exhausted generation record fails closed. Mint the private Dropship profile after
any hub restart, and check its routing bundle expiry before launching.

1. Loads the deployment config from `filesDir/agent-config.json`, or from the
   embedded `assets/agent-config.json` when the former is absent. The config
   (never committed) holds the `application` name, optional signed-network
   `relay`, and the installation `invitation` link.
2. Opens the client profile using `KeystoreUnlockProvider` (Android Keystore +
   `noBackupFilesDir`).
3. Enrolls with the installation invitation when present.
4. Polls the durable inbox over GC/2 and writes `filesDir/agent-inbox.json`.
5. Runs as a foreground `dataSync` service and re-arms on `BOOT_COMPLETED`.

Fails closed when `agent-config.json` is missing.

## Build (opt-in; not part of the SDK matrix)

```sh
cd gcoms/mobile/android
# Optional: embed a private deployment config (kept out of git).
./gradlew -PgcomsAgent=true -PgcomsAgentConfig=/abs/private/agent-config.json \
    :agent:assembleClientRelease
# -> agent/build/outputs/apk/client/release/agent-client-release.apk
```

For the DS-MIN path, build both Dropship Android archives and the actual client
SDK libraries first, then reuse their declared outputs:

```sh
./gradlew --offline -PgcomsAgent=true \
    -PdsminimalLibDir=/abs/dropship/build \
    -PgcomsNativeRoot=/abs/native/android :agent:assembleClientRelease
adb install -r agent/build/outputs/apk/client/release/agent-client-release.apk
```

Keep `dropship-config.json` private in the app's files directory. Cached APK
rebuilds take seconds; source or SDK changes may require rebuilding their inputs.
The 2026-10-08 deployment uses the lab signing certificate and the attached
emulator. Its [receipt](../../../docs/evidence/android-deploy-20261008/summary.json)
distinguishes installation/startup from full worker download and readiness.

The `:sdk` client AAR must exist first:
`../scripts/build-mobile.py android --roles client` then
`./gradlew -PgcomsPublishRole=client :sdk:assembleClientRelease`.

For the DS-MIN worker path, build Dropship's `build/build-android.sh both` first,
then supply `-PdsminimalLibDir=/abs/dropship/build`. Supply
`-PgcomsNativeRoot=/abs/sdk-output/android` when the SDK native output is outside
the default directory. The release check requires actual client-role native
libraries and their generated `client/build.json`; fixture libraries are rejected.
This lab agent's release variant uses its existing debug signing certificate.

## Status

Source scaffolded and compiled 2026-10-05 against the built SDK client AAR.
Enrollment and receive are **not** native-qualified: that needs the private
signed network config + invitation and a physical phone. Target parity is
"enroll + receive" with the desktop DS-MIN client.

## Relationship to the pico flow

The Pico installs this APK with the blind stock-Android chain (see
`pico/docs/BT-MOBILE.md` / `BT-MOBILE-RUNBOOK.md`) and opens it. The private
config is delivered out of band (build-time asset or a one-time provision), not
typed by the Pico.
