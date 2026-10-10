# Pico install-chain probe (Android)

The M1 canary for the mobile delivery plan. It is deliberately **not** the
agent: it has no GComs SDK dependency and no persistence. Its only job is to
prove the Pico's blind stock-Android install chain reached code execution.

## What it proves

1. The Pico (USB HID or BLE HID, `os=android`, `mode=app`) can drive a
   stock, otherwise-empty Android phone through:
   launcher search -> **Chrome** -> APK URL -> download -> **unknown sources**
   -> package installer -> **Install** -> **Open**.
2. The installed APK actually runs, and reports the identity the Pico cannot
   fingerprint (model / manufacturer / Android version) plus a marker.

On launch it writes `filesDir/probe.txt` (durable, network-independent) and,
when launched with `--es report_url <https url>`, POSTs the same text to a
canary endpoint. `--es marker <text>` overrides the marker.

## Build (opt-in; not part of the SDK matrix)

```sh
cd gcoms/mobile/android
./gradlew -PgcomsProbe=true :probe:assembleRelease
# -> probe/build/outputs/apk/release/probe-release.apk
```

Requires the pinned Android SDK (compileSdk 36, NDK not needed for this
module), Java 17+, and the pinned Gradle wrapper. The release is signed with
the debug key because it is a disposable lab artifact.

## Wiring into the Pico flow

Serve the APK over HTTPS and build an Android app canary whose `launcher` is
`Chrome`, `pre_command` is `ctrl-l`, and `command` is the APK URL:

```sh
PYTHONPATH=tools python3 -c "import build_bt_canary as c; c.main([ \
  '--target','android','--mode','app','--app-name','Chrome', \
  '--app-pre-command','ctrl-l','--app-command','https://<host>/probe.apk', \
  '--out','out/probe-android'])" 
```

The full blind chain (download -> unknown sources -> installer) is a
multi-step interaction that the current single-command `arm_app` schedule does
not yet drive end to end; it needs a follow-up `android.install_apk` step
(tracked in `pico/test-evidence/mobile-20261005/WORKLOG.md`). This probe is the
execution target that step installs and opens.

## Status

Source scaffolded 2026-10-05. **Not built or hardware-qualified**: the Android
SDK/NDK and Gradle toolchain were not present in the implementation
environment. Build and native qualification are operator steps.