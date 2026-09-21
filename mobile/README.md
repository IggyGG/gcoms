# Android and iOS SDKs

Implementation in progress. These packages target an emulator/simulator-tested
preview. Physical devices, background battery use and live APNs/FCM qualification
are outside the current acceptance scope.

The same native API has two mutually exclusive distributions: **client** hosts no
relay; **relay** embeds relay services while the app is allowed to execute. Android
uses a small JNI bridge and Kotlin coroutines. iOS uses the C ABI and a Swift actor.
Do not link both roles into one app. Neither package requires the GChat UI, Tauri,
a daemon, typed RPC, Firebase or a multithread Tokio runtime.

Profiles belong in Android `Context.noBackupFilesDir` or iOS Application Support
with complete file protection and backup exclusion. The provided unlock providers
use Android Keystore / iOS Keychain; apps can replace them for biometric or recovery
policies. Callers must not log the configuration JSON, invitations or unlock data.
Managed-language strings cannot guarantee heap erasure; secrets are cleared where
mutable buffers are available and are not retained for resume.

Before background suspension, await `suspendProfile`; on foreground/network
availability, obtain a new unlock secret and `open` the same profile. Mobile OSs
do not guarantee an always-running relay. Keep remotely available inbox relays
for delivery while an app is suspended. Transient event streams are bounded;
reconcile channel/file snapshots and the durable inbox after reconnection.

The host application owns document picker / ContentResolver / security-scoped
streams. SDK file helpers transfer 256 KiB pieces and preserve the caller's stream
ownership. For an atomic export, write an app-private temporary destination,
finish successfully, then publish without replacing an existing document.

Android: API 26+, ARM64 devices and x86_64 emulators, NDK 28.2.13676358 with
16 KiB ELF alignment, AGP 8.11.1, Kotlin 2.2.21, Gradle 8.13 and Java 17+.
Kotlin coroutines 1.10.2 and Android-only JNI 0.21.1 are the wrapper dependencies.
AndroidX test dependencies are qualification-only.

iOS: iOS 15+, ARM64 device and ARM64/x86_64 simulator static libraries packaged
as one XCFramework per role and a Swift package. Apple Foundation/Security are
system frameworks. The C ABI has no foreign allocation ownership or callback
thread requirements. See [native ownership and limits](native/README.md).

Optional push is a separate app-operated integration. It is a wake-up hint;
messages and files always remain on GComs. The Android FCM adapter is an optional
Gradle module selected with `-PgcomsPush=true` and Firebase Messaging 25.1.3;
the base modules have no Firebase dependency. Apple push uses only system
Foundation/Security APIs. See [registration and ownership](push/README.md).

Build production native packages with `python3 scripts/build-mobile.py android`
or `python3 scripts/build-mobile.py apple`. Use `--roles client` or `--roles relay`
to select one distribution; `--profiles 3 s z` compares optimization levels.
`--push` selects a separate output and never changes the base distribution.
The summary retains exact source hashes, toolchain, active dependencies, sizes
and artifact hashes. `--baseline summary.json` enforces at most 5% growth under
the same toolchain. Android builds require ANDROID_HOME and the pinned NDK;
Apple builds require macOS/Xcode. Both require the pinned Rust 1.98 toolchain.

The mobile CI workflow exercises each role on an Android 16 KiB emulator and iOS
simulator. Fixture packages live in a separate output and are forbidden by the
Android release packaging gate. `scripts/qualify-android.py` builds release AARs
and per-ABI APKs, records the emulator's installed APK bytes and subtracts an
equivalent baseline sample. `scripts/qualify-apple.py` records installed simulator
bundle and unsigned ARM64 device bundle deltas. These are sample costs, not
physical-device filesystem allocation or store-compressed download estimates.
