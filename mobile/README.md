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
messages and files always remain on GComs. Packaging and push qualification
instructions will be added with their corresponding implementation.
