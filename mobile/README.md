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

Android: API 26+, ARM64 devices and x86_64 emulators, NDK 27.3.13750724 with
16 KiB ELF alignment, AGP 8.11.1, Kotlin 2.2.21, Gradle 8.13 and Java 17+.
Kotlin coroutines 1.10.2 and Android-only JNI 0.21.1 are the wrapper dependencies.
AndroidX test dependencies are qualification-only.

Generate or publish Maven metadata for one role per Gradle invocation with
`-PgcomsPublishRole=client` (the default) or `-PgcomsPublishRole=relay`.
The selected SDK publication is `boo.gcoms:gcoms-client` or `gcoms-relay`, version
`0.1.0-preview`. Push SDK coordinates append `-push`; the separate `-fcm` adapter
depends on that matching SDK. Qualification retains the AAR, POM and Gradle
module metadata together. Applications must select exactly one role.

iOS: iOS 15+, ARM64 device and ARM64/x86_64 simulator static libraries packaged
as one XCFramework per role and a Swift package. Apple Foundation/Security are
system frameworks. The C ABI has no foreign allocation ownership or callback
thread requirements. See [native ownership and limits](native/README.md).

Optional push is a separate app-operated integration. It is a wake-up hint;
messages and files always remain on GComs. The Android FCM adapter is an optional
Gradle module selected with `-PgcomsPush=true` and Firebase Messaging 25.1.3;
DataStore 1.2.1 replaces Firebase's older transitive native library so both LOAD
and RELRO segments support 16 KiB pages. Release APK checks cover every native
payload, and push instrumentation exercises the native multiprocess counter.
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

Production builds emit one foreign library type per invocation: Android `cdylib`
or Apple `staticlib`. This enables LTO; the previous combined rlib/native build
disabled it despite the requested release profile. A local client probe reduces
the ARM64 library from 10,172,928 to 7,359,720 bytes and x86_64 from 11,974,984 to
8,796,864 bytes. Full production size qualification is being repeated. Apple
release samples enable symbol stripping and count only the active simulator
architecture. Archives retain linker-required external symbols.

The superseded Android size record below uses Rust inputs at `b39199e` and publication
metadata at `b3a21a9`. All four configurations pass instrumentation on the API 35
16 KiB emulator. Production AARs, POM/module dependencies, native hashes, APK ZIP
alignment and installed APK deltas are verified. `z` is the smallest of 3/s/z for
both architectures in every configuration. These pre-LTO sizes are decimal MB;
they are retained as historical evidence, not final release baselines.

| Android distribution | ARM64 native library | SDK AAR (two ABIs) | ARM64 sample APK addition | x86_64 installed APK addition |
| --- | ---: | ---: | ---: | ---: |
| Client | 10.17 | 9.75 | 10.22 | 12.02 |
| Relay | 10.82 | 10.38 | 10.87 | 12.84 |
| Client + push | 10.19 | 9.76 | 10.74 | 12.55 |
| Relay + push | 10.87 | 10.42 | 11.43 | 13.40 |

The push adapter AAR is another 25 KB; the sample APK columns include Firebase
and its transitive dependencies. App additions subtract the same sample without
GComs. Installed APK bytes exclude OS-generated code caches and application data;
ARM64 figures are build measurements. These results do not qualify physical
devices or live push delivery. [Exact inputs and measurements](../docs/evidence/mobile-preview-20260921/)
retain all three optimization levels and artifact hashes.

The mobile CI workflow exercises each role on an Android 16 KiB emulator and iOS
simulator. The client tests use a separate loopback relay; Android maps it through
`adb reverse`. Run `scripts/test-android.py` or `scripts/qualify-apple.py --test`
to own and clean up that fixture. CI installs pinned Android command-line tools
with a verified checksum; it does not depend on a preinstalled runner SDK.
The workflow's manual `push` input selects the additional push distribution.
Its `platform` and `role` inputs can qualify one distribution independently.
Client fixtures compile the consumer before minting a relay provisioning card,
so build time does not consume the grant's five-minute lifetime. Swift uses
`build-for-testing` followed by `test-without-building`; Android repackages the
fresh test asset after compilation.
Fixture packages use an unoptimized build for the emulator/simulator architecture;
the production pass builds every advertised architecture at 3/s/z.
Swift tests use an ad-hoc signed simulator host with
its own Keychain access group, covering both profile secrets and push state.
Device size builds remain unsigned; application signing belongs to the host app.
Fixture sizes
are excluded from release comparisons. They live in a separate output and are forbidden by the
Android release packaging gate. `scripts/qualify-android.py` builds release AARs
and per-ABI APKs, records the emulator's installed APK bytes and subtracts an
equivalent baseline sample. `scripts/qualify-apple.py` records installed simulator
bundle and unsigned ARM64 device bundle deltas. These are sample costs, not
physical-device filesystem allocation or store-compressed download estimates.
