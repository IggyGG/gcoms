# Android and iOS SDKs

Qualified Android emulator/iOS simulator preview (2026-09-21). Physical devices,
background battery use and live APNs/FCM qualification are outside the current
acceptance scope.

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
Gradle module selected with `-PgcomsPush=true` and Firebase Messaging 25.1.3.
DataStore 1.2.1 replaces Firebase's older transitive native library so both LOAD
and RELRO segments support 16 KiB pages. Release APK checks cover every native
payload, and push instrumentation exercises the native multiprocess counter.
See the [Android ELF requirements](https://developer.android.com/guide/practices/page-sizes#elf-alignment).
The base modules have no Firebase dependency. Apple push uses only system
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
or Apple `staticlib`, with full LTO, one codegen unit, unwind and stripping.
The manifest's default rlib is for Rust tests. Apple archives retain external
symbols needed by the host linker; release sample apps also strip symbols and
select the active simulator architecture.

The verified production measurements below use Rust 1.98.0. All architectures
were built at 3/s/z. Linked sample comparisons select z for Apple, and z also
minimizes Android native libraries. ARM64 static archives are slightly smaller
at s; their retained code does not predict the linked app's size. Figures are
decimal MB. Native archives include code that the app linker can remove;
the app-addition columns measure the resulting host application cost.

| Android distribution | ARM64 native library | SDK AAR (two ABIs) | ARM64 sample APK addition | x86_64 installed APK addition |
| --- | ---: | ---: | ---: | ---: |
| Client | 7.35 | 8.19 | 7.40 | 8.86 |
| Relay | 7.92 | 8.83 | 7.97 | 9.53 |
| Client + push | 7.36 | 8.20 | 7.93 | 9.39 |
| Relay + push | 7.96 | 8.87 | 8.52 | 10.08 |

| iOS distribution | ARM64 static archive | XCFramework (three architectures) | ARM64 sample app addition | Installed simulator app addition |
| --- | ---: | ---: | ---: | ---: |
| Client | 15.48 | 45.61 | 6.26 | 6.29 |
| Relay | 16.45 | 48.39 | 6.76 | 6.78 |
| Client + push | 15.50 | 45.66 | 6.32 | 6.36 |
| Relay + push | 16.51 | 48.57 | 6.85 | 6.87 |

The Android push adapter AAR adds about 25 KB; its sample APK measurements also
include Firebase and transitive dependencies. Base packages have no Firebase
dependency. The Apple push wrapper uses system frameworks.

App additions subtract the equivalent sample without GComs. Android installed
APK bytes include uncompressed, 16 KiB-aligned native libraries and exclude
OS-generated code caches and app data. ARM64 Android and iOS device figures
come from release builds; simulator figures are measured after installation.
These are sample costs, not physical-device filesystem allocation or
store-compressed download estimates.

[Exact sources, toolchains, all optimization levels and artifact hashes](../docs/evidence/mobile-preview-lto-20260921/)
include independently verified AAR/POM/module metadata, APK payloads and all
XCFramework slices. CI rejects native or sample-app size growth above 5% against
these same-toolchain baselines. An unmeasured native target/profile or changed
toolchain requires a new baseline. NDK 27.3.13750724 is explicitly selected in CI;
the recorded compiler previously came from the runner's NDK environment override.

The [pre-LTO evidence](../docs/evidence/mobile-preview-20260921/) is retained as
historical data and is excluded from the final mobile size gate.

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
