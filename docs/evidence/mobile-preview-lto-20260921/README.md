# Mobile preview qualification, 2026-09-21

All eight Android/Apple client/relay distributions, with and without optional
push, pass the emulator/simulator preview scope. Physical devices, battery use
and live APNs/FCM delivery remain deferred. The [mobile guide](../../../mobile/README.md)
contains the supported targets, integration steps and measured size tables.

- [Final validation](validation.json) records each successful functional test job,
  exact source revisions, dependency graphs and retained log hashes.
- [Android final qualification](android-final-qualification.json) records the
  final DataStore 1.2.1 packaging, 16 KiB LOAD/RELRO/ZIP checks and native storage
  instrumentation. These local release APK reports supersede the earlier CI APKs.
- [Android publications](android-publications.json) verifies all four AAR/POM/module
  distributions, their APK payloads and installed size arithmetic.
- [Apple publications](apple-publications.json) verifies all XCFramework slices,
  Swift package sources and the recorded app-size arithmetic. Derived Apple app
  binaries are excluded from artifact upload; their sizes come from CI reports.
- [Apple linked profiles](apple-linked-profiles.json) compares the same retained
  archives at 3/s/z in equivalent host apps. `z` minimizes linked app additions
  in every distribution; `s` slightly reduces the ARM64 static archives.
- [Size-gate checks](size-gate-checks.json) verifies acceptance, the exact 5%
  boundary, rejection above it, changed toolchains and missing native baselines.
- [Python checks](python-checks.json) records all 162 script tests passing.

Files named `{android|apple}-{client|relay}-{base|push}-{native|app}.json` are the
16 CI baselines. Native reports retain all three optimization levels; distributed
packages use `z`. App reports measure additions over equivalent samples without
GComs. Android installed APK bytes exclude generated code caches and app data;
Apple device bundles are unsigned build measurements.

[Combined Rust/GChat checks](../mobile-preview-20260921/combined-checks.json) and
[desktop qualification](../rust-integrations-mobile-20260921/) cover the unchanged
core source pair. Earlier pre-LTO mobile reports remain historical evidence and
are excluded from the final size gate.
