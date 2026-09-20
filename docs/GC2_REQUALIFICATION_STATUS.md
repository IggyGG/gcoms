# GC/2 requalification status — 2026-09-20

This records completed checks and remaining scope. It does not authorize or
claim a production rollout, privacy qualification, or a signed installer release.
The physical mobile checks remain deferred by the owner.

## Completed source integration checks

GComs `e7a6c09d3439003b1bdd1b52d87998186bdba933` and GChat
`c36be8510974f62f170f064c28034a161d2f5507` passed their complete Linux CI
entrypoints. GChat ran against an isolated, verified copy of that GComs source.
The source pair stayed unchanged during qualification.

- GComs: 832 Rust tests passed, six explicitly ignored; 112 Python checks passed.
  Rustdoc, strict Clippy, generated contracts, independent vectors, minimal
  feature builds, dependency policy, seventeen Rust archives, and both npm
  archives and their isolated consumers passed.
- GChat: 151 Rust tests passed with no skips; 44 Python checks and 17 UI tests
  passed. Generated contracts, strict Clippy, both dependency policies, desktop
  checking and the Linux release application build passed. The application
  build was not a signed installer or an installation/upgrade journey.
- The cold invitation regression redeemed a real remote invitation, transferred
  authenticated file traffic and repeated delivery after subscription renewal.
- The separate optimized 64-member PQ MLS test passed. Its largest observed
  commit was 84,304 bytes and welcome was 97,251 bytes.
- The separate optimized 1 GiB cache import/reopen/export test passed with exact
  byte verification. It took 223.35 seconds on the shared local worker. This
  measures local durable storage, not relay throughput. A redundant debug run
  was explicitly stopped after the optimized pass; its interruption is retained.

The logs are retained under each checkout's `target/gc2-requalification/`.
GChat's paired input receipt is under
`target/paired-ci/f1a547c18fc14ec5ba8a7cca06c127e5/provenance/`.
Earlier failures remain available, including the incomplete generated API
export that the full GChat gate caught before the successful run.

## Release tooling corrections

Native Windows 10 checks verified a PE signed by the pinned Gh0st certificate.
The original verifier could not add current-user root trust over headless SSH.
The replacement uses Windows signature/digest verification and exclusive
process-local certificate trust. Native regressions accepted a valid signature,
rejected modified bytes, unsigned input, the wrong pin and an expired signer,
and verified key cleanup and unchanged persistent trust stores. This is not
Windows 11/MSVC or installer acceptance. See GChat's `docs/PREVIEW_SIGNING.md`.

Follow-up release tooling requires the separate 1 GiB stress result instead of
silently accepting its normal-CI exclusion. Windows commands select `npm.cmd`
and scope PowerShell execution policy to the verifier process. Installer builds
must match the dependency locks, protocol graph and npm archives exercised by
successful paired native CI. Uploaded provenance retains the actual inputs.
Independent preparations of the passing source pair produced the same effective
dependency identity. The added release-tooling regressions passed; the full
native results above apply to the explicitly named commits.

## Remaining release scope

Canary 14 stopped before offering a file when its monitor detected a production relay
process change. All eight hosts removed their test namespaces, interfaces,
rules and mounted test volumes; the production-stability check failed for one
host. Its production service was subsequently observed active after an orderly
stop/start with a changed binary hash. This session made no fleet changes.
That run does not qualify transfer capacity or receiver reopen behavior.

The production changes were subsequently attributed by direct acknowledgment to
OpenCode session `ses_f657247f6ffe3oDxEHezkGyr1X`. It confirmed r4-only deployments
at 02:30:25 CEST (`dfaf5e620e3920b4…`) and 02:46:05 CEST
(`acd8ced269996ab7…`) on September 20. The latter running hash and service start
were also observed read-only. The owner reports original Coms `e2e858a` plus
uncommitted lease-promotion, subscription-diagnostic and logging changes. That
binary is outside the qualified separated-source pair above. The owner committed
to no further production changes until explicit coordination. Deployment end and
traffic cessation are separate. The owner subsequently confirmed its final mint
at approximately 03:16:02 CEST, payload traffic ending at 03:16:30, and residual
listener/bridge lease replays and reconnects stopping at **03:24:03 CEST**. It
holds both production changes and relay-impacting test traffic until fleet-files
explicitly coordinates a new window. This is the owner's activity acknowledgment;
each isolated run still needs a fresh observed production baseline and its
abort-on-change monitor. The exact attribution and quiet-window messages are
retained under
`target/gc2-requalification/rollout-quiet-window-acknowledgment.json`.

The other session subsequently completed canary 15 with its frozen GComs
`628ec44` / GChat `36a96ae` binaries and controller `5d8846e`. A 64 KiB file
verified in 5.510 seconds after acceptance; receiver restart preserved identity
and a second export hash. All eight cleanup checks passed. These are small-file
and receiver-reopen observations, not sustained capacity or qualification of the
newer merged release source. See [the retained fleet results](FLEET_FILES_RESULTS.md).

Coordination found conflicting descriptions of privacy acceptance. The accepted
file-profile gate remains upper 95% separability at most 0.55 for idle/chat and
matched bulk/mixed, including both window traffic and connection observations.
The file classifier now returns failure for an exceeded component bound while
retaining its valid measurement. A passing pooled component is still diagnostic;
general comparison results do not waive this specific release requirement.
The combined controller/privacy follow-up passed all 118 Python checks and the
464-path source audit. These script checks do not extend the native CI receipt
to a new source revision.

The pooled packet captures remain diagnostic. Still required are isolated
whole-client observations, the full workload/network/client-count comparison,
measured profile selection and migration, exact installed-client journeys,
native signed installers for every advertised target, and final source-bound
fuzz/soak and rollback/rollout evidence. The GC/1 release manifest also needs an
explicit GC/2 profile and decision binding before it can qualify a GC/2 rollout.
Component correctness and signing-verifier passes do not fill these gaps.
