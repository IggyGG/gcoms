# Developer-preview qualification

The release targets are **Linux x86_64, Windows x86_64, macOS x86_64, and macOS
aarch64**. Windows uses a native MSVC VM; macOS uses GitHub-hosted workers.
The local Mac is unavailable. Historical results are retained but do not qualify
new source commits. Current-protocol candidates have additional application,
fleet, installed-network and privacy requirements described below.

Forgejo remains authoritative. GitHub mirrors source and signed release assets.
These qualification scripts never publish; the separate GChat delivery tooling
performs publication only after the evidence gate passes.

## Freeze the inputs

Finish changes and commit both repositories before creating a candidate. Use a
new output directory; candidates cannot replace their source or artifact inputs.
Keep the bundle outside either source checkout, or in an ignored evidence folder.

```sh
python3 scripts/release-candidate.py init \
  --gcoms /path/to/gcoms --gchat /path/to/gchat \
  --output /path/to/evidence/rc-01
```

`candidate.json` records both full commits and Git tree hashes, the version,
GC/1 profile and supported targets. Hashed `git archive` files retain the source.
Changing either checkout after freezing requires a new candidate and fresh checks.
The private diagnostic records from earlier revisions remain useful but do not
automatically qualify a new commit.

For a GC/2 file-profile candidate, explicitly freeze its traffic configuration:

```sh
python3 scripts/release-candidate.py init \
  --gcoms /path/to/gcoms --gchat /path/to/gchat \
  --wire-profile GC/2 --traffic-config /path/to/profile-22.json \
  --output /path/to/evidence/gc2-rc-01
```

This creates schema 2, with the profile-22 file privacy contract, new-profile GC/2
selection and explicit existing-profile migration. It records intended behavior;
it does not select an unqualified production profile or authorize deployment.
GC/1 schema 1 remains supported separately. Source/configuration identities are
attached to recorded checks; older reports cannot qualify by relabelling them.

Build inspected archives in isolation:

```sh
python3 scripts/check-consumers.py --release --gchat /path/to/gchat \
  --output /path/to/evidence/rc-01/packages
```

This snapshots both checkouts, packages all 17 publishable Rust crates, checks an
external renamed-dependency consumer, builds both GChat Cargo workspaces against
the extracted crates, and installs the two npm tarballs in an external consumer.
Original source and lockfiles are checked for changes and never rewritten.
`--offline` uses cached dependencies; a missing dependency fails the check.

GComs' `check-registry-consumer.py` exercises canonical Cargo registry identities
through a loopback staging registry. Use `--application /path/to/gchat`,
`--packages /path/to/packages/package`, `--target-dir /path/to/build` and optionally
`--manifest apps/client/src-tauri/Cargo.toml`. The proposed lockfile is retained
under the output's `reports/` directory; `--lockfile-output` can export another
copy outside the source checkout. Review and explicitly adopt lockfile proposals
before freezing a candidate. The checker itself does not edit the application.

`stage-npm.py --gchat /path/to/gchat --packages /path/to/packages --output
/path/to/npm-evidence` checks GChat's npm workspaces in a source snapshot through
the inspected tarballs and exports a canonical lockfile proposal. Its output must
be outside GChat. It runs `check`, `test` and `build`; it needs access to uncached
third-party dependencies, but no publishing credentials.

## Record execution

Register every `.crate`, npm `.tgz` and native installer as an immutable input:

```sh
python3 scripts/release-candidate.py artifact \
  --candidate /path/to/evidence/rc-01/candidate.json \
  --project gcoms --kind rust --file /path/to/gcoms-sdk-0.1.0.crate
```

Use `--project gchat --kind installer --target linux-x86_64` for Linux `.deb`
and `.AppImage`, or `--target windows-x86_64` for the NSIS `.exe`. Register inputs
before recording checks that consume them. Reports bind the hashes present when
execution starts. Do not substitute new archives for a previously tested name.

```sh
python3 scripts/release-candidate.py record \
  --candidate /path/to/evidence/rc-01/candidate.json \
  --gcoms /path/to/gcoms --gchat /path/to/gchat \
  --project gcoms --check native.gcoms.linux-x86_64 --timeout 7200 \
  -- python3 scripts/ci.py
```

The runner retains command, real exit code, duration, toolchain, log hash and
before/after source identities. Timeout kills only its own process tree. Failed
attempts remain in the bundle and supersede a previous pass for the same check.
Independent checks can record concurrently without losing each other's reports.
Missing executables and source changes produce failed records, never a pass.

Native checks must execute the complete `scripts/ci.py` entrypoint. Windows must
use native `x86_64-pc-windows-msvc`; cross-built GNU executables running inside
Windows are useful diagnostics but do not qualify MSVC, rustdoc or installers.
Provision a disposable Windows 11 VM with the pinned Rust/Node/Python toolchains,
MSVC C++ build tools, Windows SDK and Tauri/WebView2 prerequisites. Linux artifacts
need install/upgrade checks on Ubuntu 24.04 and 26.04. Untrusted pull requests
must use disposable isolated runners with no release/signing secrets.

## Required evidence

`scripts/release_evidence.py` defines the complete, reviewed check inventory:

- Native GComs and GChat CI on Linux, Windows, and both macOS architectures, with nonzero test counts,
  no failed/incomplete harnesses and an explicit inventory of allowed exclusions.
- Rust and npm archive consumers, GChat through the staged registry, browser
  integration and GChat integration against the candidate inputs.
- Current dependency audits and source/license inventories. Scanning does not
  establish distribution rights.
- Explicit 64-member MLS, isolated Linux privileged-port, and 1 GiB cache streaming
  tests. The streaming gate must execute `cargo test -p gcoms-file-transfer --release
  --test swarm --locked gib_import_resume_export_is_streaming -- --ignored --exact
  --test-threads=1` and report exactly one passed, unskipped test. The three
  ignored private C TLS-probe cases do not establish public interoperability.
- At least 24 hours of parser fuzzing and a 24-hour application soak with at least
  16 clients and four channels. Soak evidence must account for durable operations,
  intact archives, bounded resources and recovery after injected faults.
- Installer journeys: fresh install, invite/unlock, messaging, file transfer,
  reconnect, restart, retained-profile upgrade, interrupted upgrade, archive
  recovery, rollback and uninstall preserving data. Bind every target installer.

`record --facts measurements.json` accepts only workload measurements, installer
scenario outcomes and evidence references. It cannot override runner exit status,
source bindings or timing. These facts must come from the workload or an actual
acceptance session, not planned work. Reports are trusted-runner attestations;
hashes detect mismatched bytes but are not proof that a dishonest runner executed
the stated workload. Protect the runner and review its retained evidence.

GC/2 retains every requirement above and additionally requires:

- `integration.gc2-bootstrap`: the real GChat runtime's disconnected authenticated
  HTTPS fresh/reopen/recovery journey. Its ordinary-suite exclusion is permitted
  only with this separate successful gate. An explicit fixture provider does not
  qualify installed signed-network onboarding.
- `integration.gc2-turnover`: actual daemons, three real credential expiries,
  separately demonstrated 1800-second carrier expiry while authority is fresh,
  both contact/channel classes, admitted MLS wire retention, authenticated ACKs,
  exact file export and same-identity reopen. Simulated time, missing ACKs,
  premature delivery and recovery beyond 300 seconds fail.
- `fleet.gc2-files`: eight hosts, exact 64 KiB through 1 GiB exports, the four-hour
  mixed/fault campaign, 16 clients and 56 directed host pairs. All cleanup and
  production-baseline comparisons must pass. The accepted file deadlines and
  overall chat latency/ACK gates remain required. Historical failed campaigns
  and unmatched background conditions cannot qualify.
- `privacy.gc2-client`: isolated actual-client all-egress/lifecycle accounting,
  packet-derived connection lifetimes and independent train/held-out cohorts on
  unconstrained and adverse links. A hash-bound classifier report must bind the
  same source, executables and traffic configuration and pass all four upper-95%
  separability bounds at **0.55**: idle/chat and matched bulk/mixed, each windows
  and connections. Pooled capture, validity calibration alone, missing components
  and valid unfavorable bounds fail release qualification.
- `installed.gc2-network.<target>` on every target: actual installed desktop
  signed-network discovery/provider TLS, retained recovery, protected catalog,
  default GC/2 on fresh profiles, and explicit migration preserving existing
  identity/archive/cache/pending operations. No silent fallback or migration.

Register workload binaries with `artifact --kind executable --project gcoms`
and `--project gchat`; reports bind actual executables as well as source archives.
GC/2 report measurement fields are specified in `gc2_release_evidence.py`. Missing
facts fail closed. Do not manufacture measurement facts from intended behavior.
Changing the candidate/configuration requires new evidence; a passing earlier
component is retained at its original source and scope.

## Check the appropriate stage

```sh
python3 scripts/check-release.py \
  --candidate /path/to/evidence/rc-01/candidate.json \
  --companion /path/to/gchat --stage candidate --json
```

Run from GChat with `--companion /path/to/gcoms` equivalently. Keep both copies of
the shared release scripts and their tests identical.

`candidate` validates private technical qualification. `preflight` adds identified
rights, operator and maintainer reviews, approved public configuration, Windows
distribution signing and manifest signature verification. Reviews require retained
evidence and cannot be manufactured by the command runner. `published` additionally
requires verification of the actual public Rust/npm packages and GChat downloads.
The latter stages remain blocked until signing identities, contacts, and actual qualification evidence are configured.

No passing flag in `publication.json`, short smoke run, empty test harness or
unavailable platform substitutes for the required evidence. Keep unresolved failures
and long-running checks visible until their real results are available.
