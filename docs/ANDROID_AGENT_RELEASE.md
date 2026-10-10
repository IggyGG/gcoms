# Android agent deployment

This lane deploys the opt-in `boo.gcoms.agent` APK and its selected hub/runtime
and downloaded worker inputs. It is separate from the GChat Play Store app.
It never waits for Apple, Windows, desktop GUI matrices, or a relay soak during
routine activation. Relevant protocol/load qualification belongs before the
release push; the required focused auth/persistence checks remain in this lane.

The deadline is 600 wall-clock seconds from the original Forgejo post-receive
timestamp, including consumer polling, queueing, artifact checks, activation and retries. The clock starts at promotion of a fully prepared immutable release; source pushes request preparation. Native
signatures, byte hashes and every declared target remain mandatory. Deadlines
and failures survive restarting the consumer; restarting cannot buy more time.
Build-only preparation has a separate one-hour bound and never claims live
deployment. Source manifests and original cached artifact provenance are retained.

| Deadline after push | Stage |
| --- | --- |
| 60 seconds | Capacity/toolchain/baseline preflight |
| 60 seconds | Verify all prepared artifact cache entries; no compilation |
| 60 seconds | Artifact and signing verification |
| 180 seconds | Activation and fresh private provisioning |
| 540 seconds | Full downloaded worker readiness on every Android target |
| 600 seconds | Reserved restoration window |

Preparation builds the SDK, installer, headless hub, downloaded worker and fleet controller in bounded parallel jobs. The running controller is verified against its prepared artifact so the sender cannot remain on an older fixed binary.
The APK includes ARM64 and x86_64 native client inputs; downloadable workers
compile only the ABIs in the declared Android target inventory.
APK packaging waits only for SDK and installer inputs. Cached artifacts require
unchanged reviewed Git input hashes, toolchains, compiler settings and verified
bytes; their original source revisions remain in receipts. Stable owned source directories preserve Cargo's paths across source changes;
compiler outputs and artifact hashes remain separate. Android application
edits do not rebuild unchanged native dependencies. Unknown native source inputs
remain conservative; this is not permission to relabel old tests for changed code.

CPU-heavy work goes through `workstation-batch`, retaining the workstation's
eight-core shared cap and storage reservations. Compiler outputs and scratch are
declared to the manager. Signed artifacts and private receipts live on SSD outside
disposable scratch. An additive Forgejo hook writes small push notifications on
the existing mounted SSD; it neither changes ownership hooks nor blocks pushes.
Source notifications coalesce before preparation. Promotion tags are processed individually with their original server push times. A pre-receive guard refuses tag rewriting/deletion and annotated or malformed tags. Failed requests and artifacts remain.

Prepare the owned workstation (no private configuration is committed):

```sh
python3 scripts/android_release_setup.py --state /absolute/SSD/android-release --install
python3 scripts/android_release.py --config /absolute/SSD/android-release/config.json prepare
python3 scripts/android_release.py --config /absolute/SSD/android-release/config.json enroll-hub --prepared-id PREPARED_SHA256
python3 scripts/android_release.py --config /absolute/SSD/android-release/config.json promote --prepared-id PREPARED_SHA256
python3 scripts/android_release.py --config /absolute/SSD/android-release/config.json status
```

The consumer timer polls the mailbox every five seconds. Warming runs twice
daily. A queued release stops this lane's warming unit before dispatch; other jobs
remain protected. Preparation resumes after dispatch, including a failed
preflight, so the next push need not wait for the twelve-hour tick. Setup refuses
to replace a running lane. The
private config lists exact source refs, target inventory, certificate pin,
toolchains (Rust/NDK 27.3, JNI NDK 28.2, CMake 3.22.1 and Java 21), storage
reservations and existing managed hub activation/rollback
commands. The one-time enrollment retains the original local units and known legacy overrides, switches their base commands to stable headless paths, and requires the existing private passphrase file for automatic unlock. Routine hub changes attach through the owner-authenticated API, Prepare, Disconnect/checkpoint and Exit before swapping the executable. Another attached view or an unreviewed override refuses activation. Routine promotion never edits the service unit. It publishes Android
workers through the existing controller's normal file publication API, then
waits for that controller to select the exact bytes. It retains previous worker
and APK bytes for restoration without replacing the identity or download state.
Restoration runs APK and hub work concurrently within the original last-minute budget, restores the controller and worker, mints fresh routing introductions, and requires a fresh exact release/worker/APK/PID readiness receipt. A byte-only restoration fails the functional gate. The latest protocol checkpoint and identity are preserved.

Profiles are minted after hub activation and their actual GCRB/2 introduction
expiries must cover the deployment window. Private provisioning is outside the
APK. The current workstation adapter targets the owned rootable emulator; adding
phones requires their real managed install/provision/observation adapter.

The agent writes private `deployment-ready.json` only after its signed payload
and admission receipt, exact requested worker hash, and downloaded worker's
in-process ready signal. The host also checks the installed APK hash and current
process ID. A stale receipt, an installed APK, or a healthy hub alone cannot pass.

The 2026-10-08 baseline failed full download/load. Routine activation refuses
that known failure before building or adding production traffic. Initial real runtime qualification must supply a current source-bound successful 42 MiB reference transfer (at most 360 seconds), downloaded worker load, identity-preserving resume and connected Mullvad observation. Generic HTTPS speed probes never qualify relay delivery. Managed hub/controller enrollment and that baseline are required before promotion. Never edit failure
flags into passes. `latest.json` records the latest attempted release;
`live.json` records the last fully verified release and cannot be replaced by a
failed attempt. Missing capacity or a cold build is a visible deadline miss.

Validation:

```sh
opencode-test python3 -m unittest discover -s scripts/tests -p android_release_test.py -v
```

These controls exercise simulated adapters, cache selection, original push
deadlines, cancellation, current-process readiness and failed-canary restoration.
They are not production timing evidence. Require three consecutive unattended
real deployments under 600 seconds and a real failed-canary restoration before
claiming the ten-minute target. Keep the original retained delivery and pull
latency failures until independently repaired and verified.

On 2026-10-09, the shared GChat controller still nominated an undeployed
runtime baseline for its own update, and the currently selected deployment
journal was blocked. The classifier correction is published on GChat main;
its activation must pass the existing controller gates. Until then, keep this
standalone operations change on its published task branch: an older classifier
would treat the new files as native SDK inputs and enqueue unrelated matrices.
The installed workstation lane independently observes the existing Android
feature refs and retains its original push receipts. No failed journal is
relabelled as deployed to unblock the shared controller.
