F5 simultaneous channel-route recovery, 2026-10-15: authenticated self-directory
announcements enter the existing bounded gossip/PEX cache after durable receive.
This lets a healthy third member bridge two peers whose old queues disappeared
together. The original MLS ciphertext and recipient authentication are preserved;
the durable all-member direct announcement remains authoritative. Causal old-source
failure, all 22 focused recovery cases, all 476 node tests, strict Clippy and
legacy compilation pass. The combined GChat registration/fleet/actual-daemon and
strict checks also pass. Full release qualification is in progress.
See [channel peer exchange](docs/CHANNEL_PEX_RELAY_FIX.md#simultaneous-route-replacement).

F5 materialized dispatch order, 2026-10-15: fresh GC/2 durable frames follow the
maintenance dispatch owner while same-peer/class durable predecessors remain.
They can still allocate available counters and pipeline; caller completion cannot
enqueue ahead of older, already-materialized frames. The causal admission test
fails old code and passes with unchanged ciphertext, IDs and deadlines. Ten full
native TLS/restart suites, all474 node tests, strict Clippy and legacy compilation
pass. The final GChat fleet/ownership/actual-daemon integration also passes.
[Evidence](docs/evidence/durable-host-20261015/materialized-dispatch.json).

F5 queued POST recovery, 2026-10-15: a finite POST waits out a known pre-TLS
dial cooldown within its original request deadline. Authentication preparation,
connection credit and actual dialing still wait for admission. The causal real-TLS
test fails the old cached-refusal path; all79 transport tests and strict Clippy pass.
[Evidence](docs/evidence/durable-host-20261015/dial-cooldown.json). Full signed
qualification and installed acceptance remain required.

F5 deferred routing-control recovery, 2026-10-15: renewed owner announcements
atomically replace obsolete, still-unencrypted contact updates for the same peer.
Equivalent deferred forward grants can be superseded only without shortening or
changing their authority. Application records and allocated ratchet frames remain
intact, with the existing byte/item limits. An uncertain checkpoint pauses the
owner until reopen. See [transaction semantics](docs/GC2_SCHEDULER.md#deferred-routing-control-supersession)
and [source evidence](docs/evidence/durable-host-20261015/deferred-route-controls.json).
The isolated retained-input rehearsal and final combined node/pair checks pass.
The subsequent cooldown/dispatch repairs address the reproduced native failures;
normal signed qualification and installed acceptance remain required.

F5 fleet status dispatch, 2026-10-15: a registered `IdentityRead` component can
request the existing read-only runtime connection/relay status. The machine
allowlist had omitted this operation after the normal IPC capability check.
Unregistered clients, shell access and profile administration remain refused.
The real retained GChat fleet regression fails before the fix and passes after
rotation and endpoint recovery; all86 SDK tests and strict checks pass.
[Evidence](docs/evidence/durable-host-20261015/fleet-runtime-status.json).

F5 recovery-batch qualification, 2026-10-15: the original227 native gate exposed
an intermittent fixture assertion that every recovery pass must encounter a full
control queue. A sorted batch can contain only healthy channels. The fixture now
covers both the original HashMap-first blocked layout and an explicit healthy-first
layout, preserving bounded progress, reported deferrals, exact queued controls,
membership epochs and durable checkpoints. Runtime scheduling and limits are
unchanged. See [qualification evidence](docs/evidence/durable-host-20261015/recovery-batches.json).

F5 retained subscription capacity, 2026-10-15: terminal connection pools reserve
finite recovery-control credit and admit additional long-lived subscriptions on
bounded shards of the same pinned route and traffic class. Admission uses the
peer's actual HTTP/2 SETTINGS, preserves the existing 64-connection hard bound,
and returns credit on cancellation. The original real-server regression blocks a
finite control behind sixteen subscriptions. See [connection ownership](docs/GC2_SCHEDULER.md#requests-and-connection-ownership)
and [source qualification](docs/evidence/durable-host-20261015/subscription-credit.json).
Installed authenticated delivery and full signed qualification remain separate gates.

F5 Android cluster migration accepted, 2026-10-13: source intake, builds, the isolated Android lab and release/rollback now execute in Kubernetes. Versioned Hetzner FSN1 S3 holds durable artifacts, checkpoints and evidence; bounded cluster volumes hold working state. The fresh signed 42 MiB interrupted transfer and in-process load passed in 292.090 seconds. Three consecutive prepared-tag promotions reached every declared target in 356.590, 288.456 and 213.545 seconds. The deliberate Android process-stop canary restored a loaded worker with unchanged identity in 44.804 seconds. The normal coordinator configuration is restored, the app and managed services are healthy, and the original failures remain retained. [Final acceptance](docs/evidence/android-cluster-20261012/completion.json), [rollback proof](docs/evidence/android-cluster-20261012/failed-canary-live.json).

The submitting client exited, and this session made no cluster or guest calls during the first release’s following ten-minute window; physical workstation poweroff was not tested. Workstation release timers and their hook are retired. The ten-minute target starts at the push of a prepared, qualified release tag; cold native preparation took 25m39s. Routine promotion reuses exact artifacts and runs no broad platform matrix. [Release procedure](docs/ANDROID_AGENT_RELEASE.md#routine-cluster-releases).

The dated investigation entries below retain the evidence and status at each earlier step. The acceptance record above is the current status of this Android cluster migration.

F5 original Android launch-clock failure, 2026-10-13: the real tag completed all 26,006,512 download bytes but failed current-process readiness. Android measured about 0.5 seconds ahead; its handoff time was 1791857609 and the signed controller decision 1791857608, below the client’s strict request-time floor. Fresh transport retries also rejected the retained decision. The original 600.295-second failure and unsuccessful functional rollback remain archived. Both original behaviors fail the causal regressions. The repaired installer passes 19 affected client/launch checks; the controller passes its retained-decision and four reply-contract checks. Exact native artifacts remain unchanged by those controls; their records were read back from FSN1 S3. Native preparation completed in 512 seconds, and both fixes are published to main. The repaired native family then passed the fresh signed 42 MiB interrupted transfer and current-process load in 292.090 seconds; PID 8308 restarted as 8619 with unchanged identity. [New reference](docs/evidence/android-cluster-20261012/runtime-qualified-launch-repair.json). The first real prepared promotion then reached every declared target in 356.590 seconds from its original server push. Its client exited and this session made no cluster or guest calls for the following ten-minute window; all six artifacts were cached. [Live promotion](docs/evidence/android-cluster-20261012/first-live-promotion.json). The next two immutable tags reached every target in 288.456 and 213.545 seconds, also using cached artifacts. All three consecutive deployments are within 600 seconds of their original server pushes. [Three live releases](docs/evidence/android-cluster-20261012/live-promotions.json). The real failed canary restored functional readiness in 44.804 seconds; the ordinary configuration is restored. [Acceptance](docs/evidence/android-cluster-20261012/completion.json). [Installer checks](docs/evidence/android-cluster-20261012/launch-window-installer.json), [controller checks](docs/evidence/android-cluster-20261012/launch-window-controller.json). [Evidence](docs/evidence/android-cluster-20261012/original-launch-clock-failure.json).

F5 cluster release procedure, 2026-10-13: document exact prepared-source selection, native-reference reuse, original server clocks, cluster execution after the submitting client exits, and retained failed Jobs. Routine promotion performs no compilation or broad platform matrix. Cold native preparation took 25m39s and remains separate from the 600-second prepared-tag objective. Three consecutive original-clock promotions and functional failed-canary restoration pass. [Procedure](docs/ANDROID_AGENT_RELEASE.md#routine-cluster-releases).

F5 end-to-end deployment deadline, 2026-10-13: the second real tag retained its failed receipt at 182.351 seconds after completing preflight and cache verification, before any activation. Its 109.523-second admission and 65.942-second preflight crossed an unnecessary internal stage cutoff. All normal stages now share the original 540-second horizon, while restoration remains inside the original 600 seconds. Individual command bounds, signing/input checks, current-process readiness and terminal failure retention remain enforced. Eight focused controls pass in 5.050 seconds; the former three-minute cutoff fails the delayed-intake control, and intake at 541 seconds is refused without activation. Live promotion and canary acceptance remain pending. [Original failure](docs/evidence/android-cluster-20261012/original-stage-cutoff-failure.json), [deadline evidence](docs/evidence/android-cluster-20261012/stage-allocation.json).

F5 cached preparation under an active compiler, 2026-10-13: the real cache-only Job prepared source `e449994` in 25 seconds with all six qualified native artifacts unchanged. Its submission helper and preparation together took 139 seconds, including coordinator ownership and source synchronization. The original independent native preparation kept its exact Job UID and continued. The result is pinned in FSN1 S3; no compilation or broad test run was part of this cached request. Original-clock live promotion remains pending. [Evidence](docs/evidence/android-cluster-20261012/cached-preparation-live.json).

F5 verified cached preparation, 2026-10-13: complete immutable artifacts can be verified while an unrelated source is compiling. The `require_cached` cluster request flag is hash-bound and rejects missing or changed artifacts without fallback compilation; live changes retain their deployment lock. Worker publication and profile mint now use the shared activation deadline instead of stale 175-second cutoffs. Both original behaviors fail causal controls; 13 focused controls pass in 6.751 seconds, including original clocks, artifact integrity and terminal-result recovery. Native inputs remain unchanged; actual promotion and failed-canary acceptance remain open. [Evidence](docs/evidence/android-cluster-20261012/cached-preparation.json).

F5 original promotion admission, 2026-10-13: tag `8bd53d82` retains its real failed receipt. Preflight began 93.894 seconds after the Forgejo push and hit the 120-second stage cutoff before any activation. The live clock includes admission and durable journaling, which the idle-only estimate missed. Validation now shares 180 seconds, activation 300, readiness 540 and restoration the unchanged 600 seconds. Seven focused controls pass in 3.641 seconds; the original two-minute budget fails the delayed-intake control. Three successful original-clock promotions and real functional rollback remain pending. [Original failure](docs/evidence/android-cluster-20261012/original-promotion-admission-failure.json), [allocation](docs/evidence/android-cluster-20261012/stage-allocation.json).

F5 cluster stage allocation, 2026-10-13: the updated real pre-promotion check passed in 37.343 seconds (previously 59.645). Measured idle intake costs 23.089 seconds, so preflight, cache verification and signing checks now share an absolute 120-second cutoff; activation stays at 180 seconds, readiness at 540 and restoration at 600 from the original server push. The original one-minute cutoff fails the delayed-intake control; seven focused controls pass in 3.722 seconds, including no compilation, immutable clocks and the reserved rollback minute. Workstation timers and their local release hook are retired, with original files/state retained. Three genuine timed promotions and functional rollback remain pending. [Stage evidence](docs/evidence/android-cluster-20261012/stage-allocation.json), [trigger retirement](docs/evidence/android-cluster-20261012/workstation-trigger-retirement.json).

F5 S3 guest recovery verified, 2026-10-13: both original guest disks were checkpointed, sealed and removed, then restored from versioned FSN1 objects onto new PVCs. The original VM identity, Android identity seed, installed APK and private owner mapping all passed verification before rebinding the new Pod. All nine network services restarted normally. The coordinator now uses the verified restored context. Full Android transfer and release timing remain pending. [Evidence](docs/evidence/android-cluster-20261012/guest-recovery-live.json).

F5 cluster Android reference, 2026-10-13: the fresh normally signed 42 MiB worker passed full download, interruption after 8,426,000 bytes, same-run resume, unchanged identity and verified in-process load in 278.640 seconds. The original run is 815b0130-2564-4d76-9ddb-d0d87101953e; Android restarted from PID 3260 to 3538. Its exact result is version-pinned in FSN1 S3. Three timed promotions and functional failed-canary restoration remain open. [Live reference](docs/evidence/android-cluster-20261012/runtime-qualified.json).

F5 cluster preflight overhead, 2026-10-13: the measured pre-promotion check took 59.645 seconds. Complete Git inventories now authenticate against the original commit and reconstructed tree objects before reuse; actual source verification drops from 11.774 to 0.832 seconds with all six native keys unchanged. Existing guest artifacts retain full private-file/hash verification while avoiding repeat uploads. APK extraction uses a bounded 128 MiB pod scratch volume. Eleven focused cache/staging controls pass in 3.015 seconds; five bounded-volume/configuration-upgrade controls pass in 0.020 seconds. The updated live preflight timing follows rollout. The explicit isolated failure fixture has six passing ownership/replay controls and has not yet injected a live fault. [Performance](docs/evidence/android-cluster-20261012/preflight-cache.json), [failure fixture](docs/evidence/android-cluster-20261012/failed-canary-fixture.json).

F5 cluster coordinator S3 recovery, 2026-10-13: a fresh Kubernetes Job recovered 73 original state files into an empty 64 MiB working volume, verified 54 original push events and 17 effects (including six failures), and reconciled the original active preparation Job UID without submitting or replaying work. Recovery took 0.698 seconds; its proof is version-pinned in FSN1 S3. This verifies coordinator recovery only; full Android transfer, timed promotion and functional rollback acceptance remain open. [Evidence](docs/evidence/android-cluster-20261012/coordinator-recovery-live.json).

F5 nested recovery command, 2026-10-13: create private diagnostic parents for staged subdirectory commands and sync each journal’s actual parent. Both guest disks were restored from S3; the first rebind failed before remote mapping because its log directory was absent. The original owner mapping and absent mutation journal were independently verified. All 13 focused provisioning controls pass in Kubernetes (1.471 seconds), including real nested execution and no replay. Full Android release acceptance remains pending. [Evidence](docs/evidence/android-cluster-20261012/nested-recovery.json).

F5 preempted guest capture, 2026-10-13: the pipeline can capture its original owner mapping after emulator recovery only when the exact original PVC and volume match the Lab recovery record. It measures the device on its current real Pod and retains both contexts for normal sealed S3 recovery. All 12 provisioning controls pass in Kubernetes (1.097 seconds). Actual guest checkpoint, restore and release acceptance remain pending. [Evidence](docs/evidence/android-cluster-20261012/retained-capture.json).

F5 cluster preflight diagnostics, 2026-10-13: early execution failures retain their exact trace in private cluster state while public receipts remain bounded. Recovery still returns the original terminal failure without rerunning the action. All 26 focused coordinator controls pass (1.623 seconds). The full Android reference stopped before mutation because routine cache maintenance preempted its emulator; its original disk remains intact. [Evidence](docs/evidence/android-cluster-20261012/preflight-diagnostics.json).

F5 restored lab mapping, 2026-10-12: the provisioning adapter can capture the owned Android/network pair, seal their completed S3 disk checkpoints, and verify the restored device and owner state before rebinding an ephemeral Android Pod identity. It preserves prior mappings and refuses foreign or uncertain state. Eleven provisioning controls and 68 release controls pass in Kubernetes. Actual disk recovery remains pending. [Evidence](docs/evidence/android-cluster-20261012/guest-recovery.json).

F5 cluster compiler availability, 2026-10-12: keep the distinct pinned compiler image ready alongside the coordinator and slim runner on eligible FSN nodes. The real cold preparation had spent roughly 3–7 minutes pulling that image. Warming has no mounted credentials or API token; all 26 focused coordinator controls pass (1.948 seconds). Live warming and full release acceptance follow. [Evidence](docs/evidence/android-cluster-20261012/compiler-warming.json).

F5 cluster metadata scope, 2026-10-12: reviewed GComs `.gitleaksignore` edits no longer rebuild Android native components; source publication still runs its secret scan and unknown build inputs still invalidate caches. All 68 release controls pass (15.087 seconds). A real coordinator replacement resumed observation in 36.523 seconds and preserved both original active Job UIDs. Full Android and release acceptance remain pending. [Evidence](docs/evidence/android-cluster-20261012/native-metadata-scope.json).

F5 cluster runtime follow-up, 2026-10-12: operation ConfigMaps now preserve executable helpers, failed Git reference checks retain bounded private diagnostics, and SIGTERM releases coordinator ownership through normal context cleanup. All 26 focused coordinator controls pass in Kubernetes (1.806 seconds). Live replacement and source preparation are being verified. [Evidence](docs/evidence/android-cluster-20261012/coordinator-polling.json).

F5 cluster operation binding and idle I/O, 2026-10-12: release Jobs and the persistent coordinator now mount their configured operation scripts. The original preparation had correctly refused stale image bytes before compilation. Unchanged polls preserve immutable request files and effect journals, and reuse checksum-verified original push receipts without repeated S3 HEAD/GET. All 173 focused controls pass (25.214 seconds); live rollout and timing comparison follow. [Evidence](docs/evidence/android-cluster-20261012/coordinator-polling.json).

F5 cluster lab recovery, 2026-10-12: archive only the exact private SSH key pair and pinned VM host key to versioned FSN1 S3. A fresh cluster Job restored them into empty scratch and authenticated the original VM with strict host-key checking. Existing access, foreign VM bindings, extra files and public modes are refused. Provisioning now retains each original attempt and private failure trace before Pod logs can disappear, including archive outages. All 169 release controls and the final eight provisioning controls pass. Guest disk recovery and full Android release acceptance remain pending. [Evidence](docs/evidence/android-cluster-20261012/access-recovery.json).

F5 fresh reserved lab, 2026-10-12: a new scoped Android/Ubuntu pair is running in FSN. Real network bootstrap recovered archived native binaries, verified provider TLS and five normal GC/2 relay introductions. Android resolves the provider through its private Service and connects to all five relays. Both proofs are versioned in S3. The original discarded instances are untouched. Signed Android bootstrap is packaged with the same exact VM binding and private execution journal; its actual load and full 42 MiB acceptance remain pending. All 166 focused controls pass (25.745 seconds). [Evidence](docs/evidence/android-cluster-20261012/fresh-pipeline-lab.json).

F5 repeatable lab provisioning, 2026-10-12: the cluster adapter provisions the normal relay network and hub/controller using live pipeline-owned identities, a private scoped Service and version-pinned native archives. Guest mutation is journaled before execution; failed or uncertain bootstrap cannot replay under a new Job. All 166 focused release controls pass (23.596 seconds). A fresh named lab pair is running under persistent reservations; actual network/bootstrap and Android acceptance remain in progress. [Evidence](docs/evidence/android-cluster-20261012/repeatable-provisioning.json).

F5 shared lab reservations, 2026-10-12: the cluster coordinator and guest-operation Jobs independently renew the same two instance Leases. Normal Lab lifecycle commands cannot discard a reserved guest, and one finishing Job cannot release another participant. UID/acquisition-epoch checks fence lost ownership. All 85 lab and 162 release controls pass in Kubernetes. A real API probe verifies renewal, discard refusal, retained sharing and natural expiry in 148.461 seconds; its temporary Lease was removed. Activation against the discarded Android guests remains pending ownership clarification. [Evidence](docs/evidence/android-cluster-20261012/lab-reservations.json).

F5 deployment runner size, 2026-10-12: separate verification/deployment tools from the native compiler. Verified archived OCI bytes fall from 2,755,394,711 to 515,596,487 (81% less). The real prepared APK passes signature, embedded SDK and native load-alignment checks in the smaller cluster image. Rust, Gradle and NDK compilation remain in the unchanged pinned builder. Images are verified in FSN1 S3. Live Android validation is blocked by external discard of both lab instances without checkpoints. [Evidence](docs/evidence/android-cluster-20261012/slim-runner.json).

F5 persistent cluster coordinator, 2026-10-12: configuration upgrades reconcile original Job definitions and immutable legacy configurations; invalid promotion pushes become archived terminal failures; execution failures recover from S3 without repeating the action. Qualification retains its original manifest. A persistent supervisor and credential-free image warming can be rendered for the same FSN placement. All 158 scoped controls pass in Kubernetes (20.438 seconds). Live timing and disconnected recovery remain pending. [Evidence](docs/evidence/android-cluster-20261012/persistent-coordinator.json).

F5 Android retained identity, 2026-10-12: reject a missing or malformed 32-byte identity seed before activation or identity-preservation claims. ADB can return a successful exit status with missing-file text; hashing that text is not identity proof. All 151 scoped release controls pass in Kubernetes (14.213 seconds). [Evidence](docs/evidence/android-cluster-20261012/identity.json).

Source-mirror audit, 2026-10-12: two historical non-secret findings are reviewed as
an immutable source reference and benchmark prose. `.gitleaksignore` records only
their exact fingerprints; full-history scanning and rejection of new findings
remain required. [Review evidence](docs/evidence/source-audit-20261012/summary.json).

F5 native qualification, 2026-10-13: the frozen GChat Linux 0.1.192 workflow
reproduces a rustfmt failure in two archive-identity source files. Formatting-only
corrections pass the pinned formatting gate and source L0. Complete native
qualification of the successor remains required.
[Evidence](docs/evidence/irc-ux-native-format-20261013/summary.json).

F5 durable ordering, 2026-10-13: Linux0.1.193 exposed a fresh send overtaking
deferred messages after session confirmation. Same-peer, same-class durable
admission now joins that retained queue. Both causal controls,74 GC/2 controls,
four metrics controls, four native TLS/restart checks and ten additional ordering
runs pass, with strict Clippy and legacy compilation. Full signed release and
installed delivery follow. See [scheduler behavior](docs/GC2_SCHEDULER.md) and
[qualification evidence](docs/evidence/irc-ux-release-repairs-20261013/summary.json).

F5 cluster source reuse, 2026-10-12: source sync now authenticates exact advertised refs and skips unchanged repositories. Prepared promotion checks its exact immutable tag and existing commit without fetching unrelated history. A real Git control rejects another fetch for unchanged sources and promotion; all 150 scoped controls pass in Kubernetes (16.673 seconds), with the 1,141-path source audit passing. Native inputs and the real Android deadlines are unchanged. [Evidence](docs/evidence/android-cluster-20261012/source-reuse.json).

F5 isolated cluster lifecycle adapter, 2026-10-12: release Jobs now verify APK signing and all prepared bytes before staging a private, checksum-bound command to the exact lab VM and Android Pod. The guest validates its private mapping, journals mutations, reconnects ADB, preserves uncertain attempts, and runs the existing full interruption/resume/load checks. Operation images and immutable script overlays retain the pinned compiler image and native cache keys. All 150 scoped controls pass in Kubernetes (25.812 seconds); runtime images built in 9.206 seconds. Real Android reference, three promotion clocks, rollback and workstation disconnection remain pending. [Evidence](docs/evidence/android-cluster-20261012/lab-adapter.json).

F5 real server push recovery, 2026-10-12: both actual Forgejo ref updates for 38891d0 reached verified FSN1 S3 one second after their original server clocks. A separate cluster Job restored their exact original bytes into empty storage, deduplicated a second intake, deleted only its scratch cache, and recovered them again. Reviewed outbox, image admission and placement files preserve native input hashes; the exact compiler image remains mandatory. All 135 focused release controls pass in Kubernetes (14.378 seconds). Automatic live promotion remains gated on the cluster Android runtime adapter and actual 360/600/60-second acceptance. [Evidence](docs/evidence/android-cluster-20261012/server-push-recovery.json).

F5 cluster promotion priority, 2026-10-12: cold preparation uses a separate lock and cannot delay an already prepared promotion. The coordinator preserves one preparation and one live operation, fetches only the exact promotion tag, and retains the original server push clock. All 139 scoped release controls pass in 17.138 seconds; the 1,133-path source audit passes. Actual Android transfer, promotion and rollback timing remain unqualified. [Evidence](docs/evidence/android-cluster-20261012/prepared-priority.json).

F5 durable cluster push intake, 2026-10-12: an additive Forgejo hook fsyncs bounded source receipts with the original server clock. A single unprivileged cluster worker mounts only the outbox subdirectory and removes each entry only after versioned FSN1 S3 readback. It has neither Git credentials nor a Kubernetes API token. Intake supports `source_event_transport: server-outbox`, validates exact repository/ref/hash/clock bindings, and restores original receipts after cache loss. The existing actor privacy settings stay intact. All 135 focused release controls pass in Kubernetes (14.417 seconds), including archive outage, replay, changed-clock and private-file controls. Worker and immutable-promotion guard are installed; real push delivery follows publication. [Evidence](docs/evidence/android-cluster-20261012/server-outbox.json).

F5 Android APK toolchain, 2026-10-12: all five native components built successfully in Kubernetes. APK packaging exposed the required Build Tools 35.0.0 package and a read-only SDK cache caused by mounting the entire signing directory. The toolchain now pins that vendor archive and appends it to the verified base; the APK Job mounts only its keystore file. The extension built in 20.750 seconds, release images in 7.114 seconds, and the unprivileged toolchain probe passed. All 128 release controls pass in Kubernetes (15.515 seconds). Full APK packaging and live Android clocks remain pending. [Evidence](docs/evidence/android-cluster-20261012/apk-toolchain.json).

F5 cluster startup, 2026-10-12: native/release Jobs use `OnRootMismatch` to avoid rewriting populated compiler caches and accept an explicit image-pull Secret. The FSN registry has a bounded read-only TLS gateway for the three exact release repositories and immutable digest paths; unauthenticated reads, writes and unrelated repositories are refused. A real kubelet pull on triform-5 with `imagePullPolicy: Always` completed in four seconds. All 128 release controls pass in Kubernetes (13.959 s). Native hub preparation also runs only its focused signed-network configuration controls. Android transfer and release clocks remain pending. [Evidence](docs/evidence/android-cluster-20261012/image-admission.json).

F5 cold native preparation, 2026-10-12: configure the pinned local SDK before fetching the hub dependency graph; reject resolved external packages absent from both source lockfiles before locked/offline compilation. The bounded builder normalizes its private temporary directory so PVC setgid inheritance does not contaminate installer private-state fixtures. The original installer failure is reproduced (directory mode 02700) and its unchanged resume/cache/network/cryptography controls pass with private scratch (0700). All 128 release controls pass in Kubernetes (15.905 s). Complete native preparation and live Android clocks remain pending. [Evidence](docs/evidence/android-cluster-20261012/native-preparation.json).

F5 Android source scope, 2026-10-12: the first cold mirror attempted every branch/tag and timed out on Dropship. Intake now fetches both selected GComs branches and each other selected branch, plus immutable Android promotion tags, with tag auto-follow disabled. A real Git regression proves unrelated branches/tags are omitted; all 127 release controls pass in Kubernetes (16.784 seconds). The fetch deadline remains 120 seconds. Original failed Jobs remain retained; complete preparation and live acceptance are pending. [Evidence](docs/evidence/android-cluster-20261012/source-intake.json).

F5 Android source-intake startup, 2026-10-12: the first real cluster run failed before Git because its private log directory was absent. Source synchronization now creates that directory before opening its first log; the regression exercises the actual logging sink on empty state. All 125 release controls pass in Kubernetes (14.408 seconds), and the repaired image passes the unprivileged toolchain probe. Original failed Job/clock retained. Bounded state/cache/RBAC resources are installed; source intake and real native preparation are next. [Evidence](docs/evidence/android-cluster-20261012/images.json).

F5 Android cluster images, 2026-10-12: release-code images now reuse a pinned Rust/Java/Android toolchain. Actual cluster updates completed in 13.957 and 7.594 seconds; the initial cold build remains separate. Native inputs require the exact builder image, while reviewed placement/recipe edits alone preserve compiler caches. Dependency warming fetches the selected component graph; compilation stays locked/offline. All 124 release controls and the real toolchain probe as UID 10001 pass in Kubernetes. Four earlier OCI image graphs have verified FSN S3 receipts, with verified shared layers reused; archival of the final permission-fixed image follows. The bounded state/cache/RBAC manifest passes server validation; installation and full native/lab/live acceptance remain pending. [Evidence](docs/evidence/android-cluster-20261012/images.json).

F5 Android cluster coordination, 2026-10-12: the release runner now hydrates exact native/prepared/terminal receipts from the FSN1 catalogue. Coordinator intent is checkpointed remotely before Job submission; lost replies and an empty working cache reconcile the original Job without repeating execution or resetting push clocks. Native Jobs use separate bounded component caches, immutable image/request bindings, no API/archive credentials, and an APK-only signing mount. Cache-writer intent is durable before admission. The existing GChat coordinator supervises this Android agent lane asynchronously; its store-app lane is separate. All 122 Android release controls and 55 coordinator controls pass in Kubernetes. The pinned Rust/Android toolchain image is building in the cluster; real native builds, lab lifecycle, live activation/rollback and workstation-independent timing remain unqualified. [Evidence](docs/evidence/android-cluster-20261012/coordinator.json).

F5 Android cluster migration, 2026-10-12: in progress. The Android flow will use the existing cluster release coordinator, bounded build Jobs and Kubernetes lab. `scripts/android_release_store.py` archives immutable, version-pinned FSN1 objects with full SHA-256 readback, exact receipts and checked empty-cache hydration; it uses the existing lab boto3 dependency. A real cluster recovery restored all six prepared artifacts (153,003,457 artifact bytes) in 4.765 seconds. `android_release_source.py` preserves the original Forgejo activity timestamp across delayed intake/restarts; repository imports require an explicit audited cursor. `android_release_kubernetes.py` fences ownership with a renewed Kubernetes Lease and reconciles deterministic Jobs by request digest and UID without repeating failed or missing executions. All 94 focused release controls passed in a bounded Kubernetes Job. Five repositories and their branches/tags are copied to cluster Forgejo; the coordinator reader has no push or admin rights. Credentials stay in trusted preparation. Build/lab/coordinator integration, activation/rollback and workstation-disconnected acceptance remain in progress; the 360/600/60-second live gates are still unqualified. [Evidence](docs/evidence/android-cluster-20261012/storage.json).

F5 Android progress observation, 2026-10-12: qualification collects downloader timestamps and paths in one bounded ADB request, then reads only current candidate states. With 38 actual closed emulator states, original metadata observation took 1.308 seconds and 39 ADB calls; the batched equivalent took 0.047–0.052 seconds and one call with identical metadata. The causal full-history control fails on the original 258 calls and passes with two total calls, including the current state read. Seven focused controls preserve run/hash/checksum/timestamp/path/ambiguity gates. This reviewed operations-only change reuses native build keys. The preceding full transfer completed at about 357 seconds but missed the unchanged six-minute in-process readiness deadline; full load, three real prepared promotion clocks and functional rollback remain unqualified. [Evidence](docs/evidence/android-ten-minute-20261009/frontier-metadata.json).

F5 Android restart receipt, 2026-10-12: normal APK assembly/lint passes in 43.785 seconds. The rebuilt Android 16 app survives an actual force-stop after 8,547,000 bytes and authenticates a resume of the same original run at 8,558,000 bytes. The full 42 MiB reference still fails the unchanged 360-second deadline at 360.746 seconds; cleanup observes 42,636,000 bytes, cancels the exact run profiles and restores adbd to UID 2000. This proves the boot restart repair, while full download/load, three live promotion clocks and functional rollback remain unqualified. Production host services are unchanged. [Evidence](docs/evidence/android-ten-minute-20261009/boot-service-restart.json).

F5 Android boot receiver recovery, 2026-10-12: Android 15 and later reject a data-sync foreground service from BOOT_COMPLETED when the app targets API 35 or higher. The broadcast can arrive while the activity is being reopened after force-stop. The receiver now defers that forbidden boot start to the activity and handles an older platform background-start refusal without killing the process. No service type, permission, SDK target, transfer limit or deadline is relaxed. The original normally signed full reference crashed at restart in BootReceiver with ForegroundServiceStartNotAllowedException and failed the unchanged six-minute deadline. Normal APK assembly/lint and a fresh interrupted full transfer remain pending; SDK, installer, hub, worker and controller bytes are reused. Three genuine live promotion timings and functional rollback also remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/boot-service-restart.json).

F5 Android checkpoint identity reuse, 2026-10-11: each encoding call derives its seed-bound public identity once and shares its public bytes/hash across sealed archive sections. No private keypair is cached; raw-seed wrapping keys, nonce generation, archive grammar, authenticated domains, limits and persistence barriers retain their existing behavior. The original causal checkpoint expands the public identity 10 times and fails the one-derivation control; the fixed checkpoint derives it once. All 63 scoped archive/recovery controls, two existing lock-scope controls, strict node/test Clippy, legacy compilation and the source audit pass. [Evidence](docs/evidence/android-ten-minute-20261009/archive-identity-reuse.json). The latest repaired-installer reference resumed the original run after 8,514,000 bytes but failed the unchanged 360-second deadline; production has not been changed. Full 42 MiB load, three actual prepared promotions and functional rollback remain required.

F5 Android preparation notifications, 2026-10-11: current `agent/` task branches now reach background preparation, while the dispatcher continues to select only exact configured source refs. Safe ASCII validation prevents ref names from changing event JSON; a per-invocation sequence preserves both notifications when multiple refs share a commit. All 55 focused release controls pass in 13.760 seconds. All 41 GC/2 runtime controls also pass, including durable replay after restart. Native inputs are unchanged by these operation edits; actual Android transfer and live timing gates remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/source-push-hook.json).

F5 cumulative credit authority, 2026-10-11: validate the exact authenticated duplicate, then issue its cumulative receive coverage under the highest received counter’s receipt authority. A delayed duplicate of an already credited frame can no longer replace a usable pending credit with a reference the sender has retired. The existing wire format, queue/counter bounds, nonce rules, persistence barrier and sender authentication remain intact. The original code fails the causal delayed-duplicate control; all 16 flow controls, 58 protocol tests, 75 minimal installer controls and strict protocol Clippy pass. The prior real Android reference failed at 360.303 seconds despite an actual 8,514,000-byte process interruption. Full 42 MiB resume/load and live promotion/rollback receipts remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/cumulative-credit-authority.json).

F5 lagging Android setup, 2026-10-11: the isolated hub retains an unconfirmed setup while the restarted installer sends a lower authenticated recovery generation. A renewed peer route now triggers local recovery above the retained floor; established sessions and unchanged routes keep their previous rejection behavior. The original runtime fails two causal controls. All 12 focused controls pass, including failed/uncertain checkpoints, preserved logical IDs/deadlines, and startup replay rejection. Retired setup request hashes are bounded to 512 and sealed to the exact session archive; older snapshots migrate, while older runtimes reject the new GCNSTO extension. The prior actual 42 MiB run failed at 360.378 seconds with zero bytes. Full Android transfer/load and live deployment/rollback receipts remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/generation-lag.json).

F5 setup archive bridge, 2026-10-11: GC/2 snapshots now retain the last 512 authenticated setup request hashes, sealed to the exact session archive. The new runtime reads existing snapshots and restores the bounded history at startup; old readers fail closed on GCNSTO. Both focused archive controls pass, including corruption, key/base mismatch, nested-wrapper rejection, trimming and channel-inbox composition. Build the managed fallback with this reader before activating recovery that depends on persisted retirement. This archive bridge permits a separately prepared runtime upgrade with compatible rollback. [Evidence](docs/evidence/android-ten-minute-20261009/setup-archive-bridge.json).

F5 Android preparation storage, 2026-10-11: the setup template now uses the measured compiler reservations (SDK/controller 3 GiB; installer/APK/hub/worker 2 GiB) and disables development/test debug data. The eight-core limit and 150 GiB workstation reserve stay intact. Immutable prepared promotions continue to verify cached bytes before activation; cold preparation remains outside the promotion clock. The existing 53 release controls and the 1,082-path source audit pass. Full Android transfer, three live timings and functional rollback still require their actual receipts. [Evidence](docs/evidence/android-ten-minute-20261009/preparation-storage.json).

F5 renewed Android setup, 2026-10-11: A retained local GC/2 setup winner now recovers through the authenticated peer’s renewed inbox/bundle instead of continuing toward its abandoned inbox. This is an explicit higher-generation recovery; pending logical IDs and original deadlines stay intact. Route/admission waits restore prior metadata without writes; an uncertain checkpoint pauses publication and restores the persisted candidate on restart. The original runtime fails the renewed-inbox reproduction. All 70 minimal-core controls, five runtime setup controls, native generation durability/failure checks, scoped strict runtime Clippy and the 1,081-path source audit pass. The prior real reference still failed at 360.719 seconds with no file bytes; full transfer/resume/load and live rollout/rollback timings remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/setup-recovery.json).

F5 bounded receipt delivery and cumulative credits, 2026-10-11: GC/2 wakes maintenance after a committed receive/credit and refills its existing sixteen receipt delivery slots on completion. The old runtime fails the 48-receipt burst before its 2250 ms periodic floor; the fix passes within 1500 ms at the real TLS/H2 fixture. A receive checkpoint now keeps one latest cumulative credit for the same authenticated peer/session, preserving other sessions and application ACKs and restoring exact prior bytes on save failure. The original full-window control queues 63 redundant credits; the fix passes both directions, failed checkpoints and restore. All 20 focused runtime controls, strict scoped Clippy and the source audit pass. Retained budgets, backoff/deadlines and GC/1 scheduling are unchanged. The actual latest Android reference still failed at 2,200,000 of 44,040,192 bytes in 360.406 seconds; full transfer/resume/load, live timings and rollback remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/receipt-maintenance.json).

F5 full-transfer qualification, 2026-10-11: each normally signed 42 MiB Android reference preserves the prepared worker prefix and adds a fresh random tail. Its content hash changes on each run, forcing the full network transfer even when the installer can reuse verified bytes from earlier admitted runs. Three focused prefix/hash/frontier/isolation controls pass. The real 8 MiB interruption, same-run resume and current-process load within 360 seconds, three prepared pushes within 600 seconds and functional rollback within 60 seconds remain pending. [Evidence](docs/evidence/android-ten-minute-20261009/fresh-reference.json).

F5 Android qualification coordination, 2026-10-11: the real reference acquires the deployment lock before changing any owner, APK or profile, and immediately refuses a competing run. Cleanup tolerates an already-collected temporary provider only after confirming that exact unit is absent; genuine service failures still fail. All 52 focused release controls and the source audit pass. Native compiler identity and cached native inputs are unchanged. The full Android reference, three live promotion timings and functional rollback remain unqualified. See [coordinator evidence](docs/evidence/android-ten-minute-20261009/qualification-coordinator.json).

Android diagnostic classification, 2026-10-10: the reviewed hosted relay workflow, its dispatch driver and its control file have a separate qualification path. Adding or changing those three exact operation files preserves all six Android native cache keys. A new unknown helper still invalidates the native cache and APK dependencies. The focused source-key regression proves both outcomes; full Android transfer and deployment timing remain separate gates.

The manual GitHub `relay-recovery.yml` workflow runs the existing isolated 64-client, 30-minute relay diagnostic on Ubuntu with a frozen GChat companion. It builds the selected source pair, retains original success/failure evidence and applies the unchanged strict latency/refusal/file/restart verifier. Supply a unique `request_id` and full `gchat_commit`; dispatch from the intended immutable GComs ref. Its read-only workflow has no signing or deployment stage. A diagnostic pass remains separate from protected release qualification and Android acceptance.

Android shared artifact cache, 2026-10-10: resolve the owned artifact output before declaring its disk reservation. The real linked cache is monitored by the workstation manager; cached artifact bytes and receipts remain bound to their original input keys. The existing compiler-cache control now covers a linked artifact root.

Android preparation, 2026-10-10: the focused installer transfer gate includes cumulative ACK batching as well as receiver validation. Preparation uses source-bound cached artifacts; full42MiB interrupted/resumed Android download and in-process load remain required before the immutable promotion starts its ten-minute clock.

Prepared Android promotion checks fresh authenticated GC/2 introductions before pushing its immutable tag. The introductions must cover the ten-minute release clock plus ninety seconds. Managed restart pins the prepared profile-owner boot through checkpoint and exit; its unlocked protocol service has a separate boot ID. Reference progress excludes old frontiers with the same worker hash and checks the saved run key against its directory. Eight focused controls pass; full Android reference and actual rollout timing remain required.

Offline checkpoint and recovery repair (F5), 2026-10-10: periodic runtime and routing saves skip unchanged logical state; explicit saves, shutdown and cryptographic transactions retain their durable barriers. Authenticated frame replays keep one exact queued ACK and can restore it after dispatch. Idle expired GC/2 sessions remain quiet; fresh durable or volatile work starts recovery only with a receiving inbox and usable peer route, without repeated generation changes during confirmation. Initial queued sends wake once when their route returns. All 537 node tests, nine runtime persistence tests and three native recovery journeys pass. All three workstation latency failures remain retained. The repaired runtime subsequently passed the full isolated hosted campaign: 64 clients for 30 minutes, all 720 authenticated commands, 2.097-second recipient p95, zero refusals, verified file transfer, relay restart and clean shutdown. The downloaded original artifact also passed the strict verifier locally. [Original failures](docs/evidence/offline-recovery-20261010/summary.json), [hosted pass](docs/evidence/offline-recovery-20261010/hosted-relay.json). Managed release qualification, full Android acceptance, combined deployment and production observation remain with the Android completion task.

The Android agent and dropship are available on main under `mobile/android/agent`; build with `-PgcomsAgent=true` and the exact prepared DS-MIN archives. The service retains one owned installer run per process, reloads private profile configuration on restart, and writes deployment readiness only after verified in-process worker startup. See `mobile/android/agent/README.md`.

Android preparation pins both Cargo final output and intermediate build storage in each component’s declared SSD cache, so a fresh workstation job can reuse checked dependency outputs. Compiler invocation identity remains part of native keys; a changed builder requires new verified receipts. Promotion uses immutable prepared artifacts.

The prepared Android lane treats the five reviewed GChat release-controller operation/test files as separately qualified operations. Changes there reuse exact native receipts; unknown build helpers still invalidate their native consumers. Android readiness remains bound to the actual full-download and in-process-load receipt.

F5 prepared configuration installation, 2026-10-10: `android_release_setup.py --install-existing` installs this lane's owned hooks/timers using the exact already-prepared config and runtime pins. It refuses active or transitioning lane jobs and does not regenerate shared compiler commands. All 41 focused release/maintenance controls and 1,056 source-path checks pass. The real Android reference remains required before production promotion. See `docs/ANDROID_AGENT_RELEASE.md`.

F5 production-owner enrollment, 2026-10-10: one-time enrollment can adopt the native desktop process holding the pinned production socket after its configured unit stopped. It checks the actual Unix peer PID/UID and retained instance, checkpoints through the owner API, and waits on a pidfd for cooperative exit before starting the headless unit. Transitioning services are preserved. Ten maintenance controls pass. Native-input exclusions now list exact reviewed operation paths; an unknown similarly named helper remains a build input. Actual enrollment and live qualification remain pending.

F5 isolated Android reference, 2026-10-10: the qualification driver requires an actual 42 MiB normally signed worker, process interruption after 8 MiB, same-run frontier recovery, unchanged identity, exact installed APK and current-process in-process readiness. Only that completed observation can update the source-bound baseline. The production preflight remains closed to initial qualification. All 39 Android release controls and source audit pass; live reference and promotion timings remain pending. See `docs/ANDROID_AGENT_RELEASE.md`.

F5 Android recovery follow-up, 2026-10-10: a replacement hub that fails before startup can restore the retained executable only after its owner completed the recorded protocol checkpoint. A live hub still requires the authenticated maintenance path. Installer preparation also runs the focused transfer and native crash/resume controls; routine promotion performs no compilation. The failed-start restoration control passes. Actual Android reference and functional rollout qualification remain pending.

F5 prepared Android promotion, 2026-10-10: source pushes request preparation; immutable `refs/tags/android-release/<prepared-id>` promote exact verified artifacts without compiling. The original server push clock reserves 60 seconds for functional restoration. The lane now includes the actual fleet controller, owner-authenticated headless checkpoint/activation, fresh rollback routing and current-process worker readiness. VPN-connected route measurements remain diagnostics; a source-bound full 42 MiB transfer/load/resume baseline is required. Live Android qualification and three real timed promotions remain open. See `docs/ANDROID_AGENT_RELEASE.md`.

GC/2 retained credit repair (F5), 2026-10-08: retries of one authenticated incoming packet retain one exact transport credit per peer. Reopening an older encrypted checkpoint coalesces identical credit deliveries before reserving the shared budget. Distinct credits, application records, durable save barriers and the 3 MiB application / 4 MiB control limits remain enforced. Admission failures now log only numeric payload and shared-node usage. The causal duplicate regression and 24 other focused persistence/recovery checks pass; this does not establish the cause or recovery of a particular deployed hub. [Evidence](docs/evidence/retained-relay-20261008/summary.json).

Offline invitation retries (F5), 2026-10-08: repeated failed publication no longer rewrites the whole encrypted profile before and after each upload. Exact saved ciphertext is reused; error status stays in memory until an ordinary save; new descriptors and successful confirmation still cross the durable barrier. Background failures back off from 30 seconds to five minutes per invitation, with four uploads at once; explicit sharing can retry immediately. All 525 node tests pass (2 explicit live/manual exclusions), including six regressions for storage rollback and stale completion guards; strict Clippy, feature checks, formatting and source audit pass. This is a source repair; the installed signed application still requires release qualification. [Evidence](docs/evidence/offline-disk-writes-20261008/summary.json).

Delayed channel receipts, 2026-10-08: candidate 170 delivered every command payload, but seven senders could not consume late authenticated receipts after newer MLS traffic exceeded the ten-generation receive window. The bounded repair retains 64 out-of-order generations, preserves the 2000-generation forward limit and replay rejection, and applies the same receive policy when saved groups reopen. This retains unused receive keys longer; it cannot recover keys already erased by an older build. Full 64-client qualification and installed delivery acceptance remain required. Validation: 46 MLS and 18 node recovery tests, strict scoped Clippy and source checks pass. [Focused repair evidence](docs/evidence/gc2-flow-control-20261008/delayed-authenticated-receipts.json).

Release harness correction (F5), 2026-10-07: independent profile preparation and readiness use four workers. Invitations and joins share one owner inbox, so they proceed in the original round-robin client order. Relay restart readiness stays bounded while delivery observations continue. The load gate and deployment reuse identical verified production relay bytes. All 48 focused harness/build controls pass. The complete 64-client, 30-minute campaign and installed delivery acceptance remain required. [Correction evidence](docs/evidence/gc2-flow-control-20261007/shared-owner-setup-correction.json).

GC/2 subscription setup, 2026-10-07: an outer setup timeout could cancel connection cleanup and leave a stalled terminal connection cached. Setup now uses the existing progress-aware cleanup at the same absolute deadline. The causal regression fails before the fix and passes afterward; all 72 transport tests and strict Clippy pass. Existing subscribers survive, the next request reconnects, and response-body timeouts preserve their connection. Public APIs, wire formats and authentication are unchanged. Separate regressions preserve a queued 268-byte payload contact across subscription expiry and authenticated session recovery. These checks do not certify the reported Android app transfer. [Repair evidence](docs/evidence/gc2-flow-control-20261007/subscription-setup-retirement.json).

Managed deployment, 2026-10-07: all 17 targets match baseline 162 and the updated release controller passed its full 16 MiB interrupted-transfer/reopen check. Controller-only updates qualify independently of native application releases; provider polling and bounded state scans avoid repeated work. GChat Android 1182 is published; iOS 1.1.82 awaits Apple's encryption review. [Deployment and remaining acceptance](docs/evidence/gc2-flow-control-20261007/candidate162-controller-completion.json).

Machine checkpoint fixture, 2026-10-07: member restart tests now restore the last successful durable checkpoint after shutdown joins workers. Historical v15 conversion happens at that same boundary. A deterministic authenticated receive after a live export reproduces MLS `SecretReuse` from the stale export and succeeds from the durable checkpoint. Both focused Linux tests pass; the signed-join, ownership, roster, epoch and 15-second delivery assertions remain. This fixes a proven fixture hazard; the original Intel failure cause and native Intel qualification remain unconfirmed. [Source-bound evidence](docs/evidence/gc2-flow-control-20261007/machine-scope-checkpoint.json).

GC/2 receive credit, 2026-10-07: one pinned TLS/HTTP2 regression now proves that a subscription with an exhausted 16-byte receive window leaves finite authenticated PUSH requests on the same connection responsive. Returning credit drains the exact retained messages in order and releases the queue and connection. The focused test passes in 0.32 seconds; independent source review also passes. No production code or API changes were needed. This narrows the server-side investigation but does not resolve or qualify the reported native-client file stall or mobile launch. See [source-bound evidence](docs/evidence/gc2-flow-control-20261007/receive-credit-regression.json) and the [client credit contract](docs/GC2_QUEUES.md).

Discovery role fixtures, 2026-10-06: candidate 154 passed native GChat qualification but exposed two discovery tests that assumed `Tp1Client` retained a physical connection after a 404. Both failures reproduce on the frozen source. These tests now retain pinned raw TLS/HTTP2 across cross-role requests and the final valid renewal, preserving GC/1 rejection, exact one/two-connection counts, terminal/control separation, bounded requests and owned cleanup. All eight discovery tests pass. Only the test fixture changes; production code, dependencies and API/wire contracts remain unchanged. The original Windows failure remains retained and a new candidate still requires native qualification. See [causal fixture evidence](docs/evidence/relay-capacity-20261005/discovery-role-test-connection.json).

Role-isolation fixture, 2026-10-05: candidate 153 exposed a test that reused `Tp1Client` after a rejected 404 while assuming the same physical connection. The client now correctly retires that pool entry. A focused baseline reproduced the failure; the fixture now retains raw TLS/HTTP2 explicitly for all three cross-role attempts, preserving rejection, unchanged queue, successful authenticated subscription, cleanup and zero-circuit assertions. All seven queue-service integration tests pass. This changes only test code; production transport behavior and API/wire contracts remain unchanged. See [causal test evidence](docs/evidence/relay-capacity-20261005/role-isolation-test-connection.json). Candidate 153 retains its failed native result and still does not qualify the release.

Relay restart recovery, 2026-10-05: unknown private paths could retain all eight unauthenticated connections for a source IP, preventing a fresh recovery connection before forwarding admission. The client now retires only the exact pooled connection on 404 without replay; existing subscribers retain their leases. The server bounds unauthenticated connections to the existing 120-second idle budget even while unknown requests continue. Authentication, connection caps, response semantics and wire/API contracts remain unchanged. Causal baseline failures and 64 passing transport/security checks plus strict Clippy are retained in [transport evidence](docs/evidence/relay-capacity-20261005/transport-unauthenticated-lifetime.json). This is a focused source fix; the new source still requires native and full fleet qualification.

Release campaign, 2026-10-05: candidate 152 admitted all 64 clients but failed after a terminal relay restart, about 20 minutes into traffic. The restarted relay accepted no further deposits; the other relays continued. The smaller terminal-restart diagnostic recovered authenticated delivery and verified the 5,235,248-byte file, but does not qualify the 64-client campaign. Preflight now restarts the receiver inbox relay, and backlog failures retain bounded recipient-versus-acknowledgment evidence without message contents. The 64-client, 30-minute, refusal, latency, file and restart gates remain unchanged. See [retained load evidence](docs/evidence/relay-capacity-20261005/terminal-restart-load.json).

Simulator grant timing, 2026-10-05: the original Apple SDK client run reached its relay test more than five minutes after fixture startup and failed with TP-1 unauthenticated 404. The test now requests one fresh card from its authenticated loopback fixture after launch; grant lifetimes, protocol authentication, Android assets and production packages are unchanged. Six fixture controls and the actual Rust helper smoke pass; fresh cards retain the listener and cleanup closes it. Native Apple qualification remains required. See [fixture evidence](docs/evidence/relay-capacity-20261005/apple-fixture-grant-timing.json).

IPC cancellation, 2026-10-05: a deterministic capacity-one transport reproduces a canceled request leaving a partial frame before the next request. The IPC writer now retains one bounded zeroizing frame and its cursor under the existing mutex, finishes its exact remaining bytes before admitting another frame, and closes the connection on a partial write error. All nine focused prefix/body cancellation, error, disconnect, read and payload-cleanup checks and strict SDK Clippy pass. Original Windows152 failed at the final `host.flush()` after archive reopen assertions; native Windows requalification remains required, and the original flush assertion is unchanged. See [retained failure and source checks](docs/evidence/relay-capacity-20261005/ipc-cancellation.json).

Explicit membership recovery, 2026-10-05: batch owner revocation now retires existing control records only for the selected leaves, in the same durable transaction. Survivor controls, ordinary message bytes and delivery acknowledgments remain intact; failed persistence restores the original controls. Already staged work stops unadmitted fragments only when its exact journal record was retired, preserving ordinary kick notices and admitted receipts. A causal regression reproduced the old 64-control backlog rejecting a fresh reusable enrollment after recovery. All 18 focused recovery and maintenance tests pass; [evidence](docs/evidence/relay-capacity-20261005/explicit-recovery-control-retirement.json) retains the causal failure. No live membership recovery is claimed.

Invitation responsiveness and pressure fixtures, 2026-10-05: creating a reusable invitation keeps channel preparation serialization and owner, policy, durable-store and 64-record checks, but no longer waits for an earlier text/presence delivery receipt. The regression holds a real first-hop reply unresolved and requires both durable creation and a full-ledger rejection to return within two seconds; admission and other command ordering are unchanged. Two restore/materialization pressure fixtures now saturate the configured scheduler data allowance instead of assuming the former 7 MiB allowance; all rejection, defer, counter and reclamation assertions remain. All six focused invitation, pressure, ordering and paired GChat controls passed; [retained receipts](docs/evidence/relay-capacity-20261005/explicit-recovery-control-retirement.json) preserve their exact source transitions. These source changes are not yet live.

Early lock validation, 2026-10-05: native CI now resolves every independent consumer lock before running the native suite. The separate mobile lock needed the same already-pinned signal dependency as the example consumer; all four tracked locks and all 16 Android/iOS client/relay, push and fixture graph combinations pass offline with `--locked`. No lock changes occur during these checks. This is dependency validation; native device, size and release qualification remain required. See [mobile lock evidence](docs/evidence/relay-capacity-20261005/mobile-lock-preflight.json).

Release portability repair, 2026-10-05: the existing outbound-only scheduler fix `9e57d2f` is reused at `09b6a0a`, and the isolated Rust consumer lock now includes the already-pinned Tokio signal dependency. The unchanged released 0.1.49 application compiles with `--locked` in IPC, embedded and network-client modes; current consumer graph checks pass and network-client still excludes relay hosting. Original Android/iOS/SDK failures are retained. Native platform qualification and SDK size measurements remain required. See [portability evidence](docs/evidence/relay-capacity-20261005/release-portability.json).

Capacity port integrated, 2026-10-05: deployed patch `5d61b75` is merged at `10a6f89`, with reviewed bounds and regression coverage at `fb8a8b5`. Default queue leases now allow 1024 cells / 16 MiB, subscription replay bookkeeping allows 4096 nonces per queue, legacy scheduler lanes allow 512 lanes / 1024 cells with 64 additional control slots, and the combined endpoint/transit scheduler budget is 64 MiB. Global byte/job bounds and shared GC/2 lease limits still apply; existing negotiated leases change only through normal provisioning or renewal. All 95 focused scheduler, queue, relay-service and GC/2 queue tests plus strict node Clippy pass. Existing wire/API contracts and the 64-member limit are unchanged. See [capacity integration evidence](docs/evidence/relay-capacity-20261005/deployed-capacity-port.json).

Live capacity, 2026-10-05: the operator reports all eight relays on the manual capacity hotfix, binary SHA-256 `a54a317de4068715512bcae2ff7512a49070c9f4421e00bb79d57019adbea21a`, with 2048 circuits and 4096 connections; the hub also has the patch. This live manual rollout remains separate from the pending managed release. Source-paired qualification, the 64-client 30-minute campaign, desktop publication and managed fleet delivery acceptance remain required. Earlier failed attempts below are retained evidence.

Automated relay qualification, 2026-10-05: the isolated fixture renews authenticated bootstrap introductions throughout setup and traffic while preserving relay identities and production lifetimes. `relay-preflight` checks two clients, a DS-sized file and relay restart before `relay-load` runs the unchanged 64-client gate. The source-bound builder accepts `--fetch` to populate dependencies only inside its retained source copy before its offline build. GChat release CI invokes the same builder and fixture automatically. Full load and live fleet acceptance remain required.

Retained channel setup coalesces an already-admitted exact ciphertext with maintenance. Invitation completion does not acknowledge delivery; the original outbox and authenticated receipt requirements still apply.

Relay load tooling: the 64-client `relay-load` campaign models the live operator fleet at 2048 circuits and 4096 connections per relay and verifies the forwarding pools before traffic. Capacity overrides are bounded by the node's existing limits. Desktop contribution budgets and the mandatory delivery, refusal, file, restart and duration thresholds stay unchanged.

Current release, 2026-10-03: SDK 0.1.98 is published with all 12 original desktop/mobile qualification archives. Its exact build inputs match qualified source 32072fe; original archive names and source labels are retained. The newer SDK 0.1.102 pointer remains available. All 17 infrastructure targets and four GChat desktop platforms are deployed or published. GChat mobile installed acceptance and SDK 1.0 remain incomplete; the 64-member limit, covered receipts and version-bound 20%/5% size policy are unchanged.

See the [immutable SDK index](https://gchat.boo/updates/sdk/f8ae216bf9016d59f17a4dad836806b5a31fbe3c4b57d35dba12d4f3f2f64852/index.json) and [current launch evidence](https://github.com/IggyGG/gchat/blob/main/docs/evidence/stabilization-20261001/launch-simplification.json). Routine releases follow an authoritative Forgejo main push automatically.

## Retained earlier checkpoints

The current release status above supersedes earlier pending matrix observations. Original outcomes and evidence remain below.

The shared native evidence policy now records the three existing explicit
64-member MLS/durable-client capacity tests under the mandatory stress.mls64
gate. Native package qualification continues to reject unknown or cross-project
exclusions; a missing capacity receipt still blocks release. All 22 policy
controls pass in both repositories. No application API or runtime changed.

The exact release SDK source 8f8fdb3 passes all four original base mobile jobs.
Three Apple combinations (client/base, relay/base and relay/push) independently
verify their provider digests, 562 source hashes and nine production libraries
each. Their native and linked size comparisons pass the approved 20% feature
allowance. Apple client/push and both Mac desktop SDK jobs remain pending.
SDK 1.0 remains unqualified and the post-1.0 5% limit is unchanged. See
`docs/evidence/stabilization-20261001/sdk-apple-8f8fdb3.json`.

The original protected Linux job for release 0.1.98 passes both full native
GChat/GComs CI commands on exact sources `52d28d7`/`8f8fdb3`. Its original provider
ZIP, both source bindings, derived Rust/npm inputs and all linked logs verify
through the unchanged qualification handler. GComs records 211 passing Python
checks, zero failed Rust checks and a successful dependency audit. The original
failed/split Linux attempts remain retained; this is a new full native pass.
Signed packaging and installed-network/fleet acceptance remain required.

The release's exact GComs revision `8f8fdb3` passes Linux/Windows SDK jobs and
all four Android role/push combinations. Independent verification retains all
six original provider ZIPs, 426 desktop source hashes per platform, 562 source
and 31 packaging hashes per Android result, 24 native libraries and the actual
16 KiB emulator/alignment evidence. All 20 desktop, 24 Android native and eight
linked APK size comparisons pass the approved 20% feature allowance. The Mac
desktop jobs remain pending. The Apple client/base job passes; its original
114,926,219-byte provider ZIP, 562 source hashes and nine production libraries
verify independently. Nine native and two linked application size comparisons
pass (maximum 11.215% growth), with matching toolchains. The remaining two
Apple push combinations are pending, so SDK 1.0 remains unqualified. See the native
policy receipt and retained `operations/desktop-8f8fdb3-verified-263.json`,
`operations/android-sdk-archives-verified-264.json` and
`operations/apple-sdk-archives-verified-277.json`.

Earlier SDK source `32072fe` also passes all four desktop jobs on Linux,
Windows, Intel Mac and Apple Silicon. Every original provider ZIP size/digest
and 426 source hashes per platform are independently verified. All 40 native
same-toolchain size comparisons remain below the approved 20% feature cap
(maximum 14.533%). Its Apple mobile jobs remain queued; no complete current-source
mobile matrix or SDK 1.0 qualification is claimed. Original failures and the
post-1.0 5% regression cap remain unchanged. See the native policy receipt and
retained `operations/desktop-32072fe-verified-225.json`.

Corrected SDK source `32072fe` now passes all four Android client/relay and
base/push emulator jobs. Full provider ZIPs, 562 source hashes and 31 packaging
hashes per result, 24 native libraries and eight linked APK size comparisons
are independently verified. The real emulator uses 16 KiB pages; alignment and
same-toolchain size checks pass the approved 20% allowance (native growth
10.07–13.59%). Apple jobs on this source remain queued, so these results do not
qualify its complete mobile matrices or SDK 1.0. Original failures are retained.
Evidence: `docs/evidence/stabilization-20261001/sdk-size-policy.json` and retained
`operations/android-sdk-archives-verified-190.json`.

Clean SDK source `1654677` now has four fully retained Apple role/push results.
Every provider ZIP size and digest, 562 reported source hashes per result and all
36 distributable native-library hashes match. The 36 same-toolchain native size
checks and eight linked application size checks pass the approved 20% feature
allowance (observed growth 8.07–11.50%). Original Android preflight failures and
overall failed mobile matrices remain unchanged; fixture static libraries were
not separately archived. All four Android role/push combinations on corrected source
`32072fe` now pass; their independent verification is recorded above. This does not qualify SDK 1.0, installed apps or the fleet.
See `docs/evidence/stabilization-20261001/sdk-size-policy.json` and retained
`operations/apple-sdk-archives-verified-175.json`.

Android SDK runs `37020911991` and `37021726565` fail before tool setup because
isolated `mobile_elf_test` cannot import `sdk_size_policy`. The test now sets its
own scripts import path; production size/security checks are unchanged. Its four
ELF controls and six size-policy controls pass independently, and full Python
passes 211 tests. L0 checks 979 paths and seven research hashes. Mobile CI now
triggers on this test's changes. The four Apple jobs in those runs succeed, but
their provider archives are independently retained and verified. Original
failed runs remain retained; corrected Android emulator qualification passes above.
No product runtime, API, limits or dependencies change in this repair. See the
[native policy receipt](docs/evidence/stabilization-20261001/sdk-size-policy.json).

The experimental `hosted-channels` profile now connects the ciphertext-only
service, durable MLS runtime, SDK/IPC and GChat. Clients enforce signed policy;
the service has no member decryption secrets. Recipient receipts stay on the
covered channel, and large channels can take longer to show delivery. An offline
newcomer sees “Topic pending” until an authorized topic writer returns.
Admission snapshot reads retain the prepared identity and pinned transcript
across up to four transport attempts, with 1/2/4-second backoff inside the same
30-second page deadline. Background routing owns recovery; admission writes and
authenticated policy refusals are not retried by this read path.

Source `1654677b3bac40977b7048ce0fe06c03fe6076e9` passes native run
`37020912213` on Linux, Windows, Intel Mac and Apple Silicon. All four backend
stages and 40 same-toolchain size comparisons pass under the approved 20% feature
allowance. Each source is clean; every one of the 426 reported file hashes on each
platform matches its committed Git blob. Full provider archives are verified and
retained. The 5% SDK 1.0 rule, original failed runs and baselines are unchanged;
see the [native policy receipt](docs/evidence/stabilization-20261001/sdk-size-policy.json).
The complete Linux workspace, Rustdoc and strict Clippy also pass on this source.
The original full CI run then fails at npm because the isolated lab has no upstream
DNS. Verified locked dependencies unblock JavaScript checks (eight tests), build,
vectors, generated files and minimal SDK/core graphs. A pinned Python 3.12 runner
with verified official registry caches now passes all 20 Rust/two npm archives,
three unchanged released-consumer feature graphs and dependency auditing in
126.30 seconds, with the original checkout unchanged. All stages are retained
separately; the original full CI failure is not relabelled as a single passing run.
These checks do not qualify full release activation or declare SDK 1.0. Mobile SDK combinations, installed acceptance, fleet activation
and a subsequent unattended release remain required.

Native Intel run `36881757477` still misses the original contact reopen deadline
with a four-block window: it receives 15 resumed blocks and makes 11 retries.
Contact files now request two blocks, leaving transport capacity for control and
receipts. General exchange remains at eight. The 30-second timer, four-ciphertext
ratchet window, 240-second phase bounds, public methods, keys and wire are unchanged.
A seven-second FIFO reproduces the four-request backlog and passes with two requests;
the earlier six-second simulation did not reproduce it and is retained separately.
The correction passes 31 file tests, strict file-transfer Clippy and the unchanged
real encrypted reopen, byte comparison and authenticated completion in 191.85
seconds total. Earlier eight/four-window evidence is preserved. Full committed
workspace and fresh four-platform native qualification remain open; see the
[request-window checkpoint](docs/evidence/stabilization-20261001/contact-request-window.json).

Full Windows worker `36863200902` retains a GC2 catalog test failure: its private
TLS origin dropped TCP without sending `close_notify`. The test origin now shuts
down its TLS stream normally after writing the complete response. Production TLS,
certificate/hostname refusals, remote DNS and bulk-body assertions are unchanged.
Both real legacy and GC2 HTTPS tests pass on Linux; fresh full Windows qualification
remains required. The original provider archive is verified and retained in the
[Windows checkpoint](docs/evidence/stabilization-20261001/windows-locked-storage-tests.json).

Verified native run `36881757477` passes Linux, Windows and Apple Silicon backend
checks and all ten size comparisons on each platform under the approved 20% policy.
Intel Mac fails contact reopen and its size phase is cancelled; the complete release
remains unqualified. The historical measurement reports also mark their source dirty
because backend evidence was written outside the ignored evidence directory. The
workflow now retains all output under `test-evidence/` and requires a clean checkout
before backend execution and after measurement, with the exact revision and a clean
measurement report. Earlier reports remain unchanged; fresh native qualification is
required. See the [native checkpoint](docs/evidence/stabilization-20261001/sdk-native-90d7eac.json).

Linux channel-service validation passes 18 tests. Its first strict Clippy
run finds an unused mutable fixture binding; that failure is retained and the
binding is corrected without changing assertions. Corrected Clippy and native
Windows full-workspace validation remain required.

Removed members independently authenticate the removal commit and its advertised
public snapshot from their prior tree and signed policy. They remain excluded
from new epoch secrets and persist an inactive channel across reopening.

IPC26 adds `sharing_v2` and `ModernFileSharing` for explicit hosted/contact file
scopes. A separate encrypted `.v2` cache preserves legacy files. Hosted offers
have their own durable consumer cursor; stable application IDs recover uncertain
publication responses. Piece transport is bulk, while completion acknowledgments
remain covered. Contacts must be explicitly registered again after reopening;
replacing that set revokes new transfer authority. File completion depends on
piece authentication, Merkle proofs and the whole-file SHA-256.

Reopening gives already durable direct application records an immediate transport
retry, using their original ciphertext, ID and expiry. This frees retained outbox
slots promptly after reconnecting; ordinary direct retry pacing remains. Neither
local restoration nor hop acceptance counts as an authenticated recipient receipt.
The complete Linux workspace and unchanged contact-file recovery pass; native
Linux and Windows backend checks pass on native workers. Mac qualification and
fresh version-bound SDK size qualification remain open in the
[reopen checkpoint](docs/evidence/stabilization-20261001/durable-reopen.json).

Hosted local mutations interrupt network waits instead of waiting behind replay
or file-piece I/O. The interrupted operation retries its retained immutable work;
this does not turn uncertain acceptance into recipient delivery. Shutdown also
cancels those waits. Read polling does not interrupt admission preparation.

File integration is undergoing end-to-end qualification. See the
[coverage ledger](docs/IRC_PARITY.md) for application, qualified 64-member and
release gates. An installed HTTPS service origin and explicit creation policy
are required; see the ledger for the deployed HEL service and exact live checks.

Owner-controlled [channel recovery](docs/MEMBERSHIP_RECOVERY.md) can revoke explicitly selected unavailable members without clearing message journals or claiming delivery. SDK/local IPC previews bind the exact membership state; ordinary authenticated ACK rules remain.

Retained file downloads query newly authenticated sources immediately and use a
bounded eight-send window; see [recovery validation](TESTPLAN.md#bounded-file-recovery-latency).
Installed platform checks remain separate from the controlled latency model.

## Immediate sending and randomized cover, 2026-09-25

Owner-approved policy: real traffic sends when transport capacity is available;
interactive cover opportunities are independently uniform 10–10,000 ms. A cover
record is skipped if that writer sent real data since the previous opportunity;
the next random interval still starts on schedule. GChat selects
new authenticated profile 46, preserving old profile meanings. This removes
intentional cover-slot waiting, not congestion or route setup. Timing/activity
privacy is reduced and unqualified. Extra bursts remain deferred. See
[traffic policy](docs/GC2_TRAFFIC_PROFILES.md) for costs, migration and limitations.
Current validation must prove immediate data/EOF, bounded cover and no catch-up
burst, cover suppression after sent data and idle resumption, old-profile compatibility, durable profile
selection, class isolation and real application delivery/recovery. R02/R03/R04
remain open until source-bound application measurements pass; prior slow/failed
runs remain failures. No deployed or installed behavior is claimed by source edits.

> Established GC/2 carriers now replace themselves on completion after at least
> 30 seconds of published readiness, without waiting for another maintenance tick.
> Failed/short-lived attempts retain retry pacing. This removes a reproduced
> owner delay; it does not yet qualify the application recovery latency target.
> See [background ownership](docs/GC2_DISCOVERY.md).

The current [reliability release requirements](docs/RELIABILITY_RELEASE.md)
define delivery/recovery deadlines, cluster validation and the subsequent graph
routing milestone. Historical qualification counts below retain their own scope.

## Protected-route error context

Recovery errors identify the failing middle number and handshake/admission stage,
or the terminal TLS handshake. These local diagnostics contain no relay addresses
or private capabilities and do not alter authentication or recovery policy.

## Local GC/2 admission diagnostics

The JSONL writer assembles each event and its newline before appending. This
avoids joining a restarted process's first event onto a complete previous event
whose separate delimiter write was interrupted. Rotation, owner-only permissions,
bounded queue and drop accounting keep their existing behavior. The observed
relay-load failure is retained and the writer's stop-boundary regression passes;
the load verifier still rejects malformed records. This avoids the observed
split-format write, without claiming arbitrary I/O or power-loss atomicity.

With the existing optional metrics sink enabled, `gchat_queue_refused` records
only `operation` (`push` or `subscribe`) and a static refusal reason. It separates
queue fullness, aggregate storage and replay capacity while retaining the same
network replies and security limits. This is local troubleshooting data, not a
delivery receipt.

# GComs

Storage tests inspect locked log bytes through their owning handle, or after
closing and reopening the normal log. This respects Windows mandatory byte-range
locks while retaining integrity, quota and real failed-write checks. Production
locking is unchanged; fresh native Windows qualification is required.

The initial feature release permits up to 20% growth against the retained
same-toolchain size baselines, as approved on 2026-10-01. Native consumers, mobile
libraries and linked mobile applications share `scripts/sdk_size_policy.py`.
SDK version 1.0 (including prereleases) automatically restores the 5% regression
ceiling. Size reports retain the policy version, ceiling and source hash. This
does not waive recovery, compatibility, signing or installed release gates.

The [stable contract preparation](docs/STABLE_CONTRACTS.md) defines the supported
application facade and the remaining SDK 1.0 gates. Native CI compiles the exact
released 0.1.49 consumer in all three feature graphs. Contact file sends now retain
up to eight actual transport attempts within a shared 128-action queue; slow sends
and control interrupts cannot start a second attempt before completion. No new
dependency, IPC layout or hosted-member limit is introduced.
Legacy direct sessions keep encrypted data and control frames in one FIFO lane
so priority changes cannot skip a DH epoch during reopening. GC/2 credited
sessions preserve separate bulk and interactive traffic, including retained
retries. Keys and authenticated receipt requirements are unchanged.
Legacy sessions retain later durable application records as plaintext in the
encrypted outbox while four ciphertexts await recipient receipts. Each receipt
releases capacity without moving the original deadline or advancing a deferred
record's ratchet counter. GC/2 keeps its existing credited send window.

IPC count/write now share bounded zeroizing storage, and clients link the codecs
for their message directions. Hosted HTTP replies borrow their JSON envelopes,
including nested records, through one byte-slice decoder. Struct variants retain
object-only bodies while newtype structs retain their original sequence support;
wire bytes, public reply shapes, bounds and dependency versions remain unchanged.
Native CI retains failed backend/size logs and measures isolated consumers even
when backend tests fail. A separate source/attempt-bound backend log archive
uploads before the long size builds so failed recovery can be diagnosed promptly.
The current Linux IPC reduction still exceeds the
original 5% size ceiling; those historical failures remain unchanged under the
new approved policy. See the [codec checkpoint](docs/evidence/stabilization-20261001/sdk-codec-size.json).
The [JSON follow-up](docs/evidence/stabilization-20261001/sdk-http-json-size.json)
retains the original conformance failure, its corrected SDK/consumer checks and
the still-failed size ceiling. SDK 1.0 remains gated on native acceptance.

Rust applications start with the [`gcoms` application API](crates/application/README.md):
one dependency for messaging, channels and files. Select `network-client,files`
for a standalone client, `embedded,files,gc2-carrier` for a built-in relay, or
`ipc,files` for the smallest consumer of an existing local host.
RPC and automatic daemon launch are optional. GChat consumes the same API.

The [combined release-branch receipt](docs/evidence/sdk-release-integration-20260921/summary.json)
records the SDK merge with GChat-specific channel, persistence and platform fixes;
existing native artifact receipts retain their original source bindings.

The Linux workspace passes 910 tests (seven explicit ignores), and GChat passes
137 tests against the shared API. Native tests and size checks pass on Linux,
macOS ARM64/Intel and Windows x64 MSVC. [Measured consumer sizes](docs/RUST_INTEGRATIONS.md).
Android/iOS client and relay SDKs are qualified as an emulator/simulator preview.
See [mobile packages and measured app additions](mobile/README.md).

Mobile packages include separate optional app-operated push-hint adapters.
Physical-device, battery and live-provider qualification remains deferred;
[PLAN.md](PLAN.md) records the completed preview scope.
The `network-client,files` feature set adds a self-contained outbound protocol
client. Select `Backend::NetworkClient` when combining it with `embedded` in one
build. It hosts its inbox on remote relays and excludes local queue hosting,
forwarding and NAT mapping from a client-only build. Existing embedded and IPC
feature combinations retain their behavior. The SDK's `in-process` feature is
the shared adapter; `embedded` additionally enables relay hosting.

Background guard renewal uses bounded retry backoff when authenticated replies
have not yet supplied enough fresh independent relays for a five-hop route. A
fresh entry alone is not reported as a usable route; application requests do not
trigger additional entry dials.

Routed profile reopening retains expired inbox authority privately for background
recovery. Public addresses respect the sealed owner lifetime even when a renewed
lease carries a later timestamp; this never extends the original saved budget.
Recovery replaces the complete saved owner-role collections rather than appending
them to live state, so retained draining queues remain unique across reconnects.

When a protocol checkpoint fails, bounded local diagnostics distinguish encoding,
store failure and the first owner-lifecycle pause site. Uncertain persistence still
pauses the owner; these diagnostics do not authorize retry or confirm delivery.

An in-process application can opt into `durable_channel_inbox(true)` before
receiving starts. Channel and channel-private plaintext is sealed with the
receive checkpoint before acknowledgment; the archive owner explicitly consumes
each saved record. The inbox is bounded to 256 messages and 4 MiB and rejects new
receives at capacity without advancing their ratchets. File pieces retain their
separate journal. Shared/attached IPC clients cannot silently opt into ownership.
Enabled profiles use the `GCNSTM` checkpoint wrapper, which requires a compatible
reader and rollback binary; older binaries cannot read it.

**GComs** is a Rust communication protocol for secure connections, with typed
service APIs for addon and client integration. **GChat** is its separate reference
application, with a desktop UI, terminal UI and local service.

Development and release authority remains in the existing local Forgejo repository.
Public delivery uses [IggyGG/gcoms](https://github.com/IggyGG/gcoms) and
[IggyGG/gchat](https://github.com/IggyGG/gchat) as GitHub mirrors.
The first signed release is being prepared for Linux x86_64, Windows x86_64,
and macOS Apple Silicon/Intel. See [release preparation](docs/RELEASE.md).

## Start here

- [Typed services and addon integration](docs/TYPED_SERVICES.md): shared Rust traits,
  generated clients, TypeScript and Rust/WASM browsers, durable operation handles.
- [Private piece exchange](docs/PRIVATE_FILES.md): resumable, encrypted multi-source file transfer.
- [Isolated GChat capture calibration](docs/GCHAT_CLIENT_CAPTURE.md): actual-daemon
  observation and validity checks, separate from privacy and fleet qualification.
- [SDK](crates/sdk/README.md): embedded runtime or capability-scoped local IPC.
- [Runnable addon](examples/typed-addon/README.md): one contract and multiple clients.
- [Implemented protocol profile](SPEC.md), [architecture](docs/ARCHITECTURE.md),
  [compatibility](docs/COMPATIBILITY.md), [security](SECURITY.md).
- [Build and test](TESTING.md), [contribute](CONTRIBUTING.md), [license](LICENSE-MIT).
- [Repository ownership and source integration](docs/REPOSITORY_STRUCTURE.md),
  [relay research](docs/RELAY_RESEARCH.md), and the
  [GC/2 implementation ledger](docs/GC2_IMPLEMENTATION.md).

After package publication, a native client can depend on:

```toml
[dependencies]
gcoms-rpc = "0.1.0"
# For low-level messaging without embedding a node:
gcoms-sdk = { version = "0.1.0", default-features = false, features = ["ipc"] }
```

The same service trait generates Rust clients and dispatchers. Calls cross an
explicit transport: in-process dispatch, a local socket/named pipe, authenticated
GComs peers, or a browser HTTP gateway. A call can fail after its remote effect;
operations expose durable status and resume rather than silently repeating work.

## Repository layout

| Location | Responsibility |
| --- | --- |
| `crates/core`, `protocol` | Wire framing and portable codecs |
| `crypto`, `mls`, `transport`, `routing`, `gossip` | Encryption, groups and network transport |
| `node`, `network`, `network-client`, `catalog` | Runtime and operator-configured discovery |
| `sdk`, `file-transfer`, `private-fs` | Application integration and local storage boundaries |
| `rpc-contract`, `rpc-macros`, `rpc` | Typed service contracts, generation and runtime |
| `packages/gc-rpc`, `packages/rpc-codegen` | `@gcoms/rpc` runtime and build-time code generator |
| `conformance`, `sim`, `fuzz`, `examples` | Fixtures, models and development tools |

GComs does not embed a production network or a Ghost deployment. Hosts supply
network trust and local authority policy. Ghost fleet, recorder, machine-agent,
managed command and installer implementations remain in their private repositories.
Historical reserved wire identifiers do not imply those implementations are present.

## Build

Rust 1.98, Node 22 and npm 11 are the tested toolchain baseline. From this checkout:

```sh
cargo test --workspace --all-features -- --test-threads=1
npm ci --ignore-scripts
npm run generate
npm run check
npm test
npm run build
```

Native libraries and target prerequisites are described in TESTING.md. Development
adds `proc-macro-crate` for dependency-alias-aware macros, and `libfuzzer-sys` in the
isolated fuzz workspace. Ajv belongs only to `@gcoms/rpc-codegen`; the packaged
JavaScript runtime has no runtime npm dependencies.

Dual licensed under **MIT OR Apache-2.0**. Attribution and dependency terms are in
[NOTICE.md](NOTICE.md). Naming changes do not change GC/1 wire bytes.

The preview pins rustls >=0.23.45 and quick-xml >=0.41 for current advisory fixes,
uses rustls-pki-types' PEM parser, and disables unused postcard heapless defaults.
`deny.toml` records exact transitive-version exceptions and one reviewed build-time
unmaintained hax/libcrux macro dependency; it does not waive runtime vulnerabilities.

The application/runtime consolidation reuses existing dependencies; `sha2` derives
a purpose-specific host cache key. TLS fixture dependencies (`rcgen`, `rustls`,
`tokio-rustls`) are test-only in the runtime. No new third-party package is added.

All three Rust variants are tested natively on Linux x86_64, macOS arm64/x86_64
and Windows x64 MSVC.
Measured sizes and exact validation inputs are in [the Rust integration report](docs/RUST_INTEGRATIONS.md).

Inbox replacement completes after both new queues and peer updates are committed.
Peer notifications remain in the encrypted outbox and use the bounded direct
maintenance retry schedule; an unavailable peer cannot hold inbox installation
open. Relay acceptance still does not imply peer delivery.

## Five-relay carrier update — 2026-09-23

The shared experimental GC/2 application carrier requires an entry, three independent middles and a terminal inbox. It defers delivery when a complete route is unavailable. This is a client routing change; live fleet rollout and minimal payload integration are not yet qualified. Offline validation is recorded in test-evidence/gc2-five-relay-20260923/verification.json.


## Transfer recovery — 2026-09-23

Accepted downloads retain verified pieces and resume automatically after restart or temporary conversation membership loss. No requests or incoming pieces are accepted without current authorization. Explicit pauses/cancellations remain stopped. Reopening repairs the older automatic membership-pause marker; other errors keep their existing recovery behavior. Transport completions continue to arm retries while files are disabled or roster refresh fails.

Validation: 51 component tests passed, two existing qualification tests ignored, including an overnight restart at 80% and a send completion delivered while locked. Evidence: `test-evidence/file-resume-20260923/verification.json`. Android live recovery remains pending; these gates do not establish fleet end-to-end acceptance. No new dependencies.

Release file checks use a bounded 16 MiB interrupted transfer; the 1 GiB campaign runs separately. See [reliability requirements](docs/RELIABILITY_RELEASE.md).

Manual channel reconnect codes use separate MLS ciphertext from background
directory announcements. They are shared out of band, after the send state is
durably saved; automatic delivery cannot consume a code before it is pasted.

Protected subscription recovery fixtures use the current responsive profile 46
on Linux, both Mac architectures and Windows. The optional Rust integration
workflow diagnostic retains redacted local dispatch/count evidence; it does
not qualify installed artifacts or change production timing constants.

Hosted recovery prefetches at most 16MiB of encoded record data and checkpoints
short replay batches before every yield. Listings and bounded file-inbox reads
use the last healthy durable view during network I/O; signed presence still
expires locally at its original deadline. Consumer commits can interrupt network
waits after the application has saved its archive. This keeps recipient ACKs
behind durable consumption while reducing repeated full-state writes.

Hosted files use a two-piece upload/download window. Immutable authenticated bulk
requests release the mutable channel owner while in flight, so covered recovery
and chat can progress. The runtime bounds bulk concurrency at two and rechecks
current local membership and upload authority before exposing results. Shutdown
cancels pending bulk requests; retry uses the same piece identity and ciphertext.

Replay batches check a 75ms scheduling budget between records before saving and
yielding; a cryptographic operation or storage write may add to that interval.
The durable capacity driver reports checkpoint counts so write reduction can be
measured alongside responsiveness, without changing any receipt or policy check.

IPC26 preserves released IPC22 owner-recovery and IPC23 invitation tags, and appends
hosted channels and modern files. Their distinct capabilities require IPC26.
The conflicting, unpublished task IPC24/25 dialects are refused at negotiation;
existing supported legacy clients retain their versioned operations. Hosted
profile archives and service HTTP wires are unchanged by this IPC integration.

Hosted recovery now prefetches at most two immutable deferred records at once,
within the existing 16 MiB batch limit. It preserves sequence, scoped proofs,
hash/MLS validation and checkpoint-before-yield behavior. Live owners release
the temporary sealed session buffer after saving or restoring; the encrypted disk
archive and its compatibility rules are unchanged. Updated runtime and actual
application recovery qualification are in progress; previous timings retain their
source bindings.

Production relay operators can explicitly budget aggregate forwarding capacity
with `gcnode serve --relay-circuits N --relay-connections N`; ordinary defaults
and per-client/source security bounds remain unchanged. See the
[node operator capacity contract](crates/node/README.md#operator-relay-capacity).
This option requires workload qualification and is not itself a 500-user claim.

GC/2 forwarding now honors that circuit budget, reserves the last slot for
interactive traffic, and waits at most one second for admission. Desktop hosts
can contribute reachable relay capacity using the optional
`ApplicationBuilder::relay_sharing(RelaySharingConfig)` configuration. The
provider verifies membership, a service-key signature and the public listener
before advertising a short lease; DNS naming is independent. See
[relay contribution and qualification](docs/RELAY_SHARING.md).

The isolated production-bootstrap fixture uses five independent relays, matching
the GC/2 route length. Recovery keeps its 120-second stage deadlines and reports
transport state when a stage fails. The bootstrap API also exposes the 24-hour
contact-lifetime bound required by the newer Drone companion; relay-admission
proofs retain their five-minute bound. See [bootstrap validation and paired-worker
checks](docs/GC2_NETWORK_BOOTSTRAP.md#bootstrap-fixture-and-companion-validation-2026-10-06).

The opt-in Android agent supports a bounded Kubernetes release lane with an isolated lab runtime, alongside the retained workstation adapter; see
[Android agent releases](docs/ANDROID_AGENT_RELEASE.md). Its 600-second deadline
starts at the original Forgejo push. Successful installation alone does not
qualify downloaded worker readiness.

[Android deployment measurements](docs/evidence/android-ten-minute-20261009/summary.json) retain cold preparation, actual cache reuse, signed APK installation and the original server push clocks. The full download/load gate remains failed; the shared controller baseline currently prevents main integration of the standalone operations files.


F5 Android bulk dispatch (initial eight-record implementation, 2026-10-11): GC/2 single-cell volatile file sends preserve
preparation and scheduler-admission order while owning independent hop completions.
Interactive, legacy, setup and durable sends retain their existing completion order.
The 64-record volatile outbox reserves eight global slots for control and separates
the existing eight-record peer allowance by authenticated record kind for credited
sessions. No retained byte budget, expiry or authenticated file credit increases.
Registered bootstrap IPC connections admit at most eight authorized file submissions
concurrently. Admission state remains on the connection owner; replies keep their
request IDs, partial request reads survive completion/event writes, and disconnect
or host shutdown cancels the owned calls. Other request types keep their dispatch.
Focused causal controls cover held TLS replies, retained queue boundaries and failed
checkpoint restoration, IPC admission/component separation, bounded inflight work,
reply matching/cancellation and partial frame reads. The original node fails all
three new regressions and the corrected node passes them. The original SDK fails its concurrent-dispatch regression; all 15 focused SDK
controls, strict combined node/SDK Clippy, non-GC/2 node and IPC-only builds pass.
The 1,088-path source audit passes. Android reference validation is in progress; this does not qualify the full 42 MiB transfer or a
production promotion. Evidence: `docs/evidence/android-bulk-dispatch-20261011/summary.json`.

F5 Android credit alignment, 2026-10-11: authorized bootstrap IPC and each credited
GC/2 peer can now carry 32 application records, matching the Android receiver's
authenticated chunk window. Each peer retains eight control records, the node
retains its 64-record total with at most 56 application records, and existing
payload, session and scheduler byte budgets still apply. Legacy peers keep their
eight-record limit. The controller continues reading ACKs while submissions wait.
Four focused held-receipt/boundary controls, strict scoped Clippy and the
non-GC/2 compile pass. Full signed Android interruption/resume/load and real
deployment/rollback timing remain required. Evidence:
`docs/evidence/android-recovery-credit-20261011/summary.json`.

Android activation now pins ownership of its fresh minted profile and cancels
that profile through the normal controller API on failed qualification or
rollback. It retains original failed clocks and reports cancellation errors.
All 58 focused release controls pass; live transfer and deployment timing
remain separate acceptance gates. See `docs/evidence/android-profile-cancellation-20261012/summary.json`.

GC/2 direct maintenance can repair an exact retained counter after the
existing jittered five-second backoff when authenticated receipt coverage
proves that a later counter arrived while it remains missing. Unknown delivery
outcomes retain the original sixty-second fallback. This changes retry
selection without granting counter credit, re-encrypting bytes, changing
traffic class or extending original deadlines. Focused maintenance/flow
controls and strict Clippy pass; live Android throughput remains separate.
Evidence: `docs/evidence/android-selective-gap-repair-20261012/summary.json`.

The image-pull deployment in `release/android-cluster/image-pull.json` exposes authenticated GET/HEAD requests for exact image digests in the three Android release repositories. It streams the existing FSN registry with buffering disabled and 32 MiB scratch; OCI recovery stays in FSN1 S3. Supply `android-image-pull-auth` with an operator-generated htpasswd entry and matching `android-release-registry` dockerconfigjson Secret out of band. Configure `cluster.image_pull_secret` and use the TLS hostname with the unchanged SHA-256. The pinned NGINX binary requires its existing NET_BIND_SERVICE file capability. Registry credentials are used by the kubelet and never mounted in compiler containers.

The server outbox deployment is declared in `release/android-cluster/server-outbox.json`. Install its ConfigMap with `android_release_outbox.py` and an `outbox.json` archive configuration, plus the image-pull and archive Secrets out of band. The Forgejo post-receive hook writes only `/data/android-release/outbox`; retain the existing generated Forgejo hooks and add the Android hook alongside them. The forwarding Pod shares the Forgejo PVC only at that subdirectory, stays on its node, and has outbound DNS/public HTTPS only. Preserve S3 receipts during operational compaction; they carry the original push clock.
Retained route recovery fairness (F5), 2026-10-13: a full channel control outbox no longer prevents other retained channels from recovering. Process-local cursors rotate both channel and prepared-join batches while retaining the existing four-attempt bounds; per-channel deferrals preserve exact controls and partial fanout, and durable checkpoint failures still pause the owner. A pinned loopback/MLS regression fails on the original code; both new controls, 453 node tests (two existing explicit exclusions), strict Clippy and the client-only feature check pass. Signed release and actual installed delivery remain pending. [Source evidence](docs/evidence/durable-host-20261013/channel-recovery.json).

Retained-channel backpressure (F5), 2026-10-14: restored, durably committed queues
can receive authenticated traffic while their outgoing control queue is full.
Receive readiness binds the exact descriptor and alias authority; announcement
completion remains separate. Authenticated directory updates retarget existing
controls without admitting another reply, while storage failure still rolls back.
Both original blockage mechanisms fail causal controls; the repaired full node
suite passes 459 tests with two existing explicit exclusions, strict Clippy and
client-only feature checks. Signed retained-peer acceptance remains required.
[Source-bound evidence](docs/evidence/durable-host-20261014/channel-backpressure.json).
