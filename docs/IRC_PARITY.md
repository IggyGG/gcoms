# Classic IRC parity implementation ledger

Owner: Codex, 2026-09-29. User authorized implementation of the comparative
analysis and plan. Initial published sources: GComs `979aeb9`, GChat `6daf481`.
The GComs task also preserves the canonical checkout's `0c2c704` bootstrap fix.

## Accepted constraints

- Native feature equivalence with classic IRC; no IRC gateway or bridge.
- Contacts only: independent private conversations without a public user directory.
- Qualify 500 independent channel identities, including offline members and churn.
- Hosted channels may use an always-online sequencing service, but it must not
  possess MLS member secrets or decrypt chat. Clients verify admission authority.
- Keep private creation and optional presence as defaults. Keep existing profiles,
  archives, scopes and security checks. A capability bit or UI button is not proof.
- Preserve service acceptance versus recipient acknowledgment, durable operation
  recovery, exact-source receipts and state-compatible upgrade/rollback checks.

## Work and acceptance ledger

| ID | Deliverable | Status | Decisive acceptance |
| --- | --- | --- | --- |
| IRC-1 | Versioned hosted MLS admission and ciphertext coordination | In progress | Real PQ-suite external joins with owner offline; forged/expired/replayed authority denied; service has no decryption state; legacy policy isolation |
| IRC-2 | Ordered persistent recovery and service integration | In progress | Concurrent joins and crash/reopen converge; offline recipients do not block admission; no false delivery or loss of accepted records |
| IRC-3 | Channel policy, operators, voice, moderation, bans/exceptions, keys, limits, discovery | In progress | All admission and message paths enforce policy against modified clients; grant/revoke and rekey persist |
| IRC-4 | Contacts and independent direct conversations/files | In progress | No shared channel required; leaving a former shared channel preserves the contact conversation; block and identity continuity |
| IRC-5 | Authenticated activity and richer presence | In progress | Actor/target/reason ordering; away/back/unknown/invisible; optional sharing; snapshot polling loses no events |
| IRC-6 | Notices, blocking/muting, highlights, formatting and client workflows | In progress | Same actual service-backed behavior through desktop/TUI/shared mobile UI; no automatic notice loops |
| IRC-7 | Operator workflows and supported bot integration | In progress | Scoped authorization, rate control, network/channel authority separation, executable bot example |
| IRC-8 | Capacity, compatibility and release qualification | Pending | 500 real identities; ten concurrent senders; churn/offline/file traffic; timing/resource evidence; profile-preserving upgrade |

The classical mode equivalents include +o/+v/+m/+b/+e/+I/+i/+k/+l/+t and
private/secret discovery; member-authenticated sending (+n) remains mandatory.
Public catalogs are distinct from user discovery. Network-wide WHO/WHOIS/WHOWAS
become scoped contact/member information, and hostname masks become identity and
admission controls. Obsolete host-login inquiries and raw IRC server syntax are
not requirements. Existing history, actions, files, navigation and daemon behavior
must remain working.

## Implementation sequence and proof boundaries

1. Prove the configured OpenMLS external-commit path behind a separate hosted
   profile; do not weaken the legacy owner-admission profile.
2. Implement signed policy and ordered ciphertext storage with a service that
   cannot grant itself private membership. Member clients perform MLS changes.
3. Connect the same contracts through node/runtime, SDK/IPC/network-client and
   GChat; add contacts, policies and client behavior with generated bindings.
4. Run adversarial, persistence, cross-client and 500-member qualification; keep
   local/source, native, installed and live-provider evidence distinct.

Mandatory healthy-network targets retain the existing reliability requirements:
200 ms feedback, 5 s online delivery/ACK, 30 s joins and 10 s recovery, with the
documented prerequisites. Physical mobile/live push remain separate from existing
emulator/simulator qualification. No feature is complete merely because a test
compiles, a mocked view displays it, or an older artifact passed.

## Worktrees and continuation

### 2026-09-29 admission checkpoint

Implemented opt-in `gcoms_mls::hosted`: signed genesis policy, public admission,
private epoch/leaf/name/expiry-bound permits, member and public-observer validation,
atomic staging of commit plus GroupInfo, and sealed client restart including
pending service acceptance. GroupInfo is pinned to the public state derived
from accepted commits. No service-held member secret is used. Configured
PQ-hybrid suite is preserved.

The regression reproduced a legacy authorization hole: a valid external commit
had no Add proposal and was accepted without owner invitation (`epoch=1`,
`roster=2`). Legacy receivers now reject non-member senders. The original red
result is retained in `test-evidence/irc-parity/mls-01.log`. The subsequent
`mls-03.log` records 34 passes and one existing explicit slow-test ignore.
Validation ran in a dedicated cluster pod after local disk reservation refused
the build. Missing image vendor dependency `futures-macro` was supplied from a
cached archive verified against the unchanged Cargo.lock checksum. Initial
compile/setup failures remain retained. `codematch=unreachable` (no tool exposed).

IRC-1 remains in progress. Hosted APIs are not yet enabled in production clients.
No claim of complete policy, service, contact, GChat or 500-member coverage.
Next: source-bound strict checks and checkpoint, followed by durable ordered
service storage and the application-facing integration.

### 2026-09-29 ordered-storage checkpoint

Added `gcoms-channel-service`, a library with an exclusively locked, bounded,
checksummed append log. Public membership validation and signed ciphertext
validation precede fsync and acceptance. Restart reconstructs public state,
checks sequence/predecessor hashes, preserves exact retry receipts, truncates
only incomplete tails, and fails closed on complete-record corruption. Real
write failures poison the instance until reopen. Accepted data is never evicted
to satisfy a quota. The library does not expose a network endpoint.

Hosted messages authenticate their service-visible sender/epoch/ciphertext.
Clients independently check the encrypted MLS sender on a speculative state
copy, so a false outer sender cannot consume the real sender's ratchet. Genesis
now follows one normal owner self-update (epoch one), removing the expiring
KeyPackage leaf from the long-term replay anchor. The expired-leaf negative
control rejects the un-updated tree while the updated anchor verifies.

`service-04.log` records 40 passes, one prior explicit slow ignore and strict
MLS/service Clippy. The first storage run correctly rejected non-private test
directories; fixtures now explicitly use shared private-filesystem setup.
A separate 500-real-identity/ten-concurrent-sender MLS test has been added for
explicit release execution. It is not application, network or native-platform
qualification. Remaining: service transport/reader authorization, shared client
integration, dynamic policy, contacts and all outstanding ledger rows above.

### Reusable private admission

`HostedAccessCode` keeps the reusable signing secret exclusively in clients;
policy publishes only its verifier. The proof is specific to an epoch, policy,
leaf, name and expiry. A captured proof is not a reusable bearer secret for the
service. Private joins work with the creator absent, and a concurrent refused
join can retry at the next epoch with the same signing identity. Secret imports
validate that the public/private key halves match and temporary exported bytes
are zeroized. `access-code-01.log`: 41 passes, two explicit scale-test ignores,
strict Clippy for MLS and storage. Ordered key rotation and remaining policies
are still pending; GChat has not been changed yet.

Both components are siblings under GComs `.worktrees/irc-parity/`. Work only in
those checkouts. GChat's original canonical lockfile and `.cargo/` are preserved.
Use the configured `origin` remote (the local Forgejo) for branch checkpoints.
Run CPU-heavy gates through `workstation-batch`/the Cargo shim and retain decisive
evidence on SSD. Update this ledger at each implementation/validation checkpoint.

### Ordered policy and component capacity checkpoint

Signed controls now enforce independent operator/voice flags, moderated posting,
bans/exemptions/invite exceptions, rotated access codes, capacity, discovery and
ownership transfer in both the public service and member receivers. Encrypted
reasons cannot change authority or consume an unrelated sender ratchet. Permits
bind the policy revision, preventing a prepared join from bypassing a later ban.
The former owner's root cannot issue admission after transfer; current operators
can issue leaf-bound invitations. Departure and rekey implementation follows.

`policy-05.log` passed 46 tests with two explicit scale exclusions and strict
Clippy; `policy-06.log` adds independent operator/voice checks (three policy tests
and strict Clippy pass). The release component test on bca003b passed with 500
real members, ten concurrent senders and 4,990 authenticated receives. Sequential
admission took 1,837.441 seconds; total execution took 1,985.29 seconds. Maximum
GroupInfo was 1,327,768 bytes and commit 21,816 bytes. This is component capacity
evidence, not network, application, latency or current-policy qualification.

### Departure, rekey and message classes

Kick/leave controls now block all new encrypted content until a member commits
the authorized removal set. Any remaining member can finish the rekey, including
an authorized newcomer while existing members are offline. Member and public
validators reject invented removals and stale policy AAD. Pending rekeys survive
sealed restart, exact acceptance gates merging, and competing accepted admission
clears speculative work safely. Rejoining preserves scoped identity and bans,
clears old roles, and counts only active members against capacity. Internal
unclean leaves have a separate bound. Removed clients become inactive.

Signed message classes distinguish text/action/notice, topic, nickname, presence,
receipt, file and contact offer. Kind is bound inside and outside MLS; relabeling
cannot bypass receiving-client permissions or consume a valid chat ratchet.
Topic permissions are independent of moderation, and unvoiced members can ACK.
Application rendering, typed payload interpretation and automatic receipt logic
still belong to the remaining client integration.

`application-01.log` passes 51 tests with two explicit scale exclusions plus
strict all-target/all-feature MLS and channel-service Clippy. The earlier removal
run's duplicate-name fixture failure is retained: the honest join helper had
started refusing the attack before the negative service/member checks could run.
The service/member negative-control coverage is preserved in the corrected suite.

### Hosted service transport and durable client checkpoint

The ciphertext service now has a versioned, bounded HTTP upstream API suitable
for an installed TLS origin. Creation is denied by default; an operator must
configure a channel allowlist or explicitly enable public creation. Read proofs
bind channel, scope, query and expiry. Admission snapshots contain public
membership/policy only; message records require current or bounded historical
member authority. Removed clients can read through their removal record after
restart, never later records. Single-use invitation verifiers are consumed by
accepted membership commits, separately from reusable admission codes.

SDK IPC22 appends HostedChannels authorization and typed client operations.
Signed network defaults supply endpoint candidates. Catalog routing retains
origin restrictions, remote DNS, WebPKI verification and no direct fallback.
Large public trees/records use the existing observable bulk class; small chat
and polling retain the covered class. The user selected covered receipt traffic and slower delivery status for large
channels (2026-09-29). 499 individual 64-byte signatures already exceed eight
seconds at 4 KiB/s, before framing. Large-channel acknowledgement latency is
therefore measured separately from message acceptance/delivery; receipt traffic
will not switch to observable bulk to meet the previous five-second ACK target.

The opt-in runtime client stores MLS state, exact pending wires, invitation
secrets, ordered cursor and unarchived application events in a separate encrypted
sidecar. Uncertain transport responses retry exact wires. Explicitly refused
stale operations replay current ordered state before being rebuilt. Competing
admissions retain their signing identity. A failed checkpoint poisons the live
client until disk state is reopened. Applications must archive events durably
before CommitEvents. Service acceptance remains distinct from recipient delivery.

Validation retained locally: `shared-api-02.log` routing 3/3 (including 2 MiB in
both directions through legacy and GC2); `shared-api-03.log` SDK 68 and network
client 17; `shared-api-clippy-01.log` corrected strict routing/SDK/network/client
facade check. The initial package-name typo and credential-boundary fixture
failures are retained. `hosted-api-final-01.log` validates service admission,
reader boundaries, single-use invites and strict MLS/service checks. Runtime
`runtime-client-04.log` passes four real-service recovery/storage tests and
strict runtime/SDK/application checks. Subsequent edits require a fresh gate.

Remaining: GChat integration, generated contracts, actual recipient receipt
aggregation, all independent-contact/file/block behavior, completed client
workflows, operator/bot experience, and full application/network/native release
qualification. The optional runtime API is an implementation checkpoint, not an
IRC-parity release. There is no automatic migration of legacy channels or PMs.

`runtime-client-05.log` validates the refreshed source, including atomic invite
secret storage: 127 tests pass, two explicit scale ignores, strict
MLS/service/runtime/SDK/application checks. The source-bound receipt is
[retained here](evidence/irc-hosted-client-20260929/summary.json).

### Covered recipient receipts and GChat archive checkpoint (in progress)

The receipt implementation now uses a separate sender-scoped append log with
recipient signatures bound to channel, sender, recipient and exact accepted record.
Batches stay on the covered endpoint. Application event commit gates receipt
publication; the sender retains the original expected recipient set and only
reports delivered after every required signature verifies. Restart/lost-response,
query-scope and forged-target regressions are being added; this paragraph is an
implementation checkpoint, not a passing qualification claim. Runtime archive v2
reads the original v1 layout and adds receipt state; older runtimes reject v2
rather than discard pending receipts. Legacy profiles are unaffected.

GChat now has opt-in hosted commands and shared API v3 projections, with a separate
encrypted hosted-history sidecar so old clients cannot overwrite its committed
cursor. The application uses the same runtime SDK through desktop/TUI; generated
contracts, typed action/notice display, IRC formatting, member roles, presence and
operator information commands are included. Full IRC-4/IRC-8 qualification remains
open, as do encrypted new-member topic recovery and the remaining client workflows.

The follow-up `receipt-02.log` passes six runtime tests, fourteen service tests,
three GChat hosted archive tests, and strict paired GChat workspace Clippy.
`receipt-01.log` retains a harness PATH failure before any compile. Source hashes
for this run are retained in `test-evidence/irc-parity/receipt-source-01.json` in
both worktrees. Presence renews only after explicit opt-in, with a ten-minute
lease and seven-minute renewal interval to bound idle large-channel traffic.
Presence updates do not require per-recipient receipt fanout. Opt-out persists
before sending and retries its invisible update after pending work clears.
Available/away is an advertised state, not proof of an active connection.
Further receipt-log corruption/quota checks and the full updated GChat suite are
running separately; end-to-end network latency remains unqualified.

User decision: newcomers show **Topic pending** when all existing members are
offline; invitation links carry no extra metadata key. The encrypted topic
handoff is sent by a member currently allowed to change topics after replaying
through the new admission. It only fills unknown topic state and cannot overwrite
an already observed topic update. With operator-only topics, an authorized
operator must return before that handoff is available. The service retains only
ciphertext. Runtime archive v3 retains the v1/v2 decode path and persists this
explicit pending state. New handoff/restart/authorization/race checks are pending.


### Topic handoff and independent-contact checkpoint

`topic-01.log` passes seven hosted runtime recovery tests and three GChat archive
checks. The offline newcomer remains pending through restart; an unauthorized
member cannot hand off an operator-only topic, and a stale handoff cannot replace
an observed topic update. `receipt-04.log` passes strict GComs checks and the full
pre-contact GChat Rust suite (176 passed, three existing explicit ignores).

GChat independent contacts use explicit signed-card exchange, local aliases and
fingerprint verification. Stable application IDs, exact-content receipts and a
separate encrypted `.contacts` archive preserve retries without linking legacy
channel identities. Receiver storage precedes durable-inbox commit and receipt
publication. Blocking stops new submissions and suppresses inbound application
replies; already admitted transport copies cannot be recalled. Card imports have
a separate 192 KiB bound; ordinary chat input limits remain unchanged.

The actual two-instance, no-shared-channel test passes in `contacts-06.log`, with
receipt/deduplication and rollback-isolation unit checks and strict GChat Clippy.
That run subsequently found a GComs Clippy range-pattern warning; the corrected
GComs strict all-target/all-feature application check passes in `contacts-07.log`,
including the new scoped hosted bot example. Updated contact/preferences checks
are still running. This is not independent-file or installed-network qualification.


### Ciphertext piece storage checkpoint (file integration remains open)

Hosted API bulk upload/download now use immutable per-publisher piece namespaces.
Proofs bind channel, owner, file, index, read/write purpose and upload digest;
current policy authorizes uploads and current membership authorizes downloads.
Pending removal immediately denies downloads. Service piece logs have exclusive
locks, bounded indexes, hash chains/checksums, fsynced acceptance, exact retry,
write poisoning, torn-tail-only recovery and aggregate quota accounting. Keys
and plaintext never enter this interface. Existing receipts stay covered.

SDK/runtime IPC23 exposes bounded piece operations separately from IPC22 base
hosted operations. Service info advertises the extension and configured rates.
`blobs-02.log` passes all 17 service tests and strict MLS/service/runtime/SDK/
application checks. `blobs-03.log` passes runtime authorization/no-receipt-fanout
and IPC version/bounds checks; its final test-style Clippy warning is corrected
and `blobs-04.log` passes strict checks. This is a storage primitive, not completed
file offer/download/resume or network capacity qualification. Those remain next.

### File integration checkpoint (under qualification)

`sharing_v2` uses explicit hosted/contact scopes and a separate encrypted cache,
with a distinct IPC23 capability. Hosted file offers have a durable consumer inbox
independent of ordinary chat commits. Retried publication uses immutable IDs.
Only verified whole-file completion produces the covered completion statement;
manifest acceptance is not download completion. Contact piece data is classified
as bulk in retained direct records; contact control/receipts stay interactive.
GChat's existing binary file controls now route through the selected conversation
profile without converting contacts into legacy channel identities.

`files-inbox-02.log` passes the new restart/idempotence/moderation cases and selected
existing file regressions. Full GChat `contacts-full-01.log` passes on GComs4c651a1
and GChatd6c0235; that receipt predates the new file worker. Contact transfer,
hosted whole-file transfer, quota/lifecycle audit, scale and release gates remain
open. The user chose covered receipts with slower large-channel delivery status
and “Topic pending” for newcomers while existing authorized writers are offline.
