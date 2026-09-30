# Reusable invitations and recoverable enrollment

Status: implemented; release qualification and controlled rollout are tracked
below. Existing single-use invitations remain supported. The checks below are
scoped evidence, not installed-platform or production-network acceptance.

## Contract

One owner-controlled mechanism serves friends and unattended devices. A valid
invitation authorizes channel admission only, never shell execution or operator
permissions. The owner must be online to admit a new member. Expiration and the
total admission limit are independent options; neither is implicitly unlimited.

| Preset | Lifetime | Distinct admissions |
| --- | --- | --- |
| One person | 1 hour | 1 |
| Friends | 7 days | 25 |
| Devices | 90 days | 100 |

Custom policies can explicitly choose no expiry or no total admission limit.
Limits count authenticated member identities, not physical machines. Reopening
or retrying the same enrollment does not consume another admission. A new
identity does. Removing a member does not refund its admission.

Revocation and policy revision are independent of the MLS membership epoch.
Expiry/revocation prevents new admission; a committed enrollment can still
retrieve its member-bound result. Closing a channel or transferring ownership
invalidates outstanding invitations. Existing member recovery is independent
of the invitation that admitted it.

## Durable state and delivery

Persist the joiner's MLS preparation and enrollment ID before its first request.
Prove the authenticated return path before owner commitment. Commit the MLS
change, counter and exact Welcome together. Retries retain the MLS package and
identity; an authenticated monotonic update can replace the return route.
Retain the result until the joiner durably applies and confirms it. Cancellation
before commitment releases a reservation; after commitment, leaving is a
separate membership operation.

Offline members must not permanently block other members. An ordered durable
epoch journal and per-member progress retain exact commits and application
wires. Catch-up applies commits in order, preserves ACK-only delivery, resolves
senders against their historical epoch roster and does not grant old history to
new members or future messages to removed members. Legacy peers retain their
existing gates until capability negotiation establishes compatibility.

Initial bounds: 64 pending enrollments per channel, 128 outstanding epochs,
32 MiB catch-up records per channel and 128 MiB per profile. Reserve capacity
before accepting work. Exhaustion produces explicit backpressure; it never
drops unacknowledged work or synthesizes ACKs. Existing scheduler and wire limits
remain in force.

## Discovery and interfaces

A compact link/QR pins the network and issuer and carries an opaque lookup ID
and bearer secret. Configured providers host encrypted, owner-signed route
descriptors with sequence/freshness checks and authenticated scoped publication.
Providers cannot admit members or extend routing authority. Secrets stay out of
provider records, query strings and logs. Expired configuration is usable only
as a locator for a freshly authenticated replacement. Refresh descriptors before
route expiry and after durable route changes. Provider visibility is an explicit
metadata limitation, not a claim of traffic privacy.

Add create/inspect/list/revoke and start/status/resume/cancel APIs across Node,
Rust SDK, IPC, application backends, Kotlin and Swift. Preserve existing blocking
and single-use methods as compatibility wrappers. GChat exposes presets and
management, a focused join screen, progress and actionable errors. Existing
v1/v2/v3 and GCI1 invitations remain readable. New schemas fail closed in old
clients. Do not increase the 600-second IPC request ceiling.

## Acceptance checklist

- [x] Policy and durable admission ledger: independent bounds, revocation,
  races, exact retry, invalid credentials, expiry and storage rollback.
- [x] Resumable enrollment: lost Welcome, both endpoints restart, changed
  authenticated routes, cancellation and unchanged identity/admission count.
- [x] Offline catch-up: several joins/messages, delayed old-epoch messages,
  leaf-index reuse, forged ACK rejection, reordered commits and resource bounds.
- [x] Descriptor service: scoped publication, encryption/signatures, freshness,
  rollback rejection, provider failover and expired embedded bootstrap recovery.
- [x] SDK/IPC/mobile and machine-channel capability compatibility.
- [x] GChat create/manage/join/share UI and progress; legacy format tests.
- [x] Actual three-client friends journey: same invitation, messages, small
  file, restart and revoke. SDK fleet fixture: isolated identities, authenticated
  operator round trip and unauthorized sender rejection.
- [ ] Required format/static/package/combined checks on frozen source; archive
  upgrade/reopen/rollback and exact artifact provenance.
- [ ] Controlled provider/client rollout, preserving personal profiles and
  requiring no unattended personal-service restart.

Implementation starts from GComs `eef71eaa1a54d28b5b7c50e305f2a08018567719`
and GChat `8df1805396fef7b76c2c5653968184e4a0881723` in fleet-files.
Parallel GComs machine-client changes through `e027722` are compatible inputs
to inspect and preserve; Drone/Dropship source is outside this task boundary.
Historical failures and receipts remain bound to their original sources.
`codematch=unreachable` in this session; its absence is not a validation gate.

## Using the implementation

GChat `/invite` opens a focused chooser. `/invite friends` creates a seven-day,
25-admission invitation; `/invite devices` creates a 90-day, 100-admission
invitation. `/invite custom never 100` or `/invite custom 7 unlimited` makes
only the named bound unlimited. `/invites` shows usage and pending joins and
lets the owner share, revoke or retire a revoked, completed invitation.
`/enrollments` reopens saved join progress. Closing the progress screen does not
cancel the operation. Cancellation is refused once admission may have happened;
resume that operation and then leave the channel if desired.

An operator removing an unfinished enrollment releases its pending slot and
its internal bootstrap messages. The record remains explicitly removed, never
acknowledged, and its admission count is not refunded. Ordinary unconfirmed
application messages are retained. A new invitation is required to admit that
same installation again after removal.

Rust clients call `GcClient::invitations(InvitationRequest::Create { channel,
policy })`, then give the resulting link to each client. Each client calls
`StartEnrollment { link, display }` once and keeps the returned 16-byte ID;
`EnrollmentStatus`, `ResumeEnrollment`, `CancelEnrollment`, `ListEnrollments`
and `RetireEnrollment` use that saved state. The old blocking join method can
wait for the same operation for at most 600 seconds; timeout does not undo an
accepted membership. Invite operations are IPC v23 additions. Older invite
methods and GCI1 links are still accepted.

Kotlin and Swift expose `createInvitation`, `listInvitations`,
`revokeInvitation`, `startEnrollment`, `enrollmentStatus`, `resumeEnrollment`,
`cancelEnrollment`, `listEnrollments` and `retireEnrollment`. IDs are 16 bytes;
expiry is Unix seconds; null means the corresponding bound is explicitly
unlimited. All wrappers use the same Rust admission and persistence code.

Device admission grants only channel membership. The application must still
check authenticated sender identity and its separate command permissions before
executing any IoT command. Nicknames and possession of the channel invitation
are not operator authority. A copied invitation can be redeemed by a new
identity, so the limit is not a physical-device license or Sybil defense.

## Provider and release requirements

Remote compact sharing requires a current network grant with the `invitations`
scope. The catalog exposes authenticated PUT and public ciphertext GET at
`/v1/invitations/{opaque-id}`. Operators enable that scope explicitly using
`gc-network-operator`; old bootstrap-only grants do not silently gain it.
Providers must deploy the matching catalog before clients use compact sharing.
A failed publication leaves the saved invitation manageable through `/invites`;
retry sharing after the provider/grant is ready.

Descriptors last at most five minutes. The online owner republishes refreshed
routes, retaining its sequence before HTTP. A joining client persists its
sequence/digest and signed-network floor before contacting the owner. Expired
provider records can release their quota only after all previously acceptable
signatures have expired. Live old descriptors cannot reclaim that storage slot.
The provider sees the lookup ID, publisher grant and access timing; it does not
receive the invitation secret. This is not traffic-analysis protection.

New admission/catch-up state is sealed with the existing profile. Old readers
fail closed on that archive extension. Rollback after using reusable invitations
requires the pre-upgrade encrypted backup, not an old daemon writing the new
archive. Do not reset identities, drop pending application outboxes, or restart
personal sessions without the user's agreed release procedure.

A local-only fixture can share an inline v4 invitation without a provider; that
link is not a long-lived network locator. Production remote sharing returns the
compact `gcoms://join#GCIR1-…` form. QR cameras open the registered app link; the
original PNG also retains the exact invitation. Share either privately.

## Qualification scope

Cluster fixtures cover durable same-link admission by two identities, protected
GC/2 request/reply, both authenticated message directions, revoked admission,
profile reopen, and an exact small file. The final protected test passed in
38 seconds; the final three-profile GChat journey passed in 77 seconds.
Earlier runs sharing a two-core quota with release compilation timed out and
remain retained. Running the same executables on a separate two-core worker
passed without changing either deadline or runtime code.

Kotlin client/relay compilation and Swift iOS-simulator typechecking cover the
new wrappers. These are not new installed Android/iOS application, live push,
traffic-privacy or fleet-scale performance receipts. The provider and personal
client rollout require separate artifact-bound checks.
