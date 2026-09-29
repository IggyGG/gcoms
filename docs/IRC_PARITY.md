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
| IRC-2 | Ordered persistent recovery and service integration | Pending | Concurrent joins and crash/reopen converge; offline recipients do not block admission; no false delivery or loss of accepted records |
| IRC-3 | Channel policy, operators, voice, moderation, bans/exceptions, keys, limits, discovery | Pending | All admission and message paths enforce policy against modified clients; grant/revoke and rekey persist |
| IRC-4 | Contacts and independent direct conversations/files | Pending | No shared channel required; leaving a former shared channel preserves the contact conversation; block and identity continuity |
| IRC-5 | Authenticated activity and richer presence | Pending | Actor/target/reason ordering; away/back/unknown/invisible; optional sharing; snapshot polling loses no events |
| IRC-6 | Notices, blocking/muting, highlights, formatting and client workflows | Pending | Same actual service-backed behavior through desktop/TUI/shared mobile UI; no automatic notice loops |
| IRC-7 | Operator workflows and supported bot integration | Pending | Scoped authorization, rate control, network/channel authority separation, executable bot example |
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

Both components are siblings under GComs `.worktrees/irc-parity/`. Work only in
those checkouts. GChat's original canonical lockfile and `.cargo/` are preserved.
Use the configured `origin` remote (the local Forgejo) for branch checkpoints.
Run CPU-heavy gates through `workstation-batch`/the Cargo shim and retain decisive
evidence on SSD. Update this ledger at each implementation/validation checkpoint.
