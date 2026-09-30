# Classic IRC feature mapping

This is the implementation audit for the native GChat equivalents, not an IRC
wire-compatibility claim. The baseline command families come from
[RFC 2812](https://www.rfc-editor.org/info/rfc2812/); channel modes and membership
semantics come from [RFC 2811](https://www.rfc-editor.org/info/rfc2811/). Client
conveniences and file workflows are additional product requirements. The user
excluded an IRC bridge, IRCv3, public user discovery and silent identity linking.

“Implemented” below refers to source on the paired IRC-parity branches. Exact
validation and unfinished release gates remain in [the evidence ledger](IRC_PARITY.md).
A source mapping does not imply an installed release or a 64-member network pass.

| Capability | GChat entry point / GComs behavior | Implementation and qualification |
| --- | --- | --- |
| Connection, disconnect, quit, reconnect | Existing `/network`, `/disconnect`, `/quit`, retained network/profile lifecycle | Preserved; current native/installed checks open |
| Join, part, room creation | `/hosted create`, `/hosted join`, `/part`; independent external MLS admission | Implemented; offline-owner, competing-join and persisted retry checks |
| Continued channel operation without creator | Ciphertext service sequences policy and membership; members verify every transition | Implemented; service holds no member key |
| Channel list | `/hosted list`, hosted `/list`, opt-in operator `/publish` | Implemented; pagination/privacy/restart/IPC25 checks |
| Member list | `/names`, scoped `/who` | Implemented; identity and role supplied by verified membership |
| Channel messages | Text or `/say`; ordered retained records | Implemented; acceptance and recipient delivery remain distinct |
| Independent private messages | Bilateral signed-card consent, `/contact add`, `/contact open` | Implemented; real no-channel delivery/reopen/block tests |
| Existing scoped private messages | Existing legacy PM conversations and encrypted archives | Preserved; no automatic contact conversion |
| Notices | `/notice` in hosted rooms and contacts | Implemented; notice-reply loops forbidden |
| Actions | `/me` and typed action rendering | Implemented across shared service/UI/TUI |
| Nicknames | `/nick`; identity remains channel-scoped and stable | Implemented; ambiguous names require an explicit scoped ID |
| Historical names | `/whowas nickname-or-scoped-id` | Implemented; bounded archive/rename/departure/reopen/scope checks pass |
| Topic | `/topic`, `/topic --clear`; encrypted authorized handoff | Implemented; offline newcomer sees Topic pending until an authorized member returns |
| Operators and voice | `/mode +o/-o/+v/-v member` | Implemented; service and receiver enforce signed policy |
| Moderated and topic-restricted rooms | `/mode +m/-m`, `/mode +t/-t` | Implemented; roles checked against accepted policy |
| Members-only sending | Mandatory authenticated membership | Implemented; unauthenticated external application messages rejected |
| Invitation-only admission | `/mode +i/-i`, `/invite`, retained `/links` | Implemented; one-use permits bind current authority and intended join |
| Channel key | `/mode +k/-k`; reusable admission code/verifier | Implemented; service receives no invitation private secret |
| Member limit | `/mode +l number` | Implemented; capacity bounded at 64 |
| Bans and exceptions | `/mode +b/-b/+e/-e/+I/-I member-id` | Implemented as scoped identities rather than host masks |
| Private and secret rooms | `/mode private/secret/public`; explicit publication required | Implemented; private/secret rooms omitted from public directory |
| Kick, departure, ownership | `/kick`, `/part`, `/owner`, `/close-channel` | Implemented; pending removal revokes authority before member-assisted rekey. Removed-client snapshot replay fix passes focused tests, exact-profile recovery/reopen and fresh 12-client live exclusion/replacement |
| Away and availability | `/away`, `/back`, `/presence on/off` | Implemented; opt-in authenticated leases, expiry becomes Unknown |
| User information | Scoped `/whois`, contact fingerprint/card/verification | Implemented; no global host/user directory |
| Persistent block, ignore and mute | `/block`, `/ignore`, `/mute` | Implemented; contact block revokes new file authority, local filters preserve encrypted history |
| Highlights and formatting | `/highlight`; bounded IRC styling in shared UI/TUI | Implemented; no executable markup or terminal escape passthrough |
| Command help, completion, aliases | `/help`, member/command completion, `/alias`, `/unalias` | Implemented; aliases expand once into one bounded command |
| Multiple windows and saved joins | Existing conversation switching, `/hide`, `/close`, retained profiles/joins | Preserved; hidden windows continue receiving |
| History and search | Encrypted local archives and paginated search | Implemented; separate hosted/contact sidecars preserve legacy rollback isolation |
| File sharing and resume | Existing file controls with explicit hosted/contact scope | Implemented; AEAD pieces, Merkle/whole-file verification, retained partial resume and authenticated completion |
| Service information | `/motd`, `/rules`, `/admin`, `/server-info` | Implemented; scoped info and configured limits, no network topology disclosure |
| Connectivity probe | `/ping`, `/refresh` | Implemented as authenticated service recovery/round trip |
| Network operator controls | Service creation allowlist, suspension, source/global rates and storage quotas | Implemented and deployed to the HEL qualification service; exact allowlist and retained-state restart checks pass |
| Bots and automation | `crates/application/examples/hosted_bot.rs` | Implemented scoped ordinary-member example; bounded replies and no notice loop |
| Delivery/recovery status | Pending, ServiceAccepted, Delivered, Failed; durable dedup and retry; confirmed catch-up progress | Implemented; covered receipts may be slower in large rooms. Ordinary offline recovery keeps 10 seconds; large membership backlogs show progress. Actual 81-member replay and indicator completion pass |
| Load and churn | 64 identities, ten senders, offline recovery, file traffic and removal | Durable-runtime 500-member/4,990-signature campaign passes within its original limits; matched 85-client bootstrap passes with hosted relay budgets. Current protected-network/GChat 64-member gate remains open; larger runs are historical and no longer required |

The following are deliberate differences in this approved scope: no raw IRC
server-link management, host login queries, global username enumeration, automatic
CTCP fingerprint replies, unverified direct-IP file negotiation or bridge. Network
operators manage service configuration and lifecycle outside ordinary chat; channel
operators cannot impersonate that authority. A nick is a display name, and neither
a name match nor a shared room silently grants an independent contact relationship.

Release completion still requires current source-bound runtime/GChat regression,
protected-network capacity and latency/resource measurements, paired package/API
checks, native/installed qualification, configured signed service origins and
normal trunk publication. Physical mobile/live push remain a separate scope.
