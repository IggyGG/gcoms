# Existing-member channel reconnect

When all saved peer queue addresses expire while members are offline, network
readiness alone cannot discover their new private channel addresses. Local
acceptance retains the exact message, but does not imply delivery.

`GcClient::channel_reconnect(channel, None)` exports a bounded (8 KiB maximum)
`gchat-reconnect1:` code. Supply that code with `Some(code)` on another current
member of the same channel and MLS epoch. Keep both devices online. The receiver
durably installs the authenticated fresh self-directory and replies with its own
fresh directory. Existing outboxes retain their IDs/ciphertexts and target the
new addresses; only authenticated recipient ACKs report delivery.

The code is canonical base64url of channel ID, epoch and the existing MLS-encrypted
self-directory wire. It is not a Welcome, cannot join a member, cannot replace
another member's address, and grants no additional lease lifetime. Invalid input
is processed on an isolated MLS checkpoint. Failed persistence restores the
original receive state and routes. IPC 21 adds the ChannelMember-gated operation
without changing previous request ordinals. Earlier hosts do not offer it.

This explicit exchange is a recovery fallback, not automatic rendezvous after
all peer contacts expire. Use another communication path to exchange it, like
an invitation. No global identity directory or relay-authority exception is added.

## Stalled retained inboxes

Background recovery first tries the retained inbox authority. After two failed
rounds, the next round attempts authenticated replacement without first repeating
the stalled restore. Otherwise a hung restore can consume every recovery deadline
and prevent failover forever. The existing round deadline, retry cadence, queued
work bounds, durable owner transition and old-alias cleanup deadlines are unchanged.
No application request dials an entry or extends an inbox lease.

The regression uses real protected loopback routes, a terminal that completes pinned TLS
but stalls its administrative response, and healthy provisioning/queue services. It checks replacement
progress and preservation of the old aliases after the retained rounds are
exhausted. This does not establish automatic rendezvous for expired peer addresses.
