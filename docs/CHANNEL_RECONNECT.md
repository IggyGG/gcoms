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
