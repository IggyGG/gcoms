# gcoms-channel-service

Experimental single-writer ciphertext service for `hosted-mls-pq-v1` channels.
It stores public membership/policy and authenticated encrypted application data;
it never instantiates an MLS member or receives client private state. The default
`http` feature supplies the HTTP upstream daemon. Disable default features when
using only the record codec/storage library.

Run `gcoms-channel-service config.json` behind the installed network's HTTPS
origin. Both `POST /v1/hosted` and `POST /v1/hosted/bulk` must reach the same
instance. Configure the origin in signed network defaults. Client routing retains
origin restrictions, remote DNS, WebPKI and no direct fallback. Large trees and
records use observable bulk; small chat and polling remain covered. Recipient
receipts must also remain covered, accepting longer status latency in large rooms.

Create the storage directory privately (0700 on Unix). A minimal bounded config:

```json
{
  "listen": "127.0.0.1:8080",
  "directory": "/var/lib/gcoms-channels",
  "max_channels": 10,
  "max_total_bytes": 536870912,
  "channel_bytes": 134217728,
  "channel_records": 100000,
  "requests_per_second": 1000,
  "source_requests_per_second": 100,
  "motd": "Welcome",
  "rules": "Respect other members",
  "operator_contact": "Contact your network administrator"
}
```

Creation defaults to denial. Set `creation` to `{"kind":"allow_list","channels":[]}`
with explicitly provisioned 32-byte channel IDs, or deliberately choose
`{"kind":"public"}`. These are network creation permissions, separate from
channel owner/operator/voice roles. `blocked_channels` stops writes while retaining
read access; `blocked_sources` denies matching upstream peer addresses. Behind a
proxy, per-source rates apply to the proxy socket, not untrusted forwarding headers.
Non-loopback listening requires `tls_terminated_upstream: true`. SIGTERM and Ctrl-C
stop admission gracefully.

Every append is validated and flushed before service acceptance. Exact retries
return the original sequence. Acceptance is not recipient delivery. Reader proofs
bind channel, scope, query and expiry; invitation holders can read admission state
but cannot read member messages. Removed members retain read access only through
their removal record, including after restart. Single-use invitations and reusable
admission codes are separate, client-held secrets; only verifiers enter the log.

Reopening checks sequence/predecessor hashes and every complete frame. Only an
incomplete final frame is truncated; complete corruption fails closed. An uncertain
write poisons the instance until reopening. Exclusive locks prevent concurrent
writers. Quotas reject new writes without evicting accepted data; memory holds
indexes rather than all ciphertext bodies. Members perform authorized rekeys.

Recipient signatures use separate sender-scoped covered receipt logs. This
checkpoint does not provide replication, compaction or complete
GChat/native/500-member network qualification. Run the
MLS/service suites and strict all-target Clippy when changing the storage or API
contract; see the repository's IRC parity ledger for evidence and remaining work.


The `ciphertext-pieces-v1` service extension adds immutable pieces on the explicit
bulk endpoint. Signed proofs bind channel, read/write purpose, publisher, file,
piece index and (for upload) ciphertext digest. A publisher can write only its own
namespace and must satisfy current posting policy. Current members may download;
a pending kick revokes this access immediately. No content keys enter this API.
Piece logs are separately locked, chained, checksummed and fsynced, count against
service/channel limits, recover only torn tails and preserve accepted pieces.
The client remains responsible for AEAD, Merkle and whole-file verification.
Service info also advertises global and source request rates; behind a proxy the
source rate refers to the upstream socket address, not a forwarded IP.
This storage primitive does not by itself implement file offers or GChat transfers.

`public-directory-v1` lists only explicitly named Public channels, in bounded
ID-ordered pages. A signed operator Listing control publishes the chosen name;
empty publication withdraws it. Private/secret/closed/suspended rooms are omitted.
The index is rebuilt from validated controls after restart. Encrypted topics and
member identities are never directory fields. Advertised public admission still
requires the client's normal proof and current policy verification.

Native systemd configuration, exact HTTPS routes and state-preserving rollback
are in [deploy/](deploy/README.md). The supplied configuration denies channel
creation until the operator explicitly provisions it.
