# Native HTTPS upstream deployment

Build the service from a recorded source revision with the locked dependency
graph. Retain its SHA-256 and the passing source checks. Install the executable in
an immutable revision directory under `/usr/local/lib/gcoms-channels/`, with a
`current` symlink selecting it. Never rebuild on the production host.

Create a system user/group `gcoms-channels` without a login shell. Install
`config.json` under `/etc/gcoms-channels/` (root owned, group gcoms-channels,
0640) and the unit under `/etc/systemd/system/`. The service owns only its private
`StateDirectory`. The supplied configuration denies creation until exact channel
IDs are provisioned; ordinary channel operators cannot change this network policy.

Install `nginx-locations.conf` as an include in the **existing HTTPS server for
the signed provider origin**. These are two exact POST routes; the existing
bootstrap, network defaults and TLS settings continue to serve their own paths.
Preserve a copy of the previous nginx configuration, validate with `nginx -t`
using that instance's prefix/config, then reload it. Do not start a second public
TLS listener. The upstream binds loopback and ignores forwarded identity headers.
The per-source service limit therefore applies to the proxy, while the boundary
retains its existing connection bounds.

Start the service and send a version-1 `info` request to the HTTPS hosted path.
Require the `hosted-mls-pq-v1` profile and expected extensions; prove the old
health/network-defaults routes still respond. A direct HTTPS probe checks only
deployment. Actual messaging qualification must use the installed signed network
and protected catalog transport, including WebPKI verification and no fallback.

For rollback, stop admission, stop this unit, restore the prior nginx include and
reload the validated boundary. Preserve the state directory and retained binary;
never delete channel logs or restore an older log snapshot over accepted writes.
An older executable may be selected only after its retained-state compatibility
check passes. This single-writer deployment does not claim replica failover.

The protected routing relays must also permit the signed provider hostnames as
HTTPS egress destinations. Configure `GC_CATALOG_ORIGINS` with those exact hosts,
preserving existing explicitly authorized catalog hosts and the eight-host bound.
`relay-origins.py --origin HOST` prints the proposed addition; `--apply` creates a
new task-specific systemd drop-in and rolls that one relay, reverting its addition
if the process/listener fails to return. Run serially and retain every result.
Its listener check is not application qualification. Ordinary destination, private
address, port, TLS and circuit authentication checks remain in force.
