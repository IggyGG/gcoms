# Protocol ownership after the split

GComs is the protocol and SDK source of truth. GChat is the reference application
and consumes the `gcoms` application facade. New transport work belongs in GComs; application
configuration, status presentation and chat behavior belong in GChat.

The split imported original coms revision
`5588d8a03e6e1f1ff446bac681cdd88dbf7502f8`, which already contained the controlled
relay-utilization repeat. The imported benchmark, utilization module and scheduler
diagnostics match that source after the `gc_` to `gcoms_` import rename. Subsequent
original-coms commits through `02a9daa` changed preparation records and added a
private authority adapter; they did not change the protocol crate sources.

Consequently, do not merge the original repository wholesale. Its managed host,
fleet, installer, recorder and command integrations were intentionally excluded.
Keep their authority implementation behind the existing host interface. Historical
protocol domains and archive formats are compatibility identifiers, not imports
of those private applications.

The missing research analyzers, their regression tests and the aggregate result
are now retained here. [The import manifest](research/IMPORT.json) pins their
original source paths and SHA-256 hashes. Verify them with
`python3 scripts/check-research-import.py`; the check does not access the old
repository. [Research notes](RELAY_RESEARCH.md) distinguish historical results
from new-source qualification.

For source development, validate the two new repositories together:

```sh
python3 scripts/check-gchat.py --gchat /path/to/gchat --offline
python3 scripts/check-gchat.py --gchat /path/to/gchat --offline --action clippy
```

The runner snapshots both repositories and builds GChat with temporary GComs
package overrides. It preserves registry manifests and lockfiles and reports a
source change during validation instead of overwriting concurrent work. Build
results and per-file source hashes are retained under
`target/gchat-source-check/reports`, including failed attempts. Actual package-archive
qualification remains `scripts/check-consumers.py --gchat /path/to/gchat`.

The [GC/2 implementation ledger](GC2_IMPLEMENTATION.md) owns the next protocol
work. Consolidating repositories does not itself change GC/1, IPC 16, deployed
relays, saved identities, or the privacy properties of the transport.
