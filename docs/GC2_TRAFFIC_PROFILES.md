# Experimental carrier comparisons

These profiles are comparison candidates. The existing full-cover profile and
production defaults are unchanged. A profile choice must be explicit and bound
into the authenticated carrier Open record; older peers reject unfamiliar IDs.

| IDs | Interactive channel | Bulk channel |
| --- | --- | --- |
| 0–11 | Fixed-size periodic records, including idle cover | Same fixed-size periodic records |
| 12–23 | Same fixed-size periodic records | Payload immediately eligible, bounded variable-size records, no idle cover records |
| 24–35 | Fixed-size records with independent bounded slot phase | Same immediately eligible bulk |

Within each group, record sizes are 1024, 2048 and 4096 bytes and periods are
250, 500, 1000 and 1500 milliseconds. Existing ID meanings remain intact.
The variable bulk record limit is 16 KiB including its nine-byte record header.
Circuit, TLS, HTTP/2 and application overhead consume additional capacity.

Jitter samples each interactive slot's phase independently in [0, period/4].
Without blocked writes, adjacent gaps remain within [0.75, 1.25] times the period,
with the same long-run mean rate. Payload arrivals never select phases or change
the rate. Blocked writes skip elapsed opportunities instead of sending a burst
to catch up. Entry ownership and connection lifetime remain independent of
application activity.

These changes retain encryption, authentication and protected routing. Removing
bulk cover exposes bulk activity, timing and volume. Random slot phase does not
establish protection against traffic correlation. All candidates need measured
comparisons and an explicit owner decision before production selection.

## Record-layer cost illustration

For two entries, counting both directions, the following are **carrier record
bytes only**. They exclude TLS/HTTP/2/TCP overhead, reconnections, retransmissions,
relay-to-relay traffic, and the legacy/control traffic still present in the node.
One GB means one billion bytes; each month is 30 days. Unshaped payload is extra.

| Candidate | Idle bytes/s | 8 connected h/day | 24 connected h/day |
| --- | ---: | ---: | ---: |
| Full, 4096 B / 1000 ms | 32,768 | 28.31 GB | 84.93 GB |
| Interactive, 4096 B / 1000 ms | 16,384 | 14.16 GB | 42.47 GB |
| Interactive, 1024 B / 1500 ms | 2,730.67 | 2.36 GB | 7.08 GB |

The jitter candidate has the same mean record budget as its deterministic
interactive counterpart. Monthly costs must ultimately use all client-interface
traffic, with identical workloads and observation durations. Battery consumption
and mobile suspend/resume remain unqualified while physical mobile tests are
deferred.

## Evidence boundaries

The file candidate's `app_performance` instrument selects ID 22 with
`--profile gchat-files --protected --cadence production`. Its
`--measurement-ms` option keeps the connected observation interval fixed across
idle, chat, bulk and mixed workloads; a workload overrun fails. This is local
protocol-component evidence. It is not an installed GChat journey or an isolated
client-interface privacy measurement.

The fleet file harness uses separate relay and GChat processes and requires
independent exported-file hashes, receiver reopening and observed routing
readiness. Privacy qualification additionally requires isolated client capture,
matched bulk workloads with and without chat, independent held-out runs and
complete build provenance. See the [file-transfer follow-up](GCHAT_FILE_TRANSFER_FOLLOWUP.md)
for current evidence and remaining gates. Keep historical failed captures and
reports; no component or file-correctness pass establishes privacy qualification.
