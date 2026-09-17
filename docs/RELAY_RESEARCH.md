# Relay performance research

The Rust loopback benchmark was already imported into GComs. This repository now
also contains its three analysis/model scripts and regression tests, pinned by
[research/IMPORT.json](research/IMPORT.json). Their historical behavior remains
unchanged so that prior results can be checked rather than reinterpreted.

## Historical controlled comparison

The [2026-09-17 aggregate report](research/relay-utilization-20260917.json) covers
120 successful generated loopback trials, 3,040 validated echoes and 11,778,560
useful bytes. It measures original coms source `7493dbe`, not a newly qualified
GComs release. Every observed link used one connection. Peak accounted buffered
payload was 195,712 bytes; the maximum ready queue contained 45 messages.

| Variant | Bulk KiB/s | Chat + bulk KiB/s | Mixed chat p95 |
| --- | ---: | ---: | ---: |
| Baseline | 8.40 | 4.52 | 41.60 s |
| Concurrency | 25.32 | 17.51 | 7.30 s |
| Packing | 8.44 | 7.38 | 2.35 s |
| Combined | 25.67 | 20.82 | 1.95 s |

These are medians across five runs. Combined and concurrency passed the fixed
performance gate; packing alone missed the pure-bulk improvement requirement.
Combined remains the application-evaluation candidate, with concurrency as the
simpler control. This evidence does not establish recipient delivery, durability,
production admission behavior, mobile power use or anonymity.

An earlier 119/120 attempt failed near hourly credential expiry. It was retained
as incomplete, not filled with replacement trials. The successful repeat deferred
fixture creation when the current credential epoch could not cover a complete
trial. That setup wait was excluded from offered-message latency and reported
separately. Production recovery across credential expiry still needs testing.

## Tools and reproduction

- `relay-performance.py`: analytical carrier costs and legacy loopback reports.
- `relay-tradeoffs.py`: historical offline models, including hard-budget variants.
- `relay-utilization.py`: validation and ranking of the controlled comparison.

```sh
python3 scripts/check-research-import.py
python3 -m unittest discover -s scripts/tests -p '*_test.py'
cargo test --offline --locked -p gcoms-node --example relay_performance
cargo build --release --offline --locked -p gcoms-node --example relay_performance
mkdir -p target/relay-research
target/release/examples/relay_performance --utilization --quick \
  --output target/relay-research/quick.json
python3 scripts/relay-utilization.py target/relay-research/quick.json \
  --output target/relay-research/quick-summary.json \
  --markdown target/relay-research/quick-summary.md
```

Choose fresh filenames: evidence files are not overwritten. The quick analyzer
intentionally returns a non-passing verdict; quick runs validate the harness only.
Omit `--quick` for the complete five-repeat matrix and retain failures, complete
logs, source/configuration hashes and original output. Serialize timed comparisons
against other local benchmark work. TCP read samples are not packet captures.

## Current implementation contract

The historical model's hard budgets are not the approved implementation policy.
Mobile 250 MB and desktop 1,000 MB per 30 days are advisory privacy-extra targets.
Exceeding a target must not block delivery, suppress required padding or change the
selected privacy profile. Report the overrun. Safety and resource limits remain
independent enforced constraints.

Protect chat activity from a local network observer throughout connected periods.
Online periods and approximate bulk volume may remain observable. Mobile respects
OS suspension and reports its availability gap. Reducing cover needs fresh
application, network-observer and physical-mobile qualification. Randomness alone
does not establish equivalence to the existing traffic pattern.

The existing 4 KiB/100 ms duplex carrier costs approximately 212.34 GB per
continuously connected 30-day period before ordinary network overhead. Initial
4 KiB/1 s and 4 KiB/1.5 s candidates would cost 21.23 and 14.16 GB respectively.
These are arithmetic record budgets, not measured bills or battery estimates, and
still exceed the soft targets. Useful data replaces some padding. Additional
connections, bulk data, headers and retransmissions have separate costs.
