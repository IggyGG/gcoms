#!/usr/bin/env python3
"""Run the application-level GC/2 qualification matrix and apply the gates.

This is the item-4 driver for the `app_performance` example. It runs each
(profile, workload) pair a balanced, predeclared number of times, validates the
per-run accounting (durable receipts, no failures, bounded latency), and applies
the acceptance rules:

  * bulk goodput: median GC/2 bulk goodput is at least 20% above GC/1 in the
    bulk and mixed workloads;
  * chat p95: median GC/2 chat p95 is at most max(+5%, +20 ms) of GC/1 in the
    chat and mixed workloads;
  * shaping delay: median GC/2 single-message delay on an established session
    is at most 3 s.

The verdict is fail-closed: missing, malformed, or incomplete runs cannot
qualify, and `--quick` runs are explicitly non-qualifying. The script never
edits evidence; it writes one JSON report and prints a summary.
"""
import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

WORKLOADS = ("chat", "bulk", "mixed")
PROFILES = ("gc1", "gc2")
BULK_GAIN = 1.20
CHAT_TOLERANCE_FRACTION = 0.05
CHAT_TOLERANCE_MS = 20.0
SHAPING_DELAY_MS_MAX = 3000.0


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="built app_performance example")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--chat-count", type=int, default=60)
    parser.add_argument("--chat-interval-ms", type=int, default=250)
    parser.add_argument("--bulk-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--bulk-chunk", type=int, default=11 * 1024)
    parser.add_argument("--inflight", type=int, default=16)
    parser.add_argument("--timeout", type=int, default=180, help="per-run example timeout (seconds)")
    parser.add_argument("--quick", action="store_true", help="non-qualifying smoke run")
    parser.add_argument("--report", type=Path, required=True)
    return parser.parse_args()


def example_command(args, profile, workload):
    command = [str(args.binary), "--profile", profile, "--seed", str(args.seed)]
    if workload in ("chat", "mixed"):
        command += [
            "--chat-count",
            str(args.chat_count),
            "--chat-interval-ms",
            str(args.chat_interval_ms),
        ]
    if workload in ("bulk", "mixed"):
        command += [
            "--bulk-bytes",
            str(args.bulk_bytes),
            "--bulk-chunk",
            str(args.bulk_chunk),
            "--inflight",
            str(args.inflight),
        ]
    command += ["--timeout", str(args.timeout)]
    return command


def run_once(args, profile, workload):
    started = time.monotonic()
    completed = subprocess.run(
        example_command(args, profile, workload),
        capture_output=True,
        text=True,
        timeout=args.timeout + 60,
    )
    elapsed = time.monotonic() - started
    record = None
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
    if completed.returncode != 0 or record is None:
        raise RuntimeError(
            f"{profile}/{workload} exited {completed.returncode}: {completed.stderr.strip()[-400:]}"
        )
    record["elapsed_s"] = elapsed
    return record


def expected_accounting(record, args):
    chat = record["chat_count"]
    chunks = -(-args.bulk_bytes // args.bulk_chunk)
    expected_receipts = record["chat_sent"] + record["bulk_chunks"] + 1
    checks = {
        "failures": record["failures"] == 0,
        "receipts": record["recipient_drained"] >= expected_receipts,
        "single": record["single_delay_ms"] > 0,
    }
    if chat:
        checks["chat_sent"] = record["chat_sent"] == chat
    if record["bulk_chunks"] or (record["bulk_chunk"] and record["bulk_acked_bytes"]):
        checks["bulk_chunks"] = record["bulk_chunks"] == chunks
    return checks, expected_receipts


def median(values):
    return statistics.median(values) if values else None


def main():
    args = parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"missing --binary {args.binary}")
    repeats = 1 if args.quick else args.repeats
    if repeats < 1:
        raise SystemExit("--repeats must be positive")
    binary_sha = hashlib.sha256(args.binary.read_bytes()).hexdigest()

    runs = []
    invalid = []
    for repeat in range(repeats):
        profile_order = PROFILES if repeat % 2 == 0 else tuple(reversed(PROFILES))
        workload_order = WORKLOADS[repeat % len(WORKLOADS):] + WORKLOADS[: repeat % len(WORKLOADS)]
        for workload in workload_order:
            for profile in profile_order:
                try:
                    record = run_once(args, profile, workload)
                except Exception as error:  # noqa: BLE001 - fail closed, report the reason
                    invalid.append(f"repeat {repeat} {profile}/{workload}: {error}")
                    continue
                checks, expected_receipts = expected_accounting(record, args)
                failed = [name for name, ok in checks.items() if not ok]
                if failed:
                    invalid.append(
                        f"repeat {repeat} {profile}/{workload}: "
                        f"accounting {failed} receipts={record['recipient_drained']}/{expected_receipts}"
                    )
                runs.append({"repeat": repeat, "profile": profile, "workload": workload, "record": record})
                print(
                    f"repeat {repeat} {profile}/{workload}: "
                    f"goodput={record['bulk_goodput_kib_s']:.1f} KiB/s "
                    f"chat_p95={record['chat_p95_ms']:.1f} ms "
                    f"single={record['single_delay_ms']:.1f} ms",
                    flush=True,
                )

    medians = {}
    for workload in WORKLOADS:
        for profile in PROFILES:
            records = [
                run["record"]
                for run in runs
                if run["workload"] == workload and run["profile"] == profile
            ]
            medians[f"{profile}/{workload}"] = {
                "runs": len(records),
                "goodput_kib_s": median([r["bulk_goodput_kib_s"] for r in records if "bulk_chunks" in r and r["bulk_chunks"]]),
                "chat_p95_ms": median([r["chat_p95_ms"] for r in records if r["chat_count"]]),
                "single_delay_ms": median([r["single_delay_ms"] for r in records if r["single_delay_ms"] > 0]),
            }

    gates = {}
    for workload in ("bulk", "mixed"):
        base = medians[f"gc1/{workload}"]["goodput_kib_s"]
        candidate = medians[f"gc2/{workload}"]["goodput_kib_s"]
        ok = base is not None and candidate is not None and candidate >= BULK_GAIN * base
        gates[f"bulk_goodput_{workload}"] = {
            "gc1": base,
            "gc2": candidate,
            "minimum_ratio": BULK_GAIN,
            "ok": ok,
        }
    for workload in ("chat", "mixed"):
        baseline = medians[f"gc1/{workload}"]["chat_p95_ms"]
        candidate = medians[f"gc2/{workload}"]["chat_p95_ms"]
        bound = None if baseline is None else max(
            baseline * (1 + CHAT_TOLERANCE_FRACTION), baseline + CHAT_TOLERANCE_MS
        )
        ok = baseline is not None and candidate is not None and candidate <= bound
        gates[f"chat_p95_{workload}"] = {"gc1": baseline, "gc2": candidate, "bound": bound, "ok": ok}
    shaping = [m["single_delay_ms"] for key, m in medians.items() if key.startswith("gc2/")]
    shaping = [value for value in shaping if value]
    shaping_median = median(shaping)
    gates["shaping_delay"] = {
        "gc2_median_ms": shaping_median,
        "maximum_ms": SHAPING_DELAY_MS_MAX,
        "ok": shaping_median is not None and shaping_median <= SHAPING_DELAY_MS_MAX,
    }
    qualified = not invalid and not args.quick and all(gate["ok"] for gate in gates.values())
    reasons = []
    if args.quick:
        reasons.append("quick runs are non-qualifying")
    if invalid:
        reasons.extend(invalid)
    reasons.extend(name for name, gate in gates.items() if not gate["ok"])

    report = {
        "schema": 1,
        "kind": "application_utilization_study",
        "quick": args.quick,
        "repeats": repeats,
        "seed": args.seed,
        "binary_sha256": binary_sha,
        "workload": {
            "chat_count": args.chat_count,
            "chat_interval_ms": args.chat_interval_ms,
            "bulk_bytes": args.bulk_bytes,
            "bulk_chunk": args.bulk_chunk,
            "inflight": args.inflight,
        },
        "acceptance": {
            "bulk_gain": BULK_GAIN,
            "chat_tolerance_fraction": CHAT_TOLERANCE_FRACTION,
            "chat_tolerance_ms": CHAT_TOLERANCE_MS,
            "shaping_delay_ms_max": SHAPING_DELAY_MS_MAX,
        },
        "medians": medians,
        "gates": gates,
        "invalid": invalid,
        "qualified": qualified,
        "reasons": reasons,
        "runs": runs,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"qualified: {qualified}")
    for reason in reasons:
        print(f"  not qualified: {reason}")
    print(f"report: {args.report}")
    return 0 if qualified else 1


if __name__ == "__main__":
    sys.exit(main())
