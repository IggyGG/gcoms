#!/usr/bin/env python3
"""Analyze only the synthetic loopback study; no packet capture or live targets.

Throughput describes validated request payload, not durable file delivery. The
privacy result deliberately remains not_qualified: byte-read observations cannot
establish packet-level indistinguishability or sender/receiver unlinkability.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics

MAX_REPORT_BYTES = 64 * 1024 * 1024


def positive(value, name, allow_zero=False):
    if type(value) is not int or value < (0 if allow_zero else 1):
        raise ValueError(f"invalid {name}")
    return value


def budget(size, interval_ms):
    positive(size, "size")
    positive(interval_ms, "interval")
    rate = size * 1000 / interval_ms
    return {
        "bytes_per_interval_per_direction": size,
        "interval_ms": interval_ms,
        "kib_s_per_direction": rate / 1024,
        "gib_day_duplex": rate * 2 * 86400 / 2**30,
        "ideal_seconds_per_mib_one_direction": 2**20 / rate,
    }


def costs():
    return {
        "kind": "analytical_wire_budgets",
        "scope": "one_continuously_open_bidirectional_stream_before_protocol_overhead",
        "profiles": [budget(size, ms) for size, ms in [(4096, 100), (16384, 100), (4096, 20), (16384, 20)]],
        "one_mib_s_each_direction_gib_day": 2 * 86400 / 1024,
        "qualification": "not_measured_goodput_or_approved_privacy_profiles",
    }


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def distribution(values):
    return {
        "count": len(values),
        "min": min(values) if values else None,
        "median": statistics.median(values) if values else None,
        "p95": percentile(values, .95),
        "p99": percentile(values, .99),
        "max": max(values) if values else None,
    }


def mean_interval(values):
    """Descriptive resampling by independent run, never by correlated records."""
    if len(values) < 2:
        return None
    rng = random.Random(271828)
    means = [statistics.mean(rng.choices(values, k=len(values))) for _ in range(2000)]
    return [percentile(means, .025), percentile(means, .975)]


def validate(report):
    if not isinstance(report, dict) or report.get("schema") != 1 or report.get("kind") != "loopback_transport_study":
        raise ValueError("expected schema-1 loopback transport study")
    if report.get("sample_unit") != "tcp_read_chunk_not_packet" or report.get("privacy_verdict") != "not_qualified":
        raise ValueError("unsupported observation or privacy claim")
    if report.get("payload") != "generated_non_executable_bytes" or type(report.get("quick")) is not bool:
        raise ValueError("invalid fixture description")
    trials = report.get("trials")
    if not isinstance(trials, list) or not 1 <= len(trials) <= 4096:
        raise ValueError("invalid trial count")
    keys = set()
    for trial in trials:
        if not isinstance(trial, dict):
            raise ValueError("invalid trial object")
        name = trial.get("case")
        if not isinstance(name, str) or not name or len(name) > 80 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in name):
            raise ValueError("invalid fixture case")
        repeat = positive(trial.get("repeat"), "repeat", True)
        if (name, repeat) in keys:
            raise ValueError("duplicate trial")
        keys.add((name, repeat))
        if "error" in trial:
            if trial["error"] not in ("timeout", "fixture_failed"):
                raise ValueError("invalid failure category")
            continue
        for field in ("transfer_us", "measurement_us", "carrier_slot_ms", "window"):
            positive(trial.get(field), field)
        positive(trial.get("useful_bytes"), "useful_bytes", True)
        positive(trial.get("warm_us"), "warm_us", True)
        for field in ("process_cpu_us", "process_peak_rss_kib"):
            positive(trial.get(field, 0), field, True)
        for name in ("queue_wait", "service"):
            metric = trial.get("scheduler", {}).get(name, {})
            for field in ("count", "total_us"):
                positive(metric.get(field), f"{name}.{field}", True)
        if trial["transfer_us"] > trial["measurement_us"]:
            raise ValueError("transfer exceeds observation duration")
        completions = trial.get("completions")
        if not isinstance(completions, list) or len(completions) > 4096:
            raise ValueError("invalid completions")
        for item in completions:
            if not isinstance(item, dict):
                raise ValueError("invalid completion object")
            positive(item.get("us"), "latency", True)
            positive(item.get("payload_bytes"), "payload")
        if sum(c["payload_bytes"] for c in completions) != trial["useful_bytes"]:
            raise ValueError("payload accounting mismatch")
        observers = trial.get("observers")
        if not isinstance(observers, list) or len(observers) != 3:
            raise ValueError("expected three loopback link observers")
        for index, observer in enumerate(observers):
            if not isinstance(observer, dict):
                raise ValueError("invalid observer object")
            if observer.get("fixture_link") != index:
                raise ValueError("invalid fixture link order")
            totals = observer.get("bytes")
            if not isinstance(totals, list) or len(totals) != 2:
                raise ValueError("invalid byte totals")
            for total in totals:
                positive(total, "wire bytes", True)
            dropped = positive(observer.get("dropped"), "dropped", True)
            samples = observer.get("samples")
            if not isinstance(samples, list) or len(samples) > 65536:
                raise ValueError("invalid trace bound")
            sums = [0, 0]
            previous = 0
            for sample in samples:
                if not isinstance(sample, dict):
                    raise ValueError("invalid sample object")
                us = positive(sample.get("us"), "sample time", True)
                direction = sample.get("direction")
                count = positive(sample.get("bytes"), "sample bytes")
                if type(direction) is not int or direction not in (0, 1) or count > 32768:
                    raise ValueError("invalid byte-read sample")
                if us < previous or us > trial["measurement_us"] + 1_000_000:
                    raise ValueError("invalid sample order or duration")
                previous = us
                sums[direction] += count
            if any(s > t for s, t in zip(sums, totals)) or (not dropped and sums != totals):
                raise ValueError("wire accounting mismatch")


def analyze(report):
    validate(report)
    grouped = defaultdict(list)
    failures = []
    for trial in report["trials"]:
        if "error" in trial:
            failures.append({key: trial[key] for key in ("case", "repeat", "error")})
        else:
            grouped[trial["case"]].append(trial)
    summaries = []
    for name, trials in sorted(grouped.items()):
        rates = [t["useful_bytes"] * 1e6 / t["transfer_us"] / 1024 for t in trials if t["useful_bytes"]]
        wire_rates = [sum(sum(o["bytes"]) for o in t["observers"]) * 1e6 / t["measurement_us"] / 1024 for t in trials]
        latencies = [c["us"] / 1000 for t in trials for c in t["completions"]]
        chat = [c["us"] / 1000 for t in trials for c in t["completions"] if c["payload_bytes"] == 128]
        summaries.append({
            "case": name, "runs": len(trials),
            "request_payload_goodput_kib_s": distribution(rates),
            "goodput_mean_bootstrap_interval_95": mean_interval(rates),
            "all_observed_links_duplex_kib_s": distribution(wire_rates),
            "request_completion_ms": distribution(latencies),
            "chat_completion_ms": distribution(chat),
            "warm_ms": distribution([t["warm_us"] / 1000 for t in trials]),
            "process_cpu_ms": distribution([t["process_cpu_us"] / 1000 for t in trials if t.get("process_cpu_us")]),
            "process_lifetime_peak_rss_kib": distribution([t["process_peak_rss_kib"] for t in trials if t.get("process_peak_rss_kib")]),
            "per_link_duplex_kib_s": [distribution([
                sum(t["observers"][index]["bytes"]) * 1e6 / t["measurement_us"] / 1024
                for t in trials
            ]) for index in range(3)],
            "dropped_observations": sum(o["dropped"] for t in trials for o in t["observers"]),
            "scheduler_queue_wait_mean_ms": distribution([
                t["scheduler"]["queue_wait"]["total_us"] / t["scheduler"]["queue_wait"]["count"] / 1000
                for t in trials if t["scheduler"]["queue_wait"]["count"]
            ]),
            "scheduler_service_mean_ms": distribution([
                t["scheduler"]["service"]["total_us"] / t["scheduler"]["service"]["count"] / 1000
                for t in trials if t["scheduler"]["service"]["count"]
            ]),
        })
    return {
        "schema": 1, "status": "incomplete" if failures else "measured",
        "quick": report["quick"], "cases": summaries, "failures": failures,
        "costs": costs(),
        "wire_shape_observations": wire_shape_observations(grouped),
        "privacy": {
            "verdict": "not_qualified",
            "required_followup": "architecture_review_and_independent_anonymity_evaluation",
            "reasons": [
                "TCP read boundaries are not packet boundaries; these traces measure link byte budgets only.",
                "Synthetic echo fixtures do not establish endpoint unlinkability, application encryption, or durable file completion.",
                "No global-observer or colluding-relay anonymity test has passed.",
                "Higher-rate carrier cases change observable traffic; their speed does not authorize a production profile.",
            ],
        },
        "limitations": [
            "Loopback timings are not Internet latency predictions.",
            "The delayed case inserts a delay per proxy read/write; it is not calibrated RTT or packet loss.",
            "Bootstrap admission retries and recipient application ACKs are outside this microbenchmark.",
            "Repeated-run bootstrap intervals are descriptive; three trials are too few for a security conclusion.",
            "CPU covers this fixture process; RSS is its lifetime high-water mark, not per-case memory growth. Battery energy is unmeasured.",
        ],
    }


def wire_shape_observations(grouped):
    """A bounded fixture observation, not a classifier or unlinkability score."""
    selected = {name: grouped.get(name, []) for name in (
        "idle_carrier_100ms", "carrier_100ms_window_4",
        "idle_production_scheduler_carrier_100ms", "production_scheduler_carrier_100ms",
    )}
    present = [t for values in selected.values() for t in values]
    if not present:
        return {"status": "controls_missing"}
    if any(not values for values in selected.values()):
        return {"status": "controls_incomplete"}
    if any(o["dropped"] for t in present for o in t["observers"]):
        return {"status": "observations_dropped"}
    window_us = min(8_000_000, min(t["measurement_us"] for t in present))
    values = {}
    for name, trials in selected.items():
        values[name] = [distribution([
            sum(s["bytes"] for s in t["observers"][link]["samples"] if s["us"] < window_us) * 1e6 / window_us / 1024
            for t in trials
        ]) for link in range(3)]
    return {
        "status": "descriptive_only", "common_prefix_us": window_us,
        "per_link_duplex_kib_s": values,
        "interpretation": "Link 2 is the synthetic terminal. Different terminal activity with similarly shaped outer links prevents inferring path-wide privacy from outer padding alone. Links 0 and 1 can exchange entry/middle roles between trials.",
    }


def markdown(summary):
    def number(value):
        return "—" if value is None else f"{value:.2f}"
    rows = ["# Relay transport measurements", "", "Privacy qualification: **NOT QUALIFIED**.", "",
            "| Case | Runs | Median request KiB/s | Median completion ms | All-link duplex KiB/s |",
            "|---|---:|---:|---:|---:|"]
    for case in summary["cases"]:
        rows.append(f'| {case["case"]} | {case["runs"]} | {number(case["request_payload_goodput_kib_s"]["median"])} | {number(case["request_completion_ms"]["median"])} | {number(case["all_observed_links_duplex_kib_s"]["median"])} |')
    rows += ["", "All-link bytes count traffic on every observed link in both directions. Useful throughput counts only validated request payload.", "",
             "## Limits", ""]
    rows.extend(f"- {item}" for item in summary["limitations"] + summary["privacy"]["reasons"])
    if summary["failures"]:
        rows += ["", f'Failed trials retained: {len(summary["failures"])}.']
    return "\n".join(rows) + "\n"


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("costs")
    command = commands.add_parser("analyze")
    command.add_argument("input", type=Path)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    if args.command == "costs":
        print(json.dumps(costs(), indent=2))
        return 0
    with args.input.open("rb") as source:
        raw = source.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("study exceeds report byte bound")
    summary = analyze(json.loads(raw))
    summary["input_sha256"] = hashlib.sha256(raw).hexdigest()
    write_new(args.output, json.dumps(summary, indent=2, allow_nan=False) + "\n")
    if args.markdown:
        write_new(args.markdown, markdown(summary))
    return 0 if summary["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
