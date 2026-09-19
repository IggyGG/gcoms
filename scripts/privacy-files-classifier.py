#!/usr/bin/env python3
"""Profile 12 privacy gate: idle/chat and identical bulk with/without chat.

Run-independent training and evaluation, with paired-run cluster bootstrap.
File activity and approximate volume are observable; chat privacy remains gated.
The historical classifier/reports retain their original contract.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import numpy as np

_spec = importlib.util.spec_from_file_location("historical_privacy", Path(__file__).with_name("privacy-classifier.py"))
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
WORKLOADS = ("idle", "chat", "bulk", "mixed")
MIN_RUNS = 8


def auc(values, labels):
    """Mann-Whitney ROC AUC, assigning average ranks to tied scores."""
    values, labels = np.asarray(values), np.asarray(labels)
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and values[order[end]] == values[order[start]]:
            end += 1
        ranks[order[start:end]] = (start + 1 + end) / 2
        start = end
    positive = int(labels.sum())
    negative = len(labels) - positive
    if not positive or not negative:
        raise ValueError("both classes are required")
    return float((ranks[labels == 1].sum() - positive * (positive + 1) / 2) / (positive * negative))


def read_packets(path, entry_ports):
    output = subprocess.run(
        ["tcpdump", "-r", str(path), "-nn", "-tt", "--time-stamp-precision=micro", "tcp"],
        capture_output=True, text=True, check=True,
    ).stdout
    pattern = re.compile(r"^(\d+\.\d+) IP6? \S+\.(\d+) > \S+\.(\d+):.*Flags \[([^]]*)\].*length (\d+)")
    rows = []
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            stamp, src, dst, flags, length = match.groups()
            if int(src) in entry_ports or int(dst) in entry_ports:
                rows.append((float(stamp), int(src), int(dst), int(length), flags))
    if not rows:
        raise ValueError("no parsable packets on the declared entry link")
    return rows


def features(rows, port, start, seconds):
    """All fixed one-second windows, including silence, with correct directions."""
    ports = {port} if isinstance(port, int) else set(port)
    result = []
    for index in range(seconds):
        window = [row for row in rows if start + index <= row[0] < start + index + 1]
        up = [row for row in window if row[2] in ports]
        down = [row for row in window if row[1] in ports]
        values = [len(up), len(down), sum(r[3] for r in up), sum(r[3] for r in down)]
        for direction in (up, down):
            gaps = np.diff(sorted(r[0] for r in direction))
            values.extend([float(gaps.mean()) if len(gaps) else 0.0,
                           float(gaps.max()) if len(gaps) else 0.0])
        sizes = [r[3] for r in window]
        values.extend([sum(s < 100 for s in sizes), sum(100 <= s < 300 for s in sizes),
                       sum(300 <= s < 1000 for s in sizes), sum(1000 <= s < 4096 for s in sizes),
                       sum(s >= 4096 for s in sizes), sum("S" in r[4] for r in window),
                       sum("R" in r[4] for r in window)])
        result.append(values)
    return np.asarray(result, dtype=float)


def evaluate(training, evaluation, bootstrap=2000):
    # Each list entry contains both classes from one independent, paired run.
    if len(training) < MIN_RUNS or len(evaluation) < MIN_RUNS:
        raise ValueError(f"at least {MIN_RUNS} independent paired runs per split are required")
    x_train = np.vstack([row[0] for row in training])
    y_train = np.concatenate([row[1] for row in training])
    mean, std = x_train.mean(axis=0), x_train.std(axis=0)
    std[std == 0] = 1
    weights = _base.logistic_fit((x_train - mean) / std, y_train)
    grouped = [(_base.scores(weights, (x - mean) / std), y) for x, y in evaluation]
    value = auc(np.concatenate([g[0] for g in grouped]), np.concatenate([g[1] for g in grouped]))
    rng = np.random.default_rng(20260920)
    resampled = []
    for _ in range(bootstrap):
        chosen = [grouped[index] for index in rng.integers(0, len(grouped), len(grouped))]
        sample = auc(np.concatenate([g[0] for g in chosen]), np.concatenate([g[1] for g in chosen]))
        resampled.append(max(sample, 1 - sample))
    upper = float(np.percentile(resampled, 97.5))
    return {"auc": value, "separability": max(value, 1 - value),
            "separability_upper_97_5": upper, "ok": upper <= 0.55,
            "train_runs": len(training), "eval_runs": len(evaluation),
            "bootstrap_unit": "paired independent run"}


def load_captures(directory, seeds):
    captures = {}
    common = None
    for path in sorted(directory.glob("*.meta.json")):
        meta = json.loads(path.read_text())
        if meta.get("seed") not in seeds or meta.get("profile") != "gchat-files":
            continue
        key = (meta["workload"], meta["seed"])
        if key in captures or key[0] not in WORKLOADS:
            raise ValueError(f"duplicate or unsupported capture {key}")
        record = meta.get("record") or {}
        if meta["inner_rc"] or not meta.get("protected") or meta["cadence"] != "production" or record.get("failures") != 0:
            raise ValueError(f"invalid/failed capture {key}")
        expected = max(1024, meta["bytes"])
        expected = ((expected + 1023) // 1024) * 1024
        if record.get("bulk_acked_bytes") != (expected if key[0] in ("bulk", "mixed") else 0):
            raise ValueError(f"incomplete or unmatched bulk workload {key}")
        if record.get("chat_sent") != (max(1, meta["bytes"] // 128) if key[0] in ("chat", "mixed") else 0):
            raise ValueError(f"incomplete chat workload {key}")
        identity = (meta.get("binary_sha256"), meta["seconds"], meta["bytes"], meta.get("chat_interval_ms"))
        if not identity[0] or (common is not None and identity != common):
            raise ValueError("captures must have the same binary, duration and workload parameters")
        common = identity
        start, end = meta.get("measurement_start_epoch"), meta.get("measurement_end_epoch")
        if start is None or end is None or abs(end - start - meta["seconds"]) > 0.5:
            raise ValueError(f"missing or unequal measurement lifetime {key}")
        pcap = directory / meta["pcap"]
        if hashlib.sha256(pcap.read_bytes()).hexdigest() != meta["pcap_sha256"]:
            raise ValueError(f"pcap digest mismatch {key}")
        # Both relay addresses can be selected as entries. Observe both, not
        # just the endpoint named "entry" by the original two-relay fixture.
        ports = {int(record[name].rsplit(":", 1)[1]) for name in ("entry_addr", "middle_addr")}
        rows = read_packets(pcap, ports)
        x = features(rows, ports, start, meta["seconds"])
        # Setup/teardown remain observable even though windows use equal lifetimes.
        run = np.asarray([[sum("S" in r[4] for r in rows), sum("R" in r[4] for r in rows),
                           record["entry_connections"], record["middle_connections"]]], dtype=float)
        captures[key] = (x, run)
    missing = [(w, s) for s in seeds for w in WORKLOADS if (w, s) not in captures]
    if missing:
        raise ValueError(f"missing captures: {missing}")
    return captures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--train-seeds", required=True, help="comma-separated independent run seeds")
    parser.add_argument("--eval-seeds", required=True)
    args = parser.parse_args()
    report = {"contract": "gchat-file-profile-12", "qualified": False, "gates": {}}
    try:
        train, evaluation = [list(map(int, value.split(","))) for value in (args.train_seeds, args.eval_seeds)]
        if len(set(train)) != len(train) or len(set(evaluation)) != len(evaluation) or set(train) & set(evaluation):
            raise ValueError("training and held-out run seeds must be unique and disjoint")
        captures = load_captures(args.out, train + evaluation)
        for name, pair in (("idle_vs_chat", ("idle", "chat")), ("matched_bulk_vs_mixed", ("bulk", "mixed"))):
            for column, scope in enumerate(("windows", "connections")):
                def design(seeds):
                    return [(np.vstack([captures[(w, s)][column] for w in pair]),
                             np.concatenate([np.full(len(captures[(w, s)][column]), label)
                                             for label, w in enumerate(pair)])) for s in seeds]
                report["gates"][f"{name}_{scope}"] = evaluate(design(train), design(evaluation))
        report["qualified"] = all(g["ok"] for g in report["gates"].values())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
    target = args.out / "privacy-files-report.json"
    with target.open("x") as output:
        output.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
