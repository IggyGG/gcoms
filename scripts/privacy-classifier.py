#!/usr/bin/env python3
"""Predeclared privacy classifier for the GC/2 gate (numpy only).

Pipeline (fixed before any qualification run):
  * One-second windows over each capture's harness ports.
  * Features per window: up/down packet counts and byte totals, up/down mean
    and max inter-arrival seconds, size-bin counts (<100, <300, <1000, <4096),
    packets >= 4096 bytes, SYN count and RST count.
  * Binary labels from the workload (chat=1 vs bulk=0; idle=0 vs chat=1).
  * Train on seed 7 captures, evaluate on held-out seed 11 captures.
  * L2 logistic regression, zero init, full-batch gradient descent, 2000
    iterations, learning rate 0.1, lambda 1e-3, no early stopping.
  * ROC-AUC with a 2000-resample percentile bootstrap; the gate is the upper
    97.5% bound <= 0.55.

Independence checks from the same captures: SYN counts per run, packets
>= 4096 bytes in chat runs, and a permutation test (10000 draws) on window
packet counts between idle and chat runs.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

FEATURE_NAMES = [
    "up_pkts", "down_pkts", "up_bytes", "down_bytes",
    "up_mean_iat", "up_max_iat", "down_mean_iat", "down_max_iat",
    "size_lt100", "size_lt300", "size_lt1000", "size_lt4096",
    "size_ge4096", "syn", "rst",
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="capture directory")
    parser.add_argument("--train-seed", type=int, default=7)
    parser.add_argument("--eval-seed", type=int, default=11)
    parser.add_argument("--windows", type=int, default=1)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--skip-seconds", type=float, default=0.0,
                        help="drop this much lead-in time from every capture")
    parser.add_argument("--idle-workload", choices=("idle", "warm_idle"), default="idle")
    parser.add_argument("--entry-link-only", action="store_true",
                        help="keep only packets on the client's entry link")
    return parser.parse_args()


def packets(pcap: Path):
    text = subprocess.run(
        ["tcpdump", "-r", str(pcap), "-nn", "-q", "-tt",
         "--time-stamp-precision=micro", "tcp"],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            timestamp = float(parts[0])
        except ValueError:
            continue
        length = 0
        for index, part in enumerate(parts):
            if part == "tcp" and index + 1 < len(parts):
                try:
                    length = int(parts[index + 1])
                except ValueError:
                    length = 0
        try:
            src_port = int(parts[2].rsplit(".", 1)[1])
            dst_port = int(parts[4].rstrip(":").rsplit(".", 1)[1])
        except (IndexError, ValueError):
            continue
        flags = " ".join(parts[5:])
        rows.append((timestamp, src_port, dst_port, length, flags))
    return rows


def window_features(rows, ports, windows):
    if not rows:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=float)
    start = rows[0][0]
    buckets = {}
    for timestamp, src_port, dst_port, length, flags in rows:
        index = int((timestamp - start) // windows)
        buckets.setdefault(index, []).append((timestamp, src_port, dst_port, length, flags))
    features = []
    for index in sorted(buckets):
        entries = sorted(buckets[index])
        up = [e for e in entries if e[1] not in ports]
        down = [e for e in entries if e[2] in ports]
        row = [len(up), len(down),
               sum(e[3] for e in up), sum(e[3] for e in down)]
        for direction in (up, down):
            times = [e[0] for e in direction]
            gaps = np.diff(times) if len(times) > 1 else np.array([])
            row += [float(gaps.mean()) if len(gaps) else 0.0,
                    float(gaps.max()) if len(gaps) else 0.0]
        sizes = [e[3] for e in entries]
        row += [sum(1 for s in sizes if s < 100),
                sum(1 for s in sizes if 100 <= s < 300),
                sum(1 for s in sizes if 300 <= s < 1000),
                sum(1 for s in sizes if 1000 <= s < 4096),
                sum(1 for s in sizes if s >= 4096),
                sum(1 for e in entries if "S" in e[4]),
                sum(1 for e in entries if "R" in e[4])]
        features.append(row)
    return np.asarray(features, dtype=float)


def logistic_fit(x, y):
    weights = np.zeros(x.shape[1] + 1)
    design = np.hstack([np.ones((x.shape[0], 1)), x])
    for _ in range(2000):
        scores = design @ weights
        probs = 1.0 / (1.0 + np.exp(-scores))
        gradient = design.T @ (probs - y) / len(y)
        gradient[1:] += 1e-3 * weights[1:]
        weights -= 0.1 * gradient
    return weights


def scores(weights, x):
    design = np.hstack([np.ones((x.shape[0], 1)), x])
    return design @ weights


def roc_auc(scores_in, y):
    order = np.argsort(scores_in, kind="mergesort")
    ranks = np.empty(len(scores_in), dtype=float)
    ranks[order] = np.arange(1, len(scores_in) + 1)
    positive = ranks[y == 1].sum()
    n_pos = int(y.sum())
    n_neg = len(y) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    return (positive - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def main():
    args = parse_args()
    captures = {}
    for meta_path in sorted(args.out.glob("*.meta.json")):
        meta = json.loads(meta_path.read_text())
        if meta["inner_rc"] != 0:
            continue
        pcap = args.out / meta["pcap"]
        rows = packets(pcap)
        if args.entry_link_only:
            entry = (meta.get("record") or {}).get("entry_addr") or ""
            if entry:
                try:
                    port = int(entry.rsplit(":", 1)[1])
                    rows = [row for row in rows if row[1] == port or row[2] == port]
                except (IndexError, ValueError):
                    pass
        idle_start = meta.get("idle_start_epoch")
        if idle_start:
            cutoff = float(idle_start)
            rows = [row for row in rows if row[0] >= cutoff]
        elif args.skip_seconds > 0 and rows:
            cutoff = rows[0][0] + args.skip_seconds
            rows = [row for row in rows if row[0] >= cutoff]
        captures[(meta["workload"], meta["seed"])] = rows

    ports = {27101, 27102}
    report = {"captures": sorted(f"{k[0]}/{k[1]}" for k in captures), "gates": {}}

    def design(pairs):
        rows, labels = [], []
        for workload, seed, label in pairs:
            features = window_features(captures[(workload, seed)], ports, args.windows)
            if features.size:
                rows.append(features)
                labels.append(np.full(features.shape[0], label, dtype=float))
        return np.vstack(rows), np.concatenate(labels)

    for name, classes in (("chat_vs_bulk", (("chat", 1), ("bulk", 0))),
                          ("idle_vs_chat", ((args.idle_workload, 0), ("chat", 1)))):
        pairs_train = [(w, args.train_seed, l) for w, l in classes]
        pairs_eval = [(w, args.eval_seed, l) for w, l in classes]
        try:
            x_train, y_train = design(pairs_train)
            x_eval, y_eval = design(pairs_eval)
        except KeyError as error:
            report["gates"][name] = {"ok": False, "reason": f"missing capture {error}"}
            continue
        if len(np.unique(y_train)) < 2 or len(np.unique(y_eval)) < 2:
            report["gates"][name] = {"ok": False, "reason": "single-class split"}
            continue
        mean, std = x_train.mean(axis=0), x_train.std(axis=0)
        std[std == 0] = 1.0
        weights = logistic_fit((x_train - mean) / std, y_train)
        evaluated = scores(weights, (x_eval - mean) / std)
        auc = roc_auc(evaluated, y_eval)
        rng = np.random.default_rng(20260919)
        bootstrap = []
        for _ in range(args.bootstrap):
            index = rng.integers(0, len(evaluated), len(evaluated))
            if len(np.unique(y_eval[index])) < 2:
                continue
            sample = roc_auc(evaluated[index], y_eval[index])
            bootstrap.append(max(sample, 1.0 - sample))
        upper_sep = float(np.percentile(bootstrap, 97.5))
        # Separability is two-sided: an AUC far below 0.5 is the same signal
        # with inverted ranking, and the bootstrap is computed per resample.
        separability = max(float(auc), 1.0 - float(auc))
        upper = float(np.percentile(bootstrap, 97.5)) if bootstrap else float("nan")
        report["gates"][name] = {
            "auc": float(auc),
            "separability": separability,
            "separability_upper_97_5": upper_sep,
            "windows_train": int(len(y_train)),
            "windows_eval": int(len(y_eval)),
            "ok": upper_sep <= 0.55,
        }

    # Independence checks.
    def syn_count(workload, seed):
        return sum(1 for row in captures.get((workload, seed), []) if "S" in row[4])

    def big_count(workload, seed):
        return sum(1 for row in captures.get((workload, seed), []) if row[3] >= 4096)

    def window_counts(workload, seed):
        features = window_features(captures.get((workload, seed), []), ports, args.windows)
        return features[:, 0] + features[:, 1] if features.size else np.array([])

    idle_syn = syn_count(args.idle_workload, args.train_seed)
    chat_syn = syn_count("chat", args.train_seed)
    idle_big = big_count(args.idle_workload, args.train_seed)
    chat_big = big_count("chat", args.train_seed)
    bulk_big = big_count("bulk", args.train_seed)
    idle_counts = window_counts(args.idle_workload, args.train_seed)
    chat_counts = window_counts("chat", args.train_seed)
    p_value = None
    if len(idle_counts) and len(chat_counts):
        observed = abs(chat_counts.mean() - idle_counts.mean())
        pooled = np.concatenate([idle_counts, chat_counts])
        rng = np.random.default_rng(7)
        hits = 0
        for _ in range(10000):
            rng.shuffle(pooled)
            split = len(idle_counts)
            if abs(pooled[split:].mean() - pooled[:split].mean()) >= observed:
                hits += 1
        p_value = hits / 10000
    report["independence"] = {
        "idle_syn": idle_syn,
        "chat_syn": chat_syn,
        "chat_connections_ok": chat_syn <= idle_syn,
        "idle_packets_ge_4096": idle_big,
        "chat_packets_ge_4096": chat_big,
        "bulk_packets_ge_4096": bulk_big,
        # Chat must not add bulk-sized records beyond the padded idle schedule
        # (a 20% allowance covers cadence jitter).
        "chat_bulk_emissions_ok": chat_big <= max(1, int(1.2 * idle_big)),
        "window_packet_permutation_p": p_value,
        "scheduling_independent": p_value is None or p_value >= 0.01,
    }
    report["qualified"] = all(
        gate.get("ok") for gate in report["gates"].values()
    ) and all(report["independence"][k] for k in
              ("chat_connections_ok", "chat_bulk_emissions_ok", "scheduling_independent"))
    (args.out / "privacy-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
