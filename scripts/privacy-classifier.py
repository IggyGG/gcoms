#!/usr/bin/env python3
"""Measure GC/2 activity separation; valid results inform the owner's decision.

Predeclared model: one-second packet windows, training-only standardization,
L2 logistic regression (zero initialization, 2000 steps, lr=.1, lambda=.001).
Training/evaluation seeds are disjoint. Confidence intervals resample complete
paired runs, never adjacent windows. Unfavorable privacy results are informative;
missing, invalid, or insufficient evidence is an execution failure.
Historical captures can be reanalyzed with --diagnostic but cannot qualify.
Requires numpy and tshark; reports retain versions and script hashes.
"""
import argparse
import ipaddress
import json
import math
from pathlib import Path
import subprocess
import sys

import numpy as np
from privacy_packets import direction, endpoint, new_connections, packets, sha256, write_new

FEATURE_NAMES = [
    "up_pkts", "down_pkts", "up_wire_bytes", "down_wire_bytes",
    "up_mean_iat", "up_max_iat", "down_mean_iat", "down_max_iat",
    "size_lt100", "size_lt300", "size_lt1000", "size_lt4096",
    "size_ge4096", "syn", "rst",
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="capture directory")
    parser.add_argument("--report", type=Path, required=True, help="new report; never overwrite evidence")
    parser.add_argument("--train-seeds", default="1001:1010", help="inclusive range or comma-separated seeds")
    parser.add_argument("--eval-seeds", default="2001:2020")
    parser.add_argument("--windows", type=float, default=1.0)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--idle-workload", choices=("idle", "warm_idle"), default="warm_idle")
    parser.add_argument("--entry-link-only", action="store_true", help="entry-only diagnostic scope")
    parser.add_argument("--diagnostic", action="store_true", help="historical/short runs; never release evidence")
    return parser.parse_args()


def seeds(value):
    if ":" in value:
        low, high = map(int, value.split(":"))
        if high < low or high - low > 10000:
            raise ValueError("invalid seed range")
        values = list(range(low, high + 1))
    else:
        values = list(map(int, value.split(",")))
    if not values or len(values) != len(set(values)) or min(values) < 0:
        raise ValueError("seeds must be unique nonnegative integers")
    return values


def window_features(rows, observer_ips, windows, start, end, entry=None):
    if not all(math.isfinite(x) for x in (windows, start, end)) or windows <= 0 or end <= start:
        raise ValueError("invalid observation interval")
    count = (end - start) / windows
    if not math.isclose(count, round(count), abs_tol=1e-4) or not 1 <= count <= 1_000_000:
        raise ValueError("observation interval must contain complete windows")
    buckets = [[] for _ in range(round(count))]
    for packet in rows:
        if start <= packet.time < end:
            side = direction(packet, observer_ips, entry)
            if side:
                buckets[min(int((packet.time - start) / windows), len(buckets) - 1)].append((packet, side))
    features = []
    for bucket in buckets:
        up = [p for p, side in bucket if side == "up"]
        down = [p for p, side in bucket if side == "down"]
        row = [len(up), len(down), sum(p.wire_bytes for p in up), sum(p.wire_bytes for p in down)]
        for stream in (up, down):
            gaps = np.diff([p.time for p in stream])
            row += [float(gaps.mean()) if len(gaps) else 0., float(gaps.max()) if len(gaps) else 0.]
        sizes = [p.wire_bytes for p, _ in bucket]
        row += [sum(s < 100 for s in sizes), sum(100 <= s < 300 for s in sizes),
                sum(300 <= s < 1000 for s in sizes), sum(1000 <= s < 4096 for s in sizes),
                sum(s >= 4096 for s in sizes), sum(p.syn and not p.ack for p, _ in bucket),
                sum(p.rst for p, _ in bucket)]
        features.append(row)
    return np.asarray(features, dtype=float)


def logistic_fit(x, y):
    weights = np.zeros(x.shape[1] + 1)
    design = np.hstack([np.ones((x.shape[0], 1)), x])
    for _ in range(2000):
        logits = np.clip(design @ weights, -500, 500)
        probs = 1.0 / (1.0 + np.exp(-logits))
        gradient = design.T @ (probs - y) / len(y)
        gradient[1:] += 1e-3 * weights[1:]
        weights -= 0.1 * gradient
    return weights


def scores(weights, x):
    return np.hstack([np.ones((x.shape[0], 1)), x]) @ weights


def roc_auc(values, labels):
    values, labels = np.asarray(values), np.asarray(labels)
    if values.ndim != 1 or values.shape != labels.shape or not np.isfinite(values).all():
        raise ValueError("invalid AUC inputs")
    if not np.isin(labels, [0, 1]).all() or len(np.unique(labels)) != 2:
        raise ValueError("AUC needs both binary classes")
    negatives = np.sort(values[labels == 0])
    positives = values[labels == 1]
    below = np.searchsorted(negatives, positives, side="left")
    equal = np.searchsorted(negatives, positives, side="right") - below
    return float((below + .5 * equal).sum() / (len(positives) * len(negatives)))


def run_interval(predictions, labels, groups, bootstrap):
    if bootstrap < 100:
        raise ValueError("at least 100 bootstrap samples required")
    keys = np.unique(groups)
    if len(keys) < 2:
        return None
    members = [np.flatnonzero(groups == key) for key in keys]
    if any(len(np.unique(labels[index])) != 2 for index in members):
        raise ValueError("each paired evaluation run must include both classes")
    rng = np.random.default_rng(20260919)
    samples = []
    for _ in range(bootstrap):
        index = np.concatenate([members[i] for i in rng.integers(0, len(keys), len(keys))])
        auc = roc_auc(predictions[index], labels[index])
        samples.append(max(auc, 1 - auc))
    return [float(x) for x in np.percentile(samples, [2.5, 97.5])]


def read_capture(path, args):
    meta = json.loads(path.read_text())
    if meta.get("inner_rc") != 0:
        raise ValueError(f"failed capture: {path.name}")
    pcap = path.parent / meta["pcap"]
    if not pcap.resolve().is_relative_to(path.parent.resolve()) or sha256(pcap) != meta.get("pcap_sha256"):
        raise ValueError(f"capture hash/path mismatch: {path.name}")
    rows = packets(pcap)
    if not rows:
        raise ValueError(f"empty capture: {path.name}")
    entry_value = (meta.get("record") or {}).get("entry_addr")
    entry = endpoint(entry_value) if entry_value else None
    observer_values = meta.get("observer_ips") or []
    if not isinstance(observer_values, list):
        raise ValueError("observer_ips must be an explicit address list")
    observer_ips = {str(ipaddress.ip_address(value)) for value in observer_values}
    if args.entry_link_only:
        if not entry:
            raise ValueError("entry-only scope requires the exact entry address")
        rows = [p for p in rows if p.source == entry or p.destination == entry]
    if not observer_ips and not (args.diagnostic and entry and args.entry_link_only):
        raise ValueError("capture requires an unambiguous observer address")
    bounds = meta.get("measurement")
    if bounds:
        start, end = float(bounds["start_epoch"]), float(bounds["end_epoch"])
    elif args.diagnostic and rows:
        start = float(meta.get("idle_start_epoch") or rows[0].time)
        end = start + int((rows[-1].time - start) / args.windows) * args.windows
    else:
        raise ValueError("capture has no explicit measurement interval")
    if not args.diagnostic:
        if args.entry_link_only or meta.get("capture_scope") != "isolated_client_interface":
            raise ValueError("release evidence must include all isolated client interface traffic")
        if meta.get("cadence") != "production" or end - start < 300:
            raise ValueError("release observation needs production cadence and >=300 seconds")
        if meta.get("dropped_packets") != 0:
            raise ValueError("missing capture loss accounting or packets dropped")
        provenance = meta.get("provenance") or {}
        if not provenance.get("build_manifest_sha256") or not provenance.get("build_manifest"):
            raise ValueError("capture lacks build provenance")
        manifest = path.parent / provenance["build_manifest"]
        if not manifest.resolve().is_relative_to(path.parent.resolve()) or sha256(manifest) != provenance["build_manifest_sha256"]:
            raise ValueError("build manifest hash/path mismatch")
        build = json.loads(manifest.read_text())
        if build.get("binary_sha256") != meta.get("binary_sha256") or not meta.get("binary_sha256"):
            raise ValueError("captured executable differs from build manifest")
        if meta.get("capture_started_epoch", math.inf) > start or meta.get("capture_finished_epoch", -math.inf) < end:
            raise ValueError("capture does not cover the measured interval")
    observed = [p for p in rows if start <= p.time < end and direction(p, observer_ips, entry)]
    features = window_features(rows, observer_ips, args.windows, start, end, entry)
    duration = end - start
    return meta, features, {
        "capture": path.name, "pcap_sha256": meta["pcap_sha256"], "seconds": duration,
        "packets": len(observed), "wire_bytes": sum(p.wire_bytes for p in observed),
        "wire_bytes_per_second": sum(p.wire_bytes for p in observed) / duration,
        "up_wire_bytes": sum(p.wire_bytes for p in observed if direction(p, observer_ips, entry) == "up"),
        "down_wire_bytes": sum(p.wire_bytes for p in observed if direction(p, observer_ips, entry) == "down"),
        "estimated_decimal_gb_30_days": {
            str(hours) + "h_per_day": sum(p.wire_bytes for p in observed) / duration * hours * 3600 * 30 / 1e9
            for hours in (8, 24)
        },
        "tcp_connections": new_connections(observed),
        "tcp_retransmitted_packets": sum(p.retransmission for p in observed),
        "large_packets_per_second": sum(p.wire_bytes >= 4096 for p in observed) / duration,
    }


def analyze(args):
    if not math.isfinite(getattr(args, "windows", 1)) or getattr(args, "windows", 1) <= 0:
        raise ValueError("window duration must be positive and finite")
    train, evaluation = seeds(args.train_seeds), seeds(args.eval_seeds)
    if set(train) & set(evaluation):
        raise ValueError("training and evaluation seeds overlap")
    if not args.diagnostic and (len(train) < 10 or len(evaluation) < 20):
        raise ValueError("release measurements require >=10 training and >=20 evaluation runs")
    captures, costs, configurations = {}, [], set()
    for path in sorted(args.out.glob("*.meta.json")):
        meta, features, cost = read_capture(path, args)
        key = meta["workload"], meta["seed"]
        if key in captures:
            raise ValueError(f"duplicate run: {key}")
        captures[key] = features
        costs.append(cost | {"workload": key[0], "seed": key[1]})
        configurations.add(json.dumps({k: meta.get(k) for k in ("profile", "traffic_profile", "entries", "cadence", "network", "provenance", "binary_sha256")}, sort_keys=True))
    if len(configurations) != 1:
        raise ValueError("missing captures or mixed source/profile/network configurations")

    def design(classes, cohort):
        xs, ys, groups = [], [], []
        for seed in cohort:
            for workload, label in classes:
                x = captures[(workload, seed)]
                xs.append(x)
                ys.append(np.full(len(x), label))
                groups.append(np.full(len(x), seed))
        return np.vstack(xs), np.concatenate(ys), np.concatenate(groups)

    comparisons = {}
    for name, classes in (("chat_vs_bulk", (("chat", 1), ("bulk", 0))),
                          ("idle_vs_chat", ((args.idle_workload, 0), ("chat", 1)))):
        x_train, y_train, _ = design(classes, train)
        x_eval, y_eval, groups = design(classes, evaluation)
        if not args.diagnostic and len({len(captures[(w, s)]) for w, _ in classes for s in train + evaluation}) != 1:
            raise ValueError("comparison captures have unequal observation durations")
        mean, std = x_train.mean(axis=0), x_train.std(axis=0)
        std[std == 0] = 1
        model = logistic_fit((x_train - mean) / std, y_train)
        predictions = scores(model, (x_eval - mean) / std)
        auc = roc_auc(predictions, y_eval)
        interval = run_interval(predictions, y_eval, groups, args.bootstrap)
        comparisons[name] = {
            "auc": auc, "separability": max(auc, 1 - auc),
            "separability_interval_95": interval,
            "reference_threshold_met": interval is not None and interval[1] <= .55,
            "training_runs_per_class": len(train), "evaluation_runs_per_class": len(evaluation),
            "training_windows": len(y_train), "evaluation_windows": len(y_eval),
            "training_mean": mean.tolist(), "training_std": std.tolist(),
            "model_coefficients": model.tolist(),
        }
    return {
        "schema": 2, "measurement_valid": not args.diagnostic,
        "status": "diagnostic" if args.diagnostic else "measured",
        "scope": "entry_only_pooled_fixture" if args.entry_link_only else "isolated_client_interface",
        "reference_threshold": .55, "reference_threshold_is_release_veto": False,
        "release_decision": "pending_owner_review", "comparisons": comparisons,
        "sample_unit": "independent paired run", "window_seconds": args.windows,
        "features": FEATURE_NAMES, "runs": costs,
        "limitations": ["Empirical classifier result, not an anonymity proof.",
                        "Costs count captured IP frame bytes, excluding physical preambles, gaps and unseen link overhead.",
                        "Monthly estimates extrapolate the measured workload and connected hours; they are not idle-only allowances.",
                        "No physical mobile energy or suspension qualification."],
    }


def main():
    args = parse_args()
    try:
        report = analyze(args)
        report["tooling"] = {
            "numpy": np.__version__,
            "tshark": subprocess.check_output(["tshark", "--version"], text=True).splitlines()[0],
            "classifier_sha256": sha256(__file__),
            "packet_parser_sha256": sha256(Path(__file__).with_name("privacy_packets.py")),
            "timestamp_order_policy": "stable chronological order; reject backsteps above 10 ms",
        }
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        report = {"schema": 2, "measurement_valid": False, "status": "invalid", "reason": str(error)}
    encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
    write_new(args.report, encoded)
    print(encoded, end="")
    return 0 if report.get("measurement_valid") or (args.diagnostic and report.get("status") == "diagnostic") else 1


if __name__ == "__main__":
    sys.exit(main())
