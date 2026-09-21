#!/usr/bin/env python3
"""Analyze the fixed, generated loopback utilization study; no live/capture inputs."""
import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import tempfile

SCENARIOS = ("idle", "sparse_chat", "burst_chat", "bulk", "chat_bulk", "four_producers")
VARIANTS = {"baseline": (1, False), "concurrency": (4, False), "packing": (1, True), "combined": (4, True)}
MAX_REPORT_BYTES = 64 * 1024 * 1024


def integer(value, name, lower=0, upper=2**63 - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"invalid {name}")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def describe(values):
    return {"count": len(values), "median": statistics.median(values) if values else None,
            "p95": percentile(values, .95), "min": min(values) if values else None,
            "max": max(values) if values else None}


def validate(report):
    if type(report.get("schema")) is not int or report["schema"] not in (1, 2) or report.get("kind") != "loopback_utilization_study":
        raise ValueError("expected schema-1 or schema-2 loopback utilization study")
    if report["schema"] == 2 and (report.get("credential_epoch_seconds") != 3600 or
            report.get("credential_control") != "defer_before_fixture_until_lifetime_exceeds_trial_deadline"):
        raise ValueError("unexpected credential lifetime control")
    for key, expected in {"payload": "generated_non_executable_bytes", "privacy_verdict": "not_qualified",
                          "sample_unit": "tcp_read_chunk_not_packet", "carrier_slot_ms": 100,
                          "carrier_record_bytes": 4096, "logical_producers_share_one_client": True,
                          "payload_limit": 12000, "queue_limit": 8 * 1024**2, "job_limit": 4096,
                          "trial_timeout_seconds": 120}.items():
        if report.get(key) != expected or type(report.get(key)) is not type(expected):
            raise ValueError(f"unexpected study assumption: {key}")
    if type(report.get("quick")) is not bool or not isinstance(report.get("trials"), list) or len(report["trials"]) > 120:
        raise ValueError("invalid study bounds")
    seen, workloads, offers, orders = set(), {}, {}, set()
    repeats = 1 if report["quick"] else 5
    for trial in report["trials"]:
        scenario = trial["scenario"]
        if scenario not in SCENARIOS:
            raise ValueError("unknown scenario")
        repeat = integer(trial["repeat"], "repeat", upper=repeats - 1)
        variant = trial["variant"]
        name = variant["name"]
        if name not in VARIANTS or variant != dict(name=name, window=VARIANTS[name][0], packing=VARIANTS[name][1]):
            raise ValueError("unknown or modified variant")
        integer(variant["window"], "window", 1, 4)
        if type(variant["packing"]) is not bool:
            raise ValueError("invalid packing flag")
        key = (scenario, repeat, name)
        if key in seen:
            raise ValueError("duplicate trial")
        seen.add(key)
        order = integer(trial["order"], "order", upper=3)
        if (scenario, repeat, order) in orders:
            raise ValueError("duplicate position")
        orders.add((scenario, repeat, order))
        work_key = (scenario, repeat)
        hashed = trial["workload_sha256"]
        if not isinstance(hashed, str) or len(hashed) != 64 or any(c not in "0123456789abcdef" for c in hashed):
            raise ValueError("invalid workload hash")
        if workloads.setdefault(work_key, hashed) != hashed:
            raise ValueError("unmatched workloads")
        if report["schema"] == 2:
            started = integer(trial["credential_started_unix"], "credential start")
            expiry = integer(trial["credential_expires_unix"], "credential expiry")
            integer(trial["finished_unix"], "finish time", started)
            integer(trial["preflight_wait_us"], "preflight wait", upper=7_200_000_000)
            if type(trial["preflight_deferred"]) is not bool or expiry != started + 3600 - started % 3600 or expiry - started <= 120:
                raise ValueError("trial started without a complete credential window")
        if "error" in trial:
            if trial["error"] not in ("timeout", "fixture_failed"):
                raise ValueError("invalid failure category")
            if "error_detail" in trial and (not isinstance(trial["error_detail"], str) or len(trial["error_detail"]) > 512):
                raise ValueError("unbounded failure detail")
            continue
        offered, completed, rejected = trial["offered"], trial["completions"], trial["rejected_ids"]
        if not all(isinstance(items, list) for items in (offered, completed, rejected)) or len(offered) > 4096:
            raise ValueError("invalid logical-message lists")
        if digest(offered) != hashed or offers.setdefault(work_key, offered) != offered:
            raise ValueError("workload content mismatch")
        kinds = set() if scenario == "idle" else ({"bulk"} if scenario == "bulk" else
                {"chat"} if scenario in ("sparse_chat", "burst_chat") else {"chat", "bulk"})
        producers = set() if scenario == "idle" else set(range(4 if scenario == "four_producers" else 1))
        if {m["kind"] for m in offered} != kinds or {m["producer"] for m in offered} != producers:
            raise ValueError("workload is missing its required traffic classes or producers")
        message_by_id = {}
        previous = (-1, -1)
        for message in offered:
            ident = integer(message["id"], "message id", upper=4095)
            integer(message["producer"], "producer", upper=3 if scenario == "four_producers" else 0)
            integer(message["at_us"], "arrival", upper=120_000_000)
            integer(message["bytes"], "payload size", 1, 11992)
            current = (message["at_us"], ident)
            if ident in message_by_id or current < previous or message["kind"] not in ("chat", "bulk"):
                raise ValueError("invalid workload identity/order/class")
            message_by_id[ident] = message
            previous = current
        accounted = set()
        for completion in completed:
            ident = integer(completion["id"], "completion id", upper=4095)
            if ident not in message_by_id or ident in accounted:
                raise ValueError("invalid or duplicated completion")
            message = message_by_id[ident]
            if any(completion[field] != message[field] for field in ("producer", "kind", "bytes")):
                raise ValueError("completion changed message")
            for field in ("latency_us", "queue_us", "service_us"):
                integer(completion[field], field, upper=120_000_000)
            if completion["queue_us"] + completion["service_us"] > completion["latency_us"]:
                raise ValueError("overlapping latency accounting")
            accounted.add(ident)
        for ident in rejected:
            integer(ident, "rejected id", upper=4095)
            if ident not in message_by_id or ident in accounted:
                raise ValueError("invalid rejection")
            accounted.add(ident)
        if accounted != set(message_by_id):
            raise ValueError("lost logical messages")
        for field in ("transfer_us", "measurement_us", "warm_us", "process_cpu_us", "process_lifetime_peak_rss_kib"):
            integer(trial[field], field)
        if not 0 < trial["transfer_us"] <= trial["measurement_us"] <= 120_000_000:
            raise ValueError("invalid observation duration")
        if any(c["latency_us"] + message_by_id[c["id"]]["at_us"] > trial["transfer_us"] for c in completed):
            raise ValueError("completion outside transfer")
        batches = integer(trial["batches"], "batches", upper=len(completed))
        encoded = integer(trial["encoded_payload_bytes"], "encoded payload")
        wire = integer(trial["request_cell_wire_bytes"], "request cell bytes")
        if encoded != sum(item["bytes"] + 8 for item in completed) or not encoded <= batches * 12000:
            raise ValueError("invalid encoding accounting")
        if not batches * 4096 <= wire <= batches * 16384 or wire % 4096:
            raise ValueError("invalid cell accounting")
        integer(trial["peak_buffered_payload_bytes"], "buffered payload", upper=8 * 1024**2 + variant["window"] * 12000)
        integer(trial["peak_queued_messages"], "queued messages", upper=4096)
        if trial.get("admission_wait_us", "missing") is not None or trial.get("application_schedule") != "transport_only" or trial.get("added_packing_delay_us") != 0:
            raise ValueError("unsupported latency/admission claims")
        observers = trial["observers"]
        if not isinstance(observers, list) or len(observers) != 3:
            raise ValueError("missing observer")
        for index, observer in enumerate(observers):
            if observer["fixture_link"] != index or len(observer["bytes"]) != 2:
                raise ValueError("invalid observer link")
            integer(observer["connections_including_warmup"], "observed connections", 1, 64)
            totals = [0, 0]
            samples = observer["samples"]
            if not isinstance(samples, list) or len(samples) > 65536:
                raise ValueError("invalid samples")
            last = 0
            for sample in samples:
                last = integer(sample["us"], "sample time", last, trial["measurement_us"])
                direction = integer(sample["direction"], "direction", upper=1)
                totals[direction] += integer(sample["bytes"], "read bytes", 1)
            dropped = integer(observer["dropped"], "dropped observations")
            for direction in (0, 1):
                count = integer(observer["bytes"][direction], "observer bytes")
                if count < totals[direction] or (not dropped and count != totals[direction]):
                    raise ValueError("invalid observation accounting")
    return sorted((scenario, repeat, name) for scenario in SCENARIOS for repeat in range(repeats)
                  for name in VARIANTS if (scenario, repeat, name) not in seen)


def analyze(report):
    missing = validate(report)
    groups, failures = defaultdict(list), []
    for trial in report["trials"]:
        if "error" in trial:
            failures.append({key: trial[key] for key in ("scenario", "repeat", "variant", "error", "error_detail") if key in trial})
        else:
            groups[trial["scenario"], trial["variant"]["name"]].append(trial)
    controls = []
    baseline_connections = {(t["scenario"], t["repeat"]): [o["connections_including_warmup"] for o in t["observers"]]
                            for t in report["trials"] if "error" not in t and t["variant"]["name"] == "baseline"}
    for trial in report["trials"]:
        if report["schema"] == 2 and trial["finished_unix"] >= trial["credential_expires_unix"]:
            controls.append({"scenario": trial["scenario"], "repeat": trial["repeat"], "variant": trial["variant"]["name"],
                             "reason": "credential_epoch_crossed"})
        if "error" in trial:
            continue
        observed = [o["connections_including_warmup"] for o in trial["observers"]]
        expected = baseline_connections.get((trial["scenario"], trial["repeat"]))
        if expected is not None and observed != expected:
            controls.append({"scenario": trial["scenario"], "repeat": trial["repeat"], "variant": trial["variant"]["name"],
                             "reason": "connection_count_changed", "baseline": expected, "observed": observed})
    rows = []
    for (scenario, variant), runs in sorted(groups.items()):
        values = defaultdict(list)
        for trial in runs:
            messages = {message["id"]: message for message in trial["offered"]}
            chats = [c for c in trial["completions"] if c["kind"] == "chat"]
            bulk = [c for c in trial["completions"] if c["kind"] == "bulk"]
            if chats:
                values["chat_p95_ms"].append(percentile([c["latency_us"] / 1000 for c in chats], .95))
                values["chat_p50_ms"].append(statistics.median(c["latency_us"] / 1000 for c in chats))
                worst = max(percentile([c["latency_us"] / 1000 for c in chats if c["producer"] == producer], .95)
                            for producer in {c["producer"] for c in chats})
                values["worst_producer_chat_p95_ms"].append(worst)
            if bulk:
                duration = max(c["latency_us"] + messages[c["id"]]["at_us"] for c in bulk) - min(m["at_us"] for m in messages.values() if m["kind"] == "bulk")
                values["bulk_goodput_kib_s"].append(sum(c["bytes"] for c in bulk) * 1e6 / duration / 1024)
            for field in ("request_cell_wire_bytes", "encoded_payload_bytes", "batches", "process_cpu_us", "process_lifetime_peak_rss_kib"):
                values[field].append(trial[field])
            for field in ("queue_us", "service_us"):
                if trial["completions"]:
                    values[field + "_p95"].append(percentile([c[field] for c in trial["completions"]], .95))
        # Wire rates use the same prefix across ALL variants of this scenario.
        prefix = min(t["measurement_us"] for (name, _), items in groups.items() if name == scenario for t in items)
        for trial in runs:
            for link, observer in enumerate(trial["observers"]):
                values[f"link_{link}_duplex_kib_s"].append(sum(s["bytes"] for s in observer["samples"] if s["us"] <= prefix) * 1e6 / prefix / 1024)
        rows.append({"scenario": scenario, "variant": variant, "runs": len(runs),
                     "metrics": {key: describe(items) for key, items in values.items()},
                     "common_prefix_us": prefix,
                     "rejected_messages": sum(len(t["rejected_ids"]) for t in runs),
                     "dropped_observations": sum(o["dropped"] for t in runs for o in t["observers"]),
                     "max_buffered_payload_bytes": max(t["peak_buffered_payload_bytes"] for t in runs)})
    complete = not missing and not failures and not controls and not any(row["rejected_messages"] or row["dropped_observations"] for row in rows)
    by_key = {(row["scenario"], row["variant"]): row for row in rows}
    candidates = []
    for variant in ("concurrency", "packing", "combined"):
        reasons, ratios = [], {}
        if report["quick"] or not complete:
            reasons.append("quick_or_incomplete_study")
        if complete and not report["quick"]:
            for scenario in ("bulk", "chat_bulk"):
                current = by_key[scenario, variant]["metrics"]["bulk_goodput_kib_s"]["median"]
                baseline = by_key[scenario, "baseline"]["metrics"]["bulk_goodput_kib_s"]["median"]
                ratios[scenario] = current / baseline
                if current < 1.2 * baseline:
                    reasons.append(scenario + ":bulk_gain_below_20_percent")
            for scenario in ("sparse_chat", "burst_chat", "chat_bulk", "four_producers"):
                for metric in ("chat_p95_ms", "worst_producer_chat_p95_ms"):
                    current = by_key[scenario, variant]["metrics"][metric]["median"]
                    baseline = by_key[scenario, "baseline"]["metrics"][metric]["median"]
                    if current > baseline + max(.05 * baseline, 20):
                        reasons.append(scenario + ":" + metric + "_regression")
        candidates.append({"variant": variant, "meets_performance_gate": not reasons, "reasons": reasons,
                           "bulk_goodput_ratio_to_baseline": ratios})
    eligible = sorted((candidate for candidate in candidates if candidate["meets_performance_gate"]),
                      key=lambda candidate: (-min(candidate["bulk_goodput_ratio_to_baseline"].values()), candidate["variant"]))
    return {"schema": 1, "kind": "loopback_utilization_summary", "status": "measured" if complete else "incomplete",
            "measurement_scope": "steady_credential_epoch" if report["schema"] == 2 else "credential_epoch_uncontrolled",
            "preflight_wait_us": sum(t.get("preflight_wait_us", 0) for t in report["trials"]),
            "preflight_deferred_trials": sum(t.get("preflight_deferred", False) for t in report["trials"]),
            "quick": report["quick"], "privacy_verdict": "not_qualified", "missing_trials": missing, "failures": failures,
            "control_mismatches": controls,
            "rows": rows, "candidates": candidates, "performance_ranking": [c["variant"] for c in eligible],
            "production_recommendation": None,
            "acceptance": {"bulk_gain_minimum": 1.2, "chat_p95_tolerance": "max(5% of baseline, 20 ms); also checks worst producer"},
            "limitations": ["Generated transport echoes, not application acknowledgements or durable delivery.",
                            "Logical producers share one client; this is not a multi-client anonymity population.",
                            "Application scheduling and admission wait are not measured by this transport comparison.",
                            "Packing has no intentional timer; queue/backpressure wait remains part of completion latency.",
                            "Cell bytes include ordinary framing and padding; they are not an isolated privacy-overhead measurement.",
                            "Fixed carrier traffic is paid while idle; packing savings in cells do not imply the same interface-byte savings.",
                            "TCP read chunks are not packets; byte rates are descriptive and not unlinkability evidence.",
                            "RSS is process-lifetime peak, not per-case allocation. Buffered payload excludes copies and crypto state.",
                            "Five repeats give descriptive ranges, not a statistical anonymity bound or an Internet performance guarantee."]}


def markdown(report):
    def metric(row, key):
        value = row["metrics"].get(key, {}).get("median")
        return "—" if value is None else f"{value:,.2f}"
    lines = ["# Loopback utilization comparison", "", "**Privacy: NOT QUALIFIED.**", "",
             "Medians across independent runs; chat p95 is the median of each run's p95. All data are synthetic transport echoes.", "",
             f'Measurement scope: {report["measurement_scope"]}. Pretrial credential wait: {report["preflight_wait_us"] / 1e6:.3f} s across {report["preflight_deferred_trials"]} deferred trials. This wait precedes offered traffic and is excluded from message latencies; it is not a production recovery solution.', "",
             "| Workload | Variant | Runs | Chat p95 ms | Worst producer p95 ms | Bulk KiB/s | Request cell bytes | Rejected | Dropped observations |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for row in report["rows"]:
        lines.append(f'| {row["scenario"]} | {row["variant"]} | {row["runs"]} | {metric(row, "chat_p95_ms")} | {metric(row, "worst_producer_chat_p95_ms")} | {metric(row, "bulk_goodput_kib_s")} | {metric(row, "request_cell_wire_bytes")} | {row["rejected_messages"]} | {row["dropped_observations"]} |')
    lines += ["", "## Decision", "", f'Study status: {report["status"]}. Missing trials: {len(report["missing_trials"])}. Failed trials: {len(report["failures"])}. Control mismatches: {len(report["control_mismatches"])}.', "",
              "Performance ranking: " + (", ".join(report["performance_ranking"]) or "no candidate qualifies") + ".", ""]
    for candidate in report["candidates"]:
        lines.append(f'- {candidate["variant"]}: ' + ("meets the laboratory performance gate" if candidate["meets_performance_gate"] else "; ".join(candidate["reasons"])))
    lines += ["", "Qualification requires at least 20% more bulk goodput in both bulk workloads, complete delivery/observations, and chat p95 within max(5%, 20 ms) of baseline in each chat workload, including the worst producer. Quick runs cannot qualify.", "", "## Limitations", ""]
    lines += ["- " + item for item in report["limitations"]]
    return "\n".join(lines) + "\n"


def write_new(path, text):
    # POSIX mode bits do not establish a private Windows DACL. Fail before
    # creating evidence rather than silently publishing with inherited access.
    if os.name != "posix":
        raise NotImplementedError("private study evidence requires POSIX file permissions")
    path = Path(path)
    fd, staged = tempfile.mkstemp(prefix=".utilization-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.link(staged, path)
    finally:
        os.unlink(staged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    outputs = [path for path in (args.output, args.markdown) if path is not None]
    if len({path.resolve() for path in outputs}) != len(outputs) or any(path.exists() or path.is_symlink() for path in outputs):
        parser.error("outputs must be distinct new evidence files")
    with args.input.open("rb") as source:
        raw = source.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        parser.error("input exceeds bounded report size")
    report = analyze(json.loads(raw))
    report["input_sha256"] = hashlib.sha256(raw).hexdigest()
    write_new(args.output, json.dumps(report, indent=2, allow_nan=False) + "\n")
    if args.markdown:
        write_new(args.markdown, markdown(report))
    print(f'{report["status"]}; performance ranking: {report["performance_ranking"]}; privacy NOT QUALIFIED')
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
