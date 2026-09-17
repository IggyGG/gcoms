#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("utilization", Path(__file__).parents[1] / "relay-utilization.py")
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


def fixture():
    report = dict(schema=1, kind="loopback_utilization_study", quick=False,
                  payload="generated_non_executable_bytes", privacy_verdict="not_qualified",
                  sample_unit="tcp_read_chunk_not_packet", carrier_slot_ms=100, carrier_record_bytes=4096,
                  logical_producers_share_one_client=True, payload_limit=12000,
                  queue_limit=8 * 1024**2, job_limit=4096, trial_timeout_seconds=120, trials=[])
    for scenario in study.SCENARIOS:
        offered = []
        if scenario not in ("idle", "bulk"):
            offered.append(dict(id=0, producer=0, kind="chat", at_us=0, bytes=128))
        if scenario in ("bulk", "chat_bulk", "four_producers"):
            offered.append(dict(id=len(offered), producer=0, kind="bulk", at_us=0, bytes=1000))
        if scenario == "four_producers":
            originals = copy.deepcopy(offered)
            for producer in range(1,4):
                for original in originals:
                    offered.append(dict(original, id=len(offered), producer=producer))
        for repeat in range(5):
            for order, (name, (window, packing)) in enumerate(study.VARIANTS.items()):
                completions = []
                for message in offered:
                    # Known exact improvement in bulk, identical chat latencies.
                    latency = 100_000 if message["kind"] == "chat" else (1_000_000 if name == "baseline" else 500_000)
                    completions.append(dict(id=message["id"], producer=message["producer"], kind=message["kind"], bytes=message["bytes"],
                                            latency_us=latency, queue_us=0, service_us=latency))
                report["trials"].append(dict(scenario=scenario, repeat=repeat, order=order,
                    variant=dict(name=name, window=window, packing=packing), workload_sha256=study.digest(offered),
                    offered=copy.deepcopy(offered), completions=completions, rejected_ids=[],
                    transfer_us=1_000_000, measurement_us=2_000_000, warm_us=1000,
                    batches=len(offered), encoded_payload_bytes=sum(m["bytes"] + 8 for m in offered),
                    request_cell_wire_bytes=len(offered)*4096, peak_buffered_payload_bytes=sum(m["bytes"] for m in offered),
                    peak_queued_messages=len(offered), process_cpu_us=100, process_lifetime_peak_rss_kib=1000,
                    observers=[dict(fixture_link=i, bytes=[4096,4096], dropped=0, connections_including_warmup=1,
                                    samples=[dict(us=1, direction=0, bytes=4096), dict(us=2, direction=1, bytes=4096)]) for i in range(3)],
                    admission_wait_us=None, application_schedule="transport_only", added_packing_delay_us=0))
    return report


class UtilizationTest(unittest.TestCase):
    def test_epoch_control_requires_a_whole_trial_window_and_reports_external_wait(self):
        report = fixture()
        report.update(schema=2, credential_epoch_seconds=3600,
                      credential_control="defer_before_fixture_until_lifetime_exceeds_trial_deadline")
        for trial in report["trials"]:
            trial.update(credential_started_unix=7201, credential_expires_unix=10800,
                         finished_unix=7203, preflight_wait_us=0, preflight_deferred=False)
        report["trials"][0].update(preflight_wait_us=61_000_000, preflight_deferred=True)
        result = study.analyze(report)
        self.assertEqual(result["measurement_scope"], "steady_credential_epoch")
        self.assertEqual(result["preflight_wait_us"], 61_000_000)
        self.assertEqual(result["preflight_deferred_trials"], 1)
        self.assertEqual(result["status"], "measured")
        report["trials"][0].update(credential_started_unix=10680, finished_unix=10682)
        with self.assertRaises(ValueError): study.analyze(report)
        report["trials"][0].update(credential_started_unix=10679, finished_unix=10800)
        result = study.analyze(report)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["performance_ranking"], [])
        self.assertEqual(result["control_mismatches"][0]["reason"], "credential_epoch_crossed")

    def test_failure_context_is_retained_and_bounded(self):
        report = fixture()
        report["trials"][0].update(error="fixture_failed", error_detail="client warm-up: fixture expiry")
        result = study.analyze(report)
        self.assertEqual(result["failures"][0]["error_detail"], "client warm-up: fixture expiry")
        self.assertEqual(result["performance_ranking"], [])
        report["trials"][0]["error_detail"] = "x" * 513
        with self.assertRaises(ValueError): study.analyze(report)

    def test_repeat_summary_preserves_observed_range_and_median(self):
        self.assertEqual(study.describe([5, 1, 3, 2, 4]),
                         dict(count=5, median=3, p95=5, min=1, max=5))
        self.assertEqual(study.describe([]),
                         dict(count=0, median=None, p95=None, min=None, max=None))

    def test_complete_matrix_passes_performance_but_never_qualifies_privacy(self):
        summary = study.analyze(fixture())
        self.assertEqual(summary["status"], "measured")
        self.assertEqual(set(summary["performance_ranking"]), {"packing", "concurrency", "combined"})
        self.assertEqual(summary["privacy_verdict"], "not_qualified")
        self.assertIsNone(summary["production_recommendation"])
        self.assertIn("NOT QUALIFIED", study.markdown(summary))

    def test_chat_regression_disqualifies_faster_bulk_and_tolerance_boundary_is_inclusive(self):
        report = fixture()
        for trial in report["trials"]:
            if trial["variant"]["name"] == "concurrency":
                for completion in trial["completions"]:
                    if completion["kind"] == "chat":
                        completion["latency_us"] = 120_000
        self.assertIn("concurrency", study.analyze(report)["performance_ranking"])
        for trial in report["trials"]:
            if trial["variant"]["name"] == "concurrency":
                for completion in trial["completions"]:
                    if completion["kind"] == "chat": completion["latency_us"] += 1
        self.assertNotIn("concurrency", study.analyze(report)["performance_ranking"])

    def test_a_candidate_must_improve_both_bulk_workloads(self):
        report = fixture()
        for trial in report["trials"]:
            if trial["scenario"] == "chat_bulk" and trial["variant"]["name"] == "combined":
                for completion in trial["completions"]:
                    if completion["kind"] == "bulk": completion["latency_us"] = 1_000_000
        summary = study.analyze(report)
        self.assertNotIn("combined", summary["performance_ranking"])
        self.assertIn("chat_bulk:bulk_gain_below_20_percent", next(c for c in summary["candidates"] if c["variant"] == "combined")["reasons"])

    def test_a_single_producers_regression_cannot_hide_in_the_overall_percentile(self):
        report = fixture()
        for trial in report["trials"]:
            if trial["scenario"] != "four_producers":
                continue
            for producer in range(4):
                for _ in range(7):
                    ident = len(trial["offered"])
                    trial["offered"].append(dict(id=ident, producer=producer, kind="chat", at_us=0, bytes=128))
                    trial["completions"].append(dict(id=ident, producer=producer, kind="chat", bytes=128,
                                                    latency_us=100_000, queue_us=0, service_us=100_000))
                    trial["batches"] += 1
                    trial["encoded_payload_bytes"] += 136
                    trial["request_cell_wire_bytes"] += 4096
            trial["workload_sha256"] = study.digest(trial["offered"])
            if trial["variant"]["name"] == "combined":
                next(c for c in trial["completions"] if c["producer"] == 3 and c["kind"] == "chat")["latency_us"] = 130_000
        summary = study.analyze(report)
        row = next(r for r in summary["rows"] if r["scenario"] == "four_producers" and r["variant"] == "combined")
        self.assertEqual(row["metrics"]["chat_p95_ms"]["median"],100)
        self.assertEqual(row["metrics"]["worst_producer_chat_p95_ms"]["median"],130)
        self.assertNotIn("combined", summary["performance_ranking"])

    def test_missing_failed_dropped_and_rejected_work_cannot_disappear_from_decision(self):
        for fault in ("missing", "failed", "dropped", "rejected"):
            report = fixture()
            trial = next(t for t in report["trials"] if t["scenario"] == "chat_bulk")
            if fault == "missing": report["trials"].remove(trial)
            elif fault == "failed": trial["error"] = "timeout"
            elif fault == "dropped": trial["observers"][0]["dropped"] = 1
            else:
                item = trial["completions"].pop()
                trial["rejected_ids"].append(item["id"])
                trial["batches"] -= 1
                trial["encoded_payload_bytes"] -= item["bytes"] + 8
                trial["request_cell_wire_bytes"] -= 4096
            summary = study.analyze(report)
            self.assertEqual(summary["status"], "incomplete", fault)
            self.assertEqual(summary["performance_ranking"], [], fault)

    def test_quick_study_is_only_harness_validation(self):
        report = fixture()
        report["quick"] = True
        report["trials"] = [t for t in report["trials"] if t["repeat"] == 0]
        summary = study.analyze(report)
        self.assertEqual(summary["status"], "measured")
        self.assertEqual(summary["performance_ranking"], [])

    def test_extra_connections_cannot_masquerade_as_better_utilization(self):
        report = fixture()
        report["trials"][1]["observers"][0]["connections_including_warmup"] = 2
        summary = study.analyze(report)
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["performance_ranking"], [])
        self.assertEqual(summary["control_mismatches"][0]["reason"], "connection_count_changed")

    def test_workloads_and_accounting_fail_closed(self):
        mutations = [
            lambda r: r.update(privacy_verdict="qualified"),
            lambda r: r.update(carrier_slot_ms=20),
            lambda r: r["trials"].append(copy.deepcopy(r["trials"][0])),
            lambda r: r["trials"][20]["offered"][0].update(bytes=129),
            lambda r: r["trials"][20]["completions"].clear(),
            lambda r: r["trials"][20]["completions"][0].update(bytes=129),
            lambda r: r["trials"][20].update(encoded_payload_bytes=1),
            lambda r: r["trials"][20].update(peak_buffered_payload_bytes=10**9),
            lambda r: r["trials"][0]["observers"][0].update(bytes=[0,0]),
            lambda r: r["trials"][0]["observers"][0]["samples"][0].update(direction=True),
            lambda r: r["trials"][0].update(admission_wait_us=1),
        ]
        for mutate in mutations:
            report = fixture(); mutate(report)
            with self.assertRaises(ValueError): study.analyze(report)

    def test_wire_rates_use_a_common_interval_and_rss_keeps_its_scope(self):
        report = fixture()
        for trial in report["trials"]:
            if trial["variant"]["name"] == "combined":
                trial["measurement_us"] = 4_000_000
                for observer in trial["observers"]:
                    observer["bytes"][0] += 4096
                    observer["samples"].append(dict(us=3_000_000,direction=0,bytes=4096))
        summary = study.analyze(report)
        for row in summary["rows"]:
            self.assertEqual(row["common_prefix_us"], 2_000_000)
            self.assertEqual(row["metrics"]["link_0_duplex_kib_s"]["median"], 4)
            self.assertIn("process_lifetime_peak_rss_kib", row["metrics"])

    def test_exclusive_evidence_and_write_failure_preserve_prior_results(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"evidence.json"
            study.write_new(path,"first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): study.write_new(path,"second")
            self.assertEqual(path.read_text(),"first")
            other = Path(directory)/"failed.json"
            with patch.object(study.os,"fsync",side_effect=OSError("fixture write failure")):
                with self.assertRaises(OSError): study.write_new(other,"incomplete")
            self.assertFalse(other.exists())


if __name__ == "__main__":
    unittest.main()
