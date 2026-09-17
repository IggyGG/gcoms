#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("relay_performance", Path(__file__).parents[1] / "relay-performance.py")
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


def fixture():
    return {
        "schema": 1, "kind": "loopback_transport_study", "quick": True,
        "sample_unit": "tcp_read_chunk_not_packet", "privacy_verdict": "not_qualified",
        "payload": "generated_non_executable_bytes",
        "trials": [{
            "case": "example", "repeat": 0, "transfer_us": 1_000_000,
            "measurement_us": 2_000_000, "carrier_slot_ms": 100, "window": 1,
            "useful_bytes": 1024, "warm_us": 1000,
            "completions": [{"us": 1_000_000, "payload_bytes": 1024}],
            "scheduler": {"queue_wait": {"count": 1, "total_us": 900_000}, "service": {"count": 1, "total_us": 100_000}},
            "observers": [{"fixture_link": i, "bytes": [4096, 4096], "dropped": 0,
                           "samples": [{"us": 1, "direction": 0, "bytes": 4096}, {"us": 2, "direction": 1, "bytes": 4096}]} for i in range(3)],
        }],
    }


class PerformanceTest(unittest.TestCase):
    def test_costs_include_both_directions_and_idle_time(self):
        baseline = study.budget(4096, 100)
        self.assertEqual(baseline["kib_s_per_direction"], 40)
        self.assertAlmostEqual(baseline["gib_day_duplex"], 6.591796875)
        self.assertEqual(study.costs()["one_mib_s_each_direction_gib_day"], 168.75)
        with self.assertRaises(ValueError):
            study.budget(4096, 0)

    def test_payload_and_all_link_bandwidth_have_different_denominators(self):
        result = study.analyze(fixture())
        case = result["cases"][0]
        self.assertEqual(case["request_payload_goodput_kib_s"]["median"], 1)
        self.assertEqual(case["all_observed_links_duplex_kib_s"]["median"], 12)
        self.assertEqual(case["scheduler_queue_wait_mean_ms"]["median"], 900)
        self.assertIsNone(case["goodput_mean_bootstrap_interval_95"])
        self.assertEqual(result["privacy"]["verdict"], "not_qualified")

    def test_failed_trials_are_retained_and_cannot_become_a_pass(self):
        source = fixture()
        source["trials"].append({"case": "failed", "repeat": 0, "error": "timeout"})
        result = study.analyze(source)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["failures"]), 1)
        self.assertIn("NOT QUALIFIED", study.markdown(result))

    def test_accounting_trace_order_and_privacy_claims_fail_closed(self):
        mutations = [
            lambda x: x.update(privacy_verdict="qualified"),
            lambda x: x["trials"][0].update(useful_bytes=42),
            lambda x: x["trials"].append(copy.deepcopy(x["trials"][0])),
            lambda x: x["trials"][0]["observers"][0].update(bytes=[1, 2]),
            lambda x: x["trials"][0]["observers"][0]["samples"][1].update(us=0),
            lambda x: x["trials"][0]["observers"][0]["samples"][0].update(direction=True),
        ]
        for mutate in mutations:
            source = fixture()
            mutate(source)
            with self.assertRaises(ValueError):
                study.analyze(source)

    def test_dropped_observations_are_counted_not_silently_accepted_as_complete(self):
        source = fixture()
        observer = source["trials"][0]["observers"][0]
        observer["dropped"] = 1
        observer["samples"].pop()
        result = study.analyze(source)
        self.assertEqual(result["cases"][0]["dropped_observations"], 1)
        self.assertEqual(result["privacy"]["verdict"], "not_qualified")

    def test_evidence_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            study.write_new(path, "first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                study.write_new(path, "second")
            self.assertEqual(path.read_text(), "first")

    def test_uncertainty_is_repeatable_and_uses_runs(self):
        self.assertIsNone(study.mean_interval([1]))
        self.assertEqual(study.mean_interval([3, 3, 3]), [3, 3])
        self.assertEqual(study.mean_interval([1, 2, 9]), study.mean_interval([1, 2, 9]))

    def test_wire_comparison_uses_common_time_and_requires_complete_controls(self):
        source = fixture()
        template = source["trials"][0]
        source["trials"] = []
        names = ("idle_carrier_100ms", "carrier_100ms_window_4",
                 "idle_production_scheduler_carrier_100ms", "production_scheduler_carrier_100ms")
        for index, name in enumerate(names):
            trial = copy.deepcopy(template)
            trial.update(case=name, measurement_us=2_000_000 + index * 1_000_000)
            source["trials"].append(trial)
        comparison = study.analyze(source)["wire_shape_observations"]
        self.assertEqual(comparison["status"], "descriptive_only")
        self.assertEqual(comparison["common_prefix_us"], 2_000_000)
        for links in comparison["per_link_duplex_kib_s"].values():
            self.assertEqual([link["median"] for link in links], [4, 4, 4])
        source["trials"][0]["observers"][0]["dropped"] = 1
        self.assertEqual(study.analyze(source)["wire_shape_observations"]["status"], "observations_dropped")
        source["trials"].pop()
        self.assertEqual(study.analyze(source)["wire_shape_observations"]["status"], "controls_incomplete")


if __name__ == "__main__":
    unittest.main()
