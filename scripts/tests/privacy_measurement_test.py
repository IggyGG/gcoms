"""Regression tests for the privacy audit's measurement failures."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from privacy_packets import Packet, FIELDS, direction, endpoint, new_connections, parse_fields, sha256, write_new

spec = importlib.util.spec_from_file_location("privacy_classifier", SCRIPTS / "privacy-classifier.py")
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)

CLIENT = ("10.50.0.2", 40123)
ENTRY = ("10.50.0.3", 4433)


def packet(time, source=CLIENT, destination=ENTRY, size=100, syn=False, ack=False, sequence="1"):
    return Packet(time, source, destination, size, max(size - 54, 0), syn, ack, False, sequence, False)


class PrivacyMeasurementTest(unittest.TestCase):
    def test_identical_scores_and_ties_have_correct_auc(self):
        self.assertEqual(study.roc_auc([0, 0, 0, 0], [0, 0, 1, 1]), .5)
        self.assertEqual(study.roc_auc([0, 0, 0, 0], [1, 1, 0, 0]), .5)
        self.assertEqual(study.roc_auc([0, 1, 1, 2], [0, 0, 1, 1]), .875)
        self.assertEqual(study.roc_auc([0, 1], [0, 1]), 1.)
        self.assertEqual(study.roc_auc([1, 0], [0, 1]), 0.)
        for scores, labels in [([1, 2], [1, 1]), ([float("nan"), 0], [0, 1]), ([0, 1], [0, 2])]:
            with self.assertRaises(ValueError):
                study.roc_auc(scores, labels)

    def test_direction_and_empty_windows_are_preserved(self):
        rows = [packet(10.1, size=100), packet(10.2, ENTRY, CLIENT, size=200)]
        features = study.window_features(rows, {CLIENT[0]}, 1, 10, 13)
        self.assertEqual(features.shape, (3, len(study.FEATURE_NAMES)))
        self.assertEqual(features[0, :4].tolist(), [1, 1, 100, 200])
        self.assertEqual(features[1:].sum(), 0)
        self.assertEqual(direction(packet(10), set(), ENTRY), "up")
        self.assertEqual(direction(packet(10, ENTRY, CLIENT), set(), ENTRY), "down")
        with self.assertRaises(ValueError):
            direction(packet(10), {CLIENT[0], ENTRY[0]})

    def test_syn_ack_and_retransmissions_are_not_new_connections(self):
        syn = packet(1, syn=True)
        rows = [syn, syn._replace(time=2, retransmission=True),
                packet(3, ENTRY, CLIENT, syn=True, ack=True),
                packet(4, source=(CLIENT[0], 40124), syn=True)]
        self.assertEqual(new_connections(rows), 2)

    def test_structured_parser_ipv6_flags_and_ports(self):
        values = dict(zip(FIELDS, [""] * len(FIELDS)))
        values.update({"frame.time_epoch": "1.25", "frame.len": "74",
                       "ipv6.src": "::1", "ipv6.dst": "::2", "tcp.srcport": "40000",
                       "tcp.dstport": "4433", "tcp.len": "0", "tcp.flags.syn": "True",
                       "tcp.flags.ack": "False", "tcp.flags.reset": "0", "tcp.seq_raw": "17"})
        row = parse_fields("\t".join(values[field] for field in FIELDS))[0]
        self.assertTrue(row.syn)
        self.assertFalse(row.ack)
        self.assertEqual(row.source, ("::1", 40000))
        self.assertEqual(endpoint("[::2]:4433"), ("::2", 4433))
        values["tcp.flags.syn"] = "maybe"
        with self.assertRaises(ValueError):
            parse_fields("\t".join(values[field] for field in FIELDS))
        with self.assertRaises(ValueError):
            parse_fields("1\t2")

    def test_capture_queue_reordering_is_normalized_but_clock_steps_fail(self):
        values = dict.fromkeys(FIELDS, "")
        values.update({"frame.len": "74", "ip.src": CLIENT[0], "ip.dst": ENTRY[0],
                       "tcp.srcport": "40000", "tcp.dstport": "4433", "tcp.len": "0"})
        def line(timestamp):
            values["frame.time_epoch"] = str(timestamp)
            return "\t".join(values[field] for field in FIELDS)
        rows = parse_fields(line(10.000001) + "\n" + line(10.0))
        self.assertEqual([row.time for row in rows], [10.0, 10.000001])
        with self.assertRaisesRegex(ValueError, "backstep"):
            parse_fields(line(10.1) + "\n" + line(10.0))

    def test_uncertainty_resamples_independent_paired_runs(self):
        labels = np.array([0, 1, 0, 1])
        predictions = np.array([0., 1., 0., 1.])
        groups = np.array([10, 10, 11, 11])
        self.assertEqual(study.run_interval(predictions, labels, groups, 100), [1., 1.])
        self.assertIsNone(study.run_interval(predictions[:2], labels[:2], groups[:2], 100))
        with self.assertRaises(ValueError):
            study.run_interval(predictions, labels, np.array([1, 2, 3, 4]), 100)

    def test_missing_endpoint_never_disables_entry_filter(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"test")
            meta = root / "capture.meta.json"
            meta.write_text(json.dumps({"inner_rc": 0, "pcap": pcap.name, "pcap_sha256": sha256(pcap)}))
            args = SimpleNamespace(diagnostic=True, entry_link_only=True, windows=1)
            with patch.object(study, "packets", return_value=[packet(1), packet(3)]):
                with self.assertRaisesRegex(ValueError, "exact entry address"):
                    study.read_capture(meta, args)

    def test_overlap_and_insufficient_runs_are_invalid(self):
        args = SimpleNamespace(train_seeds="7", eval_seeds="7", diagnostic=True)
        with self.assertRaisesRegex(ValueError, "overlap"):
            study.analyze(args)
        args.eval_seeds = "11"
        args.diagnostic = False
        with self.assertRaisesRegex(ValueError, ">=10"):
            study.analyze(args)

    def test_failed_capture_is_not_silently_discarded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "failed.meta.json"
            path.write_text('{"inner_rc": 1}')
            with self.assertRaisesRegex(ValueError, "failed capture"):
                study.read_capture(path, SimpleNamespace())

    def test_observation_lengths_must_be_complete_positive_windows(self):
        for start, end, window in [(0, 0, 1), (0, .001, 1), (0, 1.5, 1), (0, 1, 0)]:
            with self.assertRaises(ValueError):
                study.window_features([], {CLIENT[0]}, window, start, end)

    def test_reports_are_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            write_new(path, "first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_new(path, "second")
            self.assertEqual(path.read_text(), "first")

    def test_valid_unfavorable_result_is_informative(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            args = SimpleNamespace(out=root, train_seeds="1001:1010", eval_seeds="2001:2020",
                                   diagnostic=False, entry_link_only=False, windows=1, bootstrap=100,
                                   idle_workload="warm_idle")
            def fake_capture(path, _):
                workload, seed = path.stem.split(".")[0].rsplit("-", 1)
                # Perfectly distinguishable classes, equal-duration independent runs.
                value = {"warm_idle": 0., "chat": 1., "bulk": 2.}[workload]
                features = np.full((300, len(study.FEATURE_NAMES)), value)
                return {"workload": workload, "seed": int(seed), "profile": "same",
                        "cadence": "production"}, features, {}
            for seed in study.seeds(args.train_seeds) + study.seeds(args.eval_seeds):
                for workload in ("warm_idle", "chat", "bulk"):
                    (root / f"{workload}-{seed}.meta.json").touch()
            with patch.object(study, "read_capture", side_effect=fake_capture):
                result = study.analyze(args)
            self.assertTrue(result["measurement_valid"])
            self.assertFalse(result["reference_threshold_is_release_veto"])
            self.assertFalse(result["comparisons"]["idle_vs_chat"]["reference_threshold_met"])
            self.assertEqual(result["release_decision"], "pending_owner_review")


if __name__ == "__main__":
    unittest.main()
