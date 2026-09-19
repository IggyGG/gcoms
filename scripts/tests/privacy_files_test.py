import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
sys.path.insert(0, str(Path(__file__).parents[1]))
from privacy_packets import Packet, sha256

CLIENT = ("127.0.0.1", 50000)
ENTRY = ("127.0.0.1", 27101)
MIDDLE = ("127.0.0.1", 27102)


def packet(time, source=CLIENT, destination=ENTRY, size=50, syn=False, ack=False):
    return Packet(time, source, destination, size, 0, syn, ack, False, "1", False)

spec = importlib.util.spec_from_file_location("privacy_files", Path(__file__).parents[1] / "privacy-files-classifier.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class PrivacyFilesTest(unittest.TestCase):
    def test_auc_ties_and_inverted_signal(self):
        self.assertEqual(privacy.auc([0, 0, 0, 0], [0, 0, 1, 1]), 0.5)
        self.assertEqual(privacy.auc([1, 1, 0, 0], [0, 0, 1, 1]), 0)
        self.assertEqual(privacy.auc([0, 0, 1, 1], [0, 0, 1, 1]), 1)

    def test_window_directions_silence_and_bounds(self):
        rows = [packet(10.1, syn=True), packet(10.2, ENTRY, CLIENT, 100, True, True),
                packet(12.0, size=999), packet(10.3, ENTRY, MIDDLE, 800)]
        x = privacy.features(rows, {ENTRY, MIDDLE}, 10, 2)
        self.assertEqual(x.shape, (2, 15))
        self.assertEqual(x[0, :4].tolist(), [1, 1, 50, 100])
        self.assertEqual(x[0, 13], 1)
        self.assertTrue((x[1] == 0).all())

    def test_clustered_gate_rejects_signal_and_requires_independent_runs(self):
        labels = np.asarray([0, 0, 1, 1])
        identical = [(np.ones((4, 2)), labels) for _ in range(8)]
        result = privacy.evaluate(identical, identical, bootstrap=100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["separability_upper_97_5"], 0.5)
        signal = [(np.asarray([[0], [0], [10], [10]]), labels) for _ in range(8)]
        self.assertFalse(privacy.evaluate(signal, signal, bootstrap=100)["ok"])
        with self.assertRaisesRegex(ValueError, "independent"):
            privacy.evaluate(identical[:1], identical, bootstrap=100)

    def captures(self, root):
        pcap = root / "capture.pcap"
        pcap.write_bytes(b"retained-test-capture")
        for workload in privacy.WORKLOADS:
            chat = 1501 // 128 if workload in ("chat", "mixed") else 0
            bulk = 1501 if workload in ("bulk", "mixed") else 0
            metadata = {
                "profile": "gchat-files", "workload": workload, "seed": 1,
                "inner_rc": 0, "protected": True, "cadence": "production",
                "capture_returncode": 0, "dropped_packets": 0, "workload_returncode": 0,
                "seconds": 2, "bytes": 1501, "binary_sha256": "a" * 64,
                "chat_interval_ms": 500, "entries": 2, "traffic_profile": None,
                "measurement_start_epoch": 10., "measurement_end_epoch": 12.,
                "capture_started_epoch": 9., "capture_finished_epoch": 13.,
                "pcap": pcap.name, "pcap_sha256": sha256(pcap),
                "record": {"failures": 0, "exact_delivery": True, "measurement_overrun": False,
                           "traffic_profile_id": 22, "bulk_acked_bytes": bulk,
                           "chat_sent": chat, "chat_acked": chat,
                           "entry_addr": "127.0.0.1:27101", "middle_addr": "127.0.0.1:27102",
                           "entry_connections": 2, "middle_connections": 2},
            }
            (root / f"{workload}.meta.json").write_text(json.dumps(metadata))

    def test_exact_partial_chunk_and_all_receipts_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.captures(root)
            with patch.object(privacy, "read_packets", return_value=[packet(10.1)]):
                self.assertEqual(len(privacy.load_captures(root, [1])), 4)
                target = root / "chat.meta.json"
                metadata = json.loads(target.read_text())
                metadata["record"]["chat_acked"] -= 1
                target.write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, "incomplete chat"):
                    privacy.load_captures(root, [1])

    def test_loss_wrong_profile_and_truncated_capture_fail(self):
        for key, value, message in [("dropped_packets", 1, "invalid/failed"),
                                    ("capture_finished_epoch", 11., "does not cover")]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.captures(root)
                target = root / "idle.meta.json"
                metadata = json.loads(target.read_text())
                metadata[key] = value
                target.write_text(json.dumps(metadata))
                with patch.object(privacy, "read_packets", return_value=[packet(10.1)]):
                    with self.assertRaisesRegex(ValueError, message):
                        privacy.load_captures(root, [1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.captures(root)
            target = root / "idle.meta.json"
            metadata = json.loads(target.read_text())
            metadata["record"]["traffic_profile_id"] = 12
            target.write_text(json.dumps(metadata))
            with patch.object(privacy, "read_packets", return_value=[packet(10.1)]):
                with self.assertRaisesRegex(ValueError, "invalid/failed"):
                    privacy.load_captures(root, [1])


if __name__ == "__main__":
    unittest.main()
