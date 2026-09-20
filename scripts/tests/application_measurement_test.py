"""Bad byte/receipt accounting must never become favorable performance evidence."""
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import json

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("app_utilization", SCRIPTS / "app-utilization.py")
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


class ApplicationMeasurementTest(unittest.TestCase):
    def record(self):
        return dict(chat_count=4, chat_sent=4, chat_acked=4, bulk_bytes=32769,
                    bulk_chunks=3, bulk_chunk=11264, bulk_acked_bytes=32769,
                    failures=0, recipient_drained=8, exact_delivery=True,
                    single_delay_ms=100, persistence="atomic_fsync_node_archive")

    def test_partial_chunk_is_counted_exactly_and_duplicates_fail(self):
        args = SimpleNamespace(bulk_bytes=32769, bulk_chunk=11264)
        record = self.record()
        checks, expected = study.expected_accounting(record, args)
        self.assertEqual(expected, 8)
        self.assertTrue(all(checks.values()))
        record["bulk_acked_bytes"] = 3 * 11264
        self.assertFalse(study.expected_accounting(record, args)[0]["bulk_bytes"])
        record = self.record()
        record["recipient_drained"] = 9
        self.assertFalse(study.expected_accounting(record, args)[0]["receipts"])

    def test_failed_process_record_is_retained(self):
        record = self.record()
        record["failures"] = 1
        completed = subprocess.CompletedProcess([], 1, json.dumps(record), "delivery timed out")
        with patch.object(study, "example_command", return_value=["fixture"]), patch.object(study.subprocess, "run", return_value=completed):
            measured = study.run_once(SimpleNamespace(timeout=1), "gc2", "mixed")
        self.assertEqual(measured["run_returncode"], 1)
        self.assertEqual(measured["failures"], 1)
        self.assertIn("timed out", measured["stderr_tail"])


if __name__ == "__main__":
    unittest.main()
