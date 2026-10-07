import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('machine_recovery',
    Path(__file__).resolve().parents[1] / 'check-machine-scope-recovery.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class RecoveryWorkerTest(unittest.TestCase):
    def run_worker(self, output, *, missing=False, failure=False):
        commands = []
        def git(argv, **kwargs):
            return 'a' * 40 + '\n' if argv[1] == 'rev-parse' else b''
        def run(argv, **kwargs):
            commands.append(argv)
            listed = '--list' in argv
            name = worker.TEST if worker.TEST in argv else worker.CONTROL
            stdout = '' if missing else name + ': test\n\n1 test, 0 benchmarks\n'
            return subprocess.CompletedProcess(argv, int(failure and not listed),
                                               stdout=stdout, stderr='')
        with patch.object(sys, 'argv', ['worker', '--output', str(output)]), \
                patch.object(worker.subprocess, 'check_output', side_effect=git), \
                patch.object(worker.subprocess, 'run', side_effect=run):
            worker.main()
        return commands

    def test_exact_control_and_three_recovery_runs_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            commands = self.run_worker(Path(temporary))
            proof = json.loads((Path(temporary) / 'summary.json').read_text())
            self.assertTrue(proof['passed'])
            self.assertEqual(len(proof['runs']), 3)
            self.assertEqual(proof['checkpoint_control']['exit_code'], 0)
            self.assertEqual(len(commands), 6)
            self.assertTrue(all('--exact' in command for command in commands))

    def test_missing_test_retains_failure_instead_of_empty_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                self.run_worker(Path(temporary), missing=True)
            proof = json.loads((Path(temporary) / 'summary.json').read_text())
            self.assertFalse(proof['passed'])
            self.assertEqual(proof['runs'], [])

    def test_failed_control_stops_retries_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(subprocess.CalledProcessError):
                self.run_worker(Path(temporary), failure=True)
            proof = json.loads((Path(temporary) / 'summary.json').read_text())
            self.assertFalse(proof['passed'])
            self.assertEqual(proof['checkpoint_control']['exit_code'], 1)
            self.assertEqual(proof['runs'], [])
