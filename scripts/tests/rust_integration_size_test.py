"""Keep the native size ceiling strict while retaining every measured delta."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'rust_integrations', Path(__file__).resolve().parents[1] / 'check-rust-integrations.py')
sizes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sizes)


class SizeGate(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(self.directory) / 'baseline.json'
        self.baseline = dict(system='Linux', machine='x86_64', rustc='pinned',
                             panic='unwind', lto=True, codegen_units=1, stripped=True,
                             binaries=[dict(mode=mode, opt_level=level, bytes=10000)
                                       for mode in ('ipc', 'embedded', 'network-client')
                                       for level in ('3', 's', 'z')])
        self.path.write_text(json.dumps(self.baseline))
        self.report = json.loads(json.dumps(self.baseline))

    def test_failure_keeps_all_deltas_and_all_oversized_consumers(self):
        self.report['binaries'][0]['bytes'] = 13600
        self.report['binaries'][-1]['bytes'] = 10600
        with self.assertRaisesRegex(RuntimeError, '36.0%.*6.0%'):
            sizes.compare_baseline(self.report, self.path)
        self.assertEqual(len(self.report['baseline_comparison']), 9)
        self.assertEqual(self.report['baseline_comparison'][0]['growth_percent'], 36)
        self.assertEqual(self.report['baseline_comparison'][-1]['growth_percent'], 6)

    def test_size_limit_and_toolchain_binding_are_preserved(self):
        self.report['binaries'][0]['bytes'] = 10499
        sizes.compare_baseline(self.report, self.path)
        self.report['binaries'][0]['bytes'] = 10500
        sizes.compare_baseline(self.report, self.path)
        self.report['binaries'][0]['bytes'] = 10501
        with self.assertRaisesRegex(RuntimeError, 'exceeds the 5%'):
            sizes.compare_baseline(self.report, self.path)
        self.report['rustc'] = 'different'
        with self.assertRaisesRegex(RuntimeError, 'baseline rustc differs'):
            sizes.compare_baseline(self.report, self.path)
