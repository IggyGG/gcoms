"""Keep version-bound native size ceilings strict and retain measured failures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sdk_size_policy import current_policy, exceeds_limit, policy_for_version

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
        self.report['binaries'][-1]['bytes'] = 12600
        with self.assertRaisesRegex(RuntimeError, '36.0%.*26.0%'):
            sizes.compare_baseline(self.report, self.path)
        self.assertEqual(len(self.report['baseline_comparison']), 9)
        self.assertEqual(self.report['baseline_comparison'][0]['growth_percent'], 36)
        self.assertEqual(self.report['baseline_comparison'][-1]['growth_percent'], 26)

    def test_feature_limit_and_toolchain_binding_are_preserved(self):
        self.report['binaries'][0]['bytes'] = 11999
        sizes.compare_baseline(self.report, self.path)
        self.report['binaries'][0]['bytes'] = 12000
        sizes.compare_baseline(self.report, self.path)
        self.report['binaries'][0]['bytes'] = 12001
        with self.assertRaisesRegex(RuntimeError, 'exceeds the 20%'):
            sizes.compare_baseline(self.report, self.path)
        self.report['rustc'] = 'different'
        with self.assertRaisesRegex(RuntimeError, 'baseline rustc differs'):
            sizes.compare_baseline(self.report, self.path)

    def test_stable_major_and_prereleases_automatically_restore_five_percent(self):
        for version in ('1.0.0-rc.1', '1.0.0', '1.2.3', '2.0.0'):
            with self.subTest(version=version):
                self.report['size_policy'] = policy_for_version(version)
                self.report['binaries'][0]['bytes'] = 10500
                sizes.compare_baseline(self.report, self.path)
                self.report['binaries'][0]['bytes'] = 10501
                with self.assertRaisesRegex(RuntimeError, 'exceeds the 5%'):
                    sizes.compare_baseline(self.report, self.path)

    def test_missing_measurement_is_not_silently_qualified(self):
        self.report['binaries'].append(dict(mode='host', opt_level='s', bytes=10000))
        with self.assertRaisesRegex(RuntimeError, 'has no native size baseline'):
            sizes.compare_baseline(self.report, self.path)

    def test_policy_reads_inherited_and_explicit_sdk_versions(self):
        root = Path(self.directory)
        (root / 'crates/sdk').mkdir(parents=True)
        sdk = root / 'crates/sdk/Cargo.toml'
        sdk.write_text('[package]\nversion.workspace = true\n')
        (root / 'Cargo.toml').write_text('[workspace.package]\nversion = "0.1.0"\n')
        self.assertEqual(current_policy(root)['limit_percent'], 20)
        (root / 'Cargo.toml').write_text('[workspace.package]\nversion = "1.0.0"\n')
        self.assertEqual(current_policy(root)['limit_percent'], 5)
        sdk.write_text('[package]\nversion = "1.1.0"\n')
        self.assertEqual(current_policy(root)['limit_percent'], 5)

    def test_policy_cannot_be_overridden_or_accept_invalid_measurements(self):
        policy = dict(policy_for_version('1.0.0'), limit_percent=20)
        with self.assertRaisesRegex(ValueError, 'ceiling differs'):
            exceeds_limit(11000, 10000, policy)
        for current, previous in ((100, 0), (100, -1), (-1, 100), (100.0, 100), (True, 100)):
            with self.subTest(current=current, previous=previous):
                with self.assertRaises(ValueError):
                    exceeds_limit(current, previous, policy_for_version('0.1.0'))
        for version in ('', None, 'unstable', '1', '01.0.0'):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    policy_for_version(version)
