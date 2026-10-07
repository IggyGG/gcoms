"""Parallel Intel jobs may publish only a complete, unchanged qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('merge_sizes', SCRIPTS / 'merge-rust-integrations.py')
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)


class CompleteIntelQualification(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        for name in ('examples/rust-integration/Cargo.toml', 'examples/rust-integration/src/main.rs'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('unchanged consumer\n')
        fixture = 'release/contracts/application-0.1.49'
        shutil.copytree(SCRIPTS.parent / fixture, self.root / fixture)
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        self.binding = MERGE.identity('a' * 40, '12345', '2')
        self.backend = self.root / 'backend'
        self.backend.mkdir()
        (self.backend / 'source.txt').write_text(self.binding['revision'] + '\n')
        (self.backend / 'native.log').write_text('passing native tests\n')
        self.native = dict(self.binding, passed=True, system='Darwin', machine='x86_64', rustc='pinned',
                           native_log_sha256=MERGE.digest(self.backend / 'native.log'))
        MERGE.write(self.backend / 'native-backend.json', self.native)
        self.shards = []
        self.baseline = self.root / 'baseline.json'
        base = dict(schema=1, system='Darwin', machine='x86_64', rustc='pinned',
                    revision=self.binding['revision'], dirty=False, passed=True,
                    panic='unwind', lto=True, codegen_units=1, stripped=True,
                    source_sha256=MERGE.source_hashes(self.root),
                    consumer_sha256={name: MERGE.digest(self.root / name) for name in (
                        'examples/rust-integration/Cargo.toml', 'examples/rust-integration/src/main.rs')},
                    size_policy=MERGE.SIZES.current_policy())
        all_binaries = []
        for mode in MERGE.MODES:
            directory = self.root / mode
            directory.mkdir()
            self.shards.append(directory)
            report = dict(copy.deepcopy(base), graphs={mode: {'gcoms': [mode]}}, binaries=[])
            keys = [(mode, profile) for profile in MERGE.PROFILES]
            if mode == 'ipc':
                keys.append(('host', 's'))
            for kind, profile in keys:
                path = directory / (kind + '-opt-' + profile)
                path.write_bytes(b'x' * 100)
                item = dict(mode=kind, opt_level=profile, bytes=100, sha256=MERGE.digest(path),
                            artifact=path.name, imports=[])
                report['binaries'].append(item)
                all_binaries.append(item)
            compatibility = directory / 'released-facade'
            compatibility.mkdir()
            checks = []
            for consumer in MERGE.MODES:
                log = compatibility / (consumer + '.log')
                log.write_text('successful cargo check\n')
                checks.append(dict(mode=consumer, passed=True, log=log.name, sha256=MERGE.digest(log)))
            MERGE.write(compatibility / 'summary.json', dict(schema=1, passed=True, checks=checks,
                        consumer=MERGE.read(self.root / fixture / 'contract.json')))
            MERGE.write(directory / 'summary.json', report)
            self.rebind(directory)
        MERGE.write(self.baseline, dict(base, binaries=all_binaries))
        self.output = self.root / 'aggregate'

    def rebind(self, directory):
        MERGE.write(directory / 'qualification-shard.json', dict(self.binding, passed=True,
                    mode=directory.name, summary_sha256=MERGE.digest(directory / 'summary.json')))

    def change(self, directory, update):
        report = MERGE.read(directory / 'summary.json')
        update(report)
        MERGE.write(directory / 'summary.json', report)
        self.rebind(directory)

    def merge(self, shards=None):
        return MERGE.merge(self.root, self.backend, self.shards if shards is None else shards,
                           self.output, self.baseline, self.binding)

    def rejected(self, pattern, shards=None):
        with self.assertRaisesRegex(ValueError, pattern):
            self.merge(shards)
        self.assertFalse(self.output.exists(), 'failed evidence must not create an aggregate')

    def test_complete_original_contract_and_backend_are_retained(self):
        report = self.merge()
        self.assertTrue(report['passed'])
        self.assertEqual(set(report['graphs']), set(MERGE.MODES))
        self.assertEqual(len(report['binaries']), 10)
        self.assertEqual(len(report['baseline_comparison']), 10)
        self.assertEqual((self.output / 'native.log').read_bytes(), (self.backend / 'native.log').read_bytes())
        self.assertEqual(MERGE.read(self.output / 'released-facade/summary.json'),
                         MERGE.read(self.shards[0] / 'released-facade/summary.json'))
        self.assertEqual(len(list((self.output / 'shards').glob('*/qualification-shard.json'))), 3)
        for item in report['binaries']:
            self.assertEqual(MERGE.digest(self.output / item['artifact']), item['sha256'])

    def test_missing_or_duplicate_shards_cannot_qualify(self):
        self.rejected('exactly three', self.shards[:2])
        self.rejected('duplicated', [self.shards[0], self.shards[0], self.shards[2]])

    def test_missing_or_duplicate_measurements_cannot_qualify(self):
        directory = self.shards[0]
        original = MERGE.read(directory / 'summary.json')
        self.change(directory, lambda report: report['binaries'].pop())
        self.rejected('measurements')
        MERGE.write(directory / 'summary.json', original)
        self.change(directory, lambda report: report['binaries'].append(report['binaries'][0]))
        self.rejected('measurements')

    def test_failed_shard_or_backend_cannot_qualify(self):
        self.change(self.shards[1], lambda report: report.update(passed=False))
        self.rejected('consumer source')
        self.change(self.shards[1], lambda report: report.update(passed=True))
        MERGE.write(self.backend / 'native-backend.json', dict(self.native, passed=False))
        self.rejected('pass binding')

    def test_foreign_source_run_or_attempt_binding_cannot_qualify(self):
        for key, value in [('revision', 'b' * 40), ('run_id', '999'), ('run_attempt', '0'), ('run_attempt', '3')]:
            with self.subTest(key=key):
                marker = dict(self.native, **{key: value})
                MERGE.write(self.backend / 'native-backend.json', marker)
                self.rejected('binding')

    def test_completed_prior_attempt_of_same_run_is_preserved(self):
        MERGE.write(self.backend / 'native-backend.json', dict(self.native, run_attempt='1'))
        directory = self.shards[1]
        marker = MERGE.read(directory / 'qualification-shard.json')
        MERGE.write(directory / 'qualification-shard.json', dict(marker, run_attempt='1'))
        self.merge()
        attempts = MERGE.read(self.output / 'qualification-merge.json')['original_attempts']
        self.assertEqual(attempts, {'backend': '1', 'consumers': {'ipc': '2', 'embedded': '1', 'network-client': '2'}})

    def test_latest_artifact_requires_its_own_complete_bound_receipt(self):
        prefix = 'rust-integrations-intel-embedded-' + self.binding['revision'] + '-'
        first = self.root / (prefix + '1')
        second = self.root / (prefix + '2')
        first.mkdir(); second.mkdir()
        marker = dict(self.binding, passed=True, mode='embedded', run_attempt='1')
        MERGE.write(first / 'qualification-shard.json', marker)
        select = lambda paths: MERGE.latest_attempt(paths, prefix, 'qualification-shard.json', self.binding, 'embedded')
        self.assertEqual(select([first]), first)
        with self.assertRaises(FileNotFoundError):
            select([first, second])
        MERGE.write(second / 'qualification-shard.json', dict(marker, run_attempt='2', passed=False))
        with self.assertRaisesRegex(ValueError, 'pass binding'):
            select([first, second])
        for update in ({'run_id': 'other'}, {'revision': 'b' * 40}, {'mode': 'ipc'}, {'run_attempt': '1'}):
            MERGE.write(second / 'qualification-shard.json', dict(marker, **{'run_attempt': '2', **update}))
            with self.assertRaisesRegex(ValueError, 'binding'):
                select([first, second])
        MERGE.write(second / 'qualification-shard.json', dict(marker, run_attempt='2'))
        self.assertEqual(select([first, second]), second)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            select([second, second])

    def test_forged_summary_or_binary_hash_cannot_qualify(self):
        directory = self.shards[1]
        summary = directory / 'summary.json'
        original = summary.read_bytes()
        summary.write_bytes(original + b' ')
        self.rejected('artifact hash')
        summary.write_bytes(original)
        (directory / 'embedded-opt-z').write_bytes(b'changed binary')
        self.rejected('artifact hash')

    def test_native_log_must_match_completed_backend_receipt(self):
        (self.backend / 'native.log').write_text('different log')
        self.rejected('artifact hash')

    def test_changed_source_or_dirty_measurements_cannot_qualify(self):
        self.change(self.shards[0], lambda report: report.update(dirty=True))
        self.rejected('consumer source')
        self.change(self.shards[0], lambda report: report.update(dirty=False))
        (self.root / 'examples/rust-integration/src/main.rs').write_text('different source')
        self.rejected('consumer source')

    def test_mixed_toolchains_and_profile_flags_cannot_qualify(self):
        directory = self.shards[1]
        for key, value in [('lto', False), ('codegen_units', 16)]:
            original = MERGE.read(directory / 'summary.json')
            self.change(directory, lambda report: report.update({key: value}))
            self.rejected('toolchain, profile or policy')
            MERGE.write(directory / 'summary.json', original)
            self.rebind(directory)

    def test_backend_and_consumer_toolchains_must_match(self):
        MERGE.write(self.backend / 'native-backend.json', dict(self.native, rustc='another compiler'))
        self.rejected('consumer source')

    def test_graph_exclusions_are_rechecked_at_merge(self):
        cases = [('ipc', 'gcoms-node', []), ('network-client', 'gcoms-node', ['relay-host']),
                 ('network-client', 'quick-xml', []), ('embedded', 'tokio', ['rt-multi-thread']),
                 ('embedded', 'gcoms-rpc', [])]
        for mode, package, features in cases:
            directory = self.root / mode
            original = MERGE.read(directory / 'summary.json')
            self.change(directory, lambda report: report['graphs'][mode].update({package: features}))
            self.rejected('graph includes')
            MERGE.write(directory / 'summary.json', original)
            self.rebind(directory)

    def test_missing_compatibility_or_changed_log_cannot_qualify(self):
        directory = self.shards[2] / 'released-facade'
        summary = MERGE.read(directory / 'summary.json')
        MERGE.write(directory / 'summary.json', dict(summary, checks=summary['checks'][:2]))
        self.rejected('compatibility modes')
        MERGE.write(directory / 'summary.json', summary)
        (directory / 'ipc.log').write_text('different log')
        self.rejected('artifact hash')

    def test_aggregate_rechecks_size_ceiling_without_trusting_shard_pass(self):
        directory = self.shards[2]
        artifact = directory / 'network-client-opt-z'
        artifact.write_bytes(b'x' * 121)
        def alter(report):
            item = next(item for item in report['binaries'] if item['opt_level'] == 'z')
            item.update(bytes=121, sha256=MERGE.digest(artifact))
        self.change(directory, alter)
        with self.assertRaisesRegex(RuntimeError, 'exceeds the 20%'):
            self.merge()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
