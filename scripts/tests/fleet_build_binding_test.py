"""Application facade and runtime must come from the same frozen GComs source."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('fleet_build', ROOT / 'scripts/build-fleet-files.py')
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class FleetSourceTests(unittest.TestCase):
    def test_public_facade_is_bound_to_same_source_as_runtime_and_transport(self):
        patches = tomllib.loads(build.source_patches(ROOT))['patch']['crates-io']
        for name, directory in [('gcoms', 'application'), ('gcoms-runtime', 'runtime'),
                                ('gcoms-node', 'node'), ('gcoms-routing', 'routing')]:
            self.assertIn(name, patches, 'published registry facade must not escape the frozen source pair')
            self.assertEqual(Path(patches[name]['path']), ROOT / 'crates' / directory)

    def test_supplied_production_relay_rejects_changed_bytes_features_and_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / 'gcnode'; binary.write_bytes(b'production relay')
            receipt = {'schema': 1, 'kind': 'linux_native_services', 'passed': True,
                'commands': [['cargo', 'build', '--locked', '--release', '-p', 'gcoms-node',
                              '-p', 'gcoms-catalog', '-p', 'gcoms-channel-service', '--features',
                              'gcoms-node/experimental-gc2,gcoms-node/push-gateway,gcoms-catalog/experimental-gc2']],
                'target': 'x86_64-unknown-linux-gnu', 'rustc': 'pinned compiler', 'rustflags': '',
                'compiler_environment': {'RUSTFLAGS': '', 'CARGO_ENCODED_RUSTFLAGS': '', 'CARGO_BUILD_TARGET': ''},
                'sources': {'gcoms': {'commit': 'a' * 40}}, 'files': {'gcnode': build.digest(binary)}}
            report = directory / 'receipt.json'; report.write_text(json.dumps(receipt))
            def inspect(command, **kwargs):
                return 'pinned compiler' if command[0] == 'rustc' else 'a' * 40
            with patch.dict(os.environ, {}, clear=True), patch.object(build.subprocess, 'check_output', side_effect=inspect):
                self.assertEqual(build.supplied_relay(directory, {'gcoms': ROOT}), receipt)
                binary.write_bytes(b'other feature graph')
                with self.assertRaisesRegex(ValueError, 'bytes changed'):
                    build.supplied_relay(directory, {'gcoms': ROOT})
                binary.write_bytes(b'production relay')
                for change in ({'commands': [['cargo', 'build']]}, {'sources': {'gcoms': {'commit': 'b' * 40}}}):
                    report.write_text(json.dumps({**receipt, **change}))
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        build.supplied_relay(directory, {'gcoms': ROOT})


if __name__ == '__main__':
    unittest.main()
