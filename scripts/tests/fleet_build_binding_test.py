"""Application facade and runtime must come from the same frozen GComs source."""
import importlib.util
from pathlib import Path
import sys
import tomllib
import unittest

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


if __name__ == '__main__':
    unittest.main()
