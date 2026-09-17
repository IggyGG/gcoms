"""Check real Cargo staging without changing the supplied application lockfile."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-registry-consumer.py"


@unittest.skipUnless(shutil.which("cargo"), "Cargo is unavailable")
class RegistryIsolationTests(unittest.TestCase):
    def fixture(self, root, source):
        application = root / "application"
        (application / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(application)], check=True)
        (application / "Cargo.toml").write_text(
            '[package]\nname="isolated-consumer"\nversion="0.0.0"\nedition="2021"\n'
            '[dependencies]\ngcoms-fixture="=0.1.0"\n')
        (application / "src/lib.rs").write_text(source)
        original = ('version = 4\n\n[[package]]\nname = "isolated-consumer"\nversion = "0.0.0"\n'
                    'dependencies = ["gcoms-fixture"]\n\n[[package]]\nname = "gcoms-fixture"\n'
                    'version = "0.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    'checksum = "' + '0' * 64 + '"\n')
        (application / "Cargo.lock").write_text(original)
        packages = root / "packages"; packages.mkdir()
        archive = packages / "gcoms-fixture-0.1.0.crate"
        with tarfile.open(archive, "w:gz") as tar:
            for name, body in {"Cargo.toml": '[package]\nname="gcoms-fixture"\nversion="0.1.0"\nedition="2021"\n',
                               "src/lib.rs": 'pub fn value() -> u32 { 42 }\n'}.items():
                data = body.encode(); item = tarfile.TarInfo("gcoms-fixture-0.1.0/" + name)
                item.size = len(data); tar.addfile(item, io.BytesIO(data))
        return application, packages, archive, original

    def run_check(self, root, application, packages):
        return subprocess.run([sys.executable, str(SCRIPT), "--application", str(application),
                               "--packages", str(packages), "--offline", "--target-dir", str(root / "build")],
                              capture_output=True, text=True, timeout=120)

    def test_success_exports_new_checksum_without_changing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application, packages, archive, original = self.fixture(root, 'pub fn answer() -> u32 { gcoms_fixture::value() }\n')
            result = self.run_check(root, application, packages)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((application / "Cargo.lock").read_text(), original)
            report_path, = (root / "build/reports").glob("*/summary.json")
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "passed")
            self.assertIs(report["source_unchanged"], True)
            proposed = (report_path.parent / "Cargo.lock").read_text()
            self.assertIn(hashlib.sha256(archive.read_bytes()).hexdigest(), proposed)
            self.assertNotIn("127.0.0.1", proposed)

    def test_compile_failure_preserves_original_and_retains_failed_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application, packages, _, original = self.fixture(root, 'pub fn broken() { missing_function(); }\n')
            result = self.run_check(root, application, packages)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((application / "Cargo.lock").read_text(), original)
            report_path, = (root / "build/reports").glob("*/summary.json")
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "failed")
            self.assertIs(report["source_unchanged"], True)
            self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
