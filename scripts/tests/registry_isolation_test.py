"""Check real Cargo staging without changing the supplied application lockfile."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "check-registry-consumer.py"


@unittest.skipUnless(shutil.which("cargo"), "Cargo is unavailable")
class RegistryIsolationTests(unittest.TestCase):
    def fixture(self, root, source, value=42):
        application = root / "application"
        (application / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(application)], check=True)
        (application / "Cargo.toml").write_text(
            '[package]\nname="isolated-consumer"\nversion="0.0.0"\nedition="2021"\n'
            '[dependencies]\ngcoms-fixture="=0.1.0"\n[workspace]\n')
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
                               "src/lib.rs": f'pub fn value() -> u32 {{ {value} }}\n'}.items():
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
            self.assertIn("missing_function", result.stderr)
            self.assertEqual((application / "Cargo.lock").read_text(), original)
            report_path, = (root / "build/reports").glob("*/summary.json")
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "failed")
            self.assertIs(report["source_unchanged"], True)
            self.assertIn("error", report)

    def test_reused_port_checks_changed_archive_without_reusing_cached_checksum(self):
        # Keep Cargo's cache and server address identical across two different
        # archives of the same package version. Exercise the staged main path,
        # including canonical lock export and actual dependency execution.
        with patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]):
            spec = importlib.util.spec_from_file_location("registry_consumer", SCRIPT)
            registry = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(registry)
        server_type = registry.http.server.ThreadingHTTPServer
        ports = []

        def reuse_port(address, handler):
            server = server_type((address[0], ports[0] if ports else 0), handler)
            ports.append(server.server_port)
            return server

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checksums = []
            with patch.dict(os.environ, {"CARGO_HOME": str(root / "cargo-home")}), \
                    patch.object(registry.http.server, "ThreadingHTTPServer", side_effect=reuse_port):
                for number in (42, 43):
                    case = root / str(number)
                    source = f'#[test] fn exact_value() {{ assert_eq!(gcoms_fixture::value(), {number}); }}\n'
                    application, packages, archive, original = self.fixture(case, source, number)
                    argv = [str(SCRIPT), "--application", str(application), "--packages", str(packages),
                            "--offline", "--command", "test", "--target-dir", str(case / "build")]
                    with patch.object(sys, "argv", argv):
                        registry.main()
                    self.assertEqual((application / "Cargo.lock").read_text(), original)
                    report = json.loads((case / "build/summary.json").read_text())
                    self.assertEqual(report["status"], "passed")
                    self.assertIs(report["source_unchanged"], True)
                    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
                    checksums.append(checksum)
                    proposed = Path(report["lockfile"]).read_text()
                    self.assertIn(checksum, proposed)
                    self.assertNotIn("127.0.0.1", proposed)
            self.assertEqual(len(ports), 2)
            self.assertEqual(ports[0], ports[1])
            self.assertNotEqual(checksums[0], checksums[1])


if __name__ == "__main__":
    unittest.main()
