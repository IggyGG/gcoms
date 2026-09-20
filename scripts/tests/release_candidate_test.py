"""Exercise actual CLI isolation, failure retention and concurrent recording."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "release-candidate.py"


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.roots = {}
        for project in ("gcoms", "gchat"):
            root = self.base / project
            root.mkdir()
            self.roots[project] = root
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
            for args in (("init", "-q"), ("add", "."),
                         ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")):
                subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
        self.manifest = self.base / "candidate/candidate.json"

    def sources(self):
        return ["--gcoms", str(self.roots["gcoms"]), "--gchat", str(self.roots["gchat"])]

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)

    def initialize(self):
        result = self.run_cli("init", *self.sources(), "--output", self.manifest.parent)
        self.assertEqual(result.returncode, 0, result.stderr)

    def command(self, check, code, timeout=10):
        return [sys.executable, str(SCRIPT), "record", "--candidate", str(self.manifest),
                "--check", check, "--project", "gcoms", *self.sources(), "--timeout", str(timeout),
                "--", sys.executable, "-c", code]

    def record(self, check, code, timeout=10):
        return subprocess.run(self.command(check, code, timeout), capture_output=True, text=True)

    def report(self, check):
        manifest = json.loads(self.manifest.read_text())
        return json.loads((self.manifest.parent / manifest["checks"][check]["path"]).read_text())

    def test_dirty_source_is_refused_and_candidate_is_never_overwritten(self):
        (self.roots["gchat"] / "unfinished.txt").write_text("keep me")
        result = self.run_cli("init", *self.sources(), "--output", self.manifest.parent)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.manifest.exists())
        (self.roots["gchat"] / "unfinished.txt").unlink()
        self.initialize()
        original = self.manifest.read_bytes()
        result = self.run_cli("init", *self.sources(), "--output", self.manifest.parent)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.manifest.read_bytes(), original)

    def test_failed_attempt_supersedes_pass_without_erasing_evidence(self):
        self.initialize()
        self.assertEqual(self.record("packages.rust", "print('passed')").returncode, 0)
        self.assertNotEqual(self.record("packages.rust", "raise SystemExit(7)").returncode, 0)
        self.assertEqual(self.report("packages.rust")["exit_code"], 7)
        manifest = json.loads(self.manifest.read_text())
        self.assertEqual(len(manifest["attempts"]), 2)
        self.assertTrue(all((self.manifest.parent / row["path"]).is_file() for row in manifest["attempts"]))

    def test_timeout_and_launch_failure_are_retained(self):
        self.initialize()
        result = self.record("security.fuzz", "import time; time.sleep(60)", timeout=0.1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.report("security.fuzz")["status"], "timeout")
        command = self.command("packages.npm", "unused")
        command[-3:] = [str(self.base / "missing-executable")]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.report("packages.npm")["status"], "launch_failed")

    def test_source_change_is_retained_as_failure(self):
        self.initialize()
        result = self.record("packages.rust", "from pathlib import Path; Path('changed').write_text('retained')")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.report("packages.rust")["status"], "source_changed")
        self.assertEqual((self.roots["gcoms"] / "changed").read_text(), "retained")

    def test_parallel_checks_preserve_both_reports(self):
        self.initialize()
        checks = ("packages.rust", "packages.npm")
        processes = [subprocess.Popen(self.command(check, "import time; time.sleep(0.3)"),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for check in checks]
        for process in processes:
            _, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)
        manifest = json.loads(self.manifest.read_text())
        self.assertEqual(set(manifest["checks"]), set(checks))
        self.assertEqual(len(manifest["attempts"]), 2)

    def test_measurements_are_read_after_the_workload_finishes(self):
        self.initialize()
        facts = self.base / "measured.json"
        command = self.command("soak.application",
                               f"from pathlib import Path; Path({str(facts)!r}).write_text('{{\"measurements\":{{\"clients\":16}}}}')")
        position = command.index("--")
        command[position:position] = ["--facts", str(facts)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.report("soak.application")["measurements"]["clients"], 16)

    def test_current_candidate_freezes_explicit_configuration_and_records_it(self):
        result = self.run_cli("init", *self.sources(), "--output", self.manifest.parent,
                              "--wire-profile", "GC/2")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.manifest.parent.exists())
        traffic = self.base / "traffic.json"
        traffic.write_text('{"profile_id":22,"fixture":"test only"}')
        result = self.run_cli("init", *self.sources(), "--output", self.manifest.parent,
                              "--wire-profile", "GC/2", "--traffic-config", traffic)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(self.manifest.read_text())
        self.assertEqual((manifest["schema_version"], manifest["wire_profile"]), (2, "GC/2"))
        frozen = self.manifest.parent / manifest["gc2"]["traffic_config"]["path"]
        self.assertEqual(frozen.read_bytes(), traffic.read_bytes())
        traffic.write_text("later edits do not alter the candidate")
        self.assertNotEqual(frozen.read_bytes(), traffic.read_bytes())
        result = self.record("integration.gc2-turnover", "print('fixture command, not qualification')")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.report("integration.gc2-turnover")["gc2"], manifest["gc2"])


if __name__ == "__main__":
    unittest.main()
