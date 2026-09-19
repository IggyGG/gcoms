"""Release gates must reject plausible-looking but incomplete attestations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_evidence as release


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.candidate = {"schema_version": 1, "version": "0.1.0", "channel": "developer-preview",
                          "wire_profile": "GC/1", "targets": list(release.TARGETS),
                          "sources": {}, "artifacts": {}, "checks": {}}
        for i, project in enumerate(release.PROJECTS, 1):
            self.candidate["sources"][project] = {"commit": str(i) * 40, "tree": str(i + 2) * 40,
                                                 "archive": self.file(project + ".tar", b"source fixture")}
        for crate in release.RUST_CRATES:
            self.artifact(f"gcoms-{crate}-0.1.0.crate", "gcoms", "rust")
        for name in ("gcoms-rpc-0.1.0.tgz", "gcoms-rpc-codegen-0.1.0.tgz"):
            self.artifact(name, "gcoms", "npm")
        for target in release.TARGETS:
            suffixes = [".deb", ".AppImage"] if target.startswith("linux") else [".dmg"] if target.startswith("macos") else [".exe"]
            for suffix in suffixes:
                self.artifact("gchat-" + target + suffix, "gchat", "installer", target)
        self.reports = {}
        for check in release.CANDIDATE:
            target = check.split(".", 2)[2] if check in release.NATIVE | release.INSTALLERS else "linux-x86_64"
            report = {"schema_version": 1, "check": check, "sources": release.bindings(self.candidate),
                      "status": "passed", "source_unchanged": True, "started_at": "2026-09-17T00:00:00Z",
                      "finished_at": "2026-09-18T00:00:01Z", "duration_seconds": 86401,
                      "exit_code": 0, "target": target,
                      "environment": {"native_target": target, "rust_host": {"macos-x86_64":"x86_64-apple-darwin", "macos-aarch64":"aarch64-apple-darwin"}.get(target, "x86_64-pc-windows-msvc")},
                      "steps": [{"command": ["python3", "scripts/ci.py"], "status": "passed", "exit_code": 0,
                                 "log": self.file(check + ".log", b"test fixture log\n")}],
                      "artifacts": {name: artifact["sha256"] for name, artifact in self.candidate["artifacts"].items()},
                      "tests": {"passed": 1, "failed": 0, "ignored": 0, "excluded": [], "incomplete": []},
                      "scenarios": {name: "passed" for name in release.INSTALL_SCENARIOS},
                      "systems": {system: {name: "passed" for name in release.INSTALL_SCENARIOS}
                                  for system in ("ubuntu-24.04", "ubuntu-26.04")},
                      "measurements": {"workload_seconds": 86400, "clients": 16, "channels": 4,
                                       "durable_operations_accounted": True, "archives_intact": True,
                                       "resource_bounds_held": True, "fault_recovery_passed": True}}
            self.reports[check] = report
            self.save(check)

    def file(self, name, data):
        path = self.base / name
        path.write_bytes(data)
        return {"path": name, "sha256": release.digest(path)}

    def artifact(self, name, project, kind, target=None):
        self.candidate["artifacts"][name] = {**self.file(name, name.encode()), "project": project, "kind": kind, "target": target}

    def save(self, check):
        self.candidate["checks"][check] = self.file(check + ".json", json.dumps(self.reports[check]).encode())

    def errors(self):
        return release.validate(self.candidate, self.base)

    def test_complete_fixture_passes_private_gate_without_public_contacts(self):
        self.assertEqual(self.errors(), [])
        self.assertTrue(release.validate(self.candidate, self.base, "preflight"))

    def test_unknown_signing_policy_and_preview_publication_mismatch_fail(self):
        self.candidate["signing_policy"] = "unsigned"
        self.assertTrue(any("signing policy" in error for error in self.errors()))
        config = {
            "project": "gchat", "version": "0.1.0", "channel": "developer-preview",
            "publication_status": "approved_by_owner", "signing_policy": "self-signed-preview",
            "public_repository_url": "https://github.com/IggyGG/gchat",
            "companion_url": "https://github.com/IggyGG/gcoms",
            "security_contact": "iggy@gchat.boo", "conduct_contact": "iggy@gchat.boo",
            "maintainers": ["IggyGG"],
            "publisher_identities": {platform: {"name": "Gh0st", "certificate_fingerprint": "A" * 40}
                                     for platform in ("linux", "windows", "macos")},
        }
        release.validate_publication(config, "gchat", "0.1.0")
        config["channel"] = "stable"
        with self.assertRaisesRegex(release.EvidenceError, "preview channel"):
            release.validate_publication(config, "gchat", "0.1.0")

    def test_truthy_strings_and_booleans_cannot_replace_success(self):
        check = "native.gcoms.linux-x86_64"
        original = copy.deepcopy(self.reports[check])
        for key, value in [("status", "false"), ("source_unchanged", "true"), ("exit_code", False), ("schema_version", True)]:
            with self.subTest(key=key):
                self.reports[check] = {**original, key: value}; self.save(check)
                self.assertTrue(self.errors())

    def test_changed_log_and_artifact_bytes_block_release(self):
        (self.base / "native.gcoms.linux-x86_64.log").write_text("altered")
        self.assertTrue(any("hash mismatch" in error for error in self.errors()))
        (self.base / "gcoms-sdk-0.1.0.crate").write_text("changed archive")
        self.assertTrue(any("hash mismatch" in error for error in self.errors()))

    def test_stale_source_or_archive_binding_is_rejected(self):
        check = "packages.rust"
        self.reports[check]["sources"]["gcoms"]["commit"] = "f" * 40; self.save(check)
        self.assertTrue(any("source inputs" in error for error in self.errors()))
        self.reports[check]["sources"] = release.bindings(self.candidate)
        self.reports[check]["artifacts"]["gcoms-sdk-0.1.0.crate"] = "f" * 64; self.save(check)
        self.assertTrue(any("stale artifact" in error for error in self.errors()))

    def test_all_signed_platforms_are_required(self):
        self.assertTrue({"signing.macos", "signing.linux", "signing.windows"} <= release.PREFLIGHT)
        self.candidate["checks"].pop("native.gcoms.windows-x86_64")
        self.assertTrue(any("native.gcoms.windows-x86_64" in error for error in self.errors()))
        self.candidate["targets"].remove("windows-x86_64")
        self.assertTrue(any("Linux, Windows" in error for error in self.errors()))

    def test_timeout_zero_tests_and_unexplained_skips_are_rejected(self):
        check = "native.gcoms.windows-x86_64"
        original = copy.deepcopy(self.reports[check])
        for patch in [{"status": "timeout"}, {"tests": {"passed": 0}},
                      {"tests": {**original["tests"], "ignored": 1}},
                      {"tests": {**original["tests"], "incomplete": ["compile"]}}]:
            with self.subTest(patch=patch):
                self.reports[check] = {**original, **patch}; self.save(check)
                self.assertTrue(self.errors())

    def test_cross_build_and_partial_test_commands_do_not_qualify_native_target(self):
        check = "native.gcoms.windows-x86_64"
        self.reports[check]["environment"]["rust_host"] = "x86_64-pc-windows-gnu"; self.save(check)
        self.assertTrue(any("MSVC" in error for error in self.errors()))
        self.reports[check]["environment"]["rust_host"] = "x86_64-pc-windows-msvc"
        self.reports[check]["steps"][0]["command"] = ["cargo", "test", "one_case"]; self.save(check)
        self.assertTrue(any("CI entrypoint" in error for error in self.errors()))

    def test_installer_requires_complete_journey_and_artifact_binding(self):
        check = "installer.gchat.windows-x86_64"
        self.reports[check]["scenarios"].pop("upgrade_retained_profile"); self.save(check)
        self.assertTrue(any("installer scenarios" in error for error in self.errors()))
        self.reports[check]["scenarios"]["upgrade_retained_profile"] = "passed"
        self.reports[check]["artifacts"] = {}; self.save(check)
        self.assertTrue(any("bind every target artifact" in error for error in self.errors()))

    def test_short_fuzz_or_soak_cannot_pass_as_24_hours(self):
        for check in ("security.fuzz", "soak.application"):
            self.reports[check]["measurements"]["workload_seconds"] = 60; self.save(check)
        self.assertEqual(sum("24-hour workload" in error for error in self.errors()), 2)

    def test_both_linux_installation_systems_are_required(self):
        check = "installer.gchat.linux-x86_64"
        self.reports[check]["systems"].pop("ubuntu-24.04"); self.save(check)
        self.assertTrue(any("ubuntu-24.04" in error for error in self.errors()))

    def test_unreviewed_exclusion_and_nonfinite_duration_are_rejected(self):
        check = "native.gcoms.linux-x86_64"
        self.reports[check]["tests"].update(ignored=1, excluded=[{"name": "important_test", "reason": "slow"}])
        self.save(check)
        self.assertTrue(any("reviewed qualification policy" in error for error in self.errors()))
        self.reports[check]["duration_seconds"] = float("inf"); self.save(check)
        self.assertTrue(any("invalid JSON constant" in error for error in self.errors()))

    def test_evidence_paths_cannot_escape_bundle(self):
        self.candidate["checks"]["packages.rust"]["path"] = "../outside.json"
        self.assertTrue(any("stay inside" in error for error in self.errors()))

    def test_duplicate_json_keys_are_rejected(self):
        path = self.base / "duplicate.json"; path.write_text('{"status":"failed","status":"passed"}')
        with self.assertRaises(release.EvidenceError):
            release.read_json(path)


if __name__ == "__main__":
    unittest.main()
