"""Adversarial evidence fixtures, not qualification reports or measurements."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_evidence_test as fixtures
import release_evidence as release
import gc2_release_evidence as gc2


class CurrentEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.EvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.temporary.cleanup)
        f = self.fixture
        f.candidate.update(schema_version=2, wire_profile="GC/2", gc2={
            "profile_id": 22, "privacy_contract": "gchat-file-profile-22",
            "new_profile_protocol": "gc2", "existing_profile_migration": "explicit",
            "traffic_config": f.file("traffic.json", b'{"profile_id":22}')})
        for project in ("gcoms", "gchat"):
            f.artifact(project + "-binary", project, "executable", "linux-x86_64")
        base = copy.deepcopy(f.reports["integration.gchat"])
        for check in gc2.CHECKS:
            report = copy.deepcopy(base)
            report["check"] = check
            report["evidence"] = [f.file(check + "-raw.log", b"adversarial fixture, not real evidence")]
            report["artifacts"] = {name: item["sha256"] for name, item in f.candidate["artifacts"].items()}
            m = report["measurements"] = {"observed_profile_id": 22}
            if check == "integration.gc2-bootstrap":
                m["scope"] = "disconnected_gchat_runtime_https"
                self.flags(m, "fresh_current_bootstrap both_subscription_classes retained_identity_reopen "
                    "reopen_without_provider downgrade_rejected current_recovery fresh_without_invitation_rejected cleanup_complete")
            elif check == "integration.gc2-turnover":
                m.update(clock="real", credential_expiries=3, workload_seconds=10800, carrier_cap_seconds=1800,
                         missing_chat_acknowledgments=0, maximum_recovery_seconds=120)
                self.flags(m, "actual_gchat_daemon fresh_authority_at_carrier_cap both_classes_contact_and_channel "
                    "admitted_mls_wire_retained no_early_delivery authenticated_ack_after_recovery same_identity_reopen "
                    "file_spans_turnover independent_export_verified bounded_connections "
                    "no_request_triggered_dial_or_direct_fallback cleanup_complete")
            elif check == "fleet.gc2-files":
                self.flags(m, "actual_gchat_daemon matched_background_conditions failure_accounting_complete "
                    "receiver_reopen_verified fault_recovery_passed all_production_baselines_unchanged")
                m.update(hosts=["r" + str(i) for i in range(1, 9)], exact_export_sizes=[65536, 4<<20, 32<<20, 256<<20, 1<<30],
                         gib_export_seconds=12000, small_file_seconds=15, maximum_recovery_seconds=120,
                         campaign_seconds=14400, clients=16, directed_host_pairs=56,
                         baseline_chat_p95_seconds=10, mixed_chat_p95_seconds=20, maximum_chat_seconds=60,
                         missing_chat_acknowledgments=0)
                m["cleanup"] = {h: dict(resources_removed=True, production_unchanged=True, errors=[]) for h in m["hosts"]}
            elif check.startswith("installed."):
                target = check.removeprefix("installed.gc2-network.")
                report["target"] = target
                report["environment"]["native_target"] = target
                m["scope"] = "installed_desktop_signed_network"
                self.flags(m, "fresh_default_gc2 signed_network_discovery provider_tls_verified retained_reopen "
                    "bounded_recovery protected_catalog_https legacy_profile_preserved_without_consent explicit_migration "
                    "migration_preserves_identity_archive_cache_and_pending_operations no_legacy_or_direct_fallback cleanup_complete")
            else:
                self.flags(m, "all_interfaces_and_process_lifecycle packet_derived_connection_lifetimes "
                    "exact_chat_and_file_accounting no_capture_loss independent_runs matched_bulk_workload "
                    "startup_reopen_bootstrap_catalog_in_scope unconstrained_and_adverse_links")
                m.update(training_runs_per_workload_link=10, held_out_runs_per_workload_link=20)
            f.reports[check] = report
        for check, report in f.reports.items():
            report["gc2"] = copy.deepcopy(f.candidate["gc2"])
            f.save(check)
        report = f.reports["privacy.gc2-client"]
        self.privacy = dict(sources=release.bindings(f.candidate), artifacts=report["artifacts"], gc2=f.candidate["gc2"],
            scope="isolated_gchat_all_egress", measurement_valid=True, diagnostic_only=False, release_qualified=True,
            component_gate_passed=True, reference_threshold=.55, reference_threshold_is_release_veto=True,
            gates={name: dict(ok=True, separability_upper_97_5=.55) for name in gc2.PRIVACY_GATES})
        self.save_privacy()

    @staticmethod
    def flags(measurements, names):
        measurements.update({name: True for name in names.split()})

    def save_privacy(self):
        f = self.fixture
        f.reports["privacy.gc2-client"]["measurements"]["classifier_report"] = f.file("privacy.json", json.dumps(self.privacy).encode())
        f.save("privacy.gc2-client")

    def errors(self):
        return self.fixture.errors()

    def test_responsive_profile_requires_matching_contract_configuration_and_measurement(self):
        f = self.fixture
        candidate = copy.deepcopy(f.candidate)
        candidate["gc2"].update(profile_id=46, privacy_contract="gchat-responsive-profile-46",
            traffic_config=f.file("responsive.json", b'{"profile_id":46}'))
        report = copy.deepcopy(f.reports["integration.gc2-bootstrap"])
        report["gc2"] = candidate["gc2"]
        report["measurements"]["observed_profile_id"] = 46
        def require(ok, message):
            if not ok:
                raise ValueError(message)
        def file_reference(base, reference):
            return base / reference["path"]
        def read_json(path):
            return json.loads(path.read_text())
        base = Path(f.temporary.name)
        gc2.contract(candidate, base, require, file_reference, read_json)
        gc2.validate("integration.gc2-bootstrap", report, candidate, base,
                     candidate["artifacts"], require, file_reference, read_json)
        report["measurements"]["observed_profile_id"] = 22
        with self.assertRaisesRegex(ValueError, "selected profile"):
            gc2.validate("integration.gc2-bootstrap", report, candidate, base,
                         candidate["artifacts"], require, file_reference, read_json)
        candidate["gc2"]["privacy_contract"] = "gchat-file-profile-22"
        with self.assertRaisesRegex(ValueError, "privacy contract"):
            gc2.contract(candidate, base, require, file_reference, read_json)

    def test_complete_fixture_is_accepted_and_every_extra_gate_is_required(self):
        self.assertEqual(self.errors(), [])
        for check in gc2.CHECKS:
            ref = self.fixture.candidate["checks"].pop(check)
            self.assertIn(check + ": no report", self.errors())
            self.fixture.candidate["checks"][check] = ref

    def test_legacy_schema_or_report_cannot_be_relabelled(self):
        f = self.fixture
        f.candidate["schema_version"] = 1
        self.assertTrue(self.errors())
        f.candidate["schema_version"] = 2
        del f.reports["native.gchat.linux-x86_64"]["gc2"]
        f.save("native.gchat.linux-x86_64")
        self.assertTrue(any("GC/2 configuration" in e for e in self.errors()))

    def test_pooled_invalid_or_unfavorable_privacy_never_qualifies(self):
        original = copy.deepcopy(self.privacy)
        for patch in ({"scope": "pooled_loopback_entry_links"}, {"diagnostic_only": True},
                      {"measurement_valid": False}, {"release_qualified": False},
                      {"reference_threshold_is_release_veto": False}, {"reference_threshold": .6}):
            with self.subTest(patch=patch):
                self.privacy = {**copy.deepcopy(original), **patch}; self.save_privacy()
                self.assertTrue(any("privacy.gc2-client" in e for e in self.errors()))
        for name in gc2.PRIVACY_GATES:
            self.privacy = copy.deepcopy(original)
            self.privacy["gates"][name]["separability_upper_97_5"] = .551
            self.save_privacy()
            self.assertTrue(any("bound exceeded" in e for e in self.errors()))
        self.privacy = copy.deepcopy(original); self.privacy["gates"].pop(next(iter(gc2.PRIVACY_GATES)))
        self.save_privacy(); self.assertTrue(any("four file privacy" in e for e in self.errors()))

    def test_boundaries_and_omitted_executable_are_enforced(self):
        f = self.fixture
        check = "integration.gc2-turnover"
        original = copy.deepcopy(f.reports[check])
        for key, value in (("observed_profile_id", 1), ("clock", "paused"), ("credential_expiries", 1),
                           ("fresh_authority_at_carrier_cap", False), ("missing_chat_acknowledgments", 1),
                           ("maximum_recovery_seconds", 301), ("actual_gchat_daemon", "true")):
            f.reports[check] = copy.deepcopy(original)
            f.reports[check]["measurements"][key] = value; f.save(check)
            self.assertTrue(any(check in e for e in self.errors()), key)
        f.reports[check] = copy.deepcopy(original)
        del f.reports[check]["artifacts"]["gchat-binary"]; f.save(check)
        self.assertTrue(any("omits gchat executable" in e for e in self.errors()))

    def test_capacity_failure_or_cleanup_does_not_become_qualification(self):
        f = self.fixture; check = "fleet.gc2-files"; original = copy.deepcopy(f.reports[check])
        for key, value in (("exact_export_sizes", [65536, 4<<20, 32<<20, 256<<20]),
                           ("missing_chat_acknowledgments", 2), ("mixed_chat_p95_seconds", 20.01),
                           ("matched_background_conditions", False), ("cleanup", {})):
            f.reports[check] = copy.deepcopy(original)
            f.reports[check]["measurements"][key] = value; f.save(check)
            self.assertTrue(any(check in e for e in self.errors()), key)

    def test_explicit_fixture_cannot_qualify_installed_onboarding(self):
        f = self.fixture; check = "installed.gc2-network.linux-x86_64"
        f.reports[check]["measurements"]["scope"] = "disconnected_gchat_runtime_https"; f.save(check)
        self.assertTrue(any("not installed onboarding" in e for e in self.errors()))

    def test_namespace_exclusion_requires_completed_separate_gate(self):
        f = self.fixture; check = "native.gchat.linux-x86_64"
        f.reports[check]["tests"].update(ignored=1, excluded=[{
            "name": "bootstrap_gc2_tests::production_bootstrap_fresh_reopen_and_recovery",
            "reason": "integration.gc2-bootstrap"}]); f.save(check)
        self.assertEqual(self.errors(), [])
        del f.candidate["checks"]["integration.gc2-bootstrap"]
        self.assertIn("integration.gc2-bootstrap: no report", self.errors())


if __name__ == "__main__":
    unittest.main()
