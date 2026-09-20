"""Additional current-protocol gates; no legacy or diagnostic substitutions.

Like release_evidence, this validates source-bound runner attestations, not a
cryptographic proof of execution. Keep identical copies in GComs and GChat.
"""
import math

TARGETS = ("linux-x86_64", "windows-x86_64", "macos-x86_64", "macos-aarch64")
CHECKS = {"integration.gc2-bootstrap", "integration.gc2-turnover", "privacy.gc2-client",
          "fleet.gc2-files"} | {"installed.gc2-network." + target for target in TARGETS}
PRIVACY_GATES = {comparison + "_" + observation
                 for comparison in ("idle_vs_chat", "matched_bulk_vs_mixed")
                 for observation in ("windows", "connections")}


def contract(candidate, base, require, file_reference, read_json):
    value = candidate.get("gc2")
    require(isinstance(value, dict), "missing GC/2 contract")
    require(value.get("profile_id") == 22 and type(value.get("profile_id")) is int,
            "GC/2 file qualification requires explicit profile 22")
    require(value.get("new_profile_protocol") == "gc2" and
            value.get("existing_profile_migration") == "explicit",
            "GC/2 default/migration contract is missing")
    require(value.get("privacy_contract") == "gchat-file-profile-22",
            "accepted file privacy contract is missing")
    config = read_json(file_reference(base, value.get("traffic_config")))
    require(isinstance(config, dict) and type(config.get("profile_id")) is int and config["profile_id"] == 22,
            "traffic configuration does not select profile 22")
    return value


def validate(check, report, candidate, base, artifacts, require, file_reference, read_json):
    require(report.get("gc2") == candidate["gc2"], "report GC/2 configuration differs from candidate")
    if check not in CHECKS:
        return
    measurements = report.get("measurements", {})
    require(isinstance(measurements, dict), "missing GC/2 measurements")
    require(bool(report.get("evidence")), "GC/2 gate needs retained workload evidence")
    inputs = report.get("artifacts", {})
    require(type(measurements.get("observed_profile_id")) is int and measurements["observed_profile_id"] == 22,
            "workload did not observe profile 22")

    def flags(*names):
        for name in names:
            require(measurements.get(name) is True, "GC/2 invariant unproven: " + name)

    def number(name, minimum=0):
        value = measurements.get(name)
        require(type(value) in (int, float) and math.isfinite(value) and value >= minimum,
                "invalid GC/2 measurement: " + name)
        return value

    if check.startswith("installed.gc2-network."):
        target = check.removeprefix("installed.gc2-network.")
        require(report.get("target") == target and
                report.get("environment", {}).get("native_target") == target,
                "installed GC/2 journey requires the native target")
        required = {name for name, item in artifacts.items() if item.get("kind") == "installer"
                    and item.get("project") == "gchat" and item.get("target") == target}
        require(required and required <= inputs.keys(), "installed journey omits target artifacts")
        require(measurements.get("scope") == "installed_desktop_signed_network",
                "explicit fixture/provider bootstrap is not installed onboarding")
        flags("fresh_default_gc2", "signed_network_discovery", "provider_tls_verified",
              "retained_reopen", "bounded_recovery", "protected_catalog_https",
              "legacy_profile_preserved_without_consent", "explicit_migration",
              "migration_preserves_identity_archive_cache_and_pending_operations",
              "no_legacy_or_direct_fallback", "cleanup_complete")
        return

    # Workload reports must name actual executables, not just source archives.
    for project in ("gcoms", "gchat"):
        require(any(name in inputs and item.get("kind") == "executable" and item.get("project") == project
                    for name, item in artifacts.items()), "GC/2 workload omits " + project + " executable")

    if check == "integration.gc2-bootstrap":
        require(measurements.get("scope") == "disconnected_gchat_runtime_https",
                "bootstrap component scope is missing")
        flags("fresh_current_bootstrap", "both_subscription_classes", "retained_identity_reopen",
              "reopen_without_provider", "downgrade_rejected", "current_recovery",
              "fresh_without_invitation_rejected", "cleanup_complete")
    elif check == "integration.gc2-turnover":
        require(measurements.get("clock") == "real", "simulated clock does not qualify application turnover")
        require(type(measurements.get("credential_expiries")) is int and
                measurements["credential_expiries"] >= 3, "three authenticated application expiries required")
        require(number("workload_seconds", 1800) <= report["duration_seconds"], "turnover exceeds recorded runtime")
        require(measurements.get("carrier_cap_seconds") == 1800, "production carrier cap changed")
        flags("actual_gchat_daemon", "fresh_authority_at_carrier_cap",
              "both_classes_contact_and_channel", "admitted_mls_wire_retained",
              "no_early_delivery", "authenticated_ack_after_recovery", "same_identity_reopen",
              "file_spans_turnover", "independent_export_verified", "bounded_connections",
              "no_request_triggered_dial_or_direct_fallback", "cleanup_complete")
        require(number("missing_chat_acknowledgments") == 0, "turnover has missing acknowledgments")
        require(number("maximum_recovery_seconds") <= 300, "turnover recovery exceeded 300 seconds")
    elif check == "fleet.gc2-files":
        flags("actual_gchat_daemon", "matched_background_conditions", "failure_accounting_complete",
              "receiver_reopen_verified", "fault_recovery_passed", "all_production_baselines_unchanged")
        hosts = measurements.get("hosts")
        require(isinstance(hosts, list) and len(hosts) == 8 and all(isinstance(h, str) and h for h in hosts)
                and len(set(hosts)) == 8, "fleet requires eight distinct hosts")
        cleanup = measurements.get("cleanup", {})
        require(isinstance(cleanup, dict) and set(cleanup) == set(hosts) and
                all(row.get("resources_removed") is True and row.get("production_unchanged") is True
                    and row.get("errors") == [] for row in cleanup.values() if isinstance(row, dict)) and
                all(isinstance(row, dict) for row in cleanup.values()), "fleet cleanup incomplete")
        exports = measurements.get("exact_export_sizes")
        require(isinstance(exports, list) and all(type(size) is int for size in exports) and
                {65536, 4 << 20, 32 << 20, 256 << 20, 1 << 30} <= set(exports), "fleet export coverage incomplete")
        require(number("gib_export_seconds") <= 14400, "1 GiB delivery exceeded four hours")
        require(number("small_file_seconds") <= 300, "small file deadline exceeded")
        require(number("maximum_recovery_seconds") <= 300, "fleet recovery deadline exceeded")
        require(number("campaign_seconds", 14400) <= report["duration_seconds"], "campaign duration incomplete")
        require(type(measurements.get("clients")) is int and measurements["clients"] >= 16 and
                type(measurements.get("directed_host_pairs")) is int and measurements["directed_host_pairs"] == 56,
                "fleet client/pair coverage incomplete")
        baseline = number("baseline_chat_p95_seconds")
        require(number("mixed_chat_p95_seconds") <= max(2 * baseline, baseline + 2), "mixed chat p95 failed")
        require(number("maximum_chat_seconds") <= 120 and number("missing_chat_acknowledgments") == 0,
                "fleet chat delivery failed")
    elif check == "privacy.gc2-client":
        path = file_reference(base, measurements.get("classifier_report"))
        privacy = read_json(path)
        require(privacy.get("sources") == report["sources"] and privacy.get("artifacts") == inputs and
                privacy.get("gc2") == candidate["gc2"], "privacy inputs differ from candidate workload")
        require(privacy.get("scope") == "isolated_gchat_all_egress" and
                privacy.get("measurement_valid") is True and privacy.get("diagnostic_only") is False and
                privacy.get("release_qualified") is True and privacy.get("component_gate_passed") is True,
                "invalid/pooled/calibration privacy evidence cannot qualify release")
        require(privacy.get("reference_threshold") == .55 and privacy.get("reference_threshold_is_release_veto") is True,
                "file separability veto changed")
        gates = privacy.get("gates", {})
        require(isinstance(gates, dict) and set(gates) == PRIVACY_GATES, "all four file privacy gates required")
        for name, gate in gates.items():
            require(isinstance(gate, dict), "invalid privacy component: " + name)
            upper = gate.get("separability_upper_97_5")
            require(type(upper) in (int, float) and math.isfinite(upper) and .5 <= upper <= .55 and
                    gate.get("ok") is True, "file separability bound exceeded: " + name)
        flags("all_interfaces_and_process_lifecycle", "packet_derived_connection_lifetimes",
              "exact_chat_and_file_accounting", "no_capture_loss", "independent_runs",
              "matched_bulk_workload", "startup_reopen_bootstrap_catalog_in_scope",
              "unconstrained_and_adverse_links")
        require(type(measurements.get("training_runs_per_workload_link")) is int and
                measurements["training_runs_per_workload_link"] >= 10 and
                type(measurements.get("held_out_runs_per_workload_link")) is int and
                measurements["held_out_runs_per_workload_link"] >= 20,
                "privacy cohorts are incomplete")
