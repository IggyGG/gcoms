"""Local release evidence validation. Standard library only; never publishes.

Reports are trusted runner attestations, not a cryptographic proof of execution.
Hashes bind their source inputs, logs and artifacts; policy decides required scope.
Keep this module identical in GComs and GChat so either repository can check a pair.
"""
import hashlib
import datetime
import json
import math
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import gc2_release_evidence as gc2

PROJECTS = ("gcoms", "gchat")
TARGETS = ("linux-x86_64", "windows-x86_64", "macos-x86_64", "macos-aarch64")
STAGES = ("candidate", "preflight", "published")
NATIVE = {f"native.{project}.{target}" for project in PROJECTS for target in TARGETS}
INSTALLERS = {f"installer.gchat.{target}" for target in TARGETS}
CANDIDATE = NATIVE | INSTALLERS | {
    "packages.rust", "packages.npm", "packages.gchat-registry",
    "integration.browser", "integration.gchat", "security.dependencies",
    "security.inventory", "security.secrets", "security.fuzz", "stress.mls64", "stress.low-port",
    "soak.application", "stress.files-streaming",
}
PREFLIGHT = CANDIDATE | {"review.rights", "review.operator", "review.maintainers",
                         "signing.windows", "signing.macos", "signing.linux", "signing.manifest"}
PUBLISHED = PREFLIGHT | {"published.rust", "published.npm", "published.gchat"}
INSTALL_SCENARIOS = {
    "fresh_install", "invite_unlock", "messaging", "file_transfer", "reconnect",
    "restart", "upgrade_retained_profile", "interrupted_upgrade", "archive_recovery",
    "rollback", "uninstall_preserves_data",
}
RUST_CRATES = {
    "catalog", "core", "crypto", "file-transfer", "gossip", "mls", "network",
    "network-client", "node", "private-fs", "protocol", "routing", "rpc",
    "rpc-contract", "rpc-macros", "sdk", "transport",
}
# These cases have separate qualification gates or explicitly private fixtures.
# Adding another ignored test requires a reviewed policy change here.
EXCLUSIONS = {
    "gib_import_resume_export_is_streaming": "stress.files-streaming",
    "sixty_four_member_channel": "stress.mls64",
    "connectivity::privilege_tests::real_denied_low_port_falls_back_without_privileges": "stress.low-port",
    "native_c_handshake_accepts_only_the_pinned_relay_and_h2": "private external TLS probe",
    "native_c_deadline_bounds_stalled_and_trickling_peers": "private external TLS probe",
    "native_c_http2_uses_existing_tp1_post_and_stream_paths": "private external TLS probe",
}


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def invalid_constant(value):
        raise EvidenceError(f"invalid JSON constant: {value}")
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique,
                      parse_constant=invalid_constant)


def hex_string(value, size):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is not None


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def file_reference(base, reference):
    require(isinstance(reference, dict), "file reference must be an object")
    name = reference.get("path")
    require(nonempty(name), "file reference needs a path")
    relative = Path(name)
    require(not relative.is_absolute() and ".." not in relative.parts, "evidence path must stay inside candidate")
    base = Path(base).resolve()
    path = base / relative
    require(path.resolve().is_relative_to(base), "evidence symlink escapes candidate")
    require(path.is_file(), f"missing evidence: {name}")
    require(hex_string(reference.get("sha256"), 64), f"invalid SHA-256: {name}")
    require(digest(path) == reference["sha256"], f"evidence hash mismatch: {name}")
    return path


def source_identity(root):
    root = Path(root).resolve()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root)
    require(not status.strip(), f"release source is dirty: {root.name}")
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}")}


def validate_sources(candidate, base, repositories=None):
    sources = candidate.get("sources")
    require(isinstance(sources, dict) and set(sources) == set(PROJECTS), "both source repositories are required")
    for project, source in sources.items():
        require(isinstance(source, dict), f"invalid source: {project}")
        require(hex_string(source.get("commit"), 40) and hex_string(source.get("tree"), 40), f"invalid source identity: {project}")
        file_reference(base, source.get("archive"))
        if repositories and project in repositories:
            require(source_identity(repositories[project]) == {k: source[k] for k in ("commit", "tree")}, f"candidate differs from checkout: {project}")


def bindings(candidate):
    return {project: {key: source[key] for key in ("commit", "tree")} for project, source in candidate["sources"].items()}


def validate_report(check, report, candidate, base, artifacts):
    require(isinstance(report, dict) and type(report.get("schema_version")) is int and report["schema_version"] == 1, "unsupported report schema")
    require(report.get("check") == check, "report belongs to another check")
    require(report.get("sources") == bindings(candidate), "report belongs to different source inputs")
    require(report.get("status") == "passed", f"check status: {report.get('status', 'missing')}")
    require(report.get("source_unchanged") is True, "source changed during check or was not checked")
    require(nonempty(report.get("started_at")) and nonempty(report.get("finished_at")), "missing report timestamps")
    duration = report.get("duration_seconds")
    require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0, "invalid report duration")
    start = datetime.datetime.fromisoformat(report["started_at"])
    finish = datetime.datetime.fromisoformat(report["finished_at"])
    require(start.utcoffset() is not None and finish.utcoffset() is not None, "timestamps need UTC offsets")
    require(finish >= start and abs((finish - start).total_seconds() - duration) <= 10,
            "timestamps disagree with execution duration")
    if check.startswith("review."):
        require(nonempty(report.get("reviewer")), "review needs an identified reviewer")
        require(report.get("approved") is True, "review approval must be true")
        require(bool(report.get("evidence")), "review needs retained evidence")
    else:
        require(type(report.get("exit_code")) is int and report["exit_code"] == 0, "missing or unsuccessful process exit")
        steps = report.get("steps")
        require(isinstance(steps, list) and steps, "check has no executed steps")
        for step in steps:
            require(isinstance(step, dict) and step.get("status") == "passed", "incomplete step")
            command = step.get("command")
            require(isinstance(command, list) and command and all(nonempty(x) for x in command), "missing executed command")
            require(type(step.get("exit_code")) is int and step["exit_code"] == 0, "unsuccessful step exit")
            file_reference(base, step.get("log"))
    for reference in report.get("evidence", []):
        file_reference(base, reference)
    inputs = report.get("artifacts", {})
    require(isinstance(inputs, dict), "invalid report artifact bindings")
    for name, sha in inputs.items():
        require(name in artifacts and artifacts[name]["sha256"] == sha, f"stale artifact binding: {name}")
    if check in NATIVE:
        require(any(len(step["command"]) >= 2 and
                    re.fullmatch(r"python(?:3(?:\.[0-9]+)?)?(?:\.exe)?", Path(step["command"][0]).name) and
                    step["command"][1] == "scripts/ci.py" for step in report["steps"]),
                "native qualification must execute the repository CI entrypoint")
        target = check.split(".", 2)[2]
        require(report.get("target") == target, "native target mismatch")
        environment = report.get("environment", {})
        require(environment.get("native_target") == target, "cross compilation is not native qualification")
        if target == "windows-x86_64":
            require(environment.get("rust_host") == "x86_64-pc-windows-msvc", "Windows release qualification requires native MSVC")
        if target.startswith("macos"):
            expected = "aarch64-apple-darwin" if target == "macos-aarch64" else "x86_64-apple-darwin"
            require(environment.get("rust_host") == expected, "macOS qualification must run on its native architecture")
        counts = report.get("tests", {})
        require(type(counts.get("passed")) is int and counts["passed"] > 0, "no native tests executed")
        require(type(counts.get("failed")) is int and counts["failed"] == 0, "native test failures")
        require(counts.get("incomplete") == [], "incomplete native harnesses")
        require(isinstance(counts.get("excluded"), list), "missing explicit test exclusion inventory")
        require(type(counts.get("ignored")) is int and counts["ignored"] == len(counts["excluded"]), "ignored-test count lacks a complete inventory")
        for exclusion in counts["excluded"]:
            require(isinstance(exclusion, dict) and nonempty(exclusion.get("name")) and nonempty(exclusion.get("reason")), "unexplained test exclusion")
            require((check.startswith("native.gcoms.") and exclusion["name"] in EXCLUSIONS) or
                    (candidate.get("wire_profile") == "GC/2" and check.startswith("native.gchat.") and
                     exclusion["name"] == "bootstrap_gc2_tests::production_bootstrap_fresh_reopen_and_recovery"),
                    "test exclusion is not in the reviewed qualification policy")
        require(len({entry["name"] for entry in counts["excluded"]}) == len(counts["excluded"]), "duplicate test exclusions")
    if check in INSTALLERS:
        target = check.split(".", 2)[2]
        require(report.get("target") == target, "installer target mismatch")
        scenarios = report.get("scenarios", {})
        require(all(scenarios.get(name) == "passed" for name in INSTALL_SCENARIOS), "incomplete installer scenarios")
        required = {name for name, artifact in artifacts.items() if artifact.get("kind") == "installer" and artifact.get("project") == "gchat" and artifact.get("target") == target}
        require(required and required <= inputs.keys(), "installer checks must bind every target artifact")
        if target == "linux-x86_64":
            systems = report.get("systems", {})
            for system in ("ubuntu-24.04", "ubuntu-26.04"):
                require(all(systems.get(system, {}).get(name) == "passed" for name in INSTALL_SCENARIOS),
                        f"incomplete installer scenarios on {system}")
    if check.startswith("packages.") or check.startswith("published."):
        kind = "npm" if check.endswith("npm") else "installer" if check == "published.gchat" else "rust"
        required = {name for name, artifact in artifacts.items() if artifact.get("kind") == kind}
        require(required and required <= inputs.keys(), "package check omits archive inputs")
    if check.startswith("signing."):
        platform = check.split(".")[1]
        required = {name for name, artifact in artifacts.items()
                    if artifact.get("kind") != "signature" and
                    (platform == "manifest" or (artifact.get("kind") == "installer" and
                     artifact.get("target", "").startswith(platform)))}
        require(required and required <= inputs.keys(), "signing report omits signed artifact inputs")
        require(bool(report.get("evidence")), "signing verification needs retained evidence")
    if check == "stress.files-streaming":
        counts = report.get("tests", {})
        require(all(type(counts.get(key)) is int and counts[key] == expected
                    for key, expected in (("passed", 1), ("failed", 0), ("ignored", 0))) and
                counts.get("incomplete") == [],
                "streaming qualification must execute exactly one successful test")
        def streaming_command(command):
            if len(command) < 2 or Path(command[0]).name not in {"cargo", "cargo.exe"} or command[1] != "test" or "--" not in command:
                return False
            split = command.index("--")
            cargo, harness = command[2:split], command[split + 1:]
            pairs = set(zip(cargo, cargo[1:]))
            return (("-p", "gcoms-file-transfer") in pairs or
                    ("--package", "gcoms-file-transfer") in pairs) and (
                    ("--test", "swarm") in pairs and "--release" in cargo and
                    "--locked" in cargo and "--ignored" in harness and
                    "--exact" in harness and
                    "gib_import_resume_export_is_streaming" in cargo + harness)
        require(any(streaming_command(step["command"]) for step in report["steps"]),
                "streaming qualification must run the exact 1 GiB release test")
    if check in {"security.fuzz", "soak.application"}:
        measurements = report.get("measurements", {})
        measured = measurements.get("workload_seconds")
        require(type(measured) in (int, float) and math.isfinite(measured) and measured >= 86400, "24-hour workload not complete")
        require(duration >= measured, "workload exceeds recorded execution duration")
        if check == "soak.application":
            require(type(measurements.get("clients")) is int and measurements["clients"] >= 16, "soak needs 16 clients")
            require(type(measurements.get("channels")) is int and measurements["channels"] >= 4, "soak needs four channels")
            for invariant in ("durable_operations_accounted", "archives_intact", "resource_bounds_held", "fault_recovery_passed"):
                require(measurements.get(invariant) is True, f"soak invariant unproven: {invariant}")

    if candidate.get("wire_profile") == "GC/2":
        gc2.validate(check, report, candidate, base, artifacts, require, file_reference, read_json)


def required_checks(candidate, stage):
    required = {"candidate": CANDIDATE, "preflight": PREFLIGHT, "published": PUBLISHED}[stage]
    if candidate["wire_profile"] == "GC/2":
        required = required | gc2.CHECKS
    if candidate.get("channel") == "production":
        # Owner decision 2026-09-20: Linux production, bounded acceptance;
        # statistical/privacy matrices and timed campaigns are not release gates.
        deferred = {"security.fuzz", "soak.application", "privacy.gc2-client",
                    "fleet.gc2-files", "integration.gc2-turnover"}
        targets = set(candidate["targets"])
        required = {check for check in required if check not in deferred and
                    not any(check.endswith("." + target) for target in set(TARGETS) - targets)}
        required -= {"signing.windows", "signing.macos"}
    return required


def validate_publication(config, project, version):
    require(config.get("project") == project and config.get("version") == version, "publication identity/version mismatch")
    require(config.get("publication_status") == "approved_by_owner", "public publication remains deferred")
    policy = config.get("signing_policy", "publicly-trusted")
    require(policy in {"publicly-trusted", "self-signed-preview", "self-signed"}, "unknown signing policy")
    if policy == "self-signed-preview":
        require(config.get("channel") == "developer-preview", "self-signed distribution requires preview channel")
    for key in ("public_repository_url", "companion_url"):
        u = urlparse(config.get(key) or "")
        require(u.scheme == "https" and bool(u.hostname) and not u.username and not u.password and u.hostname not in {"localhost", "127.0.0.1", "::1"}, f"missing public {key}")
    for key in ("security_contact", "conduct_contact"):
        value = config.get(key)
        require(nonempty(value) and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) and not value.endswith(".invalid"), f"missing {key}")
    maintainers = config.get("maintainers")
    require(isinstance(maintainers, list) and maintainers and all(nonempty(x) for x in maintainers), "missing maintainer roster")
    if project == "gchat":
        for platform in ("windows", "macos", "linux"):
            identity = config.get("publisher_identities", {}).get(platform)
            require(isinstance(identity, dict) and nonempty(identity.get("name")) and nonempty(identity.get("certificate_fingerprint")), f"missing {platform} distribution signer")
            require(re.fullmatch(r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", identity["certificate_fingerprint"].replace(" ", "")), f"invalid {platform} distribution fingerprint")


def validate(candidate, base, stage="candidate", repositories=None, publication=None):
    errors = []
    try:
        require(stage in STAGES, "unknown qualification stage")
        require(isinstance(candidate, dict) and type(candidate.get("schema_version")) is int and
                (candidate["schema_version"], candidate.get("wire_profile")) in {(1, "GC/1"), (2, "GC/2")},
                "unsupported candidate schema/profile")
        require(candidate.get("channel") in {"developer-preview", "production"}, "unsupported release channel")
        if candidate["channel"] == "production":
            require(candidate.get("release_policy") == "production-minutes-v1", "production requires the explicit owner policy")
            require(candidate.get("privacy_qualified") is False and bool(candidate.get("privacy_improvements")), "production must disclose outstanding privacy improvements")
        if candidate["wire_profile"] == "GC/2":
            gc2.contract(candidate, base, require, file_reference, read_json)
        require(nonempty(candidate.get("version")), "missing candidate version")
        require(candidate.get("signing_policy", "publicly-trusted") in {"publicly-trusted", "self-signed-preview", "self-signed"}, "unsupported candidate signing policy")
        require(candidate.get("targets") == (["linux-x86_64"] if candidate["channel"] == "production" else list(TARGETS)), "candidate targets differ from release policy (preview requires Linux, Windows, and both macOS qualification targets)")
        validate_sources(candidate, base, repositories)
        artifacts = candidate.get("artifacts")
        require(isinstance(artifacts, dict) and artifacts, "no release artifacts recorded")
        for name, artifact in artifacts.items():
            require(nonempty(name) and isinstance(artifact, dict), "invalid artifact entry")
            require(artifact.get("project") in PROJECTS, f"invalid artifact project: {name}")
            file_reference(base, artifact)
        version = candidate["version"]
        for kind, names in {
            "rust": {f"gcoms-{name}-{version}.crate" for name in RUST_CRATES},
            "npm": {f"gcoms-rpc-{version}.tgz", f"gcoms-rpc-codegen-{version}.tgz"},
        }.items():
            actual = {name for name, artifact in artifacts.items() if artifact.get("project") == "gcoms" and artifact.get("kind") == kind}
            require(actual == names, f"{kind} artifact inventory differs from the 0.1 release package set")
        for target in candidate["targets"]:
            names = {name.lower() for name, artifact in artifacts.items() if artifact.get("kind") == "installer" and artifact.get("project") == "gchat" and artifact.get("target") == target}
            suffixes = (".deb", ".appimage") if target.startswith("linux") else (".dmg",) if target.startswith("macos") else (".exe",)
            require(all(any(name.endswith(suffix) for name in names) for suffix in suffixes), f"missing installer artifacts: {target}")
        require(isinstance(candidate.get("checks"), dict), "missing check inventory")
    except (EvidenceError, OSError, ValueError, TypeError) as error:
        return [str(error)]
    required = required_checks(candidate, stage)
    for check in sorted(required):
        try:
            reference = candidate["checks"].get(check)
            require(reference is not None, "no report")
            report = read_json(file_reference(base, reference))
            validate_report(check, report, candidate, base, artifacts)
        except (EvidenceError, OSError, ValueError, TypeError, AttributeError) as error:
            errors.append(f"{check}: {error}")
    if stage != "candidate":
        for project in PROJECTS:
            try:
                require(publication and project in publication, "missing publication configuration")
                validate_publication(publication[project], project, candidate["version"])
                require(candidate.get("signing_policy", "publicly-trusted") == publication[project].get("signing_policy", "publicly-trusted"), "candidate signing policy differs from publication")
                if project == "gchat" and publication[project].get("signing_policy") == "self-signed-preview":
                    for platform in ("windows", "macos", "linux"):
                        report = read_json(file_reference(base, candidate["checks"]["signing." + platform]))
                        measurements = report.get("measurements", {})
                        require(measurements.get("signing_policy") == "self-signed-preview", "signing report omits preview policy")
                        require(measurements.get("public_ca_trust") is False, "self-signed report must not claim public trust")
                        require(measurements.get("certificate_fingerprint") == publication[project]["publisher_identities"][platform]["certificate_fingerprint"], "signing report uses a different publisher key")
                        if platform == "macos":
                            require(measurements.get("apple_notarization") is False, "self-signed macOS report must declare absent notarization")
            except (EvidenceError, OSError, KeyError, ValueError, TypeError, AttributeError) as error:
                errors.append(f"{project}: {error}")
    return errors
