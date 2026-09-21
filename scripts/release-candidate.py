#!/usr/bin/env python3
"""Assemble source/artifact inputs and record bounded checks. Never publishes."""
import argparse
from contextlib import contextmanager
import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import time
import tomllib
import uuid

import gc2_release_evidence as gc2

from release_evidence import (
    EvidenceError, PROJECTS, TARGETS, PUBLISHED, EXCLUSIONS, bindings, digest, file_reference,
    read_json, require, source_identity,
)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


@contextmanager
def manifest_lock(path):
    # Keep the lock inode: unlinking it lets a third writer bypass a waiter.
    with path.with_suffix(".lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            lock.seek(0, os.SEEK_END)
            if not lock.tell():
                lock.write(b"\0"); lock.flush()
            deadline = time.monotonic() + 30
            while True:
                lock.seek(0)
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise EvidenceError("candidate manifest is busy")
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def reference(base, path):
    return {"path": path.relative_to(base).as_posix(), "sha256": digest(path)}


def init(args):
    roots = {project: getattr(args, project).resolve() for project in PROJECTS}
    sources = {project: source_identity(path) for project, path in roots.items()}
    versions = {tomllib.loads((path / "Cargo.toml").read_text())["workspace"]["package"]["version"] for path in roots.values()}
    require(len(versions) == 1, "candidate versions differ")
    policies = set()
    configurations = {}
    for root in roots.values():
        publication = root / "release/publication.json"
        config = read_json(publication) if publication.is_file() else {}
        configurations[root] = config
        policies.add(config.get("signing_policy", "publicly-trusted"))
    require(len(policies) == 1 and policies <= {"publicly-trusted", "self-signed-preview", "self-signed"}, "source signing policies differ or are unknown")
    channels = {config.get("channel", "developer-preview") for config in configurations.values()}
    require(len(channels) == 1 and channels <= {"developer-preview", "production"}, "source release channels differ or are unknown")
    channel = channels.pop()
    require("self-signed-preview" not in policies or channel == "developer-preview", "preview signing requires the preview channel")
    targets = args.target or (configurations[roots["gchat"]].get("qualification_targets", ["linux-x86_64"])
                              if channel == "production" else list(TARGETS))
    require(isinstance(targets, list) and bool(targets) and len(set(targets)) == len(targets)
            and all(target in TARGETS for target in targets), "invalid qualification targets")
    require(channel == "production" or targets == list(TARGETS), "preview requires all qualification targets")
    improvements = []
    if channel == "production":
        for config in configurations.values():
            policy = config.get("release_policy", {})
            require(policy.get("name") == "production-minutes-v1" and policy.get("privacy_qualified") is False
                    and isinstance(policy.get("privacy_improvements"), str) and policy["privacy_improvements"],
                    "production requires the explicit policy and privacy disclosure")
            if policy["privacy_improvements"] not in improvements:
                improvements.append(policy["privacy_improvements"])
    require((args.wire_profile == "GC/2") == (args.traffic_config is not None),
            "GC/2 requires --traffic-config; GC/1 does not accept it")
    if args.traffic_config:
        traffic_config = read_json(args.traffic_config)
        require(isinstance(traffic_config, dict) and type(traffic_config.get("profile_id")) is int and
                traffic_config["profile_id"] == 22, "traffic configuration must select profile 22")
    traffic_bytes = args.traffic_config.read_bytes() if args.traffic_config else None
    require(traffic_bytes is None or bool(traffic_bytes), "empty traffic configuration")
    base = args.output.resolve()
    base.mkdir(parents=True, exist_ok=False)
    (base / "sources").mkdir()
    for project, root in roots.items():
        archive = base / "sources" / f"{project}.tar"
        subprocess.run(["git", "archive", "--format=tar", "--output", str(archive), sources[project]["commit"]], cwd=root, check=True)
        require(source_identity(root) == sources[project], "source changed while creating candidate")
        sources[project]["archive"] = reference(base, archive)
    candidate = {"schema_version": 1, "version": versions.pop(), "channel": channel,
                 "wire_profile": "GC/1", "signing_policy": policies.pop(), "created_at": now(), "targets": targets,
                 "sources": sources, "artifacts": {}, "checks": {}, "attempts": []}
    if channel == "production":
        candidate.update(release_policy="production-minutes-v1", privacy_qualified=False,
                         privacy_improvements=improvements)
    if args.wire_profile == "GC/2":
        traffic = base / "sources" / "traffic-config.json"
        traffic.write_bytes(traffic_bytes)
        candidate.update(schema_version=2, wire_profile="GC/2", gc2={
            "profile_id": 22, "privacy_contract": "gchat-file-profile-22",
            "new_profile_protocol": "gc2", "existing_profile_migration": "explicit",
            "traffic_config": reference(base, traffic)})
    write_json(base / "candidate.json", candidate)
    print(base / "candidate.json")


def add_artifact(args):
    manifest = args.candidate.resolve(); base = manifest.parent
    with manifest_lock(manifest):
        candidate = read_json(manifest)
        source = args.file.resolve()
        require(source.is_file(), "artifact is missing")
        name = args.name or source.name
        require(name not in candidate["artifacts"], "artifact already exists; use a new candidate to replace inputs")
        sha = digest(source)
        destination = base / "artifacts" / (sha[:16] + "-" + source.name)
        destination.parent.mkdir(exist_ok=True)
        if not destination.exists():
            with source.open("rb") as incoming, destination.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
        require(digest(destination) == sha, "artifact changed during copy")
        candidate["artifacts"][name] = {**reference(base, destination), "project": args.project,
                                        "kind": args.kind, "target": args.target}
        write_json(manifest, candidate)
        print(name, sha)


def environment():
    system, machine = platform.system(), platform.machine().lower()
    os_name = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(system, system.lower())
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    rust = subprocess.run(["rustc", "-vV"], text=True, capture_output=True, check=True).stdout
    host = re.search(r"^host: (.+)$", rust, re.M)
    return {"native_target": os_name + "-" + arch, "platform": platform.platform(),
            "rust_host": host.group(1) if host else "unknown", "rustc": rust.strip(),
            "python": platform.python_version()}


def stop(process):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()


def record(args):
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    require(command and args.timeout > 0, "command and positive timeout required")
    require(not args.check.startswith("review."), "reviews need an identified reviewer and separate attestation")
    manifest = args.candidate.resolve(); base = manifest.parent
    candidate = read_json(manifest)
    roots = {project: getattr(args, project).resolve() for project in PROJECTS}
    source_bindings = bindings(candidate)
    require({name: source_identity(path) for name, path in roots.items()} == source_bindings, "candidate differs from clean checkouts")
    run_id = args.check + "-" + uuid.uuid4().hex
    (base / "reports").mkdir(exist_ok=True); (base / "logs").mkdir(exist_ok=True)
    log = base / "logs" / (run_id + ".log")
    started_at = now(); started = time.monotonic()
    status, code = "failed", None
    env = environment()
    with log.open("xb") as output:
        process = None
        try:
            process = subprocess.Popen(command, cwd=roots[args.project], stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            print(f"Recording {args.check}: PID {process.pid}; log {log}", flush=True)
            code = process.wait(timeout=args.timeout)
            status = "passed" if code == 0 else "failed"
        except subprocess.TimeoutExpired:
            stop(process); status = "timeout"; code = process.returncode
        except KeyboardInterrupt:
            if process is not None:
                stop(process); code = process.returncode
            status = "interrupted"
        except OSError as error:
            output.write(("Process launch failed: " + str(error) + "\n").encode())
            status = "launch_failed"
    try:
        unchanged = {name: source_identity(path) for name, path in roots.items()} == source_bindings
    except EvidenceError:
        unchanged = False
    if not unchanged:
        status = "source_changed"
    # Workloads write measured outcomes during execution. Read them only after
    # the process exits; a pre-run prediction is not qualification evidence.
    facts = {}
    facts_error = None
    if args.facts:
        try:
            measured = read_json(args.facts)
            require(isinstance(measured, dict) and set(measured) <= {"measurements", "scenarios", "systems", "evidence"}, "facts cannot override runner results")
            for entry in measured.get("evidence", []):
                file_reference(base, entry)
            facts = measured
        except (EvidenceError, OSError, ValueError, TypeError) as error:
            facts_error = str(error)
            status = "invalid_facts"
    output = log.read_text(errors="replace")
    counts = re.findall(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", output)
    excluded = [{"name": name, "reason": reason or EXCLUSIONS.get(name, "")}
                for name, reason in re.findall(r"^test (.+?) \.\.\. ignored(?:, (.*))?$", output, re.M)]
    report = {"schema_version": 1, "check": args.check, "sources": source_bindings,
              "status": status, "source_unchanged": unchanged, "started_at": started_at,
              "finished_at": now(), "duration_seconds": time.monotonic() - started,
              "exit_code": code, "target": env["native_target"], "environment": env,
              "steps": [{"command": command, "status": status, "exit_code": code, "log": reference(base, log)}],
              "artifacts": {name: value["sha256"] for name, value in candidate["artifacts"].items()},
              "tests": {"passed": sum(int(row[0]) for row in counts), "failed": sum(int(row[1]) for row in counts),
                        "ignored": sum(int(row[2]) for row in counts), "incomplete": [] if status == "passed" else [status], "excluded": excluded},
              **facts}
    if candidate.get("wire_profile") == "GC/2":
        report["gc2"] = candidate["gc2"]
    if facts_error:
        report["facts_error"] = facts_error
    report_path = base / "reports" / (run_id + ".json")
    write_json(report_path, report)
    with manifest_lock(manifest):
        latest = read_json(manifest)
        require(bindings(latest) == source_bindings and latest.get("gc2") == candidate.get("gc2") and
                latest.get("wire_profile") == candidate.get("wire_profile"),
                "candidate source/configuration inputs changed during execution")
        latest["checks"][args.check] = reference(base, report_path)
        latest["attempts"].append({"check": args.check, **reference(base, report_path)})
        write_json(manifest, latest)
    print(json.dumps({"check": args.check, "status": status, "report": str(report_path)}))
    return 0 if status == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("init")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--target", choices=TARGETS, action="append", help="production qualification target; repeat for several platforms")
    create.add_argument("--wire-profile", choices=("GC/1", "GC/2"), default="GC/1")
    create.add_argument("--traffic-config", type=Path, help="frozen profile-22 traffic configuration (GC/2 only)")
    for project in PROJECTS:
        create.add_argument("--" + project, type=Path, required=True)
    create.set_defaults(run=init)
    artifact = commands.add_parser("artifact")
    artifact.add_argument("--candidate", type=Path, required=True)
    artifact.add_argument("--file", type=Path, required=True)
    artifact.add_argument("--name")
    artifact.add_argument("--project", choices=PROJECTS, required=True)
    artifact.add_argument("--kind", choices=("rust", "npm", "installer", "inventory", "provenance", "signature", "executable"), required=True)
    artifact.add_argument("--target", choices=TARGETS)
    artifact.set_defaults(run=add_artifact)
    run = commands.add_parser("record")
    run.add_argument("--candidate", type=Path, required=True)
    run.add_argument("--check", choices=sorted(PUBLISHED | gc2.CHECKS), required=True)
    run.add_argument("--project", choices=PROJECTS, required=True)
    run.add_argument("--timeout", type=float, required=True)
    run.add_argument("--facts", type=Path)
    for project in PROJECTS:
        run.add_argument("--" + project, type=Path, required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(run=record)
    args = parser.parse_args()
    try:
        return args.run(args) or 0
    except (EvidenceError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Candidate operation failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
