#!/usr/bin/env python3
"""Validate GChat against this GComs source without changing either lockfile.

Only the two supplied repositories and an ignored build directory are used.
Published manifests keep registry dependencies; source overrides live in scratch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

from source_snapshot import source_files, snapshot, unchanged


ROOT = Path(__file__).resolve().parents[1]


def patches(root):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    lines = ["[patch.crates-io]"]
    packages = []
    for member in workspace["members"]:
        for directory in sorted(root.glob(member)):
            if not directory.resolve().is_relative_to(root):
                raise ValueError("workspace member escapes GComs")
            package = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
            name = package["name"]
            if (name == "gcoms" or name.startswith("gcoms-")):
                packages.append(name)
                lines.append(f"{json.dumps(name)} = {{ path = {json.dumps(str(directory))} }}")
    if not {"gcoms-node", "gcoms-sdk", "gcoms-rpc"}.issubset(packages):
        raise ValueError("expected the separated GComs workspace")
    if len(packages) != len(set(packages)):
        raise ValueError("duplicate GComs workspace package")
    return "\n".join(lines) + "\n", sorted(packages)


def write_report(target, action, run_id, report):
    directory = target / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{action}-{run_id}.json"
    encoded = json.dumps(report, indent=2) + "\n"
    with path.open("x") as output:
        output.write(encoded)
    (target / f"{action}-summary.json").write_text(encoded)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gchat", type=Path, required=True)
    parser.add_argument("--action", choices=("check", "test", "clippy"), default="test")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/gchat-source-check")
    args = parser.parse_args()
    source = args.gchat.resolve()
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    if "crates/chat-api" not in manifest.get("workspace", {}).get("members", []):
        parser.error("--gchat must name the standalone GChat repository")
    target = args.target_dir.resolve()
    target.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("CARGO_BUILD_JOBS", "2")
    environment["CARGO_TARGET_DIR"] = str((target / "build").resolve())
    # Keep socket-test paths short, independently of deeply nested worktrees.
    # Test scratch follows the workstation SSD policy: an explicit TMPDIR wins,
    # then the approved short SSD directory; /tmp is RAM/swap and repeatedly
    # filled under the full GChat suite.
    test_root = os.environ.get("TMPDIR") or os.path.join(
        os.path.expanduser("~"), ".cache", "opencode", "tmp"
    )
    os.makedirs(test_root, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gc-chat-", dir=target) as scratch, \
            tempfile.TemporaryDirectory(prefix="gc2-", dir=test_root if os.name != "nt" else None) as test_tmp:
        environment["TMPDIR"] = test_tmp
        environment["TEMP"] = test_tmp
        environment["TMP"] = test_tmp
        scratch = Path(scratch)
        checkout = scratch / "gchat"
        checkout.mkdir()
        sources = {"gcoms": ROOT, "gchat": source}
        evidence = {}
        snapshots = {}
        for name, directory in sources.items():
            revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=directory, text=True
            ).strip()
            snapshots[name] = snapshot(directory, scratch / name)
            evidence[name] = {
                "revision": revision,
                "snapshot_sha256": hashlib.sha256(
                    json.dumps(snapshots[name], sort_keys=True).encode()
                ).hexdigest(),
                "files_sha256": snapshots[name],
            }
        config, packages = patches(scratch / "gcoms")
        patch = scratch / "source.toml"
        patch.write_text(config)
        # External Cargo subcommands (including Clippy) need these options after
        # the subcommand so they reach its own Cargo invocation.
        command = ["cargo", args.action, "--config", str(patch),
                   "--workspace", "--all-features"]
        if args.offline:
            command.append("--offline")
        if args.action == "test":
            command.extend(["--", "--test-threads=1"])
        elif args.action == "clippy":
            command.extend(["--all-targets", "--", "-D", "warnings"])
        print(f"Checking a GChat snapshot against {len(packages)} local GComs packages", flush=True)
        result = subprocess.run(command, cwd=checkout, env=environment, check=False)
        for name, directory in sources.items():
            evidence[name]["unchanged_during_check"] = unchanged(directory, snapshots[name])
        report = {"schema": 1, "action": args.action, "exit_code": result.returncode,
                  "sources": evidence, "packages": packages,
                  "passed": result.returncode == 0 and all(
                      item["unchanged_during_check"] for item in evidence.values()),
                  "scope": "local source integration; no deployment or privacy qualification"}
        report_path = write_report(target, args.action, scratch.name, report)
        print(f"Integration report: {report_path}", flush=True)
        if not all(item["unchanged_during_check"] for item in evidence.values()):
            raise SystemExit("Source changed during validation; retain this result and validate the current source again")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
