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


ROOT = Path(__file__).resolve().parents[1]


def source_files(root):
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
    )
    files = []
    for name in sorted(set(os.fsdecode(raw).split("\0")) - {""}):
        path = root / name
        if not path.exists() and not path.is_symlink():
            continue  # Preserve intentional worktree deletions in the snapshot.
        if not path.resolve().is_relative_to(root):
            raise ValueError(f"source escapes repository: {name}")
        if not path.is_file():
            raise ValueError(f"unsupported source entry: {name}")
        files.append(name)
    if "Cargo.toml" not in files or "Cargo.lock" not in files:
        raise ValueError("source requires Cargo.toml and Cargo.lock")
    return files


def snapshot(source, destination):
    hashes = {}
    for name in source_files(source):
        data = (source / name).read_bytes()
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        shutil.copymode(source / name, target)
        hashes[name] = hashlib.sha256(data).hexdigest()
    return hashes


def unchanged(source, hashes):
    try:
        return source_files(source) == list(hashes) and all(
            hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
            for name, digest in hashes.items()
        )
    except (OSError, ValueError):
        return False


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
            if name.startswith("gcoms-"):
                packages.append(name)
                lines.append(f"{json.dumps(name)} = {{ path = {json.dumps(str(directory))} }}")
    if not {"gcoms-node", "gcoms-sdk", "gcoms-rpc"}.issubset(packages):
        raise ValueError("expected the separated GComs workspace")
    if len(packages) != len(set(packages)):
        raise ValueError("duplicate GComs workspace package")
    return "\n".join(lines) + "\n", sorted(packages)


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
    environment["CARGO_TARGET_DIR"] = str(target / "build")
    # Keep socket-test paths short, independently of deeply nested worktrees.
    with tempfile.TemporaryDirectory(prefix="gc-chat-", dir=target) as scratch, \
            tempfile.TemporaryDirectory(prefix="gc2-", dir="/tmp" if os.name != "nt" else None) as test_tmp:
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
            }
        config, packages = patches(scratch / "gcoms")
        patch = scratch / "source.toml"
        patch.write_text(config)
        command = ["cargo", "--config", str(patch), args.action,
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
                  "scope": "local source integration; no deployment or privacy qualification"}
        (target / f"{args.action}-summary.json").write_text(json.dumps(report, indent=2) + "\n")
        if not all(item["unchanged_during_check"] for item in evidence.values()):
            raise SystemExit("Source changed during validation; retain this result and validate the current source again")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
