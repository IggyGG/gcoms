"""Snapshot repository inputs while preserving concurrent source work."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess


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


def snapshot(source, destination, *, keep_vcs=False):
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    names = source_files(source)
    if keep_vcs:
        # Preserve Cargo's real .cargo_vcs_info.json provenance without using a
        # shared worktree or writing to the source checkout. Overlay dirty inputs
        # only in development mode; release callers require a clean source.
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
        subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(source), str(destination)], check=True)
        subprocess.run(["git", "checkout", "--quiet", "--detach", revision], cwd=destination, check=True)
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=destination).decode().split("\0")
        for name in set(tracked) - set(names) - {""}:
            (destination / name).unlink()
    hashes = {}
    for name in names:
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

