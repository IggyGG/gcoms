#!/usr/bin/env python3
"""Stage only reviewed gateway files, never the whole repository or credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def stage(output):
    manifest = json.loads((HERE / "runtime-sources.json").read_text())
    sources = {"mobile/push/gateway/" + name: HERE.parent / "gateway" / name for name in manifest["files"]}
    for name, digest in manifest["files"].items():
        if hashlib.sha256((HERE.parent / "gateway" / name).read_bytes()).hexdigest() != digest:
            raise ValueError("gateway runtime differs from frozen input")
    for name in ("Dockerfile", "requirements.lock", "launcher.py", "health.py", "prepare.py", "runtime-sources.json"):
        sources["mobile/push/deploy/" + name] = HERE / name
    output = Path(output)
    output.mkdir()  # Existing output is never silently mixed with a new build.
    hashes = {}
    for relative, source in sources.items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        hashes[relative] = hashlib.sha256(destination.read_bytes()).hexdigest()
    (output / "context-manifest.json").write_text(json.dumps({"runtime_commit": manifest["commit"], "files": hashes}, indent=2) + "\n")
    return hashes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    print(json.dumps(stage(parser.parse_args().output), indent=2))
