#!/usr/bin/env python3
"""Verify historical research provenance without accessing the source repository."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "docs/research/IMPORT.json").read_text())
for entry in manifest["files"]:
    path = root / entry["path"]
    if not path.resolve().is_relative_to(root):
        raise SystemExit("research path escapes repository")
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise SystemExit(f"historical research changed: {entry['path']}")
print(f"{len(manifest['files'])} research files match recorded import/adaptation hashes; original source {manifest['source_revision']}")
