#!/usr/bin/env python3
"""Validate a local candidate, public preflight, or published release evidence."""
import argparse
import json
from pathlib import Path
import sys

from release_evidence import EvidenceError, STAGES, read_json, validate


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--companion", type=Path, required=True)
    parser.add_argument("--stage", choices=STAGES, default="preflight")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        config = read_json(root / "release/publication.json")
        other = "gchat" if config["project"] == "gcoms" else "gcoms"
        repositories = {config["project"]: root, other: args.companion.resolve()}
        candidate = read_json(args.candidate)
        publication = {name: read_json(path / "release/publication.json") for name, path in repositories.items()}
        errors = validate(candidate, args.candidate.resolve().parent, args.stage, repositories, publication)
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as error:
        errors = [str(error)]
    result = {"stage": args.stage, "status": "blocked" if errors else "passed", "errors": errors, "published": False}
    if args.json:
        print(json.dumps(result, indent=2))
    elif errors:
        print(f"{args.stage} blocked:\n" + "\n".join("- " + error for error in errors), file=sys.stderr)
    else:
        print(f"{args.stage} evidence passed; this command publishes nothing.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
