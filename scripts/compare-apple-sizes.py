#!/usr/bin/env python3
"""Compare linked app sizes using retained, already compiled Apple native profiles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_mobile", ROOT / "scripts/build-mobile.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Downloaded native summary's directory")
    parser.add_argument("--role", choices=["client", "relay"], required=True)
    parser.add_argument("--push", action="store_true")
    parser.add_argument("--profiles", nargs="+", choices=["3", "s", "z"], default=["3", "s", "z"])
    parser.add_argument("--output", type=Path, default=ROOT / "target/apple-profile-comparison")
    args = parser.parse_args()
    source = args.input.resolve()
    native = json.loads((source / "summary.json").read_text())
    if native["fixtures"] or not native["lto"] or native.get("crate_type") != "staticlib":
        raise RuntimeError("Comparison requires production native archives built with LTO")
    if native["push"] != args.push:
        raise RuntimeError("Selected push distribution differs from the native input")
    for name, digest in native["source_sha256"].items():
        if name.startswith("mobile/apple/Sources/") or name in ("mobile/apple/project.yml", "mobile/native/include/gcoms_mobile.h"):
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Consumer source differs from the native qualification: " + name)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    targets = [("aarch64-apple-ios", "device"), ("aarch64-apple-ios-sim", "sim-arm64"), ("x86_64-apple-ios", "sim-x86_64")]
    report = {"schema": 1, "role": args.role, "push": native["push"], "native_revision": native["revision"],
        "qualification_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "native_report_sha256": hashlib.sha256((source / "summary.json").read_bytes()).hexdigest(), "profiles": {}}
    for profile in args.profiles:
        package_root = output / ("opt-" + profile) / "native"
        selected = []
        for target, label in targets:
            item, = [a for a in native["artifacts"] if a["role"] == args.role and a["target"] == target and a["opt_level"] == profile]
            archive = (source / item["artifact"]).resolve()
            if not archive.is_relative_to(source) or build.digest(archive) != item["sha256"] or archive.stat().st_size != item["bytes"]:
                raise RuntimeError("Retained native archive differs from its measurement")
            destination = package_root / "apple" / args.role / label / "libgcoms_mobile.a"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archive, destination)
            selected.append(item)
        (package_root / "summary.json").write_text(json.dumps({**native, "artifacts": selected}, indent=2) + "\n")
        build.package_apple(package_root, args.role, native["push"], targets)
        apps = output / ("opt-" + profile) / "apps"
        subprocess.run([sys.executable, str(ROOT / "scripts/qualify-apple.py"), "--role", args.role,
            "--native-root", str(package_root), "--output", str(apps)], check=True)
        app_path, = apps.rglob("summary.json")
        app = json.loads(app_path.read_text())
        report["profiles"][profile] = {k: v for k, v in app.items() if k != "apps"}
        report["profiles"][profile]["app_report_sha256"] = build.digest(app_path)
        report["profiles"][profile]["native_archives"] = {a["target"]: {k: a[k] for k in ("bytes", "sha256")} for a in selected}
        (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    for field in ("xcode", "runtime", "simulator_arch", "deployment_postprocessing"):
        if len({p[field] for p in report["profiles"].values()}) != 1:
            raise RuntimeError("Comparison environments differ: " + field)
    report["smallest_linked_profiles"] = {field: min(report["profiles"], key=lambda profile: report["profiles"][profile]["delta"][field])
        for field in ("installed_bundle_bytes", "unsigned_device_bundle_bytes")}
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["smallest_linked_profiles"]))


if __name__ == "__main__":
    main()
