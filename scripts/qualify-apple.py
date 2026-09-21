#!/usr/bin/env python3
"""Run the native Swift consumer and measure installed simulator/sample bytes."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
from mobile_fixture import relay

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def capture(args):
    return subprocess.check_output(args, text=True).strip()


def files(path):
    return {str(p.relative_to(path)): {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(path.rglob("*")) if p.is_file() and not p.is_symlink()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=["client", "relay"], required=True)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    with relay() if args.test and args.role == "client" else contextlib.nullcontext(None) as host:
        qualify(args, host)


def qualify(args, host):
    native = args.native_root.resolve()
    summary = json.loads((native / "summary.json").read_text())
    if bool(summary["fixtures"]) != args.test:
        raise RuntimeError("Fixture packages are for tests; size qualification requires production packages")
    push = summary.get("push", False)
    package = native / "packages" / (("GComsClient" if args.role == "client" else "GComsRelay") + ("Push" if push else ""))
    evidence = ROOT / "target/apple-evidence" / args.role / (("push-" if push else "") + ("tests" if args.test else "sizes"))
    evidence.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GCOMS_PACKAGE_PATH=str(package))
    spec = (ROOT / "mobile/apple/project.yml").read_text()
    spec = spec.replace("sources: [Sample]", "sources: [" + str(ROOT / "mobile/apple/Sample") + "]")
    spec = spec.replace("sources: [Tests/GComsTests]", "sources: [" + str(ROOT / "mobile/apple/Tests/GComsTests") + "]")
    if push:
        spec = spec.replace("product: GComs", "product: GComsPush")
        spec = spec.replace("GCOMS_ENABLED", "GCOMS_ENABLED GCOMS_PUSH")
    if host:
        spec = spec.replace("targets: [PreviewTests]",
            "targets: [PreviewTests]\n      environmentVariables:\n        GCOMS_RELAY: " +
            json.dumps(json.dumps(host["relay"], separators=(",", ":"))))
    (evidence / "project.yml").write_text(spec)
    run(["xcodegen", "generate", "--spec", evidence / "project.yml",
         "--project", evidence], env=env)
    project = evidence / "GComsPreview.xcodeproj"
    runtimes = json.loads(capture(["xcrun", "simctl", "list", "runtimes", "--json"]))["runtimes"]
    runtime = next(r["identifier"] for r in reversed(runtimes)
        if r["isAvailable"] and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS"))
    types = json.loads(capture(["xcrun", "simctl", "list", "devicetypes", "--json"]))["devicetypes"]
    device_type = next(d["identifier"] for d in reversed(types) if d["name"].startswith("iPhone"))
    device = capture(["xcrun", "simctl", "create", "GComs qualification", device_type, runtime])
    report = {"schema": 1, "role": args.role, "push": push, "revision": summary["revision"],
        "xcode": capture(["xcodebuild", "-version"]), "runtime": runtime, "apps": {}}
    try:
        run(["xcrun", "simctl", "boot", device])
        run(["xcrun", "simctl", "bootstatus", device, "-b"])
        if args.test:
            run(["xcodebuild", "-project", project, "-scheme", "Preview",
                "-destination", "platform=iOS Simulator,id=" + device,
                "-derivedDataPath", evidence / "derived", "-resultBundlePath", evidence / "tests.xcresult",
                "test"], env=env)
        else:
            for scheme, bundle in [("Baseline", "boo.gcoms.preview.baseline"), ("Preview", "boo.gcoms.preview.sdk")]:
                derived = evidence / "derived"
                run(["xcodebuild", "-project", project, "-scheme", scheme,
                    "-configuration", "Release", "-destination", "platform=iOS Simulator,id=" + device,
                    "-derivedDataPath", derived, "build"], env=env)
                app = derived / "Build/Products/Release-iphonesimulator" / (scheme + ".app")
                run(["xcrun", "simctl", "install", device, app])
                installed = Path(capture(["xcrun", "simctl", "get_app_container", device, bundle, "app"]))
                inventory = files(installed)
                report["apps"][scheme] = {"installed_bundle_bytes": sum(f["bytes"] for f in inventory.values()), "files": inventory}
                run(["xcodebuild", "-project", project, "-scheme", scheme,
                    "-configuration", "Release", "-destination", "generic/platform=iOS",
                    "-derivedDataPath", derived, "build"], env=env)
                device_app = derived / "Build/Products/Release-iphoneos" / (scheme + ".app")
                device_inventory = files(device_app)
                report["apps"][scheme]["unsigned_device_bundle_bytes"] = sum(f["bytes"] for f in device_inventory.values())
                report["apps"][scheme]["device_files"] = device_inventory
            report["delta"] = {field: report["apps"]["Preview"][field] - report["apps"]["Baseline"][field]
                for field in ("installed_bundle_bytes", "unsigned_device_bundle_bytes")}
            if args.baseline:
                previous = json.loads(args.baseline.read_text())
                if any(previous.get(f) != report[f] for f in ("role", "push", "xcode", "runtime")):
                    raise RuntimeError("App baseline toolchain differs")
                for field, value in report["delta"].items():
                    if value > previous["delta"][field] * 1.05:
                        raise RuntimeError("Linked application delta exceeds the 5 percent gate")
        (evidence / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        subprocess.run(["xcrun", "simctl", "shutdown", device], check=False)
        subprocess.run(["xcrun", "simctl", "delete", device], check=False)


if __name__ == "__main__":
    main()
