#!/usr/bin/env python3
"""Build AARs and measure ABI-specific release sample and installed emulator APKs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "mobile/android"


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def capture(args):
    return subprocess.check_output([str(a) for a in args], text=True).strip()


def archive(path):
    with zipfile.ZipFile(path) as content:
        entries = content.infolist()
        return {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "uncompressed_bytes": sum(i.file_size for i in entries),
            "native_bytes": sum(i.file_size for i in entries if i.filename.endswith(".so")),
            "dex_bytes": sum(i.file_size for i in entries if i.filename.endswith(".dex"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=["client", "relay"], required=True)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--serial", required=True, help="Qualification emulator serial")
    parser.add_argument("--gradle", default=str(PROJECT / "gradlew"))
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    native = args.native_root.resolve()
    summary = json.loads((native / "summary.json").read_text())
    if summary["fixtures"]:
        raise RuntimeError("Fixture packages cannot establish release sizes")
    push = summary.get("push", False)
    evidence = ROOT / "target/android-evidence" / args.role / ("push" if push else "base")
    evidence.mkdir(parents=True, exist_ok=True)
    title = args.role.title()
    command = [args.gradle, "-p", PROJECT, "-PgcomsNativeRoot=" + str(native / "android")]
    if push:
        command += ["-PgcomsPush=true"]
    run(command + [":sdk:assemble" + title + "Release", ":sample:assemble" + title + "Release",
        ":sample:assembleBaselineRelease", "--no-daemon"])
    adb = Path(os.environ["ANDROID_HOME"]) / "platform-tools/adb"
    adb_args = [adb, "-s", args.serial]
    page_size = int(capture(adb_args + ["shell", "getconf", "PAGE_SIZE"]))
    if page_size != 16384:
        raise RuntimeError("Qualification requires the 16 KiB emulator")
    report = {"schema": 1, "role": args.role, "push": push, "revision": summary["revision"],
        "ndk": summary["ndk"], "rustc": summary["rustc"], "page_size": page_size,
        "android": capture(adb_args + ["shell", "getprop", "ro.build.fingerprint"]), "apps": {}}
    import shutil
    aar = PROJECT / "sdk/build/outputs/aar" / ("sdk-" + args.role + "-release.aar")
    shutil.copy2(aar, evidence / aar.name)
    report["aar"] = archive(aar)
    for role in ("baseline", args.role):
        report["apps"][role] = {}
        for abi in ("arm64-v8a", "x86_64"):
            apk = PROJECT / "sample/build/outputs/apk" / role / "release" / ("sample-" + role + "-" + abi + "-release.apk")
            record = archive(apk)
            shutil.copy2(apk, evidence / apk.name)
            if abi == "x86_64":
                package = "boo.gcoms.sample." + role
                subprocess.run([str(a) for a in adb_args + ["uninstall", package]], check=False, capture_output=True)
                run(adb_args + ["install", "--abi", abi, apk])
                paths = capture(adb_args + ["shell", "pm", "path", package]).splitlines()
                record["installed_apk_bytes"] = sum(int(capture(adb_args + ["shell", "stat", "-c", "%s", p.removeprefix("package:")])) for p in paths)
                # AGP stores page-aligned native libraries in the APK for direct loading.
                run(adb_args + ["shell", "am", "start", "-W", "-n", package + "/boo.gcoms.sample.MainActivity"])
                run(adb_args + ["uninstall", package])
            report["apps"][role][abi] = record
    report["delta"] = {abi: {field: value - report["apps"]["baseline"][abi][field]
        for field, value in item.items() if isinstance(value, int)}
        for abi, item in report["apps"][args.role].items()}
    if args.baseline:
        previous = json.loads(args.baseline.read_text())
        for field in ("role", "push", "ndk", "rustc", "android"):
            if previous[field] != report[field]:
                raise RuntimeError("App baseline toolchain differs: " + field)
        for abi, item in report["delta"].items():
            if item["bytes"] > previous["delta"][abi]["bytes"] * 1.05:
                raise RuntimeError("Sample APK delta exceeds the 5 percent gate")
    (evidence / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["delta"], indent=2))


if __name__ == "__main__":
    main()
