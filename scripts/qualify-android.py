#!/usr/bin/env python3
"""Build AARs and measure ABI-specific release sample and installed emulator APKs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
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
        native_entries = []
        if path.suffix == ".apk":
            with path.open("rb") as raw:
                for item in entries:
                    if not item.filename.endswith(".so"):
                        continue
                    raw.seek(item.header_offset + 26)
                    name_bytes, extra_bytes = struct.unpack("<HH", raw.read(4))
                    offset = item.header_offset + 30 + name_bytes + extra_bytes
                    if item.compress_type != zipfile.ZIP_STORED or offset % 16384:
                        raise RuntimeError("Release APK native library is not uncompressed and 16 KiB aligned: " + item.filename)
                    native_entries.append({"path": item.filename, "offset": offset,
                        "sha256": hashlib.sha256(content.read(item)).hexdigest()})
        return {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "uncompressed_bytes": sum(i.file_size for i in entries),
            "native_bytes": sum(i.file_size for i in entries if i.filename.endswith(".so")),
            "dex_bytes": sum(i.file_size for i in entries if i.filename.endswith(".dex")),
            "native_entries": native_entries}


def packaging_sources():
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others",
        "--exclude-standard", "--", "mobile/android", "scripts/qualify-android.py"], cwd=ROOT).decode().split("\0")
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in sorted(set(names)) if name and (ROOT / name).is_file()}


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
    sources = packaging_sources()
    if summary["fixtures"]:
        raise RuntimeError("Fixture packages cannot establish release sizes")
    push = summary.get("push", False)
    evidence = ROOT / "target/android-evidence" / args.role / ("push" if push else "base")
    evidence.mkdir(parents=True, exist_ok=True)
    title = args.role.title()
    command = [args.gradle, "-p", PROJECT, "-PgcomsNativeRoot=" + str(native / "android"),
        "-PgcomsPublishRole=" + args.role]
    if push:
        command += ["-PgcomsPush=true"]
    if push:
        command += [":push:assemble" + title + "Release",
            ":push:generatePomFileFor" + title + "Publication",
            ":push:generateMetadataFileFor" + title + "Publication"]
    run(command + [":sdk:assemble" + title + "Release", ":sample:assemble" + title + "Release",
        ":sdk:generatePomFileFor" + title + "Publication",
        ":sdk:generateMetadataFileFor" + title + "Publication",
        ":sample:assembleBaselineRelease", "--no-daemon"])
    adb = Path(os.environ["ANDROID_HOME"]) / "platform-tools/adb"
    adb_args = [adb, "-s", args.serial]
    page_size = int(capture(adb_args + ["shell", "getconf", "PAGE_SIZE"]))
    if page_size != 16384:
        raise RuntimeError("Qualification requires the 16 KiB emulator")
    report = {"schema": 1, "role": args.role, "push": push, "revision": summary["revision"],
        "packaging_revision": capture(["git", "-C", ROOT, "rev-parse", "HEAD"]),
        "packaging_source_sha256": sources,
        "ndk": summary["ndk"], "rustc": summary["rustc"], "page_size": page_size,
        "android": capture(adb_args + ["shell", "getprop", "ro.build.fingerprint"]), "apps": {}}
    import shutil
    for module in (["sdk", "push"] if push else ["sdk"]):
        publication = PROJECT / module / "build/publications" / args.role
        for filename, suffix in (("pom-default.xml", ".pom"), ("module.json", ".module")):
            shutil.copy2(publication / filename, evidence / (module + "-" + args.role + suffix))
    aar = PROJECT / "sdk/build/outputs/aar" / ("sdk-" + args.role + "-release.aar")
    shutil.copy2(aar, evidence / aar.name)
    report["aar"] = archive(aar)
    if push:
        adapter = PROJECT / "push/build/outputs/aar" / ("push-" + args.role + "-release.aar")
        shutil.copy2(adapter, evidence / adapter.name)
        report["push_aar"] = archive(adapter)
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
    if packaging_sources() != sources:
        raise RuntimeError("Android packaging sources changed during qualification; rerun against settled inputs")
    (evidence / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["delta"], indent=2))


if __name__ == "__main__":
    main()
