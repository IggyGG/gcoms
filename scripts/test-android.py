#!/usr/bin/env python3
"""Exercise either SDK role; clients use a separate loopback relay through adb."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from mobile_fixture import relay, ROOT

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--role", choices=["client", "relay"], required=True)
parser.add_argument("--native-root", type=Path, required=True)
parser.add_argument("--serial", required=True)
parser.add_argument("--gradle", default=str(ROOT / "mobile/android/gradlew"))
parser.add_argument("--push", action="store_true")
args = parser.parse_args()
native = args.native_root.resolve()
metadata = json.loads((native / "android" / args.role / "build.json").read_text())
if not metadata["fixtures"]:
    raise RuntimeError("Functional tests require a non-distributable fixture build")
adb = [str(Path(os.environ["ANDROID_HOME"]) / "platform-tools/adb"), "-s", args.serial]
command = [args.gradle, "-p", str(ROOT / "mobile/android"),
    "-PgcomsNativeRoot=" + str(native / "android")]
if args.push:
    command += ["-PgcomsPush=true", ":push:test" + args.role.title() + "DebugUnitTest"]
with tempfile.TemporaryDirectory(prefix="fixture-assets-", dir=native) as assets:
    if args.role == "client":
        command += ["-PgcomsFixtureAssets=" + assets]
        # Compile before minting the short-lived grant. Adding its asset below
        # only repeats asset merging/packaging before installation and testing.
        assembly = [":sdk:assembleClientDebug", ":sdk:assembleClientDebugAndroidTest"]
        if args.push:
            assembly += [":push:assembleClientDebugAndroidTest"]
        subprocess.run(command + assembly + ["--no-daemon"], check=True)
    with relay() if args.role == "client" else contextlib.nullcontext(None) as host:
        port = None
        try:
            if host:
                port = "tcp:" + str(host["port"])
                subprocess.run(adb + ["reverse", port, port], check=True)
                # A relay card exceeds adb's shell command budget. Keep this
                # disposable capability in test-only assets, never command logs.
                (Path(assets) / "relay.json").write_text(json.dumps(host["relay"]))
            checks = [":sdk:connected" + args.role.title() + "DebugAndroidTest"]
            if args.push:
                checks += [":push:connected" + args.role.title() + "DebugAndroidTest"]
            subprocess.run(command + checks + ["--no-daemon"],
                env=dict(os.environ, ANDROID_SERIAL=args.serial), check=True)
        finally:
            if port:
                subprocess.run(adb + ["reverse", "--remove", port], check=False)
