#!/usr/bin/env python3
"""Prepare the pinned Linux Android qualification tools on a clean CI runner."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile

root = Path(os.environ["RUNNER_TEMP"]) / "gcoms-android"
root.mkdir(parents=True, exist_ok=True)
archive = root / "commandlinetools.zip"
url = "https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip"
urllib.request.urlretrieve(url, archive)
if hashlib.sha256(archive.read_bytes()).hexdigest() != "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583":
    raise RuntimeError("Android command-line tools checksum mismatch")
with zipfile.ZipFile(archive) as content:
    content.extractall(root / "unpack")
latest = root / "cmdline-tools/latest"
latest.parent.mkdir(exist_ok=True)
shutil.move(str(root / "unpack/cmdline-tools"), latest)
for tool in (latest / "bin").iterdir():
    tool.chmod(tool.stat().st_mode | 0o111)
environment = dict(os.environ, ANDROID_HOME=str(root), JAVA_HOME=os.environ["JAVA_HOME_21_X64"])
sdkmanager = str(latest / "bin/sdkmanager")
subprocess.run([sdkmanager, "--sdk_root=" + str(root), "--licenses"], input="y\n" * 200, text=True, env=environment, check=True)
subprocess.run([sdkmanager, "--sdk_root=" + str(root), "ndk;28.2.13676358", "platforms;android-36",
    "build-tools;35.0.0", "platform-tools", "emulator", "system-images;android-35;google_apis_ps16k;x86_64"],
    input="y\n" * 200, text=True, env=environment, check=True)
subprocess.run(["sudo", "chmod", "a+rw", "/dev/kvm"], check=True)
subprocess.run([str(latest / "bin/avdmanager"), "create", "avd", "-n", "gcoms16k", "-k",
    "system-images;android-35;google_apis_ps16k;x86_64"], input="no\n", text=True, env=environment, check=True)
with open(os.environ["GITHUB_ENV"], "a") as stream:
    stream.write("ANDROID_HOME=" + str(root) + "\nJAVA_HOME=" + environment["JAVA_HOME"] + "\n")
with open(os.environ["GITHUB_PATH"], "a") as stream:
    stream.write(str(latest / "bin") + "\n" + str(root / "platform-tools") + "\n" + environment["JAVA_HOME"] + "/bin\n")
