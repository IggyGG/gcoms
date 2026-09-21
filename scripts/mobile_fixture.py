"""Owned loopback relay for client-role emulator/simulator tests."""
import contextlib
import json
import os
from pathlib import Path
import select
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def relay():
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target/mobile-build")).resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(["cargo", "build", "--manifest-path", str(ROOT / "mobile/native/Cargo.toml"),
        "--locked", "--no-default-features", "--features", "relay,fixtures", "--example", "fixture_host"],
        env=env, check=True)
    process = subprocess.Popen([str(target / "debug/examples/fixture_host")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout], [], [], 1)
            if ready:
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError("Mobile fixture relay stopped before readiness")
                try:
                    value = json.loads(line)
                    if "relay" in value and "port" in value:
                        yield value
                        return
                except json.JSONDecodeError:
                    pass
        raise RuntimeError("Mobile fixture relay readiness timed out")
    finally:
        if process.poll() is None:
            try:
                process.communicate("stop\n", timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
