"""Owned loopback relay for client-role emulator/simulator tests."""
import contextlib
import hmac
import http.server
import json
import os
from pathlib import Path
import select
import secrets
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def read_record(process, timeout):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) <= 256 * 1024:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise RuntimeError("Mobile fixture response timed out")
        part = os.read(process.stdout.fileno(), min(65536, 256 * 1024 + 1 - len(data)))
        if not part:
            raise RuntimeError("Mobile fixture stopped before its response")
        data.extend(part)
        if len(data) > 256 * 1024:
            raise RuntimeError("Mobile fixture response exceeds bound")
        if b"\n" in data:
            if not data.endswith(b"\n") or data.count(b"\n") != 1:
                raise RuntimeError("Mobile fixture response framing differs")
            return json.loads(data)
    raise RuntimeError("Mobile fixture response exceeds bound")


@contextlib.contextmanager
def relay_issuer(issue):
    """One authenticated fresh card, requested by the already-running simulator."""
    token = secrets.token_urlsafe(32)
    used = False

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def log_message(self, *_):
            pass  # Never log the disposable capability or card.

        def do_GET(self):
            nonlocal used
            if self.path != "/relay" or not hmac.compare_digest(
                    self.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()):
                self.send_error(404)
                return
            if used:
                self.send_error(409)
                return
            try:
                data = json.dumps(issue(), separators=(",", ":")).encode()
                if len(data) > 256 * 1024:
                    raise ValueError("fixture card exceeds bound")
                used = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (OSError, RuntimeError, ValueError):
                self.send_error(503)

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              name="mobile-fixture-issuer", daemon=True)
    thread.start()
    try:
        yield {"url": "http://127.0.0.1:" + str(server.server_port) + "/relay", "token": token}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=15)
        if thread.is_alive():
            raise RuntimeError("Mobile fixture issuer did not stop")


@contextlib.contextmanager
def relay(*, fresh_at_test_start=False):
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target/mobile-build")).resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(["cargo", "build", "--manifest-path", str(ROOT / "mobile/native/Cargo.toml"),
        "--locked", "--no-default-features", "--features", "relay,fixtures", "--example", "fixture_host"],
        env=env, check=True)
    process = subprocess.Popen([str(target / "debug/examples/fixture_host")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        value = read_record(process, 60)
        if "relay" not in value or "port" not in value:
            raise RuntimeError("Mobile fixture readiness differs")
        if fresh_at_test_start:
            def issue():
                process.stdin.write(b"provision\n")
                process.stdin.flush()
                card = read_record(process, 10)
                if card.get("port") != value["port"] or not card.get("relay"):
                    raise RuntimeError("Mobile fixture relay changed")
                return card["relay"]
            with relay_issuer(issue) as issuer:
                yield dict(value, issuer=issuer)
        else:
            yield value
    finally:
        if process.poll() is None:
            try:
                process.communicate(b"stop\n", timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
