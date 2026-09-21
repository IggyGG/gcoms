import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from render import render
from prepare import prepare
from health import check


class Deployment(unittest.TestCase):
    def fixture(self, path):
        value = {"public_origin": "https://push.gchat.boo", "apps": {"boo.gchat.app": {"providers": {"fcm": {"project_id": "gchat-23115", "service_account_file": "/private/current/fcm.json"}}}}, "relays": {"fixture": {"key": "ab" * 32, "apps": ["boo.gchat.app"]}}}
        (path / "config.json").write_text(json.dumps(value))
        (path / "fcm.json").write_text("{}")
        return value

    def test_runtime_source_is_frozen(self):
        manifest = json.loads((HERE / "runtime-sources.json").read_text())
        self.assertEqual(manifest["commit"], "b864f9ba6660148589d1e67821f04e98064933ef")
        for name, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((HERE.parent / "gateway" / name).read_bytes()).hexdigest(), digest)

    def test_build_context_contains_only_explicit_public_inputs(self):
        spec = importlib.util.spec_from_file_location("build_context", HERE / "build-context.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "context"
            hashes = module.stage(output)
            self.assertEqual(len(hashes), 9)
            self.assertEqual(set(p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()), set(hashes) | {"context-manifest.json"})
            for path, digest in hashes.items():
                self.assertEqual(hashlib.sha256((output / path).read_bytes()).hexdigest(), digest)
            with self.assertRaises(FileExistsError): module.stage(output)

    def test_pins_and_hashed_dependencies(self):
        pins = json.loads((HERE / "images.json").read_text())
        for pin in pins.values():
            self.assertRegex(pin["image"], r"@sha256:[0-9a-f]{64}$")
        docker = (HERE / "Dockerfile").read_text()
        self.assertIn("FROM " + pins["python"]["image"], docker)
        self.assertIn("--only-binary=:all: --require-hashes", docker)
        entries = (HERE / "requirements.lock").read_text().splitlines()
        for i, line in enumerate(entries):
            if line and not line[0].isspace():
                self.assertIn("==", line)
                self.assertIn("--hash=sha256:", entries[i + 1])

    def test_only_immutable_image_single_writer_private_mounts(self):
        for image in ("registry:5000/gchat-push:latest", "registry/gchat-push@sha256:bad", "registry/other@sha256:" + "a" * 64):
            with self.assertRaises(ValueError): render(image)
        result = render("registry:5000/ghost/gchat-push@sha256:" + "a" * 64)
        kinds = {i["kind"]: i for i in result["items"]}
        self.assertTrue(all(i["metadata"]["namespace"] == "ghost-com" for i in result["items"]))
        deployment = kinds["Deployment"]["spec"]
        self.assertEqual(deployment["replicas"], 1)
        self.assertEqual(deployment["strategy"], {"type": "Recreate"})
        pod = deployment["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        gateway, proxy = pod["containers"]
        self.assertEqual({x["name"] for x in proxy["volumeMounts"]}, {"proxy", "proxy-tmp"})
        self.assertNotIn("ports", gateway)
        for container in [*pod["containers"], *pod["initContainers"]]:
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertEqual(kinds["Service"]["spec"]["type"], "ClusterIP")
        ingress = kinds["Ingress"]
        self.assertEqual(ingress["spec"]["tls"][0]["hosts"], ["push.gchat.boo"])
        self.assertEqual(ingress["metadata"]["annotations"]["cert-manager.io/cluster-issuer"], "letsencrypt-prod")
        self.assertEqual(ingress["metadata"]["annotations"]["nginx.ingress.kubernetes.io/enable-access-log"], "false")
        self.assertEqual(len(ingress["spec"]["rules"][0]["http"]["paths"]), 3)

    def test_private_copy_scope_and_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "input"; source.mkdir()
            self.fixture(source); output = root / "private"
            prepare(source, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(set(p.name for p in output.iterdir()), {"config.json", "fcm.json"})
            for p in output.iterdir(): self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): prepare(source, output)

    def test_wrong_origin_or_reused_key_is_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            value = self.fixture(source); value["public_origin"] = "https://attacker.invalid"
            (source / "config.json").write_text(json.dumps(value))
            with self.assertRaises(ValueError): prepare(source, source / "private")
            self.assertFalse((source / "private").exists())
            value = self.fixture(source); value["relays"]["other"] = value["relays"]["fixture"]
            (source / "config.json").write_text(json.dumps(value))
            with self.assertRaises(ValueError): prepare(source, source / "private")

    def test_projected_symlinks_may_not_escape_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "input"; source.mkdir(); self.fixture(source)
            (source / "fcm.json").unlink(); (root / "outside").write_text("sensitive")
            (source / "fcm.json").symlink_to(root / "outside")
            with self.assertRaises(ValueError): prepare(source, root / "private")
            self.assertFalse((root / "private").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX container signal contract")
    def test_actual_server_health_and_sigterm_cleanup_preserve_sqlite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.fixture(root); state = root / "state"
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
            code = "from pathlib import Path;from launcher import run;run(Path(%r),Path(%r),%d)" % (str(root / "config.json"), str(state), port)
            env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(HERE), str(HERE.parent / "gateway")]), PYTHONDONTWRITEBYTECODE="1")
            for iteration in range(2):
                with (root / (str(iteration) + ".log")).open("w") as log:
                    process = subprocess.Popen([sys.executable, "-c", code], env=env, stdout=log, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 10
                        while True:
                            try:
                                check(True, port, str(state / "push.sqlite")); break
                            except (OSError, ValueError, sqlite3.Error):
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    self.fail("fixture did not initialize: " + (root / (str(iteration) + ".log")).read_text())
                                time.sleep(0.05)
                        with sqlite3.connect(state / "push.sqlite") as db:
                            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
                        process.send_signal(signal.SIGTERM)
                        self.assertEqual(process.wait(timeout=20), 0)
                        with self.assertRaises(OSError): socket.create_connection(("127.0.0.1", port), timeout=1)
                    finally:
                        if process.poll() is None:
                            process.kill(); process.wait()
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertTrue((state / "push.sqlite").exists())


if __name__ == "__main__": unittest.main()
