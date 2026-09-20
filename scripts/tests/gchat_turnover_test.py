"""Controller regressions from the real-daemon startup/reopen attempts."""
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("gchat_turnover", Path(__file__).resolve().parents[1] / "gchat-turnover.py")
turnover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(turnover)


@unittest.skipUnless(os.name == "posix", "Linux namespace controller")
class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "c0").mkdir()
        self.worker = turnover.Journey(dict(out=str(self.root), uid=os.getuid(), gid=os.getgid(),
            workload="turnover", seed=1, config={}, build={"path": str(self.root / "build")}))
        self.worker.root = self.root
        self.worker.roles["client0"] = 1

    def test_reopen_removes_only_dead_owned_probe_socket_and_preserves_profile(self):
        endpoint = self.root / "c0/probe.sock"
        with socket.socket(socket.AF_UNIX) as stream:
            stream.bind(str(endpoint))
        profile = self.root / "c0/profile"
        profile.write_bytes(b"retained encrypted fixture bytes")
        self.worker.children.append(("probe0", mock.Mock(poll=lambda: -15)))
        with mock.patch.object(self.worker, "spawn") as spawn:
            self.worker.start_client(0)
        self.assertFalse(endpoint.exists())
        self.assertEqual(profile.read_bytes(), b"retained encrypted fixture bytes")
        _, command = spawn.call_args_list[0].args
        self.assertNotIn("--create", command)
        self.assertNotIn("--inbox-relay-file", command)
        self.assertNotIn("GC_ROUTING_BOOTSTRAP", spawn.call_args_list[0].kwargs["env"])
        self.assertIn("--gc2-carrier", command)

    def test_live_probe_or_unexpected_file_is_never_removed(self):
        endpoint = self.root / "c0/probe.sock"
        endpoint.write_text("preserve")
        self.worker.children.append(("probe0", mock.Mock(poll=lambda: None)))
        with self.assertRaisesRegex(RuntimeError, "still running"):
            self.worker.start_client(0)
        self.assertEqual(endpoint.read_text(), "preserve")
        self.worker.children.clear()
        with self.assertRaisesRegex(RuntimeError, "unexpected file"):
            self.worker.start_client(0)
        self.assertEqual(endpoint.read_text(), "preserve")

    def test_remote_join_uses_remaining_setup_budget_not_default_rpc_timeout(self):
        class SetupComplete(Exception):
            pass

        class Setup(turnover.Journey):
            def start_client(self, i):
                pass

            def request(self, *args, **kwargs):
                return {"ready": True}

            def files(self, *args, **kwargs):
                return {}

            def readiness(self, i):
                return True

            def submit(self, i, text, conversation=None):
                if text.startswith("/create"):
                    return {"conversation": "fixture"}
                if text.startswith("/invite"):
                    return {"output": {"link": "fixture", "localOnly": False}}
                if text.startswith("/join"):
                    # The real remote join took ~37 seconds. The inherited
                    # default is 30 seconds unless a phase deadline is supplied.
                    remaining = self.rpc_deadline - turnover.time.monotonic() if self.rpc_deadline else 30
                    if remaining < 40:
                        raise TimeoutError("controller abandoned join before setup deadline")
                return {}

            def chat(self, *args, **kwargs):
                raise SetupComplete

        worker = Setup(self.worker.spec)
        worker.root = self.root
        worker.ns = []
        with mock.patch.object(turnover.subprocess, "Popen"):
            with self.assertRaises(SetupComplete):
                worker.exercise()


if __name__ == "__main__":
    unittest.main()
