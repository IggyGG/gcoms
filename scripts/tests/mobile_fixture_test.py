"""Fresh simulator grants retain authentication, one-use and bounded I/O."""
import contextlib
import json
import os
from pathlib import Path
import socket
import sys
import types
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mobile_fixture import read_record, relay_issuer


class MobileFixtureTests(unittest.TestCase):
    def request(self, issuer, *, token=None, suffix="", method="GET"):
        request = urllib.request.Request(issuer["url"] + suffix, method=method)
        if token is not None:
            request.add_header("Authorization", "Bearer " + token)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return opener.open(request, timeout=2)

    def test_grant_is_minted_only_by_authenticated_test_and_only_once(self):
        issue = mock.Mock(return_value=[71, 67, 1])
        with relay_issuer(issue) as issuer:
            issue.assert_not_called()  # Arbitrary simulator launch delay mints nothing.
            for token, suffix, method, status in [
                (None, "", "GET", 404), ("wrong", "", "GET", 404),
                (issuer["token"], "?other=1", "GET", 404),
                (issuer["token"], "", "POST", 501),
            ]:
                with self.assertRaises(urllib.error.HTTPError) as error:
                    self.request(issuer, token=token, suffix=suffix, method=method)
                self.assertEqual(error.exception.code, status)
                error.exception.close()
                issue.assert_not_called()
            with self.request(issuer, token=issuer["token"]) as response:
                self.assertEqual(json.load(response), [71, 67, 1])
                self.assertEqual(response.headers["Cache-Control"], "no-store")
            issue.assert_called_once_with()
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request(issuer, token=issuer["token"])
            self.assertEqual(error.exception.code, 409)
            error.exception.close()
            issue.assert_called_once_with()
            port = urllib.parse.urlparse(issuer["url"]).port
        with socket.socket() as client:
            client.settimeout(1)
            self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)

    def test_provisioning_failure_cannot_return_a_success_card(self):
        with relay_issuer(mock.Mock(side_effect=RuntimeError("fixture unavailable"))) as issuer:
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request(issuer, token=issuer["token"])
            self.assertEqual(error.exception.code, 503)
            error.exception.close()

    @contextlib.contextmanager
    def pipe(self, data):
        read, write = os.pipe()
        with os.fdopen(read, "rb", buffering=0) as stream:
            try:
                os.write(write, data)
                yield types.SimpleNamespace(stdout=stream)
            finally:
                os.close(write)

    def test_complete_record_decodes_without_waiting_for_eof(self):
        with self.pipe(b'{"relay":[1,2],"port":1234}\n') as process:
            self.assertEqual(read_record(process, 1), {"relay": [1, 2], "port": 1234})

    def test_partial_line_honors_deadline(self):
        with self.pipe(b'{"relay":') as process:
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                read_record(process, 0.02)

    def test_unexpected_multiple_records_fail_closed(self):
        with self.pipe(b'{}\n{}\n') as process:
            with self.assertRaisesRegex(RuntimeError, "framing differs"):
                read_record(process, 1)

    def test_oversized_record_fails_at_bound(self):
        process = types.SimpleNamespace(stdout=mock.Mock())
        with mock.patch("mobile_fixture.select.select", return_value=([process.stdout], [], [])), \
                mock.patch("mobile_fixture.os.read", side_effect=lambda _, size: b"x" * size):
            with self.assertRaisesRegex(RuntimeError, "exceeds bound"):
                read_record(process, 1)


if __name__ == "__main__":
    unittest.main()
