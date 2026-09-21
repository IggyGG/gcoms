import json
import tempfile
import unittest
from pathlib import Path
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from gateway import decode
from providers import Providers


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.requests = []
        self.responses = []
        def handler(request):
            self.requests.append(request)
            return self.responses.pop(0)
        self.client = httpx.Client(transport=httpx.MockTransport(handler))
        self.providers = Providers(self.client)
        self.row = {"app": "app", "reference": "a" * 64, "token": "b" * 64, "platform": "apns"}
    def tearDown(self):
        self.client.close()
        self.directory.cleanup()
    def private(self, key, name):
        path = self.root / name
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return str(path)
    def test_apns_generic_payload_signed_token_and_provider_expiry(self):
        key = ec.generate_private_key(ec.SECP256R1())
        config = {"key_id": "KEY", "team_id": "TEAM", "topic": "boo.example.app", "sandbox": True, "private_key_file": self.private(key, "apns.pem")}
        self.responses.append(httpx.Response(200, json={}))
        self.assertEqual(self.providers.send(self.row, config).status, "accepted")
        request = self.requests[-1]
        self.assertEqual(request.url.host, "api.sandbox.push.apple.com")
        self.assertEqual(request.headers["apns-push-type"], "background")
        self.assertEqual(request.headers["apns-priority"], "5")
        self.assertEqual(json.loads(request.content), {"aps": {"content-available": 1}, "gcoms_activity": "message", "gcoms_reference": "a" * 64})
        first, second, signature = request.headers["authorization"].removeprefix("bearer ").split(".")
        signature = decode(signature)
        key.public_key().verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                                (first + "." + second).encode(), ec.ECDSA(hashes.SHA256()))
        self.assertEqual(json.loads(decode(second))["iss"], "TEAM")
        self.responses.append(httpx.Response(410, json={"reason": "Unregistered"}))
        self.assertEqual(self.providers.send(self.row, config).status, "expired")
    def test_fcm_oauth_signature_payload_retries_and_token_rotation(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        account = self.root / "account.json"
        account.write_text(json.dumps({"client_email": "service@example.invalid", "private_key": Path(self.private(key, "fcm.pem")).read_text()}))
        config = {"project_id": "project", "service_account_file": str(account)}
        self.row["platform"] = "fcm"
        self.responses.extend([httpx.Response(200, json={"access_token": "simulated", "expires_in": 3600}), httpx.Response(503, headers={"retry-after": "120"}, json={})])
        result = self.providers.send(self.row, config)
        self.assertEqual((result.status, result.retry_after), ("retry", 120))
        from urllib.parse import parse_qs
        assertion = parse_qs(self.requests[0].content.decode())["assertion"][0]
        first, second, signature = assertion.split(".")
        key.public_key().verify(decode(signature), (first + "." + second).encode(), padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(json.loads(decode(second))["aud"], "https://oauth2.googleapis.com/token")
        message = json.loads(self.requests[-1].content)["message"]
        self.assertEqual(set(message), {"token", "data", "android"})
        self.assertEqual(message["data"], {"gcoms_activity": "message", "gcoms_reference": "a" * 64})
        self.assertEqual(message["android"]["priority"], "normal")
        self.responses.append(httpx.Response(404, json={"error": {"details": [{"errorCode": "UNREGISTERED"}]}}))
        self.assertEqual(self.providers.send(self.row, config).status, "expired")
        self.assertEqual(len(self.requests), 3)  # OAuth token was reused.

    def test_visible_apns_is_generic_and_android_stays_app_controlled_data_only(self):
        key = ec.generate_private_key(ec.SECP256R1())
        config = {"key_id": "KEY", "team_id": "TEAM", "topic": "boo.gchat.app", "private_key_file": self.private(key, "visible.pem")}
        self.row["visible"] = True
        self.responses.append(httpx.Response(200, json={}))
        self.providers.send(self.row, config)
        request = self.requests[-1]
        self.assertEqual(request.headers["apns-push-type"], "alert")
        self.assertEqual(request.headers["apns-priority"], "10")
        payload = json.loads(request.content)
        self.assertEqual(payload["aps"]["alert"], {"title": "GChat", "body": "New activity. Open GChat to receive it."})
        self.assertEqual(set(payload), {"aps", "gcoms_activity", "gcoms_reference"})
        import time
        self.providers.tokens[("fcm", "app")] = ("mock-token", int(time.time()) + 100)
        self.row["platform"] = "fcm"
        self.responses.append(httpx.Response(200, json={}))
        self.providers.send(self.row, {"project_id": "project"})
        payload = json.loads(self.requests[-1].content)["message"]
        self.assertEqual(payload["android"]["priority"], "high")
        self.assertNotIn("notification", payload)
        self.assertEqual(payload["data"], {"gcoms_activity": "message", "gcoms_reference": "a" * 64})


if __name__ == "__main__": unittest.main()
