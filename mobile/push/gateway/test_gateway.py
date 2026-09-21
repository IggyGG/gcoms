import tempfile
import unittest
from gateway import Gateway, DeliveryResult, canonical, issue_ticket, relay_headers


class Fake:
    def __init__(self): self.sent, self.result = [], DeliveryResult("accepted")
    def send(self, row, config):
        self.sent.append(row)
        return self.result


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.now = 1000
        self.provider = Fake()
        self.app_key, self.relay_key = bytes(range(32)), bytes(range(32, 64))
        self.gateway = Gateway(self.directory.name + "/state.sqlite",
            {"app": {"registration_key": self.app_key, "providers": {"fcm": {}, "apns": {}}}},
            {"relay": {"key": self.relay_key, "apps": ["app"]}}, self.provider, lambda: self.now)
    def tearDown(self):
        self.gateway.db.close()
        self.directory.cleanup()
    def register(self, token="device-token"):
        return self.gateway.register({"ticket": issue_ticket("app", "installation", self.app_key, self.now), "platform": "fcm", "token": token})
    def event(self, reference, nonce=None):
        body = canonical({"reference": reference, "activity": "message"})
        headers = relay_headers("relay", self.relay_key, body, self.now, nonce)
        return self.gateway.event(headers, body)
    def test_ticket_scope_expiry_replay_and_untrusted_relay(self):
        ticket = issue_ticket("app", "installation", self.app_key, self.now)
        data = {"ticket": ticket, "platform": "fcm", "token": "token"}
        registered = self.gateway.register(data)
        with self.assertRaises(Exception): self.gateway.register(data)
        self.now += 301
        with self.assertRaises(ValueError): self.gateway.register(data)
        body = canonical({"reference": registered["reference"], "activity": "message"})
        with self.assertRaises(ValueError): self.gateway.event(relay_headers("relay", b"x" * 32, body, self.now), body)
        self.assertFalse(self.gateway.dispatch_one())
    def test_coalescing_replay_rotation_and_unregister(self):
        registered = self.register()
        for _ in range(3): self.event(registered["reference"], "a" * 32)
        self.assertTrue(self.gateway.dispatch_one())
        self.assertFalse(self.gateway.dispatch_one())
        self.assertEqual(len(self.provider.sent), 1)
        rotated = self.register("new-token")
        self.assertEqual(rotated["reference"], registered["reference"])
        self.gateway.unregister({"reference": registered["reference"], "management_token": registered["management_token"]})
        self.event(rotated["reference"])
        self.assertFalse(self.gateway.dispatch_one())
        self.now += 30
        self.assertTrue(self.gateway.dispatch_one())
        self.assertEqual(self.provider.sent[-1]["token"], "new-token")
        self.gateway.unregister({"reference": rotated["reference"], "management_token": rotated["management_token"]})
        self.event(rotated["reference"])
        self.now += 30
        self.assertFalse(self.gateway.dispatch_one())
    def test_transient_retry_and_expired_tokens(self):
        registered = self.register()
        self.provider.result = DeliveryResult("retry", 120)
        self.event(registered["reference"])
        self.assertTrue(self.gateway.dispatch_one())
        self.now += 119
        self.assertFalse(self.gateway.dispatch_one())
        self.now += 1
        self.provider.result = DeliveryResult("expired")
        self.assertTrue(self.gateway.dispatch_one())
        self.now += 3600
        self.event(registered["reference"])
        self.assertFalse(self.gateway.dispatch_one())
    def test_event_rejects_content_and_unknown_reference_is_generic(self):
        registered = self.register()
        body = canonical({"reference": registered["reference"], "activity": "message", "text": "must not enter push"})
        with self.assertRaises(ValueError): self.gateway.event(relay_headers("relay", self.relay_key, body, self.now), body)
        self.assertEqual(self.event("f" * 64), {"accepted": True})
        self.assertFalse(self.gateway.dispatch_one())
    def test_pending_notification_survives_restart(self):
        registered = self.register()
        self.event(registered["reference"])
        self.gateway.db.close()
        self.gateway = Gateway(self.directory.name + "/state.sqlite", self.gateway.apps, self.gateway.relays, self.provider, lambda: self.now)
        self.assertTrue(self.gateway.dispatch_one())


if __name__ == "__main__": unittest.main()
