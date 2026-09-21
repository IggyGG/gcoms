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

    def test_crash_during_provider_request_retains_pending_work(self):
        registered = self.register()
        self.event(registered["reference"])
        original = self.provider.send
        def interrupted(*_):
            raise KeyboardInterrupt("simulated process interruption")
        self.provider.send = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.gateway.dispatch_one()
        self.gateway.db.close()
        self.provider.send = original
        self.gateway = Gateway(self.directory.name + "/state.sqlite", self.gateway.apps, self.gateway.relays, self.provider, lambda: self.now)
        self.now += 30
        self.assertTrue(self.gateway.dispatch_one())

    def test_token_rotation_during_provider_failure_preserves_new_token(self):
        registered = self.register()
        self.event(registered["reference"])
        original = self.provider.send
        def rotate(*_):
            self.register("rotated-while-in-flight")
            return DeliveryResult("expired")
        self.provider.send = rotate
        self.assertTrue(self.gateway.dispatch_one())
        self.provider.send = original
        self.now += 30
        self.assertTrue(self.gateway.dispatch_one())
        self.assertEqual(self.provider.sent[-1]["token"], "rotated-while-in-flight")


if __name__ == "__main__": unittest.main()

class RelayTicketTests(GatewayTests):
    def setUp(self):
        super().setUp()
        self.gateway.public_origin = "https://push.example"
        self.gateway.apps["boo.gchat.app"] = {"providers": {"fcm": {}, "apns": {}}}
        self.gateway.relays["relay"]["apps"].append("boo.gchat.app")

    def ticket(self, revision=1, token="token", visible=False, **overrides):
        from gateway import encode, sign
        import hashlib, secrets
        claims = {"version": 2, "purpose": "register", "issuer": "relay", "app": "boo.gchat.app", "installation": "a" * 64,
                  "issued": self.now, "expires": self.now + 300, "nonce": secrets.token_hex(16),
                  "revision": revision, "platform": "fcm", "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                  "gateway_origin": self.gateway.public_origin, "visible": visible}
        claims.update(overrides)
        body = canonical(claims)
        return encode(body) + "." + sign(self.relay_key, b"GCOMS-PUSH-RELAY-TICKET-v2\0", body)

    def submit(self, revision=1, token="token", visible=False, **overrides):
        return self.gateway.register({"ticket": self.ticket(revision, token, visible, **overrides), "platform": "fcm", "token": token, "visible": visible})

    def test_token_origin_app_platform_consent_and_revision_are_bound(self):
        for override in [{"gateway_origin": "https://other.example"}, {"issuer": "other"}, {"app": "other"},
                         {"purpose": "unregister"}, {"platform": "apns"}, {"token_sha256": "f" * 64}, {"revision": True}, {"revision": 0},
                         {"installation": "victim"}, {"expires": self.now + 301}, {"issued": True}, {"visible": 1}]:
            with self.subTest(override=override), self.assertRaises(ValueError): self.submit(**override)
        ticket = self.ticket(visible=True)
        with self.assertRaises(ValueError): self.gateway.register({"ticket": ticket, "platform": "fcm", "token": "token", "visible": False})
        with self.assertRaises(ValueError): self.gateway.register({"ticket": ticket, "platform": "fcm", "token": "changed", "visible": True})
        accepted = self.gateway.register({"ticket": ticket, "platform": "fcm", "token": "token", "visible": True})
        self.event(accepted["reference"])
        self.gateway.dispatch_one()
        self.assertEqual(self.provider.sent[-1]["visible"], 1)

    def test_rotation_tombstone_prevents_stale_registration_after_opt_out_and_restart(self):
        first = self.submit(1)
        newer = self.submit(3, "new-token")
        self.assertEqual(first["reference"], newer["reference"])
        with self.assertRaises(ValueError): self.submit(2, "late-token")
        with self.assertRaises(ValueError): self.submit(3, "changed-token")
        self.gateway.unregister({"reference": first["reference"], "management_token": first["management_token"]})
        self.event(newer["reference"])
        self.assertTrue(self.gateway.dispatch_one())
        self.assertEqual(self.provider.sent[-1]["token"], "new-token")
        self.gateway.unregister({"reference": newer["reference"], "management_token": newer["management_token"]})
        self.gateway.db.close()
        self.gateway = Gateway(self.directory.name + "/state.sqlite", self.gateway.apps, self.gateway.relays,
                               self.provider, lambda: self.now, public_origin="https://push.example")
        with self.assertRaises(ValueError): self.submit(2)
        self.assertIsNotNone(self.submit(4))

    def test_ticket_domain_cannot_be_used_as_event_and_legacy_cannot_replace_v2(self):
        from gateway import decode, sign
        ticket = self.ticket()
        encoded, _ = ticket.split(".")
        forged = encoded + "." + sign(self.relay_key, b"GCOMS-PUSH-EVENT-v1\0", decode(encoded))
        with self.assertRaises(ValueError): self.gateway.register({"ticket": forged, "platform": "fcm", "token": "token"})
        self.submit()
        self.gateway.apps["boo.gchat.app"]["registration_key"] = self.app_key
        old = issue_ticket("boo.gchat.app", "a" * 64, self.app_key, self.now)
        with self.assertRaises(ValueError): self.gateway.register({"ticket": old, "platform": "fcm", "token": "legacy"})

    def test_rust_ticket_wire_vector_registers_with_matching_scope(self):
        import json
        from pathlib import Path
        vector = json.loads((Path(__file__).resolve().parents[3] / "crates/node/src/push_notifications/relay-ticket-v2-vector.json").read_text())
        self.gateway.relays["r1"] = {"key": bytes([90]) * 32, "apps": ["boo.gchat.app"]}
        registration = self.gateway.register({"ticket": vector["ticket"], "platform": "fcm", "token": "private-token", "visible": True})
        self.assertEqual(len(registration["reference"]), 64)

    def test_identity_ticket_revokes_after_ambiguous_rotation_without_management_token(self):
        first = self.submit(1)
        self.submit(2, "rotated-token")  # Its response is deliberately lost.
        revoke = self.ticket(3, "0" * 64, purpose="unregister")
        data = {"ticket": revoke, "platform": "fcm", "token": "0" * 64, "visible": False}
        with self.assertRaises(ValueError): self.gateway.register(data)
        self.assertEqual(self.gateway.unregister(data), {"accepted": True})
        self.event(first["reference"])
        self.assertFalse(self.gateway.dispatch_one())
        with self.assertRaises(ValueError): self.submit(2, "late-token")
        with self.assertRaises(ValueError): self.gateway.unregister(data)
        self.assertIsNotNone(self.submit(4, "fresh-opt-in"))
        registration = {"ticket": self.ticket(5), "platform": "fcm", "token": "token"}
        with self.assertRaises(ValueError): self.gateway.unregister(registration)

    def test_non_object_ticket_fails_closed_before_lookup(self):
        from gateway import encode
        for body in [b"null", b"[]", b"1", b'"ticket"']:
            with self.assertRaises(ValueError):
                self.gateway.register({"ticket": encode(body) + "." + "0" * 64, "platform": "fcm", "token": "token"})
