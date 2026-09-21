"""Optional APNs/FCM network providers; loaded only by the app-operated gateway."""
import base64
import json
import time
from pathlib import Path
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from gateway import DeliveryResult, canonical, encode


def jwt(header, claims, private_key):
    body = encode(canonical(header)) + "." + encode(canonical(claims))
    key = serialization.load_pem_private_key(private_key, password=None)
    if header["alg"] == "ES256":
        r, s = decode_dss_signature(key.sign(body.encode(), ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        signature = key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256())
    return body + "." + encode(signature)


class Providers:
    def __init__(self, client=None):
        self.http = client or httpx.Client(http2=True, timeout=15, follow_redirects=False)
        self.tokens = {}

    def send(self, registration, config):
        if registration["platform"] == "apns":
            return self.apns(registration, config)
        return self.fcm(registration, config)

    @staticmethod
    def result(response, expired):
        if response.status_code in (200, 201):
            return DeliveryResult("accepted")
        try:
            body = response.json()
        except ValueError:
            body = {}
        if expired(response.status_code, body):
            return DeliveryResult("expired")
        # Credential/configuration errors retain registration and back off.
        retry = response.headers.get("retry-after", "")
        return DeliveryResult("retry", min(3600, int(retry)) if retry.isdecimal() else 0)

    def apns(self, registration, config):
        now = int(time.time())
        key = ("apns", registration["app"])
        cached = self.tokens.get(key)
        if not cached or cached[1] <= now:
            token = jwt({"alg": "ES256", "kid": config["key_id"]}, {"iss": config["team_id"], "iat": now}, Path(config["private_key_file"]).read_bytes())
            self.tokens[key] = (token, now + 3000)
        endpoint = "api.sandbox.push.apple.com" if config.get("sandbox", False) else "api.push.apple.com"
        visible = bool(registration.get("visible", False))
        aps = {"content-available": 1}
        if visible:
            aps["alert"] = {"title": "GChat", "body": "New activity. Open GChat to receive it."}
        response = self.http.post("https://" + endpoint + "/3/device/" + registration["token"],
            headers={"authorization": "bearer " + self.tokens[key][0], "apns-topic": config["topic"],
                     "apns-push-type": "alert" if visible else "background", "apns-priority": "10" if visible else "5", "apns-expiration": str(now + 300),
                     "apns-collapse-id": registration["reference"]},
            json={"aps": aps, "gcoms_activity": "message", "gcoms_reference": registration["reference"]})
        if response.status_code == 403:
            self.tokens.pop(key, None)
        return self.result(response, lambda code, body: code == 410 or (code == 400 and body.get("reason") in ("BadDeviceToken", "DeviceTokenNotForTopic")))

    def fcm(self, registration, config):
        now = int(time.time())
        key = ("fcm", registration["app"])
        cached = self.tokens.get(key)
        if not cached or cached[1] <= now:
            account = json.loads(Path(config["service_account_file"]).read_text())
            assertion = jwt({"alg": "RS256", "typ": "JWT"},
                {"iss": account["client_email"], "scope": "https://www.googleapis.com/auth/firebase.messaging",
                 "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600},
                account["private_key"].encode())
            response = self.http.post("https://oauth2.googleapis.com/token",
                data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
            if response.status_code != 200:
                return DeliveryResult("retry", 60)
            token = response.json()
            self.tokens[key] = (token["access_token"], now + min(int(token["expires_in"]), 3600) - 60)
        response = self.http.post("https://fcm.googleapis.com/v1/projects/" + config["project_id"] + "/messages:send",
            headers={"authorization": "Bearer " + self.tokens[key][0]},
            json={"message": {"token": registration["token"], "data": {"gcoms_activity": "message", "gcoms_reference": registration["reference"]},
                              # Data-only: native Android checks current permission and opt-in
                              # before displaying the fixed generic alert, including after opt-out.
                              "android": {"priority": "high" if registration.get("visible", False) else "normal", "ttl": "300s", "collapse_key": "gcoms-activity"}}})
        if response.status_code == 401:
            self.tokens.pop(key, None)
        def expired(code, body):
            return any(item.get("errorCode") == "UNREGISTERED" for item in body.get("error", {}).get("details", []) if isinstance(item, dict))
        return self.result(response, expired)
