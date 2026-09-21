"""App-operated wake-up gateway. No message text, peer IDs or inbox queue IDs."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

MAX_REGISTRATIONS = 50000
MAX_REQUEST = 8192
REFERENCE = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def sign(key, domain, body):
    return hmac.new(key, domain + body, hashlib.sha256).hexdigest()


def issue_ticket(app, installation, key, now=None):
    """Run only on the application's authenticated server, never in the mobile app."""
    now = int(time.time()) if now is None else now
    if not NAME.fullmatch(app) or not NAME.fullmatch(installation):
        raise ValueError("invalid ticket scope")
    body = canonical({"app": app, "installation": installation, "issued": now, "expires": now + 300, "nonce": secrets.token_hex(16)})
    return encode(body) + "." + sign(key, b"GCOMS-PUSH-TICKET-v1\0", body)


def relay_headers(relay, key, body, now=None, nonce=None):
    timestamp = str(int(time.time()) if now is None else now)
    nonce = nonce or secrets.token_hex(16)
    signed = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return {"x-relay-id": relay, "x-timestamp": timestamp, "x-nonce": nonce,
            "x-signature": sign(key, b"GCOMS-PUSH-EVENT-v1\0", signed)}


@dataclass(frozen=True)
class DeliveryResult:
    status: str  # accepted, expired (device token invalid), retry
    retry_after: int = 0


class Gateway:
    def __init__(self, database, apps, relays, provider, clock=time.time):
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS registrations (
                reference TEXT PRIMARY KEY, app TEXT NOT NULL, installation TEXT NOT NULL,
                platform TEXT NOT NULL, token TEXT NOT NULL, management TEXT NOT NULL,
                expires INTEGER NOT NULL, pending INTEGER NOT NULL DEFAULT 0,
                due INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
                generation INTEGER NOT NULL DEFAULT 0, UNIQUE(app, installation)
            );
            CREATE TABLE IF NOT EXISTS replays (
                scope TEXT NOT NULL, nonce TEXT NOT NULL, expires INTEGER NOT NULL,
                PRIMARY KEY(scope, nonce)
            );
        """)
        self.apps, self.relays, self.provider, self.clock = apps, relays, provider, clock
        self.lock = threading.Lock()

    def cleanup(self, now):
        self.db.execute("DELETE FROM registrations WHERE expires <= ?", (now,))
        self.db.execute("DELETE FROM replays WHERE expires <= ?", (now,))

    def register(self, data):
        if set(data) != {"ticket", "platform", "token"}:
            raise ValueError("invalid registration")
        ticket, platform, token = data["ticket"], data["platform"], data["token"]
        if not isinstance(ticket, str) or len(ticket) > 2048 or platform not in ("apns", "fcm"):
            raise ValueError("invalid registration")
        if not isinstance(token, str) or not 1 <= len(token) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("invalid device token")
        if platform == "apns" and (len(token) % 2 or not re.fullmatch("[a-fA-F0-9]{32,256}", token)):
            raise ValueError("invalid APNs token")
        encoded, signature = ticket.split(".")
        body = decode(encoded)
        claims = json.loads(body)
        if set(claims) != {"app", "installation", "issued", "expires", "nonce"}:
            raise ValueError("invalid ticket")
        app = self.apps.get(claims["app"])
        now = int(self.clock())
        if not app or not hmac.compare_digest(signature, sign(app["registration_key"], b"GCOMS-PUSH-TICKET-v1\0", body)):
            raise ValueError("invalid ticket")
        if not NAME.fullmatch(claims["installation"]) or not re.fullmatch("[0-9a-f]{32}", claims["nonce"]):
            raise ValueError("invalid ticket")
        if not (now - 300 <= claims["issued"] <= now + 30 and now < claims["expires"] <= claims["issued"] + 300):
            raise ValueError("expired ticket")
        if platform not in app.get("providers", {}):
            raise ValueError("provider not configured")
        management = secrets.token_hex(32)
        with self.lock, self.db:
            self.cleanup(now)
            if self.db.execute("SELECT count(*) FROM replays").fetchone()[0] >= 100000:
                raise ValueError("ticket capacity reached")
            # One-use tickets; a retry must obtain a fresh ticket from the app server.
            self.db.execute("INSERT INTO replays VALUES (?, ?, ?)", ("app:" + claims["app"], claims["nonce"], claims["expires"]))
            existing = self.db.execute("SELECT reference FROM registrations WHERE app=? AND installation=?", (claims["app"], claims["installation"])).fetchone()
            if not existing and self.db.execute("SELECT count(*) FROM registrations").fetchone()[0] >= MAX_REGISTRATIONS:
                raise ValueError("registration capacity reached")
            reference = existing["reference"] if existing else secrets.token_hex(32)
            self.db.execute("""
                INSERT INTO registrations(reference,app,installation,platform,token,management,expires)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(app,installation) DO UPDATE SET
                platform=excluded.platform,token=excluded.token,management=excluded.management,
                expires=excluded.expires,generation=generation+1,attempts=0
            """, (reference, claims["app"], claims["installation"], platform, token, hashlib.sha256(management.encode()).hexdigest(), now + 7 * 86400))
        return {"reference": reference, "management_token": management, "expires": now + 7 * 86400}

    def unregister(self, data):
        if set(data) != {"reference", "management_token"} or not REFERENCE.fullmatch(data["reference"]) or not REFERENCE.fullmatch(data["management_token"]):
            raise ValueError("invalid unregister")
        with self.lock, self.db:
            self.db.execute("DELETE FROM registrations WHERE reference=? AND management=?", (data["reference"], hashlib.sha256(data["management_token"].encode()).hexdigest()))
        return {"accepted": True}

    def event(self, headers, body):
        relay_id = headers.get("x-relay-id", "")
        relay = self.relays.get(relay_id)
        timestamp, nonce = headers.get("x-timestamp", ""), headers.get("x-nonce", "")
        now = int(self.clock())
        if not relay or not timestamp.isdecimal() or len(timestamp) > 12 or abs(int(timestamp) - now) > 300 or not re.fullmatch("[0-9a-f]{32}", nonce):
            raise ValueError("unauthorized relay")
        signed = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
        if not hmac.compare_digest(headers.get("x-signature", ""), sign(relay["key"], b"GCOMS-PUSH-EVENT-v1\0", signed)):
            raise ValueError("unauthorized relay")
        data = json.loads(body)
        if set(data) != {"reference", "activity"} or data["activity"] != "message" or not REFERENCE.fullmatch(data["reference"]):
            raise ValueError("invalid event")
        with self.lock, self.db:
            self.cleanup(now)
            if self.db.execute("SELECT 1 FROM replays WHERE scope=? AND nonce=?", ("relay:" + relay_id, nonce)).fetchone():
                return {"accepted": True}
            # Bound replay storage independently of registration count.
            if self.db.execute("SELECT count(*) FROM replays").fetchone()[0] >= 100000:
                raise ValueError("event capacity reached")
            self.db.execute("INSERT INTO replays VALUES(?,?,?)", ("relay:" + relay_id, nonce, now + 600))
            registration = self.db.execute("SELECT app FROM registrations WHERE reference=?", (data["reference"],)).fetchone()
            if registration and registration["app"] in relay["apps"]:
                self.db.execute("UPDATE registrations SET pending=1,generation=generation+1 WHERE reference=?", (data["reference"],))
        # Unknown registrations have the same reply and are never forwarded.
        return {"accepted": True}

    def dispatch_one(self):
        now = int(self.clock())
        with self.lock, self.db:
            self.cleanup(now)
            row = self.db.execute("SELECT * FROM registrations WHERE pending=1 AND due<=? ORDER BY due LIMIT 1", (now,)).fetchone()
            if row is None:
                return False
            # Reserve before network I/O. One pending row coalesces all new activity.
            self.db.execute("UPDATE registrations SET due=? WHERE reference=?", (now + 30, row["reference"]))
        try:
            result = self.provider.send(dict(row), self.apps[row["app"]]["providers"][row["platform"]])
        except Exception:
            result = DeliveryResult("retry")  # Never log tokens/provider credentials.
        with self.lock, self.db:
            if result.status == "expired":
                self.db.execute("DELETE FROM registrations WHERE reference=? AND generation=?", (row["reference"], row["generation"]))
            elif result.status != "accepted":
                attempts = min(row["attempts"] + 1, 10)
                delay = max(30, min(3600, max(result.retry_after, 2 ** attempts * 15)))
                self.db.execute("UPDATE registrations SET pending=1,due=?,attempts=? WHERE reference=? AND generation=?",
                                (now + delay, attempts, row["reference"], row["generation"]))
            else:
                self.db.execute("UPDATE registrations SET pending=0,attempts=0 WHERE reference=? AND generation=?", (row["reference"], row["generation"]))
        return True
