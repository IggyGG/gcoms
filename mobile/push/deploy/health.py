"""No provider call, registration or secret output; test local service refusal."""
import http.client
import json
import sqlite3
import sys


def check(ready=False, port=8791, database="/state/push/push.sqlite"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("POST", "/v1/register", b"{}", {"Content-Type": "application/json"})
        reply = connection.getresponse()
        if reply.status != 400 or json.loads(reply.read(256)) != {"error": "request rejected"}:
            raise ValueError("gateway refusal check failed")
    finally:
        connection.close()
    if ready:
        with sqlite3.connect("file:" + database + "?mode=ro", uri=True, timeout=1) as db:
            names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"registrations", "registration_revisions", "replays"}.issubset(names):
                raise ValueError("gateway state not initialized")


if __name__ == "__main__":
    try:
        check("--ready" in sys.argv)
    except Exception:
        raise SystemExit("gateway health check failed") from None
