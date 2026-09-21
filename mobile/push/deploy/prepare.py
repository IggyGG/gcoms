"""Copy projected Kubernetes credentials to owner-private files in RAM."""
import json
import os
from pathlib import Path
import re
import sys


def prepare(source, destination):
    source, destination = Path(source).resolve(), Path(destination)
    config = source / "config.json"
    if not config.resolve().is_relative_to(source) or config.stat().st_size > 16384:
        raise ValueError("invalid private configuration")
    value = json.loads(config.read_text())
    if value.get("public_origin") != "https://push.gchat.boo" or set(value.get("apps", {})) != {"boo.gchat.app"}:
        raise ValueError("invalid application scope")
    providers = value["apps"]["boo.gchat.app"].get("providers", {})
    if not providers or set(providers) - {"apns", "fcm"}:
        raise ValueError("invalid provider selection")
    files = {"config.json"}
    if "apns" in providers:
        apns = providers["apns"]
        if apns.get("topic") != "boo.gchat.app" or apns.get("sandbox", False) is not False or apns.get("private_key_file") != "/private/current/apns.p8":
            raise ValueError("invalid APNs scope")
        files.add("apns.p8")
    if "fcm" in providers:
        fcm = providers["fcm"]
        if fcm.get("project_id") != "gchat-23115" or fcm.get("service_account_file") != "/private/current/fcm.json":
            raise ValueError("invalid FCM scope")
        files.add("fcm.json")
    keys = set()
    relays = value.get("relays", {})
    if not relays or len(relays) > 256:
        raise ValueError("invalid relay count")
    for name, relay in relays.items():
        key = relay.get("key", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name) or relay.get("apps") != ["boo.gchat.app"] or not re.fullmatch(r"[0-9a-f]{64}", key) or key == "0" * 64 or key in keys:
            raise ValueError("invalid relay scope or key")
        keys.add(key)
    contents = {}
    for name in files:
        path = source / name
        if not path.resolve().is_relative_to(source) or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError("invalid private input")
        contents[name] = path.read_bytes()
    destination.mkdir(mode=0o700)  # Refuse stale/reused private state.
    try:
        for name, content in contents.items():
            with (destination / name).open("xb") as out:
                os.chmod(out.fileno(), 0o600)
                out.write(content)
    except BaseException:
        for path in destination.iterdir():
            path.unlink()
        destination.rmdir()
        raise


if __name__ == "__main__":
    os.umask(0o077)
    try:
        prepare("/input", "/private/current")
    except Exception:
        raise SystemExit("private push configuration rejected") from None
