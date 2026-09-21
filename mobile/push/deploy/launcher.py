"""Deployment-only graceful signal adapter for the unchanged gateway server."""
import json
import os
from pathlib import Path
import signal
from server import serve


def terminate(*_):
    raise KeyboardInterrupt


def run(config=Path("/private/current/config.json"), state=Path("/state/push"), port=8791):
    os.umask(0o077)
    state.mkdir(mode=0o700, exist_ok=True)
    if state.is_symlink() or state.stat().st_mode & 0o077:
        raise SystemExit("gateway state must be private")
    signal.signal(signal.SIGTERM, terminate)
    try:
        serve(json.loads(config.read_text()), state / "push.sqlite", port)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
