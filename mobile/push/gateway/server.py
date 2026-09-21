#!/usr/bin/env python3
"""Run behind the application operator's HTTPS reverse proxy."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from gateway import Gateway, MAX_REQUEST, NAME
from providers import Providers


def serve(config, database, port):
    apps, relays = config["apps"], config["relays"]
    for app_id, app in apps.items():
        if not NAME.fullmatch(app_id): raise ValueError("invalid app id")
        app["registration_key"] = bytes.fromhex(app["registration_key"])
        if len(app["registration_key"]) != 32: raise ValueError("registration key must be 32 bytes")
        for name, provider in app["providers"].items():
            if name not in ("apns", "fcm"): raise ValueError("invalid provider")
            if name == "fcm" and not NAME.fullmatch(provider["project_id"]): raise ValueError("invalid project id")
    for relay_id, relay in relays.items():
        if not NAME.fullmatch(relay_id): raise ValueError("invalid relay id")
        relay["key"] = bytes.fromhex(relay["key"])
        if len(relay["key"]) != 32 or not set(relay["apps"]).issubset(apps): raise ValueError("invalid relay scope")
    gateway = Gateway(database, apps, relays, Providers())
    slots = threading.BoundedSemaphore(32)
    stop = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(10)
            super().setup()
        def log_message(self, *_):
            pass  # Credentials and references must not enter access logs.
        def do_POST(self):
            try:
                if self.headers.get("Transfer-Encoding"): raise ValueError("length required")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_REQUEST: raise ValueError("invalid length")
                body = self.rfile.read(length)
                if len(body) != length: raise ValueError("truncated body")
                data = json.loads(body)
                if self.path == "/v1/register": reply = gateway.register(data)
                elif self.path == "/v1/unregister": reply = gateway.unregister(data)
                elif self.path == "/v1/events": reply = gateway.event(dict((k.lower(), v) for k, v in self.headers.items()), body)
                else: raise ValueError("unknown endpoint")
                status = 200
            except (ValueError, KeyError, TypeError, sqlite3.IntegrityError, OverflowError):
                status, reply = 400, {"error": "request rejected"}
            encoded = json.dumps(reply).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        def process_request(self, request, address):
            if not slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try: super().process_request(request, address)
            except BaseException:
                slots.release()
                raise
        def process_request_thread(self, request, address):
            try: super().process_request_thread(request, address)
            finally: slots.release()
    def dispatch():
        while not stop.is_set():
            try: gateway.dispatch_one()
            except Exception: pass
            stop.wait(0.25)
    worker = threading.Thread(target=dispatch, name="push-provider")
    worker.start()
    server = Server(("127.0.0.1", port), Handler)
    try: server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        worker.join()
        gateway.db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args()
    os.umask(0o077)
    args.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.state.is_symlink() or (os.name == "posix" and args.state.stat().st_mode & 0o077):
        raise SystemExit("gateway state must be private")
    if os.name == "posix" and args.config.stat().st_mode & 0o077:
        raise SystemExit("gateway config must be private")
    serve(json.loads(args.config.read_text()), args.state / "push.sqlite", args.port)
