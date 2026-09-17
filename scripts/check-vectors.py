#!/usr/bin/env python3
"""Independent GC/1 cell decoder for language-neutral fixtures; no Rust imports."""
import json
from pathlib import Path

def decode(raw):
    if len(raw) not in (256, 1024, 4096, 16384):
        raise ValueError("bucket")
    version, kind = raw[0] >> 4, raw[0] & 15
    length = int.from_bytes(raw[4:6], "big")
    if version != 1 or kind > 9 or length > len(raw) - 6 or any(raw[6+length:]):
        raise ValueError("invalid cell")
    return {"type": kind, "flags": raw[1], "round": int.from_bytes(raw[2:4], "big"), "payload_hex": raw[6:6+length].hex()}

path = Path(__file__).resolve().parents[1] / "crates/conformance/vectors/cells.json"
fixtures = json.loads(path.read_text())["vectors"]
for fixture in fixtures:
    try:
        value = decode(bytes.fromhex(fixture["hex"]))
    except ValueError:
        assert not fixture["valid"], fixture["name"]
    else:
        assert fixture["valid"], fixture["name"]
        assert value == {key: fixture[key] for key in value}, fixture["name"]
print(f"{len(fixtures)} independent cell fixtures passed")
