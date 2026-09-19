"""Structured packet observations; never parse tcpdump prose."""
import csv
import hashlib
import io
import ipaddress
import math
import os
from pathlib import Path
import subprocess
from typing import NamedTuple


class Packet(NamedTuple):
    time: float
    source: tuple
    destination: tuple
    wire_bytes: int
    payload_bytes: int
    syn: bool
    ack: bool
    rst: bool
    sequence: str
    retransmission: bool


FIELDS = (
    "frame.time_epoch", "frame.len", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.seq_raw",
    "tcp.analysis.retransmission", "_ws.malformed",
)


def flag(value):
    # Wireshark releases export boolean fields as either numbers or words.
    if value in ("1", "True", "true"):
        return True
    if value in ("", "0", "False", "false"):
        return False
    raise ValueError(f"invalid packet flag: {value!r}")


def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def endpoint(value):
    host, port = value.rsplit(":", 1)
    host = str(ipaddress.ip_address(host.strip("[]")))
    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("invalid endpoint port")
    return host, port


def parse_fields(text):
    packets = []
    latest = 0.0
    for line, fields in enumerate(csv.reader(io.StringIO(text), delimiter="\t"), 1):
        if len(fields) != len(FIELDS):
            raise ValueError(f"packet {line}: incomplete structured fields")
        row = dict(zip(FIELDS, fields))
        if row["_ws.malformed"]:
            raise ValueError(f"packet {line}: malformed packet")
        source = row["ip.src"] or row["ipv6.src"]
        destination = row["ip.dst"] or row["ipv6.dst"]
        timestamp = float(row["frame.time_epoch"])
        length = int(row["frame.len"])
        if not math.isfinite(timestamp) or timestamp < 0 or length <= 0:
            raise ValueError(f"packet {line}: invalid time or length")
        # Parallel capture queues can export adjacent frames out of timestamp
        # order (observed even at one microsecond on loopback). Normalize small
        # queue reordering; reject larger clock discontinuities explicitly.
        if latest - timestamp > .010:
            raise ValueError("capture timestamp backstep exceeds 10 ms")
        latest = max(latest, timestamp)
        packets.append(Packet(
            timestamp,
            (str(ipaddress.ip_address(source)), int(row["tcp.srcport"] or row["udp.srcport"] or 0)),
            (str(ipaddress.ip_address(destination)), int(row["tcp.dstport"] or row["udp.dstport"] or 0)),
            length, int(row["tcp.len"] or 0), flag(row["tcp.flags.syn"]),
            flag(row["tcp.flags.ack"]), flag(row["tcp.flags.reset"]),
            row["tcp.seq_raw"], bool(row["tcp.analysis.retransmission"]),
        ))
    return sorted(packets, key=lambda packet: packet.time)


def packets(path):
    command = ["tshark", "-n", "-r", "-", "-Y", "ip or ipv6", "-T", "fields",
               "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        command += ["-e", field]
    # A read-only descriptor also works when a sandboxed decoder cannot open
    # removable-media/worktree paths itself; no elevated decoder is necessary.
    with Path(path).open("rb") as source:
        result = subprocess.run(command, stdin=source, capture_output=True, text=True, check=True)
    return parse_fields(result.stdout)


def direction(packet, observer_ips, entry=None):
    if observer_ips:
        source = packet.source[0] in observer_ips
        destination = packet.destination[0] in observer_ips
        if source and destination:
            raise ValueError("ambiguous observer: both endpoints share its address")
        return "up" if source else "down" if destination else None
    # Explicit diagnostic support for historical pooled-client entry captures.
    if entry:
        if packet.destination == entry:
            return "up"
        if packet.source == entry:
            return "down"
    return None


def new_connections(rows):
    # SYN+ACK is a response; retransmitted SYNs are not new connections.
    return len({(p.source, p.destination, p.sequence)
                for p in rows if p.syn and not p.ack})


def write_new(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(text)
