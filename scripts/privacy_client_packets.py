"""Complete Ethernet observations for one isolated client; no relay counters.

The historical pooled/IP parser intentionally has a separate API and scope.
Classic Ethernet pcap framing is checked independently of the packet decoder.
"""
import csv
from dataclasses import dataclass
import io
import ipaddress
import math
from pathlib import Path
import re
import struct
import subprocess

from privacy_packets import flag

FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
    "eth.src", "eth.dst", "eth.type", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.stream",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
    "tcp.seq_raw", "tcp.len", "tcp.analysis.retransmission", "_ws.malformed",
)


@dataclass(frozen=True)
class Frame:
    number: int
    time: float
    size: int
    direction: str
    protocol: str
    source: tuple
    destination: tuple
    stream: str
    syn: bool
    ack: bool
    rst: bool
    fin: bool
    sequence: str
    retransmission: bool


def pcap_counts(path):
    """Reject truncated files/frames and unsupported encapsulation, not omit them."""
    with Path(path).open("rb") as src:
        header = src.read(24)
        if len(header) != 24:
            raise ValueError("incomplete pcap header")
        magic = header[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("require classic microsecond Ethernet pcap")
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor, linktype) != (2, 4, 1) or snaplen < 65535:
            raise ValueError("unsupported pcap version/link type/snap length")
        count = size = 0
        while raw := src.read(16):
            if len(raw) != 16:
                raise ValueError("incomplete pcap record header")
            _, micros, captured, wire = struct.unpack(endian + "IIII", raw)
            if micros >= 1000000 or captured != wire or not 14 <= wire <= snaplen:
                raise ValueError("truncated or invalid Ethernet frame")
            if len(src.read(captured)) != captured:
                raise ValueError("incomplete pcap frame")
            count += 1
            size += wire
    return {"frames": count, "wire_bytes": size, "snaplen": snaplen,
            "truncated_frames": 0, "linktype": "Ethernet"}


def parse_fields(text, client_mac, fixture_mac):
    mac = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
    if client_mac == fixture_mac or any(not mac.fullmatch(m) for m in (client_mac, fixture_mac)):
        raise ValueError("distinct declared Ethernet MACs required")
    frames = []
    latest = 0.0
    for number, fields in enumerate(csv.reader(io.StringIO(text), delimiter="\t"), 1):
        if len(fields) != len(FIELDS):
            raise ValueError(f"frame {number}: incomplete structured decode")
        r = dict(zip(FIELDS, fields))
        if int(r["frame.number"]) != number or r["_ws.malformed"]:
            raise ValueError(f"frame {number}: omitted or malformed frame")
        timestamp, length = float(r["frame.time_epoch"]), int(r["frame.len"])
        if not math.isfinite(timestamp) or timestamp < 0 or length < 14 or int(r["frame.cap_len"]) != length:
            raise ValueError(f"frame {number}: invalid/truncated observation")
        if latest - timestamp > .010:
            raise ValueError("capture timestamp backstep exceeds 10 ms")
        latest = max(latest, timestamp)
        source_mac, destination_mac = r["eth.src"].lower(), r["eth.dst"].lower()
        if not mac.fullmatch(destination_mac):
            raise ValueError(f"frame {number}: missing Ethernet destination")
        if source_mac == client_mac:
            direction = "up"
        elif source_mac == fixture_mac:
            direction = "down"  # Includes multicast, broadcast, ARP and NDP.
        else:
            raise ValueError(f"frame {number}: undeclared link source {source_mac!r}")
        src, dst = r["ip.src"] or r["ipv6.src"], r["ip.dst"] or r["ipv6.dst"]
        if bool(src) != bool(dst):
            raise ValueError(f"frame {number}: incomplete IP endpoints")
        if src:
            src, dst = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
        tcp = bool(r["tcp.srcport"] or r["tcp.dstport"])
        udp = bool(r["udp.srcport"] or r["udp.dstport"])
        if tcp and (not src or not r["tcp.stream"] or not r["tcp.seq_raw"]):
            raise ValueError(f"frame {number}: incomplete TCP decode")
        ports = (int(r["tcp.srcport"] or r["udp.srcport"] or 0),
                 int(r["tcp.dstport"] or r["udp.dstport"] or 0))
        if (tcp or udp) and any(not 0 < p < 65536 for p in ports):
            raise ValueError(f"frame {number}: invalid ports")
        frames.append(Frame(number, timestamp, length, direction,
                            "tcp" if tcp else "udp" if udp else "ip" if src else "non_ip",
                            (src, ports[0]), (dst, ports[1]), r["tcp.stream"],
                            flag(r["tcp.flags.syn"]), flag(r["tcp.flags.ack"]),
                            flag(r["tcp.flags.reset"]), flag(r["tcp.flags.fin"]),
                            r["tcp.seq_raw"], bool(r["tcp.analysis.retransmission"])))
    return sorted(frames, key=lambda f: (f.time, f.number))


def read_frames(path, client_mac, fixture_mac):
    framing = pcap_counts(path)
    command = ["tshark", "-n", "-r", "-", "-T", "fields", "-E", "separator=/t",
               "-E", "quote=d", "-E", "occurrence=f"]  # NO display/capture filter.
    for field in FIELDS:
        command += ["-e", field]
    with Path(path).open("rb") as src:
        result = subprocess.run(command, stdin=src, capture_output=True, text=True, check=True)
    frames = parse_fields(result.stdout, client_mac, fixture_mac)
    if len(frames) != framing["frames"] or sum(f.size for f in frames) != framing["wire_bytes"]:
        raise ValueError("decoder omitted frames or bytes")
    framing.update(non_ip_frames=sum(f.protocol == "non_ip" for f in frames),
                   up_frames=sum(f.direction == "up" for f in frames),
                   down_frames=sum(f.direction == "down" for f in frames),
                   unattributed_frames=0, malformed_frames=0)
    return frames, framing


def connections(frames, start, end):
    """Bidirectional wire-observed flows, with explicit censoring.

    tcp.stream is decoder-derived from packets, not a private protocol counter.
    Retransmitted opening SYNs stay in one stream; reused tuples have distinct
    stream IDs. Tuple consistency is checked. Missing handshakes remain censored,
    and are never silently counted as successful connections.
    """
    grouped = {}
    for f in frames:
        if f.protocol == "tcp" and start <= f.time <= end:
            grouped.setdefault(f.stream, []).append(f)
    result = []
    for stream, rows in grouped.items():
        endpoints = frozenset((rows[0].source, rows[0].destination))
        if any(frozenset((r.source, r.destination)) != endpoints for r in rows):
            raise ValueError("TCP stream contains inconsistent endpoints")
        opening = [r for r in rows if r.syn and not r.ack]
        if len({(r.source, r.sequence) for r in opening}) > 1:
            raise ValueError("ambiguous SYN/tuple reuse within one decoded TCP stream")
        first = opening[0] if opening else None
        synack = next((r for r in rows if first and r.syn and r.ack
                       and r.source == first.destination and r.time >= first.time), None)
        established = bool(synack and any(r.ack and not r.syn and r.source == first.source
                                         and r.time >= synack.time for r in rows))
        fins = {r.source for r in rows if r.fin}
        reset = any(r.rst for r in rows)
        closed = reset or len(fins) == 2
        result.append({"stream": stream, "first": rows[0].time, "last": rows[-1].time,
                       "observed_seconds": rows[-1].time - rows[0].time,
                       "left_censored": not bool(first), "right_censored": not closed,
                       "opening_syns": len(opening), "syn_retransmissions": max(0, len(opening) - 1),
                       "handshake_observed": established, "reset": reset,
                       "fin_packets": sum(r.fin for r in rows),
                       "setup_refused": bool(first and reset and not established)})
    return result


def observer_features(frames, start, seconds, lifecycle_start, lifecycle_end):
    """Fixed windows plus per-run counts/lower-bound lifetimes from packets only."""
    windows = []
    for i in range(seconds):
        rows = [f for f in frames if start + i <= f.time < start + i + 1]
        up, down = ([r for r in rows if r.direction == d] for d in ("up", "down"))
        windows.append([len(up), len(down), sum(r.size for r in up), sum(r.size for r in down),
                        sum(r.syn and not r.ack for r in rows), sum(r.fin for r in rows),
                        sum(r.rst for r in rows), sum(r.protocol == "non_ip" for r in rows)])
    flows = connections(frames, lifecycle_start, lifecycle_end)
    durations = [f["observed_seconds"] for f in flows]
    counts = [len(flows), sum(f["opening_syns"] > 0 for f in flows),
              sum(f["syn_retransmissions"] for f in flows), sum(f["fin_packets"] for f in flows),
              sum(f["reset"] for f in flows), sum(f["setup_refused"] for f in flows),
              sum(f["left_censored"] for f in flows), sum(f["right_censored"] for f in flows),
              sum(f["handshake_observed"] for f in flows),
              sum(durations) / len(durations) if durations else 0, max(durations, default=0)]
    return {"windows": windows, "connections": counts, "flows": flows,
            "connection_duration_semantics": "observed lower bounds with censoring flags",
            "feature_source": "observed Ethernet packets only"}


def capture_counts(log):
    result = {}
    for key, text in (("captured", "captured"), ("received", "received by filter"),
                      ("dropped", "dropped by kernel")):
        matches = re.findall(r"(?m)^(\d+) packets " + text + r"$", log)
        if len(matches) != 1:
            raise ValueError("missing or ambiguous tcpdump accounting")
        result[key] = int(matches[0])
    return result
