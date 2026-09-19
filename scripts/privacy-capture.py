#!/usr/bin/env python3
"""Capture real endpoint packet behavior for the GC/2 privacy gate.

Each run executes the performance harness inside its own network namespace
(`sudo -n unshare -n`), so a capture on that namespace's loopback contains
exactly the harness traffic - no other workstation processes. One run writes a
pcap plus a metadata JSON next to it.

Usage:
  privacy-capture.py --binary PATH --out DIR --workload idle|chat|bulk
                     [--profile gc2|gc1] [--protected] [--seed N]
                     [--seconds 30] [--bytes 8192]
"""
import argparse
import hashlib
import json
import shlex
import subprocess
import time
from pathlib import Path

PORT_A = 27101
PORT_B = 27102


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workload", choices=("idle", "chat", "bulk", "mixed", "warm_idle"), required=True)
    parser.add_argument("--profile", choices=("gc1", "gc2", "gchat-files"), default="gc2")
    parser.add_argument("--protected", action="store_true")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--bytes", type=int, default=8192, help="matched application byte volume")
    parser.add_argument("--chat-interval-ms", type=int, default=500)
    parser.add_argument("--cadence", choices=("compressed", "production"), default="compressed")
    parser.add_argument("--timeout", type=int, default=600)
    return parser.parse_args()


def harness_args(args):
    command = [
        str(args.binary),
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--cadence",
        args.cadence,
        "--skip-single",
        "--drain-ms",
        "0",
        "--listen-a",
        str(PORT_A),
        "--listen-b",
        str(PORT_B),
        "--timeout",
        str(args.timeout),
    ]
    if args.protected and args.profile in ("gc2", "gchat-files"):
        command.append("--protected")
    if args.profile == "gchat-files":
        if not args.protected or args.cadence != "production" or args.workload == "warm_idle":
            raise ValueError("gchat-files requires protected production cadence and idle/chat/bulk/mixed")
        command += ["--measurement-ms", str(args.seconds * 1000)]
        if args.workload in ("chat", "mixed"):
            command += ["--chat-count", str(max(1, args.bytes // 128)), "--chat-bytes", "128",
                        "--chat-interval-ms", str(args.chat_interval_ms)]
        if args.workload in ("bulk", "mixed"):
            command += ["--bulk-bytes", str(max(1024, args.bytes)), "--bulk-chunk", "1024"]
        return command
    if args.workload == "idle":
        command += ["--idle-ms", str(args.seconds * 1000)]
    elif args.workload == "warm_idle":
        # One warm-up exchange, then idle on the established (warm) circuits.
        command += ["--chat-count", "1", "--chat-bytes", "128", "--chat-interval-ms", "0",
                    "--idle-ms", str(args.seconds * 1000)]
    elif args.workload == "chat":
        count = max(1, args.bytes // 128)
        command += ["--chat-count", str(count), "--chat-bytes", "128",
                    "--chat-interval-ms", str(args.chat_interval_ms)]
    else:
        chunk = 1024
        command += ["--bulk-bytes", str(max(chunk, args.bytes)),
                    "--bulk-chunk", str(chunk)]
    return command


def main():
    args = parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = f"{args.workload}-{args.profile}-{args.seed}"
    pcap = (args.out / f"{stamp}.pcap").resolve()
    record = (args.out / f"{stamp}.json").resolve()
    if pcap.exists() or record.with_suffix(".meta.json").exists():
        raise FileExistsError("capture already exists; use a fresh run seed/output directory")
    command = harness_args(args)
    # The namespace contains only the harness, so capture all TCP; the relay
    # circuits are part of the endpoint behaviour under study. Disable loopback
    # offloads so recorded segment sizes reflect real wire segments.
    inner = (
        "set -e; ip link set lo up; "
        "command -v ethtool >/dev/null && ethtool -K lo tso off gso off gro off >/dev/null 2>&1 || true; "
        f"tcpdump -i lo -s 96 -B 4096 --time-stamp-precision=micro -w {shlex.quote(str(pcap))} tcp & "
        "TPID=$!; trap 'kill -INT $TPID 2>/dev/null || true; wait $TPID 2>/dev/null || true' EXIT; sleep 2; "
        + shlex.join(command)
        + f" > {shlex.quote(str(record) + '.stdout')} 2>{shlex.quote(str(record) + '.stderr')}"
    )
    started = time.time()
    result = subprocess.run(["sudo", "-n", "unshare", "-n", "--",
                             "bash", "-c", inner],
                            capture_output=True, text=True, timeout=args.timeout + 120)
    finished = time.time()
    stdout_path = Path(str(record) + ".stdout")
    stdout_text = stdout_path.read_text() if stdout_path.exists() else ""
    record_value = None
    for line in stdout_text.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                record_value = json.loads(line)
            except json.JSONDecodeError:
                pass
    idle_start = next(
        (line.split()[1] for line in stdout_text.splitlines() if line.startswith("IDLE_START ")),
        None,
    )
    metadata = {
        "workload": args.workload,
        "profile": args.profile,
        "protected": args.protected,
        "seed": args.seed,
        "seconds": args.seconds,
        "bytes": args.bytes,
        "chat_interval_ms": args.chat_interval_ms if args.profile == "gchat-files" or args.workload == "chat" else None,
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "cadence": args.cadence,
        "command": command,
        "inner_rc": result.returncode,
        "wall_seconds": round(finished - started, 3),
        "stderr_tail": result.stderr[-400:],
        "pcap": pcap.name,
        "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest() if pcap.exists() else None,
        "record": record_value,
        "idle_start_epoch": idle_start,
        "measurement_start_epoch": next((float(line.split()[1]) for line in stdout_text.splitlines()
                                          if line.startswith("MEASUREMENT_START ")), None),
        "measurement_end_epoch": next((float(line.split()[1]) for line in stdout_text.splitlines()
                                        if line.startswith("MEASUREMENT_END ")), None),
    }
    (args.out / f"{stamp}.meta.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({k: metadata[k] for k in
                      ("workload", "profile", "seed", "inner_rc", "wall_seconds", "pcap_sha256")}))
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
