#!/usr/bin/env python3
"""Capture all traffic in a disposable pooled loopback fixture for diagnosis.

This is NOT an isolated client observation and cannot qualify a privacy release.
The strict classifier rejects its scope. Shell interpolation is never used,
children are cleaned up, failed workloads and capture loss remain in evidence,
and existing captures cannot be overwritten.
"""
import argparse
import sys
from privacy_packets import sha256, write_new
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
    parser.add_argument("--traffic-profile")
    parser.add_argument("--entries", type=int, default=2)
    parser.add_argument("--warmup-ms", type=int, default=3000)
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
    command += ["--entries", str(args.entries), "--warmup-ms", str(args.warmup_ms)]
    if args.traffic_profile:
        command += ["--traffic-profile", args.traffic_profile]
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


def namespace_worker(spec):
    """Run capture and workload with guaranteed cleanup inside unshare."""
    import os
    import select
    import signal
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    tcpdump = application = None
    result = {"inner_rc": 1, "capture_returncode": None, "dropped_packets": None}
    def stop(process, sig=signal.SIGTERM):
        if process is None or process.poll() is not None:
            return
        process.send_signal(sig)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    try:
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True)
        try:
            offload = subprocess.run(["ethtool", "-K", "lo", "tso", "off", "gso", "off", "gro", "off"], capture_output=True)
            result["offloads_disabled"] = offload.returncode == 0
        except FileNotFoundError:
            result["offloads_disabled"] = False
        with open(spec["pcap"], "wb") as capture, open(spec["stdout"], "wb") as stdout, open(spec["stderr"], "wb") as stderr:
            tcpdump = subprocess.Popen(["tcpdump", "-n", "-U", "-i", "lo", "-s", "0", "-B", "4096",
                                        "--time-stamp-precision=micro", "-w", "-"],
                                       stdout=capture, stderr=subprocess.PIPE, bufsize=0)
            initial_log = b""
            deadline = time.monotonic() + 10
            ready = False
            while time.monotonic() < deadline and tcpdump.poll() is None:
                if select.select([tcpdump.stderr], [], [], .5)[0]:
                    line = tcpdump.stderr.readline()
                    initial_log += line
                    if b"listening on" in line:
                        ready = True
                        break
            if not ready:
                raise RuntimeError("packet capture never became ready")
            result["capture_started_epoch"] = time.time()
            application = subprocess.Popen(spec["command"], stdout=stdout, stderr=stderr)
            try:
                result["inner_rc"] = application.wait(timeout=spec["timeout"])
            except subprocess.TimeoutExpired:
                result["failure"] = "application timed out"
                stop(application)
                result["inner_rc"] = application.returncode
            finally:
                stop(tcpdump, signal.SIGINT)
                result["capture_finished_epoch"] = time.time()
                result["capture_returncode"] = tcpdump.returncode
                log = (initial_log + tcpdump.stderr.read()).decode(errors="replace")
                result["capture_log"] = log
                import re
                drops = re.search(r"(\d+) packets dropped by kernel", log)
                result["dropped_packets"] = int(drops.group(1)) if drops else None
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["failure"] = str(error)
    except KeyboardInterrupt:
        result["failure"] = "capture interrupted"
    finally:
        stop(application)
        stop(tcpdump, signal.SIGINT)
    return result


def main():
    args = parse_args()
    if min(args.seconds, args.bytes, args.timeout) <= 0:
        raise ValueError("duration and volume must be positive")
    args.binary = args.binary.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = f"{args.workload}-{args.profile}-{args.seed}"
    paths = {key: (args.out / (stamp + suffix)).resolve() for key, suffix in
             (("pcap", ".pcap"), ("stdout", ".stdout"), ("stderr", ".stderr"), ("meta", ".meta.json"))}
    if any(path.exists() for path in paths.values()):
        raise ValueError("capture exists; use a new seed or output directory")
    for key in ("pcap", "stdout", "stderr"):
        write_new(paths[key], "")
    command = harness_args(args)
    binary_hash = sha256(args.binary)
    spec = {key: str(paths[key]) for key in ("pcap", "stdout", "stderr")}
    spec.update(command=command, timeout=args.timeout)
    started = time.time()
    try:
        result = subprocess.run(["sudo", "-n", "unshare", "-n", "--", sys.executable,
                                 str(Path(__file__).resolve()), "--namespace-worker"],
                                input=json.dumps(spec), capture_output=True, text=True,
                                timeout=args.timeout + 45)
        worker = json.loads(result.stdout) if result.stdout.strip() else {"inner_rc": 1}
        worker["worker_returncode"] = result.returncode
        worker["worker_stderr"] = result.stderr[-2000:]
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        worker = {"inner_rc": 1, "failure": str(error)}
    finished = time.time()
    output = paths["stdout"].read_text(errors="replace")
    record = None
    for line in output.splitlines():
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                pass
    marker = "IDLE_START " if args.profile != "gchat-files" and args.workload in ("idle", "warm_idle") else "MEASUREMENT_START "
    start = next((float(line.split()[1]) for line in output.splitlines() if line.startswith(marker)), None)
    measured_end = next((float(line.split()[1]) for line in output.splitlines()
                         if line.startswith("MEASUREMENT_END ")), None)
    duration = min(args.seconds, int(worker.get("capture_finished_epoch", finished) - start)) if start else 0
    metadata = {
        "schema": 2, "capture_scope": "pooled_loopback_fixture", "diagnostic_only": True,
        "workload": args.workload, "profile": args.profile, "seed": args.seed,
        "protected": args.protected, "traffic_profile": args.traffic_profile, "entries": args.entries,
        "seconds": args.seconds, "bytes": args.bytes, "cadence": args.cadence,
        "command": command, "wall_seconds": finished - started,
        "binary_sha256": binary_hash, "capture_script_sha256": sha256(__file__),
        "pcap": paths["pcap"].name, "pcap_sha256": sha256(paths["pcap"]),
        "record": record,
        "measurement_start_epoch": start, "measurement_end_epoch": measured_end,
        "chat_interval_ms": args.chat_interval_ms,
        "measurement": {"start_epoch": start, "end_epoch": start + duration} if start and duration > 0 else None,
        "idle_start_epoch": start if marker == "IDLE_START " else None,
        **worker,
    }
    if sha256(args.binary) != binary_hash:
        metadata.update(inner_rc=1, failure="executable changed during capture")
    metadata["workload_returncode"] = worker.get("inner_rc")
    if metadata.get("capture_returncode") != 0 or metadata.get("dropped_packets") != 0:
        metadata.update(inner_rc=1, failure=metadata.get("failure") or "incomplete capture or packet loss")
    write_new(paths["meta"], json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    print(json.dumps({key: metadata.get(key) for key in ("workload", "seed", "inner_rc", "failure", "dropped_packets", "pcap_sha256")}))
    return 0 if metadata.get("inner_rc") == 0 and metadata.get("capture_returncode") == 0 and metadata.get("dropped_packets") == 0 else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--namespace-worker"]:
        result = namespace_worker(json.load(sys.stdin))
        print(json.dumps(result))
        raise SystemExit(0 if result.get("inner_rc") == 0 else 1)
    raise SystemExit(main())
