#!/usr/bin/env python3
"""Run the production-profile bootstrap journey without any external network.

The compiled Rust test runs as the invoking user. Root only creates a temporary
network namespace and assigns fixture addresses to its loopback interface.
No host interface, firewall, service or persistent namespace is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

TEST = "bootstrap::gc2_tests::production_bootstrap_fresh_reopen_and_recovery"
ADDRESSES = [f"93.184.216.{n}/32" for n in range(71, 75)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def namespace():
    return os.readlink("/proc/self/ns/net")


def links():
    return sorted((item["ifindex"], item["ifname"])
                  for item in json.loads(subprocess.check_output(["ip", "-j", "link"])))


def worker(args):
    if os.geteuid() != 0 or args.uid <= 0 or namespace() == args.host_namespace:
        raise RuntimeError("worker requires a separate namespace and an unprivileged test user")
    if [name for _, name in links()] != ["lo"]:
        raise RuntimeError("fixture namespace must contain only loopback")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    for address in ADDRESSES:
        subprocess.run(["ip", "address", "add", address, "dev", "lo"], check=True)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("GC_", "GCOMS_", "GCHAT_"))}
    environment["GCHAT_BOOTSTRAP_NAMESPACE"] = "isolated"
    environment["GCHAT_BOOTSTRAP_HOST_NAMESPACE"] = args.host_namespace
    environment["TMPDIR"] = str(args.scratch)

    def unprivileged():
        os.setgroups([])
        os.setgid(args.gid)
        os.setuid(args.uid)

    command = [str(args.binary), TEST, "--ignored", "--exact", "--nocapture", "--test-threads=1"]
    print(json.dumps({"namespace": namespace(), "addresses": ADDRESSES,
                      "test_uid": args.uid, "test": TEST}), flush=True)
    process = subprocess.Popen(command, env=environment, start_new_session=True,
                               preexec_fn=unprivileged)
    try:
        return process.wait(timeout=args.timeout)
    finally:
        # Also reap any surviving descendants after success or failure.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=420)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--uid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--gid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--host-namespace", help=argparse.SUPPRESS)
    parser.add_argument("--scratch", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    if args.worker:
        return worker(args)
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("invoke as an ordinary Linux user with sudo -n access")
    if not 1 <= args.timeout <= 600:
        parser.error("timeout must be between 1 and 600 seconds")
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    scratch = output / "scratch"
    scratch.mkdir(mode=0o700)
    before = links()
    binary_hash = digest(args.binary)
    host = namespace()
    command = ["sudo", "-n", "timeout", "--signal=TERM", "--kill-after=5s",
               str(args.timeout + 15), "unshare", "--net", "--", sys.executable,
               str(Path(__file__).resolve()), "--worker", "--binary", str(args.binary),
               "--output", str(output), "--timeout", str(args.timeout),
               "--uid", str(os.getuid()), "--gid", str(os.getgid()),
               "--host-namespace", host, "--scratch", str(scratch)]
    started = time.monotonic()
    with (output / "test.log").open("x") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
    content = (output / "test.log").read_text()
    report = {
        "scope": "local production-profile HTTPS bootstrap; no fleet or privacy qualification",
        "test": TEST, "binary_sha256": binary_hash,
        "script_sha256": digest(Path(__file__)), "exit_code": result.returncode,
        "seconds": time.monotonic() - started,
        "test_passed": "test result: ok. 1 passed; 0 failed;" in content,
        "binary_unchanged": digest(args.binary) == binary_hash,
        "host_namespace_unchanged": namespace() == host,
        "host_interfaces_unchanged": links() == before,
    }
    report["passed"] = result.returncode == 0 and all(report[key] for key in (
        "test_passed", "binary_unchanged", "host_namespace_unchanged", "host_interfaces_unchanged"))
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
