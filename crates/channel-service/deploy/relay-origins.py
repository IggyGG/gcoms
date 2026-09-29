#!/usr/bin/env python3
"""Add operator-selected hosted HTTPS origins to one native relay.

Run on one host at a time after authenticating its SSH host key. Without --apply
this prints the exact proposed configuration. No executable, identity or retained
relay state is replaced. A failed restart restores this script's new drop-in only.
"""
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import time


def status():
    text = subprocess.check_output(['systemctl', 'show', 'ghost-relay.service',
                                    '-p', 'MainPID', '-p', 'ActiveState', '-p', 'NRestarts'], text=True)
    return dict(line.split('=', 1) for line in text.splitlines())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', action='append', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    before = status()
    if before['ActiveState'] != 'active' or before['MainPID'] == '0':
        raise RuntimeError('existing relay must be active')
    environment = Path('/proc', before['MainPID'], 'environ').read_bytes().split(b'\0')
    current = next((v.decode().split('=', 1)[1] for v in environment
                    if v.startswith(b'GC_CATALOG_ORIGINS=')), '')
    origins = sorted(set(filter(None, current.split(','))) | set(args.origin))
    if len(origins) > 8 or any(not re.fullmatch(r'[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?', host)
                             or '..' in host for host in origins):
        raise ValueError('invalid bounded hostname allowlist')
    path = Path('/etc/systemd/system/ghost-relay.service.d/60-hosted-origins.conf')
    if path.exists():
        raise FileExistsError('task drop-in already exists; inspect it before making another change')
    config = '[Service]\nEnvironment=GC_CATALOG_ORIGINS=' + ','.join(origins) + '\n'
    report = {'before': before, 'previous_origins': current, 'origins': origins,
              'dropin': str(path), 'configuration': config, 'applied': False}
    if not args.apply:
        print(json.dumps(report))
        return
    path.parent.mkdir(mode=0o755, exist_ok=True)
    with path.open('x') as stream:
        stream.write(config)
    path.chmod(0o644)
    try:
        subprocess.run(['systemd-analyze', 'verify', 'ghost-relay.service'], check=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'restart', 'ghost-relay.service'], check=True, timeout=60)
        deadline = time.monotonic() + 30
        while True:
            after = status()
            if after['ActiveState'] == 'active' and after['MainPID'] != before['MainPID']:
                try:
                    with socket.create_connection(('127.0.0.1', 4433), timeout=1):
                        break
                except OSError:
                    pass
            if time.monotonic() >= deadline:
                raise TimeoutError('relay did not restore its listener')
            time.sleep(1)
        time.sleep(5)
        after = status()
        if after['ActiveState'] != 'active' or after['NRestarts'] != '0':
            raise RuntimeError('relay did not remain active')
        report.update(applied=True, after=after,
                      qualification='unit/listener only; protected application journey still required')
    except Exception:
        path.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'restart', 'ghost-relay.service'], check=True, timeout=60)
        raise
    print(json.dumps(report))


if __name__ == '__main__':
    main()
