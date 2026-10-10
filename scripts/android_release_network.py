#!/usr/bin/env python3
"""Retain VPN-safe route measurements; only real transfer receipts qualify."""
import argparse
import json
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit

from android_release import write_json


def measure(url, size=8 * 1024 * 1024, timeout=20):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('network probe requires an ordinary HTTPS endpoint')
    result = subprocess.run(['curl', '--silent', '--output', '/dev/null', '--range', '0-' + str(size - 1),
        '--max-time', str(timeout), '--write-out', '%{http_code} %{size_download} %{time_total} %{speed_download}', url],
        capture_output=True, timeout=timeout + 2)
    status, received, seconds, rate = result.stdout.decode().split()
    return {'endpoint': parsed.hostname, 'exit_code': result.returncode, 'http_status': int(status),
            'received_bytes': int(float(received)), 'elapsed_seconds': float(seconds),
            'bytes_per_second': float(rate), 'complete': result.returncode == 0 and float(received) >= size}


def vpn():
    value = json.loads(subprocess.check_output(['mullvad', 'status', '--json'], timeout=5))
    # Never retain account, keys, addresses or the private daemon configuration.
    if value.get('state') != 'connected':
        raise ValueError('network qualification requires Mullvad to remain connected')
    return {'state': value['state'], 'relay': value.get('details', {}).get('location', {}).get('hostname')}


def reference(receipt, inputs, now=None):
    now = time.time() if now is None else now
    observed = receipt.get('observed_at', 0)
    if (receipt.get('schema') != 1 or receipt.get('kind') != 'android-runtime-qualification'
            or receipt.get('inputs') != inputs or type(observed) not in (int, float)
            or not 0 <= now - observed <= 86400
            or receipt.get('vpn', {}).get('state') != 'connected'):
        raise ValueError('Android runtime qualification is stale or belongs to other inputs')
    android = receipt.get('android', {})
    if any(android.get(key) is not True for key in ('full_download_verified', 'loaded_worker_ready',
                                                   'identity_preserved', 'resume_verified')):
        raise ValueError('Android download, resume and loaded worker qualification missing')
    bulk = receipt.get('reference_transfer', {})
    elapsed = bulk.get('elapsed_seconds', 0)
    if (type(bulk.get('bytes')) is not int or bulk['bytes'] < 42 * 1024 * 1024
            or type(elapsed) not in (int, float) or not 0 < elapsed <= 360
            or bulk.get('sha256_verified') is not True or bulk.get('current_process_verified') is not True):
        raise ValueError('real 42 MiB Android reference transfer exceeds the release budget')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--url', action='append', required=True)
    args = parser.parse_args()
    before = vpn()
    rows = [measure(url) for url in args.url]
    after = vpn()
    write_json(args.output, {'schema': 1, 'observed_at': time.time(), 'vpn_before': before,
        'vpn_after': after, 'probes': rows, 'android_runtime_qualified': False,
        'scope': 'HTTPS route diagnostics; does not qualify relay delivery or Android loading'})
