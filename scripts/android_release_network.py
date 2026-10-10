#!/usr/bin/env python3
"""Retain VPN-safe route measurements; only real transfer receipts qualify."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from android_release import write_json


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def routing_horizon(config, required_until):
    """Check real HTTPS-provisioned capability expiry before promotion starts."""
    path = Path(config.get('network_invitation',
                           str(Path(config['hub_home']) / 'network-invitation.txt')))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or not 0 < info.st_size <= 24 * 1024):
            raise ValueError('routing preflight requires the private owner invitation')
        raw = stream.read(24 * 1024 + 1)
        if len(raw) > 24 * 1024: raise ValueError('routing preflight invitation exceeds bounds')
    code = raw.decode('ascii').strip()
    if not code.startswith('GCNI1-'):
        raise ValueError('routing preflight requires a current network invitation')
    try:
        invitation = json.loads(base64.b64decode(code[6:] + '=' * (-len(code[6:]) % 4),
                                               altchars=b'-_', validate=True))
        grant, providers = invitation['grant'], invitation['provider_urls']
        if (type(invitation['expires_at']) is not int or invitation['expires_at'] <= required_until
                or not isinstance(grant, str) or not 0 < len(grant) <= 8192
                or any(ch.isspace() for ch in grant) or not isinstance(providers, list)
                or not 1 <= len(providers) <= 8):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise ValueError('routing preflight invitation is invalid or expires too soon') from None
    # Authenticate the configured HTTPS provider. Never follow a redirect with
    # the invitation grant, persist introductions or log provider errors.
    opener = build_opener(NoRedirect())
    deadline = time.monotonic() + 20
    for provider in providers:
        remaining = deadline - time.monotonic()
        if remaining <= 0: break
        try:
            if not isinstance(provider, str): raise ValueError()
            parsed = urlsplit(provider)
            if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                    or parsed.query or parsed.fragment):
                raise ValueError()
            body = json.dumps({'request_id': secrets.token_urlsafe(16), 'supported_versions': [3]}).encode()
            request = Request(provider.rstrip('/') + '/v1/relay-provisions', data=body,
                              headers={'Authorization': 'Bearer ' + grant, 'Content-Type': 'application/json'})
            with opener.open(request, timeout=min(12, remaining)) as response:
                raw = response.read(4097)
            if len(raw) > 4096: raise ValueError()
            reply = json.loads(raw)
            if (set(reply) != {'version', 'routing_protocol', 'routing_bundle_b64'}
                    or type(reply['version']) is not int or reply['version'] != 3
                    or reply['routing_protocol'] != 'gc2'):
                raise ValueError()
            encoded = reply['routing_bundle_b64']
            if not isinstance(encoded, str) or len(encoded) > 1664: raise ValueError()
            bundle = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
            if (base64.urlsafe_b64encode(bundle).decode().rstrip('=') != encoded
                    or len(bundle) < 6 or bundle[:5] != b'GCRB\2' or not 5 <= bundle[5] <= 8
                    or len(bundle) != 6 + bundle[5] * 155):
                raise ValueError()
            now = time.time()
            addresses, pins, expiries = set(), set(), []
            for offset in range(6, len(bundle), 155):
                row = bundle[offset:offset + 155]
                authorities = [row[i:i + 32] for i in (19, 51, 83, 115)]
                expiry = int.from_bytes(row[147:], 'big')
                if (row[0] != 4 or any(row[5:17]) or not any(row[17:19])
                        or not ipaddress.ip_address(row[1:5]).is_global
                        or any(not any(authority) for authority in authorities)
                        or len(set(authorities[1:])) != 3 or authorities[0] in pins
                        or not required_until <= expiry <= now + 86400):
                    raise ValueError()
                addresses.add(row[1:5]); pins.add(authorities[0]); expiries.append(expiry)
            if len(addresses) < 5: raise ValueError()
            return {'checked_at': now, 'routing_expiry_unix': min(expiries),
                    'distinct_relays': len(addresses), 'required_until': required_until}
        except (OSError, ValueError, KeyError, TypeError):
            continue
    raise ValueError('fresh authenticated GC/2 routing does not cover the deployment window')


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
