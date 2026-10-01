"""Owner-approved feature-release allowance; stable SDKs retain a 5% cap."""
import hashlib
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def policy_for_version(version):
    if not isinstance(version, str) or not re.fullmatch(
            r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
        raise ValueError('SDK size policy requires an explicit semantic version')
    stable = int(version.split('.', 1)[0]) >= 1
    return {'schema': 1, 'sdk_version': version,
            'limit_percent': 5 if stable else 20,
            'scope': 'stable SDK regression' if stable else 'initial feature release',
            'approved_on': '2026-10-01'}


def current_policy(root=ROOT):
    package = tomllib.loads((root / 'crates/sdk/Cargo.toml').read_text())['package']
    version = package['version']
    if isinstance(version, dict) and version == {'workspace': True}:
        version = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    result = policy_for_version(version)
    result['policy_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def exceeds_limit(current, previous, policy):
    # Integer comparison makes the exact boundary identical on every platform.
    if type(current) is not int or type(previous) is not int or current < 0 or previous <= 0:
        raise ValueError('size comparisons require nonnegative measured bytes and a positive baseline')
    if policy['limit_percent'] != policy_for_version(policy['sdk_version'])['limit_percent']:
        raise ValueError('size ceiling differs from the SDK version policy')
    return current * 100 > previous * (100 + policy['limit_percent'])
