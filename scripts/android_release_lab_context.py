"""Validate the private runtime mapping for an isolated Kubernetes lab guest."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid

ROOT = Path('/home/lab/.local/state/android-cluster-release')
FIELDS = {'schema', 'vm_uuid', 'android_pod_uid', 'android_pod_ip', 'boundary_sha256'}


def identity(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value.get('schema') != 1
            or not re.fullmatch('[0-9a-f]{64}', value.get('boundary_sha256', ''))):
        raise ValueError('exact cluster lab identity required')
    for key in ('vm_uuid', 'android_pod_uid'):
        parsed = uuid.UUID(value[key])
        if parsed.int == 0 or str(parsed) != value[key]:
            raise ValueError('canonical cluster lab UUID required')
    address = ipaddress.IPv4Address(value['android_pod_ip'])
    if address not in ipaddress.IPv4Network('10.244.0.0/16'):
        raise ValueError('Android address must belong to the configured lab pod network')
    return value


def private_json(path, bound=1024 * 1024):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or not 0 < info.st_size <= bound):
            raise ValueError('cluster runtime context requires a private owner file')
        data = stream.read(bound + 1)
        if len(data) > bound:
            raise ValueError('cluster runtime context exceeds its bound')
    return json.loads(data)


def isolated(config):
    """The cluster adapter stages this mapping only after fresh Lab validation."""
    if config.get('qualification_scope') != 'cluster-isolated':
        raise ValueError('explicit isolated cluster scope required')
    info = ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('cluster runtime root must be a private owned directory')
    expected = identity(config['cluster_lab'])
    if identity(private_json(ROOT / 'context.json', 4096)) != expected:
        raise ValueError('cluster guest identity or network boundary changed')
    paths = {'state': ROOT / 'release', 'hub_home': ROOT / 'hub-home',
             'hub_directory': ROOT / 'hub', 'fleet_config': ROOT / 'fleet/controller.json'}
    if any(Path(config[key]) != path or path.resolve(strict=True) != path for key, path in paths.items()):
        raise ValueError('cluster runtime mapping points outside the isolated guest')
    if (config.get('hub_unit') != 'gchat-android-cluster.service'
            or config.get('fleet_unit') != 'gdrone-android-cluster.service'):
        raise ValueError('cluster runtime requires its isolated owner services')
    fleet = private_json(paths['fleet_config'])
    if (Path(fleet['state']) != ROOT / 'fleet'
            or Path(fleet['chatEndpoint']) != ROOT / 'hub-home/gcd.chat'):
        raise ValueError('cluster controller points outside the isolated guest')
    targets = [row for row in config['targets'] if row['kind'] == 'android']
    if (len(targets) != 1 or targets[0].get('serial') != expected['android_pod_ip'] + ':5555'
            or targets[0].get('abi') != 'x86_64' or targets[0].get('channel') != 'android-x64'):
        raise ValueError('cluster qualification requires its pinned Android guest')
    return fleet, targets[0]
