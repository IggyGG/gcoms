"""Bind restored lab disks to the pipeline before changing ephemeral addresses."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from android_release import canonical, digest, write_json
from android_release_lab_context import ROOT, identity, private_json
from android_release_store import Archive, sha256


def guests(lab, plan):
    result = {}
    for component, selected in plan['guests'].items():
        state = lab.owned_state(selected['name'], plan['owner'])
        if state['image'] != selected['image']:
            raise ValueError('recovery guest image changed')
        result[component] = {key: state.get(key) for key in ('name', 'image', 'machine_uuid', 'vm_uid')}
    return result


def device_identity(lab, plan, selected):
    pod = 'gl-' + plan['guests']['android']['name']
    def adb(*args):
        current = lab.kube.get('pod', pod, ns=lab.settings.namespace)
        if current['metadata']['uid'] != selected['android_pod_uid']:
            raise ValueError('Android changed during recovery verification')
        return lab.kube.run('exec', pod, '-n', lab.settings.namespace, '--',
                            'adb', '-s', 'emulator-5556', *args, timeout=20).stdout
    adb('root')
    try:
        adb('wait-for-device')
        seed = adb('exec-out', 'head', '-c', '33', '/data/user/0/boo.gcoms.agent/files/d/identity.seed')
        if len(seed) != 32:
            raise ValueError('restored Android identity is absent or malformed')
        package = adb('shell', 'pm', 'path', 'boo.gcoms.agent').decode().strip()
        if not re.fullmatch(r'package:/data/app/[A-Za-z0-9_+~=/.-]+/base\.apk', package):
            raise ValueError('one installed Android package required for recovery')
        checksum = adb('shell', 'sha256sum', package.removeprefix('package:')).decode().split()[0]
        return {'identity_sha256': hashlib.sha256(seed).hexdigest(), 'apk_sha256': sha256(checksum)}
    finally:
        adb('unroot')


def guest_mapping(before, after=None, expected=None, root=ROOT):
    """Run as the pinned VM owner, serialized with normal release mutations."""
    identity(before)
    if after is not None:
        identity(after)
        if any(before[k] != after[k] for k in ('vm_uuid', 'boundary_sha256')):
            raise ValueError('recovery cannot change the VM or isolation boundary')
    with (root / 'release/release.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if private_json(root / 'context.json', 4096) != before:
            raise ValueError('preserve a different guest context')
        config = private_json(root / 'host-config.json')
        targets = [t for t in config['targets'] if t['kind'] == 'android']
        if len(targets) != 1 or targets[0]['serial'] != before['android_pod_ip'] + ':5555':
            raise ValueError('preserve a different Android target mapping')
        original = hashlib.sha256(canonical(config)).hexdigest()
        if expected is not None and original != sha256(expected):
            raise ValueError('restored owner configuration differs from its archived binding')
        if after is not None:
            backup = root / 'recovery' / hashlib.sha256(canonical({'before': before, 'after': after})).hexdigest()
            if backup.exists():
                raise ValueError('preserve an existing or uncertain guest rebind')
            write_json(backup / 'before-context.json', before)
            write_json(backup / 'before-host-config.json', config)
            targets[0]['serial'] = after['android_pod_ip'] + ':5555'
            write_json(root / 'host-config.json', config)
            # Write the authoritative context last. A partial change fails
            # normal mapping checks and cannot authorize the old target.
            write_json(root / 'context.json', after)
        return {'host_config_sha256': original, 'context': before if after is None else after}


def mapping_request(ssh, selected, settings, after=None, expected=None):
    from android_release_lab_provision import send, execute_once
    request = {'before': selected, 'after': after, 'expected': expected}
    sources = {name: Path(__file__).with_name(name) for name in
               ('android_release.py', 'android_release_lab_context.py', 'android_release_lab_recovery.py', 'android_release_store.py')}
    binding = hashlib.sha256(canonical({'request': request, 'files': {n: digest(p) for n, p in sources.items()}})).hexdigest()
    prefix = 'recovery-commands/' + binding
    files = {prefix + '/' + name: path for name, path in sources.items()}
    send(ssh, ROOT, files, {prefix + '/request.json': request})
    program = prefix + '/android_release_lab_recovery.py'
    if after is None:
        # Re-read the current mapping; a saved capture receipt is not proof of
        # restored live state. Only the mutation uses execute-once semantics.
        directory = Path(settings['state']); directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (directory / 'recovery-probe-private.log').open('ab') as log:
            os.chmod(log.name, 0o600)
            result = subprocess.run(ssh + ['python3 ' + shlex.quote(str(ROOT / program))],
                                    stdout=subprocess.PIPE, stderr=log, timeout=30)
        if result.returncode or len(result.stdout) > 8192:
            raise ValueError('restored guest mapping probe failed')
        return json.loads(result.stdout)
    return execute_once(ssh, ROOT, program, binding, Path(settings['state']))


def capture(lab, plan, selected, state, settings, ssh):
    return {'schema': 1, 'kind': 'android-lab-recovery', 'state': 'captured',
            'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(), 'guests': guests(lab, plan),
            'context': selected, 'android': device_identity(lab, plan, selected),
            'mapping': mapping_request(ssh, selected, settings)}


def saved_binding(lab, plan, settings, phase):
    record = Archive(settings['archive']).read_record(settings['recovery_archive'])
    value = record['result']
    if (value.get('schema') != 1 or value.get('kind') != 'android-lab-recovery'
            or value.get('state') != phase or value.get('guests') != guests(lab, plan)
            or value.get('plan_sha256') != hashlib.sha256(canonical(plan)).hexdigest()):
        raise ValueError('recovery archive belongs to another lab pair or phase')
    identity(value['context'])
    return value


def checkpoints(lab, plan, stopped=False):
    from ghost_lab.store import Store
    store = Store(lab.settings.s3_config)
    result = {}
    for component, selected in plan['guests'].items():
        state = lab.owned_state(selected['name'], plan['owner'])
        key = state.get('checkpoint', '')
        if ((stopped and state['phase'] != 'stopped') or
                not re.fullmatch('checkpoints/' + re.escape(state['name']) + r'/cp-[0-9a-f]{32}/manifest\.json', key)):
            raise ValueError('both guests require their completed original checkpoints')
        manifest = store.read(key)
        if (not manifest or manifest.get('complete') is not True or manifest.get('consistency') != 'powered-off'
                or manifest.get('instance') != state['name'] or manifest.get('machine_uuid') != state['machine_uuid']
                or manifest.get('vm_uid') != state.get('vm_uid') or not 1 <= len(manifest.get('volumes', [])) <= 16):
            raise ValueError('complete checkpoint identity changed')
        for volume in manifest['volumes']:
            sha256(volume['sha256'])
            if (not volume.get('version') or volume['version'] == 'null'
                    or volume.get('format') != 'volume.tar.zst' or type(volume.get('bytes')) is not int
                    or volume['bytes'] <= 0):
                raise ValueError('checkpoint requires verified version-pinned guest disks')
        result[component] = {'key': key, 'manifest_sha256': hashlib.sha256(canonical(manifest)).hexdigest()}
    return result


def seal(lab, plan, settings):
    value = copy.deepcopy(saved_binding(lab, plan, settings, 'captured'))
    value.update(state='sealed', checkpoints=checkpoints(lab, plan, stopped=True))
    return value


def rebind(lab, plan, selected, state, settings, ssh):
    from android_release_lab_provision import connect
    value = saved_binding(lab, plan, settings, 'sealed')
    if value['checkpoints'] != checkpoints(lab, plan):
        raise ValueError('restored guest checkpoint differs from the sealed pair')
    if any(value['context'][k] != selected[k] for k in ('vm_uuid', 'boundary_sha256')):
        raise ValueError('restored VM or isolation boundary changed')
    if device_identity(lab, plan, selected) != value['android']:
        raise ValueError('restored Android identity or installed APK changed')
    observed = mapping_request(ssh, value['context'], settings)
    if observed != value['mapping']:
        raise ValueError('restored owner mapping differs from the archived original')
    lab.kube.fence_operations()
    routing = connect(lab, plan, selected, state, settings, ssh, previous=value['context'])
    lab.kube.fence_operations()
    mapped = mapping_request(ssh, value['context'], settings, after=selected,
                             expected=value['mapping']['host_config_sha256'])
    if mapped['host_config_sha256'] != value['mapping']['host_config_sha256'] or mapped['context'] != selected:
        raise ValueError('restored guest mapping confirmation changed')
    return dict(value, state='rebound', context=selected, previous_context=value['context'], routing=routing)


if __name__ == '__main__':
    request = private_json(Path(__file__).with_name('request.json'), 8192)
    print(json.dumps(guest_mapping(request['before'], request['after'], request['expected'])), flush=True)
