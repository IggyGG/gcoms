#!/usr/bin/env python3
"""Real, bounded Android qualification on the explicitly isolated fleet."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import time

from android_release import canonical, command, digest, prepared_release, write_json
import android_release_host as host
import android_release_hub as hub
from android_release_network import reference, vpn

REFERENCE_BYTES = 42 * 1024 * 1024
INTERRUPT_BYTES = 8 * 1024 * 1024


def isolated(config):
    """Initial baseline qualification cannot bypass the production gate."""
    root = Path.home() / '.local/state/gchat-mobile-iso'
    home = Path.home() / '.local/share/gchat-mobile-iso'
    if (config.get('qualification_scope') != 'isolated'
            or config.get('hub_unit') != 'gchat-mobile-iso.service'
            or config.get('fleet_unit') != 'gdrone-mobile-iso.service'
            or Path(config['fleet_config']).resolve(strict=True) != (root / 'controller.json').resolve(strict=True)
            or Path(config['hub_home']).resolve(strict=True) != home.resolve(strict=True)):
        raise ValueError('initial qualification requires the retained isolated Android fleet')
    fleet = json.loads(Path(config['fleet_config']).read_text())
    if (Path(fleet['state']).resolve(strict=True) != root.resolve(strict=True)
            or Path(fleet['chatEndpoint']) != home / 'gcd.chat'):
        raise ValueError('qualification configuration points outside the isolated fleet')
    targets = [row for row in config['targets'] if row['kind'] == 'android']
    if (len(targets) != 1 or targets[0].get('serial') != 'emulator-5554'
            or targets[0].get('abi') != 'x86_64' or targets[0].get('channel') != 'android-x64'):
        raise ValueError('qualification requires the declared owned x86_64 emulator')
    return fleet, targets[0]


def stop_process(pid, handle):
    # The pidfd pins the identified owner across maintenance and PID reuse.
    signal.pidfd_send_signal(handle, signal.SIGTERM)
    if not select.select([handle], [], [], 20)[0]:
        raise TimeoutError('isolated owner did not stop cooperatively')


def service(path, argv, managed=False):
    if any(re.search(r'[\s%"\\]', str(arg)) for arg in argv):
        raise ValueError('isolated user service requires simple absolute paths')
    if path.exists(): raise ValueError('preserve the existing isolated service definition')
    content = ('[Unit]\nDescription=Isolated Android qualification owner\n\n[Service]\n'
               'Type=simple\nUMask=0077\nTimeoutStopSec=20\nSendSIGKILL=no\n'
               + ('Environment=GCHAT_OWNER_MANAGED_UPDATES=1\n' if managed else '')
               + 'ExecStart=' + ' '.join(map(str, argv)) + '\n')
    with path.open('x') as stream:
        os.chmod(path, 0o600); stream.write(content); stream.flush(); os.fsync(stream.fileno())


def adopt(config, ident):
    """Adopt only the known standalone lab owners, preserving their latest state."""
    fleet, _target = isolated(config)
    prepared = prepared_release(config, ident)
    for unit in (config['hub_unit'], config['fleet_unit']):
        if hub.manager(unit, 'show', '-p', 'FragmentPath', '--value'):
            raise ValueError('isolated adoption already has a service; inspect its enrollment')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.connect(fleet['chatEndpoint'])
        pid, uid, _gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid(): raise ValueError('isolated hub belongs to another owner')
    args = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
    home = Path(config['hub_home']).resolve(strict=True)
    if b'--home' not in args or Path(os.fsdecode(args[args.index(b'--home') + 1])).resolve() != home:
        raise ValueError('standalone hub is not the isolated profile owner')
    passphrase = home / 'passphrase'; info = passphrase.stat()
    if (passphrase.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077
            or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4096):
        raise ValueError('isolated headless unlock requires the existing private passphrase')
    hub_root = Path(config['hub_directory'])
    previous = hub.install_binary(hub_root, Path('/proc', str(pid), 'exe'))
    desired = hub.install_binary(hub_root, Path(config['state']) / 'artifacts/hub' / prepared['inputs']['hub'] / 'gchat')
    handle = os.pidfd_open(pid)
    try:
        instance = hub.exchange(fleet['chatEndpoint'], fleet['instanceId'], pid, {'kind': 'identify'})['instance']
        result = hub.exchange(fleet['chatEndpoint'], fleet['instanceId'], pid, {'kind': 'disconnect'})
        if result.get('kind') != 'snapshot' or result['snapshot']['instance'].get('protocolLocked') is not True:
            raise ValueError('isolated owner did not checkpoint its current protocol state')
        write_json(hub_root / 'adoption-before.json', {'path': str(previous), 'sha256': digest(previous),
            'boot_id': instance['bootId'], 'checkpoint_completed': True})
        stop_process(pid, handle)
    finally: os.close(handle)
    units = Path.home() / '.config/systemd/user'
    fragment = units / config['hub_unit']
    service(fragment, [hub_root / 'active/gchat', 'daemon', '--home', home, '--gc2-carrier',
            '--fleet-config', Path(fleet['state']) / 'gchat-fleet.json',
            '--chat-passphrase-file', passphrase], managed=True)
    hub.select(hub_root, desired)
    command(['systemctl', '--user', 'daemon-reload']); hub.manager(config['hub_unit'], 'start')
    try: hub.wait_ready(config, digest(desired), instance['bootId'])
    except BaseException:
        hub.manager(config['hub_unit'], 'stop'); hub.select(hub_root, previous)
        hub.manager(config['hub_unit'], 'start'); hub.wait_ready(config, digest(previous), instance['bootId'])
        raise
    write_json(hub_root / 'enrollment.json', {'schema': 1, 'unit': config['hub_unit'], 'fragment': str(fragment),
               'unit_sha256': digest(fragment), 'instance_id': fleet['instanceId'], 'previous': 'adoption-before.json'})
    # Stop only the exact lab controller; production and mint providers remain owned separately.
    controllers = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit(): continue
        try: argv = (path / 'cmdline').read_bytes().split(b'\0')
        except OSError: continue
        if (len(argv) > 2 and argv[1] == b'run' and b'--config' in argv
                and argv[argv.index(b'--config') + 1] == os.fsencode(config['fleet_config'])):
            controllers.append(int(path.name))
    if len(controllers) > 1: raise ValueError('multiple isolated controller owners require inspection')
    for controller in controllers:
        handle = os.pidfd_open(controller)
        try: stop_process(controller, handle)
        finally: os.close(handle)
    controller_root = Path(config['state']) / 'controller'
    binary = hub.install_binary(controller_root, Path(config['state']) / 'artifacts/controller' /
                                prepared['inputs']['controller'] / 'gdrone-fleet', 'gdrone-fleet')
    hub.select(controller_root, binary)
    fragment = units / config['fleet_unit']
    service(fragment, [controller_root / 'active/gdrone-fleet', 'run', '--config', config['fleet_config']])
    command(['systemctl', '--user', 'daemon-reload']); hub.manager(config['fleet_unit'], 'start')
    hub.wait_controller(config, digest(binary))
    write_json(controller_root / 'enrollment.json', {'schema': 1, 'unit': config['fleet_unit'],
               'fragment': str(fragment), 'unit_sha256': digest(fragment)})
    hub.eligible(config); hub.eligible_controller(config)


def worker(request, component, name):
    """Only a qualified lab request can select a padded, normally signed reference."""
    _fleet, target = isolated(request['config'])
    value = request['manifest'].get('reference', {})
    path = Path(value['path'])
    root = Path(request['directory']).resolve(strict=True)
    if (component != 'worker' or name != target['abi'] + '/worker.so'
            or not path.resolve(strict=True).is_relative_to(root) or path.is_symlink()
            or path.stat().st_size != REFERENCE_BYTES or digest(path) != value['sha256']):
        raise ValueError('reference bytes or isolated path changed')
    original = Path(request['config']['state']) / 'artifacts/worker' / request['manifest']['inputs']['worker'] / name
    with path.open('rb') as stream: prefix = stream.read(original.stat().st_size)
    if hashlib.sha256(prefix).hexdigest() != digest(original):
        raise ValueError('reference is not the exact prepared worker plus padding')
    return path


def frontier(bytes_, sha):
    if (len(bytes_) != 156 or bytes_[:8] != b'DSRSUM1\0'
            or hashlib.sha256(bytes_[:124]).digest() != bytes_[124:]
            or bytes_[40:72].hex() != sha or int.from_bytes(bytes_[72:80], 'little') != REFERENCE_BYTES
            or int.from_bytes(bytes_[80:84], 'big') != 7):
        return None
    offset = int.from_bytes(bytes_[84:92], 'little')
    if offset > REFERENCE_BYTES or (offset != REFERENCE_BYTES and offset % 11000): return None
    return offset


def observe_frontier(config, target, sha, pushed_at):
    root = '/data/user/0/' + host.PACKAGE + '/files/d'
    paths = host.output(host.adb(config, target, 'shell', 'find', root, '-maxdepth', '2',
                               '-type', 'f', '-name', 'downloader.state')).decode().splitlines()
    if len(paths) > 256: raise ValueError('Android frontier inventory exceeds bounds')
    current = []
    for path in paths:
        if not re.fullmatch(re.escape(root) + r'/[0-9a-f]{64}/downloader\.state', path): continue
        modified = host.output(host.adb(config, target, 'shell', 'stat', '-c', '%Y', path)).decode().strip()
        if not modified.isdigit() or int(modified) < int(pushed_at): continue
        raw = host.output(host.adb(config, target, 'exec-out', 'head', '-c', '157', path))
        offset = frontier(raw, sha)
        if offset is not None and raw[8:40].hex() == Path(path).parent.name:
            current.append(offset)
    if len(current) > 1: raise ValueError('Android frontier belongs to ambiguous current runs')
    return current[0] if current else 0


def run(config, ident):
    _fleet, target = isolated(config)
    prepared = prepared_release(config, ident)
    hub.eligible(config); hub.eligible_controller(config); before_vpn = vpn()
    directory = Path(config['state']) / 'qualification' / secrets.token_hex(16)
    directory.mkdir(mode=0o700, parents=True)
    source = Path(config['state']) / 'artifacts/worker' / prepared['inputs']['worker'] / target['abi'] / 'worker.so'
    if not 0 < source.stat().st_size <= REFERENCE_BYTES:
        raise ValueError('prepared worker does not fit the 42 MiB reference')
    padded = directory / 'reference.so'
    with source.open('rb') as src, padded.open('xb') as dst:
        os.chmod(padded, 0o600)
        while block := src.read(1024 * 1024): dst.write(block)
        # ELF loaders permit trailing padding; the normal publication signs all bytes.
        dst.truncate(REFERENCE_BYTES); dst.flush(); os.fsync(dst.fileno())
    value = {key: prepared[key] for key in ('sources', 'inputs', 'targets', 'configuration_sha256')}
    value.update(schema=1, purpose='android-runtime-qualification', prepared_id=ident,
                 pushed_at=time.time(), reference={'path': str(padded), 'sha256': digest(padded), 'bytes': REFERENCE_BYTES})
    value['release_id'] = hashlib.sha256(canonical(value)).hexdigest()
    request = {'config': config, 'manifest': value, 'directory': str(directory), 'warm': False}
    write_json(directory / 'request.json', request)
    result = {'schema': 1, 'kind': 'android-runtime-qualification', 'inputs': prepared['inputs'],
              'sources': prepared['sources'], 'prepared_id': ident, 'scope': 'isolated emulator-5554',
              'state': 'running', 'vpn': before_vpn, 'observed_at': time.time()}
    write_json(directory / 'result.json', result)
    started = time.monotonic(); interrupted = None
    try:
        host.verify(request); host.activate(request)
        expected = json.loads((directory / target['id'] / 'deployment-request.json').read_text())
        while True:
            if time.monotonic() - started >= 360:
                raise TimeoutError('real Android reference exceeds the six-minute transfer budget')
            if interrupted is None:
                offset = observe_frontier(config, target, expected['worker_sha256'], value['pushed_at'])
                if INTERRUPT_BYTES <= offset < REFERENCE_BYTES:
                    old_pid = host.output(host.adb(config, target, 'shell', 'pidof', host.PACKAGE)).decode().strip()
                    if not old_pid.isdigit(): raise ValueError('no running Android process to interrupt')
                    command(host.adb(config, target, 'shell', 'am', 'force-stop', host.PACKAGE))
                    command(host.adb(config, target, 'shell', 'am', 'start', '-n', host.PACKAGE + '/.MainActivity'))
                    interrupted = {'before_pid': int(old_pid), 'frontier': offset, 'at': time.time()}
                    write_json(directory / 'interruption.json', interrupted)
            try:
                proof = json.loads(host.private_file(config, target, 'deployment-ready.json'))
                pid = host.output(host.adb(config, target, 'shell', 'pidof', host.PACKAGE)).decode().strip()
                host.ready(proof, expected, pid)
            except (ValueError, OSError, subprocess.CalledProcessError):
                time.sleep(1); continue
            payload = json.loads(host.private_file(config, target, 'd/payload-evidence.json'))
            if (interrupted is None or int(pid) == interrupted['before_pid']
                    or payload.get('processId') != int(pid) or payload.get('artifactBytes') != REFERENCE_BYTES
                    or payload.get('artifactSha256') != expected['worker_sha256']
                    or payload.get('outcome') != 'launched' or payload.get('executionMode') != 'in-process-library'
                    or payload.get('payloadVerified') is not True or payload.get('admissionVerified') is not True):
                raise ValueError('current Android process has no exact resumed reference receipt')
            log = host.output(['journalctl', '--user', '-u', config['fleet_unit'], '--since',
                               '@' + str(int(value['pushed_at'])), '--no-pager', '-o', 'cat'])
            pattern = rb'transfer resumed run=' + re.escape(payload['runId'].encode()) + rb' offset=(\d+) bytes=' + str(REFERENCE_BYTES).encode()
            if not any(int(m) >= interrupted['frontier'] for m in re.findall(pattern, log)):
                raise ValueError('sender did not confirm the same run resumed beyond its saved frontier')
            before = json.loads((directory / 'android-before.json').read_text())[0]
            if host.identity(config, target) != before['identity_sha256']:
                raise ValueError('Android interruption changed the retained identity')
            installed = host.output(host.adb(config, target, 'shell', 'pm', 'path', host.PACKAGE)).decode().strip().removeprefix('package:')
            if host.output(host.adb(config, target, 'shell', 'sha256sum', installed)).decode().split()[0] != expected['apk_sha256']:
                raise ValueError('reference process runs a different APK')
            result.update(state='qualified', observed_at=time.time(), vpn=vpn(),
                android={key: True for key in ('full_download_verified', 'loaded_worker_ready', 'identity_preserved', 'resume_verified')},
                reference_transfer={'bytes': REFERENCE_BYTES, 'sha256': expected['worker_sha256'],
                    'elapsed_seconds': time.monotonic() - started, 'sha256_verified': True, 'current_process_verified': True},
                process_id=int(pid), run_id=payload['runId'], interruption=interrupted,
                evidence={'request_sha256': digest(directory / 'request.json'),
                          'payload_receipt_sha256': hashlib.sha256(canonical(payload)).hexdigest()})
            reference(result, prepared['inputs'])
            write_json(directory / 'result.json', result)
            write_json(config['baseline_receipt'], result)
            return result
    except BaseException as error:
        result.update(state='failed', observed_at=time.time(), failure_type=type(error).__name__,
                      elapsed_seconds=time.monotonic() - started, interruption=interrupted)
        write_json(directory / 'result.json', result)
        raise
    finally:
        host.cleanup(request)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--prepared-id', required=True)
    parser.add_argument('operation', choices=('adopt-isolated', 'reference'))
    args = parser.parse_args(); config = json.loads(args.config.read_text())
    if args.operation == 'adopt-isolated':
        adopt(config, args.prepared_id); print(json.dumps({'state': 'isolated_owners_enrolled'}))
    else: print(json.dumps(run(config, args.prepared_id), indent=2))
