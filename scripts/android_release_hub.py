#!/usr/bin/env python3
"""Owner-authenticated headless hub activation, without profile restoration."""
import json
import os
from pathlib import Path
import re
import secrets
import select as polling
import shutil
import signal
import socket
import stat
import struct
import sys
import time

from android_release import command, digest, write_json

FRAME_LIMIT = 4 * 1024 * 1024


def receive(stream, size):
    parts = bytearray()
    while len(parts) < size:
        block = stream.recv(size - len(parts))
        if not block:
            raise ValueError('hub closed its maintenance response')
        parts.extend(block)
    return bytes(parts)


def exchange(endpoint, instance, pid, request, timeout=15):
    """Use the existing bounded local API and pin its actual Linux owner/PID."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(endpoint))
        peer, uid, _gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid() or peer != pid:
            raise ValueError('maintenance socket belongs to another hub process')
        data = json.dumps({'version': 3, 'instance_id': instance, 'request': request}).encode()
        stream.sendall(struct.pack('!I', len(data)) + data)
        size = struct.unpack('!I', receive(stream, 4))[0]
        if not 0 < size <= FRAME_LIMIT:
            raise ValueError('hub maintenance response exceeds bounds')
        response = json.loads(receive(stream, size))
    if response.get('version') != 3 or response.get('instance_id') != instance:
        raise ValueError('maintenance response changed hub identity or API')
    result = response['response']
    if result.get('kind') == 'error':
        # Never copy a private server error into public release status.
        raise ValueError('hub maintenance request refused')
    return result


def manager(unit, *args):
    if not re.fullmatch(r'(?:gchat|gdrone)-[A-Za-z0-9_.@-]{1,112}\.service', unit):
        raise ValueError('maintenance requires an exact fleet user service')
    from android_release_host import output
    return output(['systemctl', '--user', *args, unit], timeout=20).decode().strip()


def attached(config):
    from android_release_host import active_hub
    hub = active_hub(config)
    fleet = json.loads(Path(config['fleet_config']).read_text())
    result = exchange(fleet['chatEndpoint'], fleet['instanceId'], hub['pid'], {'kind': 'identify'})
    if result.get('kind') != 'instance' or result['instance'].get('id') != fleet['instanceId']:
        raise ValueError('hub attachment does not match the retained fleet')
    return hub, fleet, result['instance']


def enrollment_owner(config):
    """The desktop can hold the pinned production socket after a unit stops."""
    state = manager(config['hub_unit'], 'show', '-p', 'ActiveState', '--value')
    if state == 'active': return (*attached(config), None)
    if state not in ('inactive', 'failed'):
        raise ValueError('preserve the transitioning hub owner')
    fleet = json.loads(Path(config['fleet_config']).read_text())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5); stream.connect(fleet['chatEndpoint'])
        pid, uid, _gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid(): raise ValueError('enrollment socket belongs to another owner')
    handle = os.pidfd_open(pid)
    try:
        argv = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
        if Path(os.fsdecode(argv[0])).name not in ('gchat', 'gchat-desktop', 'g-chat'):
            raise ValueError('pinned socket is not a native GChat profile owner')
        instance = exchange(fleet['chatEndpoint'], fleet['instanceId'], pid, {'kind': 'identify'})
        if instance.get('kind') != 'instance' or instance['instance'].get('id') != fleet['instanceId']:
            raise ValueError('enrollment changed the retained profile identity')
        return ({'pid': pid, 'sha256': digest(Path('/proc', str(pid), 'exe'))}, fleet, instance['instance'], handle)
    except BaseException:
        os.close(handle); raise


def install_binary(root, source, name='gchat'):
    root = Path(root)
    sha = digest(source)
    if name not in ('gchat', 'gdrone-fleet'): raise ValueError('unknown fleet executable')
    destination = root / 'versions' / sha / name
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not destination.exists():
        temporary = destination.with_name(name + '.' + secrets.token_hex(8))
        try:
            with Path(source).open('rb') as src, temporary.open('xb') as dst:
                os.chmod(temporary, 0o700)
                shutil.copyfileobj(src, dst)
                dst.flush(); os.fsync(dst.fileno())
            if digest(temporary) != sha:
                raise ValueError('hub binary changed while retaining it')
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    if destination.is_symlink() or digest(destination) != sha:
        raise ValueError('retained hub executable differs')
    return destination


def select(root, binary):
    root, binary = Path(root).resolve(strict=True), Path(binary).resolve(strict=True)
    if not binary.is_relative_to((root / 'versions').resolve()):
        raise ValueError('hub selection escapes retained immutable versions')
    temporary = root / ('active.' + secrets.token_hex(8))
    try:
        temporary.symlink_to(os.path.relpath(binary.parent, root))
        os.replace(temporary, root / 'active')
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def enrolled_unit(config):
    root = Path(config['hub_directory'])
    receipt = json.loads((root / 'enrollment.json').read_text())
    fragment = manager(config['hub_unit'], 'show', '-p', 'FragmentPath', '--value')
    if (receipt.get('unit') != config['hub_unit'] or fragment != receipt.get('fragment')
            or digest(fragment) != receipt.get('unit_sha256')):
        raise ValueError('headless hub service enrollment changed')
    if manager(config['hub_unit'], 'show', '-p', 'DropInPaths', '--value'):
        raise ValueError('headless hub enrollment has an unreviewed service override')
    return receipt


def eligible(config):
    root = Path(config['hub_directory'])
    receipt = enrolled_unit(config)
    hub, fleet, instance = attached(config)
    if digest(root / 'active/gchat') != hub['sha256'] or instance.get('protocolLocked') is not False:
        raise ValueError('enrolled headless hub is not running and unlocked')
    if receipt.get('instance_id') != fleet['instanceId']:
        raise ValueError('headless hub enrollment belongs to another identity')
    return hub, fleet, instance


def eligible_controller(config):
    from android_release_host import active_hub
    root = Path(config['state']) / 'controller'
    receipt = json.loads((root / 'enrollment.json').read_text())
    fragment = manager(config['fleet_unit'], 'show', '-p', 'FragmentPath', '--value')
    if (receipt.get('unit') != config['fleet_unit'] or fragment != receipt.get('fragment')
            or digest(fragment) != receipt.get('unit_sha256')
            or manager(config['fleet_unit'], 'show', '-p', 'DropInPaths', '--value')):
        raise ValueError('fleet controller service enrollment changed')
    controller = active_hub(config, config['fleet_unit'])
    if controller['sha256'] != digest(root / 'active/gdrone-fleet'):
        raise ValueError('enrolled fleet controller executable differs')
    return controller


def wait_controller(config, sha, timeout=15):
    from android_release_host import active_hub
    until = time.monotonic() + timeout
    while True:
        try:
            current = active_hub(config, config['fleet_unit'])
            if current['sha256'] == sha: return current
        except (OSError, ValueError): pass
        if time.monotonic() >= until: raise TimeoutError('fleet controller executable readiness missing')
        time.sleep(.25)


def enroll_controller(config, source):
    from android_release_host import active_hub
    current = active_hub(config, config['fleet_unit'])
    fragment = Path(manager(config['fleet_unit'], 'show', '-p', 'FragmentPath', '--value'))
    if (fragment != Path.home() / '.config/systemd/user' / config['fleet_unit']
            or manager(config['fleet_unit'], 'show', '-p', 'DropInPaths', '--value')):
        raise ValueError('controller enrollment requires its original local user unit')
    root = Path(config['state']) / 'controller'
    old = install_binary(root, '/proc/' + str(current['pid']) + '/exe', 'gdrone-fleet')
    desired = install_binary(root, source, 'gdrone-fleet')
    original = fragment.read_text()
    if original.count('ExecStart=') != 1 or original.count('[Service]') != 1:
        raise ValueError('controller enrollment requires one original service command')
    argv = [str(root / 'active/gdrone-fleet'), 'run', '--config', config['fleet_config']]
    if any(re.search(r'[\s%"\\]', arg) for arg in argv): raise ValueError('controller service path needs explicit quoting')
    backup = root / ('unit-before-' + secrets.token_hex(8)); shutil.copy2(fragment, backup)
    manager(config['fleet_unit'], 'stop')
    try:
        select(root, desired)
        fragment.write_text(re.sub(r'^ExecStart=.*$', 'ExecStart=' + ' '.join(argv), original, flags=re.M))
        command(['systemctl', '--user', 'daemon-reload']); manager(config['fleet_unit'], 'start')
        wait_controller(config, digest(desired))
    except BaseException:
        manager(config['fleet_unit'], 'stop'); select(root, old); shutil.copy2(backup, fragment)
        command(['systemctl', '--user', 'daemon-reload']); manager(config['fleet_unit'], 'start')
        raise
    write_json(root / 'enrollment.json', {'schema': 1, 'unit': config['fleet_unit'], 'fragment': str(fragment),
               'unit_sha256': digest(fragment), 'previous': str(backup)})


def controller_activate(request):
    from android_release_host import artifact
    config, directory = request['config'], Path(request['directory'])
    current = eligible_controller(config)
    desired = artifact(request, 'controller', 'gdrone-fleet')
    if current['sha256'] == digest(desired): return
    root = Path(config['state']) / 'controller'
    old = install_binary(root, '/proc/' + str(current['pid']) + '/exe', 'gdrone-fleet')
    new = install_binary(root, desired, 'gdrone-fleet')
    write_json(directory / 'controller-before.json', {'path': str(old), 'sha256': current['sha256']})
    manager(config['fleet_unit'], 'stop'); select(root, new); manager(config['fleet_unit'], 'start')
    wait_controller(config, digest(new))


def controller_rollback(request):
    config, directory = request['config'], Path(request['directory'])
    path = directory / 'controller-before.json'
    if not path.exists(): return
    before = json.loads(path.read_text())
    if digest(before['path']) != before['sha256']: raise ValueError('previous fleet controller changed')
    manager(config['fleet_unit'], 'stop'); select(Path(config['state']) / 'controller', before['path'])
    manager(config['fleet_unit'], 'start'); wait_controller(config, before['sha256'])


def checkpoint(config, release):
    hub, fleet, instance = eligible(config)
    view = secrets.token_hex(16)
    def rpc(request):
        return exchange(fleet['chatEndpoint'], fleet['instanceId'], hub['pid'], request)
    def update(action):
        body = {'action': action, 'view': view}
        if action in ('prepare', 'exit', 'abort'): body['release'] = release
        return rpc({'kind': 'update', 'request': body})
    update('heartbeat')
    try:
        prepared = update('prepare')
        if (prepared.get('kind') != 'update' or prepared['result'].get('state') != 'ready'
                or prepared['result'].get('process_id') != hub['pid']
                or prepared['result'].get('boot_id') != instance['bootId']):
            raise ValueError('hub is busy or its checkpoint owner changed')
        disconnected = rpc({'kind': 'disconnect'})
        if (disconnected.get('kind') != 'snapshot'
                or disconnected['snapshot']['instance'].get('protocolLocked') is not True):
            raise ValueError('hub did not finish its latest protocol checkpoint')
        update('exit')
    except BaseException:
        try: update('abort'); update('detach')
        except (OSError, ValueError): pass
        raise
    manager(config['hub_unit'], 'stop')
    return hub, instance['bootId']


def wait_ready(config, sha, old_boot, timeout=20):
    until = time.monotonic() + timeout
    while True:
        try:
            hub, _fleet, instance = attached(config)
            if (hub['sha256'] == sha and instance['bootId'] != old_boot
                    and instance.get('protocolLocked') is False):
                return hub
        except (OSError, ValueError): pass
        if time.monotonic() >= until:
            raise TimeoutError('headless hub identity, executable and unlock readiness missing')
        time.sleep(.25)


def activate(request):
    from android_release_host import artifact
    config, directory = request['config'], Path(request['directory'])
    hub, _fleet, _instance = eligible(config)
    root = Path(config['hub_directory'])
    previous = install_binary(root, '/proc/' + str(hub['pid']) + '/exe')
    desired = install_binary(root, artifact(request, 'hub', 'gchat'))
    before = {'path': str(previous), 'sha256': hub['sha256'], 'checkpoint_completed': False}
    write_json(directory / 'hub-managed-before.json', before)
    _hub, boot = checkpoint(config, request['manifest']['release_id'])
    before.update(checkpoint_completed=True, checkpoint_boot_id=boot, next_sha256=digest(desired))
    write_json(directory / 'hub-managed-before.json', before)
    select(root, desired)
    manager(config['hub_unit'], 'start')
    wait_ready(config, digest(desired), boot)


def rollback(request):
    config, directory = request['config'], Path(request['directory'])
    path = directory / 'hub-managed-before.json'
    if not path.exists():
        # No managed effect occurred (e.g. enrollment failed before checkpoint).
        return
    before = json.loads(path.read_text())
    if digest(before['path']) != before['sha256']:
        raise ValueError('previous headless executable changed')
    enrolled_unit(config)
    state = manager(config['hub_unit'], 'show', '-p', 'ActiveState', '--value')
    pid = int(manager(config['hub_unit'], 'show', '-p', 'MainPID', '--value'))
    if state in ('inactive', 'failed') and pid == 0:
        # A replacement that never started cannot answer maintenance RPCs.
        # Restore only after the recorded owner completed the original
        # checkpoint; retain the current profile and never force a live hub.
        if (before.get('checkpoint_completed') is not True
                or not before.get('checkpoint_boot_id')
                or digest(Path(config['hub_directory']) / 'active/gchat') != before.get('next_sha256')):
            raise ValueError('inactive hub has no completed activation checkpoint')
        boot = before['checkpoint_boot_id']
    else:
        current, _fleet, _instance = eligible(config)
        if current['sha256'] == before['sha256']:
            write_json(directory / 'hub-restored.json', {'previous_artifact_verified': True,
                       'current_checkpoint_preserved': True, 'functional_readiness_verified': True})
            return
        _hub, boot = checkpoint(config, request['manifest']['release_id'])
    select(config['hub_directory'], before['path'])
    manager(config['hub_unit'], 'start')
    wait_ready(config, before['sha256'], boot)
    # The current profile/ratchet, archive and queues remain the source of truth.
    write_json(directory / 'hub-restored.json', {'previous_artifact_verified': True,
               'current_checkpoint_preserved': True, 'functional_readiness_verified': True})


def enroll(config, source):
    """One owner-requested transition; routine promotion never edits the unit."""
    hub, fleet, instance, standalone = enrollment_owner(config)
    try:
        return enroll_owner(config, source, hub, fleet, instance, standalone)
    finally:
        if standalone is not None: os.close(standalone)


def enroll_owner(config, source, hub, fleet, instance, standalone):
    fragment = Path(manager(config['hub_unit'], 'show', '-p', 'FragmentPath', '--value'))
    if fragment != Path.home() / '.config/systemd/user' / config['hub_unit']:
        raise ValueError('enrollment only owns the configured local user unit')
    dropins = manager(config['hub_unit'], 'show', '-p', 'DropInPaths', '--value').split()
    if set(dropins) != set(config.get('hub_legacy_dropins', [])):
        raise ValueError('enrollment must explicitly retain each existing service override')
    home = Path(config['hub_home']).resolve(strict=True)
    passphrase = home / 'passphrase'
    info = passphrase.stat()
    if (passphrase.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
        raise ValueError('headless automatic unlock requires its existing private passphrase file')
    root = Path(config['hub_directory']); root.mkdir(parents=True, mode=0o700, exist_ok=True)
    old = install_binary(root, '/proc/' + str(hub['pid']) + '/exe')
    desired = install_binary(root, source)
    before = root / ('enrollment-before-' + secrets.token_hex(8)); before.mkdir(mode=0o700)
    shutil.copy2(fragment, before / 'unit')
    for path in dropins: shutil.copy2(path, before / Path(path).name)
    argv = [str(root / 'active/gchat'), 'daemon', '--home', str(home), '--gc2-carrier',
            '--fleet-config', str(Path(fleet['state']) / 'gchat-fleet.json'),
            '--chat-passphrase-file', str(passphrase)]
    if any(re.search(r'[\s%"\\]', arg) for arg in argv):
        raise ValueError('headless service paths need explicit systemd quoting support')
    original = fragment.read_text()
    if original.count('ExecStart=') != 1 or original.count('[Service]') != 1:
        raise ValueError('headless enrollment requires one original service command')
    updated = re.sub(r'^ExecStart=.*$', 'ExecStart=' + ' '.join(argv), original, flags=re.M)
    updated = updated.replace('[Service]', '[Service]\nEnvironment=GCHAT_OWNER_MANAGED_UPDATES=1')
    disconnected = exchange(fleet['chatEndpoint'], fleet['instanceId'], hub['pid'], {'kind': 'disconnect'})
    if disconnected.get('kind') != 'snapshot' or disconnected['snapshot']['instance'].get('protocolLocked') is not True:
        raise ValueError('enrollment did not checkpoint the existing protocol identity')
    if standalone is None:
        manager(config['hub_unit'], 'stop')
    else:
        # Disconnect above is the durable barrier. Do not force-kill a desktop
        # owner or manufacture a second profile; wait for this pinned process.
        signal.pidfd_send_signal(standalone, signal.SIGTERM)
        if not polling.select([standalone], [], [], 20)[0]:
            raise TimeoutError('native desktop owner did not stop cooperatively')
    try:
        select(root, desired)
        fragment.write_text(updated)
        for path in dropins: Path(path).unlink()
        command(['systemctl', '--user', 'daemon-reload'])
        manager(config['hub_unit'], 'start')
        wait_ready(config, digest(desired), instance['bootId'])
    except BaseException:
        manager(config['hub_unit'], 'stop')
        select(root, old); shutil.copy2(before / 'unit', fragment)
        for path in dropins: shutil.copy2(before / Path(path).name, path)
        command(['systemctl', '--user', 'daemon-reload']); manager(config['hub_unit'], 'start')
        raise
    write_json(root / 'enrollment.json', {'schema': 1, 'unit': config['hub_unit'], 'fragment': str(fragment),
               'unit_sha256': digest(fragment), 'instance_id': fleet['instanceId'], 'previous': str(before)})


if __name__ == '__main__':
    operation, path = sys.argv[1:]
    request = json.loads(Path(path).read_text())
    {'activate': activate, 'rollback': rollback}[operation](request)
