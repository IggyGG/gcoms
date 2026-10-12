"""Bootstrap normal owners and Android package only in the pinned isolated guest."""
import hashlib, json, os, secrets, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path('/home/lab/.local/state/android-cluster-release')
NETWORK = Path('/home/lab/.local/state/android-release-network')
sys.path.insert(0, str(ROOT / 'scripts'))
from android_release import canonical, digest, write_json
import android_release_hub as hub
import android_release_host as host
from android_release_lab_context import identity


def run(argv, timeout=45):
    result = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        # Native commands can include private profiles in their output.
        with (ROOT / 'bootstrap-private.log').open('ab') as stream:
            os.chmod(stream.name, 0o600); stream.write(result.stderr[-16384:])
        raise ValueError('isolated bootstrap command failed; retained private guest log')
    return result.stdout


def private(path, data):
    if path.exists():
        if path.read_bytes() != data: raise ValueError('preserve existing guest setup: ' + path.name)
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        os.chmod(path, 0o600); stream.write(data); stream.flush(); os.fsync(stream.fileno())


def service(unit, command, managed=False):
    fragment = Path.home() / '.config/systemd/user' / unit
    if any(any(c.isspace() or c in '%"\\' for c in str(arg)) for arg in command):
        raise ValueError('service arguments require simple absolute paths')
    private(fragment, ('# android-cluster owned lab fleet\n[Unit]\nDescription=Isolated cluster Android owner\n\n[Service]\n'
        'Type=simple\nUMask=0077\nTimeoutStopSec=20\nSendSIGKILL=no\nMemoryMax=1G\n'
        + ('Environment=GCHAT_OWNER_MANAGED_UPDATES=1\n' if managed else '')
        + 'ExecStart=' + ' '.join(map(str, command)) + '\n\n[Install]\nWantedBy=default.target\n').encode())
    run(['systemctl', '--user', 'daemon-reload'])
    run(['systemctl', '--user', 'enable', '--now', unit])
    return fragment


def main():
    os.umask(0o077)
    if os.getuid() != 1000: raise ValueError('isolated lab owner required')
    os.environ.update(XDG_RUNTIME_DIR='/run/user/1000', DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
    context = identity(json.loads((ROOT / 'context.json').read_text()))
    if run(['sudo', '-n', 'cat', '/sys/class/dmi/id/product_uuid']).decode().strip().lower() != context['vm_uuid']:
        raise ValueError('wrong lab owner')
    prepared = json.loads((ROOT / 'prepared.json').read_text())
    home = ROOT / 'hub-home'; fleet = ROOT / 'fleet'; state = ROOT / 'release'
    for directory in (home, fleet, state): directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    passphrase = home / 'passphrase'
    if not passphrase.exists(): private(passphrase, secrets.token_urlsafe(32).encode())
    config = {'state':str(state), 'hub_home':str(home), 'hub_directory':str(ROOT / 'hub'),
              'hub_unit':'gchat-android-cluster.service', 'fleet_unit':'gdrone-android-cluster.service',
              'fleet_config':str(fleet / 'controller.json'), 'fleet_binary':str(state / 'controller/active/gdrone-fleet'),
              'network_invitation':str(NETWORK / 'network/invitation'),
              'adb':str(ROOT / 'tools/platform-tools/adb')}
    binaries = {}
    for component, filename, destination in [('hub','gchat',ROOT / 'hub'),
            ('controller','gdrone-fleet',state / 'controller')]:
        source = ROOT / 'artifacts' / component / prepared['inputs'][component] / filename
        binaries[component] = hub.install_binary(destination, source, filename)
        if not (destination / 'active').exists(): hub.select(destination, binaries[component])
        elif digest(destination / 'active' / filename) != digest(source):
            raise ValueError('preserve an already deployed different owner')
    launcher = ROOT / 'launch-hub.py'
    private(launcher, ("import os\nfrom pathlib import Path\n"
        + 'home=Path(' + repr(str(home)) + ')\n'
        + 'args=' + repr([str(ROOT / 'hub/active/gchat'), 'daemon', '--home',str(home), '--gc2-carrier',
                '--network-config',str(NETWORK / 'network/installed.json'), '--chat-passphrase-file',str(passphrase)]) + '\n'
        + "if not (home/'profile.gcprotocol').exists(): args.append('--create')\n"
        + 'fleet=Path(' + repr(str(fleet / 'gchat-fleet.json')) + ')\n'
        + "if fleet.exists(): args += ['--fleet-config',str(fleet)]\nos.execv(args[0],args)\n").encode())
    fragment = service(config['hub_unit'], ['/usr/bin/python3', launcher], managed=True)
    endpoint = home / 'gcd.chat'
    until = time.monotonic() + 60
    while not endpoint.exists():
        if time.monotonic() >= until: raise TimeoutError('new isolated GChat socket unavailable')
        time.sleep(.25)
    if not Path(config['fleet_config']).exists():
        run([config['fleet_binary'], 'init', '--chat-endpoint', endpoint, '--state', fleet])
        run([config['fleet_binary'], 'register-mobile', '--config', config['fleet_config']])
        selected = json.loads(Path(config['fleet_config']).read_text())
        selected['channels'] = [x for x in selected['channels'] if x['name'] == 'android-x64']
        if len(selected['channels']) != 1: raise ValueError('one normal Android channel required')
        write_json(config['fleet_config'], selected)
        owner = host.active_hub(config)
        reply = hub.exchange(endpoint, selected['instanceId'], owner['pid'], {'kind':'disconnect'})
        if reply.get('kind') != 'snapshot' or reply['snapshot']['instance'].get('protocolLocked') is not True:
            raise ValueError('initial owner checkpoint did not complete')
        run(['systemctl','--user','restart',config['hub_unit']])
        time.sleep(1)
    selected = json.loads(Path(config['fleet_config']).read_text())
    instance = hub.wait_ready(config, digest(binaries['hub']), '', timeout=30)
    owner = host.active_hub(config)
    if not (ROOT / 'network-imported.json').exists():
        reply = hub.exchange(endpoint, selected['instanceId'], owner['pid'],
            {'kind':'import_network_invitation', 'code':Path(config['network_invitation']).read_text().strip()})
        if reply.get('kind') == 'error': raise ValueError('normal network import failed')
        write_json(ROOT / 'network-imported.json', {'schema':1,'instance_id':selected['instanceId'], 'at':time.time()})
    until = time.monotonic() + 75
    while True:
        status = hub.exchange(endpoint, selected['instanceId'], owner['pid'], {'kind': 'network_status'})['status']
        if status['state'] == 'connected': break
        if time.monotonic() >= until:
            raise TimeoutError('normal inbox routing must be ready before initial channel creation')
        time.sleep(1)
    write_json(ROOT / 'hub/enrollment.json', {'schema':1,'unit':config['hub_unit'],'fragment':str(fragment),
        'unit_sha256':digest(fragment),'instance_id':selected['instanceId']})
    fragment = service(config['fleet_unit'], [config['fleet_binary'],'run','--config',config['fleet_config']])
    hub.wait_controller(config, digest(binaries['controller']))
    write_json(state / 'controller/enrollment.json', {'schema':1,'unit':config['fleet_unit'],
        'fragment':str(fragment),'unit_sha256':digest(fragment)})
    hub.eligible(config); hub.eligible_controller(config)
    serial = context['android_pod_ip'] + ':5555'
    run([config['adb'],'connect',serial])
    target = {'id':'android-x64','kind':'android','serial':serial,'abi':'x86_64','channel':'android-x64'}
    if host.output(host.adb(config,target,'get-state')).strip() != b'device': raise ValueError('owned Android is unavailable')
    write_json(ROOT / 'host-config.json', dict(config, targets=[{'id':'hub','kind':'hub'}, target]))
    print(json.dumps({'schema':1,'state':'owners_bootstrapped','vm_uuid':context['vm_uuid'],
        'android_pod_uid':context['android_pod_uid'],'hub_sha256':digest(binaries['hub']),
        'controller_sha256':digest(binaries['controller']),'android_connected':True}),flush=True)


if __name__ == '__main__': main()
