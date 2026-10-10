#!/usr/bin/env python3
"""Prepare the owned workstation Android lane; preserve other release services."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

from android_release import command, digest, write_json
from android_release_host import build_identity


def prepare(state, install=False):
    for unit in ('gcoms-android-release.service', 'gcoms-android-warm.service'):
        observation = subprocess.run(['systemctl', '--user', 'show', unit, '-p', 'ActiveState', '--value'],
                                     capture_output=True, text=True, check=True)
        if observation.stdout.strip() in ('active', 'activating', 'deactivating'):
            raise ValueError('preserve the active Android release/warming job')
    state = state.resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime = state / 'runtime'
    runtime.mkdir(mode=0o700, exist_ok=True)
    scripts = Path(__file__).resolve().parent
    names = ('android_release.py', 'android_release_host.py', 'android_release_queue.py',
             'android_release_hub.py', 'android_release_network.py', 'android_release_qualify.py')
    for name in names:
        shutil.copy2(scripts / name, runtime / name)
    root = Path('/run/media/user/SSD-2/forgejo-data')
    events = root / 'android-release/events'
    events.mkdir(parents=True, mode=0o700, exist_ok=True)
    refs = {'gcoms': ('gcoms', 'main'), 'agent': ('gcoms', 'agent/mobile-android-aa5878dc'),
            'dropship': ('dropship', 'agent/mobile-android-019529de'),
            'gchat': ('gchat', 'main'), 'drone': ('drone', 'agent/mobile-gchat-worker')}
    sources = {name: {'repository': str(root / 'git/repositories/ghost-local' / (project + '.git')),
                      'project': project, 'ref': 'refs/heads/' + ref}
               for name, (project, ref) in refs.items()}
    sdk = '/run/media/user/SSD-2/tools/android-sdk'
    apksigner = sdk + '/build-tools/36.0.0/apksigner'
    apk = '/run/media/user/SSD-2/retained/ghost/retained-relay-20261008/android-agent-4a98864-ds55bf44c.apk'
    certs = subprocess.check_output([apksigner, 'verify', '--print-certs', apk], stderr=subprocess.PIPE, text=True)
    certificate = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})', certs)
    if len(certificate) != 1:
        raise ValueError('one previously verified Android signing certificate required')
    ndk = '/run/media/user/SSD-2/android-sdk/ndk/27.3.13750724'
    cmake = '/run/media/user/SSD-2/android-sdk/cmake/3.22.1'
    dependencies = {'sdk': ['gcoms'], 'installer': ['dropship', 'gcoms', 'drone', 'gchat'],
                    'apk': ['agent'], 'hub': ['gchat', 'gcoms'], 'worker': ['drone', 'gcoms', 'gchat'],
                    'controller': ['drone', 'gcoms', 'gchat']}
    config = {'schema': 1, 'state': str(state), 'event_directory': str(events), 'sources': sources,
              'runtime_sha256': {str(runtime / name): digest(runtime / name) for name in names},
              'targets': [{'id': 'hub', 'kind': 'hub'}, {'id': 'android-x64', 'kind': 'android',
                           'serial': 'emulator-5554', 'abi': 'x86_64', 'channel': 'android-x64'}],
              'adb': sdk + '/platform-tools/adb', 'apksigner': apksigner,
              'zipalign': sdk + '/build-tools/36.0.0/zipalign', 'certificate_sha256': certificate[0],
              'build_directory': str(state / 'build'), 'compiler_directory': str(state / 'compiler'),
              'minimum_free_bytes': 150 * 1024 ** 3, 'hub_unit': 'gchat-fleet-host.service',
              'warm_unit': 'gcoms-android-warm.service',
              'build_budgets': {'sdk': 16 * 1024 ** 3, 'installer': 4 * 1024 ** 3,
                                'apk': 2 * 1024 ** 3, 'hub': 8 * 1024 ** 3, 'worker': 8 * 1024 ** 3,
                                'controller': 8 * 1024 ** 3},
              'fleet_unit': 'gdrone-fleet.service',
              'fleet_binary': str(state / 'controller/active/gdrone-fleet'),
              'fleet_config': '/home/user/.local/state/gchat-fleet/controller.json',
              'baseline_receipt': '/run/media/user/SSD-2/retained/ghost/retained-relay-20261008/android-deployment-summary.json',
              'hub_directory': str(state / 'hub'), 'hub_home': '/home/user/.local/share/gchat-production',
              'hub_legacy_dropins': ['/home/user/.config/systemd/user/gchat-fleet-host.service.d/99zzzz-android-retained.conf'],
              'hub_activate': [sys.executable, str(runtime / 'android_release_hub.py'), 'activate'],
              'hub_rollback': [sys.executable, str(runtime / 'android_release_hub.py'), 'rollback'],
              'environment': {'ANDROID_HOME': sdk, 'ANDROID_NDK_HOME': ndk,
                              'PATH': cmake + '/bin:/usr/lib/jvm/java-21-openjdk-amd64/bin:' + os.environ['PATH'],
                              'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64',
                              'RUSTFLAGS': '', 'CARGO_INCREMENTAL': '0'},
              'toolchain': {'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
                            'ndk': Path(ndk, 'source.properties').read_text(),
                            'jni_ndk': Path(sdk, 'ndk/28.2.13676358/source.properties').read_text(),
                            'cmake': Path(cmake, 'source.properties').read_text(),
                            'java': subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-version'],
                                                   capture_output=True, text=True, check=True).stderr,
                            'builder_sha256': build_identity()},
              'builds': {name: {'sources': dependencies[name],
                                'command': [sys.executable, str(runtime / 'android_release_host.py'), 'build']}
                         for name in dependencies},
              'actions': {name: [sys.executable, str(runtime / 'android_release_host.py'), name]
                          for name in ('preflight', 'verify', 'activate', 'readiness', 'rollback')}}
    config.update(require_prepared=True, require_functional_rollback=True,
                  promotion_remote='ssh://ghost-forgejo/ghost-local/gcoms.git')
    destination = state / 'config.json'
    if destination.exists():
        previous = json.loads(destination.read_text())
        # Preserve owner-supplied managed activation hooks and verified baseline.
        for name in ('hub_activate', 'hub_rollback', 'baseline_receipt', 'hub_directory', 'hub_home', 'hub_legacy_dropins'):
            if previous.get(name): config[name] = previous[name]
    write_json(destination, config)
    if install:
        hooks = root / 'home/hooks/post-receive.d'
        hooks.mkdir(exist_ok=True)
        hook = hooks / '90-android-release'
        shutil.copy2(scripts / 'android_release_push_hook.sh', hook)
        hook.chmod(0o755)
        guards = root / 'home/hooks/pre-receive.d'
        guards.mkdir(exist_ok=True)
        guard = guards / '90-android-release'
        shutil.copy2(scripts / 'android_release_pre_receive.sh', guard)
        guard.chmod(0o755)
        units = Path.home() / '.config/systemd/user'
        units.mkdir(parents=True, exist_ok=True)
        commands = {'gcoms-android-release': [sys.executable, str(runtime / 'android_release_queue.py'), '--config', str(destination)],
                    'gcoms-android-warm': [sys.executable, str(runtime / 'android_release.py'), '--config', str(destination), 'prepare']}
        for unit, argv in commands.items():
            # The long-lived user manager predates docker-group membership.
            # Refresh this same user's supplementary groups, as the workstation
            # harness does; never restart the manager and its healthy services.
            argv = ['/usr/bin/sudo', '-n', '--preserve-env=PATH,DBUS_SESSION_BUS_ADDRESS,XDG_RUNTIME_DIR,TMPDIR',
                    '-u', pwd.getpwuid(os.getuid()).pw_name, *argv]
            # This workstation layout uses simple absolute paths. Refuse rather
            # than incorrectly quote a changed path in systemd's argv syntax.
            if any(re.search(r'[\s%"\\]', arg) for arg in argv):
                raise ValueError('systemd release paths need simple absolute names')
            (units / (unit + '.service')).write_text('[Unit]\nDescription=Bounded Android agent release\n\n[Service]\nType=oneshot\nUMask=0077\nExecStart=' +
                  ' '.join(argv) + '\nTimeoutStopSec=10\nTimeoutStartSec=' + ('3700' if unit.endswith('warm') else '620') + '\n')
            timer = ('OnBootSec=2min\nOnUnitActiveSec=12h\n' if unit.endswith('warm') else
                     'OnBootSec=15s\nOnUnitInactiveSec=5s\n')
            (units / (unit + '.timer')).write_text('[Unit]\nDescription=Android agent release scheduling\n\n[Timer]\n' + timer +
                  'AccuracySec=1s\nUnit=' + unit + '.service\n\n[Install]\nWantedBy=timers.target\n')
        command(['systemctl', '--user', 'daemon-reload'])
        command(['systemctl', '--user', 'enable', '--now', 'gcoms-android-release.timer', 'gcoms-android-warm.timer'])
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    print(prepare(args.state, args.install))
