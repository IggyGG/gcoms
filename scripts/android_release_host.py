#!/usr/bin/env python3
"""Linux workstation adapters for the Android release runner (no store upload)."""
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import zipfile

from android_release import command, digest, git, write_json

PACKAGE = 'boo.gcoms.agent'
ABIS = {'arm64-v8a': 'aarch64-linux-android', 'x86_64': 'x86_64-linux-android'}


def build_identity():
    # Provisioning/observation changes do not force recompilation. These are
    # the complete builtin compiler invocation and source preparation functions.
    body = json.dumps(ABIS, sort_keys=True) + ''.join(inspect.getsource(f) for f in
              (build, checkout, source_workspace, patch_gcoms, pinned_resolution))
    return hashlib.sha256(body.encode()).hexdigest()


def output(argv, timeout=20, cwd=None, env=None):
    return subprocess.check_output([str(a) for a in argv], stderr=subprocess.PIPE, timeout=timeout, cwd=cwd, env=env)


def checkout(config, name, commit, parent):
    destination = parent / name
    created = not destination.exists()
    if created:
        command(['git', 'clone', '--shared', '--no-checkout', config['sources'][name]['repository'], destination])
    if created or git(destination, 'rev-parse', 'HEAD').decode().strip() != commit:
        command(['git', '--shallow-file', '/dev/null', '-C', destination, 'checkout', '--detach', commit])
    if git(destination, 'status', '--porcelain', '--untracked-files=no').strip():
        raise ValueError('release source checkout was modified')
    return destination


def source_workspace(config, manifest, component):
    root = Path(config['build_directory']) / component
    root.mkdir(parents=True, exist_ok=True)
    workspace = root / 'sources'
    if not workspace.exists():
        # Keep an already prepared physical path when upgrading the first
        # hash-per-directory runner. Future source keys must not move unchanged
        # companion crates and invalidate Cargo's entire local dependency cache.
        for candidate in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not re.fullmatch('[0-9a-f]{64}', candidate.name) or not candidate.is_dir():
                continue
            names = config['builds'][component]['sources']
            if all((candidate / name / '.git').is_dir() and
                   git(candidate / name, 'rev-parse', 'HEAD').decode().strip() == manifest['sources'][name]
                   for name in names):
                workspace.symlink_to(candidate.name, target_is_directory=True)
                break
        workspace.mkdir(exist_ok=True)
    if not workspace.resolve().is_relative_to(root.resolve()):
        raise ValueError('release source workspace escapes its owned build root')
    return workspace


def patch_gcoms(consumer, companion):
    config = consumer / '.cargo/config.toml'
    if config.exists():
        return  # Dropship's committed sibling patch is already explicit.
    patches = []
    for path in sorted((companion / 'crates').glob('*/Cargo.toml')):
        name = tomllib.loads(path.read_text())['package']['name']
        if name == 'gcoms' or name.startswith('gcoms-'):
            patches.append(json.dumps(name) + ' = { path = ' + json.dumps(str(path.parent)) + ' }')
    config.parent.mkdir(exist_ok=True)
    config.write_text('[patch.crates-io]\n' + '\n'.join(patches) + '\n')


def pinned_resolution(original, companion, resolved):
    """Local patches may change resolution, never invent registry versions."""
    def external(data):
        return {(p['name'], p['version'], p['source'], p.get('checksum'))
                for p in tomllib.loads(data.decode()).get('package', []) if p.get('source')}
    if not external(resolved).issubset(external(original) | external(companion)):
        raise ValueError('derived dependencies differ from frozen source lockfiles')


def build(request):
    config, manifest, component = request['config'], request['manifest'], request['component']
    if config['toolchain'].get('builder_sha256') != build_identity():
        raise ValueError('compiler adapter changed after inputs were frozen')
    specification = config['builds'][component]
    artifact = Path(request['output'])
    artifact.mkdir(parents=True, mode=0o700, exist_ok=True)
    workspace = source_workspace(config, manifest, component)
    sources = {name: checkout(config, name, manifest['sources'][name], workspace)
               for name in specification['sources']}
    environment = dict(os.environ, **config.get('environment', {}))
    environment.pop('CARGO_ENCODED_RUSTFLAGS', None)
    environment['CARGO_BUILD_JOBS'] = '2'
    target = (Path(config['compiler_directory']) / component).resolve()
    environment['CARGO_TARGET_DIR'] = str(target)
    environment['WORKSTATION_BUILD_OUTPUTS'] = json.dumps([str(workspace), str(target), str(artifact)])
    environment['WORKSTATION_BUILD_BUDGET'] = str(config.get('build_budgets', {}).get(component, 16 * 1024 ** 3))
    log = Path(config['state']) / 'build-logs' / (component + '-' + manifest['inputs'][component] + '.log')
    log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    def run(argv, cwd, timeout=3300):
        # Wait for storage admission outside prior build outputs. A queued
        # launch in an old output's cwd would make that finished reservation
        # look active and could deadlock admission against its own cached work.
        command(['workstation-batch', '--', 'env', '--chdir=' + str(cwd), *map(str, argv)],
                cwd=Path(__file__).resolve().parent, env=environment, timeout=timeout, log=log)
    if component == 'sdk':
        run(['python3', 'scripts/build-mobile.py', 'android', '--roles', 'client', '--profiles', 'z',
             '--output', artifact], sources['gcoms'])
        run(['cargo', 'test', '--offline', '--locked', '-p', 'gcoms-node', '--all-features',
             '--lib', 'node::persist::tests::gc2_', '--', '--test-threads=1'], sources['gcoms'])
    elif component == 'installer':
        run(['sh', 'build/build-android.sh', 'both'], sources['dropship'])
        # Essential installer state/auth regressions, never a full platform matrix.
        run(['cargo', 'test', '--offline', '--locked', '--manifest-path', 'minimal/Cargo.toml',
             '-p', 'ds-minimal-core', '--features', 'qualification', '--lib', 'session'], sources['dropship'])
        run(['sh', 'build/test-minimal-mobile-install.sh'], sources['dropship'])
        for abi in ('arm64', 'x86_64'):
            shutil.copy2(sources['dropship'] / ('build/libdsminimal-android-' + abi + '.a'), artifact)
    elif component == 'apk':
        sdk = Path(config['state']) / 'artifacts/sdk' / manifest['inputs']['sdk'] / 'android'
        installer = Path(config['state']) / 'artifacts/installer' / manifest['inputs']['installer']
        run(['./gradlew', '--offline', '-PgcomsAgent=true', '-PdsminimalLibDir=' + str(installer),
             '-PgcomsNativeRoot=' + str(sdk), ':agent:assembleClientRelease', ':agent:lintClientRelease'],
            sources['agent'] / 'mobile/android')
        shutil.copy2(sources['agent'] / 'mobile/android/agent/build/outputs/apk/client/release/agent-client-release.apk',
                     artifact / 'agent.apk')
    elif component == 'hub':
        patch_gcoms(sources['gchat'], sources['gcoms'])
        environment.update(GCHAT_SOURCE_COMMIT=manifest['sources']['gchat'],
                           GCOMS_SOURCE_COMMIT=manifest['sources']['gcoms'],
                           GCHAT_RELEASE_ID=manifest['release_id'])
        lock = sources['gchat'] / 'Cargo.lock'
        original = lock.read_bytes()
        names = sorted(p['name'] for p in tomllib.loads(original.decode())['package']
                       if p['name'] == 'gcoms' or p['name'].startswith('gcoms-'))
        try:
            run(['cargo', 'update', '--offline', *[arg for name in names for arg in ('-p', name)]], sources['gchat'])
            pinned_resolution(original, (sources['gcoms'] / 'Cargo.lock').read_bytes(), lock.read_bytes())
            shutil.copy2(lock, artifact / 'resolved-Cargo.lock')
            metadata = json.loads(output(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1',
                                          '--manifest-path', sources['gchat'] / 'Cargo.toml'], timeout=45,
                                         cwd=sources['gchat'], env=environment))
            for package in metadata['packages']:
                if package['name'] == 'gcoms' or package['name'].startswith('gcoms-'):
                    if not Path(package['manifest_path']).resolve().is_relative_to(sources['gcoms'].resolve()):
                        raise ValueError('headless hub resolved an unselected registry SDK')
            run(['cargo', 'build', '--offline', '--release', '--locked', '-p', 'gchat-tui',
                 '--bin', 'gchat', '--features', 'gc2-carrier'], sources['gchat'])
        finally:
            # This is an owned detached build overlay. Preserve the committed
            # source lock, including after cancellation, and retain the actual
            # resolution separately with the artifact's byte hashes.
            lock.write_bytes(original)
        shutil.copy2(target / 'release/gchat', artifact / 'gchat')
    elif component == 'worker':
        llvm = Path(environment['ANDROID_NDK_HOME']) / 'toolchains/llvm/prebuilt/linux-x86_64/bin'
        for abi, triple in ABIS.items():
            environment['CARGO_TARGET_' + triple.replace('-', '_').upper() + '_LINKER'] = str(llvm / (triple + '26-clang'))
            environment['CC_' + triple.replace('-', '_')] = str(llvm / (triple + '26-clang'))
            environment['AR_' + triple.replace('-', '_')] = str(llvm / 'llvm-ar')
            environment['RUSTFLAGS'] = '-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384'
            run(['cargo', 'rustc', '--offline', '--locked', '--release', '-p', 'gdrone-mobile',
                 '--no-default-features', '--features', 'fleet,host', '--lib', '--crate-type', 'cdylib',
                 '--target', triple], sources['drone'])
            destination = artifact / abi
            destination.mkdir(exist_ok=True)
            shutil.copy2(target / triple / 'release/libgdrone_mobile.so', destination / 'worker.so')
            run([llvm / 'llvm-strip', '--strip-unneeded', destination / 'worker.so'], workspace)
            symbols = output([llvm / 'llvm-nm', '-D', '--defined-only', destination / 'worker.so']).decode()
            for symbol in ('drone_mobile_abi_version', 'drone_mobile_bootstrap_start',
                           'drone_mobile_bootstrap_status', 'drone_mobile_bootstrap_stop'):
                if not re.search(r'\b' + symbol + r'$', symbols, re.MULTILINE):
                    raise ValueError('downloaded Android worker omits its verified launch ABI')
    else:
        raise ValueError('unknown Android build component')
    files = {str(p.relative_to(artifact)): digest(p) for p in artifact.rglob('*') if p.is_file()}
    write_json(artifact / 'receipt.json', {'schema': 1, 'component': component,
               'input_sha256': manifest['inputs'][component],
               'sources': {n: manifest['sources'][n] for n in specification['sources']},
               'files': files, 'qualification': 'focused Android release inputs; live readiness checked separately'})


def artifact(request, component, name):
    return Path(request['config']['state']) / 'artifacts' / component / request['manifest']['inputs'][component] / name


def adb(config, target, *args):
    return [config['adb'], '-s', target['serial'], *args]


def active_hub(config):
    unit = config['hub_unit']
    state = output(['systemctl', '--user', 'show', unit, '-p', 'ActiveState', '--value']).decode().strip()
    pid = int(output(['systemctl', '--user', 'show', unit, '-p', 'MainPID', '--value']).strip())
    if state != 'active' or pid < 1:
        raise ValueError('hub is not active')
    try:
        sha = digest('/proc/' + str(pid) + '/exe')
    except PermissionError:
        sha = output(['sudo', '-n', 'sha256sum', '/proc/' + str(pid) + '/exe']).decode().split()[0]
    return {'pid': pid, 'sha256': sha}


def preflight(request):
    config = request['config']
    if shutil.disk_usage(config['state']).free < config['minimum_free_bytes']:
        raise ValueError('Android build storage headroom is insufficient')
    for path in ('adb', 'apksigner', 'zipalign'):
        if not os.access(config[path], os.X_OK):
            raise ValueError('Android toolchain is not prepared')
    if request.get('warm'):
        return
    # Do not repeatedly exercise a production hub with an already known failed
    # Android baseline. Initial qualification is a separate explicit operation.
    baseline = json.loads(Path(config['baseline_receipt']).read_text())
    android = baseline.get('android', {})
    if (android.get('full_download_verified') is not True
            or android.get('loaded_worker_ready') is not True):
        write_json(Path(request['directory']) / 'preflight-block.json',
                   {'reason': 'android_runtime_download_load_baseline_failed'})
        raise ValueError('Android runtime baseline needs full download/load qualification')
    active_hub(config)
    for target in request['manifest']['targets']:
        if target['kind'] == 'android':
            if not target['serial'].startswith('emulator-'):
                raise ValueError('this workstation adapter requires an owned Android emulator')
            if output(adb(config, target, 'get-state')).strip() != b'device':
                raise ValueError('Android target is offline')


def verify(request):
    config = request['config']
    apk = artifact(request, 'apk', 'agent.apk')
    certificate = output([config['apksigner'], 'verify', '--verbose', '--print-certs', apk]).decode()
    found = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})', certificate)
    if found != [config['certificate_sha256']]:
        raise ValueError('Android APK signing certificate differs')
    command([config['zipalign'], '-c', '-P', '16', '4', apk])
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        if any(n.endswith(('agent-config.json', 'dropship-config.json')) for n in names):
            raise ValueError('APK contains private deployment configuration')
        for abi in ABIS:
            for library in ('libdsminimal_jni.so', 'libgcoms_mobile.so'):
                if 'lib/' + abi + '/' + library not in names:
                    raise ValueError('APK omits required Android native input')
            native = artifact(request, 'sdk', 'android/client/' + abi + '/libgcoms_mobile.so')
            if hashlib.sha256(archive.read('lib/' + abi + '/libgcoms_mobile.so')).hexdigest() != digest(native):
                raise ValueError('APK embeds different SDK native bytes')
        # ZIP alignment alone cannot establish Android 16 KiB compatibility.
        llvm = Path(config['environment']['ANDROID_NDK_HOME']) / 'toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf'
        with tempfile.TemporaryDirectory(dir=config['state']) as temporary:
            for name in sorted(names):
                if name.startswith('lib/') and name.endswith('.so'):
                    file = Path(temporary) / 'library.so'
                    file.write_bytes(archive.read(name))
                    aligned_loads(output([llvm, '-lW', file]).decode())
    metadata = json.loads(artifact(request, 'sdk', 'android/client/build.json').read_text())
    if metadata.get('role') != 'client' or metadata.get('fixtures') is not False or metadata.get('push') is not False:
        raise ValueError('SDK is not the actual nonfixture Android client')


def aligned_loads(headers):
    rows = [line.split() for line in headers.splitlines() if line.strip().startswith('LOAD ')]
    if not rows or any(int(row[-1], 16) < 16384 for row in rows):
        raise ValueError('Android native load segments require 16 KiB alignment')


def private_file(config, target, relative):
    path = '/data/user/0/' + PACKAGE + '/files/' + relative
    return output(adb(config, target, 'exec-out', 'cat', path))


def identity(config, target):
    return hashlib.sha256(private_file(config, target, 'd/identity.seed')).hexdigest()


def route_expiry(value):
    encoded = value.get('gc2RoutingBundleB64', '')
    if not isinstance(encoded, str) or len(encoded) > 1664:
        raise ValueError('GC/2 routing bundle exceeds bounds')
    raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
    if (len(raw) < 6 or raw[:5] != b'GCRB\x02' or not 1 <= raw[5] <= 8
            or len(raw) != 6 + raw[5] * 155):
        raise ValueError('invalid GC/2 routing bundle')
    return min(int.from_bytes(raw[6 + i * 155 + 147:6 + (i + 1) * 155], 'big')
               for i in range(raw[5]))


def publish_worker(request, target, file, restoring=False):
    config = request['config']
    fleet = json.loads(Path(config['fleet_config']).read_text())
    row = next(r for r in fleet['channels'] if r['name'] == target['channel'])
    name = row['defaultArtifact']
    if not re.fullmatch('[A-Za-z0-9_.-]{1,128}', name) or name in ('.', '..'):
        raise ValueError('worker publication must use an existing simple channel filename')
    folder = Path(request['directory']) / target['id']
    folder.mkdir(mode=0o700, exist_ok=True)
    staged = folder / name
    shutil.copy2(file, staged)
    os.chmod(staged, 0o600)
    command([config['fleet_binary'], 'publish', '--config', config['fleet_config'],
             '--channel', target['channel'], '--file', staged], timeout=45, log=folder / 'publish.log')
    wanted = digest(file)
    until = min(time.time() + 20, request['manifest']['pushed_at'] + (595 if restoring else 415))
    while True:
        state = json.loads((Path(fleet['state']) / 'releases.json').read_text())
        current = state.get('active', {}).get(target['channel'], {})
        if current.get('publication', {}).get('sha256') == wanted:
            return
        if time.time() >= until:
            raise TimeoutError('controller has not selected the published Android worker')
        time.sleep(.5)


def activate(request):
    config, manifest = request['config'], request['manifest']
    directory = Path(request['directory'])
    hub = active_hub(config)
    desired_hub = digest(artifact(request, 'hub', 'gchat'))
    if hub['sha256'] != desired_hub:
        # The existing managed installer owns production checkpoint/rollback.
        # Never manufacture another persistent ExecStart override here.
        if not config.get('hub_activate') or not config.get('hub_rollback'):
            raise ValueError('a qualified managed hub activation adapter is required')
        write_json(directory / 'hub-before.json', hub)
        command(config['hub_activate'] + [str(directory / 'request.json')], timeout=90,
                log=directory / 'hub-activation.log')
        if active_hub(config)['sha256'] != desired_hub:
            raise ValueError('hub has not activated the exact release artifact')
    fleet = json.loads(Path(config['fleet_config']).read_text())
    releases = json.loads((Path(fleet['state']) / 'releases.json').read_text())
    for target in manifest['targets']:
        if target['kind'] != 'android':
            continue
        current = releases.get('active', {}).get(target['channel'], {})
        previous_sha = current.get('publication', {}).get('sha256', '')
        worker = artifact(request, 'worker', target['abi'] + '/worker.so')
        if previous_sha == digest(worker):
            continue
        if not re.fullmatch('[0-9a-f]{64}', previous_sha):
            raise ValueError('a retained previous Android worker is required for restoration')
        previous_file = Path(fleet['state']) / 'artifacts' / previous_sha
        if digest(previous_file) != previous_sha:
            raise ValueError('previous Android worker bytes changed')
        folder = directory / target['id']
        folder.mkdir(mode=0o700, exist_ok=True)
        write_json(folder / 'worker-before.json', {'sha256': previous_sha, 'path': str(previous_file)})
        publish_worker(request, target, worker)
    states = []
    for target in manifest['targets']:
        if target['kind'] != 'android':
            continue
        command(adb(config, target, 'root'))
        command(adb(config, target, 'wait-for-device'))
        if output(adb(config, target, 'shell', 'id', '-u')).strip() != b'0':
            raise ValueError('private Android provisioning requires the owned rootable emulator')
        folder = directory / target['id']
        folder.mkdir(mode=0o700, exist_ok=True)
        installed = output(adb(config, target, 'shell', 'pm', 'path', PACKAGE)).decode().strip()
        if not installed.startswith('package:/data/app/') or '\n' in installed:
            raise ValueError('one existing Android package required for safe restoration')
        previous = folder / 'previous.apk'
        command(adb(config, target, 'pull', installed.removeprefix('package:'), previous))
        seed = identity(config, target)
        (folder / 'previous-config.json').write_bytes(private_file(config, target, 'dropship-config.json'))
        os.chmod(folder / 'previous-config.json', 0o600)
        states.append({'target': target, 'identity_sha256': seed, 'previous_apk_sha256': digest(previous)})
        write_json(directory / 'android-before.json', states)
        command(adb(config, target, 'shell', 'am', 'force-stop', PACKAGE))
        command(adb(config, target, 'install', '-r', artifact(request, 'apk', 'agent.apk')), timeout=45)
        pid_uid = output(adb(config, target, 'shell', 'stat', '-c', '%u', '/data/user/0/' + PACKAGE)).decode().strip()
        if not pid_uid.isdigit():
            raise ValueError('Android application owner not found')
        profile = folder / 'profile.json'
        unit = 'android-release-mint-' + manifest['release_id'][:16] + '-' + target['id']
        write_json(folder / 'provider.json', {'unit': unit})
        command(['systemd-run', '--user', '--collect', '--unit=' + unit,
                 '--property=RuntimeMaxSec=600', '--property=TimeoutStopSec=5',
                 '--property=StandardOutput=append:' + str(folder / 'mint.log'),
                 '--property=StandardError=append:' + str(folder / 'mint.log'),
                 config['fleet_binary'], 'mint-ds', '--config', config['fleet_config'],
                 '--channel', target['channel'], '--output', profile, '--keep-alive', '600'])
        until = min(time.time() + 45, manifest['pushed_at'] + 415)
        while not profile.exists():
            if time.time() >= until:
                raise TimeoutError('fresh Android profile mint did not complete')
            time.sleep(.5)
        value = json.loads(profile.read_text())
        if value.get('target') != target['channel'] or value.get('expiresAtUnix', 0) < manifest['pushed_at'] + 600:
            raise ValueError('Android profile target/expiry differs')
        # Inspect actual introductions, not the longer JSON profile TTL. Native
        # authenticated contact/capability verification remains authoritative.
        if route_expiry(value) < manifest['pushed_at'] + 600:
            raise ValueError('actual GC/2 introductions expire during deployment')
        nonce = {'release_id': manifest['release_id'], 'apk_sha256': digest(artifact(request, 'apk', 'agent.apk')),
                 'worker_sha256': digest(artifact(request, 'worker', target['abi'] + '/worker.so'))}
        write_json(folder / 'deployment-request.json', nonce)
        for source, name in ((profile, 'dropship-config.json'), (folder / 'deployment-request.json', 'deployment-request.json')):
            destination = '/data/user/0/' + PACKAGE + '/files/' + name
            command(adb(config, target, 'push', source, destination))
            command(adb(config, target, 'shell', 'chown', pid_uid + ':' + pid_uid, destination))
            command(adb(config, target, 'shell', 'chmod', '600', destination))
        command(adb(config, target, 'shell', 'am', 'start', '-n', PACKAGE + '/.MainActivity'))


def readiness(request):
    config, manifest = request['config'], request['manifest']
    directory = Path(request['directory'])
    rows = []
    for target in manifest['targets']:
        if target['kind'] == 'hub':
            if active_hub(config)['sha256'] != digest(artifact(request, 'hub', 'gchat')):
                raise ValueError('running hub artifact differs')
            rows.append(dict(target, healthy=True, matches=True))
            continue
        expected = json.loads((directory / target['id'] / 'deployment-request.json').read_text())
        until = manifest['pushed_at'] + 535
        while True:
            try:
                proof = json.loads(private_file(config, target, 'deployment-ready.json'))
                pid = output(adb(config, target, 'shell', 'pidof', PACKAGE)).decode().strip()
                ready(proof, expected, pid)
                if identity(config, target) != next(r['identity_sha256'] for r in
                        json.loads((directory / 'android-before.json').read_text()) if r['target']['id'] == target['id']):
                    raise ValueError('Android identity changed during deployment')
                break
            except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError, ValueError):
                if time.time() >= until:
                    raise TimeoutError('Android full download/worker readiness missing')
                time.sleep(1)
        installed = output(adb(config, target, 'shell', 'pm', 'path', PACKAGE)).decode().strip().removeprefix('package:')
        actual_sha = output(adb(config, target, 'shell', 'sha256sum', installed)).decode().split()[0]
        if actual_sha != expected['apk_sha256']:
            raise ValueError('installed APK differs from verified release')
        rows.append(dict(target, healthy=True, matches=True, full_download_verified=True,
                         loaded_worker_ready=True, identity_preserved=True))
    write_json(directory / 'live.json', {'release_id': manifest['release_id'],
                                        'observed_at': time.time(), 'targets': rows})
    cleanup(request)


def ready(proof, expected, pid):
    if any(proof.get(k) != v for k, v in expected.items()):
        raise ValueError('Android readiness belongs to other release bytes')
    if (not pid.isdigit() or proof.get('process_id') != int(pid)
            or proof.get('full_download_verified') is not True
            or proof.get('loaded_worker_ready') is not True
            or proof.get('admission_verified') is not True):
        raise ValueError('current Android worker is not verified and ready')


def cleanup(request):
    directory, config = Path(request['directory']), request['config']
    for target in request['manifest']['targets']:
        if target['kind'] == 'android':
            marker = directory / target['id'] / 'provider.json'
            if marker.exists():
                command(['systemctl', '--user', 'stop', json.loads(marker.read_text())['unit']], timeout=10)
            command(adb(config, target, 'unroot'), timeout=10)


def rollback(request):
    directory, config = Path(request['directory']), request['config']
    marker = directory / 'android-before.json'
    if marker.exists():
        for before in json.loads(marker.read_text()):
            target = before['target']
            command(adb(config, target, 'root'), timeout=10)
            command(adb(config, target, 'wait-for-device'), timeout=10)
            command(adb(config, target, 'shell', 'am', 'force-stop', PACKAGE), timeout=10)
            folder = directory / target['id']
            if digest(folder / 'previous.apk') != before['previous_apk_sha256']:
                raise ValueError('retained previous Android APK changed')
            command(adb(config, target, 'install', '-r', '-d', folder / 'previous.apk'), timeout=25)
            installed = output(adb(config, target, 'shell', 'pm', 'path', PACKAGE)).decode().strip().removeprefix('package:')
            installed_sha = output(adb(config, target, 'shell', 'sha256sum', installed)).decode().split()[0]
            if installed_sha != before['previous_apk_sha256']:
                raise ValueError('previous Android APK was not restored')
            if identity(config, target) != before['identity_sha256']:
                raise ValueError('Android restoration changed the retained identity')
            destination = '/data/user/0/' + PACKAGE + '/files/dropship-config.json'
            command(adb(config, target, 'push', folder / 'previous-config.json', destination), timeout=10)
            uid = output(adb(config, target, 'shell', 'stat', '-c', '%u', '/data/user/0/' + PACKAGE)).decode().strip()
            command(adb(config, target, 'shell', 'chown', uid + ':' + uid, destination), timeout=10)
            command(adb(config, target, 'shell', 'chmod', '600', destination), timeout=10)
    if (directory / 'hub-before.json').exists():
        command(config['hub_rollback'] + [str(directory / 'request.json')], timeout=45,
                log=directory / 'hub-rollback.log')
        before = json.loads((directory / 'hub-before.json').read_text())
        if active_hub(config)['sha256'] != before['sha256']:
            raise ValueError('previous hub artifact was not restored')
    for target in request['manifest']['targets']:
        marker = directory / target['id'] / 'worker-before.json'
        if target['kind'] == 'android' and marker.exists():
            previous = json.loads(marker.read_text())
            if digest(previous['path']) != previous['sha256']:
                raise ValueError('previous worker changed before restoration')
            publish_worker(request, target, previous['path'], restoring=True)
    cleanup(request)
    write_json(directory / 'rollback.json', {'previous_artifacts_verified': True,
                                            'functional_readiness_verified': False})


def main():
    def interrupted(_number, _frame):
        raise InterruptedError('release adapter cancelled')
    signal.signal(signal.SIGTERM, interrupted)
    operation, path = sys.argv[1:]
    request = json.loads(Path(path).read_text())
    {'build': build, 'preflight': preflight, 'verify': verify, 'activate': activate,
     'readiness': readiness, 'rollback': rollback}[operation](request)


if __name__ == '__main__':
    main()
