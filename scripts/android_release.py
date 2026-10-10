#!/usr/bin/env python3
"""Bounded Android-agent releases; artifacts and live readiness are separate."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

LIMIT_SECONDS = 600
ACTIVATION_SECONDS = 540  # Reserve the last minute for restoration.
COMPONENTS = ('sdk', 'installer', 'apk', 'hub', 'worker', 'controller')
STAGE_SECONDS = {'preflight': 60, 'building': 60, 'verifying': 60,
                 'activation': 180, 'readiness': ACTIVATION_SECONDS}
DEPENDENCIES = {'sdk': (), 'installer': (), 'hub': (), 'worker': (), 'controller': (),
                'apk': ('sdk', 'installer')}
OPERATION_FILES = frozenset({
    'scripts/android_release.py', 'scripts/android_release_host.py',
    'scripts/android_release_queue.py', 'scripts/android_release_push_hook.sh',
    'scripts/android_release_pre_receive.sh', 'scripts/android_release_setup.py',
    'scripts/android_release_hub.py', 'scripts/android_release_network.py',
    'scripts/android_release_qualify.py', 'scripts/tests/android_release_test.py',
})
GCHAT_OPERATION_FILES = frozenset({
    'scripts/release_controller.py', 'scripts/release_deployment.py',
    'scripts/release_inputs.py', 'scripts/tests/release_controller_test.py',
    'scripts/tests/release_inputs_test.py',
})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class Deadline:
    def __init__(self, pushed_at, now=None, limit=LIMIT_SECONDS):
        now = time.time() if now is None else now
        if type(pushed_at) not in (int, float) or not 0 < pushed_at <= now:
            raise ValueError('valid original push time required')
        self.started = pushed_at
        self.ends = pushed_at + limit
        self.cap = self.ends
        # Also protect against the wall clock stepping backwards during a run.
        self.monotonic_end = time.monotonic() + max(0, self.ends - now)

    def remaining(self, activation=False):
        reserve = LIMIT_SECONDS - ACTIVATION_SECONDS if activation else 0
        seconds = min(self.ends - time.time() - reserve,
                      self.monotonic_end - time.monotonic() - reserve,
                      self.cap - time.time())
        if seconds <= 0:
            raise TimeoutError('Android push-to-live deadline expired')
        return seconds


def command(argv, cwd=None, env=None, timeout=30, log=None):
    """No shell, bounded process group, private output; never print credentials."""
    stream = open(log, 'ab') if log else subprocess.DEVNULL
    if log:
        os.chmod(log, 0o600)
    try:
        process = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env,
                                   stdout=stream, stderr=stream, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            except ProcessLookupError:
                pass
            raise
        if status:
            raise RuntimeError('release command failed with exit code ' + str(status))
    finally:
        if log:
            stream.close()


def git(repo, *args):
    return subprocess.check_output(['git', '--shallow-file', '/dev/null', '-C', str(repo),
                                    *args], stderr=subprocess.PIPE, timeout=30)


def source_tree(repo, commit):
    rows = []
    for record in git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if record:
            metadata, path = record.split(b'\t', 1)
            mode, kind, object_id = metadata.decode().split()
            if kind != 'blob':
                raise ValueError('release sources must not contain submodules')
            rows.append([path.decode(), mode, object_id])
    if not rows:
        raise ValueError('empty source tree')
    return rows


def included(project, component, name):
    """Reviewed platform/prose exclusions; unknown files remain build inputs."""
    if name.endswith('.md') or name.startswith(('docs/', 'test-evidence/')):
        return False
    if project == 'gchat' and name in GCHAT_OPERATION_FILES:
        return False  # Independently qualified controller operations, not native code.
    if project == 'gcoms':
        if name.startswith(('mobile/apple/', 'mobile/push/', 'packages/', 'examples/', 'fuzz/')):
            return False
        if name.startswith('mobile/android/'):
            return component == 'apk' and not name.startswith(('mobile/android/sample/', 'mobile/android/probe/'))
        if name.startswith('mobile/native/'):
            return component == 'sdk'
        if name in OPERATION_FILES:
            return False  # Release operations have their own focused gate.
        if name.startswith(('scripts/', '.github/', '.forgejo/')):
            return component in ('sdk', 'installer', 'hub', 'worker', 'controller')
        return component in ('sdk', 'installer', 'hub', 'worker', 'controller')
    if project == 'agent':
        return name.startswith('mobile/android/') and not name.startswith((
            'mobile/android/sample/', 'mobile/android/probe/'))
    return True


def inputs(config, sources):
    trees = {name: source_tree(row['repository'], sources[name])
             for name, row in config['sources'].items()}
    keys = {}
    for component in COMPONENTS:
        specification = config['builds'][component]
        rows = {name: [r for r in trees[name] if included(name, component, r[0])]
                for name in specification['sources']}
        keys[component] = hashlib.sha256(canonical({
            'schema': 1, 'component': component, 'sources': rows,
            'toolchain': config['toolchain'], 'build': specification,
            'environment': config.get('environment', {}),
            'dependencies': {name: keys[name] for name in DEPENDENCIES[component]},
            'worker_abis': sorted({row.get('abi') for row in config['targets'] if row['kind'] == 'android'})
                             if component == 'worker' else None
        })).hexdigest()
    return keys


def freeze(config, pushed_at, commits=None):
    commits = commits or {}
    sources = {}
    for name, row in config['sources'].items():
        ref = commits.get(name, row['ref'])
        sources[name] = git(row['repository'], 'rev-parse', '--verify', ref + '^{commit}').decode().strip()
    value = {'schema': 1, 'pushed_at': pushed_at, 'sources': sources,
             'inputs': inputs(config, sources), 'targets': config['targets'],
             'configuration_sha256': hashlib.sha256(canonical(config)).hexdigest()}
    value['release_id'] = hashlib.sha256(canonical(value)).hexdigest()
    return value


def cached_artifact(config, component, key):
    root = Path(config['state']) / 'artifacts' / component / key
    marker = root / 'receipt.json'
    if not marker.is_file():
        return None
    value = json.loads(marker.read_text())
    if value.get('component') != component or value.get('input_sha256') != key:
        raise ValueError('cached artifact input binding changed')
    files = value.get('files')
    if not isinstance(files, dict) or not files:
        raise ValueError('cached artifact has no verified bytes')
    for name, sha in files.items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink() or digest(path) != sha:
            raise ValueError('cached artifact bytes changed')
    return value


def prepare_release(config, manifest=None):
    """Prepare exact sources without starting a live deployment clock."""
    manifest = manifest or freeze(config, time.time())
    receipt = deploy(config, manifest, warm=True)
    if receipt['state'] != 'warmed':
        raise ValueError('release preparation failed; original receipt retained')
    value = {key: manifest[key] for key in ('sources', 'inputs', 'targets', 'configuration_sha256')}
    value.update(schema=1, kind='android-prepared-release',
                 artifacts={name: hashlib.sha256(canonical(cached_artifact(config, name, manifest['inputs'][name]))).hexdigest()
                            for name in COMPONENTS})
    value['prepared_id'] = hashlib.sha256(canonical(value)).hexdigest()
    path = Path(config['state']) / 'prepared' / (value['prepared_id'] + '.json')
    if path.exists() and json.loads(path.read_text()) != value:
        raise ValueError('immutable prepared release changed')
    write_json(path, value)
    write_json(Path(config['state']) / 'prepared-latest.json', {'prepared_id': value['prepared_id']})
    return value


def prepared_release(config, ident):
    import re
    if not isinstance(ident, str) or not re.fullmatch('[0-9a-f]{64}', ident):
        raise ValueError('invalid prepared release identifier')
    path = Path(config['state']) / 'prepared' / (ident + '.json')
    if path.is_symlink() or path.stat().st_size > 128 * 1024:
        raise ValueError('unsafe prepared release receipt')
    value = json.loads(path.read_text())
    unsigned = {key: item for key, item in value.items() if key != 'prepared_id'}
    if (value.get('schema') != 1 or value.get('kind') != 'android-prepared-release'
            or value.get('prepared_id') != ident or hashlib.sha256(canonical(unsigned)).hexdigest() != ident
            or value.get('configuration_sha256') != hashlib.sha256(canonical(config)).hexdigest()
            or value.get('targets') != config['targets'] or value.get('inputs') != inputs(config, value['sources'])):
        raise ValueError('prepared source/configuration binding changed')
    for component in COMPONENTS:
        artifact = cached_artifact(config, component, value['inputs'][component])
        if artifact is None or hashlib.sha256(canonical(artifact)).hexdigest() != value['artifacts'].get(component):
            raise ValueError('prepared artifact missing or changed')
    return value


def promotion_manifest(config, ident, pushed_at):
    prepared = prepared_release(config, ident)
    value = {key: prepared[key] for key in ('sources', 'inputs', 'targets', 'configuration_sha256')}
    value.update(schema=1, pushed_at=pushed_at, prepared_id=ident)
    value['release_id'] = hashlib.sha256(canonical(value)).hexdigest()
    return value


def promote(config, ident):
    """Gate before the immutable tag push; the server supplies the live clock."""
    prepared = prepared_release(config, ident)
    manifest = promotion_manifest(config, ident, time.time())
    directory = Path(config['state']) / 'promotion-checks' / ident
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = directory / 'request.json'
    write_json(request, {'config': config, 'manifest': manifest, 'directory': str(directory),
                         'artifacts': {c: cached_artifact(config, c, manifest['inputs'][c]) for c in COMPONENTS},
                         'warm': False})
    adapter(config, 'preflight', request, Deadline(manifest['pushed_at']), directory)
    tag = 'refs/tags/android-release/' + ident
    repository = config['sources']['gcoms']['repository']
    if git(repository, 'for-each-ref', '--format=%(objectname)', tag).strip():
        raise ValueError('release tag already promoted; retain its original push receipt')
    command(['git', '--shallow-file', '/dev/null', '-C', repository, 'push',
             config['promotion_remote'], prepared['sources']['gcoms'] + ':' + tag],
            timeout=45, log=directory / 'push.log')
    return {'state': 'promotion_pushed', 'prepared_id': ident, 'ref': tag}


def build(config, manifest, component, deadline, directory):
    key = manifest['inputs'][component]
    cached = cached_artifact(config, component, key)
    if cached:
        return dict(cached, cache_hit=True)
    out = Path(config['state']) / 'artifacts' / component / key
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = directory / (component + '-request.json')
    write_json(request, {'manifest': manifest, 'component': component,
                        'output': str(out), 'config': config})
    command(config['builds'][component]['command'] + [str(request)],
            timeout=deadline.remaining(activation=True), log=directory / (component + '.log'))
    value = cached_artifact(config, component, key)
    if not value:
        raise ValueError('build did not retain a verified artifact receipt')
    if value.get('sources') != {name: manifest['sources'][name]
                                for name in config['builds'][component]['sources']}:
        raise ValueError('new artifact source binding differs from frozen sources')
    return dict(value, cache_hit=False)


def checked_targets(manifest, proof):
    kinds = {row['id']: row['kind'] for row in manifest['targets']}
    expected = {row['id'] for row in manifest['targets']}
    if len(expected) != len(manifest['targets']) or not any(k == 'android' for k in kinds.values()):
        raise ValueError('unique targets including Android required')
    rows = proof.get('targets', [])
    if len(rows) != len(expected) or {row.get('id') for row in rows} != expected:
        raise ValueError('live verification omits or duplicates a deployment target')
    for row in rows:
        if row.get('kind') != kinds[row['id']]:
            raise ValueError('deployment target kind changed')
        if row.get('healthy') is not True or row.get('matches') is not True:
            raise ValueError('target has not activated the selected artifact')
        if row.get('kind') == 'android' and (
                row.get('full_download_verified') is not True or row.get('loaded_worker_ready') is not True
                or row.get('identity_preserved') is not True):
            raise ValueError('Android full download and in-process worker readiness required')
    if proof.get('release_id') != manifest['release_id']:
        raise ValueError('live verification belongs to another release')


def adapter(config, name, request, deadline, directory, activation=True):
    command(config['actions'][name] + [str(request)],
            timeout=deadline.remaining(activation=activation), log=directory / (name + '.log'))


def deploy(config, manifest, warm=False):
    if any(digest(path) != sha for path, sha in config.get('runtime_sha256', {}).items()):
        raise ValueError('release adapter bytes changed after configuration was prepared')
    unsigned = {k: v for k, v in manifest.items() if k != 'release_id'}
    if (manifest.get('release_id') != hashlib.sha256(canonical(unsigned)).hexdigest()
            or manifest.get('configuration_sha256') != hashlib.sha256(canonical(config)).hexdigest()
            or manifest['inputs'] != inputs(config, manifest['sources'])):
        raise ValueError('immutable release inputs/configuration changed')
    if not warm and config.get('require_prepared') and not manifest.get('prepared_id'):
        raise ValueError('live deployment requires an immutable prepared promotion')
    root = Path(config['state'])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = root / ('warming' if warm else 'runs') / manifest['release_id']
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_json(directory / 'manifest.json', manifest)
    deadline = Deadline(manifest['pushed_at'], limit=3600 if warm else LIMIT_SECONDS)
    receipt = {'release_id': manifest['release_id'], 'pushed_at': manifest['pushed_at'],
               'deadline_at': deadline.ends,
               'state': 'queued', 'stages': {}, 'artifacts': {}}
    marker = directory / 'receipt.json'
    if marker.exists():
        previous = json.loads(marker.read_text())
        if previous['state'] in ('live', 'failed', 'warmed'):
            return previous  # Original completed observation; never re-time it.
        receipt = previous
    write_json(marker, receipt)
    def stage(name):
        deadline.cap = deadline.ends if warm else manifest['pushed_at'] + STAGE_SECONDS[name]
        deadline.remaining(activation=True)
        receipt['state'] = name
        receipt['stages'].setdefault(name, {'started_at': time.time()})
        write_json(marker, receipt)
    def done(name):
        receipt['stages'][name]['finished_at'] = time.time()
        write_json(marker, receipt)
    with (root / 'release.lock').open('a') as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                try:
                    time.sleep(min(.25, deadline.remaining(activation=True)))
                except TimeoutError:
                    receipt.update(state='failed', failure_type='QueueDeadlineExceeded',
                                   failure_stage='queued',
                                   elapsed_seconds=time.time() - manifest['pushed_at'])
                    write_json(marker, receipt)
                    return receipt
        mutated = receipt.get('activation_started', False)
        request = directory / 'request.json'
        def save_request():
            write_json(request, {'manifest': manifest, 'config': config,
                                 'directory': str(directory), 'artifacts': receipt['artifacts'], 'warm': warm})
        try:
            if mutated:
                raise RuntimeError('interrupted activation requires restoration')
            stage('preflight')
            save_request()
            adapter(config, 'preflight', request, deadline, directory)
            done('preflight')
            stage('building')
            if not warm and manifest.get('prepared_id'):
                prepared_release(config, manifest['prepared_id'])
                receipt['artifacts'] = {c: dict(cached_artifact(config, c, manifest['inputs'][c]), cache_hit=True)
                                        for c in COMPONENTS}
                write_json(marker, receipt)
            else:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    pending = {pool.submit(build, config, manifest, c, deadline, directory): c
                               for c in COMPONENTS if not DEPENDENCIES[c]}
                    apk_started = False
                    while pending:
                        task = next(as_completed(pending))
                        component = pending.pop(task)
                        receipt['artifacts'][component] = task.result()
                        write_json(marker, receipt)
                        if not apk_started and all(c in receipt['artifacts'] for c in DEPENDENCIES['apk']):
                            pending[pool.submit(build, config, manifest, 'apk', deadline, directory)] = 'apk'
                            apk_started = True
            done('building')
            stage('verifying')
            save_request()
            adapter(config, 'verify', request, deadline, directory)
            done('verifying')
            if warm:
                receipt.update(state='warmed', finished_at=time.time())
                write_json(marker, receipt)
                return receipt
            stage('activation')
            # Journal before any mutation, so interruption enters restoration.
            receipt['activation_started'] = mutated = True
            write_json(marker, receipt)
            adapter(config, 'activate', request, deadline, directory)
            done('activation')
            stage('readiness')
            adapter(config, 'readiness', request, deadline, directory)
            proof = json.loads((directory / 'live.json').read_text())
            checked_targets(manifest, proof)
            done('readiness')
            deadline.remaining(activation=True)
            receipt.update(state='live', finished_at=time.time())
            receipt['elapsed_seconds'] = receipt['finished_at'] - manifest['pushed_at']
            write_json(marker, receipt)
            write_json(root / 'live.json', receipt)
        except Exception as error:
            receipt.update(state='failed', failure_type=type(error).__name__,
                           failure_stage=receipt['state'], finished_at=time.time())
            blocked = directory / 'preflight-block.json'
            if receipt['failure_stage'] == 'preflight' and blocked.exists():
                receipt['blocker'] = json.loads(blocked.read_text())['reason']
            if mutated:
                try:
                    deadline.cap = deadline.ends
                    save_request()
                    adapter(config, 'rollback', request, deadline, directory, activation=False)
                    proof = json.loads((directory / 'rollback.json').read_text())
                    if proof.get('previous_artifacts_verified') is not True:
                        raise ValueError('previous artifact restoration was not verified')
                    receipt['rollback'] = ('ready' if proof.get('functional_readiness_verified') is True
                                           else 'previous_artifacts_verified')
                    if config.get('require_functional_rollback') and receipt['rollback'] != 'ready':
                        raise ValueError('previous Android functional readiness missing')
                except Exception as rollback_error:
                    receipt['rollback'] = 'failed'
                    receipt['rollback_failure_type'] = type(rollback_error).__name__
            receipt['elapsed_seconds'] = time.time() - manifest['pushed_at']
            write_json(marker, receipt)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation in ('plan', 'warm', 'deploy'):
        child = sub.add_parser(operation)
        child.add_argument('--pushed-at', type=float, required=operation != 'warm')
        child.add_argument('--manifest', type=Path)
    sub.add_parser('status')
    child = sub.add_parser('enroll-hub')
    child.add_argument('--prepared-id', required=True)
    child = sub.add_parser('prepare')
    child.add_argument('--manifest', type=Path)
    child = sub.add_parser('promote')
    child.add_argument('--prepared-id', required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.operation == 'enroll-hub':
        from android_release_hub import enroll, enroll_controller
        prepared = prepared_release(config, args.prepared_id)
        enroll(config, Path(config['state']) / 'artifacts/hub' / prepared['inputs']['hub'] / 'gchat')
        enroll_controller(config, Path(config['state']) / 'artifacts/controller' / prepared['inputs']['controller'] / 'gdrone-fleet')
        print(json.dumps({'state': 'headless_hub_enrolled', 'prepared_id': args.prepared_id}))
        return
    if args.operation == 'status':
        root = Path(config['state'])
        print(json.dumps({name: json.loads((root / (name + '.json')).read_text())
                          if (root / (name + '.json')).exists() else None
                          for name in ('latest', 'live', 'prepared-latest')}, indent=2))
        return
    if args.operation == 'promote':
        print(json.dumps(promote(config, args.prepared_id), indent=2))
        return
    if args.operation == 'prepare':
        print(json.dumps(prepare_release(config, json.loads(args.manifest.read_text()) if args.manifest else None), indent=2))
        return
    manifest = (json.loads(args.manifest.read_text()) if args.manifest
                else freeze(config, args.pushed_at if args.pushed_at is not None else time.time()))
    if args.operation == 'plan':
        print(json.dumps({'manifest': manifest, 'build': [c for c in COMPONENTS
                         if not cached_artifact(config, c, manifest['inputs'][c])]}, indent=2))
        return
    receipt = deploy(config, manifest, warm=args.operation == 'warm')
    print(json.dumps(receipt, indent=2))
    if receipt['state'] not in ('live', 'warmed'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
