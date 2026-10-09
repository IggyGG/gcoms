#!/usr/bin/env python3
"""Bounded Android-agent releases; artifacts and live readiness are separate."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

LIMIT_SECONDS = 600
ACTIVATION_SECONDS = 540  # Reserve the last minute for restoration.
COMPONENTS = ('sdk', 'installer', 'apk', 'hub', 'worker')
STAGE_SECONDS = {'preflight': 60, 'building': 300, 'verifying': 360,
                 'activation': 420, 'readiness': ACTIVATION_SECONDS}
DEPENDENCIES = {'sdk': (), 'installer': (), 'hub': (), 'worker': (),
                'apk': ('sdk', 'installer')}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.new')
    with temporary.open('w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


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
    if project == 'gcoms':
        if name.startswith(('mobile/apple/', 'mobile/push/', 'packages/', 'examples/', 'fuzz/')):
            return False
        if name.startswith('mobile/android/'):
            return component == 'apk' and not name.startswith(('mobile/android/sample/', 'mobile/android/probe/'))
        if name.startswith('mobile/native/'):
            return component == 'sdk'
        if name.startswith(('scripts/android_release', 'scripts/tests/android_release')):
            return False  # Release operations have their own focused gate.
        if name.startswith(('scripts/', '.github/', '.forgejo/')):
            return component in ('sdk', 'installer', 'hub', 'worker')
        return component in ('sdk', 'installer', 'hub', 'worker')
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
            'dependencies': {name: keys[name] for name in DEPENDENCIES[component]}
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
    unsigned = {k: v for k, v in manifest.items() if k != 'release_id'}
    if (manifest.get('release_id') != hashlib.sha256(canonical(unsigned)).hexdigest()
            or manifest.get('configuration_sha256') != hashlib.sha256(canonical(config)).hexdigest()
            or manifest['inputs'] != inputs(config, manifest['sources'])):
        raise ValueError('immutable release inputs/configuration changed')
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
            with ThreadPoolExecutor(max_workers=4) as pool:
                pending = {c: pool.submit(build, config, manifest, c, deadline, directory)
                           for c in COMPONENTS if not DEPENDENCIES[c]}
                for c, task in pending.items():
                    receipt['artifacts'][c] = task.result()
                receipt['artifacts']['apk'] = build(config, manifest, 'apk', deadline, directory)
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
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.operation == 'status':
        root = Path(config['state'])
        print(json.dumps({name: json.loads((root / (name + '.json')).read_text())
                          if (root / (name + '.json')).exists() else None
                          for name in ('latest', 'live')}, indent=2))
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
