#!/usr/bin/env python3
"""Cluster Android lane, supervised by the existing release coordinator.

The supervisor only freezes requests and reconciles Kubernetes Jobs. Build,
qualification and deployment processes survive loss of the workstation client.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from android_release import (canonical, command, digest, freeze, git, prepare_release,
                             promotion_manifest, deploy, write_json)
from android_release_catalogue import Catalogue
from android_release_kubernetes import (Kubernetes, Lease, MissingSubmittedJob, OWNER,
                                        ensure_job, job_name, job_state, name)
from android_release_source import Forgejo, PROMOTION, ingest, repository_name

MAX_CHECKPOINT = 1024 * 1024


def source_sync(config):
    """Fetch HTTPS mirrors using the restricted token, never embedded in a URL."""
    origin = Forgejo(config['forgejo']).origin
    source_root = (Path(config['state']) / 'sources').resolve()
    environment = dict(os.environ, GIT_TERMINAL_PROMPT='0',
        GIT_ASKPASS=str(Path(__file__).with_name('android_release_git_askpass.py')),
        ANDROID_FORGEJO_TOKEN_FILE=config['forgejo']['token_file'],
        GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='credential.helper', GIT_CONFIG_VALUE_0='',
        GIT_CONFIG_KEY_1='http.followRedirects', GIT_CONFIG_VALUE_1='false')
    seen = {}
    for row in config['sources'].values():
        repository = repository_name(row['cluster_repository'])
        destination = Path(row['repository']).resolve()
        if destination != source_root / (repository.split('/')[1] + '.git'):
            raise ValueError('cluster source mirrors must stay in their owned source directory')
        if destination in seen:
            if seen[destination] != repository:
                raise ValueError('two repositories share a source mirror')
            continue
        seen[destination] = repository
        url = origin + '/' + repository + '.git'
        log = Path(config['state']) / 'source-logs' / (repository.split('/')[1] + '.log')
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            command(['git', '--shallow-file', '/dev/null', 'init', '--bare', destination], env=environment, log=log)
            command(['git', '--shallow-file', '/dev/null', '-C', destination,
                     'remote', 'add', 'origin', url], env=environment, log=log)
        if git(destination, 'remote', 'get-url', 'origin').decode().strip() != url:
            raise ValueError('existing cluster source mirror changed origin')
        # Branches may advance/rebase. Promotion tags may never be rewritten.
        command(['git', '--shallow-file', '/dev/null', '-C', destination, 'fetch', '--no-write-fetch-head',
                 'origin', '+refs/heads/*:refs/heads/*', 'refs/tags/*:refs/tags/*'],
                env=environment, timeout=120, log=log)


def initialize(config, client=None):
    """Explicit migration boundary: imported history is not a new deployment."""
    client = client or Forgejo(config['forgejo'])
    root = Path(config['state'])
    if (root / 'source-cursors.json').exists():
        raise ValueError('preserve the existing cluster intake boundary')
    cursors = {}
    for row in config['sources'].values():
        repository = repository_name(row['cluster_repository'])
        if repository in cursors:
            continue
        rows = client.read('repos/' + repository + '/activities/feeds?limit=1&page=1')
        if not isinstance(rows, list) or len(rows) != 1 or rows[0].get('repo', {}).get('full_name') != repository:
            raise ValueError('source migration requires an imported repository with server history')
        identity = rows[0]['id']
        if type(identity) is not int or identity <= 0:
            raise ValueError('invalid source migration activity boundary')
        cursors[repository] = identity
    write_json(root / 'source-migration.json', {'schema': 1, 'recorded_at': time.time(),
        'reason': 'all imported branches/tags verified before cluster intake', 'cursors': cursors})
    write_json(root / 'source-cursors.json', cursors)


def checkpoint(config, catalogue):
    root = Path(config['state'])
    paths = [root / 'source-cursors.json', root / 'source-migration.json',
             *sorted((root / 'cluster-effects').glob('*.json')),
             *sorted(Path(config['event_directory']).glob('*.json'))]
    files = {}
    for path in paths:
        if not path.exists():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('unsafe cluster coordinator checkpoint path')
        files[str(path.relative_to(root))] = json.loads(path.read_text())
    value = {'schema': 1, 'configuration_sha256': hashlib.sha256(canonical(config)).hexdigest(), 'files': files}
    if len(canonical(value)) > MAX_CHECKPOINT:
        raise ValueError('coordinator checkpoint is full; archive old indexed events explicitly')
    return catalogue.bind('checkpoints', 'coordinator', catalogue.archive.publish_record(value), replace=True)


def recover(config, catalogue):
    root = Path(config['state'])
    if (root / 'source-cursors.json').exists():
        return
    descriptor = catalogue.lookup('checkpoints', 'coordinator')
    if descriptor is None:
        raise ValueError('cluster source intake needs its audited initialization or recovery checkpoint')
    value = catalogue.archive.read_record(descriptor)
    if value.get('schema') != 1 or value.get('configuration_sha256') != hashlib.sha256(canonical(config)).hexdigest():
        raise ValueError('coordinator recovery configuration changed')
    files = value['files']
    if 'source-cursors.json' not in files or 'source-migration.json' not in files:
        raise ValueError('coordinator checkpoint omits its original intake boundary')
    for relative, contents in files.items():
        valid = relative in ('source-cursors.json', 'source-migration.json') or re.fullmatch(
            r'(cluster-effects/[0-9a-f]{64}|events/[A-Za-z0-9_-]+)\.json', relative)
        if not valid:
            raise ValueError('unsafe coordinator recovery path')
        path = root / relative
        if path.exists() and json.loads(path.read_text()) != contents:
            raise ValueError('preserve differing local coordinator state during recovery')
    # Cursors come last; partial recovery always reconciles the original jobs.
    for relative, contents in files.items():
        if relative != 'source-cursors.json':
            write_json(root / relative, contents)
    write_json(root / 'source-cursors.json', files['source-cursors.json'])


def job(config, request, request_path):
    cluster = config['cluster']
    image = cluster['runner_image']
    if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', image):
        raise ValueError('cluster release runner image must be digest-pinned')
    if request['operation'] not in ('prepare', 'promote', 'qualify'):
        raise ValueError('unsupported cluster release operation')
    deadline = 3600 if request['operation'] == 'prepare' else (420 if request['operation'] == 'qualify' else 600)
    labels = {'app.kubernetes.io/part-of': OWNER, 'ghost.io/android-operation': request['operation']}
    mounts = [{'name': 'state', 'mountPath': config['state']},
              {'name': 'config', 'mountPath': '/config', 'readOnly': True},
              {'name': 'archive', 'mountPath': '/credentials/archive', 'readOnly': True}]
    volumes = [{'name': 'state', 'persistentVolumeClaim': {'claimName': name(cluster['state_claim'])}},
               {'name': 'config', 'configMap': {'name': name(cluster['config_map'])}},
               {'name': 'archive', 'secret': {'secretName': name(cluster['archive_secret']), 'defaultMode': 0o440}}]
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
        'metadata': {'name': job_name(request['request_id'], request['operation']),
                     'namespace': config['kubernetes']['namespace'], 'labels': labels},
        'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': deadline,
            # Keep terminal Jobs until their evidence has been archived and an
            # explicit retention action is safe; disappearance is never retry.
            'template': {'metadata': {'labels': labels}, 'spec': {
                'restartPolicy': 'Never', 'serviceAccountName': name(cluster['service_account']),
                'nodeSelector': {'topology.kubernetes.io/zone': 'fsn1'},
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001},
                'containers': [{'name': 'runner', 'image': image,
                    'command': ['python3', '/opt/gcoms/scripts/android_release_cluster.py',
                                '--config', '/config/android-agent.json', 'execute', '--request', str(request_path),
                                '--sha256', hashlib.sha256(canonical(request)).hexdigest()],
                    'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'},
                            {'name': 'TMPDIR', 'value': config['state'] + '/tmp'}],
                    'resources': {'requests': {'cpu': '100m', 'memory': '256Mi', 'ephemeral-storage': '64Mi'},
                                  'limits': {'cpu': '1', 'memory': '1Gi', 'ephemeral-storage': '256Mi'}},
                    'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                    'volumeMounts': mounts}], 'volumes': volumes}}}}


def submit(config, kube, lease, request, marker, catalogue):
    root = Path(config['state'])
    request_path = root / 'cluster-requests' / (request['request_id'] + '.json')
    if request_path.exists() and json.loads(request_path.read_text()) != request:
        raise ValueError('original cluster request changed')
    lease.fence()
    write_json(request_path, request)
    previous = json.loads(marker.read_text()) if marker.exists() else None
    if previous and previous['request'] != request:
        raise ValueError('original cluster effect changed')
    if previous and previous['state'] in ('complete', 'failed', 'submission_unknown'):
        return previous
    value = previous or {'schema': 1, 'request': request, 'state': 'submitting'}
    already_submitted = bool(value.get('submission_started'))
    value['submission_started'] = True
    write_json(marker, value)  # Journal before the external effect.
    if not already_submitted:
        # The recovery checkpoint precedes submission too: loss of the working
        # PVC cannot generate a new request ID or clock for an accepted Job.
        checkpoint(config, catalogue)
    try:
        resource = ensure_job(kube, lease, job(config, request, request_path),
                              expected_uid=value.get('job_uid'), previously_submitted=already_submitted)
    except MissingSubmittedJob:
        value.update(state='submission_unknown', reason='original Job absent after journaled submission')
        write_json(marker, value)
        return value
    value.update(job_name=resource['metadata']['name'], job_uid=resource['metadata']['uid'], state=job_state(resource))
    if value['state'] == 'complete':
        result_path = root / 'cluster-results' / (request['request_id'] + '.json')
        if not result_path.exists():
            descriptor = catalogue.lookup('checkpoints', 'result/' + request['request_id'])
            if descriptor is None:
                raise ValueError('completed cluster Job has no archived result')
            write_json(result_path, catalogue.archive.read_record(descriptor))
        result = json.loads(result_path.read_text())
        if result.get('request_id') != request['request_id'] or result.get('request_sha256') != hashlib.sha256(canonical(request)).hexdigest():
            raise ValueError('completed cluster Job lacks its exact result')
        value['result'] = result
        if result['state'] not in ('prepared', 'live', 'qualified'):
            value['state'] = 'failed'
    write_json(marker, value)
    return value


def tick(config, kube=None, catalogue=None):
    kube = kube or Kubernetes(config['kubernetes'])
    catalogue = catalogue or Catalogue(config, kube)
    root = Path(config['state'])
    with Lease(kube, 'android-release-coordinator') as lease:
        recover(config, catalogue)
        ingest(config)
        effects = root / 'cluster-effects'
        effects.mkdir(parents=True, exist_ok=True)
        active = []
        handled = set()
        for marker in sorted(effects.glob('*.json')):
            before = json.loads(marker.read_text())
            value = submit(config, kube, lease, before['request'], marker, catalogue)
            handled.update(value['request']['events'])
            if value['state'] in ('submitting', 'running', 'submission_unknown'):
                active.append(value)
        if not active:
            events = []
            selected = {(r['project'], r['ref']) for r in config['sources'].values()}
            for path in sorted(Path(config['event_directory']).glob('*.json')):
                if path.name in handled:
                    continue
                value = json.loads(path.read_text())
                if (value['project'], value['ref']) in selected or value['ref'].startswith(PROMOTION):
                    events.append((path.name, value))
            events.sort(key=lambda row: (row[1]['pushed_at'], row[1]['forgejo_activity_id']))
            promotions = [r for r in events if r[1]['ref'].startswith(PROMOTION)]
            chosen = promotions[:1] or events
            if chosen:
                source_sync(config)
                event = chosen[-1][1]
                if promotions:
                    manifest = promotion_manifest(config, event['ref'][len(PROMOTION):], event['pushed_at'])
                    if manifest['sources']['gcoms'] != event['commit']:
                        raise ValueError('promotion tag differs from its immutable prepared source')
                    operation = 'promote'
                else:
                    # Cold preparation has its own start time; source push
                    # timestamps remain in the request and never become a live pass.
                    manifest = freeze(config, time.time())
                    operation = 'prepare'
                request = {'schema': 1, 'operation': operation, 'manifest': manifest,
                           'events': [row[0] for row in chosen], 'source_push': event}
                request['request_id'] = hashlib.sha256(canonical(request)).hexdigest()
                marker = effects / (request['request_id'] + '.json')
                active.append(submit(config, kube, lease, request, marker, catalogue))
        lease.fence()
        checkpoint(config, catalogue)
        status = {'schema': 1, 'observed_at': time.time(), 'execution': 'kubernetes',
                  'state': 'active' if active else 'idle',
                  'active': [{'request_id': v['request']['request_id'], 'operation': v['request']['operation'],
                              'state': v['state'], 'job_uid': v.get('job_uid')} for v in active]}
        write_json(root / 'cluster-status.json', status)
        return status


def execute(config, request_path, checksum):
    request_path = Path(request_path)
    request = json.loads(request_path.read_text())
    if hashlib.sha256(canonical(request)).hexdigest() != checksum:
        raise ValueError('cluster execution request bytes changed')
    unsigned = {k: v for k, v in request.items() if k != 'request_id'}
    if request['request_id'] != hashlib.sha256(canonical(unsigned)).hexdigest():
        raise ValueError('cluster execution request identity changed')
    destination = Path(config['state']) / 'cluster-results' / (request['request_id'] + '.json')
    if destination.exists():
        result = json.loads(destination.read_text())
        if result.get('request_id') != request['request_id'] or result.get('request_sha256') != checksum:
            raise ValueError('original cluster result binding changed')
        return result
    Path(config['state'], 'tmp').mkdir(exist_ok=True)
    if request['operation'] == 'prepare':
        value = prepare_release(config, request['manifest'])
        state = 'prepared'
    elif request['operation'] == 'promote':
        value = deploy(config, request['manifest'])
        state = value['state']
    else:
        raise ValueError('cluster execution operation is not installed')
    result = {'schema': 1, 'request_id': request['request_id'], 'request_sha256': checksum,
              'state': state, 'result': value}
    catalogue = Catalogue(config)
    catalogue.bind('checkpoints', 'result/' + request['request_id'], catalogue.archive.publish_record(result))
    write_json(destination, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('tick')
    sub.add_parser('initialize')
    child = sub.add_parser('execute')
    child.add_argument('--request', type=Path, required=True)
    child.add_argument('--sha256', required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.operation == 'initialize':
        source_sync(config)
        initialize(config)
        checkpoint(config, Catalogue(config))
        result = {'state': 'initialized'}
    elif args.operation == 'execute':
        result = execute(config, args.request, args.sha256)
    else:
        result = tick(config)
    print(json.dumps(result))
    return 0 if result.get('state') != 'failed' else 1


if __name__ == '__main__':
    sys.exit(main())
