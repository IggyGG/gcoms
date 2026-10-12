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
import subprocess
import sys
import tempfile
import time

from android_release import (canonical, command, digest, freeze, git, prepare_release,
                             promotion_manifest, deploy, write_json)
from android_release_catalogue import Catalogue
from android_release_kubernetes import (Kubernetes, Lease, MissingSubmittedJob, OWNER,
                                        ensure_job, job_name, job_state, name)
from android_release_source import Forgejo, PROMOTION, ingest, repository_name

MAX_CHECKPOINT = 1024 * 1024


def advertised_refs(destination, references, environment, log):
    # Avoid traversing every object on the shared source volume when a remote
    # branch has not moved. Authentication and redirect policy match fetch.
    with tempfile.NamedTemporaryFile(dir=log.parent, prefix='advertised-') as stream:
        command(['git', '--shallow-file', '/dev/null', '-C', destination,
                 'ls-remote', '--refs', 'origin', *references], env=environment,
                timeout=30, log=stream.name)
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError('advertised Android source references exceed their bound')
    result = {}
    for line in raw.decode('ascii').splitlines():
        sha, separator, ref = line.partition('\t')
        if not separator or not re.fullmatch('[0-9a-f]{40}', sha) or ref not in references or ref in result:
            raise ValueError('unexpected advertised Android source reference')
        result[ref] = sha
    if set(result) != set(references):
        raise ValueError('selected Android source reference is absent')
    return result


def source_sync(config, promotion=None):
    """Fetch HTTPS mirrors using the restricted token, never embedded in a URL."""
    origin = Forgejo(config['forgejo']).origin
    source_root = (Path(config['state']) / 'sources').resolve()
    environment = dict(os.environ, GIT_TERMINAL_PROMPT='0',
        GIT_ASKPASS=str(Path(__file__).with_name('android_release_git_askpass.py')),
        ANDROID_FORGEJO_TOKEN_FILE=config['forgejo']['token_file'],
        GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='credential.helper', GIT_CONFIG_VALUE_0='',
        GIT_CONFIG_KEY_1='http.followRedirects', GIT_CONFIG_VALUE_1='false')
    selected = {}
    if promotion is not None and not re.fullmatch(re.escape(PROMOTION) + '[0-9a-f]{64}', promotion):
        raise ValueError('promotion synchronization requires one exact immutable tag')
    for row in config['sources'].values():
        repository = repository_name(row['cluster_repository'])
        if promotion is not None and row['project'] != 'gcoms':
            continue
        destination = Path(row['repository']).resolve()
        if destination != source_root / (repository.split('/')[1] + '.git'):
            raise ValueError('cluster source mirrors must stay in their owned source directory')
        if not re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]+', row['ref']) or '..' in row['ref']:
            raise ValueError('source synchronization requires an exact branch reference')
        entry = selected.setdefault(destination, {'repository': repository, 'refs': set()})
        if entry['repository'] != repository:
            raise ValueError('two repositories share a source mirror')
        entry['refs'].add(row['ref'])
    for destination, entry in selected.items():
        repository = entry['repository']
        url = origin + '/' + repository + '.git'
        log = Path(config['state']) / 'source-logs' / (repository.split('/')[1] + '.log')
        log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            command(['git', '--shallow-file', '/dev/null', 'init', '--bare', destination], env=environment, log=log)
            command(['git', '--shallow-file', '/dev/null', '-C', destination,
                     'remote', 'add', 'origin', url], env=environment, log=log)
        if git(destination, 'remote', 'get-url', 'origin').decode().strip() != url:
            raise ValueError('existing cluster source mirror changed origin')
        references = [promotion] if promotion is not None else sorted(entry['refs'])
        advertised = advertised_refs(destination, references, environment, log)
        changed = []
        for ref, sha in advertised.items():
            try:
                current = git(destination, 'rev-parse', '--verify', ref).decode().strip()
            except subprocess.CalledProcessError:
                current = None
            if current == sha:
                continue
            if promotion is not None:
                if current is not None:
                    raise ValueError('preserve the original immutable Android promotion tag')
                # Prepared source objects are already present. Authenticate the
                # exact server tag and create it with compare-and-swap, without
                # an expensive all-history fetch during the promotion clock.
                if git(destination, 'cat-file', '-t', sha).strip() != b'commit':
                    raise ValueError('promotion must name an existing prepared commit')
                git(destination, 'update-ref', ref, sha, '0' * 40)
            else:
                changed.append('+' + ref + ':' + ref)
        if not changed:
            continue
        command(['git', '--shallow-file', '/dev/null', '-C', destination, 'fetch', '--no-write-fetch-head',
                 '--no-tags', 'origin', *changed],
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
    existing = catalogue.lookup('checkpoints', 'coordinator')
    if existing and existing['sha256'] == hashlib.sha256(canonical(value)).hexdigest():
        return existing
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
                'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {
                    'nodeSelectorTerms': [{'matchExpressions': [{'key': 'kubernetes.io/hostname',
                        'operator': 'NotIn', 'values': ['triform-1']}]}]}}},
                'imagePullSecrets': ([{'name': name(cluster['image_pull_secret'])}]
                                     if cluster.get('image_pull_secret') else []),
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
                                    'fsGroup': 10001, 'fsGroupChangePolicy': 'OnRootMismatch'},
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


def original_job(config, kube, lease, request, request_path, value, already_submitted):
    """Observe the original execution across coordinator/configuration upgrades."""
    definition = value.get('job_definition')
    if definition is not None:
        return ensure_job(kube, lease, definition, expected_uid=value.get('job_uid'),
                          previously_submitted=already_submitted)
    # Legacy effects did not journal the rendered Job. Their recorded UID and
    # immutable original configuration still identify the admitted execution;
    # observing it must not render a replacement with today's configuration.
    resource = kube.get('job', job_name(request['request_id'], request['operation']))
    if resource is None:
        raise MissingSubmittedJob('original Android Job is absent')
    metadata = resource['metadata']
    pod = resource['spec']['template']['spec']
    if (metadata.get('uid') != value.get('job_uid')
            or metadata.get('namespace') != kube.namespace
            or metadata.get('labels', {}).get('app.kubernetes.io/part-of') != OWNER):
        raise ValueError('legacy Android Job identity changed')
    volumes = [v for v in pod['volumes'] if v.get('name') == 'config']
    if len(volumes) != 1 or set(volumes[0]) != {'name', 'configMap'}:
        raise ValueError('legacy Android Job configuration volume changed')
    original = kube.get('configmap', name(volumes[0]['configMap']['name']))
    if original is None or original.get('immutable') is not True:
        raise ValueError('original immutable Android configuration is absent')
    selected = json.loads(original['data']['android-agent.json'])
    if hashlib.sha256(canonical(selected)).hexdigest() != request['manifest']['configuration_sha256']:
        raise ValueError('original Android configuration binding changed')
    containers = pod['containers']
    expected = job(selected, request, request_path)['spec']['template']['spec']['containers'][0]
    if (len(containers) != 1 or any(containers[0].get(k) != expected[k] for k in ('name', 'image', 'command'))
            or pod.get('serviceAccountName') != selected['cluster']['service_account']):
        raise ValueError('original Android execution binding changed')
    lease.fence()
    return resource


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
    if not already_submitted:
        if request['manifest'].get('configuration_sha256') != hashlib.sha256(canonical(config)).hexdigest():
            raise ValueError('new Android request configuration changed')
        value['job_definition'] = job(config, request, request_path)
    value['submission_started'] = True
    write_json(marker, value)  # Journal before the external effect.
    if not already_submitted:
        # The recovery checkpoint precedes submission too: loss of the working
        # PVC cannot generate a new request ID or clock for an accepted Job.
        checkpoint(config, catalogue)
    try:
        resource = original_job(config, kube, lease, request, request_path, value, already_submitted)
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
        # A cold compiler Job cannot delay promotion of already verified
        # artifacts. Preserve one live operation and one preparation at a time.
        live_active = any(v['request']['operation'] != 'prepare' for v in active)
        prepare_active = any(v['request']['operation'] == 'prepare' for v in active)
        if not live_active:
            events = []
            selected = {(r['project'], r['ref']) for r in config['sources'].values()}
            for path in sorted(Path(config['event_directory']).glob('*.json')):
                if path.name in handled:
                    continue
                value = json.loads(path.read_text())
                if (value['project'], value['ref']) in selected or value['ref'].startswith(PROMOTION):
                    events.append((path.name, value))
            events.sort(key=lambda row: (row[1]['pushed_at'],
                str(row[1].get('server_event_id', row[1].get('forgejo_activity_id', '')))))
            promotions = [r for r in events if r[1]['ref'].startswith(PROMOTION)]
            chosen = promotions[:1] or ([] if prepare_active else events)
            if chosen:
                event = chosen[-1][1]
                if promotions:
                    try:
                        source_sync(config, promotion=event['ref'])
                        manifest = promotion_manifest(config, event['ref'][len(PROMOTION):], event['pushed_at'])
                        if manifest['sources']['gcoms'] != event['commit']:
                            raise ValueError('promotion tag differs from its immutable prepared source')
                    except (ValueError, FileNotFoundError) as error:
                        # A malformed/missing prepared release is terminal for
                        # this immutable push. Network/API errors still retry
                        # observation; they never become a fresh push clock.
                        request = {'schema': 1, 'operation': 'promote',
                            'manifest': {'pushed_at': event['pushed_at']},
                            'events': [row[0] for row in chosen], 'source_push': event}
                        request['request_id'] = hashlib.sha256(canonical(request)).hexdigest()
                        rejected = {'schema': 1, 'request': request, 'state': 'failed',
                            'reason': 'invalid immutable prepared promotion', 'failure_type': type(error).__name__}
                        catalogue.bind('checkpoints', 'rejection/' + request['request_id'],
                                       catalogue.archive.publish_record(rejected))
                        lease.fence()
                        write_json(effects / (request['request_id'] + '.json'), rejected)
                        chosen = []
                    operation = 'promote'
                else:
                    source_sync(config)
                    # Cold preparation has its own start time; source push
                    # timestamps remain in the request and never become a live pass.
                    manifest = freeze(config, time.time())
                    operation = 'prepare'
                if chosen:
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
    if request['manifest'].get('configuration_sha256') != hashlib.sha256(canonical(config)).hexdigest():
        raise ValueError('cluster execution configuration changed')
    destination = Path(config['state']) / 'cluster-results' / (request['request_id'] + '.json')
    catalogue = Catalogue(config)
    if not destination.exists():
        archived = catalogue.lookup('checkpoints', 'result/' + request['request_id'])
        if archived is not None:
            restored = catalogue.archive.read_record(archived)
            if restored.get('request_id') != request['request_id'] or restored.get('request_sha256') != checksum:
                raise ValueError('archived cluster result binding changed')
            write_json(destination, restored)
    if destination.exists():
        result = json.loads(destination.read_text())
        if result.get('request_id') != request['request_id'] or result.get('request_sha256') != checksum:
            raise ValueError('original cluster result binding changed')
        return result
    Path(config['state'], 'tmp').mkdir(exist_ok=True)
    try:
        if request['operation'] == 'prepare':
            value = prepare_release(config, request['manifest'])
            state = 'prepared'
        elif request['operation'] == 'promote':
            value = deploy(config, request['manifest'])
            state = value['state']
        elif request['operation'] == 'qualify':
            from android_release_lab import qualify
            value = qualify(config, request['manifest'])
            state = value['state']
        else:
            raise ValueError('cluster execution operation is not installed')
    except Exception as error:
        # Preserve an execution failure remotely as well as in the original
        # Job logs. Restoring an empty cache must never rerun a failed action.
        value = {'state': 'failed', 'failure_type': type(error).__name__}
        state = 'failed'
    result = {'schema': 1, 'request_id': request['request_id'], 'request_sha256': checksum,
              'state': state, 'result': value}
    catalogue.bind('checkpoints', 'result/' + request['request_id'], catalogue.archive.publish_record(result))
    write_json(destination, result)
    return result


def workloads(config, coordinator_image, source_secret):
    """Render the persistent supervisor and image warming with the same placement."""
    if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', coordinator_image):
        raise ValueError('cluster coordinator image must be digest-pinned')
    if config['forgejo']['token_file'] != '/credentials/source/token':
        raise ValueError('cluster source credentials require their private fixed mount')
    namespace = config['kubernetes']['namespace']
    labels = {'app.kubernetes.io/part-of': OWNER, 'app.kubernetes.io/name': 'android-release-coordinator'}
    pod = job(config, {'operation': 'prepare', 'request_id': '0' * 64}, Path('/unused'))['spec']['template']['spec']
    pod['restartPolicy'] = 'Always'
    container = pod['containers'][0]
    container.update(name='coordinator', image=coordinator_image,
        command=['python3', '/opt/gcoms/scripts/android_release_cluster.py',
                 '--config', '/config/android-agent.json', 'serve'])
    container['volumeMounts'].append({'name': 'source', 'mountPath': '/credentials/source', 'readOnly': True})
    pod['volumes'].append({'name': 'source', 'secret': {'secretName': name(source_secret), 'defaultMode': 0o440}})
    deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
        'metadata': {'name': 'android-release-coordinator', 'namespace': namespace, 'labels': labels},
        'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': labels},
                 'template': {'metadata': {'labels': labels}, 'spec': pod}}}
    warm_labels = {'app.kubernetes.io/part-of': OWNER, 'app.kubernetes.io/name': 'android-release-images'}
    warm_pod = {k: pod[k] for k in ('nodeSelector', 'affinity', 'imagePullSecrets', 'securityContext')}
    warm_pod.update(automountServiceAccountToken=False, terminationGracePeriodSeconds=1,
        containers=[{'name': component, 'image': image,
            'command': ['python3', '-c', 'import signal; signal.pause()'],
            'resources': {'requests': {'cpu': '1m', 'memory': '16Mi'}, 'limits': {'cpu': '50m', 'memory': '64Mi'}},
            'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}
            for component, image in [('coordinator', coordinator_image), ('runner', config['cluster']['runner_image'])]])
    warmer = {'apiVersion': 'apps/v1', 'kind': 'DaemonSet',
        'metadata': {'name': 'android-release-images', 'namespace': namespace, 'labels': warm_labels},
        'spec': {'selector': {'matchLabels': warm_labels},
                 'template': {'metadata': {'labels': warm_labels}, 'spec': warm_pod}}}
    return {'apiVersion': 'v1', 'kind': 'List', 'items': [warmer, deployment]}


def serve(config):
    if config.get('qualification_scope') == 'cluster-isolated':
        from android_release_lab import reserved_lab
        # Keep the lab reserved during cold preparation, idle periods and
        # coordinator replacement. Active Jobs also renew this same owner.
        with reserved_lab(config) as (_, fence):
            supervise(config, fence)
    else:
        supervise(config, lambda: None)


def supervise(config, fence):
    while True:
        # A lost reservation terminates this supervisor; it must not continue
        # admitting work under a successor's lab lifecycle ownership.
        fence()
        started = time.monotonic()
        try:
            print(json.dumps(tick(config)), flush=True)
        except Exception as error:
            # Never print a command, token, private guest log or new push clock.
            print(json.dumps({'schema': 1, 'state': 'observation_failed',
                              'failure_type': type(error).__name__}), flush=True)
        time.sleep(max(1, 5 - (time.monotonic() - started)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('tick')
    sub.add_parser('initialize')
    sub.add_parser('serve')
    render = sub.add_parser('workloads')
    render.add_argument('--coordinator-image', required=True)
    render.add_argument('--source-secret', required=True)
    child = sub.add_parser('execute')
    child.add_argument('--request', type=Path, required=True)
    child.add_argument('--sha256', required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.operation == 'serve':
        serve(config)
        return 0
    if args.operation == 'workloads':
        print(json.dumps(workloads(config, args.coordinator_image, args.source_secret)))
        return 0
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
