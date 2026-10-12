#!/usr/bin/env python3
"""Run one frozen native component in a bounded, credential-scoped cluster Job."""
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from android_release import COMPONENTS, cached_artifact, canonical, inputs, write_json
from android_release_kubernetes import Kubernetes, Lease, OWNER, ensure_job, job_name, job_state, name


def native_job(request, path):
    config, manifest, component = request['config'], request['manifest'], request['component']
    if component not in COMPONENTS:
        raise ValueError('unknown native Android component')
    cluster = config['cluster']
    image = cluster['builder_image']
    if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', image):
        raise ValueError('native Android builder must be digest-pinned')
    labels = {'app.kubernetes.io/part-of': OWNER, 'ghost.io/android-operation': 'build',
              'ghost.io/android-component': component}
    mounts = [{'name': 'state', 'mountPath': config['state']}, {'name': 'cache', 'mountPath': '/build'}]
    volumes = [{'name': 'state', 'persistentVolumeClaim': {'claimName': name(cluster['state_claim'])}},
               {'name': 'cache', 'persistentVolumeClaim': {'claimName': name(cluster['cache_claims'][component])}}]
    if component == 'apk':
        mounts.append({'name': 'signing', 'mountPath': '/home/release/.android', 'readOnly': True})
        volumes.append({'name': 'signing', 'secret': {'secretName': name(cluster['signing_secret']), 'defaultMode': 0o440}})
    checksum = hashlib.sha256(canonical(request)).hexdigest()
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
        'metadata': {'name': job_name(manifest['release_id'], component),
                     'namespace': config['kubernetes']['namespace'], 'labels': labels},
        'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 3300,
            'template': {'metadata': {'labels': labels}, 'spec': {
                'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'nodeSelector': {'topology.kubernetes.io/zone': 'fsn1'},
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001},
                'containers': [{'name': 'build', 'image': image,
                    'command': ['python3', '/opt/gcoms/scripts/android_release_build_job.py', 'execute', str(path), checksum],
                    'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'},
                            {'name': 'TMPDIR', 'value': '/build/tmp'},
                            {'name': 'CARGO_HOME', 'value': '/build/cargo'},
                            {'name': 'GRADLE_USER_HOME', 'value': '/build/gradle'},
                            {'name': 'ANDROID_CLUSTER_BUILD', 'value': '1'}],
                    'resources': {'requests': {'cpu': '1', 'memory': '1Gi', 'ephemeral-storage': '128Mi'},
                                  'limits': {'cpu': '2', 'memory': '4Gi', 'ephemeral-storage': '1Gi'}},
                    'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                    'volumeMounts': mounts}], 'volumes': volumes}}}}


def remote(path, kube=None):
    path = Path(path)
    request = json.loads(path.read_text())
    config, manifest, component = request['config'], request['manifest'], request['component']
    kube = kube or Kubernetes(config['kubernetes'])
    desired = native_job(request, path)
    until = time.monotonic() + 3350
    # The cache claim is component-specific. The durable active-Job pointer
    # also prevents an expired observer lease from allowing two source writers.
    pointer_name = 'android-build-' + component
    with Lease(kube, pointer_name) as lease:
        pointer = kube.get('configmap', pointer_name)
        previous = None
        if pointer:
            if pointer['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') != OWNER:
                raise ValueError('preserve another application build-cache owner')
            previous = json.loads(pointer['data']['owner.json'])
            old = kube.get('job', previous['name'])
            if (not old or (previous.get('uid') and old['metadata']['uid'] != previous['uid'])
                    or old['metadata'].get('annotations', {}).get('ghost.io/request-sha256') != previous['request_sha256']):
                raise ValueError('original cache writer is missing or changed; reconcile before reuse')
            previous['uid'] = old['metadata']['uid']
            while job_state(old) == 'running' and previous['name'] != desired['metadata']['name']:
                if time.monotonic() >= until:
                    raise TimeoutError('previous cluster cache writer did not finish')
                lease.fence()
                time.sleep(2)
                old = kube.get('job', previous['name'])
                if not old or old['metadata']['uid'] != previous['uid']:
                    raise ValueError('original cache writer disappeared during observation')
        marker = path.with_suffix('.job.json')
        before = json.loads(marker.read_text()) if marker.exists() else {}
        same = previous and previous['name'] == desired['metadata']['name']
        current = {'name': desired['metadata']['name'],
                   'request_sha256': hashlib.sha256(canonical(desired)).hexdigest(),
                   'uid': previous.get('uid') if same else None, 'submission_started': True}
        value = {'apiVersion': 'v1', 'kind': 'ConfigMap',
            'metadata': {'name': pointer_name, 'namespace': kube.namespace, 'labels': {'app.kubernetes.io/part-of': OWNER}},
            'data': {'owner.json': json.dumps(current)}}
        if pointer:
            value['metadata'].update(uid=pointer['metadata']['uid'], resourceVersion=pointer['metadata']['resourceVersion'])
        # Publish the new cache writer intent in Kubernetes before admission.
        # It survives loss of the shared working PVC and of the observer.
        lease.fence()
        pointer = kube.replace('configmap', value) if pointer else kube.create('configmap', value)
        lease.fence()
        write_json(marker, dict(before, submission_started=True))
        resource = ensure_job(kube, lease, desired, expected_uid=before.get('uid') or current['uid'],
                              previously_submitted=bool(same) or before.get('submission_started', False))
        current['uid'] = resource['metadata']['uid']
        write_json(marker, current)
        pointer['data']['owner.json'] = json.dumps(current)
        lease.fence()
        kube.replace('configmap', pointer)
        while job_state(resource) == 'running':
            if time.monotonic() >= until:
                raise TimeoutError('native cluster build reached its original execution deadline')
            lease.fence()
            time.sleep(2)
            resource = kube.get('job', current['name'])
            if not resource or resource['metadata']['uid'] != current['uid']:
                raise ValueError('original native build disappeared; no automatic rebuild')
        if job_state(resource) != 'complete':
            raise ValueError('native cluster build failed; retain its original Job and logs')
        if cached_artifact(config, component, manifest['inputs'][component]) is None:
            raise ValueError('completed native cluster build omitted its artifact receipt')


def execute(path, checksum):
    request = json.loads(Path(path).read_text())
    config, manifest = request['config'], request['manifest']
    if (hashlib.sha256(canonical(request)).hexdigest() != checksum
            or manifest['configuration_sha256'] != hashlib.sha256(canonical(config)).hexdigest()
            or manifest['inputs'] != inputs(config, manifest['sources'])):
        raise ValueError('native cluster build request/configuration/source binding changed')
    if config.get('build_execution') != 'kubernetes' or config.get('build_directory') != '/build/trees' or config.get('compiler_directory') != '/build/compiler':
        raise ValueError('native cluster builder requires its bounded cache paths')
    for name_ in ('tmp', 'cargo', 'gradle'):
        Path('/build', name_).mkdir(exist_ok=True)
    # fsGroup gives the PVC directories an inherited setgid flag. Private
    # installer state correctly rejects that flag; its disposable test roots
    # must originate from a private scratch parent, as on Android itself.
    Path('/build/tmp').chmod(0o700)
    from android_release_host import build
    build(request)


if __name__ == '__main__':
    if sys.argv[1] == 'submit' and len(sys.argv) == 3:
        remote(sys.argv[2])
    elif sys.argv[1] == 'execute' and len(sys.argv) == 4:
        execute(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit('expected submit REQUEST or execute REQUEST SHA256')
