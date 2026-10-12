"""Cluster publication pointers for immutable Android FSN1 objects.

Kubernetes owns the small catalogue and its Lease. S3 stores immutable bytes;
neither object overwrites nor a workstation filesystem act as a distributed lock.
"""
import hashlib
import json
from pathlib import Path
import time
from urllib.error import HTTPError

from android_release import canonical, write_json
from android_release_kubernetes import Kubernetes, Lease, OWNER, name
from android_release_store import Archive, sha256

MAX_CATALOGUE = 700 * 1024
KINDS = ('artifacts', 'prepared', 'runs', 'checkpoints')


class Catalogue:
    def __init__(self, config, kube=None, archive=None):
        self.config = config
        self.kube = kube or Kubernetes(config['kubernetes'])
        self.resource = name(config['archive']['catalogue'])
        self._archive = archive

    @property
    def archive(self):
        if self._archive is None:
            self._archive = Archive(self.config['archive'])
        return self._archive

    def read(self):
        resource = self.kube.get('configmap', self.resource)
        if resource is None:
            return None, {'schema': 1, **{kind: {} for kind in KINDS}}
        if resource['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') != OWNER:
            raise ValueError('preserve another application catalogue')
        raw = resource['data']['catalogue.json']
        if len(raw.encode()) > MAX_CATALOGUE:
            raise ValueError('Android catalogue exceeds its bound')
        value = json.loads(raw)
        if value.get('schema') != 1 or any(not isinstance(value.get(k), dict) for k in KINDS):
            raise ValueError('invalid Android object catalogue')
        return resource, value

    def lookup(self, kind, key):
        if kind not in KINDS:
            raise ValueError('unknown Android catalogue record kind')
        return self.read()[1][kind].get(key)

    def bind(self, kind, key, descriptor, replace=False):
        if kind not in KINDS or (replace and kind != 'checkpoints'):
            raise ValueError('only the coordinator checkpoint pointer may advance')
        self.archive.descriptor(**{
            'key': descriptor['key'], 'version': descriptor['version'],
            'checksum': descriptor['sha256'], 'size': descriptor['bytes'], 'record': True})
        until = time.monotonic() + 30
        while True:
            try:
                with Lease(self.kube, self.resource) as lease:
                    resource, value = self.read()
                    previous = value[kind].get(key)
                    if previous and previous['sha256'] == descriptor['sha256']:
                        return previous  # Retain the original pinned object version.
                    if previous and not replace:
                        raise ValueError('immutable Android catalogue binding changed')
                    value[kind][key] = descriptor
                    raw = canonical(value).decode()
                    if len(raw.encode()) > MAX_CATALOGUE:
                        raise ValueError('Android catalogue capacity reached; retain existing evidence')
                    desired = {'apiVersion': 'v1', 'kind': 'ConfigMap',
                        'metadata': {'name': self.resource, 'namespace': self.kube.namespace,
                                     'labels': {'app.kubernetes.io/part-of': OWNER}},
                        'data': {'catalogue.json': raw}}
                    if resource:
                        desired['metadata'].update(uid=resource['metadata']['uid'],
                                                   resourceVersion=resource['metadata']['resourceVersion'])
                    lease.fence()
                    if resource:
                        self.kube.replace('configmap', desired)
                    else:
                        self.kube.create('configmap', desired)
                    return descriptor
            except BlockingIOError:
                if time.monotonic() >= until:
                    raise TimeoutError('Android catalogue publication lease is busy') from None
                time.sleep(.1)
            except HTTPError as error:
                if error.code != 409 or time.monotonic() >= until:
                    raise
                time.sleep(.1)

    def artifact(self, component, key, directory):
        descriptor = self.archive.publish_directory(directory, component, key)
        return self.bind('artifacts', component + '/' + sha256(key), descriptor)

    def hydrate_artifact(self, component, key, destination):
        descriptor = self.lookup('artifacts', component + '/' + sha256(key))
        if descriptor is None:
            return False
        self.archive.restore_directory(descriptor, destination, component, key)
        return True

    def prepared(self, value):
        ident = sha256(value['prepared_id'])
        unsigned = {k: v for k, v in value.items() if k != 'prepared_id'}
        if hashlib.sha256(canonical(unsigned)).hexdigest() != ident:
            raise ValueError('prepared object identifier differs')
        return self.bind('prepared', ident, self.archive.publish_record(value))

    def hydrate_prepared(self, ident, destination):
        descriptor = self.lookup('prepared', sha256(ident))
        if descriptor is None:
            return False
        value = self.archive.read_record(descriptor)
        unsigned = {k: v for k, v in value.items() if k != 'prepared_id'}
        if value.get('prepared_id') != ident or hashlib.sha256(canonical(unsigned)).hexdigest() != ident:
            raise ValueError('archived prepared object identifier differs')
        if Path(destination).exists():
            raise ValueError('preserve existing prepared receipt')
        write_json(destination, value)
        return True

    def run(self, directory):
        directory = Path(directory)
        manifest = json.loads((directory / 'manifest.json').read_text())
        receipt = json.loads((directory / 'receipt.json').read_text())
        ident = sha256(manifest['release_id'])
        if (receipt.get('release_id') != ident or receipt.get('pushed_at') != manifest['pushed_at']
                or receipt.get('state') not in ('live', 'failed', 'warmed')):
            raise ValueError('only original terminal run receipts can be archived')
        evidence = {'schema': 1, 'manifest': manifest, 'receipt': receipt}
        for filename in ('live.json', 'rollback.json', 'preflight-block.json'):
            path = directory / filename
            if path.exists():
                if path.is_symlink() or path.stat().st_size > 128 * 1024:
                    raise ValueError('unsafe Android terminal evidence')
                evidence[filename] = json.loads(path.read_text())
        return self.bind('runs', ident, self.archive.publish_record(evidence))

    def hydrate_run(self, ident, directory):
        descriptor = self.lookup('runs', sha256(ident))
        if descriptor is None:
            return False
        evidence = self.archive.read_record(descriptor)
        if set(evidence) - {'schema', 'manifest', 'receipt', 'live.json', 'rollback.json', 'preflight-block.json'}:
            raise ValueError('unexpected archived terminal evidence path')
        manifest, receipt = evidence['manifest'], evidence['receipt']
        unsigned = {k: v for k, v in manifest.items() if k != 'release_id'}
        if (manifest.get('release_id') != ident or hashlib.sha256(canonical(unsigned)).hexdigest() != ident
                or receipt.get('release_id') != ident or receipt.get('pushed_at') != manifest['pushed_at']
                or receipt.get('state') not in ('live', 'failed', 'warmed')):
            raise ValueError('archived original run binding changed')
        directory = Path(directory)
        for filename, value in [('manifest.json', manifest), ('receipt.json', receipt)]:
            path = directory / filename
            if path.exists() and json.loads(path.read_text()) != value:
                raise ValueError('preserve differing local original run evidence')
        # The terminal receipt is published last; an interrupted hydration can
        # never turn an archived failure into a new execution.
        for filename, value in evidence.items():
            if filename.endswith('.json'):
                write_json(directory / filename, value)
        write_json(directory / 'manifest.json', manifest)
        write_json(directory / 'receipt.json', receipt)
        return True
