"""Bounded Kubernetes operations for the cluster Android release adapter."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import ssl
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, Request, build_opener
import uuid

from android_release import canonical
from android_release_source import NoRedirect

MAX_RESPONSE = 4 * 1024 ** 2
OWNER = 'android-cluster-release'


def name(value):
    if not isinstance(value, str) or not re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
        raise ValueError('bounded Kubernetes resource name required')
    return value


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


class Kubernetes:
    def __init__(self, config, opener=None):
        self.namespace = name(config['namespace'])
        self.server = config.get('server', 'https://kubernetes.default.svc').rstrip('/')
        endpoint = urlsplit(self.server)
        if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username
                or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment):
            raise ValueError('verified Kubernetes HTTPS origin required')
        self.token_file = Path(config.get('token_file', '/var/run/secrets/kubernetes.io/serviceaccount/token'))
        ca = config.get('ca_file', '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt')
        self.opener = opener or build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca)))

    def path(self, kind, resource=None):
        group, plural = {'lease': ('apis/coordination.k8s.io/v1', 'leases'),
                         'job': ('apis/batch/v1', 'jobs'),
                         'pod': ('api/v1', 'pods'),
                         'configmap': ('api/v1', 'configmaps')}[kind]
        return '/' + group + '/namespaces/' + self.namespace + '/' + plural + ('/' + name(resource) if resource else '')

    def request(self, method, path, value=None):
        token = self.token_file.read_text().strip()  # Projected tokens rotate.
        if not token or len(token) > 16384 or '\n' in token or '\r' in token:
            raise ValueError('invalid projected Kubernetes token')
        request = Request(self.server + path, method=method,
            data=canonical(value) if value is not None else None,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Accept': 'application/json'})
        with self.opener.open(request, timeout=10) as response:
            data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError('Kubernetes response exceeds its bound')
        return json.loads(data)

    def get(self, kind, resource):
        try:
            return self.request('GET', self.path(kind, resource))
        except HTTPError as error:
            if error.code == 404:
                return None
            raise

    def create(self, kind, value):
        return self.request('POST', self.path(kind), value)

    def replace(self, kind, value):
        if not value.get('metadata', {}).get('resourceVersion'):
            raise ValueError('Kubernetes mutation needs its observed resource version')
        return self.request('PUT', self.path(kind, value['metadata']['name']), value)


class Lease:
    """One cluster owner; lost renewal stops further adapter mutations.

    Mutating adapter calls have a ten-second request bound and require at least
    thirty seconds of remaining lease time. Jobs keep their deterministic
    identity across ownership changes; an observation failure never resubmits.
    """
    duration = 120

    def __init__(self, kube, resource, holder=None):
        self.kube, self.resource = kube, name(resource)
        self.holder = holder or str(uuid.uuid4())
        self.stop = threading.Event()
        self.failed = None
        self.valid_until = 0
        self.uid = None

    def acquire(self):
        current = self.kube.get('lease', self.resource)
        if current:
            if current['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') != OWNER:
                raise ValueError('preserve another application lease')
            spec = current['spec']
            until = datetime.fromisoformat(spec['renewTime'].replace('Z', '+00:00')).timestamp() + spec['leaseDurationSeconds']
            if spec.get('holderIdentity') and spec['holderIdentity'] != self.holder and time.time() < until:
                raise BlockingIOError('another Android cluster owner holds this lease')
        value = {'apiVersion': 'coordination.k8s.io/v1', 'kind': 'Lease',
            'metadata': {'name': self.resource, 'namespace': self.kube.namespace,
                         'labels': {'app.kubernetes.io/part-of': OWNER}},
            'spec': {'holderIdentity': self.holder, 'leaseDurationSeconds': self.duration,
                     'acquireTime': timestamp(), 'renewTime': timestamp()}}
        if current:
            value['metadata'].update(uid=current['metadata']['uid'], resourceVersion=current['metadata']['resourceVersion'])
        started = time.monotonic()
        result = self.kube.replace('lease', value) if current else self.kube.create('lease', value)
        self.uid = result['metadata']['uid']
        self.valid_until = started + self.duration
        return self

    def observe(self):
        value = self.kube.get('lease', self.resource)
        if (value is None or value['metadata']['uid'] != self.uid
                or value['spec'].get('holderIdentity') != self.holder):
            raise RuntimeError('Android cluster lease ownership changed')
        return value

    def fence(self):
        if self.failed is not None or time.monotonic() + 30 >= self.valid_until:
            raise RuntimeError('Android cluster lease renewal was lost')
        self.observe()

    def renew(self):
        value = self.observe()
        value['spec']['renewTime'] = timestamp()
        started = time.monotonic()
        self.kube.replace('lease', value)
        self.valid_until = started + self.duration

    def __enter__(self):
        self.acquire()
        def keep_alive():
            while not self.stop.wait(20):
                try:
                    self.renew()
                except Exception as error:
                    self.failed = error
                    return
        self.thread = threading.Thread(target=keep_alive, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=12)
        if self.thread.is_alive():
            return
        try:
            value = self.observe()
            value['spec']['holderIdentity'] = ''
            value['spec']['renewTime'] = timestamp()
            self.kube.replace('lease', value)
        except Exception:
            pass  # Never release a successor's lease after uncertain ownership.


def job_name(release_id, component):
    if not re.fullmatch('[0-9a-f]{64}', release_id):
        raise ValueError('immutable release identity required')
    return name('android-' + name(component) + '-' + release_id[:24])


def ensure_job(kube, lease, job, expected_uid=None, previously_submitted=False):
    """Reconcile one immutable request; preserve running and failed Jobs."""
    resource = name(job['metadata']['name'])
    desired = json.loads(json.dumps(job))
    if desired['metadata'].get('namespace') != kube.namespace:
        raise ValueError('Android Job changed namespace')
    identity = hashlib.sha256(canonical(desired)).hexdigest()
    desired['metadata'].setdefault('labels', {})['app.kubernetes.io/part-of'] = OWNER
    desired['metadata'].setdefault('annotations', {})['ghost.io/request-sha256'] = identity
    existing = kube.get('job', resource)
    if existing:
        if (existing['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') != OWNER
                or existing['metadata'].get('annotations', {}).get('ghost.io/request-sha256') != identity
                or (expected_uid is not None and existing['metadata'].get('uid') != expected_uid)):
            raise ValueError('preserve the differently bound existing Job')
        return existing
    if previously_submitted or expected_uid is not None:
        raise RuntimeError('original Android Job is missing; reconcile its retained receipt before retrying')
    lease.fence()
    try:
        return kube.create('job', desired)
    except HTTPError as error:
        if error.code != 409:
            raise
        # A racing request is adopted only through the same identity check.
        existing = kube.get('job', resource)
        if (not existing or existing['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') != OWNER
                or existing['metadata'].get('annotations', {}).get('ghost.io/request-sha256') != identity):
            raise ValueError('conflicting Android Job creation') from None
        return existing


def job_state(job):
    if job is None:
        return 'missing'
    conditions = {row['type'] for row in job.get('status', {}).get('conditions', []) if row.get('status') == 'True'}
    if 'Failed' in conditions:
        return 'failed'
    if 'Complete' in conditions:
        return 'complete'
    return 'running'  # Pending/unknown observations do not authorize replacement.
