"""Cluster ownership, immutable Job identity and uncertain-observation controls."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

if sys.platform == 'win32':
    raise unittest.SkipTest('POSIX Android deployment orchestration')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release_kubernetes as cluster


class API:
    namespace = 'ghost'

    def __init__(self):
        self.objects = {}
        self.sequence = 0
        self.created = 0

    def get(self, kind, name):
        return copy.deepcopy(self.objects.get((kind, name)))

    def create(self, kind, value):
        key = kind, value['metadata']['name']
        if key in self.objects:
            raise HTTPError('', 409, 'conflict', {}, None)
        self.sequence += 1;self.created += 1
        value = copy.deepcopy(value)
        value['metadata'].update(uid='uid-' + str(self.sequence), resourceVersion=str(self.sequence))
        self.objects[key] = value
        return copy.deepcopy(value)

    def replace(self, kind, value):
        key = kind, value['metadata']['name']
        before = self.objects[key]
        if value['metadata']['resourceVersion'] != before['metadata']['resourceVersion']:
            raise HTTPError('', 409, 'conflict', {}, None)
        self.sequence += 1
        value = copy.deepcopy(value);value['metadata']['resourceVersion'] = str(self.sequence)
        self.objects[key] = value
        return copy.deepcopy(value)


class Ownership(unittest.TestCase):
    def setUp(self):
        self.api = API()

    def test_live_lease_excludes_a_second_owner(self):
        first = cluster.Lease(self.api, 'android-release').acquire()
        first.fence()
        with self.assertRaises(BlockingIOError):
            cluster.Lease(self.api, 'android-release').acquire()

    def test_expired_owner_cannot_mutate_or_release_its_successor(self):
        with cluster.Lease(self.api, 'android-release') as first:
            value = self.api.objects['lease', 'android-release']
            value['spec']['renewTime'] = '2000-01-01T00:00:00Z'
            second = cluster.Lease(self.api, 'android-release').acquire()
            with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
                first.fence()
        self.assertEqual(self.api.get('lease', 'android-release')['spec']['holderIdentity'], second.holder)

    def test_failed_renewal_and_short_remaining_window_stop_mutations(self):
        lease = cluster.Lease(self.api, 'android-release').acquire()
        lease.failed = OSError('lost connection')
        with self.assertRaises(RuntimeError): lease.fence()
        lease.failed = None;lease.valid_until = time.monotonic() + 29
        with self.assertRaises(RuntimeError): lease.fence()

    def test_another_application_lease_is_preserved(self):
        self.api.create('lease', {'metadata': {'name': 'android-release', 'labels': {}},
                                  'spec': {'holderIdentity': '', 'renewTime': cluster.timestamp(), 'leaseDurationSeconds': 120}})
        with self.assertRaisesRegex(ValueError, 'another application'):
            cluster.Lease(self.api, 'android-release').acquire()

    def test_normal_context_releases_only_its_own_lease(self):
        with cluster.Lease(self.api, 'android-release') as lease:
            lease.renew();lease.fence()
        self.assertEqual(self.api.get('lease', 'android-release')['spec']['holderIdentity'], '')

    def job(self):
        return {'apiVersion': 'batch/v1', 'kind': 'Job',
                'metadata': {'name': cluster.job_name('a' * 64, 'sdk'), 'namespace': 'ghost'},
                'spec': {'backoffLimit': 0, 'template': {'spec': {'restartPolicy': 'Never',
                         'containers': [{'name': 'builder', 'image': 'registry.example/builder@sha256:' + 'b' * 64}]}}}}

    def test_running_job_is_reconciled_without_second_execution(self):
        lease = cluster.Lease(self.api, 'android-release').acquire()
        first = cluster.ensure_job(self.api, lease, self.job())
        count = self.api.created
        second = cluster.ensure_job(self.api, lease, self.job(), expected_uid=first['metadata']['uid'])
        self.assertEqual(first, second)
        self.assertEqual(self.api.created, count)
        self.assertEqual(cluster.job_state(second), 'running')

    def test_original_missing_or_replaced_job_never_restarts_blindly(self):
        lease = cluster.Lease(self.api, 'android-release').acquire()
        first = cluster.ensure_job(self.api, lease, self.job())
        key = 'job', first['metadata']['name']
        del self.api.objects[key]
        with self.assertRaisesRegex(RuntimeError, 'original Android Job is missing'):
            cluster.ensure_job(self.api, lease, self.job(), expected_uid=first['metadata']['uid'])
        with self.assertRaises(RuntimeError):
            cluster.ensure_job(self.api, lease, self.job(), previously_submitted=True)
        replacement = cluster.ensure_job(self.api, lease, self.job())
        self.assertNotEqual(replacement['metadata']['uid'], first['metadata']['uid'])
        with self.assertRaisesRegex(ValueError, 'differently bound'):
            cluster.ensure_job(self.api, lease, self.job(), expected_uid=first['metadata']['uid'])

    def test_changed_job_image_or_namespace_is_refused(self):
        lease = cluster.Lease(self.api, 'android-release').acquire()
        cluster.ensure_job(self.api, lease, self.job())
        changed = self.job();changed['spec']['template']['spec']['containers'][0]['image'] = 'another-image'
        with self.assertRaisesRegex(ValueError, 'differently bound'):
            cluster.ensure_job(self.api, lease, changed)
        changed = self.job();changed['metadata']['namespace'] = 'production'
        with self.assertRaisesRegex(ValueError, 'namespace'):
            cluster.ensure_job(self.api, lease, changed)

    def test_failed_job_remains_failed(self):
        lease = cluster.Lease(self.api, 'android-release').acquire()
        first = cluster.ensure_job(self.api, lease, self.job())
        self.api.objects['job', first['metadata']['name']]['status'] = {'conditions': [{'type': 'Failed', 'status': 'True'}]}
        observed = cluster.ensure_job(self.api, lease, self.job())
        self.assertEqual(cluster.job_state(observed), 'failed')
        self.assertEqual(observed['metadata']['uid'], first['metadata']['uid'])

    def test_lost_owner_cannot_submit_a_new_job(self):
        lease = cluster.Lease(self.api, 'android-release').acquire()
        lease.failed = OSError('network partition')
        with self.assertRaises(RuntimeError): cluster.ensure_job(self.api, lease, self.job())
        self.assertIsNone(self.api.get('job', self.job()['metadata']['name']))

    def test_job_names_and_https_origin_are_bounded(self):
        for value in ('../../other', 'a' * 64, 'a/b', 'Mixed'):
            with self.assertRaises(ValueError): cluster.name(value)
        for url in ('http://kubernetes.default.svc', 'https://user:password@server', 'https://server/other'):
            with self.assertRaises(ValueError):
                cluster.Kubernetes({'namespace': 'ghost', 'server': url}, opener=object())


if __name__ == '__main__':
    unittest.main()
